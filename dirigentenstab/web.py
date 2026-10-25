import html
import json
import os

import httpx

from fastapi import Request
from fastapi.responses import HTMLResponse
from nicegui import app, ui

from .runtime import Runtime, provider_models, test_provider
from .diagnostics import diagnose
from .settings import Settings
from .store import Store


def agent_label(agent):
    return 'Main Agent' if agent.get('is_main') else agent['name']


def hierarchy_nodes(data):
    """Join authoritative CloudStack parents to managed-agent presentation metadata."""
    agents = {a['domain_id']: a for a in data.get('agents', [])}
    domains, roots = {}, []
    for domain in data.get('domains', []):
        agent = agents.get(domain['id'])
        domains[domain['id']] = {
            'id': 'agent:' + agent['id'] if agent else 'domain:' + domain['id'],
            'label': agent_label(agent) if agent else domain['name'],
            'icon': 'smart_toy' if agent else 'folder', 'children': [],
        }
    for domain in data.get('domains', []):
        node = domains[domain['id']]
        parent = domains.get(domain.get('parentdomainid'))
        if parent is None or parent is node:
            roots.append(node)
        else:
            parent['children'].append(node)
    # CloudStack's native ROOT is a container, never a managed AI identity.
    native_roots = {d['id'] for d in data.get('domains', [])
                    if d.get('path') == 'ROOT' or d.get('level') == 0 or
                    (d['name'] == 'ROOT' and not d.get('parentdomainid'))}
    return [child for node in roots for child in
            (node['children'] if node['id'].removeprefix('domain:') in native_roots else [node])]


def tool_label(event):
    name = event.get('name', 'Tool')
    content = event.get('content', {})
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except ValueError:
            content = {}
    target = event.get('target') or next((str(content[k])[:80] for k in ('command', 'name', 'vm_id', 'agent_id') if content.get(k)), '') \
        if isinstance(content, dict) else ''
    status = 'Failed' if event.get('failed') else 'Running' if event['type'] == 'tool_call' else 'Completed'
    mode = 'Read' if name in {'search_api', 'describe_api'} or (name == 'execute_api' and
                    target.startswith(('list', 'query', 'get'))) else 'Action'
    duration = f" · {event['duration']}s" if event.get('duration') is not None else ''
    return f'{name} · {status} · {mode}' + (f' · {target}' if target else '') + duration + (
        ' · ' + event['summary'] if event.get('summary') else '')


def history_parts(history):
    """Keep chronological messages and correlated tools, including pre-v0.1.3 histories."""
    saved = {(e['type'], e.get('call_id')): e for run in history.get('runs', []) for e in run['events']}
    emitted = set()
    for message in history.get('messages', []):
        for part in message.get('parts', []):
            kind = part.get('part_kind')
            if kind in {'user-prompt', 'text'}:
                yield 'human' if kind == 'user-prompt' else 'agent', str(part.get('content', ''))
            elif kind in {'tool-call', 'tool-return'}:
                event_type = 'tool_call' if kind == 'tool-call' else 'tool_result'
                key = (event_type, part.get('tool_call_id'))
                event = saved.get(key) or {
                    'type': event_type, 'name': part.get('tool_name', 'Tool'),
                    'call_id': part.get('tool_call_id'),
                    'content': part.get('args' if kind == 'tool-call' else 'content', ''),
                }
                emitted.add(key)
                yield 'activity', event
    for key, event in saved.items():
        if key not in emitted:
            yield 'activity', event


def build_ui(service, auth, runtime=None):
    runtime = runtime or Runtime(service)

    @app.get('/login', response_class=HTMLResponse)
    async def login_page(request: Request):
        error = '<p role="alert">Sign-in failed. Check your account details and try again.</p>' \
            if request.query_params.get('error') or request.query_params.get('failed') else ''
        return HTMLResponse('''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in · Dirigentenstab</title>
<style>body{font:16px system-ui,sans-serif;background:#f5f5f4;color:#292524;margin:0;display:grid;
min-height:100vh;place-items:center}main{background:white;border:1px solid #e7e5e4;border-radius:12px;
padding:2rem;max-width:26rem;margin:1rem}h1{font-size:1.8rem;margin-top:0}form,label{display:flex;
flex-direction:column;gap:.5rem}form{gap:1.2rem}input,button{font:inherit;padding:.8rem;border:1px solid
#a8a29e;border-radius:6px}button{background:#31595c;color:white;cursor:pointer}small{display:block;
margin-top:1.5rem;color:#78716c}[role=alert]{color:#b91c1c}</style></head><body><main>
<h1>Dirigentenstab</h1><p>Sign in with your CloudStack account.</p>''' + error + '''
<form action="/auth/login" method="post">
<label>Username<input name="username" autocomplete="username" required maxlength="255"></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required maxlength="1024"></label>
<label>CloudStack domain<input name="domain" value="/" required maxlength="1024"></label>
<button type="submit">Sign in</button></form>
<small>Accounts are managed in CloudStack. Public registration is disabled.</small>
</main></body></html>''', headers={'Cache-Control': 'no-store'})

    @ui.page('/')
    async def workspace(request: Request):
        client = ui.context.client
        token = request.cookies.get('ds_session', '')
        try:
            identity = await auth.identity(token)
            data = await service.hierarchy(identity)
        except Exception:
            ui.navigate.to('/login')
            return
        ui.colors(primary='#31595c', secondary='#ae7644', accent='#31595c')

        async def actor():
            try:
                current = await auth.identity(token)
                if not current:
                    raise PermissionError('Session expired')
                return current
            except Exception:
                ui.navigate.to('/login')
                raise PermissionError('Session expired') from None

        async def protect(action):
            # Callbacks outlive rebuilt detail cards; use the stable page slot for dialogs and notifications.
            with client:
                try:
                    await action()
                except Exception as exc:
                    error = diagnose(exc, agent_id=state['agent'])
                    ui.notify(str(error), type='negative', timeout=15000, close_button=True)

        state = {'agent': None, 'conversation': None, 'busy': False, 'data': data, 'imported': False, 'resume_operation': None}
        agents = {row['id']: row for row in data.get('agents', [])}
        dashboard_url = service.dashboard_url(identity) if identity.get('type') == 1 else ''
        dashboard_links = []

        def dashboard_link(classes):
            link = ui.link('CloudStack Dashboard', dashboard_url or '#', new_tab=True).props(
                'rel="noopener noreferrer"').classes(classes)
            link.set_visibility(bool(dashboard_url))
            dashboard_links.append(link)

        with ui.header().classes('bg-white text-stone-800 border-b items-center px-5 py-3 gap-3'):
            ui.icon('account_tree').classes('text-teal-900 text-2xl')
            ui.label('Dirigentenstab').classes('font-semibold text-xl')
            ui.space()
            if identity.get('type') == 1:
                dashboard_link('dashboard-header text-teal-900')
            ui.label(identity.get('username', 'CloudStack administrator')).classes('text-sm brand-user')
            ui.html('<form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="'
                    + html.escape(identity['csrf'], quote=True)
                    + '"><button type="submit" class="border rounded px-3 py-1">Sign out</button></form>',
                    sanitize=False)

        ui.add_css("""
            html,body{overscroll-behavior:none;overflow:hidden}
            .nicegui-content{padding:0;height:calc(var(--viewport-height,100dvh) - 65px);min-height:0}
            .workspace{height:100%;min-height:0;width:100%;padding:12px;gap:10px;flex-wrap:nowrap}
            .conversation{flex:1;min-height:0;width:100%;overflow:hidden;gap:8px}
            .messages{flex:1;min-height:0;width:100%;overflow:hidden}
            .composer{width:100%;flex-shrink:0;align-items:end;flex-wrap:nowrap}
            .composer textarea{max-height:120px;overflow:auto!important}
            .thinking-dot{width:5px;height:5px;border-radius:50%;background:currentColor;animation:thinking-pulse 1s infinite alternate}
            @keyframes thinking-pulse{from{opacity:.25}to{opacity:1;transform:translateY(-2px)}}
            @media(prefers-reduced-motion:reduce){.thinking-dot{animation:none}}
            .markdown{max-width:100%;overflow-wrap:anywhere;min-width:0}
            .markdown table,.markdown pre{display:block;max-width:100%;overflow-x:auto}
            .markdown h1,.markdown h2{font-size:1.4rem;line-height:1.3;margin:.6rem 0}
            .markdown h3{font-size:1.15rem}
            .markdown pre{padding:12px;background:#f5f5f4;border-radius:6px}
            .q-message-text{background:#f5f5f4!important;color:#292524!important;max-width:100%}
            .q-message-container,.q-message-text-content{min-width:0;max-width:100%}
            .q-dialog__inner{height:var(--viewport-height,100dvh);bottom:auto}
            .q-dialog__inner>.q-card{max-height:calc(var(--viewport-height,100dvh)*.85);overflow-y:auto}
            .q-tree__node{padding-left:8px}
            .q-tree__children{padding-left:6px}
            .q-tree__node-header{min-height:44px;overflow-wrap:anywhere}
            .q-tree__node-header-content{min-width:0}
            button,.q-btn{min-height:44px}
            .dashboard-mobile{display:none;min-height:44px}
            @media(max-width:900px){.dashboard-header{display:none}.dashboard-mobile{display:flex;align-items:center}}
            .workspace.compact .agent-details{display:none}
            @media(max-width:600px){.workspace{padding:6px;gap:6px}.agent-details{padding:10px}
            .brand-user{display:none}.q-header{padding:8px!important}.nicegui-content{height:calc(var(--viewport-height,100dvh) - 61px)}
            .q-message-name{font-size:12px}.q-message{margin-bottom:6px}}
        """)
        # Resize the bounded workspace with the mobile visual viewport (including the virtual keyboard).
        ui.add_body_html("""<script>
            (() => { const fit = () => { const el=document.querySelector('.workspace');
                const header=document.querySelector('.q-header');
                const height=window.visualViewport?.height || innerHeight;
                document.documentElement.style.setProperty('--viewport-height',height+'px');
                if(el) { el.classList.toggle('compact',innerWidth<=600 && height<=600);
                    el.style.height=Math.max(100,height-(header?.getBoundingClientRect().height || 65))+'px'; } };
                window.visualViewport?.addEventListener('resize',fit); window.addEventListener('resize',fit);
                fit(); setTimeout(fit,500); })();
        </script>""")
        # QDrawer owns responsive visibility; a server model can lag a viewport change and reopen it.
        with ui.left_drawer(value=False).props('show-if-above breakpoint=900 bordered width=300 '
                ':model-value="null"').classes('bg-stone-50') as drawer:
            with ui.column().classes('h-full w-full no-wrap p-3 gap-3'):
                with ui.row().classes('w-full items-center no-wrap'):
                    ui.label('Agents').classes('text-lg font-semibold')
                    ui.space()
                    ui.button(icon='close', on_click=lambda: drawer.run_method('hide')).props('flat round aria-label="Close agent hierarchy"')
                    refresh_button = ui.button(icon='refresh').props('flat round aria-label="Refresh hierarchy"')
                search = ui.input('Search agents and domains').props('clearable').classes('w-full')
                with ui.scroll_area().classes('w-full flex-1 min-h-0'):
                    tree = ui.tree(hierarchy_nodes(data)).classes('w-full').mark('hierarchy')
                status = ui.label(str(data.get('status', 'CloudStack connected'))).classes('text-xs text-stone-600')
                providers_button = ui.button('Model providers', icon='settings').props('outline').classes('w-full') \
                    if identity.get('type') == 1 else None
                platform_button = None
                gpu_button = None
                if identity.get('type') == 1:
                    dashboard_link('dashboard-mobile w-full text-teal-900')
                    platform_button = ui.button('Platform settings', icon='admin_panel_settings').props('outline').classes('w-full')
                    gpu_button = ui.button('GPU policies', icon='memory').props('outline').classes('w-full')
        with ui.column().classes('workspace'):
            with ui.row().classes('w-full items-center no-wrap gap-2'):
                ui.button('Agents', icon='account_tree', on_click=lambda: drawer.run_method('toggle')).props(
                    'outline aria-label="Open agent hierarchy"')
                agent_choice = ui.select({key: agent_label(row) for key, row in agents.items()},
                                         label='Chat directly with an agent', with_input=True).classes(
                                             'flex-1 min-w-0').mark('agent_selector')
            details = ui.card().classes('w-full shrink-0 agent-details')
            with details:
                ui.label('Select an agent to begin').classes('text-xl font-semibold')
            with ui.card().classes('conversation'):
                with ui.row().classes('w-full items-center no-wrap gap-2'):
                    history_select = ui.select({}, label='Conversation', with_input=True).classes('flex-1 min-w-0')
                    new_button = ui.button(icon='add').props('flat round aria-label="New conversation"').mark('New conversation')
                with ui.scroll_area().classes('messages'):
                    transcript = ui.column().classes('w-full min-w-0 gap-3 p-2')
                continue_button = ui.button('Continue saved task', icon='play_arrow').props('outline')
                continue_button.set_visibility(False)
                gpu_recover_button = ui.button('Check GPU recovery', icon='restore').props('outline')
                gpu_recover_button.set_visibility(False)
                budget_label = ui.label('').classes('text-xs text-stone-600').props('role=status')
                progress = ui.label('Ready').classes('text-xs text-stone-600').props('role=status aria-live=polite')
                with ui.row().classes('thinking-indicator items-center gap-2 text-sm text-stone-600').props(
                        'role=status aria-live=polite').bind_visibility_from(state, 'busy').mark('thinking_indicator'):
                    ui.label('Thinking…')
                    with ui.row().classes('items-center gap-1').props('aria-hidden=true'):
                        for dot in range(3):
                            ui.element('span').classes('thinking-dot').style(f'animation-delay:{dot * .15}s')
                with ui.row().classes('composer gap-2'):
                    prompt = ui.textarea(label='Message', placeholder='Give this agent a task').props(
                        'outlined autogrow rows=1 maxlength=16000').classes('flex-1 min-w-0')
                    send_button = ui.button('Send', icon='send').props('aria-label="Send"')
                    send_button.bind_enabled_from(prompt, 'value', backward=lambda value:
                                                  bool(value and value.strip()) and not state['busy'])

        tool_cards = {}

        def activity(event):
            key = (event.get('operation_id'), event.get('call_id', event.get('name')))
            card = tool_cards.get(key)
            if card is None:
                with transcript:
                    card = ui.expansion(tool_label(event), icon='terminal').classes(
                        'w-full min-w-0 bg-stone-50 rounded')
                tool_cards[key] = card
            else:
                previous = card._props.get('call_content')
                if previous and event['type'] == 'tool_result':
                    event = event | {'content': {'request': previous, 'result': event.get('content')}}
                card.set_text(tool_label(event))
                card.clear()
            if event['type'] == 'tool_call':
                card._props['call_content'] = event.get('content')
            with card:
                ui.label(json.dumps(event.get('content'), ensure_ascii=False, default=str)[:16384]).classes(
                    'whitespace-pre-wrap font-mono text-xs break-all')

        def message(kind, content):
            with transcript:
                if kind == 'tool':
                    with ui.expansion('Tool activity', icon='terminal').classes('w-full bg-stone-50 rounded'):
                        ui.label(content[:65536]).classes('whitespace-pre-wrap font-mono text-xs break-all')
                else:
                    with ui.chat_message(name='You' if kind == 'human' else 'Agent', sent=kind == 'human').classes(
                            'w-full max-w-full'):
                        if kind == 'agent':
                            ui.markdown(content, extras=['tables', 'fenced-code-blocks'], sanitize=True).classes(
                                'markdown w-full')
                        else:
                            ui.label(content).classes('whitespace-pre-wrap break-words')

        async def histories():
            current = await actor()
            if state['agent']:
                rows = await runtime.conversations(current, state['agent'])
                history_select.set_options({row['id']: row['title'] for row in rows}, value=state['conversation'])

        async def show_agent(agent_id, *, close_navigation=True):
            if state['busy']:
                ui.notify('Wait for the current reply to finish.')
                return
            current = await actor()
            agent = await service.authorize(current, agent_id)
            state.update(agent=agent_id, conversation=None, imported=False, resume_operation=None)
            continue_button.set_visibility(False)
            gpu_recover_button.set_visibility(False)
            budget_label.set_text('')
            transcript.clear()
            tool_cards.clear()
            progress.set_text('Ready')
            agent_choice.set_value(agent_id)
            tree.props['selected'] = 'agent:' + agent_id
            tree.update()
            if close_navigation:
                drawer.run_method('hide')
            details.clear()
            domain = next((d for d in state['data'].get('domains', []) if d['id'] == agent['domain_id']), {})
            with details:
                with ui.expansion(value=True).classes('w-full').props('header-class="px-0"').mark('agent_details') as expansion:
                    with expansion.add_slot('header'):
                        with ui.row().classes('w-full min-w-0 items-center gap-3'):
                            ui.label(agent_label(agents.get(agent_id, agent))).classes('text-xl font-semibold break-words')
                            ui.badge('Domain administrator', color='primary')
                    with ui.row().classes('w-full items-center justify-end gap-3'):
                        ui.button('Configure', icon='tune', on_click=lambda: protect(configure_agent)).props('flat')
                        if agent.get('can_provision'):
                            ui.button('Create subgroup', icon='create_new_folder',
                                      on_click=lambda: protect(subgroup_dialog)).props('outline')
                    provider = next((p for p in await service.providers(current) if p['id'] == agent.get('provider_id')), {})
                    ui.label('Model: ' + provider.get('name', 'No provider') + ' / ' +
                             (agent.get('model') or provider.get('default_model') or 'not configured')).classes('text-sm')
                    with ui.expansion('Domain details', icon='info').classes('w-full text-sm'):
                        ui.label(domain.get('path', domain.get('name', agent['domain_id']))).classes('break-all')
                        ui.label('CloudStack domain: ' + agent['domain_id']).classes('break-all')
                        ui.label('Administrator account: ' + agent['account_id']).classes('break-all')
                        ui.label('Original agent name: ' + agent['name'])
                        for user in state['data'].get('users', []):
                            if user.get('domainid') == agent['domain_id'] and user['id'] != agent.get('user_id'):
                                ui.label('Administrator: ' + user.get('username', user['id']))
                    for operation in state['data'].get('pending_provisioning', []):
                        if operation['parent_id'] == agent_id:
                            ui.label(f"Requires reconciliation: {operation['name']} · {operation['phase']} · "
                                     f"Reference: {operation['id']}").classes('text-amber-900 break-all')
                            ui.label('Use Create subgroup with this same name to resume, or ask an administrator '
                                     'to use scripts/admin.py repair-provisioning.').classes('text-sm')
            await histories()

        async def refresh():
            current = await actor()
            updated = await service.hierarchy(current)
            state['data'] = updated
            agents.clear()
            agents.update({row['id']: row for row in updated.get('agents', [])})
            tree.props['nodes'] = hierarchy_nodes(updated)
            tree.update()
            agent_choice.set_options({key: agent_label(row) for key, row in agents.items()})
            status.set_text(str(updated.get('status', 'CloudStack connected')))

        async def select_node(event):
            if not event.value:
                return
            kind, identifier = event.value.split(':', 1)
            if kind == 'agent':
                if identifier != state['agent']:
                    await show_agent(identifier)
                else:
                    drawer.run_method('hide')
            elif kind == 'domain':
                current = await actor()
                updated = await service.hierarchy(current)
                domain = next((d for d in updated.get('domains', []) if d['id'] == identifier), None)
                if domain is None:
                    raise PermissionError('Domain unavailable')
                details.clear()
                with details:
                    ui.label(domain['name']).classes('text-2xl font-semibold')
                    ui.label(domain.get('path', '')).classes('text-stone-600')
                    ui.label('CloudStack domain: ' + identifier).classes('text-xs text-stone-500 break-all')
                    drawer.run_method('hide')
                    for agent in updated.get('agents', []):
                        if agent['domain_id'] == identifier:
                            ui.button('Chat with ' + agent['name'],
                                      on_click=lambda _, aid=agent['id']: protect(lambda: show_agent(aid)))

        async def choose_agent(event):
            if event.value and event.value != state['agent']:
                await show_agent(event.value)

        async def choose_history(event):
            if state['busy'] or not event.value or event.value == state['conversation']:
                return
            restored = await runtime.restore(await actor(), event.value)
            if restored['agent_id'] != state['agent']:
                raise PermissionError('Conversation belongs to another agent')
            state['resume_operation'] = None
            continue_button.set_visibility(False)
            budget_label.set_text('')
            state['conversation'] = restored['id']
            state['imported'] = bool(restored.get('imported'))
            progress.set_text('Imported history is read-only. Sending starts a new conversation without '
                              'forwarding this history to the model.' if state['imported'] else '')
            transcript.clear()
            tool_cards.clear()
            if restored.get('runs'):
                run = restored['runs'][-1]
                progress.set_text(f"{run['status'].capitalize()} · Reference: {run['id']}")
                budget = run.get('budget')
                state['resume_operation'] = run['id'] if budget and budget.get('resumable') else None
                continue_button.set_visibility(bool(state['resume_operation']))
                gpu_recover_button.set_visibility(run['status'] == 'reconciliation')
                if budget:
                    show_budget(budget)
                    if budget.get('resumable'):
                        progress.set_text('Paused · ' + str(budget.get('reason')) + ' budget · Reference: ' + run['id'])
            for kind, content in history_parts(restored):
                activity(content) if kind == 'activity' else message(kind, content)

        async def new_conversation():
            await actor()
            if not state['busy']:
                state['conversation'] = None
                state['imported'] = False
                state['resume_operation'] = None
                continue_button.set_visibility(False)
                gpu_recover_button.set_visibility(False)
                budget_label.set_text('')
                progress.set_text('')
                history_select.set_value(None)
                transcript.clear()

        def show_budget(budget):
            budget_label.set_text(f"Requests: {budget.get('requests', 0)} · Tools: {budget.get('tool_calls', 0)} · "
                                  f"Windows: {budget.get('windows', 0)} · Reused: {budget.get('cache_hits', 0)} · "
                                  f"Window limits: {budget.get('requests_per_window', 20)} requests / "
                                  f"{budget.get('tools_per_window', 30)} tools")

        async def check_gpu_recovery():
            if state['busy'] or not state['conversation']:
                return
            current = await actor()
            restored = await runtime.restore(current, state['conversation'])
            run = restored['runs'][-1]
            await runtime.reconcile_gpu(service, current, run['id'])
            state['resume_operation'] = run['id']
            continue_button.set_visibility(True)
            gpu_recover_button.set_visibility(False)
            progress.set_text('GPU result verified. Continue saved task without repeating its completed action.')

        async def send(resume=False):
            text = prompt.value.strip() if prompt.value else ''
            if state['busy'] or not state['agent'] or (not resume and not text):
                return
            # Claim the submission before the first await; rapid clicks cannot start two mutations.
            state['busy'] = True
            try:
                current = await actor()
                agent_id = state['agent']
                await service.authorize(current, agent_id)
            except BaseException:
                state['busy'] = False
                raise
            if state['imported']:
                transcript.clear()
            state['busy'] = True
            send_button.disable()
            prompt.disable()
            new_button.disable()
            history_select.disable()
            agent_choice.disable()
            continue_button.set_visibility(False)
            continue_button.disable()
            gpu_recover_button.set_visibility(False)
            if not resume:
                message('human', text)
                prompt.set_value('')
            with transcript:
                with ui.chat_message(name='Agent').classes('w-full max-w-full'):
                    answer = ui.markdown('', extras=['tables', 'fenced-code-blocks'], sanitize=True).classes('markdown w-full')
            progress.set_text('Agent is working…')
            chunks = []

            async def event_received(event):
                if event.get('budget'):
                    show_budget(event['budget'])
                if event.get('type') == 'run_started':
                    state['conversation'] = event['conversation_id']
                    progress.set_text('Running · Reference: ' + event['operation_id'])
                elif event.get('type') == 'text':
                    chunks.append(event.get('text', ''))
                    answer.set_content(''.join(chunks))
                elif event.get('type') == 'budget_checkpoint':
                    progress.set_text('Checkpoint saved; continuing next bounded window · Reference: ' + event['operation_id'])
                elif event.get('type') in {'tool_call', 'tool_result'}:
                    activity(event)

            try:
                result = (await runtime.resume(current, state['resume_operation'], event_received) if resume else
                          await runtime.chat(current, agent_id, state['conversation'], text, event_received))
                state['conversation'] = result['conversation_id']
                state['imported'] = False
                answer.set_content(result['output'])
                state['resume_operation'] = result['operation_id'] if result.get('status') == 'paused' and result.get('resumable', True) else None
                continue_button.set_visibility(bool(state['resume_operation']))
                progress.set_text('Paused · Completed activity saved · Reference: ' + result['operation_id']
                                  if result.get('status') == 'paused' else
                                  'Requires reconciliation' if result.get('status') == 'reconciliation' else 'Completed')
                await histories()
                await refresh()
            except Exception as exc:
                error = diagnose(exc, agent_id=agent_id)
                progress.set_text(('Requires reconciliation · ' if error.reconciliation else 'Failed · ') + str(error))
                await histories()
                if state['conversation']:
                    restored = await runtime.restore(current, state['conversation'])
                    latest = restored.get('runs', [])[-1:]
                    if latest and (latest[0].get('budget') or {}).get('resumable'):
                        state['resume_operation'] = latest[0]['id']
                        continue_button.set_visibility(True)
                    gpu_recover_button.set_visibility(bool(latest and latest[0]['status'] == 'reconciliation'))
                raise error from None
            finally:
                state['busy'] = False
                send_button.set_enabled(bool(prompt.value and prompt.value.strip()))
                prompt.enable()
                new_button.enable()
                history_select.enable()
                agent_choice.enable()
                continue_button.enable()

        async def mcp_dialog(agent_id):
            from .mcp import MCP

            integration = MCP(service)
            configuration = await integration.configuration(await actor(), agent_id)
            servers = {server['id']: server for server in configuration['servers']}
            manage = configuration['can_manage_servers']
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl gap-3'):
                ui.label('MCP tools').classes('text-xl font-semibold')
                ui.label('Only explicitly assigned tools are available. Every ancestor limits descendant access. '
                         'External results are untrusted.').classes('text-sm')
                options = ({'': 'New server'} if manage else {}) | {key: row['name'] for key, row in servers.items()}
                selected = ui.select(options, label='MCP server', value=next(iter(servers), '' if manage else None)).classes('w-full')
                if manage:
                    name = ui.input('Server name').props('maxlength=100').classes('w-full')
                    url = ui.input('HTTPS Streamable HTTP endpoint').classes('w-full')
                    token = ui.input('API key / bearer token (blank keeps existing)', password=True).classes('w-full')
                    ui.label('Tavily: use https://mcp.tavily.com/mcp and paste your Tavily API key.').classes('text-sm')
                    clear_token = ui.checkbox('Clear saved bearer token')
                    enabled = ui.checkbox('Server enabled', value=True)
                else:
                    ui.label('Server endpoints are managed by administrators of the main agent domain.').classes('text-sm')
                ui.label('Available tools').classes('font-semibold')
                tool_list = ui.column().classes('w-full shrink-0 max-h-64 overflow-y-auto gap-2')
                inherited = ui.label('').classes('text-sm whitespace-pre-wrap')
                discovery_status = ui.label('').props('role=status').classes('text-sm')
                feedback = ui.label('').props('role=status').classes('text-sm')
                choices = {key: set(row['tools']) for key, row in servers.items()}
                catalogues, checkboxes = {}, {}
                displayed, ready, generation = None, None, 0

                def remember():
                    if displayed:
                        choices[displayed] = {name for name, checkbox in checkboxes.items() if checkbox.value}

                def render(server_id):
                    nonlocal displayed
                    displayed = server_id
                    checkboxes.clear()
                    tool_list.clear()
                    catalogue = catalogues.get(server_id, {})
                    checked = choices.get(server_id, set())
                    with tool_list:
                        for tool_name in sorted(catalogue.keys() | checked):
                            with ui.column().classes('w-full shrink-0 gap-0 min-w-0'):
                                checkboxes[tool_name] = ui.checkbox(tool_name, value=tool_name in checked)
                                ui.label(catalogue.get(tool_name, '(unavailable)')).classes(
                                    'text-sm whitespace-pre-wrap break-words')

                def load():
                    row = servers.get(selected.value, {})
                    if manage:
                        name.set_value(row.get('name', ''))
                        url.set_value(row.get('url', ''))
                        token.set_value('')
                        clear_token.set_value(False)
                        enabled.set_value(bool(row.get('enabled', True)))
                    allowed = row.get('allowed_tools')
                    inherited.set_text('Ancestor allows: ' + (', '.join(allowed) or 'no tools')
                                       if allowed is not None else 'Select only the external tools this agent needs.')

                async def discover():
                    nonlocal generation, ready
                    remember()
                    generation += 1
                    request_generation, server_id = generation, selected.value
                    ready = None
                    assignment_button.disable()
                    render(server_id)
                    if not server_id:
                        refresh_tools.disable()
                        discovery_status.set_text('Save server settings to discover tools.')
                        return
                    refresh_tools.disable()
                    discovery_status.set_text('Loading available tools…')
                    try:
                        tools = await integration.discover(await actor(), agent_id, server_id)
                    except Exception as exc:
                        if generation == request_generation and selected.value == server_id:
                            error = diagnose(exc, agent_id=agent_id, tool='discover_mcp_tools')
                            discovery_status.set_text(str(error) + ' Refresh tools to retry. Your selections are preserved.')
                    else:
                        if generation == request_generation and selected.value == server_id:
                            remember()
                            catalogues[server_id] = {tool['name']: tool['description'] for tool in tools}
                            render(server_id)
                            ready = server_id
                            assignment_button.enable()
                            discovery_status.set_text(f'{len(tools)} tools available. Select tools to allow for this agent.')
                    finally:
                        if generation == request_generation and selected.value == server_id:
                            refresh_tools.enable()

                async def selection_changed():
                    await actor()
                    remember()
                    load()
                    await discover()

                async def save_server():
                    nonlocal generation, ready
                    previous = selected.value
                    values = ((name.value or '').strip(), (url.value or '').strip(),
                              '' if clear_token.value else token.value or None, bool(enabled.value))
                    remember()
                    generation += 1
                    save_generation = generation
                    ready = None
                    assignment_button.disable()
                    try:
                        server_id = await integration.save_server(
                            await actor(), *values[:3], server_id=previous or None, enabled=values[3])
                        token.set_value('')
                        updated = await integration.configuration(await actor(), agent_id)
                    except Exception:
                        if generation == save_generation and selected.value == previous:
                            refresh_tools.set_enabled(bool(previous))
                            discovery_status.set_text('Server settings were not confirmed. Refresh tools to retry. '
                                                      'Your selections are preserved.')
                        raise
                    remember()
                    servers.clear()
                    servers.update({server['id']: server for server in updated['servers']})
                    for key, row in servers.items():
                        choices.setdefault(key, set(row['tools']))
                    if generation != save_generation or selected.value != previous:
                        return
                    selected.set_options({'': 'New server', **{key: row['name'] for key, row in servers.items()}}, value=server_id)
                    load()
                    feedback.set_text('Server saved. Select tools to enable access for this agent.')
                    if server_id == previous:
                        await discover()

                async def save_assignment():
                    server_id = selected.value
                    if not server_id or ready != server_id:
                        raise ValueError('Refresh available tools before saving assignments')
                    remember()
                    names = sorted(choices[server_id])
                    await integration.assign(await actor(), agent_id, server_id, names)
                    servers[server_id]['tools'] = names
                    if selected.value == server_id:
                        feedback.set_text('Assigned tools saved for this agent.')

                selected.on_value_change(lambda: protect(selection_changed))
                if manage:
                    ui.button('Save server settings', on_click=lambda: protect(save_server)).props('outline')
                refresh_tools = ui.button('Refresh tools', icon='refresh', on_click=lambda: protect(discover)).props('outline')
                assignment_button = ui.button('Save assigned tools', on_click=lambda: protect(save_assignment))
                assignment_button.disable()
                ui.button('Close MCP tools', on_click=dialog.close).props('flat')
                load()
            dialog.open()
            await discover()

        async def configure_agent():
            current = await actor()
            agent = await service.authorize(current, state['agent'])
            options = {p['id']: p['name'] for p in await service.providers(current)}
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl gap-4'):
                ui.label('Configure ' + agent['name']).classes('text-xl font-semibold')
                provider = ui.select(options, label='Model provider', value=agent.get('provider_id')).classes('w-full')
                original_model = agent.get('model', '')
                model = ui.select([original_model] if original_model else [], label='Model ID', value=original_model or None,
                                  with_input=True, new_value_mode='add-unique').classes('w-full')
                model_status = ui.label('').classes('text-sm').props('role=status')
                thinking_choice = agent.get('thinking', 'default')
                thinking_generation = 0
                thinking_options = {'default': 'Model default'}
                if thinking_choice != 'default':
                    thinking_options[thinking_choice] = f'Saved level: {thinking_choice} (checking support)'
                thinking = ui.select(thinking_options, value=thinking_choice, label='Thinking level').classes('w-full')
                thinking.disable()
                thinking_source = ui.label('Checking model support…').classes('text-sm').props('role=status')
                ui.label('Applies to the next invocation; an active reply keeps its current settings.').classes('text-sm text-stone-600')

                def thinking_changed(event):
                    nonlocal thinking_choice
                    thinking_choice = event.value or 'default'

                async def load_thinking():
                    nonlocal thinking_generation, thinking_choice
                    thinking_generation += 1
                    generation = thinking_generation
                    selected_provider, selected_model = provider.value, (model.value or '').strip()
                    thinking.disable()
                    thinking.props('loading')
                    save_button.disable()
                    thinking_source.set_text('Checking model support…')
                    try:
                        current = await actor()
                        capabilities = (await runtime.thinking_capabilities(current, selected_provider, selected_model)
                                        if selected_provider else {'options': {'default': 'Model default'},
                                                                  'source': 'Select a provider and model to discover thinking support.'})
                        if (generation != thinking_generation or provider.value != selected_provider
                                or (model.value or '').strip() != selected_model):
                            return
                        options = capabilities['options']
                        chosen = thinking_choice if thinking_choice in options else 'default'
                        source = capabilities['source']
                        if chosen != thinking_choice:
                            source += ' The previous thinking level is unavailable for this model; using Model default.'
                        thinking_choice = chosen
                        thinking.set_options(options, value=chosen)
                        thinking_source.set_text(source)
                    except Exception as exc:
                        if generation == thinking_generation and provider.value == selected_provider and (model.value or '').strip() == selected_model:
                            thinking_choice = 'default'
                            thinking.set_options({'default': 'Model default'}, value='default')
                            error = diagnose(exc, agent_id=agent['id'], tool='thinking_capabilities')
                            thinking_source.set_text(str(error) + ' Thinking support could not be verified; only Model default is available.')
                    finally:
                        if generation == thinking_generation and provider.value == selected_provider and (model.value or '').strip() == selected_model:
                            thinking.props(remove='loading')
                            thinking.enable()
                            save_button.enable()

                thinking.on_value_change(thinking_changed)
                model.on_value_change(lambda: protect(load_thinking))

                async def load_models():
                    selected_provider = provider.value
                    model.props('loading')
                    model_status.set_text('Loading models…')
                    try:
                        choices = await runtime.models(await actor(), selected_provider) if selected_provider else []
                        if provider.value != selected_provider:
                            return
                        selected_model = model.value
                        model.set_options(list(dict.fromkeys(([selected_model] if selected_model else []) + choices)),
                                          value=selected_model)
                        model_status.set_text(f'{len(choices)} models available. Custom IDs can be entered.' if choices
                                              else 'No models discovered. Enter a custom Model ID and press Enter.')
                    except Exception as exc:
                        if provider.value == selected_provider:
                            error = diagnose(exc, agent_id=agent['id'], tool='discover_models')
                            unsupported = isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in {404, 405, 501}
                            model_status.set_text(('This provider does not support model discovery.' if unsupported else str(error))
                                                  + ' Enter a custom Model ID and press Enter.')
                    finally:
                        if provider.value == selected_provider:
                            model.props(remove='loading')

                async def provider_changed():
                    await load_models()
                    await load_thinking()

                provider.on_value_change(lambda: protect(provider_changed))
                ui.timer(0.01, lambda: protect(provider_changed), once=True)
                instructions = ui.textarea('System prompt', value=agent.get('instructions', '')).props('maxlength=32000').classes('w-full')
                ui.label('Custom instructions for this agent, applied on its next model call.').classes('text-sm text-stone-600')
                ui.button('MCP tools', icon='extension',
                          on_click=lambda: protect(lambda: mcp_dialog(agent['id']))).props('outline')
                can_provision = ui.checkbox('Allow subordinate agent creation', value=bool(agent.get('can_provision'))) \
                    if current.get('type') == 1 else None

                async def save():
                    options = {'can_provision': can_provision.value} if can_provision is not None else {}
                    await service.update_agent(await actor(), agent['id'], provider.value,
                                               (model.value or '').strip(), instructions.value or '', thinking=thinking.value, **options)
                    dialog.close()
                    await refresh()
                    await show_agent(agent['id'])

                async def rotate():
                    await service.rotate_credentials(await actor(), agent['id'])
                    ui.notify('Agent credentials replaced and previous keys revoked.', type='positive')

                async def revoke():
                    await service.revoke_agent(await actor(), agent['id'])
                    dialog.close()
                    state.update(agent=None, conversation=None)
                    agent_choice.set_value(None)
                    transcript.clear()
                    details.clear()
                    with details:
                        ui.label('Agent access revoked').classes('text-xl font-semibold')
                    await refresh()

                ui.separator()
                ui.label('CloudStack credential access').classes('font-semibold')
                ui.label('Rotation replaces the API key pair. Revocation disables this agent.').classes(
                    'text-sm text-stone-600')
                with ui.row().classes('w-full gap-2'):
                    ui.button('Rotate credentials', icon='key', on_click=lambda: protect(rotate)).props('outline')
                    ui.button('Revoke access', icon='block', on_click=lambda: protect(revoke), color='negative').props('flat')
                with ui.row().classes('w-full justify-end'):
                    ui.button('Cancel', on_click=dialog.close).props('flat')
                    save_button = ui.button('Save', on_click=lambda: protect(save))
                    save_button.disable()
            dialog.open()

        async def subgroup_dialog():
            current = await actor()
            parent = await service.authorize(current, state['agent'])
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl gap-4'):
                ui.label('Create subgroup under ' + parent['name']).classes('text-xl font-semibold')
                name = ui.input('Name').props('maxlength=64').classes('w-full')
                model = ui.input('Model ID (blank inherits parent)').classes('w-full')
                instructions = ui.textarea('System prompt (blank inherits parent)').classes('w-full')
                result_label = ui.label('').classes('text-sm')

                async def create():
                    await service.authorize(await actor(), parent['id'])
                    result_label.set_text('Provisioning CloudStack identity…')
                    create_button.disable()
                    try:
                        child = await service.create_subgroup(parent['id'], name.value.strip(),
                                                              model.value.strip() or None,
                                                              instructions.value or None)
                        dialog.close()
                        await refresh()
                        await show_agent(child['id'])
                    finally:
                        create_button.enable()
                        result_label.set_text('')

                with ui.row().classes('w-full justify-end'):
                    ui.button('Cancel', on_click=dialog.close).props('flat')
                    create_button = ui.button('Create subgroup', on_click=lambda: protect(create))
            dialog.open()

        async def gpu_dialog():
            current = await actor()
            if current.get('type') != 1:
                raise PermissionError('Human platform administrator required')
            data = await service.gpu_admin(current)
            domains = {d['id']: d for d in data['domains']}
            profiles = {p['id']: p['name'] for p in data['profiles']}
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-3xl gap-3'):
                ui.label('GPU policies and device ownership').classes('text-xl font-semibold')
                ui.label('Missing policies deny GPU operations. Every ancestor restricts its descendants. '
                         'Only devices owned by the group or its subgroups may change.').classes('text-sm')
                domain = ui.select({k: d.get('path', d['name']) for k, d in domains.items()},
                                   label='GPU policy domain', with_input=True).classes('w-full')
                allowed = ui.select(profiles, multiple=True, with_input=True, label='Allowed vGPU profiles').props('use-chips').classes('w-full')
                maximum = ui.number('Maximum GPU allocations', value=0, min=-1, precision=0).classes('w-full')
                release = ui.checkbox('Release GPU automatically when its VM stops')
                reconfigure = ui.checkbox('Allow reconfiguration of owned unused GPU pools')
                subgroup = ui.checkbox('Allow subgroup agents to request GPU capacity')
                feedback = ui.label('').classes('text-sm whitespace-pre-wrap')

                async def load():
                    if not domain.value:
                        return
                    policy = data['policies'].get(domain.value, {})
                    allowed.set_value(policy.get('profiles', []))
                    maximum.set_value(policy.get('max_allocations', -1 if int(domains[domain.value].get('level', -1)) == 0 else 0))
                    release.set_value(policy.get('release_on_stop', False))
                    reconfigure.set_value(policy.get('reconfigure_unused', False))
                    subgroup.set_value(policy.get('subgroup_requests', False))
                    feedback.set_text('Native ROOT quota is unlimited (-1). Put real quota caps on managed child domains.'
                                      if int(domains[domain.value].get('level', -1)) == 0 else '')

                async def save():
                    current_actor = await actor()
                    if not domain.value:
                        raise ValueError('Select a GPU policy domain')
                    policy = {'profiles': allowed.value or [], 'max_allocations': int(maximum.value),
                              'release_on_stop': release.value, 'reconfigure_unused': reconfigure.value,
                              'subgroup_requests': subgroup.value}
                    await service.gpu_admin(current_actor, 'set_policy', domain_id=domain.value, policy=policy)
                    data['policies'][domain.value] = policy
                    feedback.set_text('Policy saved; native CloudStack quota verified.')

                domain.on_value_change(lambda: protect(load))
                ui.button('Save GPU policy', on_click=lambda: protect(save))
                with ui.expansion('Platform capacity preparation', icon='memory').classes('w-full'):
                    ui.table(columns=[{'name': field, 'label': label, 'field': field} for field, label in
                             [('uuid', 'Owned device'), ('domain_id', 'Owner domain'), ('profile', 'Profile')]],
                             rows=data['pools']).classes('w-full')
                    profile = ui.select(profiles, label='GPU offering profile').classes('w-full')
                    cpus = ui.number('Offering vCPUs', value=1, min=1, precision=0)
                    memory = ui.number('Offering RAM MiB', value=1024, min=512, precision=0)
                    disk = ui.number('Offering root disk GiB', value=20, min=8, precision=0)
                    async def offering():
                        if not domain.value or not profile.value:
                            raise ValueError('Select a domain and profile first')
                        result = await service.gpu_admin(await actor(), 'offering', domain_id=domain.value, profile=profile.value,
                                                         cpus=int(cpus.value), memory=int(memory.value), root_disk=int(disk.value))
                        feedback.set_text('Authorized native GPU offering: ' + result['offering_id'])
                    ui.button('Prepare authorized GPU offering', on_click=lambda: protect(offering))
                    owned = {p['uuid'] for p in data['pools']}
                    devices = {d['busaddress']: d.get('vgpuprofilename', '') + ' · ' + d['busaddress']
                               for d in data['devices'] if d.get('state') == 'Free' and d['busaddress'] not in owned}
                    device = ui.select(devices, label='Unclaimed free GPU device').classes('w-full')
                    async def claim():
                        if not domain.value or not device.value:
                            raise ValueError('Select an owner domain and free device')
                        await service.gpu_admin(await actor(), 'claim', domain_id=domain.value, uuid=device.value)
                        feedback.set_text('Free device pool owner assigned. Existing ownership cannot be overwritten.')
                    ui.button('Assign unclaimed pool to selected domain', on_click=lambda: protect(claim))
                with ui.expansion('GPU operation recovery', icon='restore').classes('w-full'):
                    operations = {o['id']: o['id'] + ' · ' + o['phase'] for o in data['operations']}
                    operation = ui.select(operations, label='GPU operation reference').classes('w-full')
                    async def recover(action):
                        if not operation.value:
                            raise ValueError('Select a saved GPU operation')
                        result = await service.gpu_admin(await actor(), action, operation_id=operation.value)
                        feedback.set_text('GPU operation verified: ' + json.dumps(result)[:1024])
                    ui.button('Reconcile GPU operation', on_click=lambda: protect(lambda: recover('reconcile')))
                    ui.button('Resume saved pre-dispatch GPU plan', on_click=lambda: protect(lambda: recover('resume')))
                ui.button('Close', on_click=dialog.close).props('flat')
            dialog.open()

        async def platform_dialog():
            current = await actor()
            if current.get('type') != 1:
                raise PermissionError('Platform administrator required')
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl'):
                ui.label('Platform settings').classes('text-xl font-semibold')
                url = ui.input('CloudStack Dashboard URL', value=service.dashboard_url(current)).classes('w-full')
                ui.label('Browser-accessible private URL. CloudStack uses its own login; blank hides the link.').classes('text-sm')
                async def save():
                    actor_identity = await actor()
                    service.save_dashboard_url(actor_identity, url.value or '')
                    value = service.dashboard_url(actor_identity)
                    for link in dashboard_links:
                        link.props['href'] = value or '#'
                        link.set_visibility(bool(value))
                        link.update()
                    dialog.close()
                with ui.row():
                    ui.button('Cancel', on_click=dialog.close).props('flat')
                    ui.button('Save', on_click=lambda: protect(save))
            dialog.open()

        async def provider_dialog():
            current = await actor()
            if current.get('type') != 1:
                raise PermissionError('Root administrator required')
            providers = {p['id']: p for p in await service.providers(current)}
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl gap-3'):
                ui.label('Model providers').classes('text-xl font-semibold')
                existing = ui.select({'': 'New provider', **{key: p['name'] for key, p in providers.items()}},
                                     value='', label='Provider').classes('w-full')
                name = ui.input('Name').classes('w-full')
                protocol = ui.select({'chat': 'OpenAI-compatible Chat Completions', 'responses': 'OpenAI Responses'},
                                     value='chat', label='Protocol').classes('w-full')
                base_url = ui.input('Base URL (including /v1)').classes('w-full')
                key = ui.input('API key (blank keeps existing)', password=True, password_toggle_button=True).classes('w-full')
                model = ui.input('Default model / test model').classes('w-full')
                test_status = ui.label('').classes('whitespace-pre-wrap text-sm')
                model_options = ui.select([], label='Discovered models',
                                          on_change=lambda e: model.set_value(e.value or '')).classes('w-full')

                async def selected(event):
                    await actor()
                    provider = providers.get(event.value, {})
                    name.set_value(provider.get('name', ''))
                    protocol.set_value(provider.get('protocol', 'chat'))
                    base_url.set_value(provider.get('base_url', ''))
                    model.set_value(provider.get('default_model', ''))
                    key.set_value('')
                    test_status.set_text('')
                    model_options.set_options([])

                async def save():
                    provider_id = await service.save_provider(await actor(), name.value.strip(), protocol.value,
                                                              base_url.value.strip(), key.value,
                                                              model.value.strip(), existing.value or None)
                    key.set_value('')
                    updated = await service.providers(await actor())
                    providers.clear()
                    providers.update({p['id']: p for p in updated})
                    existing.set_options({'': 'New provider', **{k: p['name'] for k, p in providers.items()}},
                                         value=provider_id)
                    test_status.set_text('Provider saved. Run the tool-calling test before assigning it to an agent.')
                    return provider_id

                async def discover():
                    provider_id = await save()
                    provider = await service.get_provider(await actor(), provider_id)
                    models = await provider_models(provider, service.store)
                    model_options.set_options(models)
                    test_status.set_text(f'{len(models)} model(s) discovered. Manual IDs are also supported.')

                async def test():
                    provider_id = await save()
                    provider = await service.get_provider(await actor(), provider_id)
                    test_status.set_text('Testing reachability, authentication, model and actual tool calling…')
                    result = await test_provider(provider, model.value.strip(), service.store)
                    labels = {'reachable': 'Reachable', 'authenticated': 'Authenticated',
                              'model_available': 'Model available', 'tool_calling': 'Tool calling'}
                    test_status.set_text('\n'.join(f'{label}: {result.get(field)}' for field, label in labels.items())
                                         + ('\n' + result['error'] if result.get('error') else ''))

                existing.on_value_change(lambda e: protect(lambda: selected(e)))
                with ui.row().classes('w-full gap-2 flex-wrap'):
                    ui.button('Save', on_click=lambda: protect(save))
                    ui.button('Discover models', on_click=lambda: protect(discover)).props('outline')
                    ui.button('Test tool calling', on_click=lambda: protect(test)).props('outline')
                    ui.button('Close', on_click=dialog.close).props('flat')
            dialog.open()

        def filter_tree():
            tree.props['filter'] = search.value or ''
            if search.value:
                tree.expand()
            else:
                tree.collapse()
            tree.update()

        search.on_value_change(filter_tree)
        main = next((a for a in agents.values() if a.get('is_main')), None)
        if main:
            await show_agent(main['id'], close_navigation=False)

        tree.on_select(lambda e: protect(lambda: select_node(e)))
        agent_choice.on_value_change(lambda e: protect(lambda: choose_agent(e)))
        history_select.on_value_change(lambda e: protect(lambda: choose_history(e)))
        refresh_button.on_click(lambda: protect(refresh))
        new_button.on_click(lambda: protect(new_conversation))
        send_button.on_click(lambda: protect(send))
        continue_button.on_click(lambda: protect(lambda: send(resume=True)))
        gpu_recover_button.on_click(lambda: protect(check_gpu_recovery))
        if providers_button is not None:
            providers_button.on_click(lambda: protect(provider_dialog))
        if platform_button is not None:
            platform_button.on_click(lambda: protect(platform_dialog))
        if gpu_button is not None:
            gpu_button.on_click(lambda: protect(gpu_dialog))


def main():
    from .auth import Auth, attach
    from .service import Service

    settings = Settings.load()
    service = Service(Store(settings.database, settings.key_file), settings)
    auth = Auth(service)
    attach(app, auth, settings)
    build_ui(service, auth)
    tls = {}
    if os.getenv('APP_TLS_CERT') or os.getenv('APP_TLS_KEY'):
        tls = {'ssl_certfile': os.environ['APP_TLS_CERT'], 'ssl_keyfile': os.environ['APP_TLS_KEY']}
    ui.run(host=os.getenv('APP_HOST', '0.0.0.0'), port=int(os.getenv('APP_PORT', '8088')),
           title='Dirigentenstab', reload=False, show=False, show_welcome_message=False, **tls)


if __name__ == '__main__':
    main()
