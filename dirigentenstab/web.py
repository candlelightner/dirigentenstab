import html
import json
import os

from fastapi import Request
from fastapi.responses import HTMLResponse
from nicegui import app, ui

from .runtime import Runtime, provider_models, test_provider
from .settings import Settings
from .store import Store


def hierarchy_nodes(data):
    domains = {
        domain['id']: {'id': 'domain:' + domain['id'], 'label': domain['name'], 'children': []}
        for domain in data.get('domains', [])
    }
    roots = []
    for domain in data.get('domains', []):
        node = domains[domain['id']]
        parent = domains.get(domain.get('parentdomainid'))
        if parent is None or parent is node:
            roots.append(node)
        else:
            parent['children'].append(node)
    for agent in data.get('agents', []):
        parent = domains.get(agent['domain_id'])
        if parent is not None:
            state = agent.get('model') or 'model not configured'
            parent['children'].append({'id': 'agent:' + agent['id'], 'label': f'{agent["name"]} · {state}'})
    for user in data.get('users', []):
        parent = domains.get(user.get('domainid'))
        if parent is not None:
            parent['children'].append({'id': 'human:' + user['id'],
                                       'label': 'Administrator: ' + user.get('username', user['id'])})
    return roots


def history_parts(history):
    """Render only supported persisted conversation parts as plain text."""
    for message in history.get('messages', []):
        for part in message.get('parts', []):
            kind = part.get('part_kind')
            if kind in {'user-prompt', 'text'}:
                yield 'human' if kind == 'user-prompt' else 'agent', str(part.get('content', ''))
            elif kind in {'tool-call', 'tool-return'}:
                value = part.get('args', '') if kind == 'tool-call' else part.get('content', '')
                yield 'tool', part.get('tool_name', 'Tool') + '\n' + json.dumps(value, ensure_ascii=False)


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
            try:
                await action()
            except PermissionError:
                ui.notify('Access denied or session expired.', type='negative')
            except Exception:
                ui.notify('The operation failed. Check the configuration and server audit log.', type='negative')

        state = {'agent': None, 'conversation': None, 'busy': False, 'data': data, 'imported': False}
        agents = {row['id']: row for row in data.get('agents', [])}
        with ui.header().classes('bg-white text-stone-800 border-b items-center px-5 py-3 gap-3'):
            ui.icon('account_tree').classes('text-teal-900 text-2xl')
            ui.label('Dirigentenstab').classes('font-semibold text-xl')
            ui.space()
            ui.label(identity.get('username', 'CloudStack administrator')).classes('text-sm')
            ui.html('<form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="'
                    + html.escape(identity['csrf'], quote=True)
                    + '"><button type="submit" class="border rounded px-3 py-1">Sign out</button></form>',
                    sanitize=False)

        with ui.row().classes('w-full items-start gap-5 p-3 md:p-5 flex-wrap'):
            with ui.card().classes('w-full md:w-80 shrink-0 gap-4'):
                with ui.row().classes('w-full items-center'):
                    ui.label('Domains & agents').classes('font-semibold')
                    ui.space()
                    refresh_button = ui.button(icon='refresh').props('flat round aria-label="Refresh hierarchy"')
                tree = ui.tree(hierarchy_nodes(data)).classes('w-full')
                tree.expand()
                agent_choice = ui.select({key: row['name'] for key, row in agents.items()},
                                         label='Chat directly with an agent', with_input=True).classes('w-full').mark('agent_selector')
                ui.separator()
                ui.label('Infrastructure').classes('font-semibold')
                status = ui.label(str(data.get('status', 'CloudStack connected'))).classes(
                    'text-sm text-stone-600 whitespace-pre-wrap break-all')
                if identity.get('type') == 1:
                    providers_button = ui.button('Model providers', icon='settings').props('outline').classes('w-full')
                else:
                    providers_button = None
            with ui.column().classes('flex-1 min-w-0 w-full gap-4'):
                details = ui.card().classes('w-full')
                with details:
                    ui.label('Select an agent to begin').classes('text-2xl font-semibold')
                    ui.label('The tree comes from CloudStack. Each agent uses its own administrative identity.').classes(
                        'text-stone-600')
                with ui.card().classes('w-full gap-3'):
                    with ui.row().classes('w-full items-center'):
                        history_select = ui.select({}, label='Conversation', with_input=True).classes('flex-1 min-w-48')
                        new_button = ui.button('New conversation', icon='add').props('flat')
                    with ui.scroll_area().classes('w-full h-[52vh] min-h-64'):
                        transcript = ui.column().classes('w-full gap-4 p-2')
                    with ui.row().classes('w-full items-end no-wrap'):
                        prompt = ui.textarea(label='Message', placeholder='Give this agent a task').props(
                            'outlined autogrow maxlength=16000').classes('flex-1')
                        send_button = ui.button('Send', icon='send')
                    progress = ui.label('').classes('text-sm text-stone-500')

        def message(kind, content):
            with transcript:
                if kind == 'tool':
                    with ui.expansion('Tool activity', icon='terminal').classes('w-full bg-stone-50 rounded'):
                        ui.label(content[:65536]).classes('whitespace-pre-wrap font-mono text-xs break-all')
                else:
                    with ui.chat_message(name='You' if kind == 'human' else 'Agent', sent=kind == 'human').classes(
                            'w-full max-w-full'):
                        ui.label(content).classes('whitespace-pre-wrap break-words')

        async def histories():
            current = await actor()
            if state['agent']:
                rows = await runtime.conversations(current, state['agent'])
                history_select.set_options({row['id']: row['title'] for row in rows}, value=state['conversation'])

        async def show_agent(agent_id):
            if state['busy']:
                ui.notify('Wait for the current reply to finish.')
                return
            current = await actor()
            agent = await service.authorize(current, agent_id)
            state.update(agent=agent_id, conversation=None, imported=False)
            transcript.clear()
            progress.set_text('')
            agent_choice.set_value(agent_id)
            details.clear()
            domain = next((d for d in state['data'].get('domains', []) if d['id'] == agent['domain_id']), {})
            with details:
                with ui.row().classes('w-full items-center gap-3'):
                    ui.label(agent['name']).classes('text-2xl font-semibold')
                    ui.badge('Domain administrator', color='primary')
                    ui.space()
                    ui.button('Configure', icon='tune', on_click=lambda: protect(configure_agent)).props('flat')
                    if agent.get('can_provision'):
                        ui.button('Create subgroup', icon='create_new_folder',
                                  on_click=lambda: protect(subgroup_dialog)).props('outline')
                ui.label(domain.get('path', domain.get('name', agent['domain_id']))).classes('text-stone-600')
                ui.label('CloudStack domain: ' + agent['domain_id']).classes('text-xs text-stone-500 break-all')
                ui.label('Administrator account: ' + agent['account_id']).classes('text-xs text-stone-500 break-all')
                ui.label('Model: ' + (agent.get('model') or 'not configured')).classes('text-sm')
            await histories()

        async def refresh():
            current = await actor()
            updated = await service.hierarchy(current)
            state['data'] = updated
            agents.clear()
            agents.update({row['id']: row for row in updated.get('agents', [])})
            tree.props['nodes'] = hierarchy_nodes(updated)
            tree.update()
            agent_choice.set_options({key: row['name'] for key, row in agents.items()})
            status.set_text(str(updated.get('status', 'CloudStack connected')))

        async def select_node(event):
            if not event.value:
                return
            kind, identifier = event.value.split(':', 1)
            if kind == 'agent':
                await show_agent(identifier)
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
            state['conversation'] = restored['id']
            state['imported'] = bool(restored.get('imported'))
            progress.set_text('Imported history is read-only. Sending starts a new conversation without '
                              'forwarding this history to the model.' if state['imported'] else '')
            transcript.clear()
            for kind, content in history_parts(restored):
                message(kind, content)

        async def new_conversation():
            await actor()
            if not state['busy']:
                state['conversation'] = None
                state['imported'] = False
                progress.set_text('')
                history_select.set_value(None)
                transcript.clear()

        async def send():
            if state['busy'] or not state['agent'] or not (text := prompt.value.strip()):
                return
            current = await actor()
            agent_id = state['agent']
            await service.authorize(current, agent_id)
            if state['imported']:
                transcript.clear()
            state['busy'] = True
            send_button.disable()
            prompt.disable()
            new_button.disable()
            history_select.disable()
            agent_choice.disable()
            message('human', text)
            prompt.set_value('')
            with transcript:
                with ui.chat_message(name='Agent').classes('w-full max-w-full'):
                    answer = ui.label('').classes('whitespace-pre-wrap break-words')
            progress.set_text('Agent is working…')
            chunks = []

            async def event_received(event):
                if event.get('type') == 'text':
                    chunks.append(event.get('text', ''))
                    answer.set_text(''.join(chunks))
                elif event.get('type') in {'tool_call', 'tool_result'}:
                    message('tool', event.get('name', 'Tool') + '\n' + json.dumps(
                        event.get('content'), ensure_ascii=False, default=str))

            try:
                result = await runtime.chat(current, agent_id, state['conversation'], text, event_received)
                state['conversation'] = result['conversation_id']
                state['imported'] = False
                answer.set_text(result['output'])
                await histories()
            finally:
                state['busy'] = False
                send_button.enable()
                prompt.enable()
                new_button.enable()
                history_select.enable()
                agent_choice.enable()
                progress.set_text('')

        async def configure_agent():
            current = await actor()
            agent = await service.authorize(current, state['agent'])
            options = {p['id']: p['name'] for p in await service.providers(current)}
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl gap-4'):
                ui.label('Configure ' + agent['name']).classes('text-xl font-semibold')
                provider = ui.select(options, label='Model provider', value=agent.get('provider_id')).classes('w-full')
                model = ui.input('Model ID', value=agent.get('model', '')).classes('w-full')
                instructions = ui.textarea('System instructions', value=agent.get('instructions', '')).classes('w-full')
                can_provision = ui.checkbox('Allow subordinate agent creation', value=bool(agent.get('can_provision'))) \
                    if current.get('type') == 1 else None

                async def save():
                    options = {'can_provision': can_provision.value} if can_provision is not None else {}
                    await service.update_agent(await actor(), agent['id'], provider.value,
                                               model.value.strip(), instructions.value, **options)
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
                ui.label('Rotation replaces both key pairs. Revocation disables this agent.').classes(
                    'text-sm text-stone-600')
                with ui.row().classes('w-full gap-2'):
                    ui.button('Rotate credentials', icon='key', on_click=lambda: protect(rotate)).props('outline')
                    ui.button('Revoke access', icon='block', on_click=lambda: protect(revoke), color='negative').props('flat')
                with ui.row().classes('w-full justify-end'):
                    ui.button('Cancel', on_click=dialog.close).props('flat')
                    ui.button('Save', on_click=lambda: protect(save))
            dialog.open()

        async def subgroup_dialog():
            current = await actor()
            parent = await service.authorize(current, state['agent'])
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl gap-4'):
                ui.label('Create subgroup under ' + parent['name']).classes('text-xl font-semibold')
                name = ui.input('Name').props('maxlength=64').classes('w-full')
                model = ui.input('Model ID (blank inherits parent)').classes('w-full')
                instructions = ui.textarea('System instructions (blank inherits parent)').classes('w-full')
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

        tree.on_select(lambda e: protect(lambda: select_node(e)))
        agent_choice.on_value_change(lambda e: protect(lambda: choose_agent(e)))
        history_select.on_value_change(lambda e: protect(lambda: choose_history(e)))
        refresh_button.on_click(lambda: protect(refresh))
        new_button.on_click(lambda: protect(new_conversation))
        send_button.on_click(lambda: protect(send))
        if providers_button is not None:
            providers_button.on_click(lambda: protect(provider_dialog))


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
