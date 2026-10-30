import asyncio
import json
import time
from urllib.parse import urlencode

from nicegui import ui

from . import thinking
from .diagnostics import diagnose
from .web_sidebar import agent_label, mark_attention


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


def pause_reason(*sources):
    for source in sources:
        if not source:
            continue
        if isinstance(source, str):
            try:
                source = json.loads(source)
            except (ValueError, TypeError):
                if stripped := source.strip():
                    return stripped
        if isinstance(source, dict) and source.get('reason'):
            if val := str(source['reason']).strip():
                return val
    return None


def history_parts(history):
    """Keep chronological messages and correlated tools, including pre-v0.1.3 histories."""
    saved = {(e['type'], e.get('call_id')): e for run in history.get('runs', []) for e in run['events']}
    emitted = set()
    for message in history.get('messages', []):
        for part in message.get('parts', []):
            kind = part.get('part_kind')
            if (kind == 'user-prompt' and str(part.get('content', '')).startswith(
                    '<system>[System notification: escalation decision]')
                    or kind == 'system-prompt' and part.get('dynamic_ref') == 'escalation_decision'):
                yield 'notice', 'Escalation result available.'
            elif (kind == 'user-prompt' and str(part.get('content', '')).startswith(
                    '<system>[System notification: compute offering decision]')
                    or kind == 'system-prompt' and part.get('dynamic_ref') == 'compute_offering_decision'):
                yield 'notice', 'Compute offering approved and now available.'
            elif kind in {'user-prompt', 'text'}:
                text = str(part.get('content', ''))
                if kind == 'text':
                    text = thinking.visible_text(text)
                if text or kind == 'user-prompt':
                    yield 'human' if kind == 'user-prompt' else 'agent', text
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
                if kind == 'tool-call' and (part.get('tool_name') == 'pause_work' or event.get('name') == 'pause_work'):
                    if reason := pause_reason(part.get('args'), event.get('content')):
                        yield 'agent', reason
    for key, event in saved.items():
        if key not in emitted:
            yield 'activity', event
            if event.get('type') == 'tool_call' and event.get('name') == 'pause_work':
                if reason := pause_reason(event.get('content')):
                    yield 'agent', reason


ESCALATION_NOTICES = {
    'approved': 'Escalation approved', 'applying': 'Escalation approved, applying…',
    'failed': 'Escalation approved, but the command failed',
    'uncertain': 'Escalation approved, outcome uncertain', 'deferred': 'Escalation declined',
}


def with_escalation_notices(parts, requests):
    """Place each decided escalation's notice right after its request's tool activity, keyed by request id."""
    parts = [(kind, content, None) for kind, content in parts]
    for request in requests:
        if not (text := ESCALATION_NOTICES.get(request['status'])):
            continue
        ends = [i for i, (kind, content, _) in enumerate(parts)
                if kind == 'activity' and content.get('operation_id') == request['run_id']]
        exact = [i for i in ends if parts[i][1].get('call_id') == request['call_id']]
        at = (exact or ends or [len(parts) - 1])[-1] + 1
        while at < len(parts) and parts[at][2]:
            at += 1
        parts.insert(at, ('notice', text, ('escalation', request['id'])))
    return parts


def conversation_activity(store, human_id, agent_ids):
    if not agent_ids:
        return []
    placeholders = ','.join('?' for _ in agent_ids)
    return store.all(
        'SELECT c.id,c.agent_id,c.title,r.id AS operation_id,r.status,r.updated,s.seen FROM conversations c JOIN chat_runs r '
        'ON r.id=(SELECT id FROM chat_runs WHERE conversation_id=c.id ORDER BY created DESC LIMIT 1) '
        'LEFT JOIN conversation_seen s ON s.conversation_id=c.id AND s.human_id=c.human_id '
        f'WHERE c.human_id=? AND c.agent_id IN ({placeholders}) ORDER BY r.updated DESC',
        (human_id, *agent_ids))


MARKERS = {'queued': ('◷', 'Queued'), 'running': ('▶', 'Running'),
           'blocked': ('‖', 'Blocked or paused'), 'unread': ('●', 'Unread output')}


def activity_marker(row, queued=()):
    """Marker key for a conversation's latest run; blocked and finished runs clear once the conversation is seen."""
    status, unseen = row.get('status'), (row.get('updated') or 0) > (row.get('seen') or 0)
    if status == 'running':
        return 'queued' if row.get('operation_id') in queued else 'running'
    if unseen and status in ('interrupted', 'reconciliation'):
        return 'blocked'
    if unseen and status in ('completed', 'failed'):
        return 'unread'


def save_setting(store, name, value):
    store.execute(
        'INSERT INTO platform_settings(name,value) VALUES(?,?) '
        'ON CONFLICT(name) DO UPDATE SET value=excluded.value',
        (name, value),
    )


def build_chat_view(ctx):
    protect, state = ctx.protect, ctx.state

    with ui.row().classes('conversation-controls w-full items-center no-wrap gap-2') as ctx.conversation_controls:
        ctx.history_select = ui.select({}, label='Conversation', with_input=True).props('dense').classes('flex-1 min-w-0')
        # A marked title starts with its glyph and a space; the option slot renders the glyph as a labelled marker.
        glyphs = repr(dict(MARKERS.values()))  # a JS object literal in single quotes, safe inside attributes
        ctx.history_select.add_slot('option', '''<q-item v-bind="props.itemProps"><q-item-section side v-if="%s[props.opt.label[0]]">
            <span role="img" class="text-teal-8" :aria-label="%s[props.opt.label[0]]">{{ props.opt.label[0] }}</span></q-item-section>
            <q-item-section><q-item-label class="ellipsis">{{ %s[props.opt.label[0]] ? props.opt.label.slice(2) : props.opt.label }}
            </q-item-label></q-item-section></q-item>''' % (glyphs, glyphs, glyphs))
        ctx.new_button = ui.button(icon='add').props('flat round aria-label="New conversation"').mark('New conversation')
        with ui.button(icon='info_outline').props(
                'flat round aria-label="Run details" aria-haspopup="menu"').mark('run_details_toggle'):
            with ui.menu().props('anchor="bottom right" self="top right"').classes(
                    'run-details-menu bg-white p-4').mark('run_details_menu').style(
                        'width:min(360px,calc(100vw - 24px));max-width:calc(100vw - 24px)') as ctx.run_details_menu:
                with ui.column().classes('run-details w-full gap-2').mark('run_details'):
                    ctx.run_details_fallback = ui.label('No run details yet.').classes('text-xs text-stone-500')
                    ctx.status_label = ui.label('').classes('text-xs text-stone-600 run-status').props('role=status')
                    with ctx.status_label:
                        ctx.reference = ui.tooltip('')
                    ctx.budget_label = ui.label('').classes('text-xs text-stone-600').props('role=status')
                    ctx.context_label = ui.label('').classes('text-xs text-stone-600').props('role=status').mark('context_usage')
                    ctx.compaction_status = ui.label('').classes('text-xs text-stone-600').props('role=status').mark('compaction_status')

    with ui.card().classes('conversation') as ctx.conversation_card:
        with ui.scroll_area().classes('messages') as ctx.transcript_scroll:
            ctx.transcript = ui.column().classes('w-full min-w-0 gap-3 p-2')
        with ui.row().classes('thinking-indicator items-center gap-2 text-sm text-stone-600').props(
                'role=status aria-live=polite').bind_visibility_from(state, 'busy').mark('thinking_indicator'):
            ui.label().bind_text_from(state, 'indicator')
            with ui.row().classes('items-center gap-1').props('aria-hidden=true').bind_visibility_from(
                    state, 'indicator', lambda text: text == 'Thinking…'):
                for dot in range(3):
                    ui.element('span').classes('thinking-dot').style(f'animation-delay:{dot * .15}s')
        with ui.row().classes('composer gap-2'):
            ctx.prompt = ui.textarea(label='Message', placeholder='Give this agent a task').props(
                'outlined autogrow rows=1 maxlength=16000 dense').classes('flex-1 min-w-0')
            ctx.send_button = ui.button(icon='send').props('aria-label="Send"').mark('Send')
            ctx.stop_button = ui.button(icon='stop', color='negative',
                                    on_click=lambda: protect(ctx.stop_agent)).props('outline aria-label="Stop conversation"').mark('Stop conversation')


def setup_chat(ctx):
    actor, agents, client, identity, protect, runtime, service, state = ctx.actor, ctx.agents, ctx.client, ctx.identity, ctx.protect, ctx.runtime, ctx.service, ctx.state

    def sync_run_details():
        ctx.status_label.set_visibility(bool(ctx.status_label.text))
        ctx.budget_label.set_visibility(bool(ctx.budget_label.text))
        ctx.context_label.set_visibility(bool(ctx.context_label.text))
        ctx.compaction_status.set_visibility(bool(ctx.compaction_status.text))
        ctx.run_details_fallback.set_visibility(not bool(
            ctx.status_label.text or ctx.budget_label.text or ctx.context_label.text or ctx.compaction_status.text
        ))
    ctx.sync_run_details = sync_run_details

    def sync_composer():
        has_text = bool((ctx.prompt.value or '').strip())
        show_stop = bool(state['busy']) and not has_text
        ctx.stop_button.set_visibility(show_stop)
        ctx.send_button.set_visibility(not show_stop)
        ctx.send_button.set_enabled(has_text and not state['submitting'])

    ctx.prompt.on_value_change(lambda _: sync_composer())
    sync_composer()
    ctx.sync_run_details()
    tool_cards = {}
    rendered_parts = []
    rendered_conversation = None
    render_generation = 0
    history_generation = 0
    ctx.selection_lock = asyncio.Lock()

    def activity(event):
        key = (event.get('operation_id'), event.get('call_id', event.get('name')))
        card = tool_cards.get(key)
        if card is None:
            with ctx.transcript:
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
        with ctx.transcript:
            if kind == 'notice':
                return ui.label(content).classes('w-full text-center text-sm text-stone-500').props('role=status')
            if kind == 'tool':
                with ui.expansion('Tool activity', icon='terminal').classes('w-full bg-stone-50 rounded'):
                    ui.label(content[:65536]).classes('whitespace-pre-wrap font-mono text-xs break-all')
            else:
                with ui.chat_message(name='You' if kind == 'human' else 'Agent', sent=kind == 'human').classes(
                        'w-full max-w-full'):
                    if kind == 'agent':
                        return ui.markdown(content, extras=['tables', 'fenced-code-blocks'], sanitize=True).classes(
                            'markdown w-full')
                    else:
                        return ui.label(content).classes('whitespace-pre-wrap break-words')

    def reset_run_details():
        ctx.conversation_card.props(remove='data-operation-id')
        ctx.status_label.set_text('')
        ctx.status_label.props(remove='data-operation-id')
        ctx.reference.set_text('')
        ctx.budget_label.set_text('')
        ctx.context_label.set_text('')
        ctx.compaction_status.set_text('')

    async def histories(renew=True):
        current = await actor(renew=renew)
        if state['agent']:
            rows = await runtime.conversations(current, state['agent'])
            options = {row['id']: (MARKERS[key][0] + ' ' if (key := activity_marker(row, runtime.queued)) else '') + row['title']
                       for row in rows}
            # Keep numeric select values stable when only activity ordering changes.
            if ctx.history_select.options != options:
                ctx.history_select.set_options(options, value=state['conversation'])

    async def show_agent(agent_id, *, close_navigation=True):
        state['requested_agent'] = agent_id
        async with ctx.selection_lock:
            if state['requested_agent'] != agent_id:
                return
            ctx.details_menu.close()
            ctx.run_details_menu.close()
            ctx.agent_heading.disable()
            ctx.tree.classes('pointer-events-none opacity-50').props('aria-disabled=true')
            try:
                await render_agent(agent_id, close_navigation=close_navigation)
            finally:
                ctx.agent_heading.set_enabled(bool(state['agent']))
                ctx.tree.classes(remove='pointer-events-none opacity-50').props(remove='aria-disabled')
    ctx.show_agent = show_agent

    def remember_conversation(conversation_id):
        save_setting(service.store, f'last_conversation:{identity["userid"]}:{state["agent"]}', conversation_id or '')

    def sync_url(skill_id=None):
        # Keep the main pane target in the query string so a reload restores it; ids only, never secrets.
        query = ({'skill': skill_id} if skill_id else {'vm': state['current_vm'], 'mode': ctx.terminal_mode.value}
                 if state.get('current_vm') else {'agent': state['agent']} if state['agent'] else {})
        ui.run_javascript('history.replaceState(null, "", ' + json.dumps('?' + urlencode(query)) + ')')
    ctx.sync_url = sync_url

    async def render_agent(agent_id, *, close_navigation=True):
        ctx.close_active_terminal()
        ctx.set_console_src()
        state['current_vm'] = None
        ctx.terminal_pane.set_visibility(False)
        ctx.conversation_controls.set_visibility(True)
        ctx.conversation_card.set_visibility(True)
        state['drafts'][(state['agent'], state['conversation'])] = ctx.prompt.value or ''
        ctx.prompt.disable()
        try:
            current = await actor()
            agent = await service.authorize(current, agent_id)
        finally:
            ctx.prompt.enable()
        ctx.prompt.set_value(state['drafts'].get((agent_id, None), ''))
        state.update(agent=agent_id, conversation=None, imported=False, active_operation=None, busy=False, indicator='Thinking…', activity_token=None)
        ctx.sync_url()
        sync_composer()
        ctx.prompt.enable()
        reset_run_details()
        ctx.sync_run_details()
        ctx.transcript.clear()
        tool_cards.clear()
        ctx.agent_heading.set_text(agent_label(agents.get(agent_id, agent)))
        ctx.tree.props['selected'] = 'agent:' + agent_id
        ctx.tree.update()
        if close_navigation:
            ctx.close_drawer()
        ctx.details.clear()
        domain = next((d for d in state['data'].get('domains', []) if d['id'] == agent['domain_id']), {})
        with ctx.details:
            with ui.row().classes('w-full min-w-0 items-center gap-3'):
                ui.label(agent_label(agents.get(agent_id, agent))).classes('text-xl font-semibold break-words')
                ui.badge('Root administrator' if agents.get(agent_id, agent).get('is_global')
                         else 'Domain administrator', color='primary')
                ui.space()
                ui.button(icon='close', on_click=ctx.details_menu.close).props('flat round aria-label="Close agent details"')
            with ui.row().classes('w-full items-center justify-end gap-2 no-wrap'):
                ui.button('Configure', icon='tune', on_click=lambda: protect(ctx.configure_agent)).props('flat')
                if await service.subgroup_capability(agent_id):
                    ui.button('Create subgroup', icon='create_new_folder',
                              on_click=lambda: protect(ctx.subgroup_dialog)).props('outline')
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
        remembered = service.store.one('SELECT value FROM platform_settings WHERE name=?',
                                       (f'last_conversation:{identity["userid"]}:{agent_id}',))
        conversation_id = remembered['value'] if remembered else None
        if (not remembered or conversation_id) and conversation_id not in ctx.history_select.options:
            conversation_id = next(iter(ctx.history_select.options), None)
        if conversation_id:
            generation = history_generation
            restored = await runtime.restore(current, conversation_id)
            if generation == history_generation:
                await ctx.render_history(restored)
                ctx.prompt.set_value(state['drafts'].get((agent_id, conversation_id), ''))
        ctx.history_select.set_value(state['conversation'])
        with ctx.details:
            with ui.expansion('Virtual machines', icon='dns').classes('w-full'):
                try:
                    vms = await service.vm_overview(current, agent_id)
                    if not vms:
                        ui.label('No virtual machines in this scope.').classes('text-sm')
                    for vm in vms:
                        ui.label(f"{vm.get('name', vm.get('id', 'VM'))} · {vm.get('state', 'Unknown')}").classes('font-medium')
                        if vm.get('address'):
                            target = (vm['username'] + '@' if vm.get('username') else '') + vm['address']
                            ui.label(f"SSH: {target} · Port {vm.get('port', 22)}").classes('text-sm break-all')
                        if vm.get('cloudstack_url'):
                            ui.link('Open VM in CloudStack', vm['cloudstack_url'], new_tab=True).props('rel="noopener noreferrer"')
                except Exception as exc:
                    ui.label(str(diagnose(exc, agent_id=agent_id))).classes('text-sm text-amber-900')

    async def choose_history(event):
        nonlocal history_generation
        if not event.value or event.value == state['conversation']:
            return
        history_generation += 1
        generation, agent_id = history_generation, state['agent']
        ctx.prompt.disable()
        try:
            restored = await runtime.restore(await actor(), event.value)
        finally:
            ctx.prompt.enable()
        if generation != history_generation or agent_id != state['agent'] or client.is_deleted:
            return
        if restored['agent_id'] != state['agent']:
            raise PermissionError('Conversation belongs to another agent')
        state['drafts'][(state['agent'], state['conversation'])] = ctx.prompt.value or ''
        ctx.prompt.set_value(state['drafts'].get((state['agent'], restored['id']), ''))
        await ctx.render_history(restored)

    async def render_history(restored):
        nonlocal rendered_conversation, render_generation
        render_generation += 1
        generation = render_generation
        if state['conversation'] != restored['id']:
            remember_conversation(restored['id'])
        state['conversation'] = restored['id']
        state['imported'] = bool(restored.get('imported'))
        state['active_operation'] = None
        state['busy'] = False
        state['indicator'] = 'Thinking…'
        service.store.execute(
            'INSERT INTO conversation_seen(human_id,conversation_id,seen) SELECT human_id,id,? FROM conversations WHERE id=? '
            'ON CONFLICT(human_id,conversation_id) DO UPDATE SET seen=excluded.seen', (time.time(), restored['id']))
        reset_run_details()
        if restored.get('runs'):
            run = restored['runs'][-1]
            state['active_operation'] = run['id'] if run['status'] == 'running' else None
            state['busy'] = bool(state['active_operation'])
            waiting = state['busy'] and service.store.one(
                "SELECT 1 FROM escalation_requests WHERE run_id=? AND status='pending'", (run['id'],))
            queued = run['id'] in runtime.queued
            state['indicator'] = ('Queued · waiting for a free run slot' if queued else
                                  'Waiting for your decision on an escalation request' if waiting else 'Thinking…')
            reason = (run.get('budget') or {}).get('reason')
            label = ('Blocked / paused' if run['status'] == 'reconciliation' else 'Stopped' if reason == 'stopped' else 'Blocked / paused' if run['status'] == 'interrupted'
                     else 'Queued' if queued else run['status'].capitalize())
            pause_reason = (run.get('budget') or {}).get('pause_reason')
            ctx.status_label.set_text(label + (' · ' + str(pause_reason) if pause_reason else ''))
            ctx.status_label.props(f'data-operation-id="{run["id"]}"')
            ctx.conversation_card.props(f'data-operation-id="{run["id"]}"')
            ctx.reference.set_text('Reference: ' + run['id'])
            if run.get('budget'):
                show_budget(run['budget'])
                if run['budget'].get('compactions'):
                    ctx.compaction_status.set_text('Context compacted.')
        elif state['imported']:
            ctx.status_label.set_text('Imported history is read-only. Sending starts a new conversation.')
        sync_composer()
        ctx.sync_run_details()
        requests = service.store.all(
            'SELECT id,run_id,call_id,status FROM escalation_requests WHERE conversation_id=? ORDER BY created',
            (restored['id'],))
        parts, keys, count = [], [], 0
        for kind, content, key in with_escalation_notices(history_parts(restored), requests):
            parts.append((kind, content))
            if kind == 'activity':
                key = (kind, content.get('type'), content.get('operation_id'), content.get('call_id'))
            elif not key:
                key, count = (kind, count), count + 1
            keys.append(key)
        rendered_keys = [part[0] for part in rendered_parts]
        common = next((i for i, pair in enumerate(zip(rendered_keys, keys, strict=False)) if pair[0] != pair[1]),
                      min(len(keys), len(rendered_keys)))
        rebuild = (rendered_conversation != restored['id'] or not ctx.transcript.default_slot.children
                   or common < len(rendered_parts))
        offset = None
        if rebuild:
            if rendered_conversation == restored['id'] and not ctx.autoscroll.value:
                offset = await ui.run_javascript(
                    f'getHtmlElement({ctx.transcript_scroll.id})?.querySelector(".q-scrollarea__container")?.scrollTop')
            ctx.transcript.clear()
            tool_cards.clear()
            rendered_parts.clear()
        rendered_conversation = restored['id']
        for index, ((kind, content), key) in enumerate(zip(parts, keys, strict=True)):
            if index < len(rendered_parts):
                _, previous, element = rendered_parts[index]
                if previous == content:
                    continue
                if kind == 'activity':
                    activity(content)
                elif kind == 'agent':
                    element.set_content(content)
                else:
                    element.set_text(content)
                rendered_parts[index] = (key, content, element)
            else:
                element = activity(content) if kind == 'activity' else message(kind, content)
                rendered_parts.append((key, content, element))
            if index % 20 == 0:
                await asyncio.sleep(0)
                if client.is_deleted or generation != render_generation or state['conversation'] != restored['id']:
                    return
        if ctx.autoscroll.value:
            ui.run_javascript(
                f'requestAnimationFrame(() => {{ const c = getHtmlElement({ctx.transcript_scroll.id})'
                '?.querySelector(".q-scrollarea__container"); if (c) c.scrollTop = c.scrollHeight; })'
            )
        elif offset:
            ui.run_javascript(
                f'requestAnimationFrame(() => {{ const c = getHtmlElement({ctx.transcript_scroll.id})'
                f'?.querySelector(".q-scrollarea__container"); if (c) c.scrollTop = {offset}; }})'
            )
        state['activity_token'] = None
    ctx.render_history = render_history

    async def poll_activity():
        if client.is_deleted or not state['agent'] or state['submitting']:
            return
        agent_id, conversation_id = state['agent'], state['conversation']
        try:
            current = await actor(renew=False)
            await ctx.refresh_escalations(current)
            rows = conversation_activity(service.store, current['userid'], list(agents))
            selected = next((row for row in rows if row['id'] == conversation_id), None)
            if selected:
                decisions = tuple((row['id'], row['status'], row['updated']) for row in ctx.escalation_rows
                                  if row['conversation_id'] == conversation_id)
                activity_token = (selected['operation_id'], selected['status'], selected['updated'], decisions,
                                  selected['operation_id'] in runtime.queued)
                if activity_token != state['activity_token']:
                    restored = await runtime.restore(current, conversation_id)
                    if state['agent'] == agent_id and state['conversation'] == conversation_id:
                        await ctx.render_history(restored)
                        state['activity_token'] = activity_token
            await histories(renew=False)
            markers = [(row['agent_id'], activity_marker(row)) for row in rows if row['id'] != conversation_id]
            attention = {agent: 'blocked' if (agent, 'blocked') in markers else 'unread'
                         for agent, marker in markers if marker in ('blocked', 'unread')}
            if mark_attention(ctx.tree.props['nodes'], attention):
                ctx.tree.update()
        except Exception:
            # Authentication redirects through actor; transient refresh failures retry next tick.
            return

    async def new_conversation():
        nonlocal history_generation
        history_generation += 1
        remember_conversation(None)
        state['drafts'][(state['agent'], state['conversation'])] = ctx.prompt.value or ''
        ctx.prompt.set_value(state['drafts'].get((state['agent'], None), '') if state['conversation'] else '')
        state.update(conversation=None, active_operation=None, busy=False, imported=False,
                     activity_token=None)
        sync_composer()
        reset_run_details()
        ctx.sync_run_details()
        ctx.history_select.set_value(None)
        ctx.transcript.clear()
        tool_cards.clear()
        await actor()

    def show_context(context):
        estimate = context.get('estimated_tokens')
        usable = context.get('usable_tokens')
        window, reserve = context.get('context_window'), context.get('response_reserve')
        if (type(estimate) is not int or estimate < 0
                or usable is not None and (type(usable) is not int or usable <= 0)
                or usable and (type(window) is not int or type(reserve) is not int)):
            ctx.context_label.set_text('Context usage unavailable for this activity.')
            ctx.sync_run_details()
            return
        if usable:
            usage = f'Context: ~{estimate:,} / {usable:,} usable tokens ({100 * estimate / usable:.1f}%)'
            usage += f' · Window {window:,} − response reserve {reserve:,}'
        else:
            usage = f'Context: ~{estimate:,} tokens · model context limit unavailable'
        if context.get('threshold_percent') is not None:
            usage += f" · Auto-compact at {context['threshold_percent']}%"
        ctx.context_label.set_text(usage + (' · ' + context['source'] if context.get('source') else ''))
        ctx.sync_run_details()

    def show_budget(budget):
        if budget.get('context'):
            show_context(budget['context'])
        ctx.budget_label.set_text(f"Requests: {budget.get('requests', 0)} · Tools: {budget.get('tool_calls', 0)}")
        ctx.sync_run_details()

    async def stop_agent():
        operation_id = state['active_operation']
        if not operation_id:
            return
        ctx.stop_button.disable()
        try:
            current = await actor()
            result = await runtime.stop(current, operation_id)
            if state['active_operation'] != operation_id:
                return
            if result['status'] == 'running':
                ctx.status_label.set_text('Stop requested · waiting for active work to finish')
                ctx.sync_run_details()
                return
            restored = await runtime.restore(current, state['conversation'])
            if state['active_operation'] == operation_id:
                await ctx.render_history(restored)
        finally:
            ctx.stop_button.enable()
    ctx.stop_agent = stop_agent

    async def send():
        text = (ctx.prompt.value or '').strip()
        if state['submitting'] or not state['agent'] or not text:
            return
        state['submitting'] = True
        sync_composer()
        agent_id, conversation_id = state['agent'], state['conversation']
        try:
            current = await actor()
            await service.authorize(current, agent_id)
            result = await runtime.submit(current, agent_id, conversation_id, text)
            if state['agent'] == agent_id and state['conversation'] == conversation_id:
                ctx.prompt.set_value('')
                state['drafts'].pop((agent_id, conversation_id), None)
                remember_conversation(result['conversation_id'])
                state['conversation'] = result['conversation_id']
                state['activity_token'] = None
                await ctx.render_history(await runtime.restore(current, result['conversation_id']))
                await histories()
        finally:
            state['submitting'] = False
            sync_composer()

    ui.timer(1.0, poll_activity)
    ctx.history_select.on_value_change(lambda e: protect(lambda: choose_history(e)))
    ctx.new_button.on_click(lambda: protect(new_conversation))
    ctx.send_button.on_click(lambda: protect(send))
