import html
import json

from nicegui import ui


def agent_label(agent):
    if agent.get('is_global'):
        return 'Global Admin'
    return 'Main Agent' if agent.get('is_main') else agent['name']


def hierarchy_nodes(data, mode='Agents', show_aliases=False, show_all_domains=False):
    """Join authoritative CloudStack parents to managed-agent presentation metadata."""
    selected = set(mode) if isinstance(mode, (list, tuple, set)) else set(mode.split(' and '))

    def vm_label(vm):
        alias = vm.get('displayname')
        return alias if (show_aliases and alias and alias != vm.get('name')) else (vm.get('name') or vm['id'])

    global_agents = [a for a in data.get('agents', []) if a.get('is_global')]
    agents = {a['domain_id']: a for a in data.get('agents', []) if not a.get('is_global')}
    resources_by_agent = {}
    if 'VMs' in selected:
        for vm in data.get('vms', []):
            if vm.get('owner_agent'):
                resources_by_agent.setdefault(vm['owner_agent'], []).append({
                    'id': 'vm:' + vm['id'], 'label': vm_label(vm), 'icon': 'dns', 'children': []})
    if 'Skills' in selected:
        for skill in data.get('skills', []):
            resources_by_agent.setdefault(skill['creator_agent_id'], []).append({
                'id': 'skill:' + skill['id'], 'label': skill['name'], 'icon': 'description', 'children': []})

    # By default keep only domains holding this hub's agents plus the path of ancestors leading to them.
    parents = {d['id']: d.get('parentdomainid') for d in data.get('domains', [])}
    keep = set()
    for domain_id in agents:
        while domain_id in parents and domain_id not in keep:
            keep.add(domain_id)
            domain_id = parents[domain_id]
    shown = [d for d in data.get('domains', []) if show_all_domains or d['id'] in keep]

    domains, roots = {}, []
    for domain in shown:
        agent = agents.get(domain['id'])
        node_id = 'agent:' + agent['id'] if agent else 'domain:' + domain['id']
        label = agent_label(agent) if agent else domain['name']
        icon = 'smart_toy' if agent else 'folder'
        children = list(resources_by_agent.get(agent['id'], [])) if agent else []
        domains[domain['id']] = {'id': node_id, 'label': label, 'icon': icon, 'children': children}

    for domain in shown:
        node = domains[domain['id']]
        parent = domains.get(domain.get('parentdomainid'))
        if parent is None or parent is node:
            roots.append(node)
        else:
            parent['children'].append(node)

    # Keep the global identity separate from the native domain hierarchy.
    native_roots = {d['id'] for d in data.get('domains', [])
                    if d.get('path') == 'ROOT' or d.get('level') == 0 or
                    (d['name'] == 'ROOT' and not d.get('parentdomainid'))}
    global_nodes = []
    for agent in global_agents:
        children = list(resources_by_agent.get(agent['id'], []))
        global_nodes.append({'id': 'agent:' + agent['id'], 'label': agent_label(agent),
                             'icon': 'admin_panel_settings', 'children': children})

    all_nodes = global_nodes + [
        child for node in roots for child in
        (node['children'] if node['id'].startswith('domain:') and node['id'].removeprefix('domain:') in native_roots else [node])
    ]

    if 'Agents' not in selected:
        def prune_and_mark(node):
            valid_children = []
            has_resource_in_sub = False
            for c in node.get('children', []):
                if c['id'].startswith(('vm:', 'skill:')):
                    valid_children.append(c)
                    has_resource_in_sub = True
                else:
                    child_pruned, child_has_resource = prune_and_mark(c)
                    if child_has_resource:
                        valid_children.append(child_pruned)
                        has_resource_in_sub = True
            if has_resource_in_sub:
                new_node = dict(node)
                new_node['children'] = valid_children
                new_node['selectable'] = False
                return new_node, True
            return None, False

        pruned = []
        for n in all_nodes:
            p, has_resource = prune_and_mark(n)
            if has_resource:
                pruned.append(p)
        return pruned

    return all_nodes


def mark_attention(nodes, attention):
    """Set attention markers (blocked/unread) in place on agent nodes and their ancestors; True when any node changed."""
    changed = False
    for node in nodes:
        changed = mark_attention(node.get('children', []), attention) or changed
        found = {attention.get(node['id'].removeprefix('agent:')) if node['id'].startswith('agent:') else None}
        found |= {child.get('attention') for child in node.get('children', [])}
        marker = 'blocked' if 'blocked' in found else 'unread' if 'unread' in found else None
        if node.get('attention') != marker:
            node['attention'], changed = marker, True
    return changed


def build_sidebar(ctx):
    data, identity, protect = ctx.data, ctx.identity, ctx.protect

    # QDrawer owns responsive visibility; a server model can lag a viewport change and reopen it.
    with ui.left_drawer(value=False).props('show-if-above breakpoint=900 bordered width=300 '
            ':model-value="null"').classes('bg-stone-50') as ctx.drawer:
        # Same 900px as the breakpoint above: wide screens keep the drawer pinned open.
        ctx.close_drawer = lambda: ui.run_javascript(
            f'if (innerWidth < 900) runMethod({ctx.drawer.id}, "hide", [])')
        with ui.column().classes('h-full w-full no-wrap p-3 gap-3'):
            with ui.row().classes('w-full items-center no-wrap'):
                ctx.sidebar_select = ui.select(['Agents', 'VMs', 'Skills'], multiple=True, value=['Agents']).props(
                    'dense options-dense').classes('sidebar-view-select text-base font-semibold min-w-[140px] max-w-[180px]').mark('sidebar_view_select')
                ctx.sidebar_select.disable()
                ui.space()
                ui.button(icon='close', on_click=lambda: ctx.drawer.run_method('hide')).props('flat round aria-label="Close agent hierarchy"')
                ctx.refresh_button = ui.button(icon='refresh').props('flat round aria-label="Refresh hierarchy"')
            ctx.alias_switch = ui.switch('Show aliases', value=False).props('dense').classes(
                'sidebar-show-aliases text-xs text-stone-600').mark('sidebar_show_aliases')
            ctx.alias_switch.disable()
            ctx.alias_switch.set_visibility('VMs' in (ctx.sidebar_select.value or []))
            ctx.domains_switch = ui.switch('Show all domains', value=False).props('dense').classes(
                'sidebar-show-domains text-xs text-stone-600').mark('sidebar_show_domains')
            ctx.domains_switch.disable()
            ctx.new_skill_button = ui.button('New skill', icon='add', on_click=lambda: protect(lambda: ctx.open_skill())).props('outline').classes('w-full')
            ctx.new_skill_button.set_visibility(False)
            ctx.search = ui.input('Search agents and domains').props('clearable').classes('w-full')
            with ui.scroll_area().classes('w-full flex-1 min-h-0'):
                ctx.tree = ui.tree(hierarchy_nodes(data, mode=ctx.sidebar_select.value, show_aliases=ctx.alias_switch.value,
                                                show_all_domains=ctx.domains_switch.value)).props('dense selected-color=primary').classes('w-full').mark('hierarchy')
                ctx.tree.add_slot('default-header', '''<div class="row items-center no-wrap" style="min-width:0" :title="props.node.label">
                    <q-icon :name="props.node.icon" size="sm" class="q-mr-sm" />
                    <span class="ellipsis">{{ props.node.label }}</span>
                    <q-badge v-if="props.node.attention" rounded color="teal-8" class="q-ml-sm" role="img"
                    :aria-label="props.node.attention === 'blocked' ? 'Blocked or paused conversation' : 'Unread conversation output'" /></div>''')
            ctx.status = ui.label(str(data.get('status', 'CloudStack connected'))).classes('text-xs text-stone-600')
            if identity.get('type') == 1:
                ctx.dashboard_link('dashboard-mobile w-full text-teal-900')
            with ui.button('Settings', icon='settings').props('outline aria-haspopup="menu"').classes('w-full').mark('settings_button'):
                with ui.menu().classes('bg-white p-2 min-w-[200px]').mark('settings_menu') as ctx.settings_menu:
                    with ui.column().classes('gap-1 p-0 w-full'):
                        ctx.autoscroll = ui.switch('Chat autoscroll',
                            value=not ctx.autoscroll_setting or ctx.autoscroll_setting['value'] != 'false',
                            on_change=lambda: protect(ctx.save_autoscroll)).mark('chat_autoscroll')
                        if identity.get('type') == 1:
                            ctx.providers_button = ui.button('Model providers', icon='settings').props('flat no-caps align=left').classes('w-full')
                            ctx.platform_button = ui.button('Platform settings', icon='admin_panel_settings').props('flat no-caps align=left').classes('w-full')
                            ctx.gpu_button = ui.button('GPU policies', icon='memory').props('flat no-caps align=left').classes('w-full')
                        else:
                            ctx.providers_button = None
                            ctx.platform_button = None
                            ctx.gpu_button = None
                        ui.html('<form method="post" action="/auth/logout" class="w-full" onsubmit="window.socket?.disconnect()"><input type="hidden" name="csrf" value="'
                                + html.escape(identity['csrf'], quote=True)
                                + '"><button type="submit" class="w-full text-left px-3 py-2 rounded hover:bg-stone-100">Sign out</button></form>',
                                sanitize=False)


def setup_sidebar(ctx):
    actor, agents, identity, protect, service, state = ctx.actor, ctx.agents, ctx.identity, ctx.protect, ctx.service, ctx.state

    def update_sidebar_view():
        has_vms = 'VMs' in (ctx.sidebar_select.value or [])
        ctx.alias_switch.set_visibility(has_vms)
        ctx.new_skill_button.set_visibility('Skills' in (ctx.sidebar_select.value or []))
        ui.run_javascript(f'try {{ localStorage.setItem({sidebar_key}, '
                          + json.dumps(json.dumps({'view': ctx.sidebar_select.value, 'aliases': ctx.alias_switch.value,
                                                                      'all_domains': ctx.domains_switch.value})) + ') } catch (_) {}')
        ctx.tree.props['nodes'] = hierarchy_nodes(
            state.get('data', {}), mode=ctx.sidebar_select.value, show_aliases=ctx.alias_switch.value,
            show_all_domains=ctx.domains_switch.value
        )
        if has_vms or 'Skills' in (ctx.sidebar_select.value or []):
            ctx.tree.expand()
        ctx.tree.update()

    async def refresh():
        current = await actor()
        updated = await service.hierarchy(current)
        state['data'] = updated
        agents.clear()
        agents.update({row['id']: row for row in updated.get('agents', [])})
        ctx.tree.props['nodes'] = hierarchy_nodes(
            updated, mode=ctx.sidebar_select.value, show_aliases=ctx.alias_switch.value,
            show_all_domains=ctx.domains_switch.value
        )
        if set(ctx.sidebar_select.value or []) & {'VMs', 'Skills'}:
            ctx.tree.expand()
        ctx.tree.update()
        ctx.status.set_text(str(updated.get('status', 'CloudStack connected')))
    ctx.refresh = refresh

    async def select_node(event):
        value = event.value
        if not value and (event.previous_value or '').startswith('agent:'):
            # Quasar unselects a re-clicked node: keep the agent highlighted and treat it as a re-selection.
            value = ctx.tree.props['selected'] = event.previous_value
            ctx.tree.update()
        if ctx.selection_lock.locked() or not value:
            return
        if 'Agents' not in (ctx.sidebar_select.value or []) and not value.startswith(('vm:', 'skill:')):
            return
        kind, identifier = value.split(':', 1)
        if kind == 'agent':
            if identifier != state.get('requested_agent', state['agent']) or ctx.terminal_pane.visible:
                await ctx.show_agent(identifier)
            else:
                ctx.close_drawer()
        elif kind == 'domain':
            current = await actor()
            updated = await service.hierarchy(current)
            domain = next((d for d in updated.get('domains', []) if d['id'] == identifier), None)
            if domain is None:
                raise PermissionError('Domain unavailable')
            with ui.dialog() as domain_dialog, ui.card().classes('w-full max-w-xl'):
                ui.label(domain['name']).classes('text-2xl font-semibold')
                ui.label(domain.get('path', '')).classes('text-stone-600')
                ui.label('CloudStack domain: ' + identifier).classes('text-xs text-stone-500 break-all')
                async def choose_domain_agent(agent_id):
                    domain_dialog.close()
                    await ctx.show_agent(agent_id)
                for agent in updated.get('agents', []):
                    if agent['domain_id'] == identifier:
                        ui.button('Chat with ' + agent['name'],
                                  on_click=lambda _, aid=agent['id']: protect(lambda: choose_domain_agent(aid)))
                if not any(a['domain_id'] == identifier for a in updated.get('agents', [])):
                    allowed = await service.can_add_agent(current)
                    with ui.row().classes('w-full items-center no-wrap') as add_row:
                        name = ui.input('Agent name', value=domain['name'][:64]).props('maxlength=64').classes('flex-1')
                        add_button = ui.button('Add agent here', icon='add', on_click=lambda: protect(add_agent)).props(
                            'outline' + ('' if allowed else ' disable')).mark('add_domain_agent')
                    if not allowed:
                        add_row.tooltip('Your CloudStack role cannot create accounts here')
                        name.disable()

                    async def add_agent():
                        add_button.disable()
                        try:
                            child = await service.add_domain_agent(await actor(), identifier, name.value.strip())
                        finally:
                            add_button.enable()
                        domain_dialog.close()
                        await ctx.refresh()
                        await ctx.show_agent(child['id'])
                ui.button('Close', on_click=domain_dialog.close).props('flat')
            ctx.drawer.run_method('hide')
            domain_dialog.open()
        elif kind == 'vm':
            await ctx.show_vm(identifier)
        elif kind == 'skill':
            await ctx.open_skill(identifier)

    def filter_tree():
        ctx.tree.props['filter'] = ctx.search.value or ''
        if ctx.search.value:
            ctx.tree.expand()
        else:
            ctx.tree.collapse()
        ctx.tree.update()

    async def open_dialog(dialog_fn):
        ctx.settings_menu.close()
        await dialog_fn()

    ctx.search.on_value_change(filter_tree)
    ctx.tree.on_select(lambda e: protect(lambda: select_node(e)))
    ctx.refresh_button.on_click(lambda: protect(ctx.refresh))
    last_view = list(ctx.sidebar_select.value or ['Agents'])

    def select_sidebar_view(e):
        nonlocal last_view
        val = [x for x in (e.value or []) if x in {'Agents', 'VMs', 'Skills'}]
        if not val:
            ctx.sidebar_select.set_value(last_view)
            return
        last_view = list(val)
        update_sidebar_view()

    ctx.sidebar_select.on_value_change(select_sidebar_view)
    ctx.alias_switch.on_value_change(lambda _: update_sidebar_view())
    ctx.domains_switch.on_value_change(lambda _: update_sidebar_view())
    sidebar_key = json.dumps('dirigentenstab.sidebar.' + str(identity.get('userid', '')))

    async def restore_sidebar():
        try:
            saved = json.loads(await ui.run_javascript(
                f'try {{ return localStorage.getItem({sidebar_key}) }} catch (_) {{ return null }}') or '{}')
            raw_view = saved.get('view')
            view = ([x for x in raw_view if isinstance(x, str) and x in {'Agents', 'VMs', 'Skills'}]
                    if isinstance(raw_view, list) else [])
            ctx.alias_switch.set_value(saved.get('aliases') is True)
            ctx.domains_switch.set_value(saved.get('all_domains') is True)
            if view:
                ctx.sidebar_select.set_value(view)
        except (ValueError, TypeError, AttributeError):
            pass  # Corrupt or foreign value: keep defaults.
        finally:
            ctx.sidebar_select.enable()
            ctx.alias_switch.enable()
            ctx.domains_switch.enable()

    ui.timer(0.01, lambda: protect(restore_sidebar), once=True)

    if ctx.providers_button is not None:
        ctx.providers_button.on_click(lambda: protect(lambda: open_dialog(ctx.provider_dialog)))

    if ctx.platform_button is not None:
        ctx.platform_button.on_click(lambda: protect(lambda: open_dialog(ctx.platform_dialog)))

    if ctx.gpu_button is not None:
        ctx.gpu_button.on_click(lambda: protect(lambda: open_dialog(ctx.gpu_dialog)))
