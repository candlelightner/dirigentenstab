import httpx
from nicegui import ui

from .diagnostics import diagnose
from .web_sidebar import agent_label


def setup_agent_dialogs(ctx):
    actor, agents, protect, runtime, service, state = ctx.actor, ctx.agents, ctx.protect, ctx.runtime, ctx.service, ctx.state

    async def open_skill(skill_id=None):
        ctx.tree.props['selected'] = None
        ctx.tree.update()
        current = await actor()
        skill = await service.get_skill(current, skill_id) if skill_id else {
            'creator_agent_id': state['agent'], 'name': '', 'description': '', 'text': '',
            'shared_agent_ids': [], 'can_edit': True, 'shareable_agents': [], 'global_shared': False,
        }
        if not skill['creator_agent_id']:
            raise ValueError('Select an agent before creating a skill')
        editable = skill['can_edit']
        with ui.dialog() as skill_dialog, ui.card().classes('w-full max-w-2xl min-w-0 gap-3').style(
                'max-height:90vh;overflow:auto'):
            ui.label('Skill' if skill_id else 'New skill').classes('text-xl font-semibold')
            creator = agents.get(skill['creator_agent_id'])
            ui.label('Creator: ' + (agent_label(creator) if creator else skill['creator_agent_id'])).classes('text-sm text-stone-600')
            name = ui.input('Skill name', value=skill['name']).props('maxlength=100').classes('w-full')
            description = ui.textarea('Short description', value=skill['description']).props(
                'rows=2 maxlength=500').classes('w-full')
            text = ui.textarea('Full text', value=skill['text']).props('rows=8 maxlength=60000').classes('w-full')
            for field in (name, description, text):
                field.set_enabled(editable)
            sharing = ui.select({agent['id']: agent['name'] for agent in skill['shareable_agents']},
                                multiple=True, value=skill['shared_agent_ids'],
                                label='Share with children').classes('w-full')
            sharing.set_visibility(bool(skill_id and editable and skill['shareable_agents']))
            if skill['global_shared']:
                ui.label('This revision is shared globally. Editing requires approval again.').classes(
                    'text-sm text-stone-600')

            async def save():
                saved = skill
                if not skill_id or (name.value, description.value, text.value) != (
                        skill['name'], skill['description'], skill['text']):
                    saved = await service.save_skill(await actor(), skill['creator_agent_id'], name.value or '',
                                                     description.value or '', text.value or '', skill_id=skill_id)
                if skill_id:
                    await service.share_skill(await actor(), saved['id'], sharing.value or [])
                await ctx.refresh()
                skill_dialog.close()
                ui.notify('Skill saved', type='positive')

            async def review_global():
                with ui.dialog() as approval_dialog, ui.card().classes('w-full max-w-2xl min-w-0 gap-3').style(
                        'max-height:90vh;overflow:auto'):
                    ui.label('Approve global sharing').classes('text-xl font-semibold')
                    ui.label('Revision ' + str(skill['revision'])).classes('text-sm')
                    ui.label(skill['name']).classes('font-semibold break-all')
                    ui.label(skill['description']).classes('whitespace-pre-wrap break-words')
                    ui.label(skill['text']).classes('w-full whitespace-pre-wrap break-words')
                    ui.label('All agents can read this revision. Edits require a new approval.').classes('text-sm')

                    async def approve():
                        await service.approve_skill_global(await actor(), skill_id, skill['revision'])
                        await ctx.refresh()
                        approval_dialog.close()
                        skill_dialog.close()
                        ui.notify('Skill shared globally', type='positive')

                    with ui.row():
                        ui.button('Approve', on_click=lambda: protect(approve))
                        ui.button('Cancel', on_click=approval_dialog.close).props('flat')
                approval_dialog.open()

            async def delete():
                with ui.dialog() as confirm_dialog, ui.card():
                    ui.label(f'Delete skill {skill["name"]}?')
                    with ui.row():
                        ui.button('Delete', on_click=lambda: confirm_dialog.submit(True)).props('color=negative')
                        ui.button('Cancel', on_click=lambda: confirm_dialog.submit(False)).props('flat')
                confirmed = await confirm_dialog
                confirm_dialog.delete()
                if confirmed:
                    await service.delete_skill(await actor(), skill_id)
                    await ctx.refresh()
                    skill_dialog.close()
                    ui.notify('Skill deleted', type='positive')

            with ui.row().classes('w-full items-center gap-2'):
                if editable:
                    ui.button('Save skill', on_click=lambda: protect(save))
                if skill_id and editable and current.get('type') == 1 and not skill['global_shared']:
                    global_button = ui.button('Approve global sharing', on_click=lambda: protect(review_global)).props('outline')

                    def changed():
                        global_button.set_enabled((name.value, description.value, text.value) == (
                            skill['name'], skill['description'], skill['text']))

                    for field in (name, description, text):
                        field.on_value_change(changed)
                if skill_id and current.get('type') == 1:
                    ui.button('Delete', on_click=lambda: protect(delete)).props('outline color=negative')
                ui.button('Close', on_click=skill_dialog.close).props('flat')
        ctx.drawer.run_method('hide')
        ctx.sync_url(skill_id)
        skill_dialog.on('hide', lambda: ctx.sync_url())
        skill_dialog.open()
    ctx.open_skill = open_skill

    async def mcp_dialog(agent_id):
        from .mcp import MCP

        integration = MCP(service)
        configuration = await integration.configuration(await actor(), agent_id)
        servers = {server['id']: server for server in configuration['servers']}
        manage = configuration['can_manage_servers']
        with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl gap-3'):
            ui.label('MCP tools').classes('text-xl font-semibold')
            ui.label('Global Admin starts with all tools enabled. Every ancestor limits descendant access. '
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
            agent_enabled = ui.checkbox('Enable server for this agent', value=True)
            ui.label('Available tools').classes('font-semibold')
            tool_list = ui.column().classes('w-full shrink-0 max-h-64 overflow-y-auto gap-2')
            inherited = ui.label('').classes('text-sm whitespace-pre-wrap')
            discovery_status = ui.label('').props('role=status').classes('text-sm')
            feedback = ui.label('').props('role=status').classes('text-sm')
            choices = {key: set(row['tools']) for key, row in servers.items()}
            catalogues, checkboxes = {}, {}
            displayed, ready, generation = None, None, 0

            def remember():
                if displayed and (catalogues.get(displayed) or '*' not in choices.get(displayed, set())):
                    choices[displayed] = {name for name, checkbox in checkboxes.items() if checkbox.value}

            def render(server_id):
                nonlocal displayed
                displayed = server_id
                checkboxes.clear()
                tool_list.clear()
                catalogue = catalogues.get(server_id, {})
                checked = choices.get(server_id, set())
                with tool_list:
                    for tool_name in sorted(catalogue.keys() | (checked - {'*'})):
                        with ui.column().classes('w-full shrink-0 gap-0 min-w-0'):
                            checkboxes[tool_name] = ui.checkbox(tool_name, value='*' in checked or tool_name in checked)
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
                agent_enabled.set_value(row.get('agent_enabled', True))
                agent_enabled.set_enabled(bool(row) and row.get('server_allowed', True))
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
                await integration.set_enabled(await actor(), agent_id, server_id, bool(agent_enabled.value))
                servers[server_id]['agent_enabled'] = bool(agent_enabled.value)
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
        ctx.details_menu.close()
        current = await actor()
        agent = await service.authorize(current, state['agent'])
        provider_rows = await service.providers(current)
        options = {p['id']: p['name'] for p in provider_rows}
        default_models = {p['id']: p.get('default_model') for p in provider_rows}
        with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl gap-4'):
            ui.label('Configure ' + agent['name']).classes('text-xl font-semibold')
            key_access = await service.owner_ssh_key_access(agent)
            owner_key_enabled = ui.checkbox('Access owner SSH public key', value=key_access['selected'] and key_access['allowed'])
            if not key_access['allowed']:
                owner_key_enabled.disable()
                ui.label('Disabled by an ancestor. The saved selection is retained.').classes('text-sm text-stone-600')
            escalation_access = await service.escalation_access(agent)
            escalation_enabled = ui.checkbox('Request permission escalation', value=escalation_access['selected'] and escalation_access['allowed'])
            if not escalation_access['allowed']:
                escalation_enabled.disable()
                ui.label('Escalation requests disabled by an ancestor. The saved selection is retained.').classes('text-sm text-stone-600')
            provider_access = await service.provider_configuration(current, agent['id'])
            enabled_providers = ui.select(options, label='Enabled providers', multiple=True,
                value=provider_access['selected']).classes('w-full')
            if provider_access['allowed'] is not None:
                ui.label('Ancestor access limits currently available providers. Saved selections are retained.').classes('text-sm text-stone-600')
            secret_access = await service.secret_configuration(current, agent)
            enabled_secrets = ui.select(secret_access['names'], label='Granted secrets', multiple=True,
                value=secret_access['selected']).classes('w-full').mark('enabled-secrets')
            ui.label('Agents see granted secret names only. Ancestor access limits what can be granted.').classes('text-sm text-stone-600')
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
            ui.label('Active conversations pause while settings change, then resume with the new settings.').classes('text-sm text-stone-600')

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
            context_generation = 0
            context_info = {'usable_tokens': None}
            with ui.expansion('Context compaction', value=agent.get('auto_compact_percent') is not None).classes('w-full'):
                automatic = ui.checkbox('Automatically compact context', value=agent.get('auto_compact_percent') is not None)
                auto_percent = ui.number('Compact at % of usable context', value=agent.get('auto_compact_percent') or 75,
                                         min=1, max=99, precision=0).classes('w-full')
                auto_percent.bind_enabled_from(automatic, 'value')
                compaction_provider = ui.select({'': 'Same as conversation', **options},
                    value=agent.get('compaction_provider_id') or '', label='Compaction provider').classes('w-full')
                saved_compaction_model = agent.get('compaction_model', '')
                compaction_model = ui.select([saved_compaction_model] if saved_compaction_model else [],
                    value=saved_compaction_model or None, label='Compaction model', with_input=True,
                    new_value_mode='add-unique').classes('w-full')
                compaction_model.bind_visibility_from(compaction_provider, 'value', backward=bool)
                compaction_model.bind_enabled_from(compaction_provider, 'value', backward=bool)
                compaction_model_status = ui.label('').classes('text-sm').props('role=status')
                window_override = ui.number('Context window override (tokens, optional)', value=agent.get('context_window'),
                                            min=2, precision=0).props('clearable').classes('w-full')
                ui.label('The conversation model API supplies its context limit unless overridden. '
                         'Usage is estimated; the usable window excludes the response reserve.').classes('text-sm')
                context_source = ui.label('').classes('text-sm').props('role=status')

            async def load_context():
                nonlocal context_generation, context_info
                context_generation += 1
                generation = context_generation
                context_info = {'usable_tokens': None}
                selected_provider, selected_model = provider.value, (model.value or '').strip()
                override = int(window_override.value) if window_override.value is not None else None
                context_source.set_text('Checking conversation context limit…')
                try:
                    current = await actor()
                    limits = (await runtime.context_limits(current, selected_provider, selected_model, override)
                              if selected_provider else {'usable_tokens': None,
                                                        'source': 'Select a conversation provider and model.'})
                    if (generation != context_generation or provider.value != selected_provider
                            or (model.value or '').strip() != selected_model):
                        return
                    context_info = limits
                    if limits.get('usable_tokens'):
                        context_source.set_text(f"Usable context: {limits['context_window']:,} − "
                            f"{limits['response_reserve']:,} response tokens = {limits['usable_tokens']:,} tokens. "
                            + limits['source'])
                    else:
                        context_source.set_text(limits['source'] + ' Enter a context window override before enabling automatic compaction.')
                except Exception as exc:
                    if generation == context_generation:
                        context_info = {'usable_tokens': None}
                        error = diagnose(exc, agent_id=agent['id'], tool='context_limits')
                        context_source.set_text(str(error) + ' Context limit unavailable; enter a manual override for automatic compaction.')

            async def load_compaction_models():
                selected_provider = compaction_provider.value
                if not selected_provider:
                    compaction_model_status.set_text('Uses the conversation provider and model.')
                    return
                compaction_model.props('loading')
                try:
                    choices = await runtime.models(await actor(), selected_provider)
                    if compaction_provider.value == selected_provider:
                        selected_model = compaction_model.value
                        compaction_model.set_options(list(dict.fromkeys(([selected_model] if selected_model else []) + choices)),
                                                     value=selected_model)
                        compaction_model_status.set_text('Choose a model or enter a custom model ID.')
                except Exception as exc:
                    if compaction_provider.value == selected_provider:
                        error = diagnose(exc, agent_id=agent['id'], tool='discover_compaction_models')
                        compaction_model_status.set_text(str(error) + ' Enter a compaction model ID manually.')
                finally:
                    if compaction_provider.value == selected_provider:
                        compaction_model.props(remove='loading')

            model.on_value_change(lambda: protect(load_context))
            window_override.on_value_change(lambda: protect(load_context))
            compaction_provider.on_value_change(lambda: protect(load_compaction_models))
            ui.timer(0.01, lambda: protect(load_compaction_models), once=True)

            async def load_models():
                selected_provider = provider.value
                model.props('loading')
                model_status.set_text('Loading models…')
                try:
                    choices = await runtime.models(await actor(), selected_provider) if selected_provider else []
                    if provider.value != selected_provider:
                        return
                    selected_model = model.value or default_models.get(selected_provider) or None
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
                await load_context()

            provider.on_value_change(lambda: protect(provider_changed))
            ui.timer(0.01, lambda: protect(provider_changed), once=True)
            instructions = ui.textarea('System prompt', value=agent.get('instructions', '')).props('maxlength=32000').classes('w-full')
            ui.label('Custom instructions for this agent, applied on its next model call.').classes('text-sm text-stone-600')
            ui.button('MCP tools', icon='extension',
                      on_click=lambda: protect(lambda: mcp_dialog(agent['id']))).props('outline')

            async def save():
                options = {'enabled_providers': enabled_providers.value, 'enabled_secrets': enabled_secrets.value}
                if escalation_access['allowed']:
                    options['escalation_requests_enabled'] = escalation_enabled.value
                if key_access['allowed']:
                    options['owner_ssh_key_enabled'] = owner_key_enabled.value
                if automatic.value and (type(auto_percent.value) not in {int, float}
                                        or not 1 <= auto_percent.value <= 99 or int(auto_percent.value) != auto_percent.value):
                    raise ValueError('Automatic compaction must be a whole percentage from 1 to 99, or disabled')
                if window_override.value is not None and (type(window_override.value) not in {int, float}
                        or not 2 <= window_override.value <= 2147483647 or int(window_override.value) != window_override.value):
                    raise ValueError('Context window must be a whole token count from 2 to 2147483647')
                if automatic.value and not context_info.get('usable_tokens'):
                    raise ValueError('Set a known context window before enabling automatic compaction')
                options.update(compaction_provider_id=compaction_provider.value or None,
                               compaction_model=(compaction_model.value or '').strip() if compaction_provider.value else '',
                               auto_compact_percent=int(auto_percent.value) if automatic.value else None,
                               context_window=int(window_override.value) if window_override.value is not None else None)
                await service.update_agent(await actor(), agent['id'], provider.value,
                                           (model.value or '').strip(), instructions.value or '', thinking=thinking.value, **options)
                await ctx.refresh()
                selected_conversation = state['conversation']
                selected_draft = ctx.prompt.value or ''
                await ctx.show_agent(agent['id'])
                if selected_conversation:
                    await ctx.render_history(await runtime.restore(await actor(), selected_conversation))
                    ctx.prompt.set_value(selected_draft)
                dialog.close()

            async def rotate():
                await service.rotate_credentials(await actor(), agent['id'])
                ui.notify('Agent credentials replaced and previous keys revoked.', type='positive')

            async def revoke():
                await service.revoke_agent(await actor(), agent['id'])
                dialog.close()
                state.update(agent=None, conversation=None)
                ctx.details_menu.close()
                ctx.agent_heading.set_text('Select an agent')
                ctx.agent_heading.disable()
                ctx.status_label.set_text('Agent access revoked')
                ctx.sync_run_details()
                ctx.transcript.clear()
                ctx.details.clear()
                await ctx.refresh()

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
    ctx.configure_agent = configure_agent

    async def subgroup_dialog():
        ctx.details_menu.close()
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
                    await ctx.refresh()
                    await ctx.show_agent(child['id'])
                finally:
                    create_button.enable()
                    result_label.set_text('')

            with ui.row().classes('w-full justify-end'):
                ui.button('Cancel', on_click=dialog.close).props('flat')
                create_button = ui.button('Create subgroup', on_click=lambda: protect(create))
        dialog.open()
    ctx.subgroup_dialog = subgroup_dialog
