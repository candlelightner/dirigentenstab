import base64
import binascii
import json
import math

from nicegui import ui

from .runtime import provider_models, test_provider
from .diagnostics import diagnose


def setup_admin_dialogs(ctx):
    actor, agents, protect, runtime, service = ctx.actor, ctx.agents, ctx.protect, ctx.runtime, ctx.service

    ctx.escalation_rows = []
    deciding_escalations = set()
    detail_request_id = None

    with ui.dialog() as escalation_dialog, ui.card().classes('w-full max-w-xl gap-4'):
        ui.label('Escalation requests').classes('text-xl font-semibold')
        escalation_content = ui.column().classes('w-full min-w-0 gap-2')
        ui.button('Close', on_click=escalation_dialog.close).props('flat')

    with ui.dialog() as escalation_detail_dialog, ui.card().classes('w-full max-w-xl min-w-0 gap-4'):
        escalation_detail_content = ui.column().classes('w-full min-w-0 gap-4')
        ui.button('Back to requests', on_click=escalation_detail_dialog.close).props('flat')

    async def decide_escalation(request_id, approve):
        if request_id in deciding_escalations:
            return
        deciding_escalations.add(request_id)
        render_escalation_detail()
        try:
            await service.decide_escalation(await actor(), request_id, approve)
            if approve:
                await runtime.deliver_escalation_decisions()
        finally:
            deciding_escalations.discard(request_id)
            render_escalation_detail()
            await ctx.refresh_escalations(await actor())

    def render_escalation_detail():
        escalation_detail_content.clear()
        row = next((row for row in ctx.escalation_rows if row['id'] == detail_request_id), None)
        with escalation_detail_content:
            if not row:
                ui.label('Request unavailable.')
                return
            ui.label(agents.get(row['agent_id'], {}).get('name', row['agent_id'])).classes('font-semibold break-all')
            ui.label('Dismissed' if row['status'] == 'deferred' else row['status'].capitalize()).classes('text-sm')
            ui.label('Goal: ' + row['description']).classes('w-full whitespace-pre-wrap break-words font-semibold')
            ui.label('Permission needed: ' + row['reason']).classes('w-full whitespace-pre-wrap break-words text-sm')
            ui.label(row['command']).classes('w-full font-mono font-semibold break-all')
            params = dict(row['params'])
            userdata = params.get('userdata')
            if isinstance(userdata, str):
                try:
                    params['userdata'] = base64.b64decode(userdata, validate=True).decode()
                    ui.label('userdata is shown decoded from base64').classes('text-xs font-semibold')
                except (binascii.Error, UnicodeDecodeError):
                    ui.label('userdata is not valid base64 text; shown as sent').classes('text-xs font-semibold')
            ui.label(json.dumps(params, indent=2, ensure_ascii=False)).classes(
                'w-full whitespace-pre-wrap break-all font-mono text-xs')
            if row['status'] == 'pending':
                with ui.row():
                    approve = ui.button('Approve', on_click=lambda: protect(
                        lambda: decide_escalation(row['id'], True)))
                    dismiss = ui.button('Dismiss', on_click=lambda: protect(
                        lambda: decide_escalation(row['id'], False))).props('outline')
                    approve.set_enabled(row['id'] not in deciding_escalations)
                    dismiss.set_enabled(row['id'] not in deciding_escalations)
            if row.get('result'):
                ui.label(json.dumps(row['result'], indent=2, ensure_ascii=False)).classes(
                    'w-full whitespace-pre-wrap break-all text-xs')

    async def open_escalation_detail(request_id):
        nonlocal detail_request_id
        await ctx.refresh_escalations(await actor())
        detail_request_id = request_id
        render_escalation_detail()
        escalation_detail_dialog.open()

    def render_escalations():
        escalation_content.clear()
        with escalation_content:
            if not ctx.escalation_rows:
                ui.label('No escalation requests.')
            for row in ctx.escalation_rows:
                with ui.button(color=None, on_click=lambda _, request_id=row['id']: protect(
                        lambda: open_escalation_detail(request_id))).props(
                            'flat no-caps aria-haspopup="dialog"').classes(
                                'escalation-summary w-full min-w-0 p-3 border rounded'):
                    with ui.column().classes('w-full min-w-0 gap-1'):
                        ui.label(row['description']).classes('w-full truncate text-left text-base font-bold')
                        ui.label(row['reason']).classes('w-full truncate text-left text-sm text-stone-600')
        render_escalation_detail()

    async def refresh_escalations(current):
        if current.get('type') != 1:
            return
        rows = await service.list_escalation_requests(current)
        count = sum(row['status'] == 'pending' for row in rows)
        ctx.escalation_button.props(f'aria-label="Escalation requests: {count} pending"')
        ctx.escalation_button.classes(add='pending' if count else '', remove='' if count else 'pending')
        if rows != ctx.escalation_rows:
            ctx.escalation_rows = rows
            render_escalations()
    ctx.refresh_escalations = refresh_escalations

    async def open_escalations():
        await ctx.refresh_escalations(await actor())
        render_escalations()
        escalation_dialog.open()
    ctx.open_escalations = open_escalations

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
    ctx.gpu_dialog = gpu_dialog

    async def platform_dialog():
        current = await actor()
        if current.get('type') != 1:
            raise PermissionError('Platform administrator required')
        with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl'):
            ui.label('Platform settings').classes('text-xl font-semibold')
            url = ui.input('CloudStack Dashboard URL', value=service.dashboard_url(current)).classes('w-full')
            ui.label('Browser-accessible private URL. CloudStack uses its own login; blank hides the link.').classes('text-sm')
            owner_key = ui.textarea('Owner SSH public key', value=service.owner_ssh_key(current)).classes('w-full')
            ui.label('Added alongside agent access to compatible new managed VMs.').classes('text-sm')
            request_limit = ui.number('Open escalation requests per agent', value=service.escalation_request_limit(),
                                      min=1, step=1, precision=0).classes('w-full')
            ui.label('Global limit across all conversations. Pending requests and commands being applied count as open.').classes('text-sm')
            ui.separator()
            ui.label('Secrets').classes('font-semibold')
            ui.label('Write-only named values injected by the hub into VM commands and files; agents see names only. '
                     'Granting is per agent in its settings. Setting an existing name replaces its value.').classes('text-sm')
            secret_name = ui.select(service.secret_names(), label='Secret name', with_input=True,
                                    new_value_mode='add-unique').classes('w-full').mark('secret-name')
            secret_value = ui.input('Value (never shown again)', password=True, password_toggle_button=True).classes('w-full').mark('secret-value')

            async def set_secret():
                service.save_secret(await actor(), secret_name.value or '', secret_value.value or '')
                secret_value.set_value('')
                secret_name.set_options(service.secret_names(), value=secret_name.value)
                ui.notify('Secret saved.', type='positive')

            async def delete_secret():
                service.delete_secret(await actor(), secret_name.value or '')
                secret_name.set_options(service.secret_names(), value=None)
                secret_value.set_value('')
                ui.notify('Secret deleted.', type='positive')
            with ui.row().classes('w-full gap-2'):
                ui.button('Set secret', on_click=lambda: protect(set_secret)).props('outline').mark('set-secret')
                ui.button('Delete secret', on_click=lambda: protect(delete_secret), color='negative').props('flat').mark('delete-secret')
            ui.separator()

            async def save():
                actor_identity = await actor()
                if (type(request_limit.value) not in {int, float} or not math.isfinite(request_limit.value)
                        or request_limit.value < 1 or int(request_limit.value) != request_limit.value):
                    raise ValueError('Open escalation requests per agent must be a positive whole number')
                await service.save_owner_ssh_key(actor_identity, owner_key.value or '')
                service.save_escalation_request_limit(actor_identity, int(request_limit.value))
                service.save_dashboard_url(actor_identity, url.value or '')
                value = service.dashboard_url(actor_identity)
                for link in ctx.dashboard_links:
                    link.props['href'] = value or '#'
                    link.set_visibility(bool(value))
                    link.update()
                dialog.close()
            with ui.row():
                ui.button('Cancel', on_click=dialog.close).props('flat')
                ui.button('Save', on_click=lambda: protect(save))
        dialog.open()
    ctx.platform_dialog = platform_dialog

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
                summary_provider.set_options({'': 'Disabled', **{k: p['name'] for k, p in providers.items()}},
                                             value=summary_provider.value)
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
            ui.separator().classes('my-1')
            ui.label('Summary model').classes('text-lg font-semibold')
            ui.label('Globally select a model to name chats after the first message.').classes('text-sm text-stone-600')
            summary = service.summary_settings(current)
            summary_provider = ui.select({'': 'Disabled', **{k: p['name'] for k, p in providers.items()}},
                                         value=summary['provider_id'] or '', label='Summary model provider').classes('w-full')
            saved_summary_model = summary['model']
            summary_model = ui.select([saved_summary_model] if saved_summary_model else [],
                                      value=saved_summary_model or None, label='Summary model ID',
                                      with_input=True, new_value_mode='add-unique').classes('w-full')
            summary_model_status = ui.label('').classes('text-sm').props('role=status')
            summary_prompt = ui.textarea('Summary prompt', value=summary['prompt']).props('maxlength=16000 rows=2 autogrow').classes('w-full')

            async def load_summary_models():
                selected_provider = summary_provider.value
                if not selected_provider:
                    summary_model_status.set_text('Summary model disabled. Chats will retain the initial prompt excerpt.')
                    return
                summary_model.props('loading')
                try:
                    choices = await runtime.models(await actor(), selected_provider)
                    if summary_provider.value == selected_provider:
                        selected_model = summary_model.value
                        summary_model.set_options(list(dict.fromkeys(([selected_model] if selected_model else []) + choices)),
                                                  value=selected_model)
                        summary_model_status.set_text(f'{len(choices)} models available. Custom IDs can be entered.' if choices
                                                      else 'No models discovered. Enter a custom Model ID and press Enter.')
                except Exception as exc:
                    if summary_provider.value == selected_provider:
                        error = diagnose(exc, tool='discover_summary_models')
                        summary_model_status.set_text(str(error) + ' Enter a model ID manually.')
                finally:
                    if summary_provider.value == selected_provider:
                        summary_model.props(remove='loading')

            async def save_summary():
                current_actor = await actor()
                service.save_summary_settings(current_actor, summary_provider.value, summary_model.value or '', summary_prompt.value or '')
                summary_model_status.set_text('Summary model settings saved.')

            summary_provider.on_value_change(lambda: protect(load_summary_models))
            ui.timer(0.01, lambda: protect(load_summary_models), once=True)
            with ui.row().classes('w-full gap-2 flex-wrap items-center'):
                ui.button('Save summary model', on_click=lambda: protect(save_summary)).props('outline')
                ui.space()
                ui.button('Close', on_click=dialog.close).props('flat')
        dialog.open()
    ctx.provider_dialog = provider_dialog
