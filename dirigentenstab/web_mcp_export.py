"""MCP export key management shared by the agent Configure dialog and Platform settings."""

import json
import time

from nicegui import ui

from . import mcp_export


def snippets(url, token):
    header = {'Authorization': 'Bearer ' + token}
    return {
        'Claude Code': f'claude mcp add --transport http dirigentenstab {url} --header "Authorization: Bearer {token}"',
        'Codex (~/.codex/config.toml)': f'[mcp_servers.dirigentenstab]\nurl = "{url}"\n'
                                        f'http_headers = {{ "Authorization" = "Bearer {token}" }}',
        'Gemini CLI (settings.json)': json.dumps({'mcpServers': {'dirigentenstab': {'httpUrl': url, 'headers': header}}}, indent=2),
        'opencode (opencode.json)': json.dumps({'mcp': {'dirigentenstab': {
            'type': 'remote', 'url': url, 'headers': header, 'enabled': True}}}, indent=2),
        'Generic JSON': json.dumps({'mcpServers': {'dirigentenstab': {'type': 'http', 'url': url, 'headers': header}}}, indent=2),
    }


def keys_panel(ctx, agent_id=None):
    """Render the MCP export section: key list, revoke and one-time token creation. agent_id None manages global keys."""
    service, actor, protect = ctx.service, ctx.actor, ctx.protect
    scope = 'MCP export' if agent_id else 'Global MCP export'
    with ui.expansion(scope, icon='hub').classes('w-full').mark('mcp-export'):
        ui.label(('This agent’s' if agent_id else 'Global Admin’s; /mcp/<agent id> selects any agent’s') + ' own tools with its CloudStack '
                 'permissions, for external harnesses at /mcp. Revoking a key takes effect immediately.').classes('text-sm text-stone-600')
        rows = ui.column().classes('w-full gap-1')
        label = ui.input('Key label').props('maxlength=64').classes('w-full').mark('mcp-key-label')

        async def revoke(key_id):
            await mcp_export.revoke_key(service, await actor(), key_id)
            await load()

        async def load():
            keys = await mcp_export.list_keys(service, await actor(), agent_id)
            rows.clear()
            with rows:
                for key in keys:
                    with ui.row().classes('w-full items-center justify-between no-wrap'):
                        used = time.strftime('%Y-%m-%d %H:%M', time.localtime(key['last_used'])) if key['last_used'] else 'never'
                        ui.label(f"{key['label']} · created {time.strftime('%Y-%m-%d', time.localtime(key['created']))}"
                                 f' · last used {used}').classes('text-sm min-w-0')
                        ui.button('Revoke', on_click=lambda key_id=key['id']: protect(lambda: revoke(key_id))).props('flat').props(
                            'color=negative').mark('mcp-revoke')

        async def create():
            token = await mcp_export.create_key(service, await actor(), agent_id, label.value or '')
            label.set_value('')
            await load()
            shown = snippets(mcp_export.export_url(service), token)
            with ui.dialog() as dialog, ui.card().classes('w-full max-w-xl min-w-0 gap-2'):
                ui.label('MCP export key created').classes('text-xl font-semibold')
                ui.label('Copy it now; the token is never shown again.').classes('text-sm')
                ui.code(token, language='text').classes('w-full').mark('mcp-token')
                harness = ui.select(list(shown), value='Claude Code', label='Harness').classes('w-full')
                code = ui.code(shown['Claude Code'], language='text').classes('w-full').mark('mcp-snippet')
                harness.on_value_change(lambda event: code.set_content(shown[event.value]))
                ui.button('Close', on_click=dialog.close).props('flat')
            dialog.on('hide', dialog.delete)
            dialog.open()

        ui.button('Create key', icon='add', on_click=lambda: protect(create)).props('outline').mark('mcp-create')
        ui.timer(0.01, lambda: protect(load), once=True)
