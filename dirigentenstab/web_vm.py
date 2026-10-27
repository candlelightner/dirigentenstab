import json
import posixpath
import stat
import time

import asyncssh
from nicegui import ui

from .files import MAX_UPLOAD, store_upload
from .web_sidebar import agent_label


class TerminalSession:
    def __init__(self, user_id, vm_id, conn, chan, term):
        self.user_id = user_id
        self.vm_id = vm_id
        self.conn = conn
        self.chan = chan
        self.term = term
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self.chan and not self.chan.is_closing():
                self.chan.close()
        except Exception:
            pass
        try:
            if self.conn and not self.conn.is_closing():
                self.conn.close()
        except Exception:
            pass


class XtermSSHSession(asyncssh.SSHClientSession):
    def __init__(self, term, on_disconnect):
        self.term = term
        self.chan = None
        self.on_disconnect = on_disconnect

    def connection_made(self, chan):
        self.chan = chan

    def data_received(self, data, datatype):
        self.term.write(data)

    def connection_lost(self, exc):
        self.on_disconnect(str(exc) if exc else None)


def build_vm_view(ctx):
    protect = ctx.protect

    with ui.card().classes('terminal-pane flex-1 w-full min-h-0 min-w-0 p-2 gap-2 flex flex-col').mark('terminal_pane') as ctx.terminal_pane:
        ctx.terminal_pane.set_visibility(False)
        with ui.row().classes('terminal-controls w-full items-center justify-between gap-2'):
            with ui.row().classes('items-center gap-2 no-wrap min-w-0'):
                ctx.terminal_mode = ui.toggle({'ssh': 'SSH', 'console': 'Console', 'files': 'Files'}, value='ssh').props(
                    'dense no-caps aria-label="Connection type"').mark('terminal_mode')
                ctx.terminal_status = ui.label('').classes('text-xs text-stone-600 truncate').mark('terminal_status').props('role=status')
                ctx.console_status = ui.label('').classes('text-xs text-stone-600 truncate').mark('console_status').props('role=status')
                ctx.console_status.set_visibility(False)
            with ui.row().classes('items-center gap-1 no-wrap'):
                ctx.popout_btn = ui.button(icon='open_in_new', on_click=lambda: protect(ctx.popout_console)).props(
                    'flat round dense aria-label="Open console in new tab"').mark('console_popout')
                ctx.popout_btn.set_visibility(False)
                ctx.reconnect_btn = ui.button(icon='refresh', on_click=lambda: protect(ctx.reconnect_terminal)).props('flat round dense aria-label="Reconnect"').mark('terminal_reconnect')
                ctx.disconnect_btn = ui.button(icon='power_settings_new', on_click=lambda: protect(ctx.disconnect_terminal)).props('flat round dense aria-label="Disconnect"').mark('terminal_disconnect')
                ui.button(icon='close', on_click=lambda: protect(ctx.close_terminal_view)).props('flat round dense aria-label="Close terminal"').mark('terminal_close')
        ctx.terminal_error = ui.label('').classes('text-xs text-red-600 truncate').mark('terminal_error')
        ctx.terminal_error.set_visibility(False)
        with ui.element('div').classes('terminal-container w-full flex-1 min-h-0 min-w-0 bg-black rounded overflow-hidden').mark('terminal_container') as ctx.terminal_container:
            ctx.term = ui.xterm(options={'cursorBlink': True, 'theme': {'background': '#000000'}}).classes('w-full h-full').mark('xterm')
        ctx.console_frame = ui.element('iframe').classes('console-frame bg-black rounded').props(
            'title="VM console" src="about:blank" allow="clipboard-read; clipboard-write"').mark('console_frame')
        ctx.console_frame.set_visibility(False)
        # noVNC (same-origin iframe) drops its `noVNC_connected` class on disconnect; tell the server.
        ui.add_body_html("""<script>(() => { const frame = () => document.querySelector('iframe.console-frame');
                    document.addEventListener('load', e => { if (e.target !== frame()) return;
                        const f = e.target, root = f.contentDocument?.documentElement; let seen = root?.classList.contains('noVNC_connected');
                        if (root) new MutationObserver(() => { const up = root.classList.contains('noVNC_connected');
                            if (up) seen = true; else if (seen) { seen = false; f.dispatchEvent(new Event('consoledisconnect')); }
                        }).observe(root, {attributes: true, attributeFilter: ['class']}); }, true); })();</script>""")
        # Keep the terminal fitted to the visible area while the mobile keyboard is open.
        ui.add_body_html(f"""<script>(() => {{ let t; const refit = () => {{ clearTimeout(t); t = setTimeout(() => {{
                    const box = document.querySelector('.terminal-container'); if (!box?.offsetParent) return;
                    box.scrollIntoView({{block: 'nearest'}}); try {{ getElement({ctx.term.id}).fit(); }} catch (_) {{}} }}, 150); }};
                    window.visualViewport?.addEventListener('resize', refit); window.visualViewport?.addEventListener('scroll', refit);
                    window.addEventListener('resize', refit); }})();</script>""")
        with ui.column().classes('files-pane w-full flex-1 min-h-0 min-w-0 gap-1 no-wrap') as ctx.files_pane:
            with ui.row().classes('w-full items-center gap-1 no-wrap'):
                ui.button(icon='arrow_upward', on_click=lambda: protect(lambda: ctx.list_dir(posixpath.dirname(ctx.files_dir)))).props(
                    'flat round dense aria-label="Parent directory"').mark('files_up')
                ctx.files_path = ui.input().props('dense outlined aria-label="Path"').classes('flex-1 min-w-0').mark('files_path')
                ctx.files_path.on('keydown.enter', lambda: protect(lambda: ctx.list_dir(ctx.files_path.value)))
            ctx.files_list = ui.list().props('dense separator').classes('w-full flex-1 min-h-0 overflow-auto').mark('files_list')
            ctx.files_upload = ui.upload(label='Upload to this folder', multiple=True, auto_upload=True, max_file_size=MAX_UPLOAD,
                                     on_multi_upload=lambda e: protect(lambda: ctx.upload_files(e.files)),
                                     on_rejected=lambda: ctx.terminal_error.set_text('A file exceeds the upload limit') or ctx.terminal_error.set_visibility(True),
                                     ).props('flat bordered dense').classes('w-full max-w-full').mark('files_upload')
        ctx.files_pane.set_visibility(False)


def setup_vm(ctx):
    actor, agents, client, console_proxy, protect, service, state, vm_files = ctx.actor, ctx.agents, ctx.client, ctx.console_proxy, ctx.protect, ctx.service, ctx.state, ctx.vm_files

    active_session = None
    ssh_request = 0
    files_conn = files_sftp = None
    ctx.files_dir = '.'

    def close_active_terminal():
        nonlocal active_session, ssh_request, files_conn, files_sftp
        ssh_request += 1
        if files_conn:
            files_conn.close()
            files_conn = files_sftp = None
        if active_session:
            if hasattr(service, 'unregister_terminal_session'):
                service.unregister_terminal_session(active_session)
            active_session.close()
            active_session = None
    ctx.close_active_terminal = close_active_terminal

    client.on_disconnect(ctx.close_active_terminal)

    async def connect_vm(vm_id, vm_name=None):
        ctx.close_active_terminal()
        request = ssh_request
        ctx.terminal_error.set_text('')
        ctx.terminal_error.set_visibility(False)
        ctx.reconnect_btn.disable()
        ctx.disconnect_btn.disable()
        ctx.terminal_status.set_text(f'Connecting to {vm_name or vm_id}…')
        ctx.term.write('\x1bc')
        try:
            current = await actor()
            conn, vm = await service.open_vm_terminal_connection(current, vm_id)
            if request != ssh_request or state.get('current_vm') != vm_id:
                conn.close()
                return
            session = TerminalSession(current['userid'], vm_id, conn, None, ctx.term)
            if hasattr(service, 'register_terminal_session'):
                service.register_terminal_session(session)
            nonlocal active_session
            active_session = session

            def on_disconnect(error_msg=None):
                if request != ssh_request:
                    return
                ctx.terminal_status.set_text('Disconnected' + (f': {error_msg}' if error_msg else ''))
                ctx.reconnect_btn.enable()
                ctx.disconnect_btn.disable()
                if error_msg:
                    ctx.terminal_error.set_text(error_msg)
                    ctx.terminal_error.set_visibility(True)

            cols = await ctx.term.get_columns() or 80
            rows = await ctx.term.get_rows() or 24
            chan, ssh_session = await conn.create_session(
                lambda: XtermSSHSession(ctx.term, on_disconnect),
                term_type='xterm-256color',
                term_size=(cols, rows),
                encoding=None,
            )
            if request != ssh_request:
                chan.close()
                conn.close()
                return
            session.chan = chan
            ssh_session.chan = chan
            ctx.terminal_status.set_text(f"Connected: {vm.get('name', vm_id)}")
            ctx.disconnect_btn.enable()
            ctx.reconnect_btn.enable()
            await ctx.term.fit()
        except Exception as exc:
            if request != ssh_request:
                return
            ctx.close_active_terminal()
            error_msg = str(exc)
            ctx.terminal_status.set_text('Disconnected: ' + error_msg[:60])
            ctx.terminal_error.set_text(error_msg)
            ctx.terminal_error.set_visibility(True)
            ctx.term.writeln(f'\r\n\x1b[31mConnection failed: {error_msg}\x1b[0m\r\n')
            ctx.reconnect_btn.enable()
            ctx.disconnect_btn.disable()

    def handle_term_data(e):
        if active_session and active_session.chan and not active_session.chan.is_closing():
            data = getattr(e, 'data', None)
            if data is None:
                data = getattr(e, 'args', '')
            try:
                active_session.chan.write(data.encode('utf-8') if isinstance(data, str) else data)
            except Exception:
                pass

    def handle_term_resize(e):
        cols = getattr(e, 'cols', None) or (e.args.get('cols') if hasattr(e, 'args') and isinstance(e.args, dict) else None)
        rows = getattr(e, 'rows', None) or (e.args.get('rows') if hasattr(e, 'args') and isinstance(e.args, dict) else None)
        if active_session and active_session.chan and not active_session.chan.is_closing() and cols and rows:
            try:
                active_session.chan.change_terminal_size(cols, rows)
            except Exception:
                pass

    ctx.term.on_data(handle_term_data)
    ctx.term.on_resize(handle_term_resize)
    ctx.terminal_mode.on_value_change(lambda e: protect(lambda: switch_terminal_mode(e.value)))

    def vm_name(vm_id):
        vm_info = next((v for v in state.get('data', {}).get('vms', []) if v['id'] == vm_id), None)
        return vm_info.get('name') if vm_info else vm_id

    console_request = 0

    def set_console_src(url='about:blank'):
        nonlocal console_request
        console_request += 1
        ctx.console_frame.props['src'] = url
        ctx.console_frame.update()
    ctx.set_console_src = set_console_src

    async def show_vm(vm_id):
        ctx.close_active_terminal()
        name = vm_name(vm_id)
        state['current_vm'] = vm_id
        ctx.set_console_src()
        ctx.agent_heading.set_text(f"VM: {name}")
        ctx.agent_heading.disable()
        ctx.conversation_controls.set_visibility(False)
        ctx.conversation_card.set_visibility(False)
        ctx.terminal_pane.set_visibility(True)
        ctx.drawer.run_method('hide')
        if ctx.terminal_mode.value == 'ssh':
            await switch_terminal_mode('ssh')
        else:
            ctx.terminal_mode.set_value('ssh')
    ctx.show_vm = show_vm

    async def connect_console(*, popout=False):
        ctx.set_console_src()
        request = console_request
        vm_id = state.get('current_vm')
        if not vm_id:
            return
        ctx.console_status.set_text(f'Opening console: {vm_name(vm_id)}…')
        ctx.terminal_error.set_visibility(False)
        try:
            url = await console_proxy.open(await actor(), vm_id)
        except Exception as exc:
            if request == console_request:
                ctx.console_status.set_text('Console unavailable')
                ctx.terminal_error.set_text(str(exc))
                ctx.terminal_error.set_visibility(True)
            return
        if request != console_request or vm_id != state.get('current_vm') or ctx.terminal_mode.value != 'console':
            return
        if popout:
            ui.navigate.to(url, new_tab=True)
            ctx.console_status.set_text('Console opened in new tab')
        else:
            ctx.set_console_src(url)
            ctx.console_status.set_text(f'Console: {vm_name(vm_id)}')

    async def console_disconnected():
        if ctx.console_frame.props.get('src') != 'about:blank':
            ctx.set_console_src()  # drop the dead canvas; Reconnect fetches a fresh single-use ticket
            ctx.console_status.set_text('Console disconnected')

    ctx.console_frame.on('consoledisconnect', lambda: protect(console_disconnected))

    async def popout_console():
        await connect_console(popout=True)
    ctx.popout_console = popout_console

    async def list_dir(path):
        request = ssh_request
        ctx.terminal_error.set_visibility(False)
        try:
            full = await files_sftp.realpath(path or '.')
            entries = await files_sftp.readdir(full)
            rows = []
            for entry in entries:
                if entry.filename in {'.', '..'}:
                    continue
                mode = entry.attrs.permissions or 0
                directory = stat.S_ISDIR(mode) or (stat.S_ISLNK(mode) and await files_sftp.isdir(posixpath.join(full, entry.filename)))
                rows.append((not directory, entry.filename.casefold(), entry.filename, entry.attrs.size or 0, entry.attrs.mtime))
            rows.sort()
        except Exception as exc:
            if request == ssh_request:
                ctx.files_path.set_value(ctx.files_dir)
                ctx.terminal_error.set_text(str(exc))
                ctx.terminal_error.set_visibility(True)
            return
        if request != ssh_request:
            return
        ctx.files_dir = full
        ctx.files_path.set_value(full)
        ctx.files_list.clear()
        with ctx.files_list:
            for is_file, _, name, size, mtime in rows:
                with ui.item(on_click=None if is_file else (lambda n=name: protect(lambda: ctx.list_dir(posixpath.join(ctx.files_dir, n))))).props(
                        '' if is_file else 'clickable').classes('w-full'):
                    with ui.item_section().props('avatar').classes('min-w-0'):
                        ui.icon('description' if is_file else 'folder')
                    with ui.item_section().classes('min-w-0'):
                        ui.item_label(name).classes('truncate')
                        ui.item_label((f'{size:,} B · ' if is_file else '') + (
                            time.strftime('%Y-%m-%d %H:%M', time.localtime(mtime)) if mtime else '')).props('caption')
                    if is_file:
                        with ui.item_section().props('side'):
                            ui.button(icon='download', on_click=lambda n=name: protect(lambda: download_file(n))).props(
                                f'flat round dense aria-label="Download {name}"')
    ctx.list_dir = list_dir

    async def connect_files():
        nonlocal files_conn, files_sftp
        ctx.close_active_terminal()
        request = ssh_request
        vm_id = state.get('current_vm')
        if not vm_id:
            return
        ctx.files_dir = '.'
        ctx.files_list.clear()
        ctx.terminal_error.set_visibility(False)
        ctx.terminal_status.set_text(f'Connecting to {vm_name(vm_id)}…')
        try:
            conn, _ = await service.open_vm_connection(await actor(), vm_id)
            if request != ssh_request:
                conn.close()
                return
            files_conn = conn
            files_sftp = await conn.start_sftp_client()
            ctx.terminal_status.set_text(f'Connected: {vm_name(vm_id)}')
            await ctx.list_dir('.')
        except Exception as exc:
            if request == ssh_request:
                ctx.close_active_terminal()
                ctx.terminal_status.set_text('Disconnected')
                ctx.terminal_error.set_text(str(exc))
                ctx.terminal_error.set_visibility(True)

    async def download_file(name):
        # ui.download opens a new tab (target=_blank), which browsers sometimes cancel; a same-page anchor is reliable.
        url = vm_files.grant(await actor(), state['current_vm'], posixpath.join(ctx.files_dir, name))
        ui.run_javascript(f'const a = document.createElement("a"); a.href = {json.dumps(url)}; a.download = ""; a.click()')

    async def upload_files(uploads):
        vm_id, request = state.get('current_vm'), ssh_request
        try:
            if not files_sftp:
                raise ConnectionError('Files are not connected')
            current = await actor()
            for upload in uploads:
                try:
                    try:
                        await store_upload(files_sftp, ctx.files_dir, upload)
                    except FileExistsError:
                        with ui.dialog() as dialog, ui.card():
                            ui.label(f'Overwrite {upload.name}?')
                            with ui.row():
                                ui.button('Overwrite', on_click=lambda: dialog.submit(True))
                                ui.button('Cancel', on_click=lambda: dialog.submit(False)).props('flat')
                        confirmed = await dialog
                        dialog.delete()
                        if not confirmed:
                            continue
                        await store_upload(files_sftp, ctx.files_dir, upload, overwrite=True)
                    service.store.audit(current['userid'], 'vm-file-upload', vm_id)
                except (OSError, ValueError, asyncssh.Error) as exc:
                    ctx.terminal_error.set_text(f'{upload.name}: {exc}')
                    ctx.terminal_error.set_visibility(True)
        finally:
            ctx.files_upload.reset()
        if request == ssh_request:
            await ctx.list_dir(ctx.files_dir)
    ctx.upload_files = upload_files

    async def switch_terminal_mode(mode):
        console, files = mode == 'console', mode == 'files'
        ctx.sync_url()
        ctx.terminal_error.set_text('')
        ctx.terminal_error.set_visibility(False)
        if console or files:
            ctx.close_active_terminal()
        for element in (ctx.console_status, ctx.console_frame, ctx.popout_btn):
            element.set_visibility(console)
        ctx.terminal_status.set_visibility(not console)
        ctx.terminal_container.set_visibility(mode == 'ssh')
        ctx.files_pane.set_visibility(files)
        ctx.reconnect_btn.enable()
        ctx.disconnect_btn.set_enabled(console or files or bool(active_session))
        if files:
            ctx.set_console_src()
            await connect_files()
        elif not console:
            ctx.set_console_src()
            await ctx.term.fit()
            if state.get('current_vm') and not active_session:
                await connect_vm(state['current_vm'], vm_name(state['current_vm']))
        elif state.get('current_vm') and ctx.console_frame.props.get('src') == 'about:blank':
            await connect_console()

    async def disconnect_terminal():
        if ctx.terminal_mode.value == 'console':
            ctx.set_console_src()
            ctx.console_status.set_text('Console closed')
            return
        ctx.close_active_terminal()
        ctx.files_list.clear()
        ctx.terminal_status.set_text('Disconnected')
        ctx.disconnect_btn.disable()
        ctx.reconnect_btn.enable()
        ctx.term.writeln('\r\n\x1b[33mDisconnected by user.\x1b[0m\r\n')
    ctx.disconnect_terminal = disconnect_terminal

    async def reconnect_terminal():
        if not state.get('current_vm'):
            return
        if ctx.terminal_mode.value == 'console':
            await connect_console()
        elif ctx.terminal_mode.value == 'files':
            await connect_files()
        else:
            await connect_vm(state['current_vm'], vm_name(state['current_vm']))
    ctx.reconnect_terminal = reconnect_terminal

    async def close_terminal_view():
        ctx.close_active_terminal()
        ctx.set_console_src()
        state['current_vm'] = None
        ctx.terminal_pane.set_visibility(False)
        ctx.conversation_controls.set_visibility(True)
        ctx.conversation_card.set_visibility(True)
        ctx.sync_url()
        if state.get('agent'):
            agent = agents.get(state['agent'])
            if agent:
                ctx.agent_heading.set_text(agent_label(agent))
                ctx.agent_heading.enable()
    ctx.close_terminal_view = close_terminal_view
