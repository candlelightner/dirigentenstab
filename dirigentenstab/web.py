import asyncio
from types import SimpleNamespace
import os

from fastapi import Request
from fastapi.responses import HTMLResponse
from nicegui import app, ui

from .console import ConsoleProxy
from .diagnostics import diagnose
from .files import VMFiles
from .platform_status import banner
from .runtime import Runtime
from .settings import Settings
from .store import Store
from .web_admin_dialogs import setup_admin_dialogs
from .web_agent_dialogs import setup_agent_dialogs
from .web_chat import build_chat_view, conversation_activity, history_parts, save_setting, setup_chat
from .web_sidebar import build_sidebar, hierarchy_nodes, setup_sidebar
from .web_vm import TerminalSession, XtermSSHSession, build_vm_view, setup_vm

__all__ = ['TerminalSession', 'XtermSSHSession', 'build_ui', 'conversation_activity', 'hierarchy_nodes',
           'history_parts', 'main']


def build_ui(service, auth, runtime=None):
    runtime = runtime or Runtime(service)
    console_proxy = ConsoleProxy(service)
    console_proxy.install(app)
    vm_files = VMFiles(service)
    vm_files.install(app)

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

    @ui.page('/', response_timeout=30)
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
                state['session_expired'] = False
                return current
            except Exception:
                if not state.get('session_expired'):
                    state['session_expired'] = True
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

        agents = {row['id']: row for row in data.get('agents', [])}
        state = {'agent': None, 'conversation': None, 'busy': False, 'waiting': False, 'data': data, 'imported': False, 'active_operation': None, 'submitting': False, 'activity_token': None, 'drafts': {}}
        ctx = SimpleNamespace(service=service, auth=auth, runtime=runtime, console_proxy=console_proxy,
                             vm_files=vm_files, client=client, token=token, identity=identity, data=data,
                             state=state, agents=agents, actor=actor, protect=protect)
        autoscroll_key = f'chat_autoscroll:{identity["userid"]}'
        ctx.autoscroll_setting = service.store.one('SELECT value FROM platform_settings WHERE name=?', (autoscroll_key,))

        async def save_autoscroll():
            await actor()
            save_setting(service.store, autoscroll_key, 'true' if ctx.autoscroll.value else 'false')
        ctx.save_autoscroll = save_autoscroll

        dashboard_url = service.dashboard_url(identity) if identity.get('type') == 1 else ''
        ctx.dashboard_links = []

        def dashboard_link(classes):
            link = ui.link('CloudStack Dashboard', dashboard_url or '#', new_tab=True).props(
                'rel="noopener noreferrer"').classes(classes)
            link.set_visibility(bool(dashboard_url))
            ctx.dashboard_links.append(link)
        ctx.dashboard_link = dashboard_link

        with ui.header().classes('bg-white text-stone-800 border-b items-center px-5 py-3 gap-3'):
            ui.button(icon='account_tree', on_click=lambda: ctx.drawer.run_method('toggle')).props(
                'outline round aria-label="Open agent hierarchy"').classes('text-teal-900').mark('hierarchy_toggle')
            with ui.button('Select an agent').props(
                    'flat no-caps icon-right=expand_more aria-label="Agent details" aria-haspopup="menu"').classes(
                        'agent-details-toggle flex-1 min-w-0').mark('agent_details_toggle') as ctx.agent_heading:
                with ui.menu().props('anchor="bottom left" self="top left"').classes(
                        'agent-details-menu bg-white p-4').mark('agent_details_menu').style(
                            'width:min(520px,calc(100vw - 24px));max-height:calc(var(--viewport-height,100dvh) - 84px);overflow-y:auto') as ctx.details_menu:
                    ctx.details = ui.column().classes('agent-details w-full gap-3').mark('agent_details')
            ctx.agent_heading.disable()
            if identity.get('type') == 1:
                ctx.dashboard_link('dashboard-header text-teal-900')
            ui.label(identity.get('username', 'CloudStack administrator')).classes('text-sm brand-user')
            ctx.escalation_button = ui.button(icon='approval', color=None, on_click=lambda: protect(ctx.open_escalations)).props(
                'flat round aria-label="Escalation requests: 0 pending"').classes('escalation-requests').mark('escalation_requests')
            ctx.escalation_button.set_visibility(identity.get('type') == 1)

        ui.add_css("""
            html,body{overscroll-behavior:none;overflow:hidden}
            .nicegui-content{padding:0;height:calc(var(--viewport-height,100dvh) - 65px);min-height:0}
            .agent-details-toggle{font-size:20px;padding:0 4px}
            .agent-details-toggle .q-btn__content{justify-content:space-between;flex-wrap:nowrap}
            .agent-details-toggle .q-btn__content>span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
            .escalation-summary .q-btn__content{display:block;width:100%;min-width:0;text-align:left}
            .escalation-requests{color:#78716c;flex-shrink:0}
            .escalation-requests.pending{animation:escalation-pulse 2s ease-in-out infinite alternate}
            @keyframes escalation-pulse{from{color:#ea580c}to{color:#dc2626}}
            @media(prefers-reduced-motion:reduce){.escalation-requests.pending{animation:none;color:#ea580c}}
            .workspace{height:100%;min-height:0;width:100%;padding:12px;gap:10px;flex-wrap:nowrap}
            .conversation{flex:1;min-height:0;width:100%;overflow:hidden;gap:8px}
            .terminal-pane{flex:1;min-height:0;width:100%;max-width:100%;overflow:hidden;gap:6px}
            .terminal-container{flex:1;min-height:0;width:100%;max-width:100%;overflow:hidden}
            .terminal-container .xterm{width:100%!important;height:100%!important;min-width:0;max-width:100%}
            .console-frame{flex:1;min-height:0;height:100%;width:100%;max-width:100%;border:0}
            .messages{flex:1;min-height:0;width:100%;overflow:hidden}
            .messages .q-scrollarea__container{overflow-x:hidden!important}
            .messages .q-scrollarea__content{width:100%!important;max-width:100%!important;min-width:0!important;box-sizing:border-box}
            .messages .q-message,.messages .q-message-container,.messages .q-message-container>div,.messages .q-message-text,.messages .q-message-text-content,.messages .q-expansion-item{max-width:100%;min-width:0;overflow-wrap:anywhere}
            .composer{width:100%;flex-shrink:0;align-items:end;flex-wrap:nowrap}
            .composer textarea{max-height:120px;overflow:auto!important}
            .composer .q-field__control{min-height:44px}
            .composer .q-btn{width:44px;min-width:44px;min-height:44px;padding:0}
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
            @media(max-width:600px){.workspace{padding:6px;gap:6px}
            .brand-user{display:none}.q-header{padding:8px!important}.nicegui-content{height:calc(var(--viewport-height,100dvh) - 61px)}
            .q-message-name{font-size:12px}.q-message{margin-bottom:6px}}
        """)
        # Resize the bounded workspace with the mobile visual viewport (including the virtual keyboard).
        ui.add_body_html("""<script>
            (() => { const fit = () => { const el=document.querySelector('.workspace');
                const header=document.querySelector('.q-header');
                const height=window.visualViewport?.height || innerHeight;
                document.documentElement.style.setProperty('--viewport-height',height+'px');
                if(el) { el.style.height=Math.max(100,height-(header?.getBoundingClientRect().height || 65))+'px'; } };
                window.visualViewport?.addEventListener('resize',fit); window.addEventListener('resize',fit);
                fit(); setTimeout(fit,500); })();
        </script>""")

        build_sidebar(ctx)
        with ui.column().classes('workspace'):
            build_chat_view(ctx)
            build_vm_view(ctx)
            platform_banner = ui.label().classes('fixed top-16 right-3 z-50 max-w-sm rounded shadow px-3 py-1 text-sm whitespace-pre-line').mark('platform_banner')

            def refresh_platform_banner():
                shown = banner(service.platform_status())
                platform_banner.set_visibility(bool(shown))
                if shown:
                    platform_banner.set_text(shown[0])
                    platform_banner.classes(replace='fixed top-16 right-3 z-50 max-w-sm rounded shadow px-3 py-1 text-sm whitespace-pre-line ' + (
                        'bg-orange-100 text-orange-900' if shown[1] else 'text-stone-500'))
            refresh_platform_banner()
            ui.timer(5.0, refresh_platform_banner)
        setup_admin_dialogs(ctx)
        setup_agent_dialogs(ctx)
        setup_vm(ctx)
        setup_chat(ctx)
        setup_sidebar(ctx)

        main = next((a for a in agents.values() if a.get('is_main')), None)
        query = request.query_params
        requested = query.get('agent')

        if requested in agents:
            try:
                await ctx.show_agent(requested, close_navigation=False)
            except Exception:
                pass  # Unavailable ids fall back to the default below.

        if main and not state['agent']:
            await ctx.show_agent(main['id'], close_navigation=False)

        vm_id, skill_id = query.get('vm'), query.get('skill')

        if vm_id and any(v['id'] == vm_id for v in state['data'].get('vms', [])):
            await ctx.show_vm(vm_id)
            if query.get('mode') in {'console', 'files'}:
                ctx.terminal_mode.set_value(query['mode'])
        elif skill_id and any(s['id'] == skill_id for s in state['data'].get('skills', [])):
            try:
                await ctx.open_skill(skill_id)
            except Exception:
                pass

    return runtime


def main():
    from .auth import Auth, attach
    from .service import Service

    settings = Settings.load()
    service = Service(Store(settings.database, settings.key_file), settings)
    auth = Auth(service)
    attach(app, auth, settings)
    app.on_startup(build_ui(service, auth).start)
    app.on_startup(lambda: setattr(service, 'reconciler', asyncio.create_task(service.reconcile_periodically())))
    tls = {}
    if os.getenv('APP_TLS_CERT') or os.getenv('APP_TLS_KEY'):
        tls = {'ssl_certfile': os.environ['APP_TLS_CERT'], 'ssl_keyfile': os.environ['APP_TLS_KEY']}
    ui.run(host=os.getenv('APP_HOST', '0.0.0.0'), port=int(os.getenv('APP_PORT', '8088')),
           title='Dirigentenstab', reload=False, show=False, show_welcome_message=False, **tls)


if __name__ == '__main__':
    main()
