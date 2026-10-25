import asyncio

import pytest
from nicegui import ui
from nicegui.testing.user_simulation import user_simulation

from dirigentenstab.web import build_ui, hierarchy_nodes, history_parts


def test_tree_uses_cloudstack_parents_and_only_safe_agent_labels():
    data = {
        'domains': [{'id': 'root', 'name': 'ROOT'},
                    {'id': 'research', 'parentdomainid': 'root', 'name': 'Research'},
                    {'id': 'training', 'parentdomainid': 'research', 'name': 'Training'}],
        'agents': [{'id': 'local', 'domain_id': 'training', 'name': 'Trainer', 'model': 'local-model',
                    'runtime': 'DO-NOT-EXPOSE'}],
        'users': [{'id': 'human', 'domainid': 'research', 'username': 'alice'}],
    }
    nodes = hierarchy_nodes(data)
    research = nodes[0]
    training = research['children'][0]
    assert training == {'id': 'agent:local', 'label': 'Trainer', 'icon': 'smart_toy', 'children': []}
    assert 'Administrator: alice' not in str(nodes)
    assert 'DO-NOT-EXPOSE' not in str(nodes)


def test_tree_preserves_scoped_root_without_inventing_missing_parent():
    nodes = hierarchy_nodes({'domains': [{'id': 'research', 'name': 'Research', 'parentdomainid': 'hidden'}]})
    assert nodes == [{'id': 'domain:research', 'label': 'Research', 'icon': 'folder', 'children': []}]


def test_history_excludes_system_instructions_and_keeps_tool_activity():
    history = {'messages': [
        {'kind': 'request', 'parts': [{'part_kind': 'system-prompt', 'content': 'internal instructions'},
                                     {'part_kind': 'user-prompt', 'content': '<script>alert(1)</script>'}]},
        {'kind': 'response', 'parts': [{'part_kind': 'tool-call', 'tool_name': 'list_vms', 'args': {'id': 'vm'}}]},
        {'kind': 'request', 'parts': [{'part_kind': 'tool-return', 'tool_name': 'list_vms', 'content': {'ok': True}}]},
        {'kind': 'response', 'parts': [{'part_kind': 'text', 'content': 'Ready'}]},
    ]}
    parts = list(history_parts(history))
    assert parts[0] == ('human', '<script>alert(1)</script>')
    assert parts[-1] == ('agent', 'Ready')
    assert len(parts) == 4
    assert 'internal instructions' not in str(parts)


@pytest.mark.asyncio
async def test_real_ui_direct_chat_and_callback_reauthentication(monkeypatch):
    agent = {'id': 'agent', 'name': 'Research agent', 'domain_id': 'domain',
             'account_id': 'cloud-account', 'model': 'local-model', 'can_provision': True,
             'instructions': 'Original prompt'}

    class Auth:
        calls = 0
        enabled = True

        async def identity(self, token):
            assert token == 'session'
            self.calls += 1
            if not self.enabled:
                raise PermissionError('Disabled CloudStack account')
            return {'userid': 'human', 'username': 'alice', 'domainid': 'domain', 'type': 2, 'csrf': 'csrf'}

    class Service:
        rotations = []
        updates = []

        async def hierarchy(self, identity):
            return {'domains': [{'id': 'domain', 'name': 'Research', 'path': '/ROOT/Research'}],
                    'agents': [agent], 'users': []}

        async def authorize(self, identity, agent_id):
            assert identity['userid'] == 'human' and agent_id == 'agent'
            return agent

        async def providers(self, identity):
            return []

        async def rotate_credentials(self, identity, agent_id):
            self.rotations.append((identity['userid'], agent_id))

        async def update_agent(self, identity, agent_id, provider_id, model, instructions, *, thinking='default'):
            self.updates.append((identity['userid'], agent_id, instructions))
            agent['instructions'] = instructions
            agent['thinking'] = thinking

    class Runtime:
        sent = []
        release = asyncio.Event()
        fail = False

        async def conversations(self, identity, agent_id):
            return [{'id': 'conversation', 'title': 'Example'}]

        async def chat(self, identity, agent_id, conversation_id, prompt, on_event):
            self.sent.append((identity['userid'], agent_id, prompt))
            await self.release.wait()
            if self.fail:
                raise RuntimeError('Synthetic pending reply failed')
            await on_event({'type': 'text', 'text': 'Hello'})
            await on_event({'type': 'tool_result', 'name': 'search_api', 'content': {'apis': 2}})
            return {'conversation_id': 'conversation', 'output': 'Hello'}

    auth, runtime, service = Auth(), Runtime(), Service()
    async with user_simulation() as user:
        build_ui(service, auth, runtime)
        login = await user.http_client.get('/login')
        assert login.status_code == 200
        assert 'action="/auth/login"' in login.text and '/_nicegui_ws' not in login.text
        user.http_client.cookies.set('ds_session', 'session')
        await user.open('/')
        await user.should_see('Select an agent to begin')
        user.find('agent_selector').trigger('update:modelValue', {'value': 0})
        await asyncio.sleep(0.1)
        assert auth.calls >= 2, user.notify.messages
        assert not user.notify.messages, user.notify.messages
        await user.should_see('Administrator account: cloud-account')
        expansion = next(iter(user.find('agent_details').elements))
        assert expansion.value is True
        header = list(expansion.slots['header'].children[0].descendants())
        assert {element.text for element in header if isinstance(element, (ui.label, ui.badge))} == {
            'Research agent', 'Domain administrator'}
        assert not any(isinstance(element, ui.button) for element in header)
        body = list(expansion.default_slot.children[0].descendants())
        assert {element.text for element in body if isinstance(element, ui.button)} == {'Configure', 'Create subgroup'}
        user.find('agent_details').trigger('update:modelValue', False)
        assert expansion.value is False
        user.find('agent_details').trigger('update:modelValue', True)
        assert expansion.value is True
        user.find('Message').type('Hello research')
        user.find('Send').click()
        user.find('Send').trigger('click')
        await user.should_see('thinking_indicator')
        runtime.release.set()
        await asyncio.sleep(0.1)
        await user.should_see('Hello')
        await user.should_not_see('thinking_indicator')
        assert runtime.sent == [('human', 'agent', 'Hello research')]
        user.find('Configure').click()
        await user.should_see('Rotate credentials')
        user.find('System prompt').clear().type('Explain research in German.')
        before_save = auth.calls
        user.find('Save').click()
        await asyncio.sleep(0.1)
        assert service.updates == [('human', 'agent', 'Explain research in German.')]
        assert auth.calls > before_save
        user.find('Configure').click()
        await user.should_see('Explain research in German.')
        user.find('Rotate credentials').click()
        await asyncio.sleep(0.1)
        assert service.rotations == [('human', 'agent')]
        assert auth.calls >= 4
        user.find('Cancel').click()
        user.find('New conversation').click()
        await asyncio.sleep(0.05)
        runtime.fail = True
        runtime.release.clear()
        user.find('Message').type('Exercise failed reply')
        user.find('Send').click()
        await user.should_see('thinking_indicator')
        runtime.release.set()
        await user.should_see('Failed ·')
        await user.should_not_see('thinking_indicator')
        redirects = []
        monkeypatch.setattr(user.navigate, 'to', redirects.append)
        auth.enabled = False
        user.find('New conversation').click()
        await asyncio.sleep(0.1)
        assert redirects == ['/login']


def test_main_agent_metadata_and_literal_legacy_names_are_not_guessed():
    nodes = hierarchy_nodes({
        'domains': [{'id': 'native', 'name': 'ROOT', 'path': 'ROOT'},
                    {'id': 'main-domain', 'name': 'Agents--ds-00000000000000000000', 'parentdomainid': 'native'},
                    {'id': 'child-domain', 'name': 'Research--ds-aabbcc', 'parentdomainid': 'main-domain'},
                    {'id': 'legacy', 'name': 'Meaningful--ds-1234', 'parentdomainid': 'child-domain'}],
        'agents': [{'id': 'main', 'name': 'Agents', 'domain_id': 'main-domain', 'is_main': True},
                   {'id': 'child', 'name': 'Research', 'domain_id': 'child-domain'}],
        'users': [{'id': 'human', 'username': 'alice', 'domainid': 'main-domain'}],
    })
    assert nodes[0]['label'] == 'Main Agent' and nodes[0]['icon'] == 'smart_toy'
    assert nodes[0]['children'][0]['label'] == 'Research'
    assert nodes[0]['children'][0]['children'][0]['label'] == 'Meaningful--ds-1234'
    assert 'alice' not in str(nodes) and 'Agents--ds-' not in str(nodes)


@pytest.mark.parametrize('manage', [True, False])
async def test_mcp_ui_separates_server_administration_and_agent_assignments(monkeypatch, manage):
    from dirigentenstab import mcp

    agent = {'id': 'agent', 'name': 'Research agent', 'domain_id': 'domain',
             'account_id': 'cloud-account', 'model': 'local-model'}
    identity = {'userid': 'human', 'username': 'alice', 'domainid': 'domain', 'type': 2, 'csrf': 'csrf'}

    class Auth:
        calls = 0
        enabled = True

        async def identity(self, token):
            assert token == 'session'
            self.calls += 1
            if not self.enabled:
                raise PermissionError('Session expired')
            return identity

    class Service:
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent], 'users': []}

        async def authorize(self, current, agent_id):
            assert current == identity and agent_id == 'agent'
            return agent

        async def providers(self, current):
            return []

    class Runtime:
        async def conversations(self, current, agent_id):
            return []

    class Integration:
        saved = []
        assigned = []
        discoveries = []
        fail = False
        fail_save = False
        block_once = False
        started = asyncio.Event()
        release = asyncio.Event()

        def __init__(self, service):
            pass

        async def configuration(self, current, agent_id):
            assert current == identity and agent_id == 'agent'
            return {'can_manage_servers': manage, 'servers': [
                {'id': 'search', 'name': 'Search service', 'url': 'https://search.example/mcp',
                 'enabled': True, 'tools': [], 'allowed_tools': None if manage else ['web_search']},
                {'id': 'other', 'name': 'Other service', 'url': 'https://other.example/mcp',
                 'enabled': True, 'tools': [], 'allowed_tools': None if manage else ['other_tool']}]}

        async def save_server(self, current, name, url, token=None, server_id=None, enabled=True):
            assert current == identity and manage
            if self.fail_save:
                raise ValueError('Invalid MCP endpoint')
            self.saved.append((name, url, token, server_id, enabled))
            return 'search'

        async def assign(self, current, agent_id, server_id, tools):
            assert current == identity
            self.assigned.append((agent_id, server_id, tools))

        async def discover(self, current, agent_id, server_id):
            assert current == identity and agent_id == 'agent'
            self.discoveries.append(server_id)
            if self.fail:
                raise RuntimeError('private discovery payload and API credential')
            if server_id == 'search' and self.block_once:
                Integration.block_once = False
                self.started.set()
                await self.release.wait()
                return [{'name': 'stale_tool', 'description': 'This stale result must be ignored'}]
            if server_id == 'other':
                return [{'name': 'other_tool', 'description': 'A tool from the other server'}]
            return [{'name': 'web_search', 'description': 'Search the public web'}] + (
                [{'name': 'web_extract', 'description': 'Read a public web page'}] if manage else [])

    monkeypatch.setattr(mcp, 'MCP', Integration)
    auth = Auth()
    async with user_simulation() as user:
        build_ui(Service(), auth, Runtime())
        user.http_client.cookies.set('ds_session', 'session')
        await user.open('/')
        user.find('agent_selector').trigger('update:modelValue', {'value': 0})
        await user.should_see('Configure')
        user.find('Configure').click()
        await user.should_see('System prompt')
        user.find('MCP tools').click()
        await user.should_see('Search the public web')
        assert Integration.discoveries == ['search']
        assert not next(iter(user.find(kind=ui.checkbox, content='web_search').elements)).value
        if manage:
            await user.should_see('API key / bearer token (blank keeps existing)')
            before_save = auth.calls
            user.find('Save server settings').click()
            await user.should_see('Server saved.')
            assert Integration.saved == [('Search service', 'https://search.example/mcp', None, 'search', True)]
            assert auth.calls > before_save
            user.find('Clear saved bearer token').click()
            user.find('Save server settings').click()
            await asyncio.sleep(0.1)
            assert Integration.saved[-1][2] == ''
        else:
            await user.should_not_see('API key / bearer token (blank keeps existing)')
            await user.should_not_see('Save server settings')
            await user.should_see('Ancestor allows: web_search')
        await user.should_see('Search the public web')
        user.find(kind=ui.checkbox, content='web_search').click()
        before_save = auth.calls
        user.find('Save assigned tools').click()
        await user.should_see('Assigned tools saved for this agent.')
        assert Integration.assigned == [('agent', 'search', ['web_search'])]
        assert auth.calls > before_save
        Integration.fail = True
        user.find(kind=ui.button, content='Refresh tools').click()
        await user.should_see('Your selections are preserved.')
        await user.should_not_see('private discovery payload')
        assert next(iter(user.find(kind=ui.checkbox, content='web_search').elements)).value
        assert not next(iter(user.find(kind=ui.button, content='Save assigned tools').elements)).enabled
        user.find('Save assigned tools').click()
        assert Integration.assigned == [('agent', 'search', ['web_search'])]
        Integration.fail = False
        user.find(kind=ui.button, content='Refresh tools').click()
        await user.should_see('tools available.')
        assert next(iter(user.find(kind=ui.checkbox, content='web_search').elements)).value
        if manage:
            assert not next(iter(user.find(kind=ui.checkbox, content='web_extract').elements)).value
            Integration.block_once = True
            user.find(kind=ui.button, content='Refresh tools').click()
            await asyncio.wait_for(Integration.started.wait(), timeout=1)
            Integration.fail_save = True
            user.find('Save server settings').click()
            await user.should_see('Server settings were not confirmed.')
            assert next(iter(user.find(kind=ui.button, content='Refresh tools').elements)).enabled
            assert not next(iter(user.find(kind=ui.button, content='Save assigned tools').elements)).enabled
            assert next(iter(user.find(kind=ui.checkbox, content='web_search').elements)).value
            Integration.fail_save = False
            user.find(kind=ui.button, content='Refresh tools').click()
            await user.should_see('2 tools available.')
            Integration.release.set()
            await asyncio.sleep(0.05)
            await user.should_not_see('stale_tool')
            Integration.started.clear()
            Integration.release.clear()
            Integration.block_once = True
            user.find(kind=ui.button, content='Refresh tools').click()
            await asyncio.wait_for(Integration.started.wait(), timeout=1)
            user.find('MCP server').trigger('update:modelValue', {'value': 2})
            await user.should_see('A tool from the other server')
            user.find(kind=ui.checkbox, content='other_tool').click()
            Integration.release.set()
            await asyncio.sleep(0.05)
            await user.should_not_see('stale_tool')
            assert next(iter(user.find(kind=ui.checkbox, content='other_tool').elements)).value
            user.find('MCP server').trigger('update:modelValue', {'value': 1})
            await user.should_see('Search the public web')
            assert next(iter(user.find(kind=ui.checkbox, content='web_search').elements)).value
            user.find('MCP server').trigger('update:modelValue', {'value': 2})
            await user.should_see('A tool from the other server')
            assert next(iter(user.find(kind=ui.checkbox, content='other_tool').elements)).value
            user.find('MCP server').trigger('update:modelValue', {'value': 1})
            await user.should_see('Search the public web')
        redirects = []
        monkeypatch.setattr(user.navigate, 'to', redirects.append)
        auth.enabled = False
        user.find('Save assigned tools').click()
        await asyncio.sleep(0.1)
        assert redirects == ['/login']
        assert Integration.assigned == [('agent', 'search', ['web_search'])]


async def test_thinking_selector_uses_reported_levels_preserves_settings_and_ignores_stale_discovery():
    agent = {'id': 'agent', 'name': 'Research agent', 'domain_id': 'domain', 'account_id': 'account',
             'provider_id': 'reported', 'model': 'model-a', 'thinking': 'high'}
    identity = {'userid': 'human', 'username': 'alice', 'domainid': 'domain', 'type': 2, 'csrf': 'csrf'}

    class Auth:
        async def identity(self, token):
            return identity

    class Service:
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent]}

        async def authorize(self, current, agent_id):
            assert current == identity and agent_id == 'agent'
            return agent

        async def providers(self, current):
            return [{'id': 'reported', 'name': 'Reported'}, {'id': 'local', 'name': 'Local'},
                    {'id': 'unavailable', 'name': 'Unavailable'}]

        async def update_agent(self, current, agent_id, provider_id, model, instructions, *, thinking):
            assert current == identity and agent_id == 'agent'
            agent.update(provider_id=provider_id, model=model, instructions=instructions, thinking=thinking)

    class Runtime:
        block = False
        started = asyncio.Event()
        release = asyncio.Event()

        async def conversations(self, current, agent_id):
            return []

        async def models(self, current, provider_id):
            return ['model-a', 'model-b']

        async def thinking_capabilities(self, current, provider_id, model_id):
            assert current == identity
            if provider_id == 'unavailable':
                raise RuntimeError('Private model API failure payload')
            if self.block and provider_id == 'reported' and model_id == 'model-b':
                self.started.set()
                await self.release.wait()
                return {'options': {'default': 'Model default', 'max': 'Max'}, 'source': 'Stale response'}
            if model_id == 'model-b':
                return {'options': {'default': 'Model default', 'off': 'Off', 'on': 'On'},
                        'source': 'Model API reports a thinking toggle'}
            return {'options': {'default': 'Model default', 'low': 'Low', 'high': 'High', 'max': 'Max'},
                    'source': 'Model API effort.supported_levels'}

    runtime = Runtime()
    async with user_simulation() as user:
        build_ui(Service(), Auth(), runtime)
        user.http_client.cookies.set('ds_session', 'session')
        await user.open('/')
        user.find('agent_selector').trigger('update:modelValue', {'value': 0})
        await user.should_see('Configure')
        user.find('Configure').click()
        await user.should_see('Model API effort.supported_levels')
        selector = next(iter(user.find(kind=ui.select, content='Thinking level').elements))
        assert selector.value == 'high'
        assert list(selector.options) == ['default', 'low', 'high', 'max']
        user.find('Thinking level').trigger('update:modelValue', {'value': 3})
        user.find('Save').click()
        await asyncio.sleep(0.05)
        assert agent['thinking'] == 'max'
        user.find('Configure').click()
        await user.should_see('Model API effort.supported_levels')
        selector = next(iter(user.find(kind=ui.select, content='Thinking level').elements))
        assert selector.value == 'max'
        runtime.block = True
        user.find('Model ID').trigger('update:modelValue', {'value': 1})
        await asyncio.wait_for(runtime.started.wait(), timeout=1)
        user.find('Model provider').trigger('update:modelValue', {'value': 1})
        await user.should_see('Model API reports a thinking toggle')
        assert selector.options == {'default': 'Model default', 'off': 'Off', 'on': 'On'}
        assert selector.value == 'default'
        runtime.release.set()
        await asyncio.sleep(0.05)
        await user.should_not_see('Stale response')
        assert selector.options == {'default': 'Model default', 'off': 'Off', 'on': 'On'}
        user.find('Model provider').trigger('update:modelValue', {'value': 2})
        await user.should_see('Thinking support could not be verified')
        await user.should_not_see('Private model API failure payload')
        assert selector.options == {'default': 'Model default'} and selector.value == 'default'


@pytest.mark.parametrize('restored,final_status', [(False, 'interrupted'), (False, 'reconciliation'), (True, 'interrupted'), (True, 'running')])
async def test_stop_agent_cancels_owned_run_preserves_partial_reply_and_restores_controls(restored, final_status):
    identity = {'userid': 'human', 'username': 'alice', 'domainid': 'domain', 'type': 2, 'csrf': 'csrf'}
    agent = {'id': 'agent', 'name': 'Research', 'domain_id': 'domain', 'account_id': 'account'}

    class Auth:
        async def identity(self, token):
            return identity

    class Service:
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent]}

        async def authorize(self, current, agent_id):
            assert current == identity and agent_id == 'agent'
            return agent

        async def providers(self, current):
            return []

    class Runtime:
        status = 'running'
        task = None
        stopped = []

        async def conversations(self, current, agent_id):
            return [{'id': 'conversation', 'title': 'Owned running task'}]

        async def restore(self, current, conversation_id):
            assert current == identity and conversation_id == 'conversation'
            return {'id': conversation_id, 'agent_id': 'agent', 'messages': [
                {'kind': 'response', 'parts': [{'part_kind': 'text', 'content': 'Partial reply retained'}]}],
                'runs': [{'id': 'operation', 'status': self.status, 'events': [],
                          'budget': {'reason': 'stopped', 'resumable': self.status == 'interrupted'}}]}

        async def chat(self, current, agent_id, conversation_id, prompt, on_event):
            self.task = asyncio.current_task()
            await on_event({'type': 'run_started', 'operation_id': 'operation', 'conversation_id': 'conversation'})
            await on_event({'type': 'text', 'text': 'Partial reply retained'})
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.status = final_status
                raise

        async def stop(self, current, operation_id):
            assert current == identity and operation_id == 'operation'
            self.stopped.append(operation_id)
            if self.task:
                self.task.cancel()
                try:
                    await self.task
                except asyncio.CancelledError:
                    pass
            else:
                self.status = final_status
            return {'operation_id': operation_id, 'status': self.status}

    runtime = Runtime()
    async with user_simulation() as user:
        build_ui(Service(), Auth(), runtime)
        user.http_client.cookies.set('ds_session', 'session')
        await user.open('/')
        user.find('agent_selector').trigger('update:modelValue', {'value': 0})
        await user.should_see('Configure')
        await user.should_not_see('Stop agent')
        if restored:
            user.find('Conversation').trigger('update:modelValue', {'value': 0})
        else:
            user.find('Message').type('Run a task')
            user.find('Send').click()
        await user.should_see('Stop agent')
        await user.should_see('Partial reply retained')
        user.find('Stop agent').click()
        if final_status == 'running':
            await user.should_see('Stop requested')
            await user.should_see('Stop agent')
            assert not next(iter(user.find(kind=ui.textarea, content='Message').elements)).enabled
            return
        await user.should_see('Requires reconciliation' if final_status == 'reconciliation' else 'Stopped')
        await user.should_not_see('Stop agent')
        await user.should_not_see('thinking_indicator')
        await user.should_see('Partial reply retained')
        assert runtime.stopped == ['operation']
        assert next(iter(user.find(kind=ui.textarea, content='Message').elements)).enabled
        user.find('Message').type('Next task')
        assert next(iter(user.find(kind=ui.button, content='Send').elements)).enabled
        if final_status == 'interrupted':
            await user.should_see('Continue saved task')
