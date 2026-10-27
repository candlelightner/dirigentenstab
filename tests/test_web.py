import asyncio

import pytest
from nicegui import ui
from nicegui.testing.user_simulation import user_simulation

from dirigentenstab import web_chat
from dirigentenstab.web import build_ui, hierarchy_nodes, history_parts


class AgentCapabilities:
    class store:
        @staticmethod
        def one(*args):
            return None

        @staticmethod
        def execute(*args):
            pass

        @staticmethod
        def all(*args):
            return []

    def register_terminal_session(self, session):
        pass

    def unregister_terminal_session(self, session):
        pass

    async def vm_overview(self, identity, agent_id):
        return []

    async def subgroup_capability(self, agent_id):
        return True

    def escalation_request_limit(self):
        return 3

    async def list_escalation_requests(self, identity):
        return []

    async def escalation_access(self, agent):
        return {'selected': True, 'allowed': True, 'enabled': True}

    async def owner_ssh_key_access(self, agent):
        return {'selected': bool(agent.get('owner_ssh_key_enabled', True)),
                'allowed': True}

    async def provider_configuration(self, identity, agent_id):
        providers = await self.providers(identity)
        return {'providers': providers, 'selected': [row['id'] for row in providers], 'allowed': None}


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


def test_global_admin_is_separate_above_preserved_domain_tree():
    nodes = hierarchy_nodes({
        'domains': [{'id': 'native', 'name': 'ROOT', 'level': 0},
                    {'id': 'main-domain', 'name': 'Agents', 'parentdomainid': 'native'},
                    {'id': 'child-domain', 'name': 'Research', 'parentdomainid': 'main-domain'}],
        'agents': [{'id': 'main', 'name': 'Agents', 'domain_id': 'main-domain', 'is_main': True},
                   {'id': 'global', 'name': 'Custom global name', 'domain_id': 'native', 'is_global': True},
                   {'id': 'child', 'name': 'Research', 'domain_id': 'child-domain'}],
    })
    assert nodes[0] == {'id': 'agent:global', 'label': 'Global Admin',
                        'icon': 'admin_panel_settings', 'children': []}
    assert nodes[1]['id'] == 'agent:main' and nodes[1]['label'] == 'Main Agent'
    assert nodes[1]['children'] == [{'id': 'agent:child', 'label': 'Research',
                                     'icon': 'smart_toy', 'children': []}]


def test_hierarchy_nodes_modes_and_alias_display():
    data = {
        'domains': [{'id': 'native', 'name': 'ROOT', 'level': 0},
                    {'id': 'eng-domain', 'name': 'Engineering', 'parentdomainid': 'native'}],
        'agents': [{'id': 'eng-agent', 'name': 'Eng Admin', 'domain_id': 'eng-domain'}],
        'vms': [
            {'id': 'vm-1', 'name': 'ds-vm-1111', 'displayname': 'my-custom-vm', 'owner_agent': 'eng-agent'},
            {'id': 'vm-2', 'name': 'ds-vm-2222', 'displayname': 'ds-vm-2222', 'owner_agent': 'eng-agent'},
            {'id': 'vm-3', 'name': 'ds-vm-3333', 'owner_agent': 'eng-agent'},
        ],
    }
    nodes = hierarchy_nodes(data, mode=['Agents'])
    assert 'ds-vm-1111' not in str(nodes)
    assert 'my-custom-vm' not in str(nodes)

    nodes = hierarchy_nodes(data, mode=['Agents', 'VMs'])
    labels = [c['label'] for c in nodes[0]['children']]
    assert labels == ['ds-vm-1111', 'ds-vm-2222', 'ds-vm-3333']

    nodes = hierarchy_nodes(data, mode=['Agents', 'VMs'], show_aliases=True)
    labels = [c['label'] for c in nodes[0]['children']]
    assert labels == ['my-custom-vm', 'ds-vm-2222', 'ds-vm-3333']

    nodes = hierarchy_nodes(data, mode=['VMs'], show_aliases=True)
    assert len(nodes) == 1
    assert nodes[0]['selectable'] is False
    assert [c['label'] for c in nodes[0]['children']] == ['my-custom-vm', 'ds-vm-2222', 'ds-vm-3333']


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
async def test_real_ui_direct_chat_and_callback_reauthentication(monkeypatch, caplog):
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

    class Service(AgentCapabilities):
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

        async def update_agent(self, identity, agent_id, provider_id, model, instructions, *, thinking='default', **compaction):
            self.updates.append((identity['userid'], agent_id, instructions))
            agent['instructions'] = instructions
            agent['thinking'] = thinking
            if 'owner_ssh_key_enabled' in compaction:
                agent['owner_ssh_key_enabled'] = compaction['owner_ssh_key_enabled']

    class Runtime:
        async def start(self):
            pass

        sent = []
        release = asyncio.Event()
        finished = asyncio.Event()
        fail = False
        status = 'running'
        rows = {}
        restored = []

        async def conversations(self, identity, agent_id):
            return [{'id': key, 'title': value['title']} for key, value in self.rows.items()]

        async def restore(self, identity, conversation_id):
            self.restored.append(conversation_id)
            return self.rows[conversation_id]

        async def submit(self, identity, agent_id, conversation_id, prompt):
            self.sent.append((identity['userid'], agent_id, prompt))
            conversation_id = conversation_id or f'conversation-{len(self.rows)}'
            row = {'id': conversation_id, 'agent_id': agent_id, 'title': prompt, 'messages': [],
                   'runs': [{'id': conversation_id, 'status': 'running', 'events': []}]}
            self.rows[conversation_id] = row
            async def finish():
                await self.release.wait()
                row['messages'] = [{'parts': [{'part_kind': 'text', 'content': 'Hello'}]}]
                row['runs'][-1]['status'] = 'failed' if self.fail else 'completed'
                self.finished.set()
            asyncio.create_task(finish())
            return {'conversation_id': conversation_id, 'operation_id': conversation_id, 'status': 'running'}

    auth, runtime, service = Auth(), Runtime(), Service()
    from types import SimpleNamespace
    service.store = SimpleNamespace(one=lambda *args: None, execute=lambda *args: None, all=lambda *args: [dict(id=key, agent_id='agent', title=value['title'],
        operation_id=key, status=value['runs'][-1]['status'], updated=1 if value['runs'][-1]['status'] == 'running' else 2)
        for key, value in runtime.rows.items()])
    async with user_simulation() as user:
        build_ui(service, auth, runtime)
        login = await user.http_client.get('/login')
        assert login.status_code == 200
        assert 'action="/auth/login"' in login.text and '/_nicegui_ws' not in login.text
        user.http_client.cookies.set('ds_session', 'session')
        await user.open('/')
        await user.should_see('Select an agent')
        await user.should_not_see('Select an agent to begin')
        await user.should_not_see('Chat directly with an agent')
        toggle = next(iter(user.find('hierarchy_toggle').elements))
        heading = next(iter(user.find('agent_details_toggle').elements))
        assert isinstance(toggle.parent_slot.parent, ui.header)
        assert isinstance(heading.parent_slot.parent, ui.header)
        assert heading.props['aria-label'] == 'Agent details'
        assert not heading.enabled
        assert not any('Sign out' in getattr(child, 'content', '') or getattr(child, 'text', '') == 'Sign out'
                       for child in toggle.parent_slot.parent.descendants())
        await user.should_not_see('hub_activity')
        settings_button = next(iter(user.find('settings_button').elements))
        assert settings_button.text == 'Settings'
        await user.should_not_see('agent_selector')
        assert toggle.props['aria-label'] == 'Open agent hierarchy'
        user.find('hierarchy').trigger('update:selected', 'agent:agent')
        await asyncio.sleep(0.1)
        assert auth.calls >= 2, user.notify.messages
        assert not user.notify.messages, user.notify.messages
        await user.should_see('Administrator account: cloud-account')
        details = next(iter(user.find('agent_details').elements))
        assert heading.text == 'Research agent' and heading.enabled
        menu = next(element for element in details.ancestors() if isinstance(element, ui.menu))
        assert menu.value is False
        labels = list(details.default_slot.children[0].descendants())
        assert {element.text for element in labels if isinstance(element, (ui.label, ui.badge))} == {
            'Research agent', 'Domain administrator'}
        actions = list(details.default_slot.children[1].descendants())
        assert {element.text for element in actions if isinstance(element, ui.button)} == {'Configure', 'Create subgroup'}
        user.find('Message').type('Hello research')
        user.find('Send').click()
        user.find('Send').trigger('click')
        await user.should_see('thinking_indicator')
        runtime.release.set()
        await asyncio.sleep(1.1)
        await user.should_see('Hello')
        await user.should_not_see('thinking_indicator')
        restored_count = len(runtime.restored)
        await asyncio.sleep(1.1)
        assert len(runtime.restored) == restored_count, 'Idle polling must not decrypt unchanged history'
        assert runtime.sent == [('human', 'agent', 'Hello research')]
        user.find('Configure').click()
        await user.should_see('Rotate credentials')
        owner_access = next(iter(user.find(kind=ui.checkbox, content='Access owner SSH public key').elements))
        assert owner_access.value is True and owner_access.enabled
        user.find('Access owner SSH public key').click()
        user.find('System prompt').clear().type('Explain research in German.')
        before_save = auth.calls
        user.find('Save').click()
        await asyncio.sleep(0.1)
        assert service.updates == [('human', 'agent', 'Explain research in German.')]
        assert auth.calls > before_save
        user.find('Configure').click()
        await user.should_see('Explain research in German.')
        assert not next(iter(user.find(kind=ui.checkbox, content='Access owner SSH public key').elements)).value
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
        await asyncio.sleep(1.1)
        await user.should_see('Failed')
        await user.should_not_see('thinking_indicator')
        redirects = []
        monkeypatch.setattr(user.navigate, 'to', redirects.append)
        auth.enabled = False
        user.find('New conversation').click()
        await asyncio.sleep(0.1)
        assert redirects == ['/login']
        auth.enabled, runtime.fail = True, False
        runtime.release.clear()
        runtime.finished.clear()
        user.find('Message').type('Finish after closing this page')
        user.find('Send').click()
        await user.should_see('thinking_indicator')
        user.client.delete()
        runtime.release.set()
        await asyncio.wait_for(runtime.finished.wait(), 1)
        await asyncio.sleep(0.05)
        assert 'has been deleted' not in caplog.text


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


@pytest.mark.parametrize('manage,all_tools', [(True, False), (False, False), (True, True)])
async def test_mcp_ui_separates_server_administration_and_agent_assignments(monkeypatch, manage, all_tools):
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

    class Service(AgentCapabilities):
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent], 'users': []}

        async def authorize(self, current, agent_id):
            assert current == identity and agent_id == 'agent'
            return agent

        async def providers(self, current):
            return []

    class Runtime:
        async def start(self):
            pass

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
                 'enabled': True, 'tools': ['*'] if all_tools else [], 'allowed_tools': None if manage else ['web_search']},
                {'id': 'other', 'name': 'Other service', 'url': 'https://other.example/mcp',
                 'enabled': True, 'tools': [], 'allowed_tools': None if manage else ['other_tool']}]}

        async def save_server(self, current, name, url, token=None, server_id=None, enabled=True):
            assert current == identity and manage
            if self.fail_save:
                raise ValueError('Invalid MCP endpoint')
            self.saved.append((name, url, token, server_id, enabled))
            return 'search'

        async def set_enabled(self, current, agent_id, server_id, enabled):
            assert isinstance(enabled, bool)

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
        user.find('hierarchy').trigger('update:selected', 'agent:agent')
        await user.should_see('Configure')
        user.find('Configure').click()
        await user.should_see('System prompt')
        user.find('MCP tools').click()
        await user.should_see('Search the public web')
        assert Integration.discoveries == ['search']
        assert next(iter(user.find(kind=ui.checkbox, content='web_search').elements)).value == all_tools
        if all_tools:
            assert next(iter(user.find(kind=ui.checkbox, content='web_extract').elements)).value
            await user.should_not_see('(unavailable)')
            user.find(kind=ui.checkbox, content='web_extract').click()
            user.find('Save assigned tools').click()
            await user.should_see('Assigned tools saved for this agent.')
            assert Integration.assigned == [('agent', 'search', ['web_search'])]
            return
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

    class Service(AgentCapabilities):
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent]}

        async def authorize(self, current, agent_id):
            assert current == identity and agent_id == 'agent'
            return agent

        async def providers(self, current):
            return [{'id': 'reported', 'name': 'Reported'}, {'id': 'local', 'name': 'Local'},
                    {'id': 'unavailable', 'name': 'Unavailable'}]

        async def update_agent(self, current, agent_id, provider_id, model, instructions, *, thinking, **compaction):
            assert current == identity and agent_id == 'agent'
            agent.update(provider_id=provider_id, model=model, instructions=instructions, thinking=thinking)

    class Runtime:
        async def start(self):
            pass

        block = False
        started = asyncio.Event()
        release = asyncio.Event()

        async def conversations(self, current, agent_id):
            return []

        async def models(self, current, provider_id):
            return ['model-a', 'model-b']

        async def context_limits(self, current, provider_id, model_id, context_window=None):
            return {'context_window': None, 'response_reserve': 8192, 'usable_tokens': None, 'source': 'No context metadata.'}

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
        user.find('hierarchy').trigger('update:selected', 'agent:agent')
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

    class Service(AgentCapabilities):
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent]}

        async def authorize(self, current, agent_id):
            assert current == identity and agent_id == 'agent'
            return agent

        async def providers(self, current):
            return []

    class Runtime:
        async def start(self):
            pass

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

        async def submit(self, current, agent_id, conversation_id, prompt):
            return {'conversation_id': 'conversation', 'operation_id': 'operation', 'status': 'running'}

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
        user.find('hierarchy').trigger('update:selected', 'agent:agent')
        await user.should_see('Configure')
        if not restored:
            user.find('New conversation').click()
            await user.should_not_see('Stop conversation')
        if restored:
            user.find('Conversation').trigger('update:modelValue', {'value': 0})
        else:
            user.find('Message').type('Run a task')
            user.find('Send').click()
        await user.should_see('Stop conversation')
        await user.should_not_see('Send')
        user.find('Message').type('interrupt text')
        await user.should_see('Send')
        await user.should_not_see('Stop conversation')
        user.find('Message').clear()
        await user.should_see('Stop conversation')
        await user.should_not_see('Send')
        await user.should_see('Partial reply retained')
        user.find('Stop conversation').click()
        if final_status == 'running':
            await user.should_see('Stop requested')
            await user.should_see('Stop conversation')
            assert next(iter(user.find(kind=ui.textarea, content='Message').elements)).enabled
            return
        await user.should_see('Blocked / paused' if final_status == 'reconciliation' else 'Stopped')
        await user.should_not_see('Stop conversation')
        await user.should_not_see('thinking_indicator')
        await user.should_not_see('Compacting context…')
        await user.should_see('Partial reply retained')
        assert runtime.stopped == ['operation']
        assert next(iter(user.find(kind=ui.textarea, content='Message').elements)).enabled
        user.find('Message').type('Next task')
        assert next(iter(user.find('Send').elements)).enabled


async def test_compaction_configuration_persists_and_context_meter_restores():
    agent = {'id': 'agent', 'name': 'Research', 'domain_id': 'domain', 'account_id': 'account',
             'provider_id': 'main', 'model': 'model-a', 'auto_compact_percent': None}
    identity = {'userid': 'human', 'username': 'alice', 'domainid': 'domain', 'type': 2, 'csrf': 'csrf'}

    class Auth:
        async def identity(self, token):
            return identity

    class Service(AgentCapabilities):
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent]}

        async def authorize(self, current, agent_id):
            return agent

        async def providers(self, current):
            return [{'id': 'main', 'name': 'Main'}, {'id': 'summary', 'name': 'Summary'}]

        async def update_agent(self, current, agent_id, provider_id, model, instructions, **settings):
            agent.update(provider_id=provider_id, model=model, instructions=instructions, **settings)

    class Runtime:
        async def start(self):
            pass

        saved_context = {'estimated_tokens': 321, 'context_window': 2000, 'response_reserve': 500,
                         'usable_tokens': 1500, 'percent': 21.4, 'threshold_percent': 75,
                         'source': 'Saved approximate usage'}

        async def conversations(self, current, agent_id):
            return [{'id': 'saved', 'title': 'Saved context'}]

        async def models(self, current, provider_id):
            return ['summary-small'] if provider_id == 'summary' else ['model-a', 'model-b']

        async def thinking_capabilities(self, current, provider_id, model):
            return {'options': {'default': 'Model default'}, 'source': 'No thinking controls advertised.'}

        async def context_limits(self, current, provider_id, model_id, context_window=None):
            assert current == identity
            window = context_window or (40000 if model_id == 'model-a' else None)
            reserve = min(8192, max(1, window // 4)) if window else 8192
            return {'context_window': window, 'response_reserve': reserve,
                    'usable_tokens': window - reserve if window else None,
                    'source': 'Manual context window override.' if context_window else
                              'Provider API context_window.' if window else 'API context limit unknown.'}

        async def restore(self, current, conversation_id):
            return {'id': 'saved', 'agent_id': 'agent', 'messages': [], 'runs': [
                {'id': 'run', 'status': 'completed', 'events': [], 'budget': {'context': self.saved_context, 'compactions': 1}}]}

    runtime = Runtime()
    async with user_simulation() as user:
        build_ui(Service(), Auth(), runtime)
        user.http_client.cookies.set('ds_session', 'session')
        await user.open('/')
        user.find('hierarchy').trigger('update:selected', 'agent:agent')
        await user.should_see('Configure')
        user.find('Configure').click()
        await user.should_see('Provider API context_window.')
        assert not next(iter(user.find(kind=ui.checkbox, content='Automatically compact context').elements)).value
        assert not next(iter(user.find(kind=ui.number, content='Compact at %').elements)).enabled
        user.find('Compaction provider').trigger('update:modelValue', {'value': 2})
        await user.should_see('Choose a model or enter a custom model ID.')
        user.find('Compaction model').trigger('update:modelValue', {'value': 0})
        user.find('Automatically compact context').click()
        user.find('Context window override').type('20000')
        await user.should_see('Manual context window override.')
        await user.should_see('20,000 − 5,000 response tokens = 15,000 tokens')
        user.find(kind=ui.button, content='Save').click()
        await asyncio.sleep(0.05)
        assert {key: agent[key] for key in ('compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window')} == {
            'compaction_provider_id': 'summary', 'compaction_model': 'summary-small', 'auto_compact_percent': 75, 'context_window': 20000}
        user.find('Configure').click()
        await user.should_see('Manual context window override.')
        assert next(iter(user.find(kind=ui.number, content='Compact at %').elements)).value == 75
        assert next(iter(user.find(kind=ui.select, content='Compaction model').elements)).value == 'summary-small'
        user.find('Model ID').trigger('update:modelValue', {'value': 1})
        user.find('Context window override').clear()
        await user.should_see('API context limit unknown.')
        await user.should_see('Enter a context window override before enabling automatic compaction.')
        user.find('Automatically compact context').click()
        user.find('Compact at %').clear()
        user.find('Compaction provider').trigger('update:modelValue', {'value': 0})
        await user.should_not_see('Compaction model')
        user.find(kind=ui.button, content='Save').click()
        await asyncio.sleep(0.05)
        assert agent['auto_compact_percent'] is None and agent['context_window'] is None
        assert agent['compaction_provider_id'] is None and agent['compaction_model'] == ''
        user.find('Conversation').trigger('update:modelValue', {'value': 0})
        await user.should_see('Completed')
        run_details_menu = next(iter(user.find('run_details_menu').elements))
        assert run_details_menu.value is False
        user.find('run_details_menu').trigger('update:modelValue', True)
        assert run_details_menu.value is True
        await user.should_see('Requests: 0')
        await user.should_see('Context compacted.')
        await user.should_see('Context: ~321 / 1,500 usable tokens (21.4%)')
        await user.should_see('Saved approximate usage')
        runtime.saved_context = runtime.saved_context | {'estimated_tokens': '[redacted]', 'usable_tokens': '[redacted]'}
        user.find('New conversation').click()
        await user.should_not_see('Saved approximate usage')
        user.find('Conversation').trigger('update:modelValue', {'value': 0})
        await user.should_see('Context usage unavailable for this activity.')
        assert not user.notify.messages, user.notify.messages


def test_hub_activity_only_includes_owner_visible_agents_and_latest_run():
    import sqlite3
    from dirigentenstab.web import conversation_activity

    database = sqlite3.connect(':memory:')
    database.row_factory = sqlite3.Row
    database.executescript('CREATE TABLE conversations(id,agent_id,human_id,title);'
                           'CREATE TABLE chat_runs(id,conversation_id,status,created,updated);'
                           "INSERT INTO conversations VALUES('c','visible','owner','Owned task'),"
                           "('hidden','hidden','owner','Hidden task'),('other','visible','other','Other owner');"
                           "INSERT INTO chat_runs VALUES('old','c','running',1,1),('new','c','completed',2,3),"
                           "('hidden','hidden','running',2,3),('other','other','running',2,3);")
    class Store:
        def all(self, sql, params):
            return [dict(row) for row in database.execute(sql, params)]
    assert conversation_activity(Store(), 'owner', ['visible']) == [
        {'id': 'c', 'agent_id': 'visible', 'title': 'Owned task', 'operation_id': 'new', 'status': 'completed', 'updated': 3}]
    assert conversation_activity(Store(), 'owner', []) == []


async def test_polling_preserves_conversation_option_values_when_activity_reorders_rows():
    identity = {'userid': 'owner', 'username': 'owner', 'domainid': 'domain', 'type': 2, 'csrf': 'csrf'}
    agent = {'id': 'agent', 'name': 'Research', 'domain_id': 'domain', 'account_id': 'account'}

    class Auth:
        async def identity(self, token):
            return identity

    class Service(AgentCapabilities):
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent]}

        async def authorize(self, current, agent_id):
            return agent

        async def providers(self, current):
            return []

    class Runtime:
        rows = [{'id': 'second', 'title': 'Second task'}, {'id': 'first', 'title': 'First task'}]
        restored = []

        async def conversations(self, current, agent_id):
            return self.rows

        async def restore(self, current, conversation_id):
            self.restored.append(conversation_id)
            return {'id': conversation_id, 'agent_id': 'agent', 'messages': [], 'runs': []}

    runtime = Runtime()
    async with user_simulation() as user:
        build_ui(Service(), Auth(), runtime)
        user.http_client.cookies.set('ds_session', 'session')
        await user.open('/')
        user.find('hierarchy').trigger('update:selected', 'agent:agent')
        await user.should_see('Configure')
        selector = next(iter(user.find(kind=ui.select, content='Conversation').elements))
        assert list(selector.options) == ['second', 'first']
        poll = next(element for element in user.client.elements.values()
                    if isinstance(element, ui.timer) and element.callback.__name__ == 'poll_activity')
        poll.deactivate()
        # Stopping the first task moves it ahead in the runtime's activity-sorted query.
        runtime.rows = list(reversed(runtime.rows))
        await poll.callback()
        assert list(selector.options) == ['second', 'first']
        user.find('Conversation').trigger('update:modelValue', {'value': 0})
        await user.should_see('Send')
        assert next(iter(user.find('Send').elements)).visible
        await asyncio.sleep(0)
        assert runtime.restored == ['second']


async def test_polling_updates_text_and_tool_status_without_replacing_history(monkeypatch):
    from types import SimpleNamespace

    identity = {'userid': 'owner', 'username': 'owner', 'domainid': 'domain', 'type': 2, 'csrf': 'csrf'}
    agent = {'id': 'agent', 'name': 'Research', 'domain_id': 'domain', 'account_id': 'account', 'is_main': True}
    call = {'type': 'tool_call', 'name': 'execute_api', 'call_id': 'call', 'operation_id': 'run',
            'content': {'command': 'listVirtualMachines'}}
    result = call | {'type': 'tool_result', 'content': {'virtualmachine': []}}

    class Service(AgentCapabilities):
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent]}

        async def authorize(self, current, agent_id):
            return agent

        async def providers(self, current):
            return []

    class Runtime:
        version = 0
        async def conversations(self, current, agent_id):
            return [{'id': 'conversation', 'title': 'Task'}]

        async def restore(self, current, conversation_id):
            return {'id': conversation_id, 'agent_id': 'agent', 'messages': [
                {'parts': [{'part_kind': 'user-prompt', 'content': 'Inspect'}]},
                {'parts': [{'part_kind': 'text', 'content': 'Partial' if not self.version else 'Partial complete'},
                           {'part_kind': 'tool-call', 'tool_call_id': 'call', 'tool_name': 'execute_api'}]},
            ], 'runs': [{'id': 'run', 'status': 'running', 'events': [call] + ([result] if self.version else [])}]}

    runtime = Runtime()
    async def current(token):
        return identity

    monkeypatch.setattr(web_chat, 'conversation_activity', lambda *args: [
        {'id': 'conversation', 'agent_id': 'agent', 'title': 'Task', 'operation_id': 'run',
         'status': 'running', 'updated': runtime.version}])
    async with user_simulation() as user:
        build_ui(Service(), SimpleNamespace(identity=current), runtime)
        await user.open('/')
        poll = next(element for element in user.client.elements.values()
                    if isinstance(element, ui.timer) and element.callback.__name__ == 'poll_activity')
        poll.deactivate()
        selector = next(iter(user.find(kind=ui.select, content='Conversation').elements))
        selector.set_value('conversation')
        await user.should_see('Partial')
        text = next(iter(user.find(kind=ui.markdown, content='Partial').elements))
        card = next(iter(user.find(kind=ui.expansion, content='execute_api').elements))
        runtime.version = 1
        await poll.callback()
        assert not text.is_deleted and text.content == 'Partial complete'
        assert not card.is_deleted and 'Completed' in card.text
        assert 'listVirtualMachines' in str(card._props['call_content'])
        await poll.callback()
        assert not text.is_deleted and not card.is_deleted


def test_history_displays_only_labeled_offering_system_notifications():
    history = {'messages': [{'parts': [
        {'part_kind': 'system-prompt', 'content': 'private instructions'},
        {'part_kind': 'system-prompt', 'dynamic_ref': 'compute_offering_decision', 'content': 'Offering approved'},
    ]}]}
    assert list(history_parts(history)) == [('notice', 'Compute offering approved and now available.')]


def test_history_hides_provider_converted_offering_notification_instructions():
    history = {'messages': [{'metadata': {'system_notification': 'compute_offering_decision'}, 'parts': [
        {'part_kind': 'user-prompt', 'content': '<system>[System notification: compute offering decision] internal approval instructions</system>'},
    ]}]}
    assert list(history_parts(history)) == [('notice', 'Compute offering approved and now available.')]


def test_history_preserves_real_user_beside_merged_offering_notification():
    history = {'messages': [{'parts': [
        {'part_kind': 'user-prompt', 'content': 'Continue with my VM'},
        {'part_kind': 'user-prompt', 'content': '<system>[System notification: compute offering decision] private data</system>'},
    ]}]}
    assert list(history_parts(history)) == [
        ('human', 'Continue with my VM'), ('notice', 'Compute offering approved and now available.')]


def test_history_displays_generic_escalation_notice_without_machine_instructions():
    history = {'messages': [{'parts': [
        {'part_kind': 'system-prompt', 'dynamic_ref': 'escalation_decision', 'content': 'private result'},
        {'part_kind': 'user-prompt', 'content': '<system>[System notification: escalation decision] private result</system>'},
    ]}]}
    assert list(history_parts(history)) == [('notice', 'Escalation result available.')] * 2


@pytest.mark.parametrize('mode', [
    ['Agents'], ['VMs'], ['Skills'], ['Agents', 'VMs'], ['Agents', 'Skills'],
    ['VMs', 'Skills'], ['Agents', 'VMs', 'Skills'],
])
def test_sidebar_resources_remain_under_creators_and_keep_only_needed_ancestors(mode):
    data = {
        'domains': [{'id': 'root', 'name': 'ROOT', 'level': 0},
                    {'id': 'parent', 'name': 'Parent', 'parentdomainid': 'root'},
                    {'id': 'child', 'name': 'Child', 'parentdomainid': 'parent'},
                    {'id': 'vm-owner', 'name': 'VM owner', 'parentdomainid': 'parent'},
                    {'id': 'empty', 'name': 'Empty', 'parentdomainid': 'parent'}],
        'agents': [{'id': aid, 'domain_id': aid, 'name': aid} for aid in ('parent', 'child', 'vm-owner', 'empty')],
        'vms': [{'id': 'vm', 'name': 'Worker', 'owner_agent': 'vm-owner'}],
        'skills': [{'id': 'skill', 'creator_agent_id': 'child', 'name': 'GPU setup',
                    'description': 'Prepare GPU capacity', 'text': 'FULL-TEXT-MUST-NOT-BE-IN-SIDEBAR'}],
    }
    nodes = hierarchy_nodes(data, mode=mode)
    parent = nodes[0]
    assert parent['id'] == 'agent:parent'
    expected = ['agent:child', 'agent:vm-owner', 'agent:empty'] if 'Agents' in mode else [
        *(['agent:child'] if 'Skills' in mode else []), *(['agent:vm-owner'] if 'VMs' in mode else [])]
    assert [child['id'] for child in parent['children']] == expected
    children = {child['id']: child for child in parent['children']}
    if 'Skills' in mode:
        assert children['agent:child']['children'] == [
            {'id': 'skill:skill', 'label': 'GPU setup', 'icon': 'description', 'children': []}]
    else:
        assert 'GPU setup' not in str(nodes)
    if 'VMs' in mode:
        assert children['agent:vm-owner']['children'] == [
            {'id': 'vm:vm', 'label': 'Worker', 'icon': 'dns', 'children': []}]
    else:
        assert 'Worker' not in str(nodes)
    for node in [parent, *parent['children']]:
        assert node.get('selectable', True) == ('Agents' in mode)
    assert 'FULL-TEXT-MUST-NOT-BE-IN-SIDEBAR' not in str(nodes)
    assert 'Prepare GPU capacity' not in str(nodes)


@pytest.mark.parametrize('mode', [['Skills'], ['Agents', 'Skills'], ['VMs', 'Skills'], ['Agents', 'VMs', 'Skills']])
def test_skills_preserve_creator_agent_on_native_root_and_separate_global_admin(mode):
    nodes = hierarchy_nodes({
        'domains': [{'id': 'root', 'name': 'ROOT', 'level': 0}],
        'agents': [{'id': 'root-creator', 'domain_id': 'root', 'name': 'Root creator'},
                   {'id': 'global', 'domain_id': 'root', 'name': 'Global', 'is_global': True}],
        'skills': [{'id': 'root-skill', 'name': 'Root skill', 'creator_agent_id': 'root-creator'},
                   {'id': 'global-skill', 'name': 'Global skill', 'creator_agent_id': 'global'}],
    }, mode=mode)
    assert [node['id'] for node in nodes] == ['agent:global', 'agent:root-creator']
    assert nodes[0]['children'] == [
        {'id': 'skill:global-skill', 'label': 'Global skill', 'icon': 'description', 'children': []}]
    assert nodes[1]['children'] == [
        {'id': 'skill:root-skill', 'label': 'Root skill', 'icon': 'description', 'children': []}]


async def test_unknown_main_pane_query_ids_fall_back_to_default_agent():
    identity = {'userid': 'owner', 'username': 'owner', 'domainid': 'domain', 'type': 2, 'csrf': 'csrf'}
    agent = {'id': 'agent', 'name': 'Research', 'domain_id': 'domain', 'account_id': 'account', 'is_main': True}

    class Auth:
        async def identity(self, token):
            return identity

    class Service(AgentCapabilities):
        async def hierarchy(self, current):
            return {'domains': [{'id': 'domain', 'name': 'Research'}], 'agents': [agent], 'vms': [], 'skills': []}

        async def authorize(self, current, agent_id):
            return agent

        async def providers(self, current):
            return []

    class Runtime:
        async def conversations(self, current, agent_id):
            return []

    async with user_simulation() as user:
        build_ui(Service(), Auth(), Runtime())
        user.http_client.cookies.set('ds_session', 'session')
        for query in ('agent=nope', 'vm=nope&mode=console', 'skill=nope'):
            await user.open('/?' + query)
            await user.should_see('Configure')
            await user.should_not_see('Console')
