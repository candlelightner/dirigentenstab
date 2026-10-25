import asyncio

import pytest
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
    research = nodes[0]['children'][0]
    training = research['children'][0]
    assert training['children'][0] == {'id': 'agent:local', 'label': 'Trainer · local-model'}
    assert research['children'][1]['label'] == 'Administrator: alice'
    assert 'DO-NOT-EXPOSE' not in str(nodes)


def test_tree_preserves_scoped_root_without_inventing_missing_parent():
    nodes = hierarchy_nodes({'domains': [{'id': 'research', 'name': 'Research', 'parentdomainid': 'hidden'}]})
    assert nodes == [{'id': 'domain:research', 'label': 'Research', 'children': []}]


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
             'account_id': 'cloud-account', 'model': 'local-model', 'can_provision': False}

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

    class Runtime:
        sent = []

        async def conversations(self, identity, agent_id):
            return [{'id': 'conversation', 'title': 'Example'}]

        async def chat(self, identity, agent_id, conversation_id, prompt, on_event):
            self.sent.append((identity['userid'], agent_id, prompt))
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
        user.find('Message').type('Hello research')
        user.find('Send').click()
        await asyncio.sleep(0.1)
        await user.should_see('Hello')
        assert runtime.sent == [('human', 'agent', 'Hello research')]
        user.find('Configure').click()
        await user.should_see('Rotate credentials')
        user.find('Rotate credentials').click()
        await asyncio.sleep(0.1)
        assert service.rotations == [('human', 'agent')]
        assert auth.calls >= 4
        redirects = []
        monkeypatch.setattr(user.navigate, 'to', redirects.append)
        auth.enabled = False
        user.find('New conversation').click()
        await asyncio.sleep(0.1)
        assert redirects == ['/login']
