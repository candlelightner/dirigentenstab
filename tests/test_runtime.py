import json
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import DeltaToolCall, FunctionModel

from dirigentenstab import runtime
from dirigentenstab.store import Store


@pytest.fixture
def service(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    store.execute('INSERT INTO providers(id,name,protocol,base_url,api_key) VALUES(?,?,?,?,?)',
                  ('provider', 'Local', 'chat', 'http://inference/v1', store.seal('provider-secret')))
    for name in ('parent', 'child', 'other'):
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning,'
                      'provider_id,model) VALUES(?,?,?,?,?,?,?,?,?)',
                      (name, name, name + '-domain', name + '-account', name + '-user',
                       store.seal({'apikey': name + '-secret'}), store.seal({}), 'provider', name))

    class Service:
        settings = SimpleNamespace(workspace=str(tmp_path / 'transfers'), max_output=1024,
                                   ssh_networks='10.50.0.0/24')

        def __init__(self):
            self.store = store
            self.executions = []

        async def agent(self, agent_id):
            return store.one('SELECT * FROM agents WHERE id=?', (agent_id,))

        async def authorize(self, identity, agent_id):
            if identity['userid'] != 'human' or agent_id == 'other':
                raise PermissionError('not authorized')
            return await self.agent(agent_id)

        async def context(self, agent):
            return {'name': agent['name'], 'domain_id': agent['domain_id']}

        async def can_delegate(self, caller, target):
            return caller == 'parent' and target == 'child'

        async def execute(self, agent_id, command, params):
            self.executions.append((agent_id, command, params))
            return {'result': 'SUPERSECRET VM ready'}

        async def search_api(self, agent_id, query):
            return {'api': []}

        async def describe_api(self, agent_id, command):
            return {'name': command}

        async def create_subgroup(self, agent_id, name, model, instructions):
            return {'id': 'new-child'}

        def redact(self, value):
            if isinstance(value, str):
                return value.replace('SUPERSECRET', '[redacted]')
            if isinstance(value, dict):
                return {key: self.redact(item) for key, item in value.items()}
            if isinstance(value, list):
                return [self.redact(item) for item in value]
            return value

    return Service()


async def test_streamed_delegation_uses_child_identity_and_restores_private_history(service, monkeypatch):
    observed_child_history = []

    def child(messages, info):
        assert 'parent-secret' not in str(messages) + str(info.instructions)
        if any(part.part_kind == 'tool-return' for part in messages[-1].parts):
            observed_child_history.extend(messages)
            assert 'SUPERSECRET' not in str(messages[-1])
            return ModelResponse(parts=[TextPart('Child completed its own task')])
        return ModelResponse(parts=[ToolCallPart('execute_api', {'command': 'listVirtualMachines', 'params': {}})])

    async def parent(messages, info):
        if any(part.part_kind == 'tool-return' for part in messages[-1].parts):
            yield 'Delegation '
            yield 'complete'
        else:
            yield {0: DeltaToolCall(name='delegate', json_args=json.dumps({'agent_id': 'child', 'task': 'inspect'}))}

    monkeypatch.setattr(runtime, 'build_model', lambda provider, model, store:
                        FunctionModel(child) if model == 'child' else FunctionModel(stream_function=parent))
    manager = runtime.Runtime(service)
    events = []

    async def emit(event):
        events.append(event)

    result = await manager.chat({'userid': 'human'}, 'parent', None, 'inspect SUPERSECRET', emit)
    assert result['output'] == 'Delegation complete'
    assert service.executions == [('child', 'listVirtualMachines', {})]
    assert observed_child_history
    assert any(event['type'] == 'tool_result' and event['name'] == 'delegate' for event in events)
    assert ''.join(event['text'] for event in events if event['type'] == 'text') == result['output']
    restored = await manager.restore({'userid': 'human'}, result['conversation_id'])
    assert 'SUPERSECRET' not in str(restored)
    assert '[redacted]' in str(restored)
    assert len(await manager.conversations({'userid': 'human'}, 'child')) == 1
    with pytest.raises(PermissionError):
        await manager.restore({'userid': 'other-human'}, result['conversation_id'])
    assert b'Child completed its own task' not in service.store.path.read_bytes()


async def test_failed_runtime_suppresses_provider_secrets_and_preserves_retryable_history(service, monkeypatch):
    def fail(*args):
        raise RuntimeError('provider failed with SUPERSECRET')

    monkeypatch.setattr(runtime, 'build_model', fail)
    manager = runtime.Runtime(service)
    with pytest.raises(ValueError, match='Agent execution failed') as error:
        await manager.chat({'userid': 'human'}, 'parent', None, 'Hello')
    assert 'SUPERSECRET' not in str(error.value)
    conversation = (await manager.conversations({'userid': 'human'}, 'parent'))[0]
    restored = await manager.restore({'userid': 'human'}, conversation['id'])
    assert 'Execution interrupted' in str(restored['messages'])
    assert not manager.running


async def test_provider_requires_actual_nonce_tool_invocation(service, monkeypatch):
    async def models(*args):
        return ['local']

    def tool_model(messages, info):
        if any(part.part_kind == 'tool-return' for part in messages[-1].parts):
            return ModelResponse(parts=[TextPart('probe completed')])
        nonce = messages[-1].parts[0].content.split('value ')[1].split(',')[0]
        return ModelResponse(parts=[ToolCallPart('probe', {'value': nonce})])

    monkeypatch.setattr(runtime, 'provider_models', models)
    monkeypatch.setattr(runtime, 'build_model', lambda *args: FunctionModel(tool_model))
    provider = service.store.one('SELECT * FROM providers')
    result = await runtime.test_provider(provider, 'local', service.store)
    assert result == {'reachable': True, 'authenticated': True, 'model_available': True,
                      'tool_calling': True, 'error': None}
    monkeypatch.setattr(runtime, 'build_model', lambda *args:
                        FunctionModel(lambda messages, info: ModelResponse(parts=[TextPart('reachable')])) )
    result = await runtime.test_provider(provider, 'local', service.store)
    assert result['reachable'] and not result['tool_calling']
