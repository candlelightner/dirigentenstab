import json
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from pydantic_ai.messages import ModelMessagesTypeAdapter, ModelRequest, ModelResponse, TextPart, ToolCallPart, UserPromptPart
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
    assert 'Hello' in str(restored['messages'])
    assert restored['runs'][-1]['status'] == 'failed'
    assert not manager.running


async def test_imported_history_is_read_only_and_never_automatically_sent_to_a_model(service, monkeypatch):
    original = json.loads(ModelMessagesTypeAdapter.dump_json([
        ModelRequest(parts=[UserPromptPart('legacy-private-context')]),
        ModelResponse(parts=[TextPart('Historical tool output, not a current tool invocation')]),
    ]))
    encrypted = service.store.seal(original)
    service.store.execute('INSERT INTO conversations VALUES(?,?,?,?,?,?,1)',
                          ('legacy', 'parent', 'human', 'Imported history', 1, encrypted))

    async def model(messages, info):
        assert 'legacy-private-context' not in str(messages)
        assert messages[-1].parts[0].content == 'New task'
        yield 'New conversation'

    monkeypatch.setattr(runtime, 'build_model', lambda *args: FunctionModel(stream_function=model))
    manager = runtime.Runtime(service)
    assert (await manager.restore({'userid': 'human'}, 'legacy'))['imported']
    result = await manager.chat({'userid': 'human'}, 'parent', 'legacy', 'New task')
    assert result['conversation_id'] != 'legacy'
    assert service.store.one('SELECT messages FROM conversations WHERE id=?', ('legacy',))['messages'] == encrypted


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


async def test_second_turn_after_redaction_and_legacy_usage_recovery(service, monkeypatch):
    from dirigentenstab.cloud import redact
    from pydantic_ai.usage import RequestUsage
    service.redact = redact
    calls = []

    async def subgroup(agent_id, name, model, instructions):
        calls.append((agent_id, name))
        return {'id': 'sandbox', 'name': name}

    service.create_subgroup = subgroup

    def model(messages, info):
        if any(p.part_kind == 'tool-return' for p in messages[-1].parts):
            return ModelResponse(parts=[TextPart('Sandbox ready')], usage=RequestUsage(input_tokens=42, output_tokens=3))
        if any(p.part_kind == 'user-prompt' and p.content == 'Create Sandbox' for p in messages[-1].parts):
            return ModelResponse(parts=[ToolCallPart('create_subgroup', {'name': 'Sandbox'})])
        return ModelResponse(parts=[TextPart('32 domains, 21 VMs')], usage=RequestUsage(input_tokens=100, output_tokens=8))

    async def stream(messages, info):
        response = model(messages, info)
        for part in response.parts:
            if isinstance(part, ToolCallPart):
                yield {0: DeltaToolCall(name=part.tool_name, json_args=part.args_as_json_str(), tool_call_id=part.tool_call_id)}
            elif isinstance(part, TextPart):
                yield part.content

    monkeypatch.setattr(runtime, 'build_model', lambda *args: FunctionModel(stream_function=stream))
    manager = runtime.Runtime(service)
    first = await manager.chat({'userid': 'human'}, 'parent', None, 'Inventory')
    restored = await manager.restore({'userid': 'human'}, first['conversation_id'])
    ModelMessagesTypeAdapter.validate_python(restored['messages'])
    assert type(restored['messages'][-1]['usage']['input_tokens']) is int
    # Actual v0.1.2 persisted shape: every field containing "token" was replaced.
    restored['messages'][-1]['usage']['input_tokens'] = '[redacted]'
    restored['messages'][-1]['usage']['details'] = {'reasoning_tokens': '[redacted]'}
    service.store.execute('UPDATE conversations SET messages=? WHERE id=?',
                          (service.store.seal(restored['messages']), first['conversation_id']))
    second = await manager.chat({'userid': 'human'}, 'parent', first['conversation_id'], 'Create Sandbox')
    assert second['output'] == 'Sandbox ready'
    assert calls == [('parent', 'Sandbox')]
    assert not manager.running


async def test_provider_failure_keeps_completed_tools_and_correlation(service, monkeypatch, caplog):
    from pydantic_ai.exceptions import ModelHTTPError
    def model(messages, info):
        if any(p.part_kind == 'tool-return' for p in messages[-1].parts):
            raise ModelHTTPError(503, 'fixture', {'private': 'SUPERSECRET private conversation'})
        return ModelResponse(parts=[ToolCallPart('execute_api', {'command': 'listDomains', 'params': {}},
                                               tool_call_id='call-1')])

    async def stream(messages, info):
        response = model(messages, info)
        for part in response.parts:
            if isinstance(part, ToolCallPart):
                yield {0: DeltaToolCall(name=part.tool_name, json_args=part.args_as_json_str(), tool_call_id=part.tool_call_id)}
            elif isinstance(part, TextPart):
                yield part.content

    monkeypatch.setattr(runtime, 'build_model', lambda *args: FunctionModel(stream_function=stream))
    manager = runtime.Runtime(service)
    with pytest.raises(ValueError) as error:
        await manager.chat({'userid': 'human'}, 'parent', None, 'private conversation')
    restored = await manager.restore({'userid': 'human'}, (await manager.conversations({'userid': 'human'}, 'parent'))[0]['id'])
    assert any(p['part_kind'] == 'tool-return' for m in restored['messages'] for p in m['parts'])
    run = restored['runs'][-1]
    assert run['status'] == 'failed' and run['category'] == 'model-provider'
    assert [e['type'] for e in run['events']] == ['tool_call', 'tool_result']
    assert run['events'][0]['call_id'] == run['events'][1]['call_id'] == 'call-1'
    assert error.value.operation_id == run['id']
    assert 'Traceback' in caplog.text and run['id'] in caplog.text
    assert 'SUPERSECRET' not in caplog.text + str(error.value)
    assert 'private conversation' not in caplog.text


async def test_disconnected_browser_does_not_lose_tracked_operation(service, monkeypatch):
    async def stream(messages, info):
        yield 'Done'
    monkeypatch.setattr(runtime, 'build_model', lambda *args: FunctionModel(stream_function=stream))
    manager = runtime.Runtime(service)

    async def disconnected(event):
        raise ConnectionError('private socket credential')

    result = await manager.chat({'userid': 'human'}, 'parent', None, 'inspect', disconnected)
    restored = await manager.restore({'userid': 'human'}, result['conversation_id'])
    assert restored['runs'][-1]['status'] == 'completed'


def test_only_numeric_usage_counters_bypass_secret_redaction():
    from dirigentenstab.cloud import redact
    value = redact({'input_tokens': 12, 'output_tokens': 0, 'access_token': 1234,
                    'nested': {'input_tokens': 'private-token', 'token': 'private'}})
    assert value['input_tokens'] == 12 and value['output_tokens'] == 0
    assert value['access_token'] == value['nested']['input_tokens'] == value['nested']['token'] == '[redacted]'


@pytest.mark.parametrize('status,body,expected', [
    (200, {'data': [{'id': 'first'}, {'id': 'second'}, {'invalid': 'missing'}]}, ['first', 'second']),
    (200, {'data': []}, []), (404, {}, None), (401, {'error': 'private credentials'}, None),
    (200, {'invalid': []}, None),
])
async def test_model_discovery_server_side_and_bounded(service, monkeypatch, status, body, expected):
    import httpx
    real_client = httpx.AsyncClient
    observed = []

    def handle(request):
        observed.append(request)
        return httpx.Response(status, json=body)

    monkeypatch.setattr(runtime.httpx, 'AsyncClient', lambda **kwargs:
                        real_client(**kwargs, transport=httpx.MockTransport(handle)))
    provider = service.store.one('SELECT * FROM providers WHERE id=?', ('provider',))
    if expected is None:
        with pytest.raises((httpx.HTTPStatusError, ValueError)):
            await runtime.provider_models(provider, service.store)
    else:
        assert await runtime.provider_models(provider, service.store) == expected
    assert str(observed[0].url) == 'http://inference/v1/models'
    assert observed[0].headers['Authorization'] == 'Bearer provider-secret'


@pytest.mark.parametrize('code,category,description', [
    (401, 'authentication', 'API key'), (403, 'authentication', 'account access'),
    (404, 'model-provider', 'Model ID'), (429, 'model-provider', 'quota'),
    (503, 'model-provider', 'unavailable'), (400, 'model-provider', 'compatibility'),
])
def test_specific_provider_errors_never_expose_payload(code, category, description, caplog):
    from dirigentenstab.diagnostics import diagnose
    from pydantic_ai.exceptions import ModelHTTPError
    error = diagnose(ModelHTTPError(code, 'private model', {'error': 'secret private conversation'}),
                     operation_id='operation', agent_id='agent', tool='execute_api')
    assert error.category == category and description in str(error)
    assert 'private' not in str(error) + caplog.text and 'secret' not in str(error) + caplog.text
    assert 'agent=agent tool=execute_api' in caplog.text


async def test_partial_stream_and_interruption_survive_reload(service, monkeypatch):
    from pydantic_ai.exceptions import ModelHTTPError

    async def stream(messages, info):
        yield 'Work completed before the connection failed.'
        raise ModelHTTPError(503, 'fixture', {})

    monkeypatch.setattr(runtime, 'build_model', lambda *args: FunctionModel(stream_function=stream))
    manager = runtime.Runtime(service)
    with pytest.raises(ValueError):
        await manager.chat({'userid': 'human'}, 'parent', None, 'inspect')
    conversation = (await manager.conversations({'userid': 'human'}, 'parent'))[0]
    restored = await manager.restore({'userid': 'human'}, conversation['id'])
    assert 'Work completed before the connection failed.' in str(restored['messages'])
    assert restored['runs'][-1]['status'] == 'failed'
    service.store.execute("UPDATE chat_runs SET status='running'")
    restarted = runtime.Runtime(service)
    assert (await restarted.restore({'userid': 'human'}, conversation['id']))['runs'][-1]['status'] == 'interrupted'


def test_interrupted_tool_history_is_closed_without_reexecuting():
    history = json.loads(ModelMessagesTypeAdapter.dump_json([
        ModelRequest(parts=[UserPromptPart('Create Sandbox')]),
        ModelResponse(parts=[ToolCallPart('create_subgroup', {'name': 'Sandbox'}, tool_call_id='interrupted')]),
    ]))
    recovered = runtime.load_history(history)
    result = recovered[-1].parts[0]
    assert result.part_kind == 'tool-return' and result.tool_call_id == 'interrupted'
    assert 'Outcome unknown' in result.content
