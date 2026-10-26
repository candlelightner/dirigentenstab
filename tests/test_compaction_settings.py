from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab.service import Service
from dirigentenstab.store import Store


@pytest.fixture
def service(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    for provider in ('main', 'summary'):
        store.execute('INSERT INTO providers(id,name,protocol,base_url,api_key,default_model) VALUES(?,?,?,?,?,?)',
                      (provider, provider, 'chat', 'https://provider.invalid/v1', store.seal('secret'), provider + '-model'))
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,provider_id,model) '
                  'VALUES(?,?,?,?,?,?,?,?)', ('agent', 'Agent', 'domain', 'account', 'user', store.seal({'apikey': 'private'}),
                                             'main', 'main-model'))
    app = Service(store, SimpleNamespace())

    async def authorize(identity, agent_id):
        if identity['userid'] != 'owner' or agent_id != 'agent':
            raise PermissionError('Agent outside your CloudStack domain')
        return await app.agent(agent_id)

    async def chain(agent):
        return [agent]
    app.authorize, app.agent_chain = authorize, chain
    return app


async def test_compaction_configuration_persists_and_omitted_fields_are_preserved(service):
    owner = {'userid': 'owner', 'type': 2}
    original = await service.agent('agent')
    assert original['auto_compact_percent'] is None and original['compaction_model'] == ''
    await service.update_agent(owner, 'agent', 'main', 'main-model', 'Prompt', compaction_provider_id='summary',
                               compaction_model='cheap-model', auto_compact_percent=80, context_window=32000)
    await service.update_agent(owner, 'agent', 'main', 'new-main-model', 'New prompt', thinking='high')
    agent = await service.agent('agent')
    assert {key: agent[key] for key in ('compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window')} == {
        'compaction_provider_id': 'summary', 'compaction_model': 'cheap-model',
        'auto_compact_percent': 80, 'context_window': 32000}
    assert agent['credentials'] == original['credentials']
    await service.update_agent(owner, 'agent', 'main', 'new-main-model', '', compaction_provider_id=None,
                               compaction_model='', auto_compact_percent=None, context_window=None)
    agent = await service.agent('agent')
    assert agent['compaction_provider_id'] is agent['auto_compact_percent'] is agent['context_window'] is None
    assert agent['compaction_model'] == ''


@pytest.mark.parametrize('options', [
    {'auto_compact_percent': 0}, {'auto_compact_percent': 100}, {'auto_compact_percent': True},
    {'auto_compact_percent': 80.5}, {'context_window': 1}, {'context_window': False},
    {'context_window': 2147483648}, {'compaction_provider_id': 'missing'},
    {'compaction_provider_id': []}, {'compaction_model': False}, {'compaction_model': 'x' * 257},
])
async def test_invalid_compaction_settings_never_partially_change_agent(service, options):
    original = await service.agent('agent')
    with pytest.raises(ValueError):
        await service.update_agent({'userid': 'owner', 'type': 1}, 'agent', 'main', 'changed', 'changed',
                                   can_provision=False, **options)
    assert await service.agent('agent') == original


async def test_compaction_settings_require_agent_ownership(service):
    with pytest.raises(PermissionError):
        await service.update_agent({'userid': 'other', 'type': 1}, 'agent', 'main', '', '', auto_compact_percent=80)
    assert (await service.agent('agent'))['auto_compact_percent'] is None


def test_compaction_migration_retains_original_encrypted_history_and_keys(service):
    store = service.store
    original = store.one('SELECT credentials FROM agents')['credentials']
    history = store.seal([{'private': 'full original transcript'}])
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'agent', 'owner', 'Existing', 1, history))
    store.execute('DROP TABLE conversation_compactions')
    for column in ('compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window'):
        store.execute('ALTER TABLE agents DROP COLUMN ' + column)
    store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_providers')
    store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    store.execute('PRAGMA user_version=13')
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    assert reopened.one('PRAGMA user_version')['user_version'] == 16
    assert reopened.one('SELECT messages FROM conversations')['messages'] == history
    assert reopened.one('SELECT credentials FROM agents')['credentials'] == original
    assert reopened.one('SELECT auto_compact_percent FROM agents')['auto_compact_percent'] is None
    assert reopened.all('SELECT * FROM conversation_compactions') == []


async def test_context_limits_use_advertised_size_and_reserve_response_space(service, monkeypatch):
    from dirigentenstab.runtime import Runtime
    runtime = Runtime(service)
    calls = []

    async def catalogue(identity, provider_id):
        calls.append(provider_id)
        return {'default_model': 'main-model'}, [{'id': 'main-model', 'context_window': 1000000},
                                                {'id': 'small', 'max_model_len': 8192},
                                                {'id': 'local', 'meta': {'n_ctx': 16000}},
                                                {'id': 'training-only', 'meta': {'n_ctx_train': 131072}}]

    monkeypatch.setattr(runtime, '_catalogue', catalogue)
    owner = {'userid': 'owner', 'type': 2}
    limits = await runtime.context_limits(owner, 'main', 'main-model')
    assert limits == {'context_window': 1000000, 'response_reserve': 8192,
                      'usable_tokens': 991808, 'source': 'Provider model API (context_window).'}
    small = await runtime.context_limits(owner, 'main', 'small')
    assert small['response_reserve'] == 2048 and small['usable_tokens'] == 6144
    local = await runtime.context_limits(owner, 'main', 'local')
    assert local['context_window'] == 16000 and 'meta.n_ctx' in local['source']
    assert (await runtime.context_limits(owner, 'main', 'training-only'))['context_window'] is None
    before = len(calls)
    manual = await runtime.context_limits(owner, 'main', 'private-id', 32000)
    assert manual['context_window'] == 32000 and 'Manual' in manual['source'] and len(calls) == before
    with pytest.raises(PermissionError):
        await runtime.context_limits({'userid': 'other', 'type': 0}, 'main', '', 32000)


async def test_unknown_context_limit_is_explicit_without_guessing(service, monkeypatch):
    import httpx
    from dirigentenstab.runtime import Runtime
    runtime = Runtime(service)

    async def unavailable(*args):
        raise httpx.ConnectError('private connection detail')

    monkeypatch.setattr(runtime, '_catalogue', unavailable)
    limits = await runtime.context_limits({'userid': 'owner', 'type': 2}, 'main', 'custom-id')
    assert limits['context_window'] is limits['usable_tokens'] is None
    assert 'unavailable' in limits['source'] and 'private connection detail' not in limits['source']


async def test_runtime_uses_selected_compactor_and_keeps_full_archive_across_turns(service, monkeypatch):
    import json
    from pydantic_ai.messages import ModelMessagesTypeAdapter, ModelRequest, ModelResponse, TextPart, UserPromptPart
    from pydantic_ai.models.function import FunctionModel
    from dirigentenstab import runtime as module

    observed, summaries, events = [], [], []
    original = [ModelRequest(parts=[UserPromptPart('Original task: ' + 'important facts ' * 1800)]),
                ModelResponse(parts=[TextPart('Old completed work ' * 1000)]),
                ModelRequest(parts=[UserPromptPart('Preserve resource R-123')]),
                ModelResponse(parts=[TextPart('Recent result ' * 250)])]
    store = service.store
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'agent', 'owner', 'Long task', 1,
                   store.seal(json.loads(ModelMessagesTypeAdapter.dump_json(original)))))
    await service.update_agent({'userid': 'owner', 'type': 2}, 'agent', 'main', 'main-model', 'Always be precise.',
                               compaction_provider_id='summary', compaction_model='cheap-summary',
                               auto_compact_percent=50, context_window=20000)

    async def context(record):
        return {'name': record['name']}

    async def reply(messages, info):
        observed.append(messages)
        assert 'Always be precise.' in info.instructions
        yield 'Main response'

    def summarize(messages, info):
        summaries.append(messages)
        assert not info.function_tools
        return ModelResponse(parts=[TextPart('The original task completed earlier work; retain resource R-123.')])

    def build(provider, model_id, _store):
        if provider['id'] == 'summary':
            assert model_id == 'cheap-summary'
            return FunctionModel(summarize)
        assert provider['id'] == 'main' and model_id == 'main-model'
        return FunctionModel(stream_function=reply)

    async def emit(event):
        events.append(event)

    service.context = context
    monkeypatch.setattr(module, 'build_model', build)
    manager = module.Runtime(service)
    identity = {'userid': 'owner', 'type': 2}
    result = await manager.chat(identity, 'agent', 'conversation', 'Continue the task exactly.', emit)
    assert result['output'] == 'Main response' and len(summaries) == 1
    assert 'important facts important facts' not in str(observed[0])
    assert 'Continue the task exactly.' in str(observed[0])
    saved = store.open(store.one("SELECT messages FROM conversations WHERE id='conversation'")['messages'])
    assert 'important facts important facts' in str(saved) and 'Old completed work' in str(saved)
    assert len(saved) == len(original) + 2
    restored = await manager.restore(identity, 'conversation')
    assert restored['runs'][-1]['budget']['compactions'] == 1
    assert restored['runs'][-1]['budget']['context']['response_reserve'] == 5000
    assert any(event['type'] == 'context_usage' for event in events)
    await manager.chat(identity, 'agent', 'conversation', 'One small follow-up.')
    assert len(summaries) == 1
    assert 'important facts important facts' in str(store.open(
        store.one("SELECT messages FROM conversations WHERE id='conversation'")['messages']))
