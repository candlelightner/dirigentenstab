import asyncio
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from pydantic_ai.models.function import FunctionModel

from dirigentenstab.runtime import Runtime
from dirigentenstab.service import DEFAULT_SUMMARY_PROMPT, Service
from dirigentenstab.store import Store


@pytest.fixture
def service(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    for provider in ('main', 'summary-prov'):
        store.execute('INSERT INTO providers(id,name,protocol,base_url,api_key,default_model) VALUES(?,?,?,?,?,?)',
                      (provider, provider, 'chat', 'https://provider.invalid/v1', store.seal('secret'), provider + '-model'))
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,provider_id,model) '
                  'VALUES(?,?,?,?,?,?,?,?)', ('agent', 'Agent', 'domain', 'account', 'user', store.seal({'apikey': 'private'}),
                                             'main', 'main-model'))
    app = Service(store, SimpleNamespace(cloudstack_ui_url=''))

    async def authorize(identity, agent_id):
        return await app.agent(agent_id)

    async def chain(agent):
        return [agent]

    app.authorize, app.agent_chain = authorize, chain
    return app


def test_summary_settings_permissions_and_defaults(service):
    admin = {'userid': 'admin', 'type': 1}
    user = {'userid': 'user', 'type': 2}
    agent = {'userid': 'admin', 'type': 1, '_agent_id': 'agent'}

    with pytest.raises(PermissionError, match='Platform administrator required'):
        service.summary_settings(user)
    with pytest.raises(PermissionError, match='Platform administrator required'):
        service.summary_settings(agent)

    defaults = service.summary_settings(admin)
    assert defaults == {'provider_id': None, 'model': '', 'prompt': DEFAULT_SUMMARY_PROMPT}
    assert service.summary_settings() == defaults


def test_save_summary_settings_validation_and_audit(service):
    admin = {'userid': 'admin', 'type': 1}
    user = {'userid': 'user', 'type': 2}
    agent = {'userid': 'admin', 'type': 1, '_agent_id': 'agent'}

    with pytest.raises(PermissionError, match='Platform administrator required'):
        service.save_summary_settings(user, 'summary-prov', 'model-1', 'prompt')
    with pytest.raises(PermissionError, match='Platform administrator required'):
        service.save_summary_settings(agent, 'summary-prov', 'model-1', 'prompt')

    with pytest.raises(ValueError, match='Provider missing'):
        service.save_summary_settings(admin, 'unknown-provider', 'model-1', 'prompt')
    with pytest.raises(ValueError, match='Invalid model name'):
        service.save_summary_settings(admin, 'summary-prov', 'x' * 301, 'prompt')
    with pytest.raises(ValueError, match='Invalid prompt'):
        service.save_summary_settings(admin, 'summary-prov', 'model-1', 'x' * 16001)

    service.save_summary_settings(admin, 'summary-prov', 'summary-model', 'Summarize this')
    saved = service.summary_settings(admin)
    assert saved == {'provider_id': 'summary-prov', 'model': 'summary-model', 'prompt': 'Summarize this'}
    audit = service.store.all('SELECT * FROM audit WHERE operation=?', ('configure-summary-model',))
    assert len(audit) == 1 and audit[0]['actor'] == 'admin'

    # Clearing provider clears model
    service.save_summary_settings(admin, '', 'ignored', '')
    cleared = service.summary_settings(admin)
    assert cleared == {'provider_id': None, 'model': '', 'prompt': DEFAULT_SUMMARY_PROMPT}


@pytest.mark.asyncio
async def test_runtime_summarizes_title_on_first_message(service, monkeypatch):
    from dirigentenstab import runtime as runtime_module

    admin = {'userid': 'admin', 'type': 1}
    service.save_summary_settings(admin, 'summary-prov', 'summary-model', 'Custom summary prompt')

    async def fake_summary_model(messages, info):
        assert 'Custom summary prompt' in str(info.instructions)
        yield 'Summarized Conversation Title'

    monkeypatch.setattr(runtime_module, 'build_model', lambda *args: FunctionModel(stream_function=fake_summary_model))

    runtime = Runtime(service)
    result = await runtime.submit(admin, 'agent', None, 'Long user request that needs a good short title')
    conv_id = result['conversation_id']

    # Give background task time to complete
    for _ in range(50):
        row = service.store.one('SELECT title FROM conversations WHERE id=?', (conv_id,))
        if row and row['title'] == 'Summarized Conversation Title':
            break
        await asyncio.sleep(0.05)

    assert row['title'] == 'Summarized Conversation Title'

    # Second message on existing conversation does not re-summarize title
    async def failing_summary_model(messages, info):
        raise RuntimeError('Should not be called')

    monkeypatch.setattr(runtime_module, 'build_model', lambda *args: FunctionModel(stream_function=failing_summary_model))
    await runtime.submit(admin, 'agent', conv_id, 'Second message')
    await asyncio.sleep(0.1)
    row = service.store.one('SELECT title FROM conversations WHERE id=?', (conv_id,))
    assert row['title'] == 'Summarized Conversation Title'
