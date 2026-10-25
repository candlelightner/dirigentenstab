import time
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab import auth as auth_module
from dirigentenstab.cloud import Cloud, validate
from dirigentenstab.service import Service
from dirigentenstab.store import Store


@pytest.fixture
def store(tmp_path):
    master = tmp_path / 'key'
    master.write_bytes(Fernet.generate_key())
    return Store(str(tmp_path / 'state.db'), str(master))


async def test_socket_client_id_cannot_cross_sessions_or_unbound_sockets(store, monkeypatch):
    from nicegui import Client, core

    accepted = []

    def original(sid, message):
        accepted.append((sid, message['client_id']))
        return True

    def original_connect(sid, environ, data=None):
        accepted.append(('connect', sid))
        return True

    handlers = {name: original for name in ('handshake', 'event', 'javascript_response', 'ack', 'log')}
    handlers['connect'] = original_connect
    monkeypatch.setattr(core.sio, 'handlers', {'/': handlers})
    scopes = {name: {'asgi.scope': {'ds_identity': {'_session': name}}} for name in ('alice', 'bob')}
    scopes['unbound'] = scopes['alice']
    monkeypatch.setattr(core.sio, 'get_environ', lambda sid: scopes[sid])
    client = SimpleNamespace(request=SimpleNamespace(scope={'ds_identity': {'_session': 'alice'}}),
                             _socket_to_document_id={'alice': 'document'})
    monkeypatch.setattr(Client, 'instances', {'victim-client': client})
    for identity in ('alice', 'bob'):
        store.execute('INSERT INTO sessions(token_hash,csrf,identity,expires) VALUES(?,?,?,?)',
                      (identity, 'csrf', store.seal({}), time.time() + 60))
    auth_module.bind_sockets(SimpleNamespace(store=store))
    for sender in ('alice', 'bob'):
        environ = {**scopes[sender], 'QUERY_STRING': 'client_id=victim-client&implicit_handshake=true'}
        result = await handlers['connect'](sender, environ)
        assert result is (sender == 'alice')
    assert accepted == [('connect', 'alice')]
    accepted.clear()
    for name in ('event', 'javascript_response', 'ack', 'log'):
        await handlers[name]('bob', {'client_id': 'victim-client'})
        await handlers[name]('unbound', {'client_id': 'victim-client'})
        assert accepted == []
        await handlers[name]('alice', {'client_id': 'victim-client'})
        assert accepted.pop() == ('alice', 'victim-client')
    await handlers['handshake']('bob', {'client_id': 'victim-client'})
    assert accepted == []
    store.execute('DELETE FROM sessions WHERE token_hash=?', ('alice',))
    await handlers['event']('alice', {'client_id': 'victim-client'})
    assert accepted == []


@pytest.mark.parametrize('value', ['@/run/secrets/master_key', '"@/etc/shadow"', '""@/etc/passwd'])
async def test_cloudmonkey_file_expansion_is_rejected_before_subprocess(value):
    metadata = {'params': [{'name': 'name', 'type': 'string'}]}
    with pytest.raises(ValueError, match='File references'):
        validate(metadata, {'name': value})
    cloud = Cloud(SimpleNamespace(), {'apikey': 'key', 'secretkey': 'secret'})
    with pytest.raises(ValueError, match='Local file inputs'):
        await cloud.raw('listVirtualMachines', {'name': value})


@pytest.mark.parametrize('parameter', ['sessionkey', 'apikey', 'secretkey', 'signature', 'signatureversion'])
def test_runtime_cannot_override_server_selected_authentication(parameter):
    metadata = {'params': [{'name': parameter, 'type': 'string'}]}
    with pytest.raises(ValueError, match='authentication is selected by the server'):
        validate(metadata, {parameter: '/host/private'})


@pytest.mark.parametrize('parameter', ['hostid', 'hosttags', 'extraconfig', 'details', 'mountpoint', 'path', 'filepath'])
def test_remote_cloudstack_parameters_remain_subject_to_native_permissions(parameter):
    metadata = {'params': [{'name': parameter, 'type': 'string'}]}
    assert validate(metadata, {parameter: '/cloudstack/remote/path'}) is None


async def test_key_retry_adopts_the_committed_operation_pair_without_reissuing_or_deleting(store, monkeypatch):
    service = Service(store, SimpleNamespace())
    agent = {'user_id': 'user', 'account_id': 'account', 'domain_id': 'domain'}
    pair = {'id': 'orphan', 'apikey': 'orphan-api', 'secretkey': 'orphan-secret'}
    existing = {**pair, 'name': 'ds-operation-key', 'userid': 'user', 'accountid': 'account',
                'domainid': 'domain', 'state': 'Enabled'}

    async def owned(call, actual):
        assert actual == agent
        return [existing]

    async def forbidden(*args):
        pytest.fail('A committed, operation-named pair must be adopted without issuance or deletion')

    monkeypatch.setattr(service, '_owned_keys', owned)
    monkeypatch.setattr(service, '_key', forbidden)
    assert await service._credentials(forbidden, agent, 'operation') == pair


async def test_credential_maintenance_denies_out_of_scope_humans_before_mutation(store, monkeypatch):
    service = Service(store, SimpleNamespace())

    async def denied(*args, **kwargs):
        raise PermissionError('Outside your CloudStack domain')

    async def forbidden(*args):
        pytest.fail('Denied maintenance must never reach a privileged credential operation')

    monkeypatch.setattr(service, 'authorize', denied)
    monkeypatch.setattr(service, 'human_call', forbidden)
    for operation in (service.rotate_credentials, service.revoke_agent):
        with pytest.raises(PermissionError, match='Outside'):
            await operation({'userid': 'human'}, 'agent')


async def test_agent_cloud_client_uses_only_its_single_recorded_pair(store, monkeypatch):
    service = Service(store, SimpleNamespace())
    pair = {'id': 'one-key', 'apikey': 'one-api', 'secretkey': 'one-secret'}
    observed = []
    client = object()

    def signed(credentials):
        observed.append(credentials)
        return client

    async def forbidden(*args):
        pytest.fail('Runtime authentication must not fall back to a human session')

    monkeypatch.setattr(service, 'client', signed)
    monkeypatch.setattr(service, 'human_call', forbidden)
    assert await service.cloud_client({'credentials': store.seal(pair)}) is client
    assert observed == [pair]
