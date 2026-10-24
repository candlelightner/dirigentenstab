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


@pytest.mark.parametrize('parameter', ['hostid', 'hosttags', 'extraconfig', 'details', 'mountpoint',
                                      'path', 'filepath', 'sessionkey', 'apikey', 'secretkey'])
def test_runtime_cannot_configure_host_or_select_credentials(parameter):
    metadata = {'params': [{'name': parameter, 'type': 'string'}]}
    with pytest.raises(ValueError, match='not permitted'):
        validate(metadata, {parameter: '/host/private'})


async def test_retry_cleanup_uses_actual_cloudstack_userkeys_response(store, monkeypatch):
    service = Service(store, SimpleNamespace())
    deleted = []

    class Cloud:
        async def catalogue(self):
            from dirigentenstab.cloud import PROVISION_APIS, RUNTIME_APIS
            return {api: {} for api in PROVISION_APIS | RUNTIME_APIS}

        async def raw(self, command, params):
            if command == 'listUserKeys':
                return {'userapikey': [{'id': 'orphan', 'name': 'ds-operation-runtime'},
                                       {'id': 'unrelated', 'name': 'other-operation-runtime'}]}
            assert command == 'deleteUserKeys'
            deleted.append(params['keypairid'])
            return {'success': True}

    async def key(cloud, user_id, name, allowed):
        return {'id': name, 'apikey': name + '-key', 'secretkey': name + '-secret'}

    monkeypatch.setattr(service, '_key', key)
    await service._credentials(Cloud(), 'user', 'operation')
    assert deleted == ['orphan']


async def test_revocation_includes_replacements_from_interrupted_rotation(store, monkeypatch):
    def pair(name):
        return {'id': name, 'apikey': name + '-api', 'secretkey': name + '-secret'}

    current = {'runtime': pair('old-runtime'), 'provisioning': pair('old-provisioning')}
    replacement = {'runtime': pair('new-runtime'), 'provisioning': pair('new-provisioning')}
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning) '
                  'VALUES(?,?,?,?,?,?,?)', ('agent', 'Agent', 'domain', 'account', 'user',
                                           store.seal(current['runtime']), store.seal(current['provisioning'])))
    store.execute('INSERT INTO credential_rotations VALUES(?,?,?,?,?,?)',
                  ('agent', 'rotation', store.seal(current), store.seal(replacement), 'validating', time.time()))
    service = Service(store, SimpleNamespace())
    deleted = []
    available = [pair['id'] for pair in [*current.values(), *replacement.values()]]

    class Cloud:
        async def raw(self, command, params):
            if command == 'listUserKeys':
                return {'userapikey': [{'id': key, 'name': 'ds-rotation-' + key} for key in available
                                       if key not in deleted]}
            assert command == 'deleteUserKeys'
            deleted.append(params['keypairid'])
            return {'success': True}

    async def authorize(identity, agent_id, **kwargs):
        assert identity['userid'] == 'human' and agent_id == 'agent'
        return store.one('SELECT * FROM agents WHERE id=?', (agent_id,))

    async def cloud_client(agent, purpose='runtime'):
        return Cloud()

    monkeypatch.setattr(service, 'authorize', authorize)
    monkeypatch.setattr(service, 'cloud_client', cloud_client)
    await service.revoke_agent({'userid': 'human'}, 'agent')
    assert set(deleted) == set(available)
    assert deleted[-1] == 'old-provisioning'
    assert store.one('SELECT enabled FROM agents WHERE id=?', ('agent',))['enabled'] == 0
