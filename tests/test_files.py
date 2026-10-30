import os
import time
from types import SimpleNamespace

import asyncssh
import httpx
import pytest
from fastapi import FastAPI

from dirigentenstab.files import MAX_UPLOAD, VMFiles, disposition, store_upload


class Upload:
    def __init__(self, name, data):
        self.name, self.data = name, data

    def size(self):
        return len(self.data)

    async def iterate(self, chunk_size=1024):
        for start in range(0, len(self.data), chunk_size):
            yield self.data[start:start + chunk_size]


@pytest.fixture
async def sftp_server(tmp_path):
    (tmp_path / 'dir').mkdir()
    (tmp_path / 'dir' / 'a.bin').write_bytes(b'x' * 1_000_000)
    (tmp_path / 'b.txt').write_text('hello')

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return False

    async with asyncssh.create_server(Server, '127.0.0.1', 0, server_host_keys=[asyncssh.generate_private_key('ssh-ed25519')],
                                      sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(tmp_path))) as server:
        yield server.get_port(), tmp_path


async def test_listing_and_upload(sftp_server):
    port, root = sftp_server
    async with asyncssh.connect('127.0.0.1', port, known_hosts=None, config=None) as conn:
        sftp = await conn.start_sftp_client()
        assert await sftp.realpath('.') == '/'
        names = {entry.filename for entry in await sftp.readdir('/')}
        assert {'dir', 'b.txt'} <= names
        await store_upload(sftp, '/dir', Upload('new.bin', b'abc' * 200_000))
        assert (root / 'dir' / 'new.bin').read_bytes() == b'abc' * 200_000
        with pytest.raises(FileExistsError):
            await store_upload(sftp, '/', Upload('b.txt', b'other'))
        assert (root / 'b.txt').read_text() == 'hello'
        await store_upload(sftp, '/', Upload('b.txt', b'other'), overwrite=True)
        assert (root / 'b.txt').read_text() == 'other'
        for name in ('a/b', 'x\0y', '', '..'):
            with pytest.raises(ValueError, match='Invalid file name'):
                await store_upload(sftp, '/', Upload(name, b'z'))
        with pytest.raises(ValueError, match='upload limit'):
            await store_upload(sftp, '/', Upload('big', b'z' * (MAX_UPLOAD + 1)))
        assert not (root / 'big').exists()


def test_disposition_sanitizes_names():
    header = disposition('/d/we"ird\r\nna\x00me é.txt')
    assert header.isascii() and '\r' not in header and '\n' not in header and '\x00' not in header
    assert header.startswith('attachment; filename="weirdname _.txt"; filename*=UTF-8\'\'weirdname%20%C3%A9.txt')
    assert disposition('/') == 'attachment; filename="download"; filename*=UTF-8\'\'download'


@pytest.fixture
async def client(sftp_server):
    port, _ = sftp_server
    calls = []

    class Service:
        allowed = True

        async def open_vm_connection(self, identity, vm_id, operation=None):
            calls.append((identity['_session'], vm_id, operation))
            if not self.allowed:
                raise PermissionError('VM is not accessible')
            return await asyncssh.connect('127.0.0.1', port, known_hosts=None, config=None), {}

    service = Service()
    files = VMFiles(service)
    app = FastAPI()
    files.install(app)
    session = {'value': 'sess-1'}

    async def identity_middleware(scope, receive, send):
        scope['ds_identity'] = {'userid': 'u', '_session': session['value']}
        await app(scope, receive, send)

    transport = httpx.ASGITransport(app=identity_middleware)
    async with httpx.AsyncClient(transport=transport, base_url='http://test') as http:
        yield SimpleNamespace(http=http, files=files, service=service, calls=calls, session=session)


async def test_download_streams_for_the_granting_session(client):
    url = client.files.grant({'_session': 'sess-1'}, 'vm-1', '/dir/a.bin')
    response = await client.http.get(url)
    assert response.status_code == 200
    assert response.content == b'x' * 1_000_000
    assert response.headers['content-type'] == 'application/octet-stream'
    assert response.headers['content-length'] == '1000000'
    assert 'filename="a.bin"' in response.headers['content-disposition']
    assert client.calls == [('sess-1', 'vm-1', 'vm-file-download')]
    assert (await client.http.get(url)).status_code == 403  # single use


async def test_download_refused_for_other_session_expired_grant_or_failed_authorization(client):
    url = client.files.grant({'_session': 'sess-1'}, 'vm-1', '/b.txt')
    client.session['value'] = 'sess-2'
    assert (await client.http.get(url)).status_code == 403
    client.session['value'] = 'sess-1'
    assert (await client.http.get(url)).status_code == 403  # the mismatched attempt consumed the grant

    url = client.files.grant({'_session': 'sess-1'}, 'vm-1', '/b.txt')
    token = url.rsplit('/', 1)[1]
    client.files.grants[token] = (*client.files.grants[token][:3], time.time() - 1)
    assert (await client.http.get(url)).status_code == 403
    assert not client.calls

    client.service.allowed = False
    response = await client.http.get(client.files.grant({'_session': 'sess-1'}, 'vm-1', '/b.txt'))
    assert response.status_code == 403 and 'not accessible' in response.text

    client.service.allowed = True
    assert (await client.http.get(client.files.grant({'_session': 'sess-1'}, 'vm-1', '/dir'))).status_code == 403
    assert (await client.http.get(client.files.grant({'_session': 'sess-1'}, 'vm-1', '/missing'))).status_code == 404


def test_use_spool_dir_replaces_tmpfs_tempdir(tmp_path, monkeypatch):
    import tempfile
    from dirigentenstab.files import use_spool_dir
    spool = tmp_path / 'tmp'
    spool.mkdir()
    (spool / 'stale').write_text('x')
    monkeypatch.setattr(tempfile, 'tempdir', None)
    use_spool_dir(str(spool))
    assert tempfile.gettempdir() == str(spool)
    assert list(spool.iterdir()) == [] and spool.stat().st_mode & 0o777 == 0o700
    with tempfile.NamedTemporaryFile() as f:
        assert os.path.dirname(f.name) == str(spool)
