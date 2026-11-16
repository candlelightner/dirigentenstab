import base64
import json
from types import SimpleNamespace

import asyncssh
import pytest
from pydantic_ai.messages import BinaryContent, ModelMessagesTypeAdapter, ModelRequest, TextPart, UserPromptPart, ModelResponse
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models import ModelRequestParameters

from dirigentenstab import runtime
from dirigentenstab.cloud import redact
from dirigentenstab.compaction import estimate_tokens, text_json
from dirigentenstab.files import PASTE_DIR, paste_command, store_paste
from dirigentenstab.images import MAX_IMAGE_BYTES, validate_images
from dirigentenstab.web_chat import history_parts
from test_runtime import service as runtime_service  # noqa: F401

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 20
JPEG = b'\xff\xd8\xff\xe0' + b'\x00' * 20


def test_validation_count_size_type_and_sniffing():
    assert validate_images([('image/png', PNG), ('image/jpeg', JPEG)]) == [('image/png', PNG), ('image/jpeg', JPEG)]
    assert validate_images(()) == []
    with pytest.raises(ValueError, match='At most 4'):
        validate_images([('image/png', PNG)] * 5)
    with pytest.raises(ValueError, match='MiB'):
        validate_images([('image/png', PNG + b'x' * MAX_IMAGE_BYTES)])
    with pytest.raises(ValueError, match='MiB'):
        validate_images([('image/png', b'')])
    with pytest.raises(ValueError, match='PNG, JPEG'):
        validate_images([('image/svg+xml', b'<svg/>')])
    with pytest.raises(ValueError, match='does not match'):
        validate_images([('image/png', JPEG)])
    with pytest.raises(ValueError, match='does not match'):
        validate_images([('image/jpeg', b'<html>not an image</html>')])


async def test_submit_images_validation_persistence_and_history(runtime_service, monkeypatch):  # noqa: F811
    seen = []

    async def model(messages, info):
        seen.append(messages[-1].parts[0].content)
        yield 'ok'

    monkeypatch.setattr(runtime, 'build_model', lambda *args: FunctionModel(stream_function=model))
    manager = runtime.Runtime(runtime_service)
    me = {'userid': 'human'}
    for prompt, images in (('', ()), ('   ', ()), ('hi', [('image/png', JPEG)]), ('hi', [('image/png', PNG)] * 5)):
        with pytest.raises(ValueError):
            await manager.submit(me, 'parent', None, prompt, images=images)
    assert not runtime_service.store.all('SELECT id FROM conversations')
    result = await manager.chat(me, 'parent', None, 'look')
    assert seen[-1] == 'look'
    only = await manager.submit(me, 'parent', None, '', images=[('image/png', PNG)])
    await runtime.asyncio.shield(manager.active[only['operation_id']])
    assert runtime_service.store.one('SELECT title FROM conversations WHERE id=?', (only['conversation_id'],))['title'] == 'Image'
    content = seen[-1]
    assert [type(item) for item in content] == [BinaryContent] and content[0].data == PNG
    withtext = await manager.submit(me, 'parent', result['conversation_id'], 'what', images=[('image/jpeg', JPEG)])
    await runtime.asyncio.shield(manager.active[withtext['operation_id']])
    assert seen[-1][0] == 'what' and seen[-1][1].data == JPEG and seen[-1][1].media_type == 'image/jpeg'
    # Redacted, sealed, and restored without corrupting the bytes.
    restored = await manager.restore(me, withtext['conversation_id'])
    stored = runtime.load_history(runtime_service.store.open(runtime_service.store.one(
        'SELECT messages FROM conversations WHERE id=?', (withtext['conversation_id'],))['messages']))
    assert next(p.content for m in stored for p in m.parts if p.part_kind == 'user-prompt' and isinstance(p.content, list))[1].data == JPEG
    parts = list(history_parts(restored))
    assert [kind for kind, _ in parts].count('images') == 1
    assert ('images', [('image/jpeg', base64.b64encode(JPEG).decode())]) in parts


def test_redaction_keeps_binary_payload_intact():
    secret = 'abcdefgh'
    payload = {'kind': 'binary', 'data': 'QUJDREVGR0g=' + secret, 'media_type': 'image/png'}
    out = redact([{'content': ['see ' + secret, payload]}], (secret,))
    assert out[0]['content'][0] == 'see [redacted]' and out[0]['content'][1] == payload


def test_history_parts_shows_text_and_images_and_image_only():
    def history(content):
        return {'messages': [{'parts': [{'part_kind': 'user-prompt', 'content': content}]}], 'runs': []}
    image = {'kind': 'binary', 'data': 'AA-_', 'media_type': 'image/png'}
    assert list(history_parts(history(['hello', image]))) == [('human', 'hello'), ('images', [('image/png', 'AA+/')])]
    assert list(history_parts(history([image]))) == [('images', [('image/png', 'AA+/')])]
    assert list(history_parts(history('plain'))) == [('human', 'plain')]
    assert list(history_parts(history([{'kind': 'binary', 'data': 'AAAA', 'media_type': 'text/html'}]))) == [('human', '')]


def test_compaction_sees_placeholder_not_base64():
    big = BinaryContent(data=b'\x89PNG\r\n\x1a\n' + b'\xff' * 100_000, media_type='image/png')
    messages = [ModelRequest(parts=[UserPromptPart(['hi', big])]), ModelResponse(parts=[TextPart('ok')])]
    shown = text_json(messages)
    assert b'[image]' in shown and len(shown) < 1000 and b'iVBOR' not in shown
    assert estimate_tokens(messages, ModelRequestParameters()) < 500
    assert json.loads(text_json(messages[1:])) == json.loads(ModelMessagesTypeAdapter.dump_json(messages[1:]))


class FakeConn:
    def __init__(self, returncode=0):
        self.calls, self.returncode = [], returncode

    async def run(self, command, input=None, check=True, encoding="utf-8"):
        assert encoding is None  # bytes on stdin
        self.calls.append((command, input))
        return SimpleNamespace(returncode=self.returncode)


async def test_agent_shell_paste_uses_fixed_quoted_command_and_hub_generated_name():
    conn = FakeConn()
    path = await store_paste(conn, 'image/png', PNG, 'agent-1')
    command, data = conn.calls[0]
    assert data == PNG and path.startswith(PASTE_DIR + '/paste-') and path.endswith('.png')
    assert command == paste_command('agent-1', path.rsplit('/', 1)[1])
    assert command.startswith("sudo -n docker exec -i -u dev ws-agent-1 sh -c ")
    assert f'mkdir -p {PASTE_DIR} && cat > {path}' in command
    with pytest.raises(ValueError):
        await store_paste(conn, 'image/png', JPEG, 'agent-1')
    assert len(conn.calls) == 1
    with pytest.raises(OSError):
        await store_paste(FakeConn(1), 'image/png', PNG, 'agent-1')


async def test_vm_paste_writes_through_sftp(tmp_path):
    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return False

    async with asyncssh.create_server(Server, '127.0.0.1', 0, server_host_keys=[asyncssh.generate_private_key('ssh-ed25519')],
                                      sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(tmp_path))) as server:
        async with asyncssh.connect('127.0.0.1', server.get_port(), known_hosts=None, config=None) as conn:
            path = await store_paste(conn, 'image/jpeg', JPEG)
    assert (tmp_path / path.lstrip('/')).read_bytes() == JPEG and path.endswith('.jpg')
