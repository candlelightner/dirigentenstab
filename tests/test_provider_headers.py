import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet
from pydantic_ai import Agent
from pydantic_ai.exceptions import ModelAPIError

from dirigentenstab import runtime
from dirigentenstab.headers import expand_headers, validate_headers
from dirigentenstab.service import Service
from dirigentenstab.store import Store

ROOT = {'userid': 'root', 'type': 1}
CHAT = {'id': 'c', 'object': 'chat.completion', 'created': 1, 'model': 'm',
        'choices': [{'index': 0, 'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': 'Done'}}],
        'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}
RESPONSES = {'id': 'r', 'object': 'response', 'created_at': 1, 'status': 'completed', 'model': 'm',
             'output': [{'id': 'm1', 'type': 'message', 'status': 'completed', 'role': 'assistant',
                         'content': [{'type': 'output_text', 'text': 'Done', 'annotations': []}]}],
             'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}


def sse(*chunks):
    return ''.join(f'data: {json.dumps(chunk)}\n\n' for chunk in chunks) + 'data: [DONE]\n\n'


STREAM = sse(*({'id': 'c', 'object': 'chat.completion.chunk', 'created': 1, 'model': 'm',
                'choices': [{'index': 0, 'delta': delta, 'finish_reason': reason}]}
               for delta, reason in (({'role': 'assistant', 'content': 'Done'}, None), ({}, 'stop'))))


@pytest.fixture
def store(tmp_path):
    master = tmp_path / 'master'
    master.write_bytes(Fernet.generate_key())
    return Store(str(tmp_path / 'state.db'), str(master))


@pytest.fixture
def service(store):
    return Service(store, SimpleNamespace())


async def save(service, headers, **kwargs):
    return await service.save_provider(ROOT, 'Local', 'chat', 'http://inference/v1', 'api-secret', 'm',
                                       'p', **({'headers': headers} if headers is not None else {}), **kwargs)


def row(service):
    return service.store.one('SELECT * FROM providers WHERE id=?', ('p',))


@pytest.fixture
def wire(monkeypatch):
    """Route every SDK and catalogue request through one recorder."""
    requests = []

    def install(handler=None, *, body=None):
        def handle(request):
            requests.append(request)
            if handler:
                return handler(request)
            if request.url.path.endswith('/models'):
                return httpx.Response(200, json={'data': [{'id': 'm'}]})
            if request.url.path.endswith('/responses'):
                return httpx.Response(200, json=RESPONSES)
            if body:
                return httpx.Response(200, text=body, headers={'content-type': 'text/event-stream'})
            return httpx.Response(200, json=CHAT)

        plain = httpx.AsyncClient
        monkeypatch.setattr(runtime.openai, 'DefaultAsyncHttpxClient',
                            lambda **kwargs: plain(transport=httpx.MockTransport(handle), **kwargs))
        # A proxy, not the global module: the SDK's own client subclasses httpx.AsyncClient.
        monkeypatch.setattr(runtime, 'httpx', SimpleNamespace(
            AsyncClient=lambda **kwargs: plain(transport=httpx.MockTransport(handle), **kwargs),
            HTTPStatusError=httpx.HTTPStatusError, HTTPError=httpx.HTTPError))
        return requests
    return install


@pytest.mark.parametrize('headers', [
    {'Bad Name': 'x'}, {'': 'x'}, {'X-A': 'a\r\nInjected: 1'}, {'X-A': 'a\x00'}, {'X-A': 'tab\there'},
    {'X-A': '{{other}}'}, {'X-A': '{{conversation_id'}, {'X-A': '{{ conversation_id }}'}, {'X-A': ''},
    {'X-A': 'é'}, {'X-A': 'x' * 1025}, {f'X-{n}': 'x' for n in range(21)}, {'X-A': 1}, ['X-A'],
    {'X-A': 'a', 'x-a': 'b'},
    *({name: 'x'} for name in ('authorization', 'Host', 'CONTENT-LENGTH', 'Transfer-Encoding', 'Connection', 'Cookie',
                               'Proxy-Authorization', 'Upgrade', 'TE', 'Te', 'Keep-Alive', 'Api-Key')),
])
def test_invalid_headers_are_rejected_without_echoing_values(headers):
    with pytest.raises(ValueError) as error:
        validate_headers(headers)
    assert 'Injected' not in str(error.value)


def test_valid_headers_and_templates_expand_at_request_time():
    headers = validate_headers({'User-Agent': ' Dirigentenstab/{{app_version}} ', 'x-session': '{{conversation_id}}'})
    assert headers['User-Agent'] == 'Dirigentenstab/{{app_version}}'
    expanded = expand_headers(headers, 'conversation-1')
    assert expanded['x-session'] == 'conversation-1'
    assert expanded['User-Agent'].startswith('Dirigentenstab/') and '{{' not in expanded['User-Agent']
    assert expand_headers(headers)['x-session'] != expand_headers(headers)['x-session']


async def test_headers_are_encrypted_preserved_kept_by_blank_value_and_removed(service):
    await save(service, {'X-Secret': 'plaintext-header-secret', 'X-Other': 'one'})
    stored = row(service)['extra_headers']
    assert b'plaintext-header-secret' not in stored
    assert not any(b'plaintext-header-secret' in file.read_bytes() for file in service.store.path.parent.glob('state.db*'))
    assert service.store.open(stored) == {'X-Secret': 'plaintext-header-secret', 'X-Other': 'one'}
    assert all('extra_headers' not in p for p in await service.providers(ROOT))
    await save(service, None)  # unrelated edit preserves headers
    assert service.store.open(row(service)['extra_headers'])['X-Secret'] == 'plaintext-header-secret'
    await save(service, {'X-Secret': '', 'X-New': 'two'})  # blank keeps; omitted X-Other is removed
    assert service.store.open(row(service)['extra_headers']) == {'X-Secret': 'plaintext-header-secret', 'X-New': 'two'}
    with pytest.raises(ValueError):
        await save(service, {'X-Missing': ''})
    with pytest.raises(ValueError):
        await save(service, {'Authorization': 'Bearer x'})
    assert service.store.open(row(service)['extra_headers'])['X-New'] == 'two'
    await save(service, {})
    assert row(service)['extra_headers'] is None


def test_migration_adds_nullable_column_to_existing_providers(tmp_path):
    master = tmp_path / 'master'
    master.write_bytes(Fernet.generate_key())
    path = tmp_path / 'old.db'
    conn = sqlite3.connect(path)
    for n in range(1, 26):
        conn.executescript((Path(runtime.__file__).parent / 'migrations' / f'{n:03}.sql').read_text())
    conn.execute("INSERT INTO providers(id,name,protocol,base_url,api_key) VALUES('p','Old','chat','http://x/v1',x'00')")
    conn.execute('PRAGMA user_version=25')
    conn.commit()
    conn.close()
    old = Store(str(path), str(master)).one('SELECT * FROM providers')
    assert old['extra_headers'] is None and old['name'] == 'Old'
    assert runtime.provider_headers(old, Store(str(path), str(master))) is not None


@pytest.mark.parametrize('protocol,path', [('chat', '/chat/completions'), ('responses', '/responses')])
async def test_inference_requests_carry_configured_headers_and_conversation_scope(service, wire, protocol, path):
    requests = wire()
    await service.save_provider(ROOT, 'Local', protocol, 'http://inference/v1', 'api-secret', 'm', 'p',
                                headers={'User-Agent': 'Dirigentenstab/{{app_version}}',
                                         'x-session': '{{conversation_id}}', 'HTTP-Referer': 'https://example.org'})
    provider = row(service)
    for conversation in ('one', 'one', 'two'):
        agent = Agent(runtime.build_model(provider, 'm', service.store, conversation), retries=0)
        assert (await agent.run('hi')).output == 'Done'
    assert all(r.url.path.endswith(path) for r in requests)
    assert [r.headers['x-session'] for r in requests] == ['one', 'one', 'two']
    assert all(r.headers['http-referer'] == 'https://example.org' for r in requests)
    assert all(r.headers['user-agent'].startswith('Dirigentenstab/') for r in requests)
    assert all(r.headers['authorization'] == 'Bearer api-secret' for r in requests)


async def test_streaming_chat_request_carries_headers(service, wire):
    requests = wire(body=STREAM)
    await save(service, {'x-session': '{{conversation_id}}'})
    agent = Agent(runtime.build_model(row(service), 'm', service.store, 'stream-1'), retries=0)
    async with agent.run_stream('hi') as result:
        assert await result.get_output() == 'Done'
    assert json.loads(requests[0].content)['stream'] is True
    assert requests[0].headers['x-session'] == 'stream-1'


async def test_empty_configuration_keeps_sdk_user_agent_and_custom_one_replaces_it(service, wire):
    requests = wire()
    await save(service, None)
    await Agent(runtime.build_model(row(service), 'm', service.store), retries=0).run('hi')
    assert requests[0].headers['user-agent'].startswith('pydantic-ai/')
    await save(service, {'User-Agent': 'Custom/1'})
    await Agent(runtime.build_model(row(service), 'm', service.store), retries=0).run('hi')
    assert requests[1].headers['user-agent'] == 'Custom/1'
    await runtime.provider_catalogue(row(service), service.store)
    assert requests[2].headers['user-agent'] == 'Custom/1'


async def test_catalogue_carries_same_headers_with_ephemeral_scope(service, wire):
    requests = wire()
    await save(service, {'x-session': '{{conversation_id}}', 'X-Static': 'same'})
    await runtime.provider_models(row(service), service.store)
    await runtime.provider_models(row(service), service.store)
    first, second = requests
    assert first.url.path.endswith('/models') and first.headers['x-static'] == 'same'
    assert first.headers['authorization'] == 'Bearer api-secret'
    assert first.headers['x-session'] != second.headers['x-session']
    assert (await runtime.test_provider(row(service), 'm', service.store))['model_available'] is True
    probe = [r.headers['x-session'] for r in requests[2:]]
    assert len(set(probe)) == 1 and probe[0] not in {'one', first.headers['x-session']}


async def test_custom_headers_never_follow_a_redirect_to_another_origin(service, wire):
    seen = []

    def redirect(request):
        seen.append(request.url.host)
        return httpx.Response(307, headers={'location': 'https://elsewhere.example/v1/chat/completions'})

    wire(redirect)
    await save(service, {'X-Secret': 'redirect-secret'})
    with pytest.raises(ModelAPIError):
        await Agent(runtime.build_model(row(service), 'm', service.store, 'c'), retries=0).run('hi')
    with pytest.raises(httpx.HTTPStatusError):
        await runtime.provider_catalogue(row(service), service.store)
    assert set(seen) == {'inference'}
