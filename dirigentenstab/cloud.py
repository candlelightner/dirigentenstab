"""CloudMonkey is the only signed CloudStack API transport."""
import asyncio
import configparser
from contextlib import suppress
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
from pathlib import Path
from uuid import UUID


class CloudError(RuntimeError):
    def __init__(self, message, *, rejected=False, operation_id=None, public_detail=None):
        super().__init__(message)
        self.rejected = rejected
        self.operation_id = operation_id
        self.public_detail = public_detail


AUTH_PARAMS = frozenset({'apikey', 'secretkey', 'signature', 'signatureversion', 'sessionkey',
                         'command', 'response'})
SENSITIVE_FIELD = re.compile(r'(?i)(password|secret|private.?key|api.?key|sessionkey|cookie|token|userdata)')
TOKEN_COUNT = re.compile(r'^(?:input|output|cache_write|cache_read|input_audio|cache_audio_read|output_audio|prompt_cache_hit|prompt_cache_miss|reasoning|estimated|usable)_tokens$')
NAME = re.compile(r'^[a-z][a-zA-Z0-9]{1,80}$')
PARAM_NAME = re.compile(r'^[a-z][a-z0-9]*(?:\[\d{1,3}\]\.[a-z][a-z0-9]*)?$')

def redact(value, secrets=()):
    if isinstance(value, dict):
        return {k: v if TOKEN_COUNT.fullmatch(str(k)) and type(v) is int and v >= 0
                else '[redacted]' if SENSITIVE_FIELD.search(str(k)) else redact(v, secrets)
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret and len(secret) >= 8:
                value = value.replace(secret, '[redacted]')
        value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                       '[redacted private key]', value, flags=re.S)
    return value


def error_detail(detail, params, secrets=()):
    hidden = [*secrets, *(str(value) for key, value in params.items()
              if SENSITIVE_FIELD.search(key) or len(str(value)) > 64)]
    detail = str(detail)
    for value in sorted(set(hidden), key=len, reverse=True):
        if value:
            detail = detail.replace(value, '[redacted]')
    return ' '.join(str(redact(detail)).split())[:400]


def validate(metadata: dict | None, params: dict):
    if not isinstance(params, dict) or len(params) > 128:
        raise ValueError('Parameters must be an object with at most 128 entries')
    specifications = {p['name']: p for p in (metadata or {}).get('params', [])}
    provided = {key.split('[')[0] for key in params if isinstance(key, str)}
    for spec in specifications.values():
        if spec.get('required') and spec['name'] not in provided:
            raise ValueError(f"Missing required parameter: {spec['name']}")
    for key, value in params.items():
        if not isinstance(key, str) or not PARAM_NAME.fullmatch(key):
            raise ValueError('Invalid parameter name')
        base = key.split('[')[0]
        if base in AUTH_PARAMS:
            raise ValueError('CloudStack authentication is selected by the server')
        if metadata is not None and base not in specifications:
            raise ValueError(f'Unknown CloudStack parameter: {base}')
        spec = specifications.get(base, {})
        kind = spec.get('type', 'string').lower()
        nested = '[' in key
        if metadata is not None and nested and kind not in {'map', 'object'}:
            raise ValueError(f'Parameter is not a map: {base}')
        if value is None or isinstance(value, (dict, list)):
            raise ValueError('Use scalar values, comma-separated lists, or indexed map parameters')
        if not nested:
            if kind in {'boolean', 'bool'} and not isinstance(value, bool):
                raise ValueError(f'Expected boolean: {key}')
            if kind in {'integer', 'long', 'short', 'byte'} and (type(value) is not int):
                raise ValueError(f'Expected integer: {key}')
            if kind in {'number', 'float', 'double'} and (type(value) not in {int, float}):
                raise ValueError(f'Expected number: {key}')
            if kind == 'uuid':
                UUID(str(value))
            if kind == 'ipaddress':
                ipaddress.ip_address(value)
        text = str(value)
        # CloudMonkey interprets @file and quoted @file as local file reads, even without a shell.
        if text.lstrip('"').startswith('@') or '\x00' in text or len(text) > 65536:
            raise ValueError('File references, NULs and oversized values are forbidden')
        # Other paths/URLs are literal remote API values; CloudStack authorizes their use.


async def wait_for_job(call, result, detail_for):
    if result.get('jobid'):
        job_id = result['jobid']
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                job = await call('queryAsyncJobResult', {'jobid': job_id})
            except (CloudError, PermissionError):
                raise CloudError(f'CloudStack job status unavailable; job ID {job_id}. '
                                 'Check status before retrying') from None
            if job.get('jobstatus') == 1:
                return job.get('jobresult', {})
            if job.get('jobstatus') == 2:
                failure = job.get('jobresult')
                if not isinstance(failure, dict):
                    failure = {}
                detail = detail_for(failure.get('errortext', 'Native operation rejected'))
                raise CloudError(f"CloudStack asynchronous operation failed ({failure.get('errorcode', 'unknown')}): "
                                 f'{detail}; job ID {job_id}', public_detail=f'{detail}; job ID {job_id}'[:500])
            await asyncio.sleep(2)
        raise CloudError(f'CloudStack job remains pending; job ID {job_id}. Check status before retrying')
    return result


class Cloud:
    def __init__(self, settings, credentials):
        self.settings = settings
        self.credentials = credentials
        self.profile = 'ds' + hashlib.sha256(credentials['apikey'].encode()).hexdigest()[:20]
        self._catalogue_lock = asyncio.Lock()
        self._metadata = None
        self._metadata_time = 0
        self._limit = asyncio.Semaphore(4)

    def _error_detail(self, detail, params):
        return error_detail(detail, params, self.credentials.values())

    async def _process(self, directory, args, max_bytes):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('CMK_', 'OPENAI_', 'CLOUDSTACK_'))}
        env['HOME'] = str(directory)
        env['CMK_CONFIG'] = str(Path(directory) / 'config')
        proc = await asyncio.create_subprocess_exec(
            self.settings.cmk, *args, env=env, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        async def read(stream):
            chunks, size = [], 0
            while chunk := await stream.read(16384):
                size += len(chunk)
                if size > max_bytes:
                    raise CloudError('CloudStack response exceeded its size limit; narrow the query')
                chunks.append(chunk)
            return b''.join(chunks)

        readers = [asyncio.create_task(read(proc.stdout)), asyncio.create_task(read(proc.stderr))]
        try:
            async with asyncio.timeout(90):
                stdout, stderr = await asyncio.gather(*readers)
                await proc.wait()
            if proc.returncode:
                message = 'CloudStack rejected the operation or could not be reached'
                rejected = False
                detail = None
                text = stdout.decode(errors='replace') + '\n' + stderr.decode(errors='replace')
                params = dict(arg.split('=', 1) for arg in args if '=' in arg)
                try:
                    error = json.JSONDecoder().raw_decode(text[text.index('{'):])[0]
                    if 'errorresponse' in error:
                        error = error['errorresponse']
                    if 'errorcode' not in error:
                        error = next(value for value in error.values()
                                     if isinstance(value, dict) and 'errorcode' in value)
                    code = int(error['errorcode'])
                    detail = self._error_detail(error.get('errortext', ''), params)
                    message = f'CloudStack error {code}: {detail}'
                    rejected = code in {400, 401, 403, 431, 435, 436, 531, 535}
                except (ValueError, KeyError, TypeError, UnicodeError, StopIteration):
                    match = re.search(r'\(HTTP (\d{3}), error code \d+\)\s*(.*)', text, re.S)
                    if match:
                        status = int(match[1])
                        detail = self._error_detail(match[2], params)
                        message = f'CloudStack HTTP {status}: {detail}'
                        rejected = status in {400, 401, 403, 431, 435, 436, 531, 535}
                raise CloudError(message, rejected=rejected, public_detail=detail)
            return stdout
        finally:
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            if proc.returncode is None:
                with suppress(ProcessLookupError):
                    proc.kill()
            # Drain pipes after killing: a full, paused stdout pipe otherwise prevents wait() completing.
            with suppress(TimeoutError):
                async with asyncio.timeout(5):
                    await proc.communicate()

    async def raw(self, command, params=None):
        if not isinstance(command, str) or not NAME.fullmatch(command):
            raise ValueError('Invalid CloudStack command')
        if command.lower() in {'help', 'version', 'switch', 'set', 'sync', 'exit'}:
            raise ValueError('CloudMonkey local commands are not CloudStack APIs')
        args = []
        for key, value in (params or {}).items():
            if not isinstance(key, str) or not PARAM_NAME.fullmatch(key):
                raise ValueError('Invalid parameter')
            if key in AUTH_PARAMS:
                raise ValueError('CloudStack authentication is selected by the server')
            if key == 'filepath':
                raise ValueError('CloudMonkey local file uploads are forbidden')
            text = str(value).lower() if isinstance(value, bool) else str(value)
            if text.lstrip('"').startswith('@') or '\x00' in text:
                raise ValueError('Local file inputs are forbidden')
            args.append(key + '=' + text)
        config = configparser.ConfigParser(interpolation=None)
        config['DEFAULT'] = {'profile': self.profile, 'output': 'json', 'asyncblock': 'false',
                             'timeout': '60', 'verifycert': 'true', 'postrequest': 'true',
                             'autocomplete': 'false'}
        for val in self.credentials.values():
            if not isinstance(val, str) or any(c in val for c in '\r\n'):
                raise ValueError('Invalid credential record')
        config[self.profile] = {'url': self.settings.cloudstack_url, 'username': '', 'password': '',
                                **self.credentials, 'signaturealgorithm': 'HmacSHA1'}
        async with self._limit:
            with tempfile.TemporaryDirectory(prefix='ds-cmk-', dir='/dev/shm') as directory:
                path = Path(directory) / 'config'
                with open(path, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as handle:  # noqa: ASYNC230 -- tmpfs only
                    config.write(handle)
                cache_home = Path(directory) / '.cmk'
                cache_home.mkdir(mode=0o700)
                profiles = cache_home / 'profiles'
                profiles.mkdir(mode=0o700)
                descriptor = {'api': [{'name': command, 'isasync': False, 'description': '',
                                       'params': [], 'response': []}]}
                # Seed syntax only: native CloudStack, never CMK discovery, authorizes this request.
                cache = profiles / (self.profile + '.cache')
                with open(cache, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as handle:  # noqa: ASYNC230 -- tmpfs only
                    json.dump(descriptor, handle)
                limit = 16 * 1024 * 1024 if command == 'listApis' else 4 * 1024 * 1024
                data = await self._process(directory, [command, *args], limit)
        try:
            result = json.loads(data) if data.strip() else {}
        except (ValueError, UnicodeError):
            raise CloudError('CloudMonkey returned an invalid response') from None
        if isinstance(result, dict) and 'errorresponse' in result:
            result = result['errorresponse']
        if isinstance(result, dict) and len(result) == 1:
            key = next(iter(result))
            if key.lower().endswith('response'):
                result = result[key]
        if not isinstance(result, dict):
            raise CloudError('Unexpected CloudStack response')
        if 'errorcode' in result:
            code = str(result['errorcode'])
            detail = self._error_detail(result.get('errortext', ''), params or {})
            raise CloudError(f'CloudStack error {code}: {detail}',
                             rejected=code in {'400', '401', '403', '431', '435', '436', '531', '535'},
                             public_detail=detail)
        return result

    async def catalogue(self, *, refresh=False):
        async with self._catalogue_lock:
            if refresh or self._metadata is None or time.monotonic() - self._metadata_time > 300:
                response = await self.raw('listApis')
                self._metadata = {api['name']: api for api in response.get('api', [])}
                self._metadata_time = time.monotonic()
        return self._metadata

    async def execute(self, command, params):
        if not isinstance(command, str) or not NAME.fullmatch(command):
            raise ValueError('Invalid CloudStack command')
        if command.lower() in {'help', 'version', 'switch', 'set', 'sync', 'exit'}:
            raise ValueError('CloudMonkey local commands are not CloudStack APIs')
        cached = self._metadata is not None and time.monotonic() - self._metadata_time <= 300
        try:
            metadata = (await self.catalogue()).get(command)
            if not metadata and cached:
                metadata = (await self.catalogue(refresh=True)).get(command)
        except CloudError:
            metadata = None
        # Discovery validates inputs, never authorization: send the caller's signed request.
        validate(metadata, params)
        try:
            result = await self.raw(command, params)
        except CloudError as exc:
            if exc.rejected:
                self._metadata = None
            raise
        return await wait_for_job(self.raw, result, lambda detail: self._error_detail(detail, params))
