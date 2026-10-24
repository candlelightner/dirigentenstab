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
    def __init__(self, message, *, rejected=False):
        super().__init__(message)
        self.rejected = rejected


# This is an authorization policy, not an API specification. Signatures come from listApis.
RUNTIME_APIS = frozenset('''
listApis listDomains listAccounts listUsers listVirtualMachines listVirtualMachinesMetrics
listServiceOfferings listDiskOfferings listTemplates listIsos listOsTypes listZones
listNetworks listNetworkOfferings listNetworkACLs listNetworkACLLists listNics listVolumes
listSnapshots listVMSnapshots listPublicIpAddresses listFirewallRules listEgressFirewallRules
listPortForwardingRules listStaticNatRules listSecurityGroups listTags listResourceLimits
listResourceCounts listAsyncJobs queryAsyncJobResult listCapabilities listEvents listAlerts
deployVirtualMachine startVirtualMachine stopVirtualMachine rebootVirtualMachine
destroyVirtualMachine recoverVirtualMachine restoreVirtualMachine scaleVirtualMachine
updateVirtualMachine resetUserDataForVirtualMachine
createVolume attachVolume detachVolume resizeVolume deleteVolume
createSnapshot deleteSnapshot revertSnapshot createVMSnapshot deleteVMSnapshot revertToVMSnapshot
createNetwork updateNetwork deleteNetwork restartNetwork
createNetworkACL deleteNetworkACL createNetworkACLList deleteNetworkACLList
createFirewallRule deleteFirewallRule createEgressFirewallRule deleteEgressFirewallRule
createPortForwardingRule deletePortForwardingRule enableStaticNat disableStaticNat
associateIpAddress disassociateIpAddress createSecurityGroup deleteSecurityGroup
authorizeSecurityGroupIngress revokeSecurityGroupIngress authorizeSecurityGroupEgress revokeSecurityGroupEgress
addNicToVirtualMachine removeNicFromVirtualMachine updateDefaultNicForVirtualMachine
createTags deleteTags
'''.split())
PROVISION_APIS = frozenset('''
listApis listDomains listAccounts listUsers listRoles createDomain createAccount
registerUserKeys listUserKeys listUserKeyRules deleteUserKeys listCapabilities
'''.split())
FORBIDDEN_PARAMS = frozenset('''
extraconfig cleanupextraconfig details hypervisor hostid hostids hosttags
path mountpoint filesystem command apikey secretkey signature signatureversion
sessionkey response filter exclude filepath externaldetails externalid importsource
'''.split())
SENSITIVE_FIELD = re.compile(r'(?i)(password|secret|private.?key|api.?key|sessionkey|cookie|token|userdata)')
NAME = re.compile(r'^[a-z][a-zA-Z0-9]{1,80}$')
PARAM_NAME = re.compile(r'^[a-z][a-z0-9]*(?:\[\d{1,3}\]\.[a-z][a-z0-9]*)?$')


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {k: '[redacted]' if SENSITIVE_FIELD.search(str(k)) else redact(v, secrets)
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


def validate(metadata: dict, params: dict, *, runtime=True):
    if not isinstance(params, dict) or len(params) > 128:
        raise ValueError('Parameters must be an object with at most 128 entries')
    specifications = {p['name']: p for p in metadata.get('params', [])}
    provided = {key.split('[')[0] for key in params if isinstance(key, str)}
    for spec in specifications.values():
        if spec.get('required') and spec['name'] not in provided:
            raise ValueError(f"Missing required parameter: {spec['name']}")
    for key, value in params.items():
        if not isinstance(key, str) or not PARAM_NAME.fullmatch(key):
            raise ValueError('Invalid parameter name')
        base = key.split('[')[0]
        if base not in specifications or (runtime and base in FORBIDDEN_PARAMS):
            raise ValueError(f'Parameter not permitted: {base}')
        spec = specifications[base]
        kind = spec.get('type', 'string').lower()
        nested = '[' in key
        if nested and kind not in {'map', 'object'}:
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
        if runtime and isinstance(value, str) and value.lower().startswith(('file:', 'host:', 'dir:', 'sharedmountpoint:')):
            raise ValueError('Host filesystem references are platform-administrator only')


class Cloud:
    def __init__(self, settings, credentials):
        self.settings = settings
        self.credentials = credentials
        self.profile = 'ds' + hashlib.sha256(credentials['apikey'].encode()).hexdigest()[:20]
        self._metadata = None
        self._metadata_time = 0
        self._limit = asyncio.Semaphore(4)

    async def _process(self, directory, args, max_bytes):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('CMK_', 'OPENAI_', 'CLOUDSTACK_'))}
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
                text = stdout.decode(errors='replace') + '\n' + stderr.decode(errors='replace')
                hidden = list(self.credentials.values())
                for arg in args:
                    if '=' in arg:
                        key, value = arg.split('=', 1)
                        if SENSITIVE_FIELD.search(key) or len(value) > 64:
                            hidden.append(value)
                try:
                    error = json.JSONDecoder().raw_decode(text[text.index('{'):])[0]
                    if 'errorresponse' in error:
                        error = error['errorresponse']
                    if 'errorcode' not in error:
                        error = next(value for value in error.values()
                                     if isinstance(value, dict) and 'errorcode' in value)
                    code = int(error['errorcode'])
                    detail = str(error.get('errortext', ''))
                    detail = str(redact(detail, hidden))[:400]
                    message = f'CloudStack error {code}: {detail}'
                    rejected = code in {400, 401, 403, 431, 435, 436, 535}
                except (ValueError, KeyError, TypeError, UnicodeError, StopIteration):
                    match = re.search(r'\(HTTP (\d{3}), error code \d+\)\s*(.*)', text, re.S)
                    if match:
                        status = int(match[1])
                        message = f'CloudStack HTTP {status}: ' + str(redact(match[2], hidden))[:400]
                        rejected = status in {400, 401, 403, 431, 435, 436, 535}
                raise CloudError(message, rejected=rejected)
            return stdout
        finally:
            for reader in readers:
                reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            if proc.returncode is None:
                with suppress(ProcessLookupError):
                    proc.kill()
            # Drain pipes after killing: a full, paused stdout pipe otherwise prevents wait() completing.
            await proc.communicate()

    async def raw(self, command, params=None):
        if not NAME.fullmatch(command):
            raise ValueError('Invalid CloudStack command')
        args = []
        for key, value in (params or {}).items():
            if not PARAM_NAME.fullmatch(key):
                raise ValueError('Invalid parameter')
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
                                **self.credentials, 'signaturealgorithm': 'auto'}
        async with self._limit:
            with tempfile.TemporaryDirectory(prefix='ds-cmk-', dir='/dev/shm') as directory:
                path = Path(directory) / 'config'
                with open(path, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as handle:  # noqa: ASYNC230 -- tmpfs only
                    config.write(handle)
                # cmk sync populates its maintained catalogue; never invoke its interactive shell.
                await self._process(directory, ['sync'], 8192)
                limit = 16 * 1024 * 1024 if command == 'listApis' else 4 * 1024 * 1024
                data = await self._process(directory, [command, *args], limit)
        try:
            result = json.loads(data) if data.strip() else {}
        except (ValueError, UnicodeError):
            raise CloudError('CloudMonkey returned an invalid response') from None
        if 'errorresponse' in result or 'errorcode' in result:
            raise CloudError('CloudStack denied or failed the operation')
        if len(result) == 1:
            key = next(iter(result))
            if key.lower().endswith('response'):
                result = result[key]
        if not isinstance(result, dict):
            raise CloudError('Unexpected CloudStack response')
        return result

    async def catalogue(self):
        if self._metadata is None or time.monotonic() - self._metadata_time > 300:
            response = await self.raw('listApis')
            self._metadata = {api['name']: api for api in response.get('api', [])}
            self._metadata_time = time.monotonic()
        return self._metadata

    async def execute(self, command, params, *, runtime=True):
        if command not in (RUNTIME_APIS if runtime else PROVISION_APIS):
            raise PermissionError('This API is reserved for the platform administrator or trusted provisioning')
        metadata = (await self.catalogue()).get(command)
        if not metadata:
            raise PermissionError('API unavailable to this CloudStack identity')
        validate(metadata, params, runtime=runtime)
        result = await self.raw(command, params)
        if result.get('jobid'):
            job_id = result['jobid']
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                job = await self.raw('queryAsyncJobResult', {'jobid': job_id})
                if job.get('jobstatus') == 1:
                    return job.get('jobresult', {})
                if job.get('jobstatus') == 2:
                    raise CloudError(f'CloudStack asynchronous operation failed; job ID {job_id}')
                await asyncio.sleep(2)
            raise CloudError(f'CloudStack job remains pending; job ID {job_id}. Check status before retrying')
        return result
