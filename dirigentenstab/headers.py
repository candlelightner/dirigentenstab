"""Per-provider extra HTTP headers: validation and request-time placeholder expansion."""

import re
import uuid
from importlib.metadata import PackageNotFoundError, version

MAX_HEADERS, MAX_VALUE = 20, 1024
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}")
PLACEHOLDER = re.compile(r'\{\{(conversation_id|app_version)\}\}')
RESERVED = frozenset({'authorization', 'proxy-authorization', 'host', 'content-length', 'transfer-encoding',
                      'connection', 'proxy-connection', 'cookie', 'upgrade', 'te', 'trailer', 'keep-alive', 'api-key'})


def validate_headers(headers):
    """Return a clean name/value map or raise ValueError; messages never echo values."""
    if not isinstance(headers, dict) or len(headers) > MAX_HEADERS:
        raise ValueError(f'At most {MAX_HEADERS} additional headers are allowed')
    clean = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str) or not TOKEN.fullmatch(name):
            raise ValueError('Invalid HTTP header name or value')
        if name.lower() in RESERVED or name.lower() in {key.lower() for key in clean}:
            raise ValueError(f'Header {name} is reserved or duplicated')
        value = value.strip()
        if (not value or len(value) > MAX_VALUE or not value.isascii() or not value.isprintable()
                or '{{' in PLACEHOLDER.sub('', value) or '}}' in PLACEHOLDER.sub('', value)):
            raise ValueError(f'Invalid value for header {name}; only {{{{conversation_id}}}} and {{{{app_version}}}} templates are supported')
        clean[name] = value
    return clean


def expand_headers(headers, conversation_id=None):
    """Expand templates at request time; without a conversation use a fresh request-session id."""
    values = {'conversation_id': conversation_id or str(uuid.uuid4())}
    try:
        values['app_version'] = version('dirigentenstab')
    except PackageNotFoundError:
        values['app_version'] = 'unknown'
    return {name: PLACEHOLDER.sub(lambda match: values[match.group(1)], value)
            for name, value in (headers or {}).items()}
