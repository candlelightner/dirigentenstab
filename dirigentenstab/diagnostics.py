"""Public error categories and payload-free administrator tracebacks."""

import asyncio
import logging
import re
import traceback
import uuid

import httpx
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError, UnexpectedModelBehavior, UsageLimitExceeded

from .cloud import CloudError, redact

logger = logging.getLogger('dirigentenstab.operations')


# CloudStack ApiErrorCode values (ApiServer.java): 431 PARAM_ERROR, 432 UNSUPPORTED_ACTION_ERROR, 530 INTERNAL_ERROR,
# 532 ACCOUNT_RESOURCE_LIMIT_ERROR, 533 INSUFFICIENT_CAPACITY_ERROR, 535 RESOURCE_ALLOCATION_ERROR.
# 530 is generic, so its rule matches on text only. Each rule: (error codes, errortext fragments, hint). The first match wins; hints are guesses, never verified causes.
ERROR_HINTS = (
    ({533}, ('insufficientservercapacity', 'unable to create a deployment'),
     'placement failed. Common causes: cluster CPU/RAM allocation above cluster.cpu|memory.allocated.capacity.disablethreshold (default 85%), '
     'host/storage tags not matching the offering, local vs shared primary storage mismatch, no free GPU/vGPU slot. '
     'Check usage of running VMs in the domain, try a smaller or local-storage offering, or ask the owner.'),
    ({532, 535}, ('maximum number of resources of type',),
     'quota or resource limit of the account or domain{resource}. Check resource limits and usage, free resources or ask the owner.'),
    ({432}, ('does not exist or is not available', 'is not available for user'),
     'your role lacks this API. Do not retry with other identities; use APIs in available_api_names or request_escalation if truly required.'),
    ({431}, ('due to invalid value',),
     'invalid parameter{parameter}. Use describe_api to check names, types and allowed values.'),
    (set(), ('is not in a state', ' in state '),
     'a VM/resource state precondition failed. Check its current state with the list API first.'),
)


def error_hint(text):
    code = re.search(r'\((\d{3})\)|error (\d{3})|HTTP (\d{3})', text)
    code = int(next(g for g in code.groups() if g)) if code else None
    lowered = text.lower()
    for codes, fragments, hint in ERROR_HINTS:
        if code in codes or any(fragment in lowered for fragment in fragments):
            resource = re.search(r"of type '?(\w+)", text)
            parameter = re.search(r"[Pp]arameter:? '?([A-Za-z]\w+)", text)
            return ' Hint (not a verified cause): ' + hint.format(
                resource=f' (resource type {resource[1]})' if resource else '',
                parameter=f' {parameter[1]}' if parameter else '')
    return ''


SECRET_PAIR = re.compile(r'(?i)(["\']?\b(?:api[_-]?key|secret[_-]?key|signature|session[_-]?key|access[_-]?token|token|password|secret|'
                         r'authorization|userdata)\b["\']?\s*[:=]\s*)("[^"]*"|\'[^\']*\'|[^\s&,;}]+)')
SECRET_TOKEN = re.compile(r'(?i)\bbearer\s+\S+|\bsk-[A-Za-z0-9_-]{8,}|[A-Za-z0-9+/=]{200,}|(?<=://)[^/\s:@]+:[^/\s@]+(?=@)')


def public_text(value, limit=1000):
    """The real message with credentials, keys, tokens and userdata removed, capped for display."""
    text = SECRET_PAIR.sub(r'\1[redacted]', SECRET_TOKEN.sub('[redacted]', redact(str(value))))
    return ' '.join(text.split())[:limit]


class OperationError(ValueError):
    def __init__(self, category, description, operation_id, *, reconciliation=False):
        self.category = category
        self.operation_id = operation_id
        self.reconciliation = reconciliation
        super().__init__(f'{description} Reference: {operation_id}')


def diagnose(exc, *, operation_id=None, agent_id=None, tool=None, reconciliation=False):
    if isinstance(exc, OperationError):
        return exc
    operation_id = operation_id or str(uuid.uuid4())
    detail = public_text(exc)
    if isinstance(exc, (asyncio.TimeoutError, httpx.TimeoutException)):
        category, description = 'timeout', 'The operation timed out.'
    elif isinstance(exc, PermissionError):
        category, description = 'authorization', 'Access denied or session expired. Sign in again if needed.'
        if str(exc) in {'API unavailable to this CloudStack identity and API key', 'API not available to this identity'}:
            description, detail = 'CloudStack does not permit this API for this agent’s current account and API key.', ''
    elif isinstance(exc, CloudError):
        category = 'cloudstack'
        description = ('CloudStack rejected the operation. Check permissions, resource limits and parameters.'
                       if exc.rejected else 'CloudStack could not complete the operation. Check API connectivity and permissions.')
        if exc.rejected and any(word in str(exc).lower() for word in ('quota', 'limit exceeded', 'maximum')):
            description = 'CloudStack rejected the operation because a resource quota or limit was exceeded.'
        elif exc.rejected and any(marker in str(exc) for marker in ('HTTP 401:', 'error 401:')):
            category = 'authentication'
            description = 'CloudStack rejected this agent’s API credentials. An administrator must reconcile its keys.'
        elif 'expung' in str(exc).lower() and 'permission' in str(exc).lower():
            category = 'authorization'
            description = 'CloudStack denied permanent VM deletion (expunge) for this agent’s API key.'
        elif exc.rejected and any(code in str(exc) for code in ('401', '403', '531')):
            category = 'authorization'
            description = 'CloudStack denied this operation for the agent’s account, domain or API key.'
        if exc.public_detail and exc.public_detail not in detail:
            detail = public_text(f'{detail} {exc.public_detail}')
    elif isinstance(exc, ModelHTTPError):
        category = 'model-provider'
        code = exc.status_code
        if code in {401, 403}:
            category, description = 'authentication', 'The model provider rejected authentication. Check its API key and account access.'
        elif code == 404:
            description = 'The model or provider endpoint was not found. Check the Model ID, base URL and protocol.'
        elif code == 429:
            description = 'The model provider rate limit or account quota was reached. Wait before retrying or check provider billing.'
        elif code >= 500:
            description = f'The model provider is unavailable (HTTP {code}). Retry after the provider recovers.'
        else:
            description = f'The model provider rejected the request (HTTP {code}). Check model and tool compatibility.'
    elif isinstance(exc, UsageLimitExceeded):
        category, description = 'budget', 'The bounded execution window is exhausted. Progress has been saved for continuation.'
    elif isinstance(exc, UnexpectedModelBehavior):
        category, description = 'model-provider', 'The model returned an invalid or incomplete response. Check model tool-calling support.'
    elif isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in {401, 403}:
        category, description = 'authentication', 'The model provider rejected authentication. Check its credentials.'
    elif isinstance(exc, (ModelAPIError, ModelHTTPError, UnexpectedModelBehavior, UsageLimitExceeded, httpx.HTTPError)):
        category, description = 'model-provider', 'The model provider could not complete this reply. Check its configuration.'
    elif isinstance(exc, RuntimeError) and str(exc) == (
            'Context compaction failed; the original conversation and previous summary are preserved'):
        category, description, detail = 'compaction', str(exc) + '.', ''
    elif isinstance(exc, ValueError):
        category, description = 'configuration', 'The request or configuration is invalid. Review the selected settings.'
    else:
        category = 'tool-execution' if tool else 'unexpected'
        description = 'Agent execution failed. The administrator can investigate using this reference.'
    if detail:
        description += ' Details: ' + detail + error_hint(detail)
    if reconciliation:
        category = 'provisioning'
        description += ' Infrastructure requires reconciliation. Inspect the saved provisioning or VM deployment before continuing; do not create duplicates.'
    # Exception messages, locals and source lines can contain prompts, HTTP bodies and secrets.
    frames = '\n'.join(f'  {frame.filename}:{frame.lineno} in {frame.name}'
                       for frame in traceback.extract_tb(exc.__traceback__))
    logger.error('operation=%s agent=%s tool=%s category=%s exception=%s status=%s\nTraceback (payloads omitted):\n%s',
                 operation_id, agent_id, tool, category, type(exc).__name__, getattr(exc, 'status_code', None), frames)
    return OperationError(category, description, operation_id, reconciliation=reconciliation)
