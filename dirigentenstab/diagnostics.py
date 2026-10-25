"""Public error categories and payload-free administrator tracebacks."""

import asyncio
import logging
import traceback
import uuid

import httpx
from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError, UnexpectedModelBehavior, UsageLimitExceeded

from .cloud import CloudError

logger = logging.getLogger('dirigentenstab.operations')


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
    if isinstance(exc, (asyncio.TimeoutError, httpx.TimeoutException)):
        category, description = 'timeout', 'The operation timed out.'
    elif isinstance(exc, PermissionError):
        category, description = 'authorization', 'Access denied or session expired. Sign in again if needed.'
    elif isinstance(exc, CloudError):
        category = 'cloudstack'
        description = ('CloudStack rejected the operation. Check permissions, resource limits and parameters.'
                       if exc.rejected else 'CloudStack could not complete the operation. Check API connectivity and permissions.')
        if exc.rejected and any(word in str(exc).lower() for word in ('quota', 'limit exceeded', 'maximum')):
            description = 'CloudStack rejected the operation because a resource quota or limit was exceeded.'
        elif exc.rejected and any(code in str(exc) for code in ('401', '403')):
            description = 'CloudStack rejected the credentials or API permission. Check this agent’s restricted access.'
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
    elif isinstance(exc, ValueError):
        category, description = 'configuration', 'The request or configuration is invalid. Review the selected settings.'
        safe_messages = {
            'Configure a model identifier before starting a conversation',
            'Select a model provider in this agent’s settings first',
            'This conversation already has an execution in progress',
            'Conversation reached its context limit; start a new conversation',
            'Use scalar values, comma-separated lists, or indexed map parameters',
            'Provider missing', 'Invalid provider name or protocol', 'Agent configuration too large',
            'Use an HTTP(S) URL without embedded credentials',
            'Endpoint URLs cannot contain queries, fragments or newlines',
            'Model catalogue exceeds the size limit',
            'Provider returned an invalid model catalogue; enter a model ID manually',
            'Use a short subgroup name with letters, numbers, spaces, underscores or dashes',
            'Subgroup configuration too large', 'Message must contain 1–32768 characters',
        }
        if str(exc) in safe_messages:
            description = str(exc) + '.'
    else:
        category = 'tool-execution' if tool else 'unexpected'
        description = 'Agent execution failed. The administrator can investigate using this reference.'
    if reconciliation:
        category = 'provisioning'
        description += ' Infrastructure requires reconciliation. Inspect the saved provisioning or VM deployment before continuing; do not create duplicates.'
    # Exception messages, locals and source lines can contain prompts, HTTP bodies and secrets.
    frames = '\n'.join(f'  {frame.filename}:{frame.lineno} in {frame.name}'
                       for frame in traceback.extract_tb(exc.__traceback__))
    logger.error('operation=%s agent=%s tool=%s category=%s exception=%s status=%s\nTraceback (payloads omitted):\n%s',
                 operation_id, agent_id, tool, category, type(exc).__name__, getattr(exc, 'status_code', None), frames)
    return OperationError(category, description, operation_id, reconciliation=reconciliation)
