import pytest

from dirigentenstab.cloud import CloudError
from dirigentenstab.diagnostics import diagnose


@pytest.mark.parametrize('exc,description,category', [
    (CloudError('CloudStack HTTP 531: Caller does not have permission; private-payload', rejected=True),
     'account, domain or API key', 'authorization'),
    (CloudError('CloudStack asynchronous operation failed (530): Account does not have permission for expunging; private-payload'),
     'permanent VM deletion (expunge)', 'authorization'),
    (PermissionError('API unavailable to this CloudStack identity and API key'), 'does not permit this API', 'authorization'),
    (CloudError('CloudStack HTTP 401: Invalid key; private-payload', rejected=True), 'API credentials', 'authentication'),
])
def test_native_permission_diagnostics_are_specific_without_exposing_details(exc, description, category, caplog):
    error = diagnose(exc, operation_id='operation', agent_id='agent', tool='execute_api')
    assert error.category == category and description in str(error)
    assert 'operation' in str(error) and 'private-payload' not in str(error) + caplog.text


@pytest.mark.parametrize('exc,description', [
    (RuntimeError('Context compaction failed; the original conversation and previous summary are preserved'),
     'original conversation and previous summary are preserved'),
    (ValueError('Context compaction requires a known context window, output reserve and threshold of 1–99 percent'),
     'known context window'),
    (ValueError('Automatic compaction must be a whole percentage from 1 to 99, or disabled'), 'whole percentage'),
])
def test_safe_compaction_failures_remain_clear_to_users(exc, description):
    assert description in str(diagnose(exc, operation_id='compaction-operation'))


def test_compaction_like_provider_error_cannot_expose_payload(caplog):
    error = diagnose(RuntimeError('Context compaction failed; provider secret private-payload'), operation_id='operation')
    assert 'private-payload' not in str(error) + caplog.text
