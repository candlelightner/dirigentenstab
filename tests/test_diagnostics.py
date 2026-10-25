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
