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
def test_native_permission_diagnostics_are_specific_and_keep_payloads_out_of_logs(exc, description, category, caplog):
    error = diagnose(exc, operation_id='operation', agent_id='agent', tool='execute_api')
    assert error.category == category and description in str(error)
    assert 'operation' in str(error) and 'private-payload' not in caplog.text


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
    assert 'private-payload' in str(error) and 'private-payload' not in caplog.text


def test_native_public_detail_is_bounded_and_kept_out_of_logs(caplog):
    detail = 'Native deployment rejected: ' + 'x' * 1000
    error = diagnose(CloudError('private-payload', rejected=True, public_detail=detail),
                     operation_id='operation', tool='execute_api')
    assert 'private-payload Native deployment rejected' in str(error) and len(str(error)) < 1200
    assert 'private-payload' not in caplog.text
    assert 'Native deployment rejected' not in caplog.text


@pytest.mark.parametrize('message,expected', [
    ('CloudStack error 533: Unable to create a deployment for VM[User|x]', 'disablethreshold'),
    ('CloudStack asynchronous operation failed (533): Unable to create a deployment for VM[User|x]; job ID 391', 'disablethreshold'),
    ('CloudStack error 535: Maximum number of resources of type \'cpu\' for account x has been exceeded', 'resource type cpu'),
    ('CloudStack error 431: Unable to execute API command deployvirtualmachine due to invalid value. Invalid parameter zoneid', 'invalid parameter zoneid'),
    ('CloudStack error 432: The API [foo] does not exist or is not available for the account', 'available_api_names'),
    ('CloudStack asynchronous operation failed (530): VM is not in a state to stop', 'current state'),
])
def test_known_cloudstack_errors_keep_native_text_first_then_hint(message, expected):
    detail = message.split(': ', 1)[1]
    text = str(diagnose(CloudError(message, public_detail=detail), operation_id='op'))
    assert expected in text and 'Hint (not a verified cause)' in text
    assert text.index(detail) < text.index('Hint (not a verified cause)')


def test_unknown_cloudstack_error_has_no_hint_and_secrets_stay_redacted():
    text = str(diagnose(CloudError('CloudStack error 599: Something odd', public_detail='Something odd'), operation_id='op'))
    assert 'Hint' not in text and 'Something odd' in text
    from dirigentenstab.cloud import error_detail
    detail = error_detail('Unable to create a deployment; token=abcdefgh12345', {'userdata': 'abcdefgh12345'})
    text = str(diagnose(CloudError(f'CloudStack error 533: {detail}', public_detail=detail), operation_id='op'))
    assert 'abcdefgh12345' not in text and 'Hint' in text


@pytest.mark.parametrize('exc', [
    CloudError('CloudStack error 530: VM is locked by another job', rejected=True),
    PermissionError('Managed operation is unavailable to this agent'),
    ValueError('Unknown CloudStack parameter: foo'),
    RuntimeError('Something specific broke'),
])
def test_the_real_message_passes_through_with_category_and_reference(exc):
    error = diagnose(exc, operation_id='operation', tool='execute_api')
    assert str(exc) in str(error) and str(error).endswith('Reference: operation')


def test_passed_through_messages_are_redacted_and_bounded():
    key = '-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----'
    message = ('GET https://user:hunter2pass@cloud.example/client/api?command=listVMs&apikey=AKEY123&signature=SIG%2B456'
              f'&sessionkey=SK789 failed; Authorization: Bearer tok_abc; "api_key": "sk-live12345678"; {key} ' + 'x' * 2000)
    text = str(diagnose(CloudError(message), operation_id='operation'))
    for secret in ('hunter2pass', 'AKEY123', 'SIG%2B456', 'SK789', 'tok_abc', 'sk-live12345678', 'abc123', 'PRIVATE KEY'):
        assert secret not in text
    assert 'command=listVMs' in text and len(text) < 1300


def test_permission_refusals_show_their_cause_but_session_failures_stay_generic():
    error = diagnose(PermissionError('Secret API_KEY is unknown or not granted to this agent'), operation_id='op')
    assert 'Secret API_KEY is unknown or not granted to this agent. Reference: op' == str(error)
    assert error.category == 'authorization'
    for message in ('CloudStack session no longer authorized', 'CloudStack role changed; log in again'):
        assert 'Access denied or session expired' in str(diagnose(PermissionError(message), operation_id='op'))
