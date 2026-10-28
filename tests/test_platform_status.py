import json
import time
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab.cloud import CloudError
from dirigentenstab.platform_status import banner, read, summary
from dirigentenstab.service import Service
from dirigentenstab.store import Store


def status(path, *, age=0, host='Up', healthy=True, **extra):
    now = time.time()
    path.write_text(json.dumps({'version': 1, 'updated': now - age, 'healthy': healthy,
                                'hosts': [{'name': 'kvm1', 'status': host, 'resource_state': 'Enabled', 'since': now - 3600}],
                                'issues': ['host kvm1 Disconnected'], 'actions': [{'at': now, 'action': 'restart', 'result': 'ok'}],
                                **extra}))
    return str(path)


def test_reader_missing_invalid_stale_fresh(tmp_path):
    assert read(str(tmp_path / 'missing.json')) is None
    for text in ('{', '[]', '{"healthy": true}', '{"updated": "x"}'):
        (tmp_path / 'bad.json').write_text(text)
        assert read(str(tmp_path / 'bad.json')) is None
    assert read(status(tmp_path / 's.json', age=301))['stale'] is True
    assert read(status(tmp_path / 's.json', age=10))['stale'] is False


def test_tool_summary_excludes_actions_and_caps_issues(tmp_path):
    full = read(status(tmp_path / 's.json', issues=[f'issue {i}' for i in range(9)]))
    result = summary(full)
    assert 'actions' not in result and result['stale'] is False and result['hosts'][0]['name'] == 'kvm1'
    assert len(result['issues']) == 6 and result['issues'][-1] == '... and 4 more'
    assert summary(None)['status'] == 'unknown'


def test_banner_text(tmp_path):
    assert banner(None) is None
    assert banner(read(status(tmp_path / 's.json', healthy=True))) is None
    assert banner(read(status(tmp_path / 's.json', healthy=False))) == ('host kvm1 Disconnected', True)
    assert banner(read(status(tmp_path / 's.json', age=900, healthy=False))) == ('Platform status unavailable', False)


@pytest.fixture
def service(tmp_path):
    master = tmp_path / 'master'
    master.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(master))
    return Service(store, SimpleNamespace(platform_status=str(tmp_path / 'status.json')))


class NoCloud:
    async def catalogue(self):
        raise AssertionError('CloudStack must not be called')


async def test_preflight_refuses_when_fresh_and_host_down_without_rows(service, tmp_path):
    status(tmp_path / 'status.json', host='Disconnected')
    with pytest.raises(CloudError, match=r'CloudStack host kvm1 is Disconnected since \d\d:\d\d; managed deployment refused') as raised:
        await service._deploy_managed({'id': 'parent'}, NoCloud(), {})
    assert raised.value.rejected
    assert service.store.all('SELECT * FROM vm_deployments') == [] and service.store.all('SELECT * FROM vm_access') == []


@pytest.mark.parametrize('stale', [True, False])
async def test_preflight_proceeds_when_stale_or_missing(service, tmp_path, stale):
    if stale:
        status(tmp_path / 'status.json', age=900, host='Disconnected')
    with pytest.raises(AssertionError, match='must not be called'):  # got past pre-flight to the CloudStack catalogue
        await service._deploy_managed({'id': 'parent'}, NoCloud(), {})
