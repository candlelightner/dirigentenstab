from pathlib import Path

import pytest


def test_real_lifecycle_evidence_requires_native_running_results_in_order(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / 'scripts'))
    from gpu_lifecycle_acceptance import evidence
    def event(ids, offering, **overrides):
        return {'type': 'tool_result', 'target': 'listVirtualMachines', 'content': {'virtualmachine': [
            {'id': identifier, 'displayname': 'owned-'+identifier, 'state': 'Running', 'gpucount': 1,
             'serviceofferingid': offering, **overrides} for identifier in ids]}}
    eight, full = event(['a', 'b', 'c'], '8q'), event(['d'], '24q')
    assert evidence([eight, full], 'owned-', '8q', '24q') == ['a', 'b', 'c', 'd']
    for events in ([full, eight], [event(['a', 'b'], '8q'), full],
                   [event(['a', 'b', 'c'], '8q', state='Stopped'), full],
                   [eight, event(['d'], '24q', displayname='unrelated')],
                   [eight, event(['a'], '24q')]):
        with pytest.raises(AssertionError):
            evidence(events, 'owned-', '8q', '24q')


async def test_cleanup_resumes_after_a_lost_reply_and_never_touches_baseline(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / 'scripts'))
    import gpu_lifecycle_acceptance as script
    saved, removed = [], []
    monkeypatch.setattr(script, 'save', lambda state: saved.append(state['phase']))
    state = {'baseline': ['original'], 'vm_ids': ['a', 'b', 'c', 'd'], 'config': {'cpu_offering': 'cpu'}, 'prefix': 'test-'}
    class Cloud:
        async def raw(self, command, params):
            if params.get('id') in {'a', *removed}:
                return {}  # A prior successful removal lost its receipt.
            if params.get('id'):
                return {'virtualmachine': [{'id': params['id'], 'state': 'Stopped', 'serviceofferingid': 'cpu',
                    'domainid': 'main', 'account': 'main-owner', 'displayname': 'test-'+params['id']}]}
            return {'virtualmachine': [{'id': 'original'}]}
        async def execute(self, command, params):
            assert command == 'destroyVirtualMachine' and params['expunge']
            removed.append(params['id'])
    await script.cleanup(Cloud(), state, domain_id='main', account='main-owner')
    assert removed == ['b', 'c', 'd'] and saved == ['cleanup', 'cleaned']
    state['vm_ids'] = ['original', 'a', 'b', 'c']
    with pytest.raises(AssertionError, match='non-baseline'):
        await script.cleanup(Cloud(), state, domain_id='main', account='main-owner')
    assert removed == ['b', 'c', 'd']
    state['vm_ids'] = ['e', 'f', 'g', 'h']
    class ForeignCloud(Cloud):
        async def raw(self, command, params):
            result = await super().raw(command, params)
            for vm in result.get('virtualmachine', []):
                vm['domainid'] = 'unrelated'
            return result
    with pytest.raises(AssertionError, match='refused'):
        await script.cleanup(ForeignCloud(), state, domain_id='main', account='main-owner')
    assert removed == ['b', 'c', 'd']
