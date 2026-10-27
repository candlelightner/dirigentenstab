import importlib.util
import os
from pathlib import Path
import re
import subprocess
import textwrap

import pytest


spec = importlib.util.spec_from_file_location('native_setup', Path(__file__).parents[1] / 'scripts/native_setup.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def test_native_network_rejects_overlapping_existing_route():
    with pytest.raises(RuntimeError, match='conflicts'):
        native.check_routes([{'dst': '10.253.0.0/16', 'dev': 'existing-bridge'}])


def test_default_route_and_owned_bridge_are_accepted_without_mutation():
    routes = [{'dst': 'default', 'gateway': '10.0.0.138', 'dev': 'eth0'},
              {'dst': '10.253.80.0/24', 'dev': native.BRIDGE},
              {'dst': '172.18.0.0/16', 'dev': 'docker0'}]
    previous = [dict(route) for route in routes]
    native.check_routes(routes)
    assert routes == previous


def test_existing_link_local_route_is_not_replaced():
    with pytest.raises(RuntimeError, match='link-local'):
        native.check_routes([{'dst': '169.254.169.254/32', 'dev': 'existing-metadata'}])


def test_properties_preserve_permissions_and_back_up_original_once(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir()
    monkeypatch.setattr(native, 'STATE', state)
    settings = tmp_path / 'agent.properties'
    settings.write_text('# host=old\nport=8250\n')
    settings.chmod(0o600)
    native.properties(settings, {'host': '10.253.80.1'})
    first = settings.stat().st_mtime_ns
    native.properties(settings, {'host': '10.253.80.1'})
    assert settings.stat().st_mtime_ns == first
    assert settings.stat().st_mode & 0o777 == 0o600
    assert (state / 'originals' / str(settings).lstrip('/')).read_text() == '# host=old\nport=8250\n'
    assert settings.read_text() == 'host=10.253.80.1\nport=8250\n'


def test_completed_install_step_is_not_repeated(tmp_path, monkeypatch):
    monkeypatch.setattr(native, 'STATE', tmp_path)
    (tmp_path / 'database.done').touch()
    native.step('database', lambda: pytest.fail('Completed database setup must not run again'))


def test_guest_ssh_rules_are_scoped_and_removal_preserves_other_rules():
    import json
    from types import SimpleNamespace
    spec = importlib.util.spec_from_file_location('guest_forwarding',
        Path(__file__).parents[1] / 'scripts/guest_ssh_forwarding.py')
    forwarding = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(forwarding)
    commands = []
    owned = '-A FORWARD ' + ' '.join(forwarding.rules('br-test')[0])
    def run(command, **kwargs):
        commands.append(command)
        if command[:3] == ('iptables', '-w', '-S'):
            return SimpleNamespace(returncode=0, stdout='-P FORWARD ACCEPT\n'+owned+'\n-A FORWARD -o dscloud0 -j DROP\n')
        return SimpleNamespace(returncode=0, stdout=json.dumps([{'Id': 'a'*64}]))
    forwarding.maintain(remove=True, run=run)
    deletes = [c for c in commands if '-D' in c]
    assert len(deletes) == 1 and forwarding.TAG in deletes[0]
    assert all('-F' not in c and '-P' not in c for c in commands)
    outbound, inbound = forwarding.rules('br-test')
    assert '172.30.253.2/32' in outbound and '10.253.80.0/24' in outbound
    assert '--dport' in outbound and outbound[outbound.index('--dport')+1] == '22'
    assert 'ESTABLISHED,RELATED' in inbound and '--sport' in inbound


def test_guest_ssh_installer_does_not_restart_native_services(monkeypatch):
    writes, commands = {}, []
    monkeypatch.setattr(native, 'save', lambda path, text, *args: writes.update({path: text}))
    monkeypatch.setattr(native, 'run', lambda *args: commands.append(args))
    native.guest_ssh()
    assert '/usr/local/libexec/dirigentenstab-guest-ssh.py' in writes
    assert '/etc/systemd/system/dirigentenstab-guest-ssh.timer' in writes
    assert all('restart' not in command and 'stop' not in command for command in commands)
    assert commands[-1] == ('systemctl', 'start', 'dirigentenstab-guest-ssh.service')


def test_fresh_native_install_includes_guest_ssh_without_imports(tmp_path, monkeypatch):
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(native, 'STATE', tmp_path)
    monkeypatch.setattr(native.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(native.os, 'umask', lambda value: None)
    monkeypatch.setattr(native.sys, 'argv', ['setup.sh', '--install'])
    for name in ('preflight', 'repositories', 'packages', 'network', 'database', 'services',
                 'verify', 'prepare_application', 'guest_ssh', 'gpu_control'):
        monkeypatch.setattr(native, name, lambda name=name: calls.append(name))
    monkeypatch.setattr(native, 'step', lambda name, action: action())
    monkeypatch.setattr(native.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0))
    native.main()
    assert calls[-4:] == ['verify', 'prepare_application', 'guest_ssh', 'gpu_control']
    assert calls[:3] == ['preflight', 'repositories', 'packages']


def test_gpu_helper_installer_creates_only_its_backend_group_socket_and_service(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / 'scripts'))
    import install_gpu_helper as installer
    import dirigentenstab.gpu_control as control
    commands, writes, created = [], {}, []
    (tmp_path / '.env').write_text('IMAGE=example:0.1.5\nCOMPOSE_FILE=compose.yaml:compose.private.yaml\n')
    def run(*args):
        commands.append(args)
        if args[0] == 'groupadd':
            created.append(True)
    def group(gid):
        assert gid == 10001
        if not created:
            raise KeyError(gid)
        return SimpleNamespace(gr_name='dirigentenstab-gpu')
    monkeypatch.setattr(installer, 'ROOT', tmp_path)
    monkeypatch.setattr(installer, 'STATE', tmp_path / 'setup')
    monkeypatch.setattr(installer.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installer, 'run', run)
    monkeypatch.setattr(installer.grp, 'getgrgid', group)
    monkeypatch.setattr(installer.shutil, 'which', lambda name: None)
    monkeypatch.setattr(installer, 'save', lambda path, value, *args: writes.update({str(path): value}))
    monkeypatch.setattr(installer.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1))
    monkeypatch.setattr(control, 'NativeHost', lambda parent: SimpleNamespace(profiles=lambda: {'nvidia-51': {}}))
    installer.install('0000:07:00.0', '1bda91f5-3a27-43a4-8e52-4d955e8eed10')
    assert ('apt-get', 'install', '-y', '--no-install-recommends', 'mdevctl', 'xmlstarlet') in commands
    assert 'SocketGroup=dirigentenstab-gpu' in writes['/etc/systemd/system/dirigentenstab-gpu.socket']
    assert ('systemctl', 'is-active', 'dirigentenstab-gpu.socket') in commands
    assert all('cloudstack' not in ' '.join(c) and 'libvirtd' not in c and 'nvidia' not in ' '.join(c) for c in commands)
    assert 'COMPOSE_FILE=compose.yaml:compose.private.yaml:compose.gpu.yaml' in writes[str(tmp_path / '.env')]
    assert 'ENABLE_GPU_CONTROL=true' in writes[str(tmp_path / '.env')]


def test_gpu_automatic_setup_checks_opt_in_and_detects_local_hardware(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / 'scripts'))
    import install_gpu_helper as installer
    import admin
    gpu = tmp_path / 'hardware' / '0000:07:00.0' / 'mdev_supported_types' / 'nvidia-51'
    gpu.mkdir(parents=True)
    (tmp_path / '.env').write_text('ENABLE_GPU_CONTROL=false\n')
    monkeypatch.setattr(installer, 'ROOT', tmp_path)
    monkeypatch.setattr(installer, 'STATE', tmp_path)
    monkeypatch.setattr(installer, 'Path', lambda value: tmp_path / 'hardware' if str(value) == '/sys/bus/pci/devices' else Path(value))
    installed = []
    monkeypatch.setattr(installer, 'install', lambda *args: installed.append(args))
    installer.automatic()
    assert installed == []
    (tmp_path / '.env').write_text('ENABLE_GPU_CONTROL=true\n')
    (tmp_path / 'cloudstack-admin.json').write_text(json.dumps({'apikey': 'synthetic', 'secretkey': 'synthetic'}))
    async def raw(command, params):
        assert (command, params) == ('listHosts', {'type': 'Routing'})
        return {'host': [{'id': 'local-host', 'name': 'test-host', 'state': 'Up'},
                         {'id': 'remote-host', 'name': 'another-host', 'state': 'Up'}]}
    monkeypatch.setattr(admin, 'service', lambda: SimpleNamespace(client=lambda keys: SimpleNamespace(raw=raw)))
    monkeypatch.setattr(installer.socket, 'gethostname', lambda: 'test-host')
    monkeypatch.setattr(installer.socket, 'getfqdn', lambda: 'test-host.local')
    installer.automatic()
    assert installed == [('0000:07:00.0', 'local-host')]


def test_test_runner_manifest_computation_and_invalidation(tmp_path):
    repo = Path(__file__).parents[1]
    spec_tr = importlib.util.spec_from_file_location('test_runner', repo / 'scripts/test_runner.py')
    test_runner = importlib.util.module_from_spec(spec_tr)
    spec_tr.loader.exec_module(test_runner)

    for name in ('Dockerfile.test-runner', 'requirements.lock', 'pyproject.toml', 'scripts/test_runner.py'):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text((repo / name).read_text(encoding='utf-8'), encoding='utf-8')

    base = test_runner.compute_manifest(tmp_path)
    assert base['python_version'] == '3.12'
    assert base['playwright_version'] == '1.64.1'
    assert base['image'] == 'ghcr.io/candlelightner/dirigentenstab'
    assert base['tag'].startswith('test-runner-py3.12-pw1.64.1-')

    manifest_file = tmp_path / 'manifest.json'
    test_runner.write_manifest(tmp_path, manifest_file)

    # Changing version in pyproject.toml does NOT invalidate manifest
    pyproj = (tmp_path / 'pyproject.toml').read_text(encoding='utf-8')
    version_bump = re.sub(r'^version = "[^"]+"$', 'version = "999.0.0"', pyproj, flags=re.MULTILINE)
    assert version_bump != pyproj
    (tmp_path / 'pyproject.toml').write_text(version_bump)
    bumped = test_runner.compute_manifest(tmp_path)
    assert bumped['manifest_sha256'] == base['manifest_sha256']
    assert bumped['tag'] == base['tag']

    # Changing dependencies in pyproject.toml DOES invalidate manifest and fails validate
    (tmp_path / 'pyproject.toml').write_text(pyproj.replace('"nicegui>=3,<4",', '"nicegui>=3,<4",\n  "demo>=1",'))
    dep_changed = test_runner.compute_manifest(tmp_path)
    assert dep_changed['manifest_sha256'] != base['manifest_sha256']
    assert dep_changed['tag'] != base['tag']
    with pytest.raises(RuntimeError, match='Manifest validation failed'):
        test_runner.validate(tmp_path, manifest_file, check_workflows=False)

    # Changing optional dependencies (playwright) DOES invalidate manifest
    (tmp_path / 'pyproject.toml').write_text(pyproj.replace('playwright==1.64.1', 'playwright==1.65.0'))
    pw_changed = test_runner.compute_manifest(tmp_path)
    assert pw_changed['manifest_sha256'] != base['manifest_sha256']
    assert pw_changed['playwright_version'] == '1.65.0'

    # Violating requires-python raises ValueError
    (tmp_path / 'pyproject.toml').write_text(
        pyproj.replace('requires-python = ">=3.12"', 'requires-python = ">=3.13"')
    )
    with pytest.raises(ValueError, match='violates requires-python'):
        test_runner.compute_manifest(tmp_path)

    # Changing requirements.lock DOES invalidate manifest
    (tmp_path / 'pyproject.toml').write_text(pyproj)
    reqs = (tmp_path / 'requirements.lock').read_text(encoding='utf-8')
    (tmp_path / 'requirements.lock').write_text(reqs + 'extra-locked==1.0.0\n')
    lock_changed = test_runner.compute_manifest(tmp_path)
    assert lock_changed['manifest_sha256'] != base['manifest_sha256']

    # Changing Dockerfile.test-runner DOES invalidate manifest
    (tmp_path / 'requirements.lock').write_text(reqs)
    df = (tmp_path / 'Dockerfile.test-runner').read_text(encoding='utf-8')
    (tmp_path / 'Dockerfile.test-runner').write_text(df + '# modification\n')
    df_changed = test_runner.compute_manifest(tmp_path)
    assert df_changed['manifest_sha256'] != base['manifest_sha256']

    (tmp_path / 'Dockerfile.test-runner').write_text(df)
    script = tmp_path / 'scripts/test_runner.py'
    script.write_text(script.read_text() + '# modification\n')
    assert test_runner.compute_manifest(tmp_path)['tag'] != base['tag']


def test_test_runner_workflow_validation(tmp_path):
    repo = Path(__file__).parents[1]
    spec_tr = importlib.util.spec_from_file_location('test_runner', repo / 'scripts/test_runner.py')
    test_runner = importlib.util.module_from_spec(spec_tr)
    spec_tr.loader.exec_module(test_runner)

    # The repository workflows must pass full validation
    manifest_file = tmp_path / 'manifest.json'
    test_runner.write_manifest(repo, manifest_file)
    test_runner.validate(repo, manifest_file, check_workflows=True)

    # Setup isolated test directory with workflows
    for name in ('Dockerfile.test-runner', 'requirements.lock', 'pyproject.toml', 'scripts/test_runner.py'):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text((repo / name).read_text(encoding='utf-8'), encoding='utf-8')
    wf_dir = tmp_path / '.github/workflows'
    wf_dir.mkdir(parents=True)
    ci_text = (repo / '.github/workflows/ci.yaml').read_text(encoding='utf-8')
    browser_text = (repo / '.github/workflows/browser.yaml').read_text(encoding='utf-8')
    (wf_dir / 'ci.yaml').write_text(ci_text, encoding='utf-8')
    (wf_dir / 'browser.yaml').write_text(browser_text, encoding='utf-8')

    test_runner.validate(tmp_path, manifest_file, check_workflows=True)

    # Workflow without pinned digest fails
    (wf_dir / 'ci.yaml').write_text(re.sub(r'@sha256:[a-f0-9]{64}', '', ci_text), encoding='utf-8')
    with pytest.raises(RuntimeError, match='does not pin'):
        test_runner.validate(tmp_path, manifest_file, check_workflows=True)
    (wf_dir / 'ci.yaml').write_text(ci_text, encoding='utf-8')

    # Workflow with redundant playwright install fails
    (wf_dir / 'browser.yaml').write_text(browser_text + '\n      - run: playwright install\n', encoding='utf-8')
    with pytest.raises(RuntimeError, match='redundant playwright install'):
        test_runner.validate(tmp_path, manifest_file, check_workflows=True)
    (wf_dir / 'browser.yaml').write_text(browser_text, encoding='utf-8')

    # Workflow with redundant pip install -r fails
    (wf_dir / 'ci.yaml').write_text(ci_text + '\n      - run: pip install -r requirements.lock\n', encoding='utf-8')
    with pytest.raises(RuntimeError, match='redundant pip install -r'):
        test_runner.validate(tmp_path, manifest_file, check_workflows=True)
    (wf_dir / 'ci.yaml').write_text(ci_text, encoding='utf-8')

    # Workflow with packages: write fails
    (wf_dir / 'ci.yaml').write_text(ci_text.replace('contents: read', 'packages: write'), encoding='utf-8')
    with pytest.raises(RuntimeError, match='unauthorized packages: write'):
        test_runner.validate(tmp_path, manifest_file, check_workflows=True)
    (wf_dir / 'ci.yaml').write_text(ci_text, encoding='utf-8')

    # Workflow missing timeout-minutes fails
    (wf_dir / 'browser.yaml').write_text(browser_text.replace('timeout-minutes:', 'timeout:'), encoding='utf-8')
    with pytest.raises(RuntimeError, match='missing timeout-minutes'):
        test_runner.validate(tmp_path, manifest_file, check_workflows=True)
    (wf_dir / 'browser.yaml').write_text(browser_text, encoding='utf-8')

    # Docker steps in browser workflow fail
    (wf_dir / 'browser.yaml').write_text(browser_text + '\n      - run: docker compose ps\n', encoding='utf-8')
    with pytest.raises(RuntimeError, match='must not contain docker steps'):
        test_runner.validate(tmp_path, manifest_file, check_workflows=True)
    (wf_dir / 'browser.yaml').write_text(browser_text, encoding='utf-8')

    # Docker steps in ci test job fail
    (wf_dir / 'ci.yaml').write_text(
        ci_text.replace('run: python scripts/test_runner.py prepare',
                        'run: python scripts/test_runner.py prepare\n      - run: docker compose ps'),
        encoding='utf-8',
    )
    with pytest.raises(RuntimeError, match='test job must not run docker commands'):
        test_runner.validate(tmp_path, manifest_file, check_workflows=True)


@pytest.mark.parametrize(('force', 'error', 'expected'), [
    ('false', '', 'build=false'),
    ('false', 'manifest unknown', 'build=true'),
    ('false', 'no such manifest: example/runner:content-tag', 'build=true'),
    ('true', 'unauthorized', 'build=true'),
    ('false', 'unauthorized', None),
    ('false', 'connection timed out', None),
])
def test_runner_publisher_reuses_only_existing_images(tmp_path, force, error, expected):
    workflow = (Path(__file__).parents[1] / '.github/workflows/test-runner.yaml').read_text()
    probe = workflow.split('        id: existing\n', 1)[1].split('        run: |\n', 1)[1]
    probe = textwrap.dedent(probe.split('\n      - ', 1)[0])
    docker = tmp_path / 'docker'
    docker.write_text('#!/bin/sh\ntouch docker-called\necho "$DOCKER_ERROR" >&2\n[ -z "$DOCKER_ERROR" ]\n')
    docker.chmod(0o755)
    output = tmp_path / 'output'
    result = subprocess.run(['bash', '-e', '-c', probe], cwd=tmp_path, capture_output=True, text=True,
                            env={**os.environ, 'PATH': f'{tmp_path}:{os.environ["PATH"]}',
                                 'FORCE_REBUILD': force, 'DOCKER_ERROR': error,
                                 'IMAGE': 'example/runner:content-tag', 'GITHUB_OUTPUT': str(output)})
    assert (tmp_path / 'docker-called').exists() == (force != 'true')
    if expected is None:
        assert result.returncode != 0
        assert error in result.stderr
        assert not output.exists()
    else:
        assert result.returncode == 0, result.stderr
        assert output.read_text().strip() == expected
    for step in ('uses: docker/setup-buildx-action@v3', 'name: Build image for verification',
                 'name: Verify image offline before publishing', 'id: push', 'name: Record digest'):
        assert f"      - {step}\n        if: steps.existing.outputs.build == 'true'" in workflow
