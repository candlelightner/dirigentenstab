import importlib.util
from pathlib import Path

import pytest

from network_config import DEFAULTS, load_network


def test_custom_network_configuration_reaches_setup_and_forwarding(tmp_path, monkeypatch):
    values = {key: value.replace('10.253.80.', '10.42.0.').replace('172.30.253.', '172.29.8.')
              for key, value in DEFAULTS.items()}
    values.update(CLOUDSTACK_BRIDGE='vmbr7', TAILSCALE_INTERFACE='tail7', CLOUDSTACK_NETWORK='10.42.0.0/23')
    env = tmp_path / '.env'
    env.write_text('\n'.join(f'{key}="{value}" # configured' for key, value in values.items())
                   + '\nSECRET=$(never execute this)\n')
    assert load_network(env) == values
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    scripts = Path(__file__).parents[1] / 'scripts'
    for name in ('console_forwarding', 'guest_ssh_forwarding', 'native_setup'):
        spec = importlib.util.spec_from_file_location('custom_' + name, scripts / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.BRIDGE == 'vmbr7'
        if name == 'console_forwarding':
            assert 'iifname "tail7" oifname "vmbr7"' in module.GUARD
            assert '10.42.0.0/23' in module.GUARD
        elif name == 'guest_ssh_forwarding':
            assert module.APP == '172.29.8.2/32' and module.GUESTS == '10.42.0.0/23'
        else:
            assert module.ADDRESS == '10.42.0.1' and str(module.NETWORK) == '10.42.0.0/23'
            writes, commands = {}, []
            monkeypatch.setattr(module, 'save', lambda path, text: writes.update({path: text}))
            monkeypatch.setattr(module, 'run', lambda *args: commands.append(args))
            module.network()
            assert ('ip', 'address', 'replace', '10.42.0.1/23', 'dev', 'vmbr7') in commands
            assert 'Address=10.42.0.1/23' in writes['/etc/systemd/network/80-dirigentenstab.network']
            assert 'ip saddr 172.29.8.2' in writes['/etc/dirigentenstab-network.nft']


@pytest.mark.parametrize('key,value', [
    ('CLOUDSTACK_BRIDGE', 'bad";drop'), ('TAILSCALE_INTERFACE', 'dscloud0'),
    ('CLOUDSTACK_NETWORK', '0.0.0.0/0'), ('CLOUDSTACK_NETWORK', '127.0.0.0/24'), ('APP_NETWORK', '10.253.80.0/24'),
    ('CLOUDSTACK_GATEWAY', '10.253.80.100'), ('CLOUDSTACK_GUEST_END', '10.253.81.220'),
    ('CLOUDSTACK_SYSTEM_END', '10.253.80.100'), ('CLOUDSTACK_GUEST_END', '10.253.80.99'),
    ('APP_ADDRESS', '172.30.253.255'), ('CLOUDSTACK_BRIDGE', 'two words'),
])
def test_invalid_network_config_fails_before_any_host_mutation(tmp_path, key, value):
    env = tmp_path / '.env'
    env.write_text(f'{key}={value}\n')
    with pytest.raises(ValueError):
        load_network(env)


def test_installed_helpers_receive_only_validated_network_settings(monkeypatch):
    import native_setup
    writes = {}
    monkeypatch.setattr(native_setup, 'save', lambda path, text, mode: writes.update({path: (text, mode)}))
    native_setup.install_network_config()
    config, mode = writes['/etc/dirigentenstab-network.env']
    assert mode == 0o600
    assert dict(line.split('=', 1) for line in config.splitlines()) == native_setup.NETWORK_CONFIG
    assert 'def load_network' in writes['/usr/local/libexec/network_config.py'][0]
