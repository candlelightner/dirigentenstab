#!/usr/bin/env python3
"""Opt-in persistence for the reference host's private Tailscale VM route."""

import os

from native_setup import ROOT, STATE, install_network_config, run, save


def install():
    if os.geteuid() != 0:
        raise PermissionError('Run as platform administrator/root')
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    install_network_config()
    save('/usr/local/libexec/dirigentenstab-console.py',
         (ROOT / 'scripts/console_forwarding.py').read_text(), 0o755)
    save('/etc/systemd/system/dirigentenstab-console.service', '''[Unit]
Description=Private Tailscale to CloudStack VM forwarding
Wants=network-online.target tailscaled.service cloudstack-agent.service cloudstack-management.service
After=network-online.target tailscaled.service cloudstack-agent.service cloudstack-management.service dirigentenstab-network.service

[Service]
Type=oneshot
EnvironmentFile=/etc/dirigentenstab-network.env
ExecStart=/usr/bin/python3 /usr/local/libexec/dirigentenstab-console.py
TimeoutStartSec=120
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
''', 0o644)
    save('/etc/systemd/system/dirigentenstab-console.timer', '''[Unit]
Description=Repair scoped Tailscale VM rules after asynchronous firewall initialization

[Timer]
OnBootSec=20s
OnUnitInactiveSec=30s
AccuracySec=1s

[Install]
WantedBy=timers.target
''', 0o644)
    run('systemctl', 'daemon-reload')
    run('systemd-analyze', 'verify', '/etc/systemd/system/dirigentenstab-console.service',
        '/etc/systemd/system/dirigentenstab-console.timer')
    run('systemctl', 'enable', 'dirigentenstab-console.service')
    run('systemctl', 'enable', '--now', 'dirigentenstab-console.timer')
    run('systemctl', 'start', 'dirigentenstab-console.service')
    print('Tailscale VM access persistence installed; native services were not restarted.')


if __name__ == '__main__':
    install()
