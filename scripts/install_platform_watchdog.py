#!/usr/bin/env python3
"""Idempotent installer for the platform watchdog (run as root; restarts no CloudStack service)."""

import os

from native_setup import ROOT, STATE, install_network_config, run, save


def install():
    if os.geteuid() != 0:
        raise PermissionError('Run as platform administrator/root')
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.makedirs('/var/lib/dirigentenstab/platform', mode=0o755, exist_ok=True)
    os.chmod('/var/lib/dirigentenstab/platform', 0o755)
    install_network_config()
    save('/usr/local/libexec/dirigentenstab-platform-watchdog.py',
         (ROOT / 'scripts/platform_watchdog.py').read_text(), 0o755)
    for kind in ('service', 'timer'):
        save(f'/etc/systemd/system/dirigentenstab-platform-watchdog.{kind}',
             (ROOT / f'scripts/platform-watchdog.{kind}').read_text(), 0o644)
    run('systemctl', 'daemon-reload')
    run('systemd-analyze', 'verify', '/etc/systemd/system/dirigentenstab-platform-watchdog.service',
        '/etc/systemd/system/dirigentenstab-platform-watchdog.timer')
    run('systemctl', 'enable', '--now', 'dirigentenstab-platform-watchdog.timer')
    run('systemctl', 'start', 'dirigentenstab-platform-watchdog.service')
    print('Platform watchdog installed; status in /var/lib/dirigentenstab/platform/status.json.')


if __name__ == '__main__':
    install()
