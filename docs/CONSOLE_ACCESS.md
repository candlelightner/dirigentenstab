# Persistent private Tailscale VM access

The reference host routes authorized Tailscale clients through `tailscale0` and
`dscloud0` to all IPv4 VMs in `10.253.80.0/24`, on all ports and protocols.
This includes current/future guest VMs and CloudStack system VMs such as the
Console Proxy VM (CPVM). The CloudStack management interface remains a separate
Tailscale Serve endpoint. No Tailscale installation inside guests is needed.

Only Tailscale ingress is expanded. LAN/internet ingress stays blocked by the
host; existing private application SSH access remains. Native CloudStack
security groups still control VM-to-VM traffic and guest egress, and are not
disabled or rewritten. Changes to VM isolation remain explicit native operations
under the requesting user/agent's CloudStack permissions. Tailscale ingress is
a host-admin access path ahead of the bridge security-group rules; services
inside a guest still need to listen and any image-provided guest firewall applies.

## Scope and persistence

Install or update from the repository root:

```sh
sudo python3 scripts/install_console_forwarding.py
```

The installer copies the helper to root-owned
`/usr/local/libexec/dirigentenstab-console.py` and enables
`dirigentenstab-console.service` and `dirigentenstab-console.timer`. This is an
explicit optional installation; ordinary application setup does not enable it.
No CloudStack, Tailscale, Docker, libvirt or SSH service is restarted.

The oneshot service runs after `network-online.target`, `tailscaled.service`,
`cloudstack-management.service`, `cloudstack-agent.service` and the existing
private network service. Service activation alone does not prove asynchronous
initialization has finished: the helper checks CloudStack's bridge drops and
Tailscale's forwarding mark, acceptance and SNAT rules before adding exceptions.
The timer retries every 30 seconds after completion, including failed attempts,
and repairs ordering after later CloudStack/Tailscale rule updates. Allow native
initialization to finish after boot; VM access can be unavailable until then.

Only two tagged IPv4 FORWARD exceptions are managed:

| Direction | Match | Action |
| --- | --- | --- |
| Client to VM | `tailscale0` to `dscloud0`, source `100.64.0.0/10`, destination `10.253.80.0/24`, NEW/ESTABLISHED/RELATED | Jump to **ts-forward** |
| VM reply | `dscloud0` to `tailscale0`, source `10.253.80.0/24`, destination `100.64.0.0/10`, RELATED/ESTABLISHED | ACCEPT |

Jumping to `ts-forward` preserves Tailscale's `0x40000/0xff0000` packet mark;
`ts-postrouting` then masquerades requests to the bridge address `10.253.80.1`.
VMs need no new return route. A plain ACCEPT would skip that mark.
Tailscale owns these chains and their NAT rules; the helper only checks them.
See [Tailscale subnet SNAT](https://tailscale.com/docs/features/subnet-routers)
and its [netfilter implementation](https://github.com/tailscale/tailscale/blob/main/util/linuxfw/iptables_runner.go).

A separate owned nftables table, `inet dirigentenstab_console`, filters forward
traffic at priority -10. It drops `tailscale0` to `dscloud0` traffic except the
IPv4 source and destination ranges above; IPv6 remains blocked on this path.
Its allow verdict still passes through the normal iptables forwarding rules.
This guard prevents a general `ts-forward` hook moved to the top by Tailscale
from bypassing the allowed source/destination ranges. It does not filter host INPUT,
Docker ingress, bridged VM traffic or traffic from the application bridge.

Client identity authorization remains with the **existing tailnet access policy**;
`100.64.0.0/10` is an address range, not an authorization list. The helper neither
grants tailnet permissions nor advertises additional routes. The existing route
advertisement is `10.253.80.0/24`. The tailnet policy must allow the intended
users/devices to this subnet and desired ports. Linux clients must accept subnet
routes (`tailscale set --accept-routes`).

The helper replaces its tagged console-only rules during upgrade and adopts
exact untagged equivalents of its current rules. Existing service, timer and
rule names are retained so an upgrade does not create competing reconcilers.
It uses a small `iptables-restore --noflush` transaction containing only deletions
of those/owned rules and insertion of the two exceptions. It never saves or
restores the dynamic ruleset, flushes shared chains or changes default policies.
The guard is replaced atomically only when missing or changed. Repeated runs
leave correct rules and counters in place. Existing guest SSH rules remain owned
by their separate helper. Forwarding is already persisted by
`/etc/sysctl.d/90-tailscale-routing.conf`; this installer does not change sysctls.

**Address lifecycle:** new VMs in this subnet are covered automatically. A subnet
change requires updating the host policy and Tailscale advertisement together.
A changed Tailscale firewall backend/mark/SNAT configuration requires review;
prerequisite failure appears in the journal.

## Reapply and test after a reboot

After an independently scheduled host reboot, use SSH to check:

```sh
systemctl is-enabled dirigentenstab-console.service dirigentenstab-console.timer
systemctl list-timers dirigentenstab-console.timer
systemctl show dirigentenstab-console.service -p Result -p ExecMainStatus -p After
sudo journalctl -b -u dirigentenstab-console.service --no-pager
sudo iptables -nvL FORWARD --line-numbers
sudo nft list table inet dirigentenstab_console
tailscale status
tailscale serve status
ip route get 10.253.80.100
sysctl net.ipv4.ip_forward
```

Both units should be enabled, the timer active, and the last helper result
`success`/status 0 once native initialization finishes. A successful oneshot is
normally **inactive (dead)** between timer runs. There should be exactly two
`dirigentenstab-console` tagged rules before the CloudStack bridge drops and any
general forwarding accepts; the disjoint application SSH rules may precede them.
The CPVM route must use `dscloud0` and IPv4 forwarding must be 1.

Reapply twice without restarting dependencies:

```sh
sudo systemctl start dirigentenstab-console.service
sudo systemctl start dirigentenstab-console.service
sudo iptables -S FORWARD
```

On an **authorized Windows Tailscale client**, use PowerShell:

```powershell
curl.exe -I --connect-timeout 5 http://10.253.80.100/
curl.exe -I --connect-timeout 5 http://10.253.80.100:8080/
Test-NetConnection 10.253.80.100 -Port 80
Test-NetConnection 10.253.80.100 -Port 8080
Test-NetConnection 10.253.80.177 -Port 22
```

An HTTP 404 at `/` is a successful transport test. Then open a **fresh** console
from the authenticated CloudStack interface and check that screen updates and
keyboard input work; HTTP probes alone do not test the WebSocket/session ticket.
Confirm tagged rule counters increase. Keep console URLs/tickets private.

Use a known running guest and listening port for the guest probe. From a LAN
client without Tailscale, attempts to the guest must fail. An unauthorized
Tailscale client's attempts must also fail under the tailnet policy. Check
VM-to-VM access against the VMs' existing native security-group policy. Verify
host SSH, Tailscale Serve routes, application-to-guest SSH and guest egress still
work. The host's own local curl/ping is not proof of forwarded Tailscale access.

The host is not rebooted as part of installation. Repeat these checks at the
next scheduled reboot.

## Remove only this persistence

```sh
sudo systemctl disable --now dirigentenstab-console.timer
sudo systemctl disable dirigentenstab-console.service
sudo systemctl stop dirigentenstab-console.service
sudo python3 /usr/local/libexec/dirigentenstab-console.py --remove
```

Removal deletes only tagged Tailscale VM exceptions and the owned guard table;
VM forwarding then depends on the remaining native rules. Re-run the
installer to restore it. Do not flush iptables/nftables or stop Tailscale to roll
this back. Stopping the oneshot alone deliberately leaves rules in place.
