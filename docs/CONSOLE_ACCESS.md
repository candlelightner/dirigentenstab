# Persistent private console access

The reference host routes authorized Tailscale clients through `tailscale0` and
`dscloud0` to Console Proxy VM (CPVM) `10.253.80.100`, TCP **80 and 8080** only.
These are the working HTTP/WebSocket endpoints for this deployment. The
CloudStack management interface remains a separate Tailscale Serve endpoint.

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
initialization to finish after boot; console access can be unavailable until then.

Only two tagged IPv4 FORWARD exceptions are managed:

| Direction | Match | Action |
| --- | --- | --- |
| Client to CPVM | `tailscale0` to `dscloud0`, source `100.64.0.0/10`, destination `10.253.80.100/32`, TCP destination 80/8080, NEW/ESTABLISHED | Jump to **ts-forward** |
| CPVM reply | `dscloud0` to `tailscale0`, source `10.253.80.100/32`, destination `100.64.0.0/10`, TCP source 80/8080, RELATED/ESTABLISHED | ACCEPT |

Jumping to `ts-forward` preserves Tailscale's `0x40000/0xff0000` packet mark;
`ts-postrouting` then masquerades requests to the bridge address `10.253.80.1`.
The CPVM needs no new return route. A plain ACCEPT would skip that mark.
Tailscale owns these chains and their NAT rules; the helper only checks them.
See [Tailscale subnet SNAT](https://tailscale.com/docs/features/subnet-routers)
and its [netfilter implementation](https://github.com/tailscale/tailscale/blob/main/util/linuxfw/iptables_runner.go).

A separate owned nftables table, `inet dirigentenstab_console`, filters forward
traffic at priority -10. It drops `tailscale0` to `dscloud0` traffic except the
exact source range, CPVM and TCP ports above, including IPv6 and other protocols.
Its allow verdict still passes through the normal iptables forwarding rules.
This guard prevents a general `ts-forward` hook moved to the top by Tailscale
from opening other CloudStack guests or services. It does not filter host INPUT,
Docker ingress, bridged VM traffic or traffic from the application bridge.

Client identity authorization remains with the **existing tailnet access policy**;
`100.64.0.0/10` is an address range, not an authorization list. The helper neither
grants tailnet permissions nor advertises additional routes. The existing route
advertisement is `10.253.80.0/24`; the host guard restricts its use through this
bridge to CPVM TCP 80/8080. If client authorization needs changing, review the
tailnet policy separately, targeting `10.253.80.100` TCP 80/8080.

The helper adopts only the two exact pre-existing untagged console exceptions.
It uses a small `iptables-restore --noflush` transaction containing only deletions
of those/owned rules and insertion of the two exceptions. It never saves or
restores the dynamic ruleset, flushes shared chains or changes default policies.
The guard is replaced atomically only when missing or changed. Repeated runs
leave correct rules and counters in place. Existing guest SSH rules remain owned
by their separate helper. Forwarding is already persisted by
`/etc/sysctl.d/90-tailscale-routing.conf`; this installer does not change sysctls.

**Address lifecycle:** the CPVM address is pinned. If CloudStack replaces the
CPVM or changes console ports, confirm the new system VM identity before updating
the helper and guard together, reinstall, then repeat the tests. Do not replace
the `/32` with the guest subnet. A changed Tailscale firewall backend/mark/SNAT
configuration requires review; prerequisite failure appears in the journal.

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
```

An HTTP 404 at `/` is a successful transport test. Then open a **fresh** console
from the authenticated CloudStack interface and check that screen updates and
keyboard input work; HTTP probes alone do not test the WebSocket/session ticket.
Confirm tagged rule counters increase. Keep console URLs/tickets private.

For negative checks on the same client, `Test-NetConnection` to CPVM ports 22,
2049 and 16509, and to a known different CloudStack guest on port 80, must report
`TcpTestSucceeded: False`. An unauthorized client's CPVM 80/8080 attempts must
also fail under the tailnet policy. Test only known owned addresses. Verify SSH
to the host, existing Tailscale Serve routes, application-to-guest SSH and normal
VM networking still work. Do not use the host's local curl as proof of forwarding.

## Verification on 25 October 2026

Installation and repeated application passed; **15 focused/setup tests** and lint
checks passed. An isolated kernel forwarding test verified HTTP on 80/8080,
the actual SNAT source `10.253.80.1`, denial of SSH/NFS/libvirt ports, another VM
address and a source outside the Tailscale range. It also verified that a broad
Tailscale hook inserted first could not bypass the guard, ordering repair,
idempotent application and repeated removal. Unrelated iptables rules, Tailscale preferences/Serve routes,
Docker network inventory and running VM inventory were unchanged. Host SSH,
Tailscale, Docker, CloudStack management/agent and libvirt stayed active. Local
CPVM requests returned HTTP 404 on both ports, management returned 200, the Serve
application returned 303, and the application received an existing VM's SSH
banner. The operator's Windows Tailscale client received HTTP 404 on **both**
ports and confirmed that the **console also works** after application.

The host was not rebooted. Use the procedure above at the next scheduled reboot.

## Remove only this persistence

```sh
sudo systemctl disable --now dirigentenstab-console.timer
sudo systemctl disable dirigentenstab-console.service
sudo systemctl stop dirigentenstab-console.service
sudo python3 /usr/local/libexec/dirigentenstab-console.py --remove
```

Removal deletes only tagged console exceptions and the owned guard table;
console forwarding then depends on the remaining native rules. Re-run the
installer to restore it. Do not flush iptables/nftables or stop Tailscale to roll
this back. Stopping the oneshot alone deliberately leaves rules in place.
