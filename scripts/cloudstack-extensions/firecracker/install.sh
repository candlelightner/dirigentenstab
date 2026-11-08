#!/usr/bin/env bash
# Idempotent installer for the Firecracker CloudStack extension. Run as the owner (needs `sudo -n`).
# Additive only: files under /opt/dirigentenstab/firecracker, /var/lib/dirigentenstab/firecracker, the CloudStack
# extensions dir, two systemd units, and CloudStack objects named fc-*/firecracker. Nothing is restarted.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
FC_VERSION=v1.17.0
KERNEL_URL=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261105-6ea6634994fa-0/x86_64/vmlinux-6.1.188
KERNEL_SHA=31fe88d6c72b93d5c9c63cca599ccadec49fd35673bbfd04850d6c00ff27f032
IMAGE_URL=https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img
IMAGE_SHA=04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94
ROOTFS=ubuntu-24.04-20261017.ext4
OPT=/opt/dirigentenstab/firecracker
EXT_DIR=/etc/cloudstack/extensions/firecracker   # /usr/share/cloudstack-management/extensions is a symlink to /etc/cloudstack/extensions
API=${CLOUDSTACK_API:-http://10.253.80.1:8080/client/api}
BRIDGE=${FC_BRIDGE:-dscloud0}
S="sudo -n"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

# ---- artifacts (checksum-verified) ----
if [ ! -x "$OPT/$FC_VERSION/firecracker" ]; then
  curl -fsSL -o "$work/fc.tgz" "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-x86_64.tgz"
  curl -fsSL -o "$work/fc.sha" "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-x86_64.tgz.sha256.txt"
  (cd "$work" && sed 's# .*# fc.tgz#' fc.sha | sha256sum -c - && tar xzf fc.tgz)
  $S install -d "$OPT/$FC_VERSION" && $S install -m 755 "$work/release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64" "$OPT/$FC_VERSION/firecracker"
fi
if [ ! -f "$OPT/$FC_VERSION/vmlinux" ]; then
  curl -fsSL -o "$work/vmlinux" "$KERNEL_URL"; echo "$KERNEL_SHA  $work/vmlinux" | sha256sum -c -
  $S install -m 644 "$work/vmlinux" "$OPT/$FC_VERSION/vmlinux"
fi
$S ln -sfn "$FC_VERSION" "$OPT/current"
if [ ! -f "$OPT/rootfs/$ROOTFS" ]; then
  # Ubuntu 24.04 cloud image -> bare ext4 root partition, cloud-init NoCloud on a second disk labelled cidata
  curl -fsSL -o "$work/img" "$IMAGE_URL"; echo "$IMAGE_SHA  $work/img" | sha256sum -c -
  qemu-img convert -O raw "$work/img" "$work/raw"
  read -r start size < <(sfdisk -J "$work/raw" | jq -r '.partitiontable.partitions[] | select(.node|endswith("raw1")) | "\(.start) \(.size)"')
  dd if="$work/raw" of="$work/root.ext4" bs=512 skip="$start" count="$size" conv=sparse status=none
  e2fsck -fy "$work/root.ext4" >/dev/null || true
  mkdir "$work/mnt"; $S mount -o loop "$work/root.ext4" "$work/mnt"
  printf '/dev/vda / ext4 defaults,discard,commit=30,errors=remount-ro 0 1\n' | $S tee "$work/mnt/etc/fstab" >/dev/null
  printf 'datasource_list: [ NoCloud, None ]\ndatasource:\n  NoCloud:\n    fs_label: cidata\nmanage_etc_hosts: localhost\n' | $S tee "$work/mnt/etc/cloud/cloud.cfg.d/99-firecracker.cfg" >/dev/null
  for u in ModemManager multipathd multipathd.socket open-iscsi iscsid.socket open-vm-tools vgauth udisks2 lvm2-monitor \
           lvm2-lvmpolld.socket dm-event.socket blk-availability apport apport-forward.socket apport-autoreport.path \
           unattended-upgrades ua-reboot-cmds ubuntu-advantage pollinate grub-common grub-initrd-fallback finalrd \
           secureboot-db tpm-udev.path sysstat setvtrgb console-setup keyboard-setup lxd-installer.socket e2scrub_reap snapd snapd.socket snapd.seeded snapd.apparmor snapd.autoimport snapd.core-fixup \
           snapd.recovery-chooser-trigger snapd.system-shutdown; do
    case $u in *.service|*.socket|*.path) ;; *) u=$u.service;; esac
    $S ln -sf /dev/null "$work/mnt/etc/systemd/system/$u"
  done
  $S ln -sf /dev/null "$work/mnt/etc/systemd/system/systemd-networkd-wait-online.service"
  # cloud-init-local races virtio disk probing and its blkid lookup misses the ext4 seed: mount it as the seed dir
  $S install -m 755 "$here/guest-seed.sh" "$work/mnt/usr/local/sbin/fc-seed.sh"
  $S install -d "$work/mnt/etc/systemd/system/cloud-init-local.service.d"
  printf '[Service]\nExecStartPre=/usr/local/sbin/fc-seed.sh\n' | $S tee "$work/mnt/etc/systemd/system/cloud-init-local.service.d/10-firecracker.conf" >/dev/null
  $S truncate -s 0 "$work/mnt/etc/machine-id"
  $S umount "$work/mnt"
  $S install -d "$OPT/rootfs"; $S cp --sparse=always "$work/root.ext4" "$OPT/rootfs/$ROOTFS"
fi
$S ln -sfn "$ROOTFS" "$OPT/rootfs/current.ext4"

# ---- worker (root, socket-activated) + thin client in the CloudStack extension dir ----
$S install -d "$OPT/bin" /var/lib/dirigentenstab/firecracker
$S install -m 755 "$here/firecracker.py" "$OPT/bin/firecracker.py"
$S install -m 644 "$here/dirigentenstab-firecracker.socket" "$here/dirigentenstab-firecracker@.service" /etc/systemd/system/
$S systemctl daemon-reload && $S systemctl enable --now dirigentenstab-firecracker.socket
$S install -d -o cloud -g cloud "$EXT_DIR"
$S install -m 755 -o cloud -g cloud "$here/firecracker.py" "$EXT_DIR/firecracker.py"

# ---- CloudStack registration (additive; skipped when the object already exists) ----
cs() { $S cat /var/lib/dirigentenstab/setup/initial-admin.json | python3 -c '
import http.cookiejar, json, sys, urllib.error, urllib.parse, urllib.request
login, api, cmd, params = json.load(sys.stdin), sys.argv[1], sys.argv[2], dict(a.split("=", 1) for a in sys.argv[3:])
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def call(data):
    try:
        return json.load(opener.open(urllib.request.Request(api, urllib.parse.urlencode({**data, "response": "json"}).encode())))
    except urllib.error.HTTPError as e:  # CloudStack answers API errors with 4xx plus a JSON body
        return json.load(e)
key = call({"command": "login", "username": login["username"], "password": login["password"], "domain": login.get("domain", "/")})["loginresponse"]["sessionkey"]
try:
    print(json.dumps(call({"command": cmd, "sessionkey": key, **params})))
finally:
    call({"command": "logout", "sessionkey": key})
' "$API" "$@"; }
ext=$(cs listExtensions name=firecracker | jq -r '.listextensionsresponse.extension[0].id // empty')
[ -n "$ext" ] || ext=$(cs createExtension name=firecracker type=Orchestrator path=firecracker.py orchestratorrequirespreparevm=false \
  description="Firecracker microVM orchestrator (Dirigentenstab)" | jq -r '.createextensionresponse.extension.id')
zone=$(cs listZones | jq -r '.listzonesresponse.zone[0].id'); pod=$(cs listPods | jq -r '.listpodsresponse.pod[0].id')
cluster=$(cs listClusters name=fc-cluster | jq -r '.listclustersresponse.cluster[0].id // empty')
[ -n "$cluster" ] || cluster=$(cs addCluster zoneid="$zone" podid="$pod" clustername=fc-cluster hypervisor=External \
  clustertype=CloudManaged extensionid="$ext" | jq -r '.addclusterresponse.cluster[0].id')
cs listHosts clusterid="$cluster" | jq -e '.listhostsresponse.host' >/dev/null 2>&1 || \
  cs addHost zoneid="$zone" podid="$pod" clustername=fc-cluster hypervisor=External url=http://fc-host-homeserver \
    username=none password=none "externaldetails[0].bridge=$BRIDGE" >/dev/null
echo "extension=$ext zone=$zone pod=$pod"
echo "Template: see docs/FIRECRACKER.md (External templates need a size/store entry; blocked on CloudStack 4.23)."
