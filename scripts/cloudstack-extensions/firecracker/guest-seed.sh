#!/bin/sh
# Mount the Firecracker cidata disk (ext4, the guest kernel has no iso9660/vfat) as the NoCloud seed directory.
seed=/var/lib/cloud/seed/nocloud
mkdir -p "$seed"
for _ in $(seq 150); do
  mountpoint -q "$seed" && exit 0
  [ -b /dev/vdb ] && mount -o ro /dev/vdb "$seed" 2>/dev/null && exit 0
  sleep 0.1
done
exit 0
