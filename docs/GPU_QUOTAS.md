# GPU quotas and compute offerings

CloudStack owns GPU devices, passthrough, vGPU profiles and resource accounting.
Dirigentenstab agents are Domain Administrators and operate with their own
restricted runtime keys. They cannot create GPU devices, bind PCI devices, alter
host drivers or create compute offerings through generic tools.

GPU resource type is **16** in the pinned
[CloudStack 4.23 resource enumeration](https://github.com/apache/cloudstack/blob/4.23.0.0/api/src/main/java/com/cloud/configuration/Resource.java).
Some API parameter descriptions still list only older resource types. Configure
GPU limits through CloudStack's supported UI/API, including
`updateResourceLimit domainid=<domain> resourcetype=16 max=0` as an authorized
platform administrator. `-1` means unlimited for that domain; it does not remove
a limit on an ancestor.

[CloudStack checks every non-ROOT ancestor](https://github.com/apache/cloudstack/blob/4.23.0.0/server/src/main/java/com/cloud/resourcelimit/ResourceLimitManagerImpl.java)
and maintains aggregate domain usage. Its native `ROOT` domain is always
unlimited and rejects attempts to set a resource limit. The application's root
agent belongs to the separate `/Agents` domain, whose limits can be set to zero.
Native system/root administrator accounts bypass resource limits; no managed
agent receives one of those account types.

Before deploy, start, scale, restore or recover, the backend verifies the actual
compute offering using the calling agent's identity. Domain-restricted offerings
must cover the VM owner's domain. For GPU operations it reads the current
CloudStack parent chain and GPU usage through the application's root agent's
read-only runtime APIs. This trusted check does not execute VM operations with a
parent identity, expose credentials to a model, or maintain a local mutable
hierarchy. Missing ancestor information fails closed. Every ancestor GPU limit
of zero blocks GPU operations, including restarting an already counted VM.

CloudStack remains the final atomic quota authority. The backend preflight is
not a replacement for its reservations, account limits or aggregate counters.
Use modern offerings with a vGPU profile and a positive native `gpucount`.
Legacy `pciDevice`/`vgpuType` offerings without a native count are rejected because
[native GPU reservations depend on that count](https://github.com/apache/cloudstack/blob/4.23.0.0/server/src/main/java/com/cloud/vm/UserVmManagerImpl.java).
Stopped VMs normally retain their GPUs and count toward limits; CloudStack's
`gpu.detach.on.stop` setting changes that behavior.

## Real acceptance test

After host/application setup, run explicitly on the platform host:

```sh
sudo .venv/bin/python scripts/gpu_acceptance.py --run
```

The test creates owned, tracked administrative domains and compute-offering
metadata beneath the application root. It sets a parent GPU quota to zero and
both a child and grandchild to unlimited. It uses a real discovered GPU profile,
requires the native deployment error to identify a GPU quota violation, and
checks that an offering restricted to a sibling domain is unavailable. It also
checks the application's ancestor guard independently.

Every attempted test deployment sets `startvm=false`. No GPU assignment, PCI
binding, existing VM shutdown or driver reconfiguration occurs. A failure that
unexpectedly creates a stopped VM records its ID for administrator review. The
test never treats missing GPU hardware or storage capacity as proof of quota
enforcement.

The root-private journal
`/var/lib/dirigentenstab/setup/gpu-acceptance.json` records owned agents,
offerings, API calls and rejection messages. Repeated runs reuse those resources.
The deliberately denied GPU quotas remain on the owned test domains; other
domains' limits remain unchanged. These tests establish quota and authorization
behavior, not successful CUDA/vGPU workloads or licensing compatibility.

The real CloudStack 4.23.0.0 acceptance run passed with a discovered Tesla P40
passthrough profile and local-storage GPU offerings. Native CloudMonkey calls
returned HTTP 535 for the ancestor GPU quota of zero and HTTP 531 for the
sibling-only offering. The backend independently rejected both requests. No VM
was created by these denied requests and no GPU assignment was attempted.
