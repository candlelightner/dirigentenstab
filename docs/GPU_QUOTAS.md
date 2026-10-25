# GPU quotas and compute offerings

CloudStack owns GPU devices, passthrough, vGPU profiles and resource accounting.
Each Dirigentenstab agent uses its own account's single API key pair. Native
CloudStack account, domain and role permissions decide which APIs it can call;
there is no application API allow/deny list or privileged fallback.

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

Every generic VM and offering operation uses the calling agent account's one API
key pair. CloudStack authorizes the command and enforces offering visibility,
account/domain limits and reservations. Dirigentenstab does not add a GPU API
policy, query parent credentials to widen access, or route a rejected request
through the privileged host controller. Native-authorized `createServiceOffering`
and `updateServiceOffering` remain available like any other discovered API.

Use modern offerings with a vGPU profile and positive native `gpucount` for native
GPU accounting. Stopped VMs normally retain their GPUs and count toward limits;
CloudStack's `gpu.detach.on.stop` setting changes that behavior. Physical mdev
creation and safe pool transitions are separate human-operated host preparation,
subject to real profile capacity, explicit device ownership and libvirt attachment
checks. Those host controls do not grant or remove the agent's CloudStack APIs.

## Real acceptance test

After host/application setup, run explicitly on the platform host:

```sh
sudo .venv/bin/python scripts/gpu_acceptance.py --run
```

The test creates owned, tracked administrative domains and compute-offering
metadata beneath the application root. It sets a parent GPU quota to zero and
both a child and grandchild to unlimited. It uses a real discovered GPU profile,
requires the native deployment error to identify a GPU quota violation, and
checks that an offering restricted to a sibling domain is unavailable. These
assertions exercise CloudStack directly with the leaf agent's credentials.

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

The historical CloudStack 4.23.0.0 acceptance run passed with a discovered Tesla P40
passthrough profile and local-storage GPU offerings. Native CloudMonkey calls
returned HTTP 535 for the ancestor GPU quota of zero and HTTP 531 for the
sibling-only offering. That release also had a backend preflight, since removed so native permissions
remain the sole authority. No VM was created by these denied requests and no GPU assignment was attempted.
