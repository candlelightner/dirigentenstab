# Dirigentenstab V1 product specification

Based on the owner's requirements interview. This describes intended behavior,
not a claim that the current implementation already provides it. Where the
existing README, code, or previous audit conflicts with these decisions, this
specification defines the product intent. Implementation is not authorized by
the creation of this document.

## Purpose

A central hierarchical agent hub for managing VMs without requiring the owner
to configure infrastructure permissions manually. The owner gives instructions
in ordinary language; agents carry them out autonomously within their actual
rights. The GUI also permits manual administration.

The hierarchy defines administrative scope, not a chain for distributing tasks.
Only the human owner assigns work. A parent can administer resources in its
descendants' scope itself; it does not hand tasks to child agents.

V1 serves one human owner, authenticated through the existing CloudStack
administrator login. Subgroup administrators are agents, not additional human
users. There is no new hub account or registration system.

## Hierarchy and infrastructure permissions

- Retain a main admin agent and clearly defined CloudStack subgroup domains.
- Provide a separate Global Admin above the existing sidebar hierarchy, with its
  own dedicated native CloudStack root administrator account and encrypted key.
  Preserve Main Agent, its domain hierarchy, configuration and conversations.
  Only the human root administrator can open/configure Global Admin; other
  agents cannot access it. Global Admin uses the same agent settings and starts
  with all central providers, MCP servers/tools and owner SSH access enabled.
  Explicit selections persist on subsequent setup. Main Agent's inherited
  external-service settings remain independent; new Global Admin subgroups
  inherit Global Admin's settings. Native root authority permits administering
  CloudStack-wide resources, including public service offerings.
- Creating a subgroup also creates its admin agent, visible in the hub hierarchy.
- Agents may create subgroups autonomously by default, unless that capability
  has been disabled. Creation does not require a separate human approval.
- The owner can request a subgroup and its restrictions in ordinary language,
  for example a testing group limited to specified resources. The agent configures
  the corresponding native CloudStack domain/account permissions and quotas.
- Parents may administer their descendants' permissions within their own native
  authority. The owner can change permissions manually through the GUI or
  CloudStack. Both surfaces must reflect the same native authority.
- CloudStack domains, accounts, roles, and native quotas are the infrastructure
  permission authority. Do not introduce a duplicate hub API permission system
  or a separate local subgroup-creation gate that disagrees with CloudStack.
- Use the acting agent's own CloudStack identity. A denied action must not retry
  with a parent, main-admin, or platform credential to escalate its authority.
- Native permission changes govern subsequent actions; agent autonomy and
  system prompts do not override them.

## Owner-approved escalation

- Agents use native CloudStack operations through their own identity whenever
  permitted. When their current native permissions prevent a required action,
  `request_escalation` queues a short goal, a short explanation of that limitation,
  and the exact native command and parameters for the human owner's review.
  This covers arbitrary native actions, including registering a GPU profile;
  it is not an offering-specific provisioning workflow.
- Every agent has this tool enabled by default. The owner or an ancestor can
  disable it; inherited disabling immediately blocks descendants while retaining
  their individual selections. This setting governs requesting assistance, not
  the agent's native CloudStack authority.
- A global platform setting limits open escalation requests per agent across all
  conversations, defaulting to three. Pending and applying requests occupy slots;
  repeated delivery of the same tool call does not consume another slot. Finished
  or dismissed requests release their slots. Enforce the count and insertion atomically.
- Requests are asynchronous. Agents finish other work before using `pause_work`
  if they need to wait. A request does not execute the command or pause the agent.
- Explicit approval executes only the reviewed command and unchanged parameters
  through the owner's current native platform-administrator session. Validate
  against that administrator's native API metadata; do not inject a domain or
  change the agent's persistent permissions. Reuse the existing native API
  execution and asynchronous-job handling. This path does not execute host
  commands or bypass the GPU controller for host-device operations.
- The owner's decision view shows the exact parameters that will run, including
  password, token and similar fields, with `userdata` decoded from base64 and
  labelled as decoded. Agent-facing results and logs keep these fields redacted.
  The visible-domain set used to list requests is cached per session for 30 seconds.
- Keep one durable queue. Migrate existing compute-offering requests as explicit
  `createServiceOffering` commands, preserving their parameters, decisions,
  results, history and notifications. Persist submitted asynchronous job IDs
  before waiting. An uncertain outcome must never silently replay a command.
- Deliver approved, failed and uncertain results to the originating agent once,
  after its current conversation finishes or pauses. A stopped conversation must
  not restart because a result arrived. Results are clearly identified system
  notifications, not owner-authored messages.
- Each decided request shows a centered note ("Escalation approved", "Escalation
  declined", or an applying, failed or uncertain variant) in the originating chat
  directly after that request's tool activity, not at the end. While the run is
  still marked running with a pending request of its own, the busy indicator reads
  "Waiting for your decision on an escalation request" instead of "Thinking…".
- Dismissal invokes no agent and changes no infrastructure. Its originating chat
  shows only a centered informational note. The top-right icon opens a compact
  list with the goal and reason on two ellipsized lines; selecting a request opens
  a separate full-text popup with the exact command and parameters. Approve and
  Dismiss controls appear only in that detail popup. Pending requests pulse
  orange/red; the idle icon is gray.

## Autonomous execution and conversations

- Work begins from the owner's message. There are no scheduled or recurring
  tasks in V1.
- Each agent supports multiple conversations. Conversations run independently,
  including simultaneous conversations belonging to the same agent. There is
  no one-task-per-agent serialization requirement.
- Tell the agent how many conversations are active for that agent. This is
  awareness, not a guarantee against conflicting operations on the same VM.
- Work continues when the browser closes or the owner selects another agent
  or conversation. Reopening the hub shows saved history and current status.
- The hub keeps the owner's CloudStack login alive server-side for the hub session's lifetime and never signs the owner out because CloudStack was briefly unreachable; only a definitive CloudStack rejection ends the session early.
  Revalidation is retried every 5 minutes and an unreachable CloudStack is tolerated for 15 minutes since the last success. Reloading during an outage shows a "CloudStack unreachable, retrying" page that retries on its own, never the sign-in page, and open VM consoles stay up within that window.
- Failed sign-ins are limited to 8 per account per 15 minutes and 40 in total; the client IP is not used because the hub sits behind a shared proxy address.
- Signing out or expiration of the owner's browser session does not stop accepted
  tasks. A valid human login authorizes submitting instructions; background work
  runs under the agent's own credentials and current native permissions, without
  requiring a live human session. This does not bypass revoked agent authority.
- Unfinished work survives an application restart and resumes without requiring
  the owner to press Continue. Explicitly stopped or agent-paused work must not
  be mistaken for work interrupted by a restart.
- There are no application-imposed task runtime, request-count, tool-call-count,
  or spending caps in V1. Work continues until completed, interrupted by the
  owner, or judged blocked by the agent. Native quotas, provider limits, and
  individual transport failures still exist; they are not artificial task budgets.
- Retain practical output bounds, network timeouts, and finite simultaneous
  request capacity. These protect the application and cause waiting or recoverable
  errors, not termination because an overall task budget expired.
- A new message in an active conversation interrupts that conversation's current
  execution, preserves its progress, and becomes its next instruction. This
  must not interrupt any other conversation.
- Keep an explicit Stop control. It stops only the current conversation and
  preserves completed work. It does not stop the agent's other conversations.
- An already-submitted remote operation may finish after interruption. Preserve
  enough operation state for the agent to establish the outcome before proceeding.
- After interruption, restart, or a lost response, the agent checks actual
  infrastructure state and reconciles what happened itself, then resumes. A lost
  response is not proof that a mutation failed. Do not make routine recovery
  depend on the owner running an administrator repair command.
- The hub itself resolves stale managed VM deployments (startup, every 5 minutes,
  and before refusing a new managed VM): it binds a unique usable VM, or closes
  the row when its job is finished or purged and no owned VM is live, or when a
  never-dispatched `prepared` row is older than 30 minutes with no matching VM.
  It only reads CloudStack and never creates, deletes or redeploys anything; an
  agent is never left blocked by such a row waiting for a human.
- If the outcome remains uncertain, the agent decides whether to investigate
  further, continue where possible, or pause and ask the owner. Do not impose a
  universal manual-review gate merely because an operation was interrupted.
- The runtime does not silently replay uncertain actions. Give the agent saved
  action details, known outcomes, and inspection tools so it can decide whether
  to retry, continue, or pause. Do not build a universal recovery framework for
  every possible SSH command or external service; agents handle those situations.
- Show completion, unread activity, and blocked/paused status in the hub.
  External notifications are not required for V1.

## Agent configuration and external services

Keep per-agent model selection and system prompts. A new subgroup initially
inherits its parent's model/provider configuration, system prompt, and enabled
provider/MCP selections. The parent can narrow the enabled selections during
creation.

The Main Agent and Global Admin start with a shipped default system prompt
(`DEFAULT_INSTRUCTIONS`): short sections on role and hierarchy, working method,
CloudStack practice, VMs and guests, skills, safety, diagnosis and reporting. It
is only an editable default: the owner, a parent, or the agent itself can change
or clear it, and the hub hardcodes no behavioral guidance beyond it. The runtime
appends only tool/API semantics and enforced safety invariants (list formatting,
`managed=True`, saved/uncertain operations, untrusted MCP output, environment
state). A migration upgrades prompts equal to the former one-line default and
leaves customized prompts untouched.

| Setting or action | Human owner | Parent agent | Agent itself |
| --- | --- | --- | --- |
| Manage central provider/MCP endpoints and credentials | Yes | No | No |
| Select an agent's model/provider | Yes | Yes, within inherited access | No |
| Edit an agent's system prompt | Yes | Yes | Yes |
| Change enabled providers, MCP servers, or MCP tools | Yes | Yes, within its own effective allowance | No |

- Model providers and MCP connections are centrally managed, not separately
  recreated for every agent. Keep support for local models and the existing
  compatible provider protocols; do not require a commercial provider.
- Per-agent configuration selects from the central catalog and enables or
  disables access. Parent agents cannot grant external-service access they do
  not themselves have.
- MCP connections autodetect their tools, support bearer tokens, and expose
  individual tool toggles as in the current implementation. Enabling a server
  does not eliminate the individual tool selections.
- Disabling a provider, server, or tool at an ancestor makes it unavailable to
  every descendant immediately for subsequent dispatches. Preserve descendants'
  selections so access can return when the ancestor enables it again.
- Named secrets (for example `gh` tokens or dev-VM API keys) are set write-only
  by the human owner in Platform settings: a value can be replaced or deleted,
  never shown again, and is sealed with the master key. Agents see granted
  names only. Grants follow the same strict ancestor inheritance as providers
  and MCP servers, except that an unset selection grants nothing. The hub
  injects values at execution time through exactly two sinks: `{{secret:NAME}}`
  placeholders in the `env` of `run_vm_command`, and `write_vm_secret_file`
  (mode 600 file on an enrolled VM). Both send values over SSH stdin, never on
  a command line. Unknown or ungranted names fail closed. All tool output,
  histories and events are scrubbed of each value and its base64 and
  URL-encoded forms. This guards against accidental leaks, not hostile agents:
  an agent with a shell on the VM can read the value. Rotation UI, external
  vaults, per-secret ACLs and audit dashboards are out of scope.
- These small inherited provider/MCP rules belong to the hub because CloudStack
  does not manage external model and tool access. They are not a second system
  for infrastructure permissions.
- Self-editing a system prompt cannot change enforced permissions or enabled
  tools. Configuring a child's prompt does not authorize assigning it a task.
- Changing an agent's configuration pauses its active actions and conversations,
  applies the new configuration, and resumes that work from the new state.
  Stop further dispatches during the transition and account for already-submitted
  remote actions. Do not start idle conversations or restart work explicitly
  stopped by the owner. Apply this behavior to agents affected by inherited
  access changes as well.
- Retain existing model-capability discovery and thinking-level configuration;
  no new model-management platform is required.

## Skills

- Skills have a required name, short description, and full text. Metadata appears
  in each eligible agent's context; full text is loaded only through `get_skill`.
- The creator and its ancestors can read and edit a skill, as can the human owner.
  Editors may share it with selected descendants of the creator without approval;
  recipients can read it but cannot edit or reshare it.
- Global sharing requires explicit human approval of the exact revision, either
  in the existing escalation queue or in the human skill editor. Editing removes
  global visibility until the new revision receives approval.
- `remove_skill` requests removal of a skill the agent can read. Removal always
  requires human owner approval of the exact revision; requests never delete it immediately.
- The human owner can delete any skill directly with the editor's Delete button
  (after confirmation); this uses the same removal as an approved request and is audited.
- The sidebar's existing view selector includes Skills. Selecting a skill opens
  a minimal editor; names and descriptions are listed without loading full text.

## Context compaction

Retain current configurable automatic compaction behavior, including:

- A selectable compaction provider/model.
- A configurable percentage threshold for automatic compaction.
- Existing context-window discovery, manual override, and usage display.
- Preservation of the full transcript and durable operation state while reducing
  the history sent to the model.

Compaction supports long autonomous conversations; it is not a reason to impose
hard task-length limits. This requirement does not request a redesign of the
current compaction settings.

## VMs and guest access

- The hub's primary responsibility is VM infrastructure administration.
- The selected agent's view shows VMs within its native scope, including status,
  available SSH connection details, and links to the VMs in CloudStack.
- This VM list is informational. Start, stop, restart, delete, and other VM
  actions remain available through chat and CloudStack, not duplicate GUI buttons.
- The owner normally uses SSH or the CloudStack console to work inside VMs and
  run dedicated development harnesses there. Those harnesses are independent
  workloads; the hub does not orchestrate their agents or import their hierarchy.
- Main and subgroup admins can still execute commands inside VMs they control.
  Guest administrator privileges are the default, not an additional opt-in for
  each managed VM. This can use an SSH account with elevated privileges; direct
  root login is not a product requirement.
- Parent admins can execute guest commands in descendants' VMs, authorized using
  their own CloudStack identity rather than borrowing a child agent's identity.
  Guest authentication must still be established; native VM control alone does
  not manufacture an SSH credential for an arbitrary existing machine.
- Configure the owner's SSH public key centrally once and add it to newly
  created VMs alongside agent access. Do not require per-VM manual SSH setup for
  compatible managed deployments. VM enrollment never needs the owner's private
  SSH key. The embedded SSH terminal uses the VM's managed access key after native
  authorization; the hub stores no owner private key.
- These enrollment defaults apply to compatible new managed VMs. Existing
  machines are not silently modified; agents handle other guest setup as part
  of their assigned work. V1 does not promise automatic enrollment of every OS.
- Preserve verified guest host keys and protected agent credentials. Guest
  administrator access is not permission to execute arbitrary commands on the
  physical host running the hub or CloudStack.
- V1 supplies connection details, CloudStack links, an embedded SSH terminal,
  a file browser (browse, download, upload up to 100 MiB per file) over the
  managed SFTP connection after the same native authorization, and
  CloudStack's native noVNC console (embedded or in a new tab). Console
  endpoints are requested just in time through the signed-in owner's own
  CloudStack session; the hub does not implement its own VNC service.

## vGPU support: explicit host-level exception

Retain the current vGPU capability: detect available vGPU profiles and prepare
capacity so CloudStack can use it. Full physical GPU passthrough is excluded.

The existing host GPU controller is the explicit exception to CloudStack-only
infrastructure enforcement. Retain its host safety checks, ownership rules,
ancestor GPU policies, and existing distinction between agent operations and
human platform-administrator policy/ownership changes. Agents must not bypass
those boundaries or use the controller as a fallback for native permission denial.

Retaining this feature does not automatically add a GPU-worker image factory,
guest licensing service, or development-workload orchestration to V1.

## Installation and implementation boundaries

- Retain the current `setup.sh` workflows: preflight, native installation,
  connection to an existing CloudStack installation, and verification. Preserve
  supported installation outcomes without treating every current implementation
  mechanism as a permanent requirement.
- Retain the current stack unless an agreed requirement cannot reasonably be met
  with it. Do not add frameworks, service layers, or general-purpose orchestration
  abstractions just to implement this specification.
- Preserve existing VM data, credentials, and conversation history when removing
  unwanted features. Removing delegation must not delete prior conversations or
  discard records of remote operations whose outcomes remain unresolved.
- Keep the hierarchy, direct chat, central configuration, VM overview, and task
  status usable in the existing desktop and mobile GUI. Clean up UI/UX where
  feasible while preserving the existing layout.
- Implement the agreed workflows with reasonable failure handling. Do not expand
  V1 into exhaustive edge-case machinery; agents are responsible for investigating
  and handling operational situations within their authority.

## Platform status

- A host-side watchdog writes a read-only, secret-free `status.json` (hosts,
  management API, system VMs, capacity, `issues`, owner-only `actions`, and an
  `updated` timestamp). Compose mounts `/var/lib/dirigentenstab/platform` read-only
  at `/platform`; `PLATFORM_STATUS_FILE` overrides the path. A missing file, invalid
  JSON, or a status older than 300 seconds is "unknown/stale" and never blocks work.
  Create the host directory before `docker compose up` (otherwise Docker creates it as root).
- Agents have a read-only `platform_status` tool (status, summarized `issues`,
  `stale`; never `actions`). After a placement or start failure, and before
  retrying, they check it and wait or report instead of retrying when a host is not Up.
- Managed VM deployment and GPU deploy/start refuse immediately with a rejected
  error, before any deployment row or CloudStack call, when a fresh status shows a
  host that is not Up.
- The owner sees a compact warning banner with the `issues` while a fresh status is
  unhealthy, or a subtle "Platform status unavailable" note when stale, refreshed
  every few seconds.

## Explicitly outside V1

- Agent-to-agent task assignment, delegation tools, and delegation execution.
- Orchestration of development agents or harnesses running inside VMs.
- Scheduled or recurring tasks.
- Artificial task spending, request, tool-call, or elapsed-time caps.
- Additional human-user product workflows or a separate authentication system.
- Duplicate CloudStack permission enforcement or a replacement CloudStack dashboard.
- Direct VM lifecycle buttons in the hub's informational VM list.
- External notification integrations.
- Full GPU passthrough.

Previous audit suggestions, such as conversation archiving or a broad refactor,
are not approved requirements merely because they appeared in the audit.

## Acceptance scenarios

1. The owner asks the main agent to create a restricted testing subgroup. It
   creates the native domain and admin agent without a separate approval; both
   appear in the hierarchy. Restrictions apply through CloudStack itself.
2. Disabling native subgroup-creation authority prevents creation through both
   GUI-driven actions and agent requests, without credential escalation.
3. A subgroup admin completes an owner-assigned VM task autonomously inside its
   scope. It cannot assign that work to another agent.
4. The owner closes the browser, signs out, or lets the session expire; accepted
   tasks continue under their agents' own credentials and current permissions.
   After an application restart, unfinished work checks any uncertain operation
   outcomes and continues without routine manual repair. Revoked agent authority
   still prevents subsequent unauthorized actions.
5. Two conversations on the same agent work independently. A message or Stop in
   one affects only that conversation. The agent receives its active-conversation
   count, and a stopped conversation does not restart merely because the app does.
6. A new subgroup inherits configuration and permitted external tools. Disabling
   a tool at its parent prevents subsequent child calls while retaining the child
   selection. Re-enabling it restores access subject to other ancestor restrictions.
7. A new install seeds the default prompt, and clearing it leaves only the
   hardcoded tool semantics. An agent can change its own prompt but cannot change its own model or enabled
   tools. Its parent can change those settings only within its own allowance.
   Configuration changes pause the affected agent's active work and resume it
   under the new state without restarting explicitly stopped conversations.
8. A compatible new VM receives the owner's SSH public key and agent guest-admin
   access. The owner sees status and connection details; a parent can administer
   the guest after authorization under the parent's own CloudStack identity.
9. A long task continues through configurable context compaction without losing
   the full transcript or pausing solely because an artificial task budget expired.
10. Authorized vGPU preparation makes detected profile capacity available to
    CloudStack while preserving existing host-controller safeguards. No full
    passthrough workflow is introduced.

These are behavioral checks for later implementation. They do not prescribe a
new testing framework, scheduler, or distributed execution architecture.
