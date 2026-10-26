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

## Compute offering requests

- Agents create CPU and permitted mediated GPU offerings directly with
  `execute_api` and native `createServiceOffering` when their own CloudStack
  authority permits it. The request tool is optional owner assistance when
  owner action is needed; it does not replace or restrict native creation.
- Requests are asynchronous. Agents finish other work before using `pause_work`
  when they need to wait for an offering; calling the tool does not pause them.
- Every agent can request a native CloudStack compute offering by default. The
  owner or an ancestor can disable this tool; disabling any ancestor blocks all
  descendants immediately while preserving their individual selections.
- The tool accepts native `createServiceOffering` parameters and durably queues
  the request for the human owner's review. Requests do not borrow administrator
  credentials or directly create offerings.
- Approval creates the requested offering through the owner's current native
  CloudStack session, scoped to the requesting agent's domain. Native CloudStack
  authority still applies. Approval does not resize or create a VM.
- Denial dismisses the request without changing infrastructure or invoking the
  agent. Its originating chat shows only a centered UI note: “Compute offering
  request declined”. Approved offerings notify the requesting agent that the
  offering is available. Durable decisions and notifications survive application
  restarts. Uncertain creation outcomes are inspected rather than submitted again.
- Agents with existing mediated GPU permission may request native vGPU-profile
  offerings. Validate their current inherited GPU policy and native quota both
  when queuing and approving. No physical GPU passthrough or legacy GPU details
  bypass is allowed, and requesting an offering does not mutate host devices.
- A top-right header icon opens requests on mobile and desktop. Pending requests
  pulse between orange and red; the idle icon is gray.

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
  compatible managed deployments or store the owner's private SSH key.
- These enrollment defaults apply to compatible new managed VMs. Existing
  machines are not silently modified; agents handle other guest setup as part
  of their assigned work. V1 does not promise automatic enrollment of every OS.
- Preserve verified guest host keys and protected agent credentials. Guest
  administrator access is not permission to execute arbitrary commands on the
  physical host running the hub or CloudStack.
- V1 supplies connection details and CloudStack links. Embedded terminals and
  embedded noVNC consoles are possible V2 work, not V1 requirements.

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

## Explicitly outside V1

- Agent-to-agent task assignment, delegation tools, and delegation execution.
- Orchestration of development agents or harnesses running inside VMs.
- Scheduled or recurring tasks.
- Artificial task spending, request, tool-call, or elapsed-time caps.
- Additional human-user product workflows or a separate authentication system.
- Duplicate CloudStack permission enforcement or a replacement CloudStack dashboard.
- Embedded SSH terminals or embedded VM consoles.
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
7. An agent can change its own prompt but cannot change its own model or enabled
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
