Name: dev-vm

Description: Create a ready-to-use dev VM (Claude Code, Codex, Gemini CLI, opencode, gh, VS Code CLI, tmux) from the owner's dev template and hand the one-time logins to the owner.

Text:

Use this when the owner asks for a development VM or a place to run AI coding CLIs.

1. Find the dev template: `execute_api('listTemplates', templatefilter='self', name='dev-vm')`. If it does not exist, stop and tell the owner it must be built first (procedure: docs/DEV_TEMPLATE.md in the dirigentenstab repository). Never build it unprompted.
2. Check capacity: `execute_api('listCapacity')`. Do not deploy if the target cluster would pass CloudStack's 85% allocation threshold; report the shortfall instead. Choose the smallest compute offering that fits, about 2 vCPU / 4 GB for a single CLI user, with a root disk of at least 20 GB.
3. Deploy with `execute_api('deployVirtualMachine', ..., managed=true)`, using the dev template, an offering from step 2 and a descriptive `displayname` such as `dev-<owner or project>`. Tagging a purpose is optional. Never pass custom `userdata`; managed deployments supply it.
4. Wait for the VM to run, then `run_vm_command(vm_id, 'cloud-init status --wait')`, and verify with `claude --version`, `codex --version`, `gemini --version`, `opencode --version`, `gh --version`, `code --version`.
5. Give the owner the VM name, its address, and the one-time logins to run themselves over SSH: `claude` then `/login`; `codex login --device-auth`; `gemini` then `/auth`; `opencode auth login`; `gh auth login`; `code tunnel`.
6. For token-based tools such as `gh`, if a granted secret name is listed in `secret_names`, write it with `write_vm_secret_file` or `run_vm_command` `env` using `{{secret:NAME}}` instead of asking for the token; interactive OAuth logins stay with the owner. Never read, print, copy or transfer credential files in the guest (for example `~/.claude*`, `~/.codex/auth.json`, `~/.gemini`, `~/.local/share/opencode/auth.json`, `~/.config/gh`) and never run the login commands yourself. Do not enable bypass or auto-approve permission modes or add MCP servers there; the owner decides.
7. Destroy only VMs you created, and only when the owner asks.
