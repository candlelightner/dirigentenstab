# Dev VM template

A private CloudStack template with the owner's AI coding CLIs preinstalled, so a
new dev VM is ready after a one-time login per tool. Built by
[`scripts/dev_template.sh`](../scripts/dev_template.sh) in a **new, explicitly
authorized disposable builder VM** (like the [desktop template](DESKTOP_TEMPLATE.md));
never run it on an existing VM.

Installed (official routes): Claude Code (Anthropic signed apt repo, all users),
OpenAI Codex CLI (`@openai/codex`), Google Gemini CLI (`@google/gemini-cli`),
opencode (`opencode-ai`), GitHub CLI `gh` (cli.github.com apt repo), the
standalone VS Code CLI (`code tunnel`), Node.js LTS (NodeSource apt repo; Ubuntu
24.04's own is 18), tmux, git, curl, build-essential, python3/pip/venv, jq,
ripgrep and nfs-common. npm packages go to `/usr/local`, so every user has them.
Antigravity CLI (`agy`) is not installed: no verified unattended installer
exists; the script has a marked TODO.

## Build (hub agent)

1. Check capacity first: `execute_api('listCapacity')`. Keep the cluster below
   CloudStack's 85% allocation threshold with the builder included. Pick the
   existing cloud-init **Ubuntu 24.04** template and a service offering of
   about 2 vCPU / 4 GB with a root disk of at least 20 GB (`rootdisksize`
   if the offering allows it).
2. Deploy the builder with `execute_api('deployVirtualMachine', ..., managed=true)`,
   name it e.g. `dev-template-builder`, and wait until `run_vm_command(vm_id, 'cloud-init status --wait')` succeeds.
3. Fetch the script pinned to a commit of this repository (never a branch):

   ```sh
   curl -fsSL https://raw.githubusercontent.com/candlelightner/dirigentenstab/<commit>/scripts/dev_template.sh -o dev_template.sh
   ```
4. `run_vm_command` allows at most 600 seconds, and the install can take
   longer, so run it detached and poll:

   ```sh
   sudo nohup bash dev_template.sh > dev_template.log 2>&1 &
   ```

   Then poll with `tail -n 5 dev_template.log; pgrep -f dev_template.sh`
   until the process is gone. The log ends with one version line per tool
   (`claude`, `codex`, `gemini`, `opencode`, `gh`, `code`, `node` ...); none may say `MISSING`.
   The script is idempotent: after a failure fix the cause and run it again.
5. Finalize and stop (**run nothing else afterwards**):

   ```sh
   sudo bash dev_template.sh --finalize
   ```

   This is everything the managed `createTemplate` workflow does not do (it only
   captures the stopped root volume): it clears apt caches, `/tmp`, shell
   histories and any tool credentials, removes SSH host keys and builder
   `authorized_keys`, and runs `cloud-init clean --logs --machine-id`. Clones
   therefore run cloud-init again and receive their own host key, agent key,
   owner key and machine-id from the managed user-data. The `dirigent` user is
   kept; cloud-init re-applies it.
6. `execute_api('stopVirtualMachine', id=<builder>)`, wait for `Stopped`, then
   `execute_api('createTemplate', name='dev-vm', displaytext='Dev VM (<commit>)', ostypeid=..., volumeid=<builder ROOT volume>, managed=true)`.
   Do not boot the builder again before the template is ready.

## Test and clean up

1. Deploy one test clone from the new template with `managed=true`.
2. With `run_vm_command` check `claude --version`, `codex --version`,
   `gemini --version`, `opencode --version`, `gh --version`, `code --version`,
   `node --version` (>= 20), `tmux -V`; confirm `cat /etc/machine-id` and
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` differ from the values
   you recorded on the builder before finalizing.
3. Destroy the builder and the test clone. Keep the template. Report the commit
   and template id to the owner.

## One-time owner login in each new dev VM

Agents must not do these steps or read the resulting credential files; the owner
runs them over SSH (or `code tunnel`):

| Tool | Command |
| - | - |
| Claude Code | `claude`, then `/login` |
| Codex | `codex login --device-auth` (enable device code login in ChatGPT security settings first) |
| Gemini CLI | `gemini`, then `/auth` (Google's free tier moved to Antigravity CLI on 2026-06-18; use an API key or Code Assist account if that applies) |
| opencode | `opencode auth login` (or `/connect` in the TUI) |
| GitHub CLI | `gh auth login` |
| VS Code tunnel | `code tunnel` and follow the device login prompt |

Do not bake any of these logins into the template; finalize removes them.

## Updating

Rebuild from a fresh builder with a newer pinned commit. Claude Code in the
template updates through apt; the npm tools update with
`sudo npm install -g --prefix /usr/local @openai/codex @google/gemini-cli opencode-ai`.
