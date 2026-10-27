#!/usr/bin/env bash
# Build a "dev VM" CloudStack template on an Ubuntu 24.04 builder (see docs/DEV_TEMPLATE.md).
#   sudo bash dev_template.sh              install/upgrade every tool (idempotent)
#   sudo bash dev_template.sh --finalize   clean the builder for template capture, then stop it
# Nothing here logs in to any service; the owner does that once per tool in each clone.
set -euo pipefail

NODE_MAJOR="${NODE_MAJOR:-24}" # current Node.js LTS; see https://nodejs.org/en/about/previous-releases
export DEBIAN_FRONTEND=noninteractive

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0" >&2; exit 1; }
case "${1:-}" in ''|--finalize) ;; *) echo "usage: $0 [--finalize]" >&2; exit 2;; esac

apt_repo() { # name key-url key-file deb-line
	install -d -m 0755 /etc/apt/keyrings
	curl -fsSL "$2" -o "/etc/apt/keyrings/$3"
	chmod 0644 "/etc/apt/keyrings/$3"
	echo "$4" >"/etc/apt/sources.list.d/$1.list"
}

versions() {
	for cmd in "node --version" "npm --version" "git --version" "tmux -V" "python3 --version" "pip3 --version" \
		"jq --version" "rg --version" "gcc --version" "claude --version" "codex --version" \
		"gemini --version" "opencode --version" "gh --version" "code --version"; do
		printf '%-10s ' "${cmd%% *}"
		(set +o pipefail; $cmd 2>&1 | head -n1) || echo "MISSING"
	done
	command -v mount.nfs >/dev/null && echo "nfs-common installed" || echo "nfs-common MISSING"
}

finalize() {
	versions
	apt-get clean
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.npm /root/.cache /root/.claude* /root/.codex /root/.gemini
	# Credentials or histories if anyone ran a tool by hand in the builder.
	rm -f /root/.bash_history /home/*/.bash_history /home/*/.python_history /home/*/.lesshst
	rm -rf /home/*/.claude* /home/*/.codex /home/*/.gemini /home/*/.config/gh /home/*/.local/share/opencode /home/*/.vscode*
	# The managed workflow only captures the disk. Clones get their own keys from cloud-init user-data.
	rm -f /etc/ssh/ssh_host_* /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys
	if command -v cloud-init >/dev/null; then
		cloud-init clean --logs --machine-id
	else
		echo "cloud-init not found: skipped 'cloud-init clean' (expected only in a container)"
	fi
	find /var/log -type f -exec truncate -s 0 {} +
	history -c 2>/dev/null || true
	echo "Finalized. Do not run anything else: stop the VM now, then create the template."
}

if [ "${1:-}" = "--finalize" ]; then finalize; exit 0; fi

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg
apt-get install -y tmux git curl build-essential python3 python3-pip python3-venv jq ripgrep nfs-common

# Node.js: Ubuntu 24.04's own nodejs is 18; NodeSource's apt repo provides the current LTS.
apt_repo nodesource https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key nodesource.asc \
	"deb [signed-by=/etc/apt/keyrings/nodesource.asc] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main"
# Claude Code: official signed apt repo (stable channel), available to all users; updated by apt.
apt_repo claude-code https://downloads.claude.ai/keys/claude-code.asc claude-code.asc \
	"deb [signed-by=/etc/apt/keyrings/claude-code.asc] https://downloads.claude.ai/claude-code/apt/stable stable main"
# GitHub CLI: official apt repo (Ubuntu's gh 2.45 is broken against current GitHub APIs).
apt_repo github-cli https://cli.github.com/packages/githubcli-archive-keyring.gpg githubcli-archive-keyring.gpg \
	"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main"
apt-get update
apt-get install -y nodejs claude-code gh

# Codex, Gemini CLI and opencode are npm packages; /usr/local keeps them usable by every user.
npm install -g --prefix /usr/local @openai/codex @google/gemini-cli opencode-ai

# VS Code CLI (for `code tunnel`): official standalone tarball (not the GUI package).
case "$(uname -m)" in
	x86_64) vscode_os=cli-alpine-x64 ;;
	aarch64) vscode_os=cli-alpine-arm64 ;;
	*) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
tmp="$(mktemp -d)"
curl -fsSL "https://code.visualstudio.com/sha/download?build=stable&os=$vscode_os" -o "$tmp/vscode_cli.tar.gz"
tar -xzf "$tmp/vscode_cli.tar.gz" -C "$tmp"
install -m 0755 "$tmp/code" /usr/local/bin/code
rm -rf "$tmp"

# TODO (optional): Antigravity CLI (agy) has no verified unattended installer yet; add it here once
# the vendor documents one. Do not guess a URL.

versions
