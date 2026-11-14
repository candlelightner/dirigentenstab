# Shared logins: credential files (never configs or histories) live in the shared volume ~/.logins and each harness path is a
# symlink into it. Runs on every login and self-heals: a real file (atomic rename replaced the link, or the user logged in
# before the link existed) moves into the store when it is newer than the stored copy, else it is discarded; then it is re-linked.
dirigentenstab_share_login() {  # $1 path under $HOME, $2 path under ~/.logins
    local path="$HOME/$1" store="$HOME/.logins/$2"
    if [ -z "$DIRIGENTENSTAB_SHARED_LOGINS" ]; then  # sharing is off: drop links that would dangle
        if [ -L "$path" ] && [ ! -e "$path" ] && [ "$(readlink "$path")" = "$store" ]; then rm -f "$path"; fi
        return 0
    fi
    if [ -f "$path" ] && [ ! -L "$path" ]; then
        mkdir -p "$(dirname "$store")" && chmod 700 "$(dirname "$store")"
        if [ ! -e "$store" ] || [ "$path" -nt "$store" ]; then mv -f "$path" "$store"; else rm -f "$path"; fi
    fi
    [ -e "$store" ] && chmod 600 "$store"
    if [ ! -e "$path" ] && [ ! -L "$path" ] && [ -e "$store" ]; then
        mkdir -p "$(dirname "$path")" && ln -s "$store" "$path"
    fi
    return 0
}
if [ -d "$HOME/.logins" ] || [ -z "$DIRIGENTENSTAB_SHARED_LOGINS" ]; then
    dirigentenstab_share_login .codex/auth.json codex/auth.json
    dirigentenstab_share_login .gemini/oauth_creds.json gemini/oauth_creds.json
    dirigentenstab_share_login .gemini/google_accounts.json gemini/google_accounts.json
    dirigentenstab_share_login .local/share/opencode/auth.json opencode/auth.json
    dirigentenstab_share_login .config/gh/hosts.yml gh/hosts.yml
    dirigentenstab_share_login .claude/.credentials.json claude/.credentials.json
fi
unset -f dirigentenstab_share_login

# Register the hub MCP server with each installed harness whose config lacks this exact URL (idempotent; a changed URL
# re-registers, since homes outlive containers). The key stays in the container environment: configs reference it by
# variable and never store or print it. The URL comes only from the hub's tunnel; nothing here assumes a hub name or origin.
if [ -n "$DIRIGENTENSTAB_MCP_URL" ] && [ -n "$DIRIGENTENSTAB_MCP_KEY" ]; then
    if command -v claude >/dev/null 2>&1 && ! grep -qsF "\"$DIRIGENTENSTAB_MCP_URL\"" "$HOME/.claude.json"; then
        claude mcp remove --scope user dirigentenstab >/dev/null 2>&1
        claude mcp add --scope user --transport http dirigentenstab "$DIRIGENTENSTAB_MCP_URL" \
            --header 'Authorization: Bearer ${DIRIGENTENSTAB_MCP_KEY}' >/dev/null 2>&1
    fi
    if command -v codex >/dev/null 2>&1 && ! grep -qsF "\"$DIRIGENTENSTAB_MCP_URL\"" "$HOME/.codex/config.toml"; then
        mkdir -p "$HOME/.codex"
        sed -i '/^\[mcp_servers\.dirigentenstab\]$/,/^bearer_token_env_var/d' "$HOME/.codex/config.toml" 2>/dev/null
        printf '\n[mcp_servers.dirigentenstab]\nurl = "%s"\nbearer_token_env_var = "DIRIGENTENSTAB_MCP_KEY"\n' \
            "$DIRIGENTENSTAB_MCP_URL" >> "$HOME/.codex/config.toml"
    fi
    if command -v opencode >/dev/null 2>&1 && ! grep -qsF "\"$DIRIGENTENSTAB_MCP_URL\"" "$HOME/.config/opencode/opencode.json"; then
        mkdir -p "$HOME/.config/opencode"
        if [ -s "$HOME/.config/opencode/opencode.json" ]; then
            node -e 'const f=process.argv[1],c=JSON.parse(require("fs").readFileSync(f));c.mcp={...c.mcp,dirigentenstab:{type:"remote",url:process.env.DIRIGENTENSTAB_MCP_URL,headers:{Authorization:"Bearer {env:DIRIGENTENSTAB_MCP_KEY}"},enabled:true}};require("fs").writeFileSync(f,JSON.stringify(c,null,2))' \
                "$HOME/.config/opencode/opencode.json"
        else
            node -e 'require("fs").writeFileSync(process.argv[1],JSON.stringify({mcp:{dirigentenstab:{type:"remote",url:process.env.DIRIGENTENSTAB_MCP_URL,headers:{Authorization:"Bearer {env:DIRIGENTENSTAB_MCP_KEY}"},enabled:true}}},null,2))' \
                "$HOME/.config/opencode/opencode.json"
        fi
    fi
    # gemini and qwen expand $VAR inside settings.json, so only the variable name is stored. aider has no MCP support.
    for pair in gemini:.gemini qwen:.qwen; do
        tool=${pair%%:*}; dir="$HOME/${pair#*:}"
        if command -v "$tool" >/dev/null 2>&1 && ! grep -qsF "\"$DIRIGENTENSTAB_MCP_URL\"" "$dir/settings.json"; then
            mkdir -p "$dir"
            node -e 'const fs=require("fs"),f=process.argv[1];let c={};try{c=JSON.parse(fs.readFileSync(f))}catch{}
c.mcpServers={...c.mcpServers,dirigentenstab:{httpUrl:process.env.DIRIGENTENSTAB_MCP_URL,headers:{Authorization:"Bearer $DIRIGENTENSTAB_MCP_KEY"}}};fs.writeFileSync(f,JSON.stringify(c,null,2))' "$dir/settings.json"
        fi
    done
    echo "Hub MCP registered. Log in once: claude -> /login, codex login --device-auth, opencode auth login (gemini, qwen, aider if installed: their own login)"
    echo "Env logins: a granted secret becomes an environment variable here (Claude Code reads CLAUDE_CODE_OAUTH_TOKEN from 'claude setup-token'; also GH_TOKEN, GEMINI_API_KEY, OPENAI_API_KEY)."
    if [ -n "$DIRIGENTENSTAB_SHARED_LOGINS" ]; then
        echo "File logins (codex, gemini, opencode, gh) are shared across agents via ~/.logins; two agents refreshing one token at once can log it out, then log in again."
    fi
fi
