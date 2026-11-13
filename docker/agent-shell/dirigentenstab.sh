# Register the hub MCP server with each installed harness that lacks it (idempotent). The key stays in the container
# environment: configs reference it by variable and never store or print it.
if [ -n "$DIRIGENTENSTAB_MCP_URL" ] && [ -n "$DIRIGENTENSTAB_MCP_KEY" ]; then
    if command -v claude >/dev/null 2>&1 && ! grep -qs '"dirigentenstab"' "$HOME/.claude.json"; then
        claude mcp add --scope user --transport http dirigentenstab "$DIRIGENTENSTAB_MCP_URL" \
            --header 'Authorization: Bearer ${DIRIGENTENSTAB_MCP_KEY}' >/dev/null 2>&1
    fi
    if command -v codex >/dev/null 2>&1 && ! grep -qs 'mcp_servers.dirigentenstab' "$HOME/.codex/config.toml"; then
        mkdir -p "$HOME/.codex"
        printf '\n[mcp_servers.dirigentenstab]\nurl = "%s"\nbearer_token_env_var = "DIRIGENTENSTAB_MCP_KEY"\n' \
            "$DIRIGENTENSTAB_MCP_URL" >> "$HOME/.codex/config.toml"
    fi
    if command -v opencode >/dev/null 2>&1 && ! grep -qs '"dirigentenstab"' "$HOME/.config/opencode/opencode.json"; then
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
        if command -v "$tool" >/dev/null 2>&1 && ! grep -qs '"dirigentenstab"' "$dir/settings.json"; then
            mkdir -p "$dir"
            node -e 'const fs=require("fs"),f=process.argv[1];let c={};try{c=JSON.parse(fs.readFileSync(f))}catch{}
c.mcpServers={...c.mcpServers,dirigentenstab:{httpUrl:process.env.DIRIGENTENSTAB_MCP_URL,headers:{Authorization:"Bearer $DIRIGENTENSTAB_MCP_KEY"}}};fs.writeFileSync(f,JSON.stringify(c,null,2))' "$dir/settings.json"
        fi
    done
    echo "Hub MCP registered. Log in once: claude -> /login, codex login --device-auth, opencode auth login (gemini, qwen, aider if installed: their own login)"
fi
