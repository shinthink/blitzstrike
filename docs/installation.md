# Installation

Blitz Strike is an MCP server. Install it once, then register it with whichever
MCP client you use — Claude Code, Cursor, Hermes, OpenCode, or any other.

## Prerequisites

- **Bun 1.4+** (or Node 20+) — for running from source and building.
- **One MCP client** — anything that speaks MCP over stdio.

```bash
# Install Bun (Linux/macOS)
curl -fsSL https://bun.sh/install | bash
```

## Install

### From source

```bash
git clone https://github.com/shinthink/blitzstrike.git
cd blitzstrike
bun install
```

### Pre-built binary

Download the single static binary for your platform from
[releases](https://github.com/shinthink/blitzstrike/releases), then:

```bash
chmod +x blitzstrike
./blitzstrike serve --mcp
```

## Register with a client

### Automatic (`blitzstrike install`)

```bash
blitzstrike install           # detect every agent CLI + write native config
blitzstrike install --dry-run # preview without writing
```

`install` auto-detects which agent CLIs you have installed and writes the
correct MCP config to **each one**, in its native format:

| Agent | Config written | Format |
|---|---|---|
| Claude Code | `~/.claude.json` | JSON `mcpServers` |
| Claude Desktop | `~/.config/Claude/claude_desktop_config.json` | JSON `mcpServers` |
| Cursor | `~/.cursor/mcp.json` | JSON `mcpServers` |
| OpenCode | `~/.config/opencode/opencode.json` | `mcp` → `type: local` + command array |
| Codex | `~/.codex/config.toml` | TOML `[mcp_servers.blitzstrike]` |
| Hermes | `~/.hermes/config.yaml` | YAML `mcp_servers:` |
| Gemini CLI | `~/.gemini/settings.json` | JSON `mcpServers` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON `mcpServers` |
| Copilot | `~/.copilot/mcp.json` | JSON `mcpServers` |
| Cline | `~/.cline/mcp_settings.json` | JSON `mcpServers` |

Every write **merges** — it never overwrites your existing MCP servers or
other config keys. Existing servers are preserved; BlitzStrike is added.

### Manual — any MCP client

```json
{
  "mcpServers": {
    "blitzstrike": {
      "command": "blitzstrike",
      "args": ["serve", "--mcp"]
    }
  }
}
```

Client-specific locations:

| Client | Config location |
|---|---|
| Claude Code / Desktop | `.mcp.json` (project) or `claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| OpenCode | `.mcp.json` |
| Hermes | `mcp_servers:` under `~/.hermes/config.yaml` |
| Gemini / Copilot | native MCP config |

For Hermes specifically, add to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  blitzstrike:
    command: "blitzstrike"
    args: ["serve", "--mcp"]
```

## Verify

```bash
blitzstrike doctor
```

`doctor` checks runtime, the 130-tool catalog, credentials, and data layers —
each with a severity and a `fix:` line. See
[Usage](usage.md) for what a full engagement looks like.

## Optional credentials

| Variable | Purpose |
|---|---|
| `FOFA_EMAIL` + `FOFA_KEY` | Enable `fofa_search` asset-index lookups |

All other tools need no credentials.
