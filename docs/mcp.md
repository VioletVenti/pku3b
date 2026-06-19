# `pku3b mcp` — MCP server

`pku3b mcp` runs pku3b as an [MCP](https://modelcontextprotocol.io) server, exposing
pku3b's **read-only** teaching-network capabilities as tools that an agent host
(or any MCP client) can call. It is the data/automation foundation for the
[MyAL1S](https://github.com/VioletVenti/MyAL1S) campus assistant, but works with
any MCP client.

It is gated behind the `mcp` cargo feature and adds nothing to the default CLI.

```bash
cargo build --release --features mcp
./target/release/pku3b mcp        # speaks JSON-RPC on stdin/stdout
```

## Transport

- **Newline-delimited JSON-RPC 2.0 over stdio**, per the MCP stdio transport
  spec (one message per line; messages contain no embedded newlines).
- `stdout` carries **only** MCP messages. All logging goes to `stderr` (set
  `RUST_LOG` to adjust), so the channel stays clean.
- The client launches `pku3b mcp` as a subprocess and closes stdin to stop it.

## Methods

| Method | Notes |
|--------|-------|
| `initialize` | Echoes the client's `protocolVersion`; advertises `tools` capability. |
| `tools/list` | Lists the tools below. |
| `tools/call` | Runs a tool; result is a `content` text block + `structuredContent`. |
| `ping` | Returns `{}`. |
| `notifications/initialized` | Accepted, no reply. |

## Tools (all read-only)

| Tool | Args | Returns |
|------|------|---------|
| `get_course_table` | — | Current-semester personal course table (from the portal). |
| `list_assignments` | `include_finished?: bool` (default `false`) | Assignments with deadlines, sorted by DDL; unfinished only by default. |
| `get_grades` | — | Published grade items for current-semester courses. |

The one side-effecting API method (`submit_file`) is intentionally **not**
exposed.

### Result envelope

Every tool returns a uniform envelope inside the `tools/call` result so clients
branch on one field:

```jsonc
{ "status": "ok",        "data": { /* tool payload */ } }
{ "status": "needs_otp", "mobile_mask": "135****1234", "hint": "..." }
```

## Authentication & OTP

The server reuses pku3b's existing credential store (`cfg.toml`) and cookie
cache (`ua.json`) — run `pku3b init` once, and ideally `pku3b ct` once, to warm
the session before connecting an MCP client.

Login is **prompt-free**: the server never blocks on a terminal prompt. If a
one-time password is required and none is available, tools return the
`needs_otp` envelope instead of hanging. (Interactive OTP round-trips are a
client-side concern and out of scope for the server.)

Honours the global `--config` / `PKU3B_CONFIG`.

## Quick smoke test

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | ./target/release/pku3b mcp
```
