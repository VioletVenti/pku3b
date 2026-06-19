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
| `login` | `otp: string` (required) | Warms portal + Blackboard sessions once; `{portal, blackboard}` booleans. **Not read-only.** |
| `get_course_table` | `otp?: string` | Current-semester personal course table (from the portal). Reuses a warm session; `otp` only needed when cold. |
| `list_assignments` | `include_finished?: bool` (default `false`), `otp?: string` | Assignments with deadlines, sorted by DDL; unfinished only by default. |
| `get_grades` | `otp?: string` | Published grade items for current-semester courses. |

The one side-effecting API method (`submit_file`) is intentionally **not**
exposed. Every data tool is read-only; `login` is the only stateful tool.

### Result envelope

Every tool returns a uniform envelope inside the `tools/call` result so clients
branch on one field:

```jsonc
{ "status": "ok",        "data": { /* tool payload */ } }
{ "status": "needs_otp", "mobile_mask": "135****1234", "hint": "..." }
```

## Authentication & OTP (log in once per session)

The server reuses pku3b's credential store (`cfg.toml`) and cookie cache
(`ua.json`) — run `pku3b init` once to set credentials.

Login is **prompt-free**: the server never blocks on a terminal prompt. The
intended flow for 2FA accounts is **log in once**:

1. Call `login` with a one-time password (`otp`). The HTTP client (and its
   cookie jar) lives for the whole `pku3b mcp` process, so this warms the
   session for the **portal** (and best-effort Blackboard via IAAA SSO) and
   persists cookies.
2. Every later `get_course_table` / `list_assignments` / `get_grades` reuses the
   warm session — **no per-call OTP** — until it expires.

If a tool is called with no valid session and no `otp`, it returns the
`needs_otp` envelope (the client should prompt the user to `login`). Each data
tool also accepts an optional `otp` as a fallback.

> A single IAAA OTP is typically one-shot, so one `login` reliably warms the
> portal; Blackboard is warmed via SSO when IAAA allows it, otherwise it may
> need its own `login`. Either way it is never per-operation.

Honours the global `--config` / `PKU3B_CONFIG`.

## Quick smoke test

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | ./target/release/pku3b mcp
```
