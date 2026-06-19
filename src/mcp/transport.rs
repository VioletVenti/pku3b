//! MCP stdio transport (**Seam 3**) — a thin adapter over [`ToolRegistry`].
//!
//! Newline-delimited JSON-RPC 2.0 over stdio, per the MCP stdio transport spec
//! (2025-06-18): each message is one line, messages MUST NOT contain embedded
//! newlines, stdout carries *only* MCP messages, and logging goes to stderr
//! (pku3b's `env_logger`/`indicatif` already write to stderr). This layer holds
//! no domain logic — it frames, routes the three JSON-RPC methods to the
//! registry, and serializes responses.

use compio::fs;
use compio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader};
use serde_json::{Value, json};

use super::tools::{ToolError, ToolRegistry};

/// Run the JSON-RPC loop until stdin reaches EOF (client closed the pipe).
pub async fn serve(registry: ToolRegistry) -> anyhow::Result<()> {
    let mut reader = BufReader::new(fs::stdin());
    let mut stdout = fs::stdout();

    while let Some(line) = read_line(&mut reader).await? {
        let trimmed = trim_ascii(&line);
        if trimmed.is_empty() {
            continue;
        }
        if let Some(response) = handle_message(&registry, trimmed).await {
            // Compact serialization => no embedded newlines (spec requirement).
            let mut bytes = serde_json::to_vec(&response)?;
            bytes.push(b'\n');
            stdout.write_all(bytes).await.0?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Read one `\n`-delimited line (without the newline). `Ok(None)` on EOF.
async fn read_line<R: AsyncBufRead>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return Ok(Some(line));
        }
        let n = available.len();
        line.extend_from_slice(available);
        reader.consume(n);
    }
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// Dispatch one JSON-RPC message. Returns `Some(response)` for requests and
/// `None` for notifications (which get no reply).
async fn handle_message(registry: &ToolRegistry, line: &[u8]) -> Option<Value> {
    let msg: Value = match serde_json::from_slice(line) {
        Ok(v) => v,
        Err(e) => return Some(rpc_error(Value::Null, -32700, &format!("parse error: {e}"))),
    };

    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));

    match method {
        "initialize" => {
            let id = id?;
            // Echo the client's protocol version when present (lenient negotiation).
            let pv = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-06-18");
            Some(rpc_ok(
                id,
                json!({
                    "protocolVersion": pv,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "pku3b", "version": env!("CARGO_PKG_VERSION") }
                }),
            ))
        }
        // Notifications — no response.
        "notifications/initialized" | "initialized" | "notifications/cancelled" => None,
        "ping" => id.map(|id| rpc_ok(id, json!({}))),
        "tools/list" => Some(rpc_ok(id?, json!({ "tools": registry.list_mcp() }))),
        "tools/call" => {
            let id = id?;
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match registry.call(name, args).await {
                Ok(envelope) => Some(rpc_ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": envelope.to_string() }],
                        "structuredContent": envelope,
                        "isError": false
                    }),
                )),
                Err(ToolError::UnknownTool(n)) => {
                    Some(rpc_error(id, -32602, &format!("unknown tool: {n}")))
                }
                // Tool ran but failed: an MCP tool error, not a protocol error.
                Err(ToolError::Internal(message)) => Some(rpc_ok(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": format!("tool error: {message}") }],
                        "isError": true
                    }),
                )),
            }
        }
        other => id.map(|id| rpc_error(id, -32601, &format!("method not found: {other}"))),
    }
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_crlf_and_spaces() {
        assert_eq!(trim_ascii(b"  hi \r"), b"hi");
        assert_eq!(trim_ascii(b"{}\r"), b"{}");
        assert_eq!(trim_ascii(b""), b"");
    }

    #[test]
    fn error_object_shape() {
        let e = rpc_error(json!(1), -32601, "method not found: foo");
        assert_eq!(e["jsonrpc"], "2.0");
        assert_eq!(e["id"], 1);
        assert_eq!(e["error"]["code"], -32601);
    }

    #[test]
    fn ok_object_shape() {
        let r = rpc_ok(json!("a"), json!({ "x": 1 }));
        assert_eq!(r["jsonrpc"], "2.0");
        assert_eq!(r["id"], "a");
        assert_eq!(r["result"]["x"], 1);
    }
}
