use super::*;
use crate::mcp;

/// `pku3b mcp` — run the MCP server (JSON-RPC over stdio).
///
/// Takes no arguments; honours the global `--config` / `PKU3B_CONFIG`. The
/// client (an agent host) launches this as a subprocess and speaks
/// newline-delimited JSON-RPC on stdin/stdout. All logging goes to stderr so
/// stdout stays a clean MCP channel.
#[derive(clap::Args)]
pub struct CommandMcp {}

pub async fn run(_cmd: CommandMcp, ctx: &CommandCtx<'_>) -> anyhow::Result<()> {
    mcp::run(ctx.config_path.clone()).await
}
