//! MCP (Model Context Protocol) server for pku3b.
//!
//! Exposes pku3b's **read-only** teaching-network capabilities as MCP tools over
//! newline-delimited JSON-RPC 2.0 on stdio (`pku3b mcp`). Built so an external
//! agent host (e.g. a Python FastAPI + PydanticAI backend) can both render
//! deterministic dashboards (calling tools directly, never through an LLM) and
//! drive an LLM agent over the same tool catalog.
//!
//! Module layout (each is a seam — see the per-file docs):
//! - [`tools`] — the tool catalog/registry (Seam 1, the center).
//! - [`auth`]  — prompt-free login returning `NeedsOtp` as data (Seam 2).
//! - [`transport`] — the newline JSON-RPC stdio loop (Seam 3, a thin adapter).
//!
//! This module is gated behind the `mcp` cargo feature and adds nothing to the
//! default CLI build.

mod auth;
mod tools;
mod transport;

use std::path::PathBuf;

/// Entry point for the `pku3b mcp` subcommand: build the tool registry from the
/// given config and serve JSON-RPC on stdio until the client closes stdin.
pub async fn run(config_path: PathBuf) -> anyhow::Result<()> {
    let registry = tools::ToolRegistry::new(config_path).await?;
    transport::serve(registry).await
}
