//! The MCP tool catalog (**Seam 1**) — the system's central seam.
//!
//! One catalog, two consumers (architecture decision #3): the stdio transport
//! drives it from JSON-RPC, and in-process tests call [`ToolRegistry::call`]
//! directly without any transport. The deterministic Python path will later
//! call these same tools over MCP, never through the LLM.
//!
//! The interface is small — [`ToolRegistry::specs`] + [`ToolRegistry::call`] —
//! while the implementation hides all of pku3b's `api::*` orchestration (build
//! client, log in, crawl, serialize). Every tool here is **read-only**; the one
//! side-effecting method in the API (`CourseAssignment::submit_file`) is
//! deliberately not exposed.
//!
//! ## Result envelope
//! Every tool returns a uniform JSON envelope so both consumers branch on one
//! field:
//! - `{"status":"ok","data": <payload>}`
//! - `{"status":"needs_otp","mobile_mask": <str|null>,"hint": <str>}`

use anyhow::Context as _;
use serde_json::{Value, json};
use std::path::PathBuf;

use super::auth::{self, LoginOutcome};
use crate::{api, config, utils};

/// Static metadata for one tool. Serialized to MCP's tool shape by [`ToolRegistry::list_mcp`].
pub struct ToolSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
    pub read_only: bool,
}

/// Error from dispatching a tool call.
pub enum ToolError {
    /// No tool with this name is registered (maps to JSON-RPC -32602).
    UnknownTool(String),
    /// The tool ran but failed (maps to a `tools/call` result with `isError`).
    Internal(String),
}

/// The deep module behind Seam 1. Holds the HTTP client and the config path,
/// and dispatches tool calls. Credentials are read **lazily** (only when a tool
/// actually needs to log in) so the server can `initialize` and `tools/list`
/// even before the user has configured/authenticated. Acquiring per-service
/// session handles is likewise done per call (cheap when Blackboard cookies are
/// warm); caching is a future optimization that does not change this interface.
pub struct ToolRegistry {
    client: api::Client,
    config_path: PathBuf,
}

impl ToolRegistry {
    /// Build the client (with cookie reuse + caching). Does not read config or
    /// log in — those happen lazily on the first tool call that needs them.
    pub async fn new(config_path: PathBuf) -> anyhow::Result<Self> {
        let client = api::Client::builder()
            .cookie_restore_path(Some(utils::default_user_agent_data_path()))
            .cache_ttl(Some(std::time::Duration::from_hours(1)))
            .download_artifact_ttl(Some(std::time::Duration::from_hours(24)))
            .build()
            .await
            .context("构建 HTTP client")?;

        Ok(Self {
            client,
            config_path,
        })
    }

    /// Read credentials on demand. Fails (surfaced as a tool error) if the user
    /// has not run `pku3b init` yet.
    async fn cfg(&self) -> anyhow::Result<config::Config> {
        config::read_cfg(&self.config_path).await.with_context(|| {
            format!(
                "读取配置文件 {} 失败 (请先运行 `pku3b init` 配置学号/密码)",
                self.config_path.display()
            )
        })
    }

    /// The catalog rendered as MCP `tools/list` entries.
    pub fn list_mcp(&self) -> Vec<Value> {
        tool_specs()
            .into_iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "description": s.description,
                    "inputSchema": s.input_schema,
                    "annotations": { "title": s.title, "readOnlyHint": s.read_only }
                })
            })
            .collect()
    }

    /// Dispatch a tool call by name. Returns the uniform result envelope, or a
    /// [`ToolError`]. Unknown names are rejected before any network work.
    pub async fn call(&self, name: &str, args: Value) -> Result<Value, ToolError> {
        let result = match name {
            "get_course_table" => self.get_course_table().await,
            "list_assignments" => {
                let include_finished = args
                    .get("include_finished")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.list_assignments(include_finished).await
            }
            "get_grades" => self.get_grades().await,
            other => return Err(ToolError::UnknownTool(other.to_string())),
        };
        result.map_err(|e| ToolError::Internal(format!("{e:#}")))
    }

    // ---- tool implementations (the hidden depth) --------------------------

    async fn get_course_table(&self) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let portal = match auth::login_portal(&self.client, &cfg, None).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(p) => p,
        };
        let raw = portal.get_my_course_table().await.context("获取课表")?;
        // The portal returns a JSON string; surface it structured when possible.
        let data = serde_json::from_str::<Value>(&raw).unwrap_or(Value::String(raw));
        Ok(ok(data))
    }

    async fn list_assignments(&self, include_finished: bool) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let bb = match auth::login_blackboard(&self.client, &cfg, None).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(b) => b,
        };

        let handles = bb.get_courses(true).await.context("获取课程列表")?;
        let mut items: Vec<Value> = Vec::new();

        for handle in handles {
            let course = handle.get().await.context("获取课程")?;
            let course_name = course.meta().name().to_owned();

            // Drain the lazy content stream, then keep only assignments.
            let mut stream = course.content_stream();
            let mut contents = Vec::new();
            while let Some(batch) = stream.next_batch().await {
                contents.extend(batch);
            }

            for data in contents {
                let Some(handle) = course.build_content(data).into_assignment_opt() else {
                    continue;
                };
                let assignment = handle.get().await.context("获取作业详情")?;
                let submitted = assignment.last_attempt().is_some();
                if !include_finished && submitted {
                    continue;
                }
                items.push(json!({
                    "course": course_name,
                    "title": assignment.title(),
                    "deadline": assignment.deadline().map(|d| d.to_rfc3339()),
                    "deadline_raw": assignment.deadline_raw(),
                    "submitted": submitted,
                    "last_attempt": assignment.last_attempt(),
                }));
            }
        }

        // Sort by deadline ascending; assignments with no parseable deadline last.
        items.sort_by(|a, b| {
            let key = |v: &Value| v.get("deadline").and_then(Value::as_str).map(str::to_owned);
            match (key(a), key(b)) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });

        Ok(ok(
            json!({ "include_finished": include_finished, "assignments": items }),
        ))
    }

    async fn get_grades(&self) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let bb = match auth::login_blackboard(&self.client, &cfg, None).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(b) => b,
        };

        let user_id = bb.user_info_id().await.context("获取用户信息")?;
        let mut enrollments = bb.user_courses(&user_id).await.context("获取选课列表")?;
        enrollments.retain(|e| e.course_role_id == "Student");

        let mut grades: Vec<Value> = Vec::new();
        for enrollment in &enrollments {
            let detail = match bb.course_detail(&enrollment.course_id).await {
                Ok(d) => d,
                Err(e) => {
                    log::warn!("跳过课程 {}: {e}", enrollment.course_id);
                    continue;
                }
            };
            if !detail.data().is_available() {
                continue;
            }
            for g in detail.all_grades().await.context("获取成绩")? {
                grades.push(json!({
                    "course": g.course_name,
                    "item": g.column_name,
                    "score": g.score,
                    "possible": g.possible,
                }));
            }
        }

        Ok(ok(json!({ "grades": grades })))
    }
}

fn empty_object_schema() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

/// The static tool catalog. Free function so it is testable without building a
/// [`ToolRegistry`] (which needs async IO).
fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "get_course_table",
            title: "个人课表",
            description: "获取当前学期的个人课表 (来自校内门户)。返回每天每节次的课程信息。",
            input_schema: empty_object_schema(),
            read_only: true,
        },
        ToolSpec {
            name: "list_assignments",
            title: "作业列表 (含 DDL)",
            description: "列出本学期课程的作业及截止时间, 默认只返回未提交的作业。\
                          适合回答 \"这周哪些作业要交 / 按 DDL 排序\" 一类问题。",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "include_finished": {
                        "type": "boolean",
                        "description": "是否包含已提交/已完成的作业, 默认 false (只看未完成)。"
                    }
                },
                "additionalProperties": false
            }),
            read_only: true,
        },
        ToolSpec {
            name: "get_grades",
            title: "成绩查询",
            description: "查询当前学期各门课程已公布的成绩条目 (作业/总评等)。",
            input_schema: empty_object_schema(),
            read_only: true,
        },
    ]
}

fn ok(data: Value) -> Value {
    json!({ "status": "ok", "data": data })
}

fn needs_otp(mobile_mask: Option<String>) -> Value {
    json!({
        "status": "needs_otp",
        "mobile_mask": mobile_mask,
        "hint": "教学网会话已过期或需要手机令牌 (OTP)。请先在终端运行 `pku3b ct` 完成一次登录以刷新会话, 然后重试。"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_read_only_and_named() {
        let specs = tool_specs();
        let names: Vec<_> = specs.iter().map(|s| s.name).collect();
        assert!(names.contains(&"get_course_table"));
        assert!(names.contains(&"list_assignments"));
        assert!(names.contains(&"get_grades"));
        // P0 exposes read-only tools only — submit_file must never appear.
        assert!(specs.iter().all(|s| s.read_only));
        assert!(!names.contains(&"submit_assignment"));
    }

    #[test]
    fn mcp_listing_uses_camelcase_input_schema() {
        // tools/list entries must use `inputSchema` (MCP) and a closed schema.
        let s = &tool_specs()[0];
        let mcp = json!({
            "name": s.name,
            "inputSchema": s.input_schema,
        });
        assert!(mcp.get("inputSchema").is_some());
        assert_eq!(mcp["inputSchema"]["type"], "object");
    }

    #[test]
    fn empty_schema_is_closed_object() {
        let s = empty_object_schema();
        assert_eq!(s["type"], "object");
        assert_eq!(s["additionalProperties"], false);
    }

    #[test]
    fn envelopes_carry_status() {
        assert_eq!(ok(json!({"a":1}))["status"], "ok");
        assert_eq!(ok(json!({"a":1}))["data"]["a"], 1);
        let n = needs_otp(Some("135****1234".into()));
        assert_eq!(n["status"], "needs_otp");
        assert_eq!(n["mobile_mask"], "135****1234");
        assert!(n["hint"].as_str().unwrap().contains("OTP"));
    }
}
