//! The MCP tool catalog (**Seam 1**) — the system's central seam.
//!
//! One catalog, two consumers (architecture decision #3): the stdio transport
//! drives it from JSON-RPC, and in-process tests call [`ToolRegistry::call`]
//! directly without any transport. The deterministic Python path calls these
//! same tools over MCP, never through the LLM.
//!
//! The interface is small — [`tool_specs`] + [`ToolRegistry::call`] — while the
//! implementation hides all of pku3b's `api::*` orchestration (build client, log
//! in, crawl, serialize). All data tools are read-only; the one side-effecting
//! API method (`CourseAssignment::submit_file`) is deliberately not exposed.
//! `login` is the only non-read-only tool (it establishes a session).
//!
//! ## Sessions / OTP
//! The HTTP client (and its cookie jar) lives for the whole `pku3b mcp` process,
//! so a single [`ToolRegistry::login`] with an OTP warms the session and every
//! later call reuses it — no per-call OTP. Course-table reuse is explicit: we
//! try the existing portal cookies first and only log in when they're stale.
//!
//! ## Result envelope
//! - `{"status":"ok","data": <payload>}`
//! - `{"status":"needs_otp","mobile_mask": <str|null>,"hint": <str>}`
//! - `{"status":"error","message": <str>}`

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
/// and dispatches tool calls. Credentials are read **lazily** so the server can
/// `initialize` and `tools/list` before the user has configured/authenticated.
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

    /// Persist the current cookie jar so the warmed session survives restarts.
    async fn save_session(&self) {
        if let Err(e) = self
            .client
            .save_set_cookies(utils::default_user_agent_data_path())
            .await
        {
            log::warn!("保存会话 cookie 失败: {e:#}");
        }
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
        let otp = args
            .get("otp")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let result = match name {
            "login" => self.login(otp).await,
            "get_course_table" => self.get_course_table(otp).await,
            "list_assignments" => {
                let include_finished = args
                    .get("include_finished")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.list_assignments(include_finished, otp).await
            }
            "get_grades" => self.get_grades(otp).await,
            other => return Err(ToolError::UnknownTool(other.to_string())),
        };
        result.map_err(|e| ToolError::Internal(format!("{e:#}")))
    }

    // ---- tool implementations (the hidden depth) --------------------------

    /// One-time login: connect the teaching-network session with a SINGLE OTP.
    /// The OTP is spent on the portal; the login also sends `remTrustChk=true`,
    /// which marks this device trusted, so Blackboard then logs in with **no
    /// second OTP**. After warming, the long-lived process reuses the session.
    async fn login(&self, otp: Option<&str>) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;

        // Reuse checks: portal is a plain data GET; Blackboard is verified by
        // listing courses — NOT a bb_homepage preflight, which 200s on an
        // unauthenticated guest page and would falsely report "connected".
        let portal_warm = self.portal_warm().await;
        let mut blackboard_ok = self.blackboard_courses_ok(&cfg).await;
        log::info!("[mcp] login: portal_warm={portal_warm} blackboard_warm={blackboard_ok}");

        // Already fully connected -> no OTP needed.
        if portal_warm && blackboard_ok {
            return Ok(ok(json!({ "portal": true, "blackboard": true })));
        }

        let Some(otp) = otp else {
            log::info!("[mcp] login: not fully connected and no OTP -> needs_otp");
            return Ok(needs_otp(None));
        };

        let mut portal_ok = portal_warm;
        if !portal_warm {
            // Spend the one OTP on the portal; this also trusts the device.
            portal_ok = matches!(
                auth::login_portal(&self.client, &cfg, Some(otp)).await,
                Ok(LoginOutcome::Ready(_))
            );
            log::info!("[mcp] login: portal login result={portal_ok}");
            if portal_ok {
                self.save_session().await;
            }
        }

        if !blackboard_ok {
            // Trusted device (from the portal login's remTrustChk) -> Blackboard
            // should log in with an EMPTY OTP. try_blackboard FORCES the login
            // (bypassing the unreliable bb_homepage preflight) and verifies.
            blackboard_ok = self.try_blackboard(&cfg, None).await;
            log::info!("[mcp] login: blackboard via trusted device (no OTP) = {blackboard_ok}");
            // Trust didn't carry AND the OTP is still unused (portal was already
            // warm) -> spend the fresh OTP directly on Blackboard.
            if !blackboard_ok && portal_warm {
                blackboard_ok = self.try_blackboard(&cfg, Some(otp)).await;
            }
        }
        if blackboard_ok {
            self.save_session().await;
        }
        log::info!("[mcp] login: result portal={portal_ok} blackboard={blackboard_ok}");

        if !portal_ok && !blackboard_ok {
            return Ok(json!({
                "status": "error",
                "message": "登录失败：请确认手机令牌 (OTP) 正确且未过期, 然后重试。"
            }));
        }
        Ok(ok(
            json!({ "portal": portal_ok, "blackboard": blackboard_ok }),
        ))
    }

    /// True if Blackboard is usable right now — verified by actually listing
    /// courses off the current session. This is the real auth signal: a bare
    /// `bb_homepage` GET 200s on an unauthenticated guest page (false positive),
    /// while `get_courses` fails unless genuinely logged in. Does not force a
    /// login, so it doubles as the OTP-free reuse check.
    async fn blackboard_courses_ok(&self, cfg: &config::Config) -> bool {
        match auth::login_blackboard(&self.client, cfg, None).await {
            Ok(LoginOutcome::Ready(bb)) => match bb.get_courses(true).await {
                Ok(courses) => {
                    log::info!(
                        "[mcp] blackboard verify: get_courses OK ({})",
                        courses.len()
                    );
                    true
                }
                Err(e) => {
                    log::info!("[mcp] blackboard verify: get_courses ERR: {e:#}");
                    false
                }
            },
            _ => {
                log::info!("[mcp] blackboard verify: not authorized (needs login)");
                false
            }
        }
    }

    /// True if the portal session is usable right now (reuses cookies, no login).
    async fn portal_warm(&self) -> bool {
        match self.client.portal_my_course_table_get("", "").await {
            Ok(raw) => {
                let parsed = serde_json::from_str::<Value>(&raw).ok();
                let warm = parsed
                    .as_ref()
                    .is_some_and(|v| v.get("course").is_some() || v.get("nowXnxq").is_some());
                if warm {
                    log::info!("[mcp] portal_warm: HIT (reused session)");
                } else {
                    let snip: String = raw.chars().take(120).collect();
                    log::info!(
                        "[mcp] portal_warm: MISS (len={}, snippet={snip:?})",
                        raw.len()
                    );
                }
                warm
            }
            Err(e) => {
                log::info!("[mcp] portal_warm: MISS (request error: {e:#})");
                false
            }
        }
    }

    /// Force a fresh Blackboard IAAA login, then verify by listing courses.
    ///
    /// We must NOT go through `Client::blackboard` for the login: its
    /// `bb_homepage` preflight returns Ok on an unauthenticated course.pku.edu.cn
    /// guest page, which silently skips `bb_login`. So we call `bb_login`
    /// directly. `otp = None` sends an EMPTY OTP — relying on a trusted device
    /// (the portal login's `remTrustChk`); `otp = Some(..)` spends a fresh OTP.
    async fn try_blackboard(&self, cfg: &config::Config, otp: Option<&str>) -> bool {
        match self
            .client
            .bb_login(&cfg.username, &cfg.password, otp.unwrap_or(""))
            .await
        {
            Ok(()) => {
                log::info!(
                    "[mcp] try_blackboard: bb_login OK (with_otp={})",
                    otp.is_some()
                );
                self.save_session().await;
            }
            Err(e) => {
                log::info!(
                    "[mcp] try_blackboard: bb_login ERR (with_otp={}): {e:#}",
                    otp.is_some()
                );
                return false;
            }
        }
        // Verify the session actually works by listing courses.
        self.blackboard_courses_ok(cfg).await
    }

    async fn get_course_table(&self, otp: Option<&str>) -> anyhow::Result<Value> {
        // 1. Reuse an existing (warm) portal session — no login, no OTP.
        if let Ok(raw) = self.client.portal_my_course_table_get("", "").await
            && let Ok(v) = serde_json::from_str::<Value>(&raw)
            && (v.get("course").is_some() || v.get("nowXnxq").is_some())
        {
            return Ok(ok(v));
        }
        // 2. Cold / expired -> log in (needs OTP for a 2FA account).
        let cfg = self.cfg().await?;
        match auth::login_portal(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(portal) => {
                self.save_session().await;
                let raw = portal.get_my_course_table().await.context("获取课表")?;
                let data = serde_json::from_str::<Value>(&raw).unwrap_or(Value::String(raw));
                Ok(ok(data))
            }
        }
    }

    async fn list_assignments(
        &self,
        include_finished: bool,
        otp: Option<&str>,
    ) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let bb = match auth::login_blackboard(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(b) => b,
        };
        self.save_session().await;

        let handles = match bb.get_courses(true).await {
            Ok(h) => h,
            // "courses not found" almost always means the Blackboard session
            // isn't actually valid (cold preflight) -> ask the user to log in.
            Err(e) => {
                log::warn!("获取课程列表失败: {e:#}");
                return Ok(needs_otp(None));
            }
        };

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

    async fn get_grades(&self, otp: Option<&str>) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let bb = match auth::login_blackboard(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(b) => b,
        };
        self.save_session().await;

        let user_id = match bb.user_info_id().await {
            Ok(id) => id,
            Err(e) => {
                log::warn!("获取用户信息失败: {e:#}");
                return Ok(needs_otp(None));
            }
        };
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

/// Schema for a data tool: an optional `otp` (usually omitted after `login`).
fn otp_optional_schema(extra: Value) -> Value {
    let mut props = json!({
        "otp": {
            "type": "string",
            "description": "手机令牌 (OTP); 一般先用 login 登录后此处可省略。"
        }
    });
    if let (Some(props), Some(extra)) = (props.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            props.insert(k.clone(), v.clone());
        }
    }
    json!({ "type": "object", "properties": props, "additionalProperties": false })
}

/// The static tool catalog. Free function so it is testable without building a
/// [`ToolRegistry`] (which needs async IO).
fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "login",
            title: "登录教学网",
            description: "用手机令牌 (OTP) 登录教学网。一个 OTP 只能登录一个服务: \
                          门户(课表)优先登录; 若作业/成绩 (Blackboard) 未连接, \
                          用一个新的 OTP 再调用一次即可。登录后本次运行内查询无需再输 OTP。\
                          OTP 必须由用户提供, 不要自行编造。",
            input_schema: json!({
                "type": "object",
                "properties": { "otp": { "type": "string", "description": "手机令牌 (OTP) 6 位码" } },
                "required": ["otp"],
                "additionalProperties": false
            }),
            read_only: false,
        },
        ToolSpec {
            name: "get_course_table",
            title: "个人课表",
            description: "获取当前学期的个人课表 (来自校内门户)。返回每天每节次的课程信息。",
            input_schema: otp_optional_schema(json!({})),
            read_only: true,
        },
        ToolSpec {
            name: "list_assignments",
            title: "作业列表 (含 DDL)",
            description: "列出本学期课程的作业及截止时间, 默认只返回未提交的作业。\
                          适合回答 \"这周哪些作业要交 / 按 DDL 排序\" 一类问题。",
            input_schema: otp_optional_schema(json!({
                "include_finished": {
                    "type": "boolean",
                    "description": "是否包含已提交/已完成的作业, 默认 false (只看未完成)。"
                }
            })),
            read_only: true,
        },
        ToolSpec {
            name: "get_grades",
            title: "成绩查询",
            description: "查询当前学期各门课程已公布的成绩条目 (作业/总评等)。",
            input_schema: otp_optional_schema(json!({})),
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
        "hint": "需要登录教学网。请用手机令牌 (OTP) 登录一次 (网页端登录入口 / login 工具), 之后无需重复输入。"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_named_and_login_is_only_non_read_only() {
        let specs = tool_specs();
        let names: Vec<_> = specs.iter().map(|s| s.name).collect();
        assert!(names.contains(&"login"));
        assert!(names.contains(&"get_course_table"));
        assert!(names.contains(&"list_assignments"));
        assert!(names.contains(&"get_grades"));
        // Data tools are read-only; `login` is the only stateful one.
        for s in &specs {
            assert_eq!(
                s.read_only,
                s.name != "login",
                "read_only wrong for {}",
                s.name
            );
        }
        // No write/side-effecting data tool is exposed.
        assert!(!names.contains(&"submit_assignment"));
    }

    #[test]
    fn data_tools_accept_optional_otp() {
        let s = otp_optional_schema(json!({}));
        assert_eq!(s["type"], "object");
        assert_eq!(s["additionalProperties"], false);
        assert!(s["properties"]["otp"].is_object());
    }

    #[test]
    fn assignments_schema_merges_extra_props() {
        let s = otp_optional_schema(json!({"include_finished": {"type": "boolean"}}));
        assert!(s["properties"]["otp"].is_object());
        assert!(s["properties"]["include_finished"].is_object());
    }

    #[test]
    fn login_requires_otp_in_schema() {
        let login = tool_specs()
            .into_iter()
            .find(|s| s.name == "login")
            .unwrap();
        assert_eq!(login.input_schema["required"][0], "otp");
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
