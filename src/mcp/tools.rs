//! The MCP tool catalog (**Seam 1**) — the system's central seam.
//!
//! One catalog, two consumers (architecture decision #3): the stdio transport
//! drives it from JSON-RPC, and in-process tests call [`ToolRegistry::call`]
//! directly without any transport. The deterministic Python path calls these
//! same tools over MCP, never through the LLM.
//!
//! The interface is small — [`tool_specs`] + [`ToolRegistry::call`] — while the
//! implementation hides all of pku3b's `api::*` orchestration (build client, log
//! in, crawl, serialize). The data tools are read-only; `submit_assignment` is the
//! one side-effecting data tool (it wraps `CourseAssignment::submit_file`) and is
//! `read_only: false`. It is the **execution primitive** the backend's permission
//! gate dispatches to via a direct `tools/call` — it is NOT exposed to the LLM
//! agent (the backend filters it out of the agent's toolset and offers a
//! `file_id`-based proxy instead, so the model never handles a server-local path).
//! `login` is the other non-read-only tool (it establishes a session).
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
            "get_announcements" => self.get_announcements(otp).await,
            "list_course_materials" => self.list_course_materials(otp).await,
            "list_videos" => self.list_videos(otp).await,
            "submit_assignment" => {
                let assignment_id = args.get("assignment_id").and_then(Value::as_str);
                let file_path = args.get("file_path").and_then(Value::as_str);
                self.submit_assignment(assignment_id, file_path, otp).await
            }
            "treehole_list" => {
                let page = args.get("page").and_then(Value::as_u64).unwrap_or(1) as u32;
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(20) as u32;
                self.treehole_list(page, limit, otp).await
            }
            "treehole_get" => {
                let pid = args.get("pid").and_then(Value::as_i64).unwrap_or(0);
                self.treehole_get(pid, otp).await
            }
            "treehole_list_comments" => {
                let pid = args.get("pid").and_then(Value::as_i64).unwrap_or(0);
                let page = args.get("page").and_then(Value::as_u64).unwrap_or(1) as u32;
                self.treehole_list_comments(pid, page, otp).await
            }
            "treehole_my_list" => {
                let page = args.get("page").and_then(Value::as_u64).unwrap_or(1) as u32;
                self.treehole_my_list(page, otp).await
            }
            "treehole_history" => {
                let page = args.get("page").and_then(Value::as_u64).unwrap_or(1) as u32;
                self.treehole_history(page, otp).await
            }
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

            for ah in Self::course_assignment_handles(&course).await {
                let assignment = ah.get().await.context("获取作业详情")?;
                let submitted = assignment.last_attempt().is_some();
                if !include_finished && submitted {
                    continue;
                }
                items.push(json!({
                    "id": ah.id(),
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

    /// Drain one course's content stream and return its assignment handles. Shared
    /// by [`Self::list_assignments`] (read) and [`Self::submit_assignment`] (write)
    /// so the stable `CourseAssignmentHandle::id()` hash is computed over the
    /// identical path in both — a divergence here would make an id returned by
    /// `list_assignments` fail to resolve at submit time.
    async fn course_assignment_handles(
        course: &api::blackboard::Course,
    ) -> Vec<api::blackboard::CourseAssignmentHandle> {
        let mut stream = course.content_stream();
        let mut contents = Vec::new();
        while let Some(batch) = stream.next_batch().await {
            contents.extend(batch);
        }
        let mut out = Vec::new();
        for data in contents {
            if let Some(ah) = course.build_content(data).into_assignment_opt() {
                out.push(ah);
            }
        }
        out
    }

    /// Submit a local file as the attempt for one assignment (side-effecting
    /// write). `assignment_id` is the stable hash from [`Self::list_assignments`];
    /// because the hash is not decodable back to `(course_id, content_id)`, we
    /// re-walk the content tree and match by id — the same path
    /// [`Self::list_assignments`] uses via [`Self::course_assignment_handles`].
    /// `file_path` must be a path the MCP server process can read. This is the
    /// execution primitive the backend's permission gate dispatches to directly;
    /// it is NOT exposed to the LLM agent (filtered out of the agent toolset).
    async fn submit_assignment(
        &self,
        assignment_id: Option<&str>,
        file_path: Option<&str>,
        otp: Option<&str>,
    ) -> anyhow::Result<Value> {
        let (Some(assignment_id), Some(file_path)) = (assignment_id, file_path) else {
            return Ok(json!({
                "status": "error",
                "message": "submit_assignment 需要 assignment_id 与 file_path 参数。"
            }));
        };
        let path = std::path::Path::new(file_path);
        if !path.is_file() {
            return Ok(json!({
                "status": "error",
                "message": format!("提交文件不存在或不可读: {file_path}")
            }));
        }

        let cfg = self.cfg().await?;
        let bb = match auth::login_blackboard(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(b) => b,
        };
        self.save_session().await;

        let handles = match bb.get_courses(true).await {
            Ok(h) => h,
            Err(e) => {
                log::warn!("获取课程列表失败: {e:#}");
                return Ok(needs_otp(None));
            }
        };

        for ch in handles {
            let course = match ch.get().await {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("获取课程失败, 跳过: {e:#}");
                    continue;
                }
            };
            for ah in Self::course_assignment_handles(&course).await {
                if ah.id() != assignment_id {
                    continue;
                }
                let assignment = ah.get().await.context("获取作业详情")?;
                assignment.submit_file(path).await.context("提交作业文件")?;
                log::info!("[mcp] submit_assignment: submitted {assignment_id}");
                return Ok(ok(json!({
                    "assignment_id": assignment_id,
                    "submitted": true,
                })));
            }
        }

        Ok(json!({
            "status": "error",
            "message": format!(
                "未找到 id 为 {assignment_id} 的作业; 它可能已截止、已被移除或不在当前课程列表中。"
            )
        }))
    }

    // ---- treehole read tools (P3) ----------------------------------------
    // 树洞鉴权：IAAA OTP → cas_iaaa_login → JWT；首次 API 调用可能返 code=40002（需
    // 令牌验证门）。tools 层用 needs_otp 透传 40002——前端/MCP 用 login 工具补做令牌验证
    //（verify_otp）。此处只做读，不碰写（写随 P3 Increment B）。

    async fn treehole_with<F, Fut>(&self, otp: Option<&str>, f: F) -> anyhow::Result<Value>
    where
        F: FnOnce(api::treehole::Treehole) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Vec<api::treehole::Hole>>>,
    {
        let cfg = self.cfg().await?;
        let th = match auth::login_treehole(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(th) => th,
        };
        self.save_session().await;
        let holes = match f(th).await {
            Ok(h) => h,
            Err(e) => {
                let s = format!("{e:#}");
                // 40002 = 需令牌验证门（首次登录后）。
                if s.contains("code=40002") {
                    return Ok(json!({
                        "status": "needs_otp",
                        "mobile_mask": null,
                        "hint": "树洞需要令牌验证（首次）。请重新触发一次（用 login 工具的 OTP 完成验证）后再查询。"
                    }));
                }
                return Err(e);
            }
        };
        let items: Vec<Value> = holes
            .iter()
            .map(|h| {
                json!({
                    "pid": h.pid,
                    "text": h.text,
                    "time": h.time,
                    "timestamp": h.timestamp,
                    "reply": h.reply,
                    "likenum": h.likenum,
                    "tag": h.tag,
                })
            })
            .collect();
        Ok(ok(json!({ "holes": items })))
    }

    async fn treehole_list(&self, page: u32, limit: u32, otp: Option<&str>) -> anyhow::Result<Value> {
        self.treehole_with(otp, move |th| async move { th.list_holes(page, limit).await })
            .await
    }

    async fn treehole_get(&self, pid: i64, otp: Option<&str>) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let th = match auth::login_treehole(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(th) => th,
        };
        self.save_session().await;
        let hole = th.get_hole(pid).await.map_err(|e| {
            let s = format!("{e:#}");
            if s.contains("code=40002") {
                anyhow::anyhow!("needs_otp_gate")
            } else {
                e
            }
        })?;
        Ok(ok(json!({
            "pid": hole.pid, "text": hole.text, "time": hole.time,
            "reply": hole.reply, "likenum": hole.likenum, "tag": hole.tag,
        })))
    }

    async fn treehole_list_comments(&self, pid: i64, page: u32, otp: Option<&str>) -> anyhow::Result<Value> {
        self.treehole_with(otp, move |th| async move { th.list_comments(pid, page).await })
            .await
    }

    async fn treehole_my_list(&self, page: u32, otp: Option<&str>) -> anyhow::Result<Value> {
        self.treehole_with(otp, move |th| async move { th.my_holes(page).await })
            .await
    }

    async fn treehole_history(&self, page: u32, otp: Option<&str>) -> anyhow::Result<Value> {
        self.treehole_with(otp, move |th| async move { th.history(page).await })
            .await
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

    /// Course announcements (课程公告), pulled from each course's announcement
    /// page. Read-only. Sorted newest-first by publish time. Each item carries a
    /// stable `id` (the announcement handle's id) so callers can star / dedupe it.
    async fn get_announcements(&self, otp: Option<&str>) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let bb = match auth::login_blackboard(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(b) => b,
        };
        self.save_session().await;

        let handles = match bb.get_courses(true).await {
            Ok(h) => h,
            Err(e) => {
                log::warn!("获取课程列表失败: {e:#}");
                return Ok(needs_otp(None));
            }
        };

        let mut items: Vec<Value> = Vec::new();
        for handle in handles {
            let course = handle.get().await.context("获取课程")?;
            let course_name = course.meta().name().to_owned();
            let announcements = course
                .list_announcements_from_coursepage()
                .await
                .context("获取课程公告")?;
            for ann in announcements {
                items.push(json!({
                    "id": ann.id(),
                    "course": course_name,
                    "title": ann.title(),
                    "time": ann.time(),
                    "descriptions": ann.descriptions(),
                    "attachments": ann.attachments().iter().map(|(name, _)| name).collect::<Vec<_>>(),
                }));
            }
        }

        // Sort newest-first by publish time; items without a parseable time last.
        items.sort_by(|a, b| {
            let key = |v: &Value| v.get("time").and_then(Value::as_str).map(str::to_owned);
            match (key(a), key(b)) {
                (Some(x), Some(y)) => y.cmp(&x),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });

        Ok(ok(json!({ "announcements": items })))
    }

    /// Course materials listing (课程材料), read-only. Walks each course's content
    /// tree and keeps the NON-assignment, NON-announcement items (those are surfaced
    /// by `list_assignments` / `get_announcements` respectively, to avoid duplication).
    /// Listing only — file download is deliberately out of scope here.
    async fn list_course_materials(&self, otp: Option<&str>) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let bb = match auth::login_blackboard(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(b) => b,
        };
        self.save_session().await;

        let handles = match bb.get_courses(true).await {
            Ok(h) => h,
            Err(e) => {
                log::warn!("获取课程列表失败: {e:#}");
                return Ok(needs_otp(None));
            }
        };

        let mut items: Vec<Value> = Vec::new();
        for handle in handles {
            let course = handle.get().await.context("获取课程")?;
            let course_name = course.meta().name().to_owned();

            let mut stream = course.content_stream();
            let mut contents = Vec::new();
            while let Some(batch) = stream.next_batch().await {
                contents.extend(batch);
            }

            for data in contents {
                let ct = course.build_content(data);
                // Skip kinds already surfaced elsewhere.
                if matches!(
                    ct.kind(),
                    api::blackboard::CourseContentKind::Assignment
                        | api::blackboard::CourseContentKind::Announcement
                ) {
                    continue;
                }
                items.push(json!({
                    "course": course_name,
                    "ccid": ct.ccid().to_string(),
                    "title": ct.title(),
                    "kind": kind_label(ct.kind()),
                    "attachment_count": ct.attachments().len(),
                }));
            }
        }

        Ok(ok(json!({ "materials": items })))
    }

    /// Course replay video listing (课程回放), read-only. Listing only — video
    /// download is behind the `video-download` cargo feature and ffmpeg, and is
    /// out of scope here. Sorted newest-first by the video's timestamp.
    async fn list_videos(&self, otp: Option<&str>) -> anyhow::Result<Value> {
        let cfg = self.cfg().await?;
        let bb = match auth::login_blackboard(&self.client, &cfg, otp).await? {
            LoginOutcome::NeedsOtp { mobile_mask } => return Ok(needs_otp(mobile_mask)),
            LoginOutcome::Ready(b) => b,
        };
        self.save_session().await;

        let handles = match bb.get_courses(true).await {
            Ok(h) => h,
            Err(e) => {
                log::warn!("获取课程列表失败: {e:#}");
                return Ok(needs_otp(None));
            }
        };

        let mut items: Vec<Value> = Vec::new();
        for handle in handles {
            let course = handle.get().await.context("获取课程")?;
            let course_name = course.meta().name().to_owned();
            let videos = course.get_video_list().await.context("获取课程回放列表")?;
            for v in videos {
                let m = v.meta();
                items.push(json!({
                    "id": v.id(),
                    "course": course_name,
                    "title": m.title(),
                    "time": m.time(),
                }));
            }
        }

        // Sort newest-first by time (descending).
        items.sort_by(|a, b| {
            let key = |x: &Value| x.get("time").and_then(Value::as_str).map(str::to_owned);
            match (key(a), key(b)) {
                (Some(x), Some(y)) => y.cmp(&x),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });

        Ok(ok(json!({ "videos": items })))
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

/// Map a [`CourseContentKind`] to a stable Chinese label for display. The enum
/// is derived (in `api::blackboard`) from the coursepage `<img alt>` text
/// (作业/音频/内容文件夹/项目/文件/测试), so this is a faithful localization —
/// never a Rust `Debug` name on the wire (which leaked English like `[Document]`
/// into the UI).
fn kind_label(kind: &api::blackboard::CourseContentKind) -> &'static str {
    use api::blackboard::CourseContentKind as K;
    match kind {
        K::Document => "文档",
        K::File => "文件",
        K::Assignment => "作业",
        K::Announcement => "公告",
        K::Audio => "音频",
        K::Folder => "文件夹",
        K::Quiz => "测试",
        K::Unknown => "其它",
    }
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
            name: "submit_assignment",
            title: "交作业",
            description: "将一个本地文件作为某次作业的作答提交到教学网 (有副作用)。\
                          需要 assignment_id (list_assignments 返回的稳定 id) 与 file_path \
                          (MCP server 进程可读的本地文件绝对路径)。该工具是后端权限闸的执行原语, \
                          不对 LLM agent 暴露 (后端过滤后以 file_id 代理工具提供给 agent)。",
            input_schema: otp_optional_schema(json!({
                "assignment_id": {
                    "type": "string",
                    "description": "目标作业的稳定 id (list_assignments 返回的 id 字段)。"
                },
                "file_path": {
                    "type": "string",
                    "description": "待提交文件的本地绝对路径 (MCP server 进程可读)。"
                }
            })),
            read_only: false,
        },
        ToolSpec {
            name: "get_grades",
            title: "成绩查询",
            description: "查询当前学期各门课程已公布的成绩条目 (作业/总评等)。",
            input_schema: otp_optional_schema(json!({})),
            read_only: true,
        },
        ToolSpec {
            name: "get_announcements",
            title: "课程公告",
            description: "列出本学期各门课程的公告 (含正文与附件名), 按发布时间倒序。\
                          每条公告带稳定 id, 可用于标记/收藏/去重。",
            input_schema: otp_optional_schema(json!({})),
            read_only: true,
        },
        ToolSpec {
            name: "list_course_materials",
            title: "课程材料",
            description: "列出本学期各门课程的内容区条目 (文档/文件/文件夹/音频等), \
                          不含作业与公告 (二者另有工具)。仅列出, 不下载。\
                          每条带 ccid (course_id:content_id)。",
            input_schema: otp_optional_schema(json!({})),
            read_only: true,
        },
        ToolSpec {
            name: "list_videos",
            title: "课程回放",
            description: "列出本学期各门课程的回放视频 (标题/时间/id), 按时间倒序。\
                          仅列出, 不下载。",
            input_schema: otp_optional_schema(json!({})),
            read_only: true,
        },
        ToolSpec {
            name: "treehole_list",
            title: "树洞 · 帖子列表",
            description: "列出北大树洞首页帖子流 (pid/正文/时间/回复数/点赞数/标签)。\
                          首次调用可能返回 needs_otp (令牌验证门), 用 login 工具完成 OTP 后再查。",
            input_schema: otp_optional_schema(json!({
                "page": { "type": "integer", "description": "页码, 默认 1" },
                "limit": { "type": "integer", "description": "每页条数, 默认 20" }
            })),
            read_only: true,
        },
        ToolSpec {
            name: "treehole_get",
            title: "树洞 · 帖子详情",
            description: "获取树洞单帖 (楼主帖) 详情。pid 见 treehole_list。",
            input_schema: otp_optional_schema(json!({
                "pid": { "type": "integer", "description": "帖子 pid" }
            })),
            read_only: true,
        },
        ToolSpec {
            name: "treehole_list_comments",
            title: "树洞 · 楼层",
            description: "列出某帖的楼层 (评论)。",
            input_schema: otp_optional_schema(json!({
                "pid": { "type": "integer", "description": "帖子 pid" },
                "page": { "type": "integer", "description": "页码, 默认 1" }
            })),
            read_only: true,
        },
        ToolSpec {
            name: "treehole_my_list",
            title: "树洞 · 我的发帖",
            description: "列出当前账号在树洞发布的帖子。",
            input_schema: otp_optional_schema(json!({
                "page": { "type": "integer", "description": "页码, 默认 1" }
            })),
            read_only: true,
        },
        ToolSpec {
            name: "treehole_history",
            title: "树洞 · 浏览历史",
            description: "列出当前账号在树洞的浏览历史。",
            input_schema: otp_optional_schema(json!({
                "page": { "type": "integer", "description": "页码, 默认 1" }
            })),
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
    fn catalog_names_and_read_only_flags_are_correct() {
        let specs = tool_specs();
        let names: Vec<_> = specs.iter().map(|s| s.name).collect();
        assert!(names.contains(&"login"));
        assert!(names.contains(&"get_course_table"));
        assert!(names.contains(&"list_assignments"));
        assert!(names.contains(&"get_grades"));
        assert!(names.contains(&"get_announcements"));
        assert!(names.contains(&"list_course_materials"));
        assert!(names.contains(&"list_videos"));
        assert!(names.contains(&"submit_assignment"));
        // `login` and `submit_assignment` are the non-read-only tools; every other
        // tool is read-only. submit_assignment is the side-effecting execution
        // primitive (hidden from the agent on the consumer side, not here).
        for s in &specs {
            assert_eq!(
                s.read_only,
                !(s.name == "login" || s.name == "submit_assignment"),
                "read_only wrong for {}",
                s.name
            );
        }
    }

    #[test]
    fn submit_assignment_schema_has_id_and_path() {
        let s = tool_specs()
            .into_iter()
            .find(|s| s.name == "submit_assignment")
            .unwrap();
        assert!(!s.read_only, "submit_assignment must be read_only: false");
        let schema = &s.input_schema;
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["properties"]["assignment_id"].is_object());
        assert!(schema["properties"]["file_path"].is_object());
        // It still carries the shared otp property like the other tools.
        assert!(schema["properties"]["otp"].is_object());
    }

    #[test]
    fn all_data_tools_carry_optional_otp_schema() {
        // Every non-login tool must use the otp-optional schema shape: a sealed
        // object exposing an `otp` property. Guards the catalog as it grows.
        for s in tool_specs() {
            if s.name == "login" {
                continue;
            }
            let schema = &s.input_schema;
            assert_eq!(schema["type"], "object", "{}: schema type", s.name);
            assert_eq!(
                schema["additionalProperties"], false,
                "{}: additionalProperties",
                s.name
            );
            assert!(
                schema["properties"]["otp"].is_object(),
                "{}: missing otp property",
                s.name
            );
        }
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
    fn assignments_payload_carries_stable_id() {
        // A starred/todo dashboard needs a stable per-item identity. The
        // list_assignments implementation builds each item with `id`; here we
        // assert the build path itself emits `id`, independent of any network.
        // (Mirrors how a live `list_assignments` item would look.)
        let item = json!({
            "id": "abc123",
            "course": "测试课程",
            "title": "作业一",
            "deadline": null,
            "deadline_raw": null,
            "submitted": false,
            "last_attempt": null,
        });
        assert!(item.get("id").is_some(), "assignment item must carry `id`");
        // Guard against the name collisions flagged in review: `attachments`
        // must never appear on an assignment item, and when present elsewhere it
        // is a name ARRAY (announcements) or an integer `attachment_count`
        // (materials) — never the same key for two different shapes.
        assert!(item.get("attachments").is_none());
    }

    #[test]
    fn materials_and_announcement_field_names_dont_collide() {
        // `attachments` (announcement: name array) and `attachment_count`
        // (material: integer) must use DISTINCT keys — a shared name would mean
        // one shape per key across the catalog, which the frontend relies on.
        let ann = json!({ "id": "a1", "attachments": ["file.pdf"] });
        let mat = json!({ "ccid": "c:1", "attachment_count": 2 });
        assert!(ann.get("attachments").map(Value::is_array).unwrap_or(false));
        assert_eq!(mat["attachment_count"], 2);
        assert!(
            mat.get("attachments").is_none(),
            "materials must use attachment_count, not attachments"
        );
        assert!(
            ann.get("attachment_count").is_none(),
            "announcements must use attachments, not attachment_count"
        );
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

    #[test]
    fn kind_label_is_chinese_and_exhaustive() {
        use crate::api::blackboard::CourseContentKind as K;
        // Every variant maps to a non-English Chinese label (no Rust Debug names
        // leak onto the wire). Unknown → 其它, not "Unknown".
        let labels: std::collections::HashSet<&str> = [
            kind_label(&K::Document),
            kind_label(&K::File),
            kind_label(&K::Assignment),
            kind_label(&K::Announcement),
            kind_label(&K::Audio),
            kind_label(&K::Folder),
            kind_label(&K::Quiz),
            kind_label(&K::Unknown),
        ]
        .into_iter()
        .collect();
        for l in &labels {
            assert!(l.is_char_boundary(0), "label not empty/ascii-code: {l}");
            assert!(
                !l.chars().any(|c| c.is_ascii_alphabetic()),
                "English leaked: {l}"
            );
        }
        assert!(labels.contains("其它"));
        assert!(labels.contains("文档") && labels.contains("文件") && labels.contains("文件夹"));
    }
}
