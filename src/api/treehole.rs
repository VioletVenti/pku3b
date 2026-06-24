//! 北大树洞服务层（PKU Helper app 生态）。
//!
//! 鉴权模型见 [`crate::api::low_level::treehole`]：IAAA OTP → cas_iaaa_login →
//! `/web/iaaa_success` 签发 Bearer JWT；API 带 `Authorization: Bearer <JWT>` +
//! `uuid` + `userAgent:pku_web` 头。首次登录后 API 返 code=40002，需走令牌验证门
//!（[`Treehole::verify_otp`]）。详见 memory `myal1s-p3-treehole-protocol`。

use crate::api::low_level::treehole::TreeholeSession;

use super::*;

impl Client {
    /// 登录树洞（IAAA OTP → cas_iaaa_login → iaaa_success JWT）。
    pub async fn treehole(
        &self,
        username: &str,
        password: &str,
        otp_code: &str,
    ) -> anyhow::Result<Treehole> {
        let session = self
            .0
            .http_client
            .treehole_login(username, password, otp_code)
            .await?;
        log::info!(
            "[treehole] logged in (uuid={}…, jwt={})",
            &session.uuid.get(..40).unwrap_or(&session.uuid),
            session.access_token.is_some()
        );
        Ok(Treehole {
            client: self.clone(),
            session,
        })
    }
}

/// 树洞服务句柄。
#[derive(Debug, Clone)]
pub struct Treehole {
    client: Client,
    session: TreeholeSession,
}

/// 一次「洞」（帖子）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct Hole {
    pub pid: i64,
    pub text: String,
    pub timestamp: i64,
    pub reply: i64,
    pub likenum: i64,
    pub tag: Option<String>,
    /// 时间戳 → RFC3339（前端格式化用）。
    pub time: Option<String>,
}

/// 统一的 v3 响应信封。
#[derive(Debug, serde::Deserialize)]
struct V3Envelope<T> {
    code: i64,
    data: Option<T>,
    #[allow(dead_code)]
    success: bool,
    message: Option<String>,
}
const CODE_OK: i64 = 20000;
/// 需令牌验证（首次登录后的门）。
pub const CODE_NEED_OTP: i64 = 40002;

impl Treehole {
    /// GET 一个 v3 端点，解析信封，code==20000 时返回 data；否则把 code/message 透传
    /// 为错误（含 CODE_NEED_OTP=40002，调用方据此触发令牌验证）。
    async fn get_v3<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let body = self
            .client
            .0
            .http_client
            .treehole_api_get(&self.session, path)
            .await?;
        let env: V3Envelope<T> = serde_json::from_str(&body).map_err(|e| {
            anyhow::anyhow!(
                "解析树洞响应失败: {e}; body[:200]={}",
                body.chars().take(200).collect::<String>()
            )
        })?;
        if env.code == CODE_OK {
            return env
                .data
                .ok_or_else(|| anyhow::anyhow!("树洞返回空 data（message={:?}）", env.message));
        }
        Err(anyhow::anyhow!(
            "树洞 code={} message={:?}（path={path}）",
            env.code,
            env.message.unwrap_or_default()
        ))
    }

    /// 帖子列表（首页流）。JSON 形如 `{list:[{pid,text,timestamp,reply,likenum,tag,...}]}`。
    pub async fn list_holes(&self, page: u32, limit: u32) -> anyhow::Result<Vec<Hole>> {
        #[derive(serde::Deserialize)]
        struct D {
            list: Vec<RawHole>,
        }
        let path = format!("/api/v3/hole/list?page={page}&limit={limit}");
        let d: D = self.get_v3(&path).await?;
        Ok(d.list.into_iter().map(raw_to_hole).collect())
    }

    /// 单帖详情（楼主帖）。
    pub async fn get_hole(&self, pid: i64) -> anyhow::Result<Hole> {
        let path = format!("/api/v3/hole/get?pid={pid}");
        let raw: RawHole = self.get_v3(&path).await?;
        Ok(raw_to_hole(raw))
    }

    /// 楼层（评论）列表。
    pub async fn list_comments(&self, pid: i64, page: u32) -> anyhow::Result<Vec<Hole>> {
        #[derive(serde::Deserialize)]
        struct D {
            list: Vec<RawHole>,
        }
        let path = format!(
            "/api/v3/hole/list_comments?page={page}&limit=10&comment_limit=20&comment_stream=1&pid={pid}"
        );
        let d: D = self.get_v3(&path).await?;
        Ok(d.list.into_iter().map(raw_to_hole).collect())
    }

    /// 我的发帖。
    pub async fn my_holes(&self, page: u32) -> anyhow::Result<Vec<Hole>> {
        #[derive(serde::Deserialize)]
        struct D {
            list: Vec<RawHole>,
        }
        let path = format!("/api/v3/hole/my_list?page={page}&limit=20");
        let d: D = self.get_v3(&path).await?;
        Ok(d.list.into_iter().map(raw_to_hole).collect())
    }

    /// 浏览历史。
    pub async fn history(&self, page: u32) -> anyhow::Result<Vec<Hole>> {
        #[derive(serde::Deserialize)]
        struct D {
            list: Vec<RawHole>,
        }
        let path = format!("/api/v3/hole/history?page={page}&limit=20");
        let d: D = self.get_v3(&path).await?;
        Ok(d.list.into_iter().map(raw_to_hole).collect())
    }

    /// 关注的帖子列表。
    pub async fn attention(&self, page: u32) -> anyhow::Result<Vec<Hole>> {
        #[derive(serde::Deserialize)]
        struct D {
            list: Vec<RawHole>,
        }
        let path = format!("/api/v3/hole/attention?page={page}&limit=20");
        let d: D = self.get_v3(&path).await?;
        Ok(d.list.into_iter().map(raw_to_hole).collect())
    }

    /// 关键词搜索帖子（hole/list?keyword=…）。实测 401（路由存在，需鉴权）。
    pub async fn search(&self, keyword: &str, page: u32, limit: u32) -> anyhow::Result<Vec<Hole>> {
        #[derive(serde::Deserialize)]
        struct D {
            list: Vec<RawHole>,
        }
        let kw = percent_encoding::utf8_percent_encode(keyword, percent_encoding::NON_ALPHANUMERIC);
        let path = format!("/api/v3/hole/list?keyword={kw}&page={page}&limit={limit}");
        let d: D = self.get_v3(&path).await?;
        Ok(d.list.into_iter().map(raw_to_hole).collect())
    }

    /// 未读消息计数。message_type: "int_msg"（关注帖子更新）/ "sys_msg"（系统）。
    pub async fn unread_count(&self, message_type: &str) -> anyhow::Result<i64> {
        #[derive(serde::Deserialize)]
        struct D {
            count: i64,
        }
        let path = format!("/api/v3/message/un_read?message_type={message_type}");
        let d: D = self.get_v3(&path).await?;
        Ok(d.count)
    }

    /// 消息列表（通知——关注帖子的新回复等）。
    pub async fn messages(&self, message_type: &str, page: u32) -> anyhow::Result<Vec<TreeholeMessage>> {
        #[derive(serde::Deserialize)]
        struct D {
            list: Vec<RawMessage>,
        }
        let path = format!("/api/v3/message/index?message_type={message_type}&page={page}&limit=20");
        let d: D = self.get_v3(&path).await?;
        Ok(d.list.into_iter().map(RawMessage::into_msg).collect())
    }

    /// 收藏夹列表。
    pub async fn bookmarks(&self) -> anyhow::Result<Vec<TreeholeBookmark>> {
        #[derive(serde::Deserialize)]
        struct D {
            list: Vec<RawBookmark>,
        }
        let d: D = self.get_v3("/api/v3/bookmark/list?page=1&limit=60").await?;
        Ok(d.list.into_iter().map(RawBookmark::into_bm).collect())
    }

    // ---- 令牌验证门（首次登录后 API 返 code=40002 时用）----

    /// 取令牌提示（如「请输入北京大学App手机令牌」）。
    pub async fn get_otp_title(&self) -> anyhow::Result<String> {
        let body = self
            .client
            .0
            .http_client
            .treehole_api_get(&self.session, "/api/title-otp")
            .await?;
        let v: serde_json::Value = serde_json::from_str(&body)?;
        v.get("data")
            .and_then(|d| d.as_str())
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("title-otp 无 data"))
    }

    /// 提交 IAAA 令牌完成验证（端点 `/api/login_iaaa_check_token` body `{code}`）。
    pub async fn verify_otp(&self, code: &str) -> anyhow::Result<()> {
        let body = format!(r#"{{"code":"{code}"}}"#);
        let resp = self
            .client
            .0
            .http_client
            .treehole_api_post(&self.session, "/api/login_iaaa_check_token", &body)
            .await?;
        let v: serde_json::Value = serde_json::from_str(&resp)?;
        if v.get("success").and_then(|s| s.as_bool()).unwrap_or(false) {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "令牌验证失败: {}",
                v.get("message").and_then(|m| m.as_str()).unwrap_or("?")
            ))
        }
    }

    /// 暴露 session（probe/MCP auth 用）。
    pub fn session(&self) -> &TreeholeSession {
        &self.session
    }
}

/// 原始帖子字段（树洞 API 形状，spike 实测）。
#[derive(Debug, serde::Deserialize)]
struct RawHole {
    pid: i64,
    #[serde(default)]
    text: String,
    #[serde(default)]
    timestamp: i64,
    #[serde(default)]
    reply: i64,
    #[serde(default)]
    likenum: i64,
    #[serde(default)]
    tag: Option<String>,
}

fn raw_to_hole(r: RawHole) -> Hole {
    let time = if r.timestamp > 0 {
        chrono::DateTime::from_timestamp(r.timestamp, 0).map(|dt| dt.to_rfc3339())
    } else {
        None
    };
    Hole {
        pid: r.pid,
        text: r.text,
        timestamp: r.timestamp,
        reply: r.reply,
        likenum: r.likenum,
        tag: r.tag,
        time,
    }
}

// ---- 消息 / 收藏 ----

/// 一条通知消息（关注帖子有新回复等）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct TreeholeMessage {
    pub description: String,
    pub pid: Option<i64>,
    pub time: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct RawMessage {
    #[serde(default)]
    description: String,
    #[serde(default)]
    pid: Option<i64>,
    #[serde(default)]
    created_at: Option<String>,
}

impl RawMessage {
    fn into_msg(self) -> TreeholeMessage {
        TreeholeMessage {
            description: self.description,
            pid: self.pid,
            time: self.created_at,
        }
    }
}

/// 一个收藏夹。
#[derive(Debug, Clone, serde::Serialize)]
pub struct TreeholeBookmark {
    pub id: i64,
    pub name: String,
    pub hole_count: i64,
}

#[derive(Debug, serde::Deserialize)]
struct RawBookmark {
    id: i64,
    bookmark_name: String,
    #[serde(default)]
    hole_count: i64,
}

impl RawBookmark {
    fn into_bm(self) -> TreeholeBookmark {
        TreeholeBookmark {
            id: self.id,
            name: self.bookmark_name,
            hole_count: self.hole_count,
        }
    }
}
