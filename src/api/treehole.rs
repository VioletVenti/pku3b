//! 北大树洞服务层（PKU Helper app 生态）。
//!
//! 鉴权模型见 [`crate::api::low_level::treehole`]：Laravel session cookie + 每请求
//! `uuid`/`X-XSRF-TOKEN` 头（low-level 注入）。无 access_token。

use crate::api::low_level::treehole::TreeholeSession;

use super::*;

impl Client {
    /// 登录树洞（IAAA OTP → cas_iaaa_login 建立 Laravel session）。
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
        log::info!("[treehole] session established (uuid={}…)", &session.uuid.get(..40).unwrap_or(&session.uuid));
        Ok(Treehole {
            client: self.clone(),
            session,
        })
    }
}

/// 树洞服务句柄（持 web 设备 uuid；session cookie 在共享 jar）。
#[derive(Debug, Clone)]
pub struct Treehole {
    client: Client,
    session: TreeholeSession,
}

impl Treehole {
    /// 拉一次 hole/list，返回原始 JSON 文本。
    pub async fn list_holes_raw(&self) -> anyhow::Result<String> {
        self.client
            .0
            .http_client
            .treehole_api_get(&self.session, "/api/v3/hole/list_comments?page=1&limit=10&comment_limit=10&comment_stream=1")
            .await
    }

    /// 暴露 session（probe 诊断用）。
    pub fn session(&self) -> &TreeholeSession {
        &self.session
    }
}
