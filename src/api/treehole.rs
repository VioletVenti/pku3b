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

    /// 触发短信验证码发送（首次登录后服务端要求「请手机短信验证」code=40002）。
    /// 返回原始响应（探明字段）。
    pub async fn send_sms(&self) -> anyhow::Result<String> {
        // body 字段名未在 bundle 压缩里定位——先试空对象（手机号绑定在账号）。
        self.client
            .0
            .http_client
            .treehole_api_post(&self.session, "/api/jwt_send_msg", "{}")
            .await
    }

    /// 提交短信验证码完成验证。
    pub async fn verify_sms(&self, code: &str) -> anyhow::Result<String> {
        let body = format!(r#"{{"code":"{code}"}}"#);
        self.client
            .0
            .http_client
            .treehole_api_post(&self.session, "/api/jwt_msg_verify", &body)
            .await
    }

    /// 暴露 session（probe 诊断用）。
    pub fn session(&self) -> &TreeholeSession {
        &self.session
    }
}
