//! 北大树洞服务层（PKU Helper app 生态）。
//!
//! SPIKE 阶段：树洞 web 端的鉴权落点尚未最终确认——可能是 (a) cas_iaaa_login
//! 落 cookie（像教学网），或 (b) 换 app-JWT 走 Authorization 头（像 thesis_lib）。
//! 本模块先用「cas_iaaa_login 后直接试 hole/list」探测，同时尝试 cookie-only 与
//! Bearer 两种路径，一次性判定形态。形态探明后再收敛为产品码。

use super::*;

impl Client {
    /// 登录树洞（IAAA OTP → cas_iaaa_login）。spike 版：不要求返回 JWT，
    /// 登录态可能落 cookie；返回一个仅持 client 的句柄供探测。
    pub async fn treehole(
        &self,
        username: &str,
        password: &str,
        otp_code: &str,
    ) -> anyhow::Result<Treehole> {
        // treehole_login 现在在 body 无 JWT 时会跑诊断并 bail。spike 探测阶段我们
        // 容忍「没有 JWT」——只要 cas_iaaa_login 跑通（cookie 可能已落 jar），
        // 就允许进入探测，让 probe 自行判断 hole/list 用 cookie 还是 Bearer。
        match self
            .0
            .http_client
            .treehole_login(username, password, otp_code)
            .await
        {
            Ok(t) => {
                log::info!("[treehole] logged in with JWT (uuid={})", t.uuid);
                Ok(Treehole {
                    client: self.clone(),
                    token: Some(t),
                })
            }
            Err(e) => {
                log::warn!("[treehole] JWT login failed ({e:#}); 继续以 cookie-only 探测");
                Ok(Treehole {
                    client: self.clone(),
                    token: None,
                })
            }
        }
    }
}

/// 树洞服务句柄。token 为 None 表示走 cookie 模型（cas_iaaa_login 已落 cookie）。
#[derive(Debug, Clone)]
pub struct Treehole {
    client: Client,
    token: Option<crate::api::low_level::treehole::TreeholeToken>,
}

impl Treehole {
    /// SPIKE 探测：拉一次 hole/list。先试 Bearer（若有 JWT），再试 cookie-only。
    /// 返回 (路径标签, 原始响应)。
    pub async fn list_holes_raw(&self) -> anyhow::Result<(&'static str, String)> {
        let ll = &self.client.0.http_client;
        // 1) 若有 JWT，先试 Bearer + uuid。
        if let Some(t) = &self.token {
            match ll.treehole_api_get_raw(t, "/api/v3/hole/list").await {
                Ok(body) => return Ok(("bearer", body)),
                Err(e) => log::warn!("[treehole] Bearer hole/list failed: {e:#}"),
            }
        }
        // 2) cookie-only（cas_iaaa_login 落的 cookie 在共享 jar 里）。
        let body = ll.treehole_api_get_cookie_only("/api/v3/hole/list").await?;
        Ok(("cookie", body))
    }

    /// 暴露 token（probe 诊断用）。
    pub fn token(
        &self,
    ) -> Option<&crate::api::low_level::treehole::TreeholeToken> {
        self.token.as_ref()
    }
}
