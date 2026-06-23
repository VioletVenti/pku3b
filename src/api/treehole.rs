//! 北大树洞服务层（PKU Helper app 生态）。
//!
//! 见 [`crate::api::low_level::treehole`] 的认证说明。本模块镜像 [`crate::api::thesis_lib`]
//! 的 bearer-token 模型：`Treehole` 持 `TreeholeToken`，请求时由 low-level 注入
//! `Authorization` / `uuid` 头。

use crate::api::low_level::treehole::TreeholeToken;

use super::*;

impl Client {
    /// 登录树洞（IAAA OTP → app-JWT）。
    pub async fn treehole(
        &self,
        username: &str,
        password: &str,
        otp_code: &str,
    ) -> anyhow::Result<Treehole> {
        let token = self
            .0
            .http_client
            .treehole_login(username, password, otp_code)
            .await?;
        log::info!("[treehole] logged in (uuid={})", token.uuid);
        Ok(Treehole {
            client: self.clone(),
            token,
        })
    }
}

/// 树洞服务句柄（持有 app-JWT）。
#[derive(Debug, Clone)]
pub struct Treehole {
    client: Client,
    token: TreeholeToken,
}

impl Treehole {
    /// SPIKE 探测：拉一次 hole/list，返回原始 JSON 文本。
    pub async fn list_holes_raw(&self) -> anyhow::Result<String> {
        self.client
            .0
            .http_client
            .treehole_api_get_raw(&self.token, "/api/v3/hole/list")
            .await
    }

    /// 暴露 token（probe 诊断用）。
    pub fn token(&self) -> &TreeholeToken {
        &self.token
    }
}
