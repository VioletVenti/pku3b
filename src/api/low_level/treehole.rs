//! 北大树洞 (treehole.pku.edu.cn) 低层 API
//!
//! 认证模型（HAR 实测，非猜测）：
//! - IAAA 半段复用 [`super::iaaa::iaaa_oauth_login`]，appid = `PKU Helper`。trusted-
//!   device 机制使一次 OTP 后通常免 OTP（与教学网同 cookie jar）。
//! - 服务半段是 **Laravel session + CSRF**，**不是** Bearer/`access_token`：登录 =
//!   带 IAAA token 访问 `cas_iaaa_login` → 服务端建立 Laravel session（Set-Cookie
//!   `XSRF-TOKEN` + `_session`）。此后所有 `/chapi/api/v3/*` 请求只需：
//!     · session cookie（共享 jar 自动带）
//!     · `uuid` 头（web 设备标识，形如 `Web_PKUHOLE_2.0.0_WEB_UUID_<rand>`）
//!     · `X-XSRF-TOKEN` 头（取 `XSRF-TOKEN` cookie 的值原样回填，无需 decode）
//!   HAR 确认成功请求**无 `Authorization` 头** —— bundle 里的 `Bearer` 是手机 app
//!   端逻辑，web 端不用。
//! - API base = `https://treehole.pku.edu.cn/chapi`（bundle `s2e=origin+"/chapi/"`）。

use anyhow::Context as _;
use super::LowLevelClient;

/// IAAA appid —— 树洞走「PKU Helper」（实测 oauth.jsp 重定向携带此 appID）。
pub const TREEHOLE_APP_ID: &str = "PKU Helper";
/// IAAA 登录后的回调入口（建立 Laravel session）。
pub const TREEHOLE_CAS_LOGIN: &str = "https://treehole.pku.edu.cn/chapi/cas_iaaa_login";
/// 发起 IAAA 重定向的入口（web 平台）。
#[allow(dead_code)]
pub const TREEHOLE_REDIRECT_IAAA: &str = "https://treehole.pku.edu.cn/chapi/redirect_iaaa_login";
/// API 基址（web 端 axios baseURL = host + "/chapi/"）。
pub const TREEHOLE_API: &str = "https://treehole.pku.edu.cn/chapi";

/// 树洞会话句柄。无 access_token —— 鉴权靠共享 jar 里的 Laravel session cookie，
/// 外加每个请求的 `uuid` + `X-XSRF-TOKEN` 头（low-level 自动注入）。
#[derive(Debug, Clone)]
pub struct TreeholeSession {
    /// web 设备 UUID，形如 `Web_PKUHOLE_2.0.0_WEB_UUID_<rand>`。
    pub uuid: String,
}

impl LowLevelClient {
    /// 是否需要 OTP（复用 IAAA 通用判定，appid = PKU Helper）。
    pub async fn treehole_login_require_otp(&self, username: &str) -> anyhow::Result<bool> {
        let data = self.iaaa_is_mobile_authen(TREEHOLE_APP_ID, username).await?;
        Ok(data.authen_mode == "OTP")
    }

    /// 树洞登录：IAAA（OTP）→ cas_iaaa_login 建立 Laravel session。返回会话句柄
    ///（uuid）。之后的 API 请求由 [`treehole_api_get`] 自动带 session cookie +
    /// `uuid` + `X-XSRF-TOKEN` 头。
    pub async fn treehole_login(
        &self,
        username: &str,
        password: &str,
        otp_code: &str,
    ) -> anyhow::Result<TreeholeSession> {
        // web 设备 UUID（HAR 实测格式）。
        let uuid = pku_web_uuid();
        let redir = format!("{TREEHOLE_CAS_LOGIN}?version=3&uuid={uuid}&plat=web");

        // IAAA 半段：复用 oauthlogin.do，appid=PKU Helper。
        let token = self
            .iaaa_oauth_login(TREEHOLE_APP_ID, username, password, otp_code, &redir)
            .await
            .context("IAAA oauth login (PKU Helper) 失败")?;
        log::info!("[treehole] IAAA token acquired (len={})", token.len());

        // 服务半段：带 IAAA token 访问 cas_iaaa_login，建立 Laravel session。
        // 有效 token → 200（SPA HTML）+ Set-Cookie XSRF-TOKEN/_session；无效 → 302 登录异常。
        let url = format!("{TREEHOLE_CAS_LOGIN}?version=3&uuid={uuid}&plat=web&token={token}");
        let res = self.http_client.get(&url)?.send().await?;
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        log::info!("[treehole] cas_iaaa_login status={status} body.len={}", body.len());
        // 校验 session 落了：XSRF-TOKEN cookie 应存在。
        let api_url = url::Url::parse(TREEHOLE_API).unwrap();
        let xsrf = self.http_client.cookie_value(&api_url, "XSRF-TOKEN");
        if xsrf.is_none() {
            log::warn!("[treehole] XSRF-TOKEN cookie 未落（cas_iaaa_login 可能未建立 session）");
        }
        Ok(TreeholeSession { uuid })
    }

    /// 鉴权 GET：session cookie（共享 jar 自动）+ `uuid` 头 + `X-XSRF-TOKEN` 头。
    /// HAR 实测成功请求即此三件，无 Authorization。返回原始 JSON 文本。
    pub async fn treehole_api_get(
        &self,
        session: &TreeholeSession,
        path: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{TREEHOLE_API}{path}");
        let api_url = url::Url::parse(TREEHOLE_API).unwrap();
        let mut req = self
            .http_client
            .get(&url)?
            .header("uuid", &session.uuid)?
            .header("Referer", "https://treehole.pku.edu.cn/ch/web/")?;
        if let Some(x) = self.http_client.cookie_value(&api_url, "XSRF-TOKEN") {
            req = req.header("X-XSRF-TOKEN", x)?;
        }
        let res = req.send().await?;
        let status = res.status();
        let body = res.text().await?;
        log::debug!("[treehole] GET {path} status={status}");
        anyhow::ensure!(status.is_success(), "treehole {path} 失败: {status}\n{}", body);
        Ok(body)
    }
}
/// 生成 web 端设备 UUID（HAR 实测格式）：`Web_PKUHOLE_2.0.0_WEB_UUID_<v4hex>`。
/// bundle: `localStorage.pku-uuid = "Web_PKUHOLE_2.0.0_WEB_UUID_" + pz()`。
fn pku_web_uuid() -> String {
    format!("Web_PKUHOLE_2.0.0_WEB_UUID_{}", uuid_v4_hex())
}

/// 标准 v4 UUID hex（8-4-4-4-12）。无 uuid crate 依赖。
fn uuid_v4_hex() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let hi = t.wrapping_mul(0x9E3779B97F4A7C15) ^ n.rotate_left(13);
    let lo = t.rotate_left(27).wrapping_add(n.wrapping_mul(0xD1B54A32D192ED03));
    let v4_lo = (lo >> 48) & 0x0FFF | 0x4000;
    let var = (lo >> 60) & 0x3 | 0x8;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        hi >> 32,
        (hi >> 16) & 0xFFFF,
        v4_lo & 0xFFFF,
        (var << 12) | (lo >> 48) & 0xFFF,
        lo & 0xFFFFFFFFFFFF,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pku_web_uuid_format() {
        let u = pku_web_uuid();
        assert!(u.starts_with("Web_PKUHOLE_2.0.0_WEB_UUID_"), "prefix: {u}");
        let hex = u.strip_prefix("Web_PKUHOLE_2.0.0_WEB_UUID_").unwrap();
        assert_eq!(hex.len(), 36);
        assert_eq!(hex.chars().filter(|&c| c == '-').count(), 4);
    }
}
