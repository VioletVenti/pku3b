//! 北大树洞 (treehole.pku.edu.cn) 低层 API
//!
//! 认证模型（两份 HAR + otp-chunk 实测，非猜测；详见 memory
//! `myal1s-p3-treehole-protocol`）：
//! - IAAA 半段：复用 [`super::iaaa::iaaa_oauth_login`]，appid = `PKU Helper`。
//! - 服务半段：IAAA token → GET `/cas_iaaa_login?uuid=<tail12>&plat=web&token=<IAAA>`
//!   （**根 `/cas_iaaa_login`，不是 `/chapi/cas_iaaa_login`**）。成功 → 302 →
//!   `/web/iaaa_success?token=<JWT>`（HS256 access_token；从 `res.url()` query 取）。
//! - **API 鉴权**（`/chapi/api/v3/*`）：`Authorization: Bearer <JWT>` + `uuid` 头 +
//!   `userAgent: pku_web` 头。**有 Bearer**（早期被 HAR 脱敏 Cookie 头误导以为无；
//!   401 body `{"message":"Token not provided"}` 证伪）。
//! - **令牌验证门**（首次登录后 API 返 code=40002「请手机短信验证」，实为 IAAA 令牌
//!   验证非短信）：GET `/api/title-otp`（提示）→ POST `/api/login_iaaa_check_token
//!   {code}` → success。详见 `api::treehole::verify_otp`。
//! - uuid 两段：完整 `Web_PKUHOLE_2.0.0_WEB_UUID_<v4hex>`（作 `uuid` 头），但 IAAA
//!   redirectUrl + cas_iaaa_login 的 `?uuid=` 用其**尾 12 位 hex**。
//! - 路径 base：登录走根（`/redirect_iaaa_login`、`/cas_iaaa_login`、`/web/`）；
//!   OTP 类走根 `/api/`（`title-otp`、`login_iaaa_check_token`）；业务 API 走 `/chapi`。

use anyhow::Context as _;
use super::LowLevelClient;

/// IAAA appid —— 树洞走「PKU Helper」。
pub const TREEHOLE_APP_ID: &str = "PKU Helper";
/// IAAA 登录后的回调（**根路径**，建立 session + 签发 JWT）。
pub const TREEHOLE_CAS_LOGIN: &str = "https://treehole.pku.edu.cn/cas_iaaa_login";
/// 发起 IAAA 重定向的入口（根路径，web 平台）。
#[allow(dead_code)]
pub const TREEHOLE_REDIRECT_IAAA: &str = "https://treehole.pku.edu.cn/redirect_iaaa_login";
/// API 基址（web 端 axios baseURL = host + "/chapi/"）。
pub const TREEHOLE_API: &str = "https://treehole.pku.edu.cn/chapi";
/// 登录成功着陆页（cas_iaaa_login 302 到此，query 带 access_token JWT）。
pub const TREEHOLE_IAAA_SUCCESS: &str = "https://treehole.pku.edu.cn/web/iaaa_success";

/// 树洞会话句柄。鉴权靠 Laravel session cookie（共享 jar），每请求加 `uuid` +
/// `X-XSRF-TOKEN` 头。`access_token`（JWT）也保留——个别端点可能用 Bearer。
#[derive(Debug, Clone)]
pub struct TreeholeSession {
    /// 完整 web 设备 UUID：`Web_PKUHOLE_2.0.0_WEB_UUID_<v4hex>`（随 `uuid` 头发送）。
    pub uuid: String,
    /// access_token（HS256 JWT，来自 /web/iaaa_success?token=…）。API 主路径用 cookie，
    /// 但保留以备 Bearer 端点。
    pub access_token: Option<String>,
}

impl LowLevelClient {
    /// 是否需要 OTP（复用 IAAA 通用判定，appid = PKU Helper）。
    pub async fn treehole_login_require_otp(&self, username: &str) -> anyhow::Result<bool> {
        let data = self.iaaa_is_mobile_authen(TREEHOLE_APP_ID, username).await?;
        Ok(data.authen_mode == "OTP")
    }

    /// 树洞登录：IAAA（OTP）→ cas_iaaa_login（根路径，尾 12 位 uuid）→ iaaa_success
    /// （拿 JWT）+ 建立 Laravel session。返回会话句柄。
    pub async fn treehole_login(
        &self,
        username: &str,
        password: &str,
        otp_code: &str,
    ) -> anyhow::Result<TreeholeSession> {
        // 完整 web UUID（HAR: localStorage pku-uuid）。
        let uuid = pku_web_uuid();
        let uuid_tail = uuid_tail12(&uuid);

        // IAAA 半段：redirUrl 用 cas_iaaa_login（根）+ 尾 12 位 uuid（HAR 实测）。
        let redir = format!("{TREEHOLE_CAS_LOGIN}?uuid={uuid_tail}&plat=web");
        let token = self
            .iaaa_oauth_login(TREEHOLE_APP_ID, username, password, otp_code, &redir)
            .await
            .context("IAAA oauth login (PKU Helper) 失败")?;
        log::info!("[treehole] IAAA token acquired (len={})", token.len());

        // 服务半段：GET cas_iaaa_login（根路径，尾 12 位 uuid + IAAA token）。
        // 成功 → 302 → /web/iaaa_success?token=<JWT>。pku3b 跟随重定向，最终 URL 即
        // iaaa_success；从其 query 取 JWT。过程中 cas_iaaa_login 的 Set-Cookie（Laravel
        // session）由 send() 在最终响应采集——但 302 的 Set-Cookie 会丢，故下面也兜底
        // 直访 iaaa_success 让其 cookie 落 jar。
        let cas_url = format!(
            "{TREEHOLE_CAS_LOGIN}?uuid={uuid_tail}&plat=web&_rand=0&token={token}"
        );
        let res = self.http_client.get(&cas_url)?.send().await?;
        let final_url = res.url().clone();
        let status = res.status();
        log::info!("[treehole] cas_iaaa_login → final status={status} url={final_url}");

        // 从最终 URL（iaaa_success?token=<JWT>）提取 access_token。
        let access_token = final_url
            .query_pairs()
            .find(|(k, _)| k == "token")
            .map(|(_, v)| v.to_string());
        if let Some(t) = &access_token {
            log::info!("[treehole] access_token (JWT) acquired from iaaa_success (len={})", t.len());
        } else {
            log::warn!("[treehole] 未能从 iaaa_success URL 取 access_token（final={final_url}）");
        }

        // 兜底：确保 iaaa_success 的 cookie（Laravel session）落 jar。
        if let Some(t) = &access_token {
            let _ = self
                .http_client
                .get(&format!("{TREEHOLE_IAAA_SUCCESS}?token={t}"))?
                .send()
                .await?;
        }
        Ok(TreeholeSession { uuid, access_token })
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
        // 鉴权（实测）：`Authorization: Bearer <JWT>`（access_token from iaaa_success）
        // 是主因子 —— 401 body 明确 `{"message":"Token not provided"}`。辅以 uuid 头 +
        // userAgent:pku_web + Referer（bundle 拦截器与 HAR 一致）。
        let mut req = self
            .http_client
            .get(&url)?
            .header("uuid", &session.uuid)?
            .header("userAgent", "pku_web")?
            .header("Accept", "application/json, text/plain, */*")?
            .header("Referer", "https://treehole.pku.edu.cn/ch/web/pc/index")?;
        if let Some(t) = &session.access_token {
            req = req.header("Authorization", format!("Bearer {t}"))?;
        }
        if let Some(x) = self.http_client.cookie_value(&api_url, "XSRF-TOKEN") {
            req = req.header("X-XSRF-TOKEN", x)?;
        }
        let res = req.send().await?;
        let status = res.status();
        let body = res.text().await?;
        log::info!(
            "[treehole] GET {path} status={status} bearer={} xsrf={}",
            session.access_token.is_some(),
            self.http_client.cookie_value(&api_url, "XSRF-TOKEN").is_some(),
        );
        anyhow::ensure!(status.is_success(), "treehole {path} 失败: {status}\n{}", body);
        Ok(body)
    }

    /// 鉴权 POST（同 treehole_api_get 的头集 + body）。spike 探测用，返回原始文本。
    pub async fn treehole_api_post(
        &self,
        session: &TreeholeSession,
        path: &str,
        body: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{TREEHOLE_API}{path}");
        let api_url = url::Url::parse(TREEHOLE_API).unwrap();
        let mut req = self
            .http_client
            .post(&url)?
            .header("uuid", &session.uuid)?
            .header("userAgent", "pku_web")?
            .header("Accept", "application/json, text/plain, */*")?
            .header("Content-Type", "application/json")?
            .header("Referer", "https://treehole.pku.edu.cn/ch/web/pc/index")?;
        if let Some(t) = &session.access_token {
            req = req.header("Authorization", format!("Bearer {t}"))?;
        }
        if let Some(x) = self.http_client.cookie_value(&api_url, "XSRF-TOKEN") {
            req = req.header("X-XSRF-TOKEN", x)?;
        }
        let res = req.body(body.to_owned()).send().await?;
        let status = res.status();
        let rb = res.text().await?;
        log::info!("[treehole] POST {path} status={status} body[:120]={:?}", rb.chars().take(120).collect::<String>());
        anyhow::ensure!(status.is_success(), "treehole POST {path} 失败: {status}\n{rb}");
        Ok(rb)
    }
}
/// 生成 web 端设备 UUID（HAR 实测格式）：`Web_PKUHOLE_2.0.0_WEB_UUID_<v4hex>`。
/// bundle: `localStorage.pku-uuid = "Web_PKUHOLE_2.0.0_WEB_UUID_" + pz()`。
fn pku_web_uuid() -> String {
    format!("Web_PKUHOLE_2.0.0_WEB_UUID_{}", uuid_v4_hex())
}

/// 取完整 UUID 的尾 12 位 hex（HAR: IAAA redirectUrl + cas_iaaa_login 的 `?uuid=`
/// 用尾段，如 `4a1e5d9f2f6a`，不是完整字符串）。
fn uuid_tail12(full: &str) -> String {
    // 取 `<hex>` 的最后 12 字符（v4 hex 尾段足以唯一）。
    let hex_part = full.rsplit('_').next().unwrap_or(full);
    let len = hex_part.len();
    hex_part[len.saturating_sub(12)..].to_string()
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
