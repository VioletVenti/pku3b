//! 北大树洞 (treehole.pku.edu.cn) 低层 API
//!
//! 树洞属「PKU Helper」app 生态，认证链与教学网不同：
//! - IAAA 半段复用 [`super::iaaa::iaaa_oauth_login`]，appid = `PKU Helper`。
//! - 服务半段是 **app-JWT** 模型：IAAA 登录拿 token → 经 `cas_iaaa_login` 回调 →
//!   后端签发 `access_token`（+ `refresh_token`）。请求时以
//!   `Authorization: Bearer <jwt>` + `uuid` 头携带。这与教学网的「写 cookie」SSO
//!   不同，更接近 thesis_lib 的 bearer-token 模型。
//!
//! SPIKE：本模块先实现最小认证 + 一次 `hole/list` 探测，验证「oauth.jsp → JWT」
//! 交换在 pku3b 的 HTTP 客户端（不执行 JS）下是否可行。形态在 probe 里探明。

use anyhow::Context as _;
use super::LowLevelClient;

/// IAAA appid —— 树洞走「PKU Helper」（实测 oauth.jsp 重定向携带此 appID）。
pub const TREEHOLE_APP_ID: &str = "PKU Helper";
/// IAAA 登录后的回调入口（oauth.jsp 携带的 redirectUrl）。
pub const TREEHOLE_CAS_LOGIN: &str = "https://treehole.pku.edu.cn/chapi/cas_iaaa_login";
/// 发起 IAAA 重定向的入口（web 平台）。
pub const TREEHOLE_REDIRECT_IAAA: &str = "https://treehole.pku.edu.cn/chapi/redirect_iaaa_login";
/// API 基址。
pub const TREEHOLE_API: &str = "https://treehole.pku.edu.cn";

/// 树洞访问令牌（app-JWT）。
#[derive(Debug, Clone)]
pub struct TreeholeToken {
    pub access_token: String,
    /// 设备/会话 UUID（web 平台登录流程生成；API 调用需随 `uuid` 头带回）。
    pub uuid: String,
}

impl LowLevelClient {
    /// 是否需要 OTP（复用 IAAA 通用判定，appid = PKU Helper）。
    pub async fn treehole_login_require_otp(&self, username: &str) -> anyhow::Result<bool> {
        let data = self.iaaa_is_mobile_authen(TREEHOLE_APP_ID, username).await?;
        Ok(data.authen_mode == "OTP")
    }

    /// 树洞登录：IAAA OTP 换 IAAA token → cas_iaaa_login 换 app-JWT。
    ///
    /// SPIKE 实现注意：`cas_iaaa_login` 在 oauth.jsp 流程里由浏览器带 IAAA 签发
    /// 的 token 到达。这里我们 (1) 走 `redirect_iaaa_login` 拿 uuid + 观察重定向，
    /// (2) 用 IAAA token 直访 `cas_iaaa_login`，(3) 解析返回（JSON JWT 或后续跳转）。
    /// 真实形态由 probe 探明，本函数实现最可能路径并详尽打日志。
    pub async fn treehole_login(
        &self,
        username: &str,
        password: &str,
        otp_code: &str,
    ) -> anyhow::Result<TreeholeToken> {
        // 1. 生成一个 UUID（web 客户端用 localStorage 存；这里每次新建即可）。
        let uuid = uuid_v4();
        let redir = format!(
            "{TREEHOLE_CAS_LOGIN}?version=3&uuid={uuid}&plat=web"
        );

        // 2. IAAA 半段：复用 oauthlogin.do，appid=PKU Helper。
        //    注意：portal 等服务的 redirUrl 是服务端 ssoLogin.do；树洞的 redirUrl
        //    是 cas_iaaa_login。oauth.jsp 实测携带的 redirectUrl 即此。
        let token = self
            .iaaa_oauth_login(TREEHOLE_APP_ID, username, password, otp_code, &redir)
            .await
            .context("IAAA oauth login (PKU Helper) 失败")?;
        log::info!("[treehole] IAAA token acquired (len={})", token.len());

        // 3. 服务半段：带 token 访问 cas_iaaa_login，换 app-JWT。
        //    先尝试带 ?token=（portal 风格）；解析 JSON。失败则记录响应体供 probe。
        let url = format!("{TREEHOLE_CAS_LOGIN}?version=3&uuid={uuid}&plat=web&token={token}");
        log::debug!("[treehole] cas_iaaa_login GET {url}");
        let res = self.http_client.get(&url)?.send().await?;
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        log::info!("[treehole] cas_iaaa_login status={status} body.len={}", body.len());
        log::debug!("[treehole] cas_iaaa_login body: {body}");

        // cas_iaaa_login 的真实形态尚未探明（spike 阶段）：它可能 (a) 在 JSON body
        // 里直接返回 access_token，或 (b) 落 cookie（Set-Cookie）+ 把浏览器重定向回
        // SPA。先试 body 解析；失败时记录详细诊断（headers）供 probe 迭代。
        if let Some(access_token) = extract_access_token(&body) {
            log::info!("[treehole] access_token from body (len={})", access_token.len());
            return Ok(TreeholeToken { access_token, uuid });
        }

        // body 里没有 token —— 走诊断路径：再请求一次，把响应头（Set-Cookie 等）
        // dump 出来，判断登录态是否落在 cookie，而不是 JWT。
        log::warn!("[treehole] no access_token in body; running cookie/redirect diagnostics");
        self.treehole_diag(&url).await?;
        anyhow::bail!(
            "cas_iaaa_login 未在 body 返回 access_token（status={status}, body[:160]={:?}）。\
             已 dump 诊断信息到日志——多半登录态落在 cookie 或需别处换 JWT。",
            body.chars().take(160).collect::<String>()
        )
    }

    /// 诊断：dump 一次请求的响应头（Set-Cookie / Location / Content-Type）+ 当前
    /// cookie jar 内容，帮 spike 判定登录态落点。spike 专用，产品码不用。
    async fn treehole_diag(&self, url: &str) -> anyhow::Result<()> {
        let res = self.http_client.get(url)?.send().await?;
        let status = res.status();
        log::info!("[treehole-diag] status={status}");
        for (k, v) in res.headers().iter() {
            log::info!("[treehole-diag]   header {k}: {}", String::from_utf8_lossy(v.as_bytes()));
        }
        // cookie jar 当前内容（save_set_cookies 落临时文件后读回）。
        let tmp = std::env::temp_dir().join("myal1s-treehole-cookies.json");
        let _ = self.save_set_cookies(&tmp).await;
        if let Ok(s) = std::fs::read_to_string(&tmp) {
            // 只 dump 树洞相关行，避免刷屏。
            let relevant: Vec<&str> = s
                .lines()
                .filter(|l| l.contains("treehole") || l.contains("pku.edu.cn"))
                .collect();
            log::info!("[treehole-diag] cookie jar (treehole lines): {relevant:?}");
        }
        Ok(())
    }

    /// 带鉴权头 GET 一个树洞 JSON 端点，返回原始文本（spike 用，解析留给上层）。
    pub async fn treehole_api_get_raw(
        &self,
        token: &TreeholeToken,
        path: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{TREEHOLE_API}{path}");
        let res = self
            .http_client
            .get(&url)?
            .header("Authorization", format!("Bearer {}", token.access_token))?
            .header("uuid", &token.uuid)?
            .send()
            .await?;
        let status = res.status();
        let body = res.text().await?;
        log::debug!("[treehole] GET {path} (bearer) status={status}");
        anyhow::ensure!(status.is_success(), "treehole {path} 失败: {status}\n{}", body);
        Ok(body)
    }

    /// Cookie-only GET（依赖 cas_iaaa_login 落在共享 jar 里的 cookie；像教学网模型）。
    /// spike 用：判定树洞 web 端是否是 cookie 鉴权而非 Bearer。
    pub async fn treehole_api_get_cookie_only(&self, path: &str) -> anyhow::Result<String> {
        let url = format!("{TREEHOLE_API}{path}");
        let res = self.http_client.get(&url)?.send().await?;
        let status = res.status();
        let body = res.text().await?;
        log::debug!("[treehole] GET {path} (cookie-only) status={status}");
        anyhow::ensure!(
            status.is_success(),
            "treehole {path} (cookie-only) 失败: {status}\n{}",
            body
        );
        Ok(body)
    }
}

/// 从 cas_iaaa_login 响应体里尽力挖出 access_token（容忍多种信封形状）。
fn extract_access_token(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    // 常见形状：{access_token}, {data:{access_token}}, {token:{access_token}}.
    for key in ["access_token", "accessToken", "token"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            return Some(s.to_owned());
        }
    }
    for parent in ["data", "token", "result"] {
        if let Some(s) = v
            .get(parent)
            .and_then(|x| x.get("access_token").or_else(|| x.get("accessToken")))
            .and_then(|x| x.as_str())
        {
            return Some(s.to_owned());
        }
    }
    None
}

/// 简易 v4 UUID（无 uuid crate 依赖；spike 用）。标准 8-4-4-4-12 hex（36 字符）。
fn uuid_v4() -> String {
    // 时间 + 计数混合种子（spike 不要求密码学随机，只要唯一 + 合法形状）。
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // 128 bits from two mixed u64s.
    let hi = t.wrapping_mul(0x9E3779B97F4A7C15) ^ n.rotate_left(13);
    let lo = t.rotate_left(27).wrapping_add(n.wrapping_mul(0xD1B54A32D192ED03));
    // Layout: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (v4, variant 10).
    let v4_lo = (lo >> 48) & 0x0FFF | 0x4000; // version 4
    let var = (lo >> 60) & 0x3 | 0x8; // variant 10x
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
    fn extract_access_token_flat() {
        assert_eq!(
            extract_access_token(r#"{"access_token":"abc.def.ghi","foo":1}"#).as_deref(),
            Some("abc.def.ghi")
        );
    }

    #[test]
    fn extract_access_token_nested_data() {
        assert_eq!(
            extract_access_token(r#"{"code":20000,"data":{"access_token":"tkn"}}"#).as_deref(),
            Some("tkn")
        );
    }

    #[test]
    fn extract_access_token_none_on_html() {
        // cas_iaaa_login 在异常时返回 HTML 重定向页 —— 拿不到 token。
        assert!(extract_access_token("<!DOCTYPE html><html>登录异常").is_none());
    }

    #[test]
    fn uuid_shape() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36, "uuid str len");
        assert_eq!(u.chars().filter(|&c| c == '-').count(), 4);
    }
}
