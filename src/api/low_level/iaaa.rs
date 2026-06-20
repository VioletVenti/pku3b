use super::*;

pub const IAAA_IS_MOBILE_AUTHEN: &str = "https://iaaa.pku.edu.cn/iaaa/isMobileAuthen.do";
pub const IAAA_OAUTH_LOGIN: &str = "https://iaaa.pku.edu.cn/iaaa/oauthlogin.do";
pub const IAAA_OAUTH_AUTHORIZE: &str = "https://iaaa.pku.edu.cn/iaaa/oauth.jsp";
#[cfg(feature = "thesislib")]
pub const IAAA_PUBKEY: &str = "https://iaaa.pku.edu.cn/iaaa/getPublicKey.do";

/// OAuth login error codes:
///
/// - E05: OTP code incorrect
/// - E21: Too many attempts. Please sign in after a half hour.
///
#[derive(serde::Deserialize, Debug)]
pub struct OAuthLoginError {
    pub code: String,
    pub msg: String,
}

impl std::error::Error for OAuthLoginError {}

impl std::fmt::Display for OAuthLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OAuth login error [{}]: msg={}", self.code, self.msg)
    }
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(unused)]
pub struct AuthenData {
    pub authen_mode: String,
    pub bz_auth_mode: String,
    pub is_bind: bool,
    pub is_mobile_authen: bool,
    pub is_unu_auth: bool,
    pub mobile_mask: String,
    pub success: bool,
}

impl AuthenData {
    pub fn is_no(&self) -> bool {
        self.authen_mode == "否"
    }
}

impl LowLevelClient {
    /// 向 [`IAAA_OAUTH_LOGIN`] 发送登录请求，并返回 token
    ///
    /// - `otp_code`: 手机令牌码，空串表示不提供
    pub async fn iaaa_oauth_login(
        &self,
        appid: &str,
        username: &str,
        password: &str,
        otp_code: &str,
        redir: &str,
    ) -> anyhow::Result<String> {
        let res = self
            .http_client
            .post(IAAA_OAUTH_LOGIN)?
            .form(&[
                ("appid", appid),
                ("userName", username),
                ("password", password),
                ("randCode", ""),
                ("smsCode", ""),
                ("otpCode", otp_code),
                ("redirUrl", redir),
            ])?
            .send()
            .await?;

        anyhow::ensure!(
            res.status().is_success(),
            "oauth login not success: {}",
            res.status()
        );

        let rbody = res.text().await?;

        #[derive(serde::Deserialize, Debug)]
        struct OAuthLoginData {
            success: bool,
            token: Option<String>,
            errors: Option<OAuthLoginError>,
        }
        let data: OAuthLoginData = serde_json::from_str(&rbody)
            .context("fail to parse response")
            .inspect_err(|e| {
                log::debug!("{e}");
                log::debug!("response body: {rbody}")
            })?;
        anyhow::ensure!(data.success, "oauth login not success: {:?}", data);

        if let Some(err) = data.errors {
            return Err(err.into());
        }

        data.token.context("token not found")
    }

    /// IAAA single sign-on (no OTP). With a warm IAAA session (from a prior
    /// [`iaaa_oauth_login`](Self::iaaa_oauth_login)), GET the OAuth authorize
    /// page for `appid`; IAAA hands back a token bound to `redir` — either via
    /// an HTTP 3xx `Location` or a client-side `window.location` redirect — with
    /// no password/OTP. We drive the whole redirect chain so the target service
    /// ends up authenticated in the shared cookie jar.
    ///
    /// Honest success signal: SSO only worked if IAAA actually issued a token
    /// (some hop carried `token=`) **and** the chain ended on a successful page.
    /// A cold session serves the login page instead — no token anywhere — and we
    /// return `Err` so the caller knows to fall back to a full OTP login rather
    /// than trusting a half-open session.
    pub async fn iaaa_sso_login(
        &self,
        appid: &str,
        app_name: &str,
        redir: &str,
    ) -> anyhow::Result<()> {
        let mut res = self
            .http_client
            .get(IAAA_OAUTH_AUTHORIZE)?
            .query(&[
                ("appID", appid),
                ("appName", app_name),
                ("redirectUrl", redir),
            ])?
            .send()
            .await?;
        log::info!("[sso] authorize appid={appid}: status={}", res.status());

        let mut hops = 0usize;
        let mut saw_token = false;
        // Follow both HTTP 3xx and JS/meta redirects until a terminal page.
        let final_ok = loop {
            if hops > 12 {
                anyhow::bail!("too many SSO redirects");
            }
            let status = res.status();

            // HTTP redirect: follow the `Location` header.
            if status.is_redirection() {
                let url = extract_redirect_url(&res)?.to_owned();
                hops += 1;
                saw_token |= url.contains("token=");
                // Log host+path only — the query string can carry the token.
                log::info!(
                    "[sso] hop {hops} -> {}",
                    url.split('?').next().unwrap_or(&url)
                );
                res = self.get_by_uri(&url).await?;
                continue;
            }

            // Non-redirect: IAAA sometimes delivers the token via a client-side
            // `window.location = '...token=...'` instead of a 3xx. `text()`
            // consumes `res`, so capture success-ness first.
            let ok = status.is_success();
            let body = res.text().await?;
            match extract_js_redirect(&body) {
                Some(url) => {
                    hops += 1;
                    saw_token |= url.contains("token=");
                    log::info!(
                        "[sso] js-hop {hops} -> {}",
                        url.split('?').next().unwrap_or(&url)
                    );
                    res = self.get_by_uri(&url).await?;
                    continue;
                }
                // Terminal page — nothing more to follow.
                None => break ok,
            }
        };

        log::info!("[sso] done after {hops} hop(s): saw_token={saw_token} final_ok={final_ok}");
        anyhow::ensure!(
            saw_token && final_ok,
            "IAAA SSO did not authenticate (likely a cold IAAA session served the \
             login page); a full OTP login is required"
        );
        Ok(())
    }

    pub async fn iaaa_is_mobile_authen(
        &self,
        appid: &str,
        username: &str,
    ) -> anyhow::Result<AuthenData> {
        let mut rng = rand::rng();

        let _rand: f64 = rng.sample(rand::distr::Open01);
        let _rand = format!("{_rand:.20}");

        let res = self
            .http_client
            .get(IAAA_IS_MOBILE_AUTHEN)?
            .query(&[
                ("appId", appid),
                ("userName", username),
                ("_rand", _rand.as_str()),
            ])?
            .send()
            .await?;

        let rbody = res.text().await?;
        let data: AuthenData = serde_json::from_str(&rbody).context("fail to parse response")?;
        Ok(data)
    }

    #[cfg(feature = "thesislib")]
    pub async fn iaaa_public_key(&self) -> anyhow::Result<String> {
        let res = self.get_by_uri(IAAA_PUBKEY).await?;
        anyhow::ensure!(res.status().is_success(), "error status {}", res.status());

        #[derive(serde::Deserialize)]
        struct Data {
            success: bool,
            key: String,
        }

        let data: Data = serde_json::from_str(&res.text().await?)?;
        anyhow::ensure!(data.success, "get pubkey failed");

        Ok(data.key)
    }
}
