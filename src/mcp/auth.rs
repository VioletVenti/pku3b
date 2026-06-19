//! Prompt-free authentication for the MCP server (**Seam 2**).
//!
//! The interactive CLI blocks on `inquire::Text::new("OTP").prompt()` when a
//! one-time password is required (see `crate::cli`), which is impossible inside
//! a stdio MCP subprocess — there is no terminal to prompt on. The `api::*`
//! login layer itself is already prompt-free, so this module reuses it directly
//! and turns "OTP required" from a blocking side effect into a returned value
//! ([`LoginOutcome::NeedsOtp`]).
//!
//! Asymmetry between the two services is deliberate and hidden behind the
//! uniform [`LoginOutcome`] interface:
//! - **Blackboard** reuses cached cookies via a `bb_homepage` preflight, so we
//!   *try the login first* (a warm `ua.json` skips login and OTP entirely) and
//!   only fall back to an OTP check on failure.
//! - **Portal** has no such preflight and logs in every time, so we check
//!   `portal_login_require_otp` *first* to avoid burning IAAA login attempts
//!   (repeated failed attempts can trigger a half-hour lockout, IAAA code E21).

use crate::api::{Client, blackboard::Blackboard, portal::Portal};
use crate::config::Config;

/// Result of an attempted login: either a ready session handle, or a signal
/// that the caller must supply a one-time password. Never blocks.
pub enum LoginOutcome<T> {
    Ready(T),
    NeedsOtp { mobile_mask: Option<String> },
}

/// Log in to Blackboard (course.pku.edu.cn), reusing cached cookies when warm.
pub async fn login_blackboard(
    client: &Client,
    cfg: &Config,
    otp: Option<&str>,
) -> anyhow::Result<LoginOutcome<Blackboard>> {
    // Warm cookies make this a no-op login (the `bb_homepage` preflight skips
    // the IAAA round-trip), so trying first costs nothing and avoids a false
    // "needs OTP" when we don't actually need to log in.
    match client
        .blackboard(&cfg.username, &cfg.password, otp.unwrap_or(""))
        .await
    {
        Ok(bb) => Ok(LoginOutcome::Ready(bb)),
        Err(e) => {
            if otp.is_none()
                && client
                    .bb_login_require_otp(&cfg.username)
                    .await
                    .unwrap_or(false)
            {
                Ok(LoginOutcome::NeedsOtp { mobile_mask: None })
            } else {
                Err(e)
            }
        }
    }
}

/// Log in to the campus portal (portal.pku.edu.cn).
pub async fn login_portal(
    client: &Client,
    cfg: &Config,
    otp: Option<&str>,
) -> anyhow::Result<LoginOutcome<Portal>> {
    // Portal logs in on every call (no cookie-reuse preflight), so check the
    // OTP requirement *before* attempting login to avoid burning attempts.
    if otp.is_none() && client.portal_login_require_otp(&cfg.username).await? {
        return Ok(LoginOutcome::NeedsOtp { mobile_mask: None });
    }
    let portal = client
        .portal(&cfg.username, &cfg.password, otp.unwrap_or(""))
        .await?;
    Ok(LoginOutcome::Ready(portal))
}
