//! 北大树洞 CLI（SPIKE：认证 + hole/list 探测）。
//!
//! `pku3b treehole probe` —— 复用 cfg.toml 学号/密码，按需 inquire 提示 OTP，
//! 走完整 IAAA → cas_iaaa_login → JWT 链，打印是否拿到 token 以及 hole/list
//! 首屏。用于验证树洞认证在 pku3b HTTP 客户端（不执行 JS）下可行。

use anyhow::Context;

use super::*;

/// `pku3b treehole …`
#[derive(clap::Args)]
pub struct CommandTreehole {
    #[command(subcommand)]
    command: TreeholeCommands,
}

#[derive(Subcommand)]
enum TreeholeCommands {
    /// 探测树洞认证 + 拉 hole/list（spike）
    Probe {
        /// 直接提供 OTP（省略则在需要时交互提示）
        #[arg(short = 'o', long)]
        otp: Option<String>,
    },
}

pub async fn run(cmd: CommandTreehole, ctx: &CommandCtx<'_>) -> anyhow::Result<()> {
    match cmd.command {
        TreeholeCommands::Probe { otp } => probe(ctx, otp).await,
    }
}

async fn probe(ctx: &CommandCtx<'_>, otp: Option<String>) -> anyhow::Result<()> {
    let sp = ctx.spinner();
    sp.set_message("reading config...");
    let cfg = config::read_cfg(&ctx.config_path)
        .await
        .context("read config file (请先 `pku3b init` 配置学号/密码)")?;

    let client = build_client(false).await?;

    // OTP：先探测树洞是否要求 OTP（PKU Helper appid）。
    sp.set_message("checking OTP requirement (PKU Helper)...");
    let need_otp = client
        .treehole_login_require_otp(&cfg.username)
        .await
        .unwrap_or(true);
    let otp_code = if need_otp {
        match otp {
            Some(o) => o,
            None => inquire::Text::new("请输入手机令牌（OTP）码: ").prompt()?,
        }
    } else {
        String::new()
    };

    ctx.remove_spinner(sp);

    println!("{}登录树洞（IAAA → cas_iaaa_login → JWT）…", BL);
    let th = client
        .treehole(&cfg.username, &cfg.password, &otp_code)
        .await
        .context("树洞登录失败（见日志；oauth.jsp→JWT 交换是 spike 的核心未知点）")?;

    let tok = th.token();
    println!(
        "{GR}{B}✓ 登录成功{B:#}  access_token(len={})  uuid={}…",
        tok.access_token.len(),
        &tok.uuid.get(..8).unwrap_or(&tok.uuid),
    );
    println!(
        "{D}access_token 前 24 字符: {}…{D:#}",
        &tok.access_token.chars().take(24).collect::<String>(),
    );

    println!("{}拉取 hole/list …", BL);
    match th.list_holes_raw().await {
        Ok(body) => {
            println!("{GR}{B}✓ hole/list 成功{B:#} ({} 字节)", body.len());
            // 打印前 600 字符，便于看到真实字段结构（spike 收集事实）。
            let preview: String = body.chars().take(600).collect();
            println!("{D}{preview}{D:#}");
        }
        Err(e) => {
            println!("{RD}{B}✗ hole/list 失败{B:#}: {e:#}{RD:#}");
            println!("{D}（登录成功但取数失败——可能是 uuid/header/Bearer 细节，记日志继续调）{D:#}");
        }
    }
    Ok(())
}
