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
    /// 完成树洞的「手机短信验证」（hole/list 返 code=40002 时用）
    Verify {
        #[arg(short = 'o', long)]
        otp: Option<String>,
    },
}

pub async fn run(cmd: CommandTreehole, ctx: &CommandCtx<'_>) -> anyhow::Result<()> {
    match cmd.command {
        TreeholeCommands::Probe { otp } => probe(ctx, otp).await,
        TreeholeCommands::Verify { otp } => verify(ctx, otp).await,
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

    let th = login_treehole(ctx, client, &cfg, otp_code).await?;

    println!("{}拉取 hole/list（Bearer JWT + uuid）…", BL);
    match th.list_holes_raw().await {
        Ok(body) => {
            println!("{GR}{B}✓ hole/list 成功{B:#} ({} 字节)", body.len());
            let preview: String = body.chars().take(600).collect();
            println!("{D}{preview}{D:#}");
        }
        Err(e) => {
            println!("{RD}{B}✗ hole/list 失败{B:#}: {e:#}{RD:#}");
            println!(
                "{D}（若提示 code=40002 请手机短信验证，跑 `pku3b treehole verify`）{D:#}"
            );
        }
    }
    Ok(())
}

async fn verify(ctx: &CommandCtx<'_>, otp: Option<String>) -> anyhow::Result<()> {
    let sp = ctx.spinner();
    sp.set_message("reading config...");
    let cfg = config::read_cfg(&ctx.config_path)
        .await
        .context("read config file")?;
    let client = build_client(false).await?;
    sp.set_message("checking OTP...");
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

    let th = login_treehole(ctx, client, &cfg, otp_code).await?;

    // 1. 发送短信验证码。
    println!("{}发送树洞短信验证码…", BL);
    match th.send_sms().await {
        Ok(b) => println!("{D}send_msg 响应: {}{D:#}", b.chars().take(200).collect::<String>()),
        Err(e) => {
            println!("{RD}✗ 发送短信失败: {e:#}{RD:#}");
            return Ok(());
        }
    }

    // 2. 用户输入收到的短信码。
    let code = inquire::Text::new("请输入收到的树洞短信验证码: ").prompt()?;

    // 3. 提交验证（自动试字段名）。
    println!("{}提交短信验证…", BL);
    match th.verify_sms(&code).await {
        Ok((field, b)) => println!(
            "{GR}{B}✓ 验证响应{B:#} [字段={field}]: {}{GR:#}",
            b.chars().take(200).collect::<String>(),
        ),
        Err(e) => println!("{RD}✗ 验证失败: {e:#}{RD:#}"),
    }

    // 4. 重读 hole/list 看是否通过。
    println!("{}重读 hole/list…", BL);
    match th.list_holes_raw().await {
        Ok(b) => {
            println!("{GR}{B}✓ hole/list 成功{B:#} ({} 字节){GR:#}", b.len());
            println!("{D}{}{D:#}", b.chars().take(400).collect::<String>());
        }
        Err(e) => println!("{RD}✗ 仍失败: {e:#}{RD:#}"),
    }
    Ok(())
}

/// 共享：登录树洞（cfg + OTP）→ 打印 session。
async fn login_treehole(
    ctx: &CommandCtx<'_>,
    client: api::Client,
    cfg: &config::Config,
    otp_code: String,
) -> anyhow::Result<api::treehole::Treehole> {
    let _ = ctx;
    println!("{}登录树洞（IAAA → cas_iaaa_login → iaaa_success JWT）…", BL);
    let th = client
        .treehole(&cfg.username, &cfg.password, &otp_code)
        .await
        .context("树洞登录失败")?;
    println!(
        "{GR}{B}✓ 登录成功{B:#}  JWT={}  uuid={}…{GR:#}",
        th.session().access_token.is_some(),
        th.session().uuid.get(..40).unwrap_or(&th.session().uuid),
    );
    Ok(th)
}
