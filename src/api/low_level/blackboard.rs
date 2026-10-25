use super::*;

pub const OAUTH_REDIR: &str =
    "http://course.pku.edu.cn/webapps/bb-sso-BBLEARN/execute/authValidate/campusLogin";
pub const SSO_LOGIN: &str =
    "https://course.pku.edu.cn/webapps/bb-sso-BBLEARN/execute/authValidate/campusLogin";
pub const BB_HOME: &str = "https://course.pku.edu.cn/webapps/portal/execute/tabs/tabAction";
pub const BB_LOGIN: &str = "https://course.pku.edu.cn/webapps/login/";
pub const BB_CONTENT_FILE: &str =
    "https://course.pku.edu.cn/webapps/blackboard/execute/content/file";
pub const COURSE_INFO: &str = "https://course.pku.edu.cn/webapps/blackboard/execute/announcement";
pub const UPLOAD_ASSIGNMENT: &str = "https://course.pku.edu.cn/webapps/assignment/uploadAssignment";
pub const LIST_CONTENT: &str =
    "https://course.pku.edu.cn/webapps/blackboard/content/listContent.jsp";
pub const VIDEO_LIST: &str =
    "https://course.pku.edu.cn/webapps/bb-streammedia-hqy-BBLEARN/videoList.action";
pub const VIDEO_SUB_INFO: &str =
    "https://yjapise.pku.edu.cn/courseapi/v2/schedule/get-sub-info-by-auth-data";

#[derive(Debug)]
pub struct BlackboardUnautherizedError;

impl std::error::Error for BlackboardUnautherizedError {}

impl std::fmt::Display for BlackboardUnautherizedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blackboard login not authorized")
    }
}

impl LowLevelClient {
    pub async fn bb_login_require_otp(&self, username: &str) -> anyhow::Result<bool> {
        let data = self.iaaa_is_mobile_authen("blackboard", username).await?;
        Ok(data.authen_mode == "OTP")
    }

    /// 使用 OAuth login 返回的 token 登录教学网。登录状态会记录在 client cookie 中，无需返回值.
    pub async fn bb_login(
        &self,
        username: &str,
        password: &str,
        otp_code: &str,
    ) -> anyhow::Result<()> {
        let data = self.iaaa_is_mobile_authen("blackboard", username).await?;

        if data.is_no() {
            log::info!("unprotected login is allowed");
        } else {
            log::warn!("unsupported login context: {data:?}")
        }

        let token = self
            .iaaa_oauth_login("blackboard", username, password, otp_code, OAUTH_REDIR)
            .await?;

        log::debug!("iaaa oauth token for {username}: {token}");

        let mut rng = rand::rng();

        let _rand: f64 = rng.sample(rand::distr::Open01);
        let _rand = format!("{_rand:.20}");

        let mut res = self
            .http_client
            .get(SSO_LOGIN)?
            .query(&[("_rand", _rand.as_str()), ("token", &token)])?
            .send()
            .await?;

        // It seems that multiple redirections are possible during sso login.
        while let Ok(url) = extract_redirect_url(&res) {
            log::debug!("sso login redirected to {url}");
            res = self.get_by_uri(url).await?;
        }

        anyhow::ensure!(
            res.status().is_success(),
            "sso login not success: {}",
            res.status()
        );

        Ok(())
    }

    /// 获取教学网主页内容 ([`BB_HOME`]), 返回 HTML 文档
    pub async fn bb_homepage(&self) -> anyhow::Result<Html> {
        let res = self
            .http_client
            .get(BB_HOME)?
            .query(&[("tab_tab_group_id", "_1_1")])?
            .send()
            .await?;

        if extract_redirect_url(&res).ok() == Some(BB_LOGIN) {
            anyhow::bail!(BlackboardUnautherizedError);
        }
        anyhow::ensure!(res.status().is_success(), "status not success");

        let rbody = res.text().await?;
        let dom = scraper::Html::parse_document(&rbody);
        Ok(dom)
    }

    /// 根据课程的 key 获取课程主页内容 ([`COURSE_INFO`])
    pub async fn bb_coursepage(&self, key: &str) -> anyhow::Result<Html> {
        let res = self
            .http_client
            .get(COURSE_INFO)?
            .query(&[
                ("method", "search"),
                ("context", "course_entry"),
                ("course_id", key),
                ("handle", "announcements_entry"),
                ("mode", "view"),
            ])?
            .send()
            .await?;

        anyhow::ensure!(res.status().is_success(), "status not success");

        let rbody = res.text().await?;
        let dom = scraper::Html::parse_document(&rbody);
        Ok(dom)
    }

    /// 根据 content_id 和 course_id 获取课程内容列表页面（包含作业、公告和一些其他东西）
    pub async fn bb_course_content_page(
        &self,
        course_id: &str,
        content_id: &str,
    ) -> anyhow::Result<Html> {
        let res = self
            .http_client
            .get(LIST_CONTENT)?
            .query(&[("content_id", content_id), ("course_id", course_id)])?
            .send()
            .await?;

        anyhow::ensure!(res.status().is_success(), "status not success");

        let rbody = res.text().await?;
        let dom = scraper::Html::parse_document(&rbody);
        Ok(dom)
    }

    /// 根据 content_id 和 course_id 获取作业上传页面的信息.
    pub async fn bb_course_assignment_uploadpage(
        &self,
        course_id: &str,
        content_id: &str,
    ) -> anyhow::Result<Html> {
        let res = self
            .http_client
            .get(UPLOAD_ASSIGNMENT)?
            .query(&[
                ("action", "newAttempt"),
                ("content_id", content_id),
                ("course_id", course_id),
            ])?
            .send()
            .await?;

        anyhow::ensure!(res.status().is_success(), "status not success");

        let rbody = res.text().await?;
        let dom = scraper::Html::parse_document(&rbody);
        Ok(dom)
    }

    /// 根据 content_id 和 course_id 获取作业的历史提交页面.
    pub async fn bb_course_assignment_viewpage(
        &self,
        course_id: &str,
        content_id: &str,
    ) -> anyhow::Result<Html> {
        let res = self
            .http_client
            .get(UPLOAD_ASSIGNMENT)?
            .query(&[
                ("mode", "view"),
                ("content_id", content_id),
                ("course_id", course_id),
            ])?
            .send()
            .await?;

        anyhow::ensure!(res.status().is_success(), "status not success");

        let rbody = res.text().await?;
        let dom = scraper::Html::parse_document(&rbody);
        Ok(dom)
    }

    /// 向 [`UPLOAD_ASSIGNMENT`] 发送提交作业的请求
    pub async fn bb_course_assignment_uploaddata(
        &self,
        body: multipart::MultipartBuilder<'_>,
    ) -> anyhow::Result<cyper::Response> {
        let boundary = body.boundary().to_owned();
        let body = body.build().context("build multipart form body")?;

        log::debug!("body built: {}", body.len());

        let res = self
            .http_client
            .post(UPLOAD_ASSIGNMENT)?
            .header("origin", "https://course.pku.edu.cn")?
            .header("accept", "*/*")?
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )?
            .query(&[("action", "submit")])?
            .body(body)
            .send()
            .await?;

        Ok(res)
    }

    /// 根据 course_id 获取回放列表页面内容.
    pub async fn bb_course_video_list(&self, course_id: &str) -> anyhow::Result<Html> {
        let res = self
            .http_client
            .get(VIDEO_LIST)?
            .query(&[
                ("sortDir", "ASCENDING"),
                ("numResults", "100"), // 一门课一般不会有超过 100 条回放
                ("editPaging", "false"),
                ("course_id", course_id),
                ("mode", "view"),
                ("startIndex", "0"),
            ])?
            .send()
            .await?;

        anyhow::ensure!(res.status().is_success(), "status not success");

        let rbody = res.text().await?;
        let dom = scraper::Html::parse_document(&rbody);
        Ok(dom)
    }

    /// 获取视频回放的 sub_info（用于下载 m3u8 playlist）, 返回 response body
    pub async fn bb_course_video_sub_info(
        &self,
        course_id: &str,
        sub_id: &str,
        app_id: &str,
        auth_data: &str,
    ) -> anyhow::Result<String> {
        let res = self
            .http_client
            .get(VIDEO_SUB_INFO)?
            .query(&[
                ("all", "1"),
                ("course_id", course_id),
                ("sub_id", sub_id),
                ("with_sub_data", "1"),
                ("app_id", app_id),
                ("auth_data", auth_data),
            ])?
            .send()
            .await?;

        anyhow::ensure!(res.status().is_success(), "status not success");

        let rbody = res.text().await?;
        Ok(rbody)
    }

    /// Download a 「文件」 content item into `outdir`, returning the saved path.
    ///
    /// The content page's `document.location` points at `/bbcswebdav/...`, which
    /// either redirects to the real file URL (older behaviour; the name is the last
    /// path segment) or — as of 2026-10 — serves the file directly with 200, the
    /// name then coming from `Content-Disposition`. `fallback_stem` + an extension
    /// guessed from `Content-Type` is used when neither yields a name.
    pub async fn bb_course_content_file_download(
        &self,
        course_id: &str,
        content_id: &str,
        outdir: &std::path::Path,
        fallback_stem: &str,
    ) -> anyhow::Result<std::path::PathBuf> {
        let res = self
            .http_client
            .get(BB_CONTENT_FILE)?
            .query(&[
                ("cmd", "view"),
                ("content_id", content_id),
                ("course_id", course_id),
                ("launch_in_new", "true"),
            ])?
            .send()
            .await?;
        let body = res.text().await?;
        let re = regex::Regex::new(r#"document.location = '(.*?)';"#).unwrap();
        let loc = re
            .captures(&body)
            .and_then(|c| c.get(1))
            .context("file link (document.location) not found on content page")?
            .as_str()
            .to_owned();
        log::debug!("content file link {loc}");

        let mut res = self.get_by_uri(&loc).await?;
        let mut url_name = None;
        if res.status().is_redirection() {
            let next = extract_redirect_url(&res)?.to_owned();
            url_name = next.rsplit_once('/').map(|(_, n)| percent_decode_str(n));
            res = self.get_by_uri(&next).await?;
        }
        anyhow::ensure!(
            res.status().is_success(),
            "download status {}",
            res.status()
        );

        let header = |k: &str| {
            res.headers()
                .get(k)
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        };
        let name = header("content-disposition")
            .and_then(|cd| filename_from_content_disposition(&cd))
            .or(url_name)
            .filter(|n| !n.trim().is_empty() && !n.starts_with("xid-"))
            .unwrap_or_else(|| {
                let ext = header("content-type").and_then(|ct| ext_from_content_type(&ct));
                match ext {
                    Some(ext) => format!("{fallback_stem}.{ext}"),
                    None => fallback_stem.to_owned(),
                }
            });
        let name = sanitize_file_name(&name);
        let dest = outdir.join(&name);
        let bytes = res.bytes().await?;
        let r = compio::fs::write(&dest, bytes).await;
        compio::buf::buf_try!(@try r);
        Ok(dest)
    }
}

// REST API 支持
impl LowLevelClient {
    /// 发送 GET 请求到 REST API 并解析 JSON 响应
    pub async fn api_get<T: serde::de::DeserializeOwned>(&self, url: &str) -> anyhow::Result<T> {
        let res = self.http_client.get(url)?.send().await?;

        anyhow::ensure!(
            res.status().is_success(),
            "API request failed: {}",
            res.status()
        );

        let rbody = res.text().await?;
        let data: T = serde_json::from_str(&rbody)?;
        Ok(data)
    }
}

fn percent_decode_str(s: &str) -> String {
    percent_encoding::percent_decode(s.as_bytes())
        .decode_utf8_lossy()
        .into_owned()
}

/// `filename*=UTF-8''<pct-encoded>` wins over `filename="..."` (RFC 6266).
fn filename_from_content_disposition(cd: &str) -> Option<String> {
    let mut plain = None;
    for part in cd.split(';').map(str::trim) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"');
        match k.trim().to_ascii_lowercase().as_str() {
            "filename*" => {
                let encoded = v.rsplit_once("''").map(|(_, e)| e).unwrap_or(v);
                return Some(percent_decode_str(encoded));
            }
            "filename" => {
                plain = Some(if v.contains('%') {
                    percent_decode_str(v)
                } else {
                    v.to_owned()
                })
            }
            _ => {}
        }
    }
    plain
}

fn ext_from_content_type(ct: &str) -> Option<&'static str> {
    let ct = ct.split(';').next()?.trim().to_ascii_lowercase();
    Some(match ct.as_str() {
        "application/pdf" => "pdf",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => "pptx",
        "application/vnd.ms-powerpoint" => "ppt",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/msword" => "doc",
        "application/zip" | "application/x-zip-compressed" => "zip",
        "text/plain" => "txt",
        _ => return None,
    })
}

fn sanitize_file_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let s = s.trim().trim_start_matches('.').to_owned();
    if s.is_empty() { "_".to_owned() } else { s }
}

#[cfg(test)]
mod content_file_tests {
    use super::*;

    #[test]
    fn content_disposition_names() {
        assert_eq!(
            filename_from_content_disposition(
                "attachment; filename=\"x.pdf\"; filename*=UTF-8''%E7%AC%AC%E4%B8%80%E7%AB%A0.pdf"
            )
            .as_deref(),
            Some("第一章.pdf")
        );
        assert_eq!(
            filename_from_content_disposition("inline; filename=\"lec%201.pptx\"").as_deref(),
            Some("lec 1.pptx")
        );
        assert_eq!(filename_from_content_disposition("inline").as_deref(), None);
        assert_eq!(
            ext_from_content_type("application/pdf; charset=binary"),
            Some("pdf")
        );
        assert_eq!(ext_from_content_type("text/html"), None);
        assert_eq!(sanitize_file_name("../a/b.pdf"), "_a_b.pdf");
    }
}
