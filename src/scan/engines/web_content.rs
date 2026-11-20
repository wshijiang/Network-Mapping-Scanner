//! Best-effort concurrent web asset enrichment for identified http/https
//! endpoints: favicon bytes (hashed server-side), external JS paths + MD5, and
//! a conditional landing-page body when the probe hit a redirect or empty body.
//!
//! Every fetch is pinned to the scanned IP through a custom DNS resolver, so
//! redirects can never attribute another host's content to this endpoint. The
//! pass is strictly bounded (concurrency, per-fetch timeout, byte caps, block
//! budget) and never fails the scan: incomplete results keep the base evidence.

use crate::scan::ServiceObservation;
use crate::types::{ServiceDetectionConfig, WebContentConfig};
use base64::Engine as _;
use md5::{Digest, Md5};
use regex::Regex;
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;
use tokio::time::{Duration, Instant};

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (compatible; NetworkMappingScanner/1.0)";
const MAX_FAVICON_CANDIDATES: usize = 8;
const MAX_URL_CHARS: usize = 2048;

static LINK_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<link\b[^>]*>").expect("link tag regex is valid"));
static SCRIPT_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<script\b[^>]*>").expect("script tag regex is valid"));
static ATTR_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\b([a-z-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("attribute regex is valid")
});

/// Resolves every hostname to the scanned endpoint address. Redirects to other
/// hostnames still connect to the original IP (virtual-host semantics), never
/// to a third-party server.
struct PinnedResolver(SocketAddr);

impl reqwest::dns::Resolve for PinnedResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let addr = self.0;
        Box::pin(std::future::ready(Ok(
            Box::new(std::iter::once(addr)) as Box<dyn Iterator<Item = SocketAddr> + Send>
        )))
    }
}

fn is_web(service: &ServiceObservation) -> bool {
    matches!(service.service.as_deref(), Some("http" | "https"))
}

fn has_web_assets(service: &ServiceObservation) -> bool {
    service
        .data
        .as_ref()
        .and_then(|data| data.get("evidence"))
        .and_then(Value::as_array)
        .is_some_and(|evidence| {
            evidence
                .iter()
                .any(|item| item.get("module").and_then(Value::as_str) == Some("web_assets"))
        })
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    for captures in ATTR_VALUE.captures_iter(tag) {
        if captures
            .get(1)
            .is_some_and(|key| key.as_str().eq_ignore_ascii_case(name))
        {
            let value = captures
                .get(3)
                .or_else(|| captures.get(4))
                .or_else(|| captures.get(5))
                .map(|value| value.as_str().trim().to_owned())?;
            return (!value.is_empty()).then_some(value);
        }
    }
    None
}

/// Favicon candidates from `<link rel=icon>` tags, best rel first, same-origin
/// only, deduplicated and bounded.
fn favicon_candidates(body: &str, base: &reqwest::Url) -> Vec<reqwest::Url> {
    let mut ranked: Vec<(u8, reqwest::Url)> = Vec::new();
    for tag in LINK_TAG.find_iter(body) {
        let tag = tag.as_str();
        let Some(rel) = attribute(tag, "rel") else {
            continue;
        };
        let rel = rel.to_ascii_lowercase();
        let tokens: Vec<&str> = rel.split_whitespace().collect();
        let rank = if tokens == ["icon"] {
            0
        } else if rel.contains("shortcut") && rel.contains("icon") {
            1
        } else if rel.contains("apple-touch-icon") {
            2
        } else if rel.contains("icon") {
            3
        } else {
            continue;
        };
        let Some(href) = attribute(tag, "href") else {
            continue;
        };
        if let Some(url) = same_origin_url(base, &href) {
            ranked.push((rank, url));
        }
    }
    ranked.sort_by_key(|(rank, _)| *rank);
    let mut seen = std::collections::HashSet::new();
    ranked
        .into_iter()
        .filter(|(_, url)| seen.insert(url.as_str().to_owned()))
        .map(|(_, url)| url)
        .take(MAX_FAVICON_CANDIDATES)
        .collect()
}

/// External `<script src>` paths, same-origin only, deduplicated. The caller
/// applies the configured count limit.
fn script_sources(body: &str, base: &reqwest::Url) -> Vec<reqwest::Url> {
    let mut seen = std::collections::HashSet::new();
    let mut urls = Vec::new();
    for tag in SCRIPT_TAG.find_iter(body) {
        let Some(src) = attribute(tag.as_str(), "src") else {
            continue;
        };
        if let Some(url) = same_origin_url(base, &src)
            && seen.insert(url.as_str().to_owned())
        {
            urls.push(url);
        }
    }
    urls
}

/// Resolve a reference against the endpoint base URL, keeping only http(s)
/// URLs on the same host and port. Credentials are stripped; data:, javascript:
/// and cross-origin references are rejected.
fn same_origin_url(base: &reqwest::Url, reference: &str) -> Option<reqwest::Url> {
    let reference = reference.trim();
    if reference.is_empty() || reference.len() > MAX_URL_CHARS {
        return None;
    }
    let lower = reference.to_ascii_lowercase();
    if lower.starts_with("data:") || lower.starts_with("javascript:") || lower.starts_with("blob:")
    {
        return None;
    }
    let mut url = base.join(reference).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    if url.host_str() != base.host_str()
        || url.port_or_known_default() != base.port_or_known_default()
    {
        return None;
    }
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_fragment(None);
    Some(url)
}

fn endpoint_base_url(service: &ServiceObservation) -> Option<reqwest::Url> {
    let scheme = service.service.as_deref()?;
    let ip: IpAddr = service.ip.parse().ok()?;
    let authority = if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    reqwest::Url::parse(&format!("{scheme}://{authority}:{}/", service.port)).ok()
}

/// Body and status code of the http/https probe evidence, preferring the module
/// matching the identified service.
fn probe_body_and_status(service: &ServiceObservation) -> (Option<String>, Option<u16>) {
    let Some(evidence) = service
        .data
        .as_ref()
        .and_then(|data| data.get("evidence"))
        .and_then(Value::as_array)
    else {
        return (None, None);
    };
    let mut fallback = (None, None);
    for item in evidence {
        let module = item.get("module").and_then(Value::as_str).unwrap_or("");
        if !matches!(module, "http" | "https") {
            continue;
        }
        let response = item.pointer("/result/response");
        let body = response
            .and_then(|response| response.get("body"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let status = response
            .and_then(|response| response.get("status_code"))
            .and_then(Value::as_u64)
            .and_then(|code| u16::try_from(code).ok())
            .or_else(|| {
                response
                    .and_then(|response| response.get("status_line"))
                    .and_then(Value::as_str)
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|code| code.parse().ok())
            });
        if module == service.service.as_deref().unwrap_or("") {
            return (body, status);
        }
        if fallback.0.is_none() {
            fallback = (body, status);
        }
    }
    fallback
}

/// Magic-byte validation: many servers answer /favicon.ico with a 200 HTML
/// error page, which must not be stored or hashed as an icon.
fn looks_like_image(bytes: &[u8], content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    if content_type.contains("text/html") {
        return false;
    }
    if bytes.starts_with(&[0x00, 0x00, 0x01, 0x00])
        || bytes.starts_with(&[0x89, b'P', b'N', b'G'])
        || bytes.starts_with(b"GIF8")
        || bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        || bytes.starts_with(b"BM")
        || (bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"))
    {
        return true;
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).to_ascii_lowercase();
    let head = head.trim_start();
    content_type.contains("svg")
        || head.starts_with("<svg")
        || (head.starts_with("<?xml") && head.contains("<svg"))
}

/// Stream a response body up to `limit` bytes. `truncate` keeps the prefix for
/// JS/body captures; favicon fetches reject oversized responses instead.
async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
    truncate: bool,
) -> Result<(Vec<u8>, bool), ()> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if bytes.len() + chunk.len() > limit {
            if !truncate {
                return Err(());
            }
            bytes.extend_from_slice(&chunk[..limit - bytes.len()]);
            truncated = true;
            break;
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((bytes, truncated))
}

fn truncate_utf8(text: &str, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text.to_owned(), false);
    }
    let mut end = 0;
    for (offset, character) in text.char_indices() {
        if offset + character.len_utf8() > limit {
            break;
        }
        end = offset + character.len_utf8();
    }
    (text[..end].to_owned(), true)
}

fn strip_nul(value: &str) -> String {
    if value.contains('\0') {
        value.replace('\0', "")
    } else {
        value.to_owned()
    }
}

fn md5_hex(bytes: &[u8]) -> String {
    format!("{:x}", Md5::digest(bytes))
}

fn build_client(
    config: &ServiceDetectionConfig,
    web: &WebContentConfig,
    addr: SocketAddr,
) -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .user_agent(web.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT))
        .danger_accept_invalid_certs(true)
        // Redirects are followed manually so a Location without an explicit
        // port keeps the scanned endpoint port instead of drifting to 80/443.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(config.connect_timeout_seconds))
        .timeout(Duration::from_secs(web.fetch_timeout_seconds))
        .dns_resolver(PinnedResolver(addr))
        .build()
        .ok()
}

/// GET with manual, endpoint-pinned redirect following. Every hop connects to
/// the scanned IP (PinnedResolver); a redirect that omits the port keeps the
/// endpoint port so evidence is never attributed to another service. Returns
/// the final response plus the redirect chain.
async fn send_pinned(
    client: &reqwest::Client,
    url: &reqwest::Url,
    endpoint_port: u16,
    max_redirects: usize,
    accept: &str,
) -> Result<(reqwest::Response, Vec<String>), ()> {
    let mut current = url.clone();
    let mut chain = Vec::new();
    for _ in 0..=max_redirects {
        let response = client
            .get(current.clone())
            .header("accept", accept)
            .header("accept-encoding", "identity")
            .send()
            .await
            .map_err(|_| ())?;
        if response.status().is_redirection()
            && let Some(location) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
            && let Some(mut next) = current.join(location).ok()
            && matches!(next.scheme(), "http" | "https")
        {
            if next.port().is_none() {
                let _ = next.set_port(Some(endpoint_port));
            }
            let _ = next.set_username("");
            let _ = next.set_password(None);
            chain.push(strip_nul(
                &next
                    .as_str()
                    .chars()
                    .take(MAX_URL_CHARS)
                    .collect::<String>(),
            ));
            current = next;
            continue;
        }
        return Ok((response, chain));
    }
    Err(())
}

async fn fetch_favicon(
    client: &reqwest::Client,
    web: &WebContentConfig,
    sem: &Semaphore,
    base: &reqwest::Url,
    candidates: &[reqwest::Url],
    deadline: Instant,
) -> Option<Value> {
    let mut urls: Vec<reqwest::Url> = candidates.to_vec();
    if let Ok(fallback) = base.join("/favicon.ico")
        && !urls.iter().any(|url| url == &fallback)
    {
        urls.push(fallback);
    }
    let endpoint_port = base.port().unwrap_or(80);
    for url in urls {
        if Instant::now() >= deadline {
            return None;
        }
        let Ok(_permit) = sem.acquire().await else {
            return None;
        };
        let Ok((response, _)) = send_pinned(
            client,
            &url,
            endpoint_port,
            web.max_redirects,
            "image/*,*/*;q=0.8",
        )
        .await
        else {
            continue;
        };
        if response.status() != reqwest::StatusCode::OK {
            continue;
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .chars()
            .take(128)
            .collect::<String>();
        let final_url = response
            .url()
            .as_str()
            .chars()
            .take(MAX_URL_CHARS)
            .collect::<String>();
        let Ok((bytes, _)) = read_bounded(response, web.max_favicon_bytes, false).await else {
            continue;
        };
        if bytes.is_empty() || !looks_like_image(&bytes, &content_type) {
            continue;
        }
        return Some(json!({
            "url": strip_nul(&final_url),
            "content_type": strip_nul(&content_type),
            "size": bytes.len(),
            "data_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
        }));
    }
    None
}

fn looks_like_html(bytes: &[u8], content_type: &str) -> bool {
    if content_type.to_ascii_lowercase().contains("text/html") {
        return true;
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]).to_ascii_lowercase();
    let head = head.trim_start();
    head.starts_with("<html") || head.starts_with("<!doctype html")
}

async fn fetch_js(
    client: &reqwest::Client,
    web: &WebContentConfig,
    sem: &Semaphore,
    base: &reqwest::Url,
    urls: &[reqwest::Url],
    deadline: Instant,
) -> (Vec<Value>, bool) {
    let truncated = urls.len() > web.max_js_files;
    let endpoint_port = base.port().unwrap_or(80);
    let mut results = Vec::new();
    for url in urls.iter().take(web.max_js_files) {
        if Instant::now() >= deadline {
            break;
        }
        let path = strip_nul(&url.path().chars().take(512).collect::<String>());
        let full_url = strip_nul(&url.as_str().chars().take(MAX_URL_CHARS).collect::<String>());
        let Ok(_permit) = sem.acquire().await else {
            break;
        };
        let entry = match send_pinned(client, url, endpoint_port, web.max_redirects, "*/*").await {
            Ok((response, _)) if response.status() == reqwest::StatusCode::OK => {
                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                match read_bounded(response, web.max_js_bytes, true).await {
                    Ok((bytes, truncated))
                        if !bytes.is_empty() && !looks_like_html(&bytes, &content_type) =>
                    {
                        // A prefix MD5 is not the asset's MD5: keep the path
                        // searchable but never publish a partial hash.
                        if truncated {
                            json!({"path": path, "url": full_url, "size": bytes.len(), "status": "truncated"})
                        } else {
                            json!({"path": path, "url": full_url, "size": bytes.len(), "hash_md5": md5_hex(&bytes), "status": "success"})
                        }
                    }
                    Ok((_, _)) => json!({"path": path, "url": full_url, "status": "html_response"}),
                    Err(()) => json!({"path": path, "url": full_url, "status": "error"}),
                }
            }
            Ok((response, _)) => {
                json!({"path": path, "url": full_url, "status": format!("http_{}", response.status().as_u16())})
            }
            Err(()) => json!({"path": path, "url": full_url, "status": "error"}),
        };
        results.push(entry);
    }
    (results, truncated)
}

async fn fetch_landing(
    client: &reqwest::Client,
    web: &WebContentConfig,
    sem: &Semaphore,
    base: &reqwest::Url,
    deadline: Instant,
) -> Option<Value> {
    if Instant::now() >= deadline {
        return None;
    }
    let _permit = sem.acquire().await.ok()?;
    let endpoint_port = base.port().unwrap_or(80);
    let (response, chain) = send_pinned(
        client,
        base,
        endpoint_port,
        web.max_redirects,
        "text/html,*/*;q=0.8",
    )
    .await
    .ok()?;
    let status = response.status().as_u16();
    let final_url = strip_nul(
        &response
            .url()
            .as_str()
            .chars()
            .take(MAX_URL_CHARS)
            .collect::<String>(),
    );
    let (bytes, truncated) = read_bounded(response, web.max_body_bytes, true)
        .await
        .ok()?;
    if bytes.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    let (body, body_truncated) = truncate_utf8(&strip_nul(&text), web.max_body_bytes);
    let mut landing = json!({
        "url": final_url,
        "status_code": status,
        "body": body,
        "body_truncated": truncated || body_truncated,
    });
    if !chain.is_empty() {
        landing["redirects"] = json!(chain);
    }
    Some(landing)
}

async fn enrich_service(
    config: &ServiceDetectionConfig,
    service: &ServiceObservation,
    sem: Arc<Semaphore>,
    deadline: Instant,
) -> Option<Value> {
    let web = &config.web_content;
    let base = endpoint_base_url(service)?;
    let ip: IpAddr = service.ip.parse().ok()?;
    let client = build_client(config, web, SocketAddr::new(ip, 0))?;
    let (body, status) = probe_body_and_status(service);
    let mut body = body.unwrap_or_default();

    let mut result = serde_json::Map::new();
    // A redirect or empty probe body means the real page was never captured:
    // re-fetch "/" first and extract favicon/JS references from the landing HTML.
    let needs_landing =
        status.is_some_and(|code| (300..400).contains(&code)) || body.trim().is_empty();
    if needs_landing && let Some(landing) = fetch_landing(&client, web, &sem, &base, deadline).await
    {
        if let Some(landing_body) = landing.get("body").and_then(Value::as_str)
            && !landing_body.trim().is_empty()
        {
            body = landing_body.to_owned();
        }
        result.insert("landing".into(), landing);
    }
    let candidates = favicon_candidates(&body, &base);
    if let Some(favicon) = fetch_favicon(&client, web, &sem, &base, &candidates, deadline).await {
        result.insert("favicon".into(), favicon);
    }
    let scripts = script_sources(&body, &base);
    if !scripts.is_empty() {
        let (js, js_truncated) = fetch_js(&client, web, &sem, &base, &scripts, deadline).await;
        if !js.is_empty() {
            result.insert("js".into(), Value::Array(js));
        }
        result.insert("js_truncated".into(), json!(js_truncated));
    }
    (!result.is_empty()).then_some(Value::Object(result))
}

fn attach_web_assets(service: &mut ServiceObservation, result: Value) {
    let item = json!({"module": "web_assets", "status": "success", "result": result});
    let data = service
        .data
        .get_or_insert_with(|| json!({"schema_version": 2, "evidence": []}));
    if let Some(evidence) = data.get_mut("evidence").and_then(Value::as_array_mut) {
        evidence.push(item);
    }
}

/// Enrich one service-detection block in place. Returns the serialized bytes
/// added so the caller can keep the block under the result-size limit. Never
/// errors: cancellation, deadlines and fetch failures only shrink the output.
pub(crate) async fn enrich_block(
    config: &ServiceDetectionConfig,
    services: &mut [ServiceObservation],
    stage_deadline: Instant,
    cancel_requested: &AtomicBool,
    byte_budget: usize,
) -> usize {
    let web = &config.web_content;
    if !web.enabled || cancel_requested.load(Ordering::Relaxed) {
        return 0;
    }
    let started = Instant::now();
    let deadline = stage_deadline.min(started + Duration::from_secs(web.max_stage_seconds));
    let sem = Arc::new(Semaphore::new(web.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (index, service) in services.iter().enumerate() {
        if !is_web(service) || has_web_assets(service) {
            continue;
        }
        let config = config.clone();
        let service = service.clone();
        let sem = sem.clone();
        set.spawn(async move {
            (
                index,
                enrich_service(&config, &service, sem, deadline).await,
            )
        });
    }
    if set.is_empty() {
        return 0;
    }
    let mut added = 0usize;
    let mut enriched = 0usize;
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let aborted = loop {
        tokio::select! {
            joined = set.join_next() => {
                match joined {
                    Some(Ok((index, Some(result)))) => {
                        let item = json!({"module": "web_assets", "status": "success", "result": result});
                        let bytes = serde_json::to_vec(&item).map(|value| value.len()).unwrap_or(0);
                        if added.saturating_add(bytes) <= byte_budget {
                            attach_web_assets(&mut services[index], item["result"].clone());
                            added += bytes;
                            enriched += 1;
                        }
                    }
                    Some(Ok((_, None))) => {}
                    Some(Err(_)) => {}
                    None => break false,
                }
            }
            _ = ticker.tick() => {
                if cancel_requested.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    set.abort_all();
                    break true;
                }
            }
        }
    };
    // Keep results that finished before the abort; aborted tasks yield Err.
    while let Some(joined) = set.join_next().await {
        if let Ok((index, Some(result))) = joined {
            let item = json!({"module": "web_assets", "status": "success", "result": result});
            let bytes = serde_json::to_vec(&item)
                .map(|value| value.len())
                .unwrap_or(0);
            if added.saturating_add(bytes) <= byte_budget {
                attach_web_assets(&mut services[index], item["result"].clone());
                added += bytes;
                enriched += 1;
            }
        }
    }
    tracing::info!(
        event = "WebContentEnrichmentCompleted",
        endpoint_count = services.len(),
        enriched_count = enriched,
        added_bytes = added,
        aborted,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "web content enrichment finished"
    );
    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ServiceDetectionConfig;

    fn service_with_body(body: &str, status: u16) -> ServiceObservation {
        ServiceObservation {
            ip: "192.0.2.1".into(),
            port: 8080,
            protocol: "tcp".into(),
            service: Some("http".into()),
            banner: None,
            source: "zgrab2".into(),
            data: Some(json!({
                "schema_version": 2,
                "evidence": [{
                    "module": "http",
                    "status": "success",
                    "result": {"response": {"status_code": status, "body": body}}
                }]
            })),
            observed_at: 1,
        }
    }

    fn base() -> reqwest::Url {
        reqwest::Url::parse("http://192.0.2.1:8080/").unwrap()
    }

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn favicon_candidates_rank_rel_and_skip_cross_origin() {
        let body = r#"<html><head>
            <link rel="apple-touch-icon" href="/touch.png">
            <link rel="shortcut icon" href="/legacy.ico">
            <link rel="icon" type="image/png" href="/best.png">
            <link rel="icon" href="https://cdn.example.com/x.png">
            <link rel="icon" href="data:image/png;base64,AAAA">
            <link rel="stylesheet" href="/style.css">
        </head></html>"#;
        let urls = favicon_candidates(body, &base());
        let paths: Vec<_> = urls.iter().map(|url| url.path()).collect();
        assert_eq!(paths, vec!["/best.png", "/legacy.ico", "/touch.png"]);
    }

    #[test]
    fn script_sources_skip_inline_data_and_cross_origin() {
        let body = r#"<script>var inline = 1;</script>
            <script src="/static/js/app.js"></script>
            <script src='/static/js/app.js'></script>
            <script src="https://other.example/lib.js"></script>
            <script src="data:text/javascript,alert(1)"></script>
            <script src="//192.0.2.1:8080/proto.js"></script>"#;
        let urls = script_sources(body, &base());
        let paths: Vec<_> = urls.iter().map(|url| url.path()).collect();
        assert_eq!(paths, vec!["/static/js/app.js", "/proto.js"]);
    }

    #[test]
    fn image_magic_rejects_html_error_pages() {
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        assert!(looks_like_image(&png, "image/png"));
        assert!(looks_like_image(&[0, 0, 1, 0], "image/x-icon"));
        assert!(looks_like_image(
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
            "image/svg+xml"
        ));
        assert!(!looks_like_image(
            b"<html><body>404</body></html>",
            "text/html"
        ));
        assert!(!looks_like_image(b"<html></html>", "image/x-icon"));
        assert!(!looks_like_image(b"", "image/png"));
    }

    #[test]
    fn utf8_truncation_keeps_char_boundaries() {
        let (text, truncated) = truncate_utf8("aé中", 4);
        assert_eq!(text, "aé");
        assert!(truncated);
        let (text, truncated) = truncate_utf8("abc", 10);
        assert_eq!(text, "abc");
        assert!(!truncated);
    }

    #[test]
    fn probe_body_prefers_matching_module() {
        let mut service = service_with_body("primary", 200);
        let evidence = service.data.as_mut().unwrap()["evidence"]
            .as_array_mut()
            .unwrap();
        evidence.push(json!({"module": "https", "result": {"response": {"status_code": 301, "body": "other"}}}));
        let (body, status) = probe_body_and_status(&service);
        assert_eq!(body.as_deref(), Some("primary"));
        assert_eq!(status, Some(200));
    }

    #[test]
    fn enrichment_is_idempotent_and_skips_non_web() {
        let mut config = ServiceDetectionConfig::default();
        config.web_content.enabled = true;
        let mut web_service = service_with_body("", 200);
        attach_web_assets(&mut web_service, json!({"favicon": {"size": 1}}));
        let mut ssh = service_with_body("", 200);
        ssh.service = Some("ssh".into());
        let mut services = vec![web_service, ssh];
        let added = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(enrich_block(
                &config,
                &mut services,
                Instant::now() + Duration::from_secs(5),
                &AtomicBool::new(false),
                1024 * 1024,
            ));
        assert_eq!(added, 0);
    }

    /// Minimal HTTP/1.1 test server: routes are (path, status, content-type, body).
    /// Every request is answered with Connection: close; redirects may point at
    /// other hostnames because the pinned resolver must keep them on this server.
    async fn serve(listener: tokio::net::TcpListener, routes: Vec<(String, u16, String, Vec<u8>)>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let Ok(read) = socket.read(&mut buffer).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let (status, content_type, body) = routes
                    .iter()
                    .find(|(route, _, _, _)| route == &path)
                    .map(|(_, status, content_type, body)| {
                        (*status, content_type.clone(), body.clone())
                    })
                    .unwrap_or((404, "text/html".into(), b"not found".to_vec()));
                let reason = if status == 200 {
                    "OK"
                } else if status == 302 {
                    "Found"
                } else {
                    "Not Found"
                };
                // Redirect to another hostname on purpose: the pinned resolver
                // must keep the connection on this test server.
                let location = if status == 302 {
                    "Location: http://redirected.example/landing\r\n"
                } else {
                    ""
                };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&body).await;
                let _ = socket.shutdown().await;
            });
        }
    }

    async fn local_server(
        routes: Vec<(String, u16, String, Vec<u8>)>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (addr, tokio::spawn(serve(listener, routes)))
    }

    fn png_bytes() -> Vec<u8> {
        vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13]
    }

    fn config_for() -> ServiceDetectionConfig {
        let mut config = ServiceDetectionConfig::default();
        config.web_content.fetch_timeout_seconds = 5;
        config.web_content.max_stage_seconds = 15;
        config.connect_timeout_seconds = 2;
        config
    }

    #[tokio::test]
    async fn enriches_favicon_js_and_landing_from_local_server() {
        let html = r#"<html><head><link rel="icon" href="/icon.png"></head>
            <body><script src="/app.js"></script>hello</body></html>"#;
        let js = b"console.log('hi');";
        let (addr, server) = local_server(vec![
            ("/".into(), 302, "text/html".into(), b"redirect".to_vec()),
            (
                "/landing".into(),
                200,
                "text/html".into(),
                html.as_bytes().to_vec(),
            ),
            ("/icon.png".into(), 200, "image/png".into(), png_bytes()),
            (
                "/app.js".into(),
                200,
                "application/javascript".into(),
                js.to_vec(),
            ),
        ])
        .await;
        // The probe saw a redirect; the landing page must be re-fetched. The
        // redirect target uses another hostname to prove DNS pinning.
        let mut service = service_with_body("", 302);
        service.ip = addr.ip().to_string();
        service.port = addr.port();
        let config = config_for();
        let mut services = vec![service];
        let added = enrich_block(
            &config,
            &mut services,
            Instant::now() + Duration::from_secs(20),
            &AtomicBool::new(false),
            4 * 1024 * 1024,
        )
        .await;
        server.abort();
        assert!(added > 0);
        let evidence = services[0].data.as_ref().unwrap()["evidence"]
            .as_array()
            .unwrap();
        let web = evidence
            .iter()
            .find(|item| item["module"] == "web_assets")
            .expect("web_assets evidence attached");
        let result = &web["result"];
        assert_eq!(result["favicon"]["size"], json!(png_bytes().len()));
        assert_eq!(result["js"][0]["path"], json!("/app.js"));
        assert_eq!(result["js"][0]["hash_md5"], json!(md5_hex(js)));
        assert_eq!(result["landing"]["status_code"], json!(200));
        assert!(
            result["landing"]["body"]
                .as_str()
                .unwrap()
                .contains("hello")
        );
    }

    #[tokio::test]
    async fn html_favicon_falls_back_to_favicon_ico() {
        let (addr, server) = local_server(vec![
            (
                "/".into(),
                200,
                "text/html".into(),
                b"<html>ok</html>".to_vec(),
            ),
            (
                "/favicon.ico".into(),
                200,
                "image/x-icon".into(),
                vec![0, 0, 1, 0, 1, 0],
            ),
        ])
        .await;
        let mut service = service_with_body("<html>ok</html>", 200);
        service.ip = addr.ip().to_string();
        service.port = addr.port();
        let config = config_for();
        let mut services = vec![service];
        enrich_block(
            &config,
            &mut services,
            Instant::now() + Duration::from_secs(20),
            &AtomicBool::new(false),
            4 * 1024 * 1024,
        )
        .await;
        server.abort();
        let evidence = services[0].data.as_ref().unwrap()["evidence"]
            .as_array()
            .unwrap();
        let web = evidence
            .iter()
            .find(|item| item["module"] == "web_assets")
            .unwrap();
        assert!(
            web["result"]["favicon"]["url"]
                .as_str()
                .unwrap()
                .ends_with("/favicon.ico")
        );
        assert!(web["result"].get("landing").is_none());
    }

    #[tokio::test]
    async fn oversized_js_keeps_path_but_no_prefix_hash() {
        let big_js = vec![b'a'; 4096];
        let (addr, server) = local_server(vec![
            (
                "/".into(),
                200,
                "text/html".into(),
                b"<html><script src=\"/big.js\"></script></html>".to_vec(),
            ),
            (
                "/big.js".into(),
                200,
                "application/javascript".into(),
                big_js.clone(),
            ),
        ])
        .await;
        let mut service = service_with_body("<html><script src=\"/big.js\"></script></html>", 200);
        service.ip = addr.ip().to_string();
        service.port = addr.port();
        let mut config = config_for();
        config.web_content.max_js_bytes = 1024;
        let mut services = vec![service];
        enrich_block(
            &config,
            &mut services,
            Instant::now() + Duration::from_secs(20),
            &AtomicBool::new(false),
            4 * 1024 * 1024,
        )
        .await;
        server.abort();
        let evidence = services[0].data.as_ref().unwrap()["evidence"]
            .as_array()
            .unwrap();
        let web = evidence
            .iter()
            .find(|item| item["module"] == "web_assets")
            .unwrap();
        let entry = &web["result"]["js"][0];
        assert_eq!(entry["path"], json!("/big.js"));
        assert_eq!(entry["status"], json!("truncated"));
        assert!(
            entry.get("hash_md5").is_none(),
            "prefix MD5 must not be published"
        );
    }

    #[tokio::test]
    async fn disabled_enrichment_attaches_nothing() {
        let mut config = ServiceDetectionConfig::default();
        config.web_content.enabled = false;
        let mut services = vec![service_with_body("<html></html>", 200)];
        let added = enrich_block(
            &config,
            &mut services,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            1024 * 1024,
        )
        .await;
        assert_eq!(added, 0);
        assert!(!has_web_assets(&services[0]));
    }

    #[tokio::test]
    async fn byte_budget_drops_oversized_results() {
        let (addr, server) = local_server(vec![
            (
                "/".into(),
                200,
                "text/html".into(),
                b"<html>ok</html>".to_vec(),
            ),
            (
                "/favicon.ico".into(),
                200,
                "image/x-icon".into(),
                vec![0, 0, 1, 0, 1, 0],
            ),
        ])
        .await;
        let mut service = service_with_body("<html>ok</html>", 200);
        service.ip = addr.ip().to_string();
        service.port = addr.port();
        let config = config_for();
        let mut services = vec![service];
        let added = enrich_block(
            &config,
            &mut services,
            Instant::now() + Duration::from_secs(20),
            &AtomicBool::new(false),
            10,
        )
        .await;
        server.abort();
        assert_eq!(added, 0);
        assert!(!has_web_assets(&services[0]));
    }
}
