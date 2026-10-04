//! The provider adapter: one HTTPS POST of one prepared body to the enrolled
//! endpoint. It alone reads the OpenRouter key, inside the thread that sends
//! the request, from the owner-installed env file; the key never enters the
//! process environment, a child, the configuration, the state, the journal
//! or an error message. No proxy from the environment, no redirects, no
//! retries, one connect and one total deadline.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::config::{Model, OPENROUTER_ENDPOINT, endpoint};

/// Public fixture marker, never an owner credential.
pub const SYNTHETIC_CREDENTIAL: &str = "CONSTELLATION_QUALIFICATION_ONLY_NOT_A_PROVIDER_KEY";

/// Response bodies larger than this are not an answer.
const BODY_LIMIT: u64 = 64 * 1024;
const KEY_FILE_LIMIT: u64 = 4096;
const KEY_NAME: &str = "OPENROUTER_API_KEY";

/// One answered exchange.
#[derive(Clone, Debug)]
pub struct Exchange {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why no answer came back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendError {
    /// Proven never sent (key unavailable, name not resolved, connection not
    /// established): nothing reached the provider.
    Unsent(String),
    /// The deadline passed after the request may have been sent.
    Timeout(String),
    /// The exchange broke after the request may have been sent.
    Uncertain(String),
}

/// Check the key file without reading the key: a regular file, not a
/// symlink, private to its owner.
pub fn key_file_ready(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("key file {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("key file {} is not a regular file", path.display()));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "key file {} must not be readable by group or others",
            path.display()
        ));
    }
    if metadata.size() > KEY_FILE_LIMIT {
        return Err(format!("key file {} is too large", path.display()));
    }
    Ok(())
}

/// Read `OPENROUTER_API_KEY=...` from the env file. Errors never carry any
/// of the file's content.
fn read_key(path: &Path) -> Result<String, String> {
    key_file_ready(path)?;
    let mut text = String::new();
    fs::File::open(path)
        .and_then(|file| file.take(KEY_FILE_LIMIT).read_to_string(&mut text))
        .map_err(|_| format!("key file {} is unreadable", path.display()))?;
    let key = text
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix(KEY_NAME)?.trim_start().strip_prefix('='))
        .map(|value| value.trim().trim_matches('"').trim_matches('\'').to_owned())
        .next_back()
        .unwrap_or_default();
    if key.is_empty() || key.len() > 512 || !key.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(format!(
            "key file {} has no usable {KEY_NAME}",
            path.display()
        ));
    }
    Ok(key)
}

/// Validate the destination before any credential-file access.
pub fn credentials_ready(model: &Model) -> Result<(), String> {
    endpoint(&model.endpoint)?;
    if model.endpoint == OPENROUTER_ENDPOINT {
        key_file_ready(&model.key_file)?;
    }
    Ok(())
}

fn exchange(model: &Model, body: &[u8]) -> Result<Exchange, SendError> {
    credentials_ready(model).map_err(SendError::Unsent)?;
    let key = if model.endpoint == OPENROUTER_ENDPOINT {
        read_key(&model.key_file).map_err(SendError::Unsent)?
    } else {
        SYNTHETIC_CREDENTIAL.to_owned()
    };
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .https_only(model.endpoint.starts_with("https://"))
        .timeout_global(Some(Duration::from_millis(model.total_timeout_ms)))
        .timeout_connect(Some(Duration::from_millis(model.connect_timeout_ms)))
        .user_agent("constellation-remediation-consumer")
        .max_idle_connections(0)
        .build()
        .into();
    let sent = agent
        .post(&model.endpoint)
        .header("Authorization", &format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .send(body);
    drop(key);
    let mut response = sent.map_err(classify)?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_vec()
        .map_err(classify)?;
    Ok(Exchange { status, body })
}

/// ureq's errors carry no header values; only the class is kept.
fn classify(error: ureq::Error) -> SendError {
    use ureq::Error as E;
    match error {
        E::HostNotFound => SendError::Unsent("name not resolved".into()),
        E::ConnectionFailed => SendError::Unsent("connection not established".into()),
        E::Timeout(ureq::Timeout::Resolve | ureq::Timeout::Connect) => {
            SendError::Unsent("connect deadline".into())
        }
        E::Timeout(which) => SendError::Timeout(format!("{which:?} deadline")),
        E::BodyExceedsLimit(limit) => {
            SendError::Uncertain(format!("response body exceeds {limit} bytes"))
        }
        E::Io(error) => SendError::Uncertain(format!("transport: {:?}", error.kind())),
        other => SendError::Uncertain(format!("transport: {}", short(&other.to_string()))),
    }
}

fn short(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(160).collect()
}

/// POST `body` in a dedicated thread; give up (as a timeout) if the thread
/// has not answered shortly after the total deadline.
pub fn post(model: &Model, body: Vec<u8>) -> Result<Exchange, SendError> {
    let (sender, receiver) = mpsc::channel();
    let owned = model.clone();
    thread::Builder::new()
        .name("provider-adapter".into())
        .spawn(move || {
            let _ = sender.send(exchange(&owned, &body));
        })
        .map_err(|error| SendError::Unsent(format!("adapter thread: {error}")))?;
    let grace = Duration::from_millis(model.total_timeout_ms.saturating_add(1_000));
    match receiver.recv_timeout(grace) {
        Ok(result) => result,
        Err(_) => Err(SendError::Timeout("adapter deadline".into())),
    }
}
