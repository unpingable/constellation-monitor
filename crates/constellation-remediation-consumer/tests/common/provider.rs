//! A fake OpenRouter endpoint on loopback: answers each POST with the next
//! scripted reply and records every request (headers and body).

use std::collections::VecDeque;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

/// One scripted reply.
#[derive(Clone, Debug)]
pub enum Reply {
    /// HTTP status and raw body.
    Raw(u16, Vec<u8>),
    /// Never answer within the client's deadline.
    Hang(Duration),
    /// SIGKILL the consumer pass after the request arrived (a crash after
    /// the send, before settlement).
    KillClient,
    /// Write `contents` to `path` (a fake's control file), then reply.
    WriteThen(std::path::PathBuf, String, Box<Reply>),
}

/// One received request.
#[derive(Clone, Debug)]
pub struct Received {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

#[derive(Default)]
struct Shared {
    script: VecDeque<Reply>,
    received: Vec<Received>,
    child: Option<Arc<AtomicU32>>,
}

pub struct FakeProvider {
    port: u16,
    shared: Arc<Mutex<Shared>>,
}

/// A chat-completions envelope whose content is `content`.
#[must_use]
pub fn completion(content: &str) -> Reply {
    Reply::Raw(
        200,
        serde_json::to_vec(&json!({
            "id": "gen-fake-1",
            "model": "google/gemini-2.5-flash-lite",
            "provider": "Google",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }],
            "usage": {"prompt_tokens": 812, "completion_tokens": 14, "total_tokens": 826, "cost": 0.0000868},
        }))
        .unwrap(),
    )
}

#[must_use]
pub fn decision(decision: &str, reason: &str) -> Reply {
    completion(&format!(
        "{{\"decision\":\"{decision}\",\"reason\":\"{reason}\"}}"
    ))
}

impl FakeProvider {
    #[must_use]
    pub fn start(script: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Arc::new(Mutex::new(Shared {
            script: script.into(),
            ..Shared::default()
        }));
        let state = shared.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = state.clone();
                thread::spawn(move || serve(stream, &state));
            }
        });
        Self { port, shared }
    }

    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}/api/v1/chat/completions", self.port)
    }

    pub fn watch(&self, child: Arc<AtomicU32>) {
        self.shared.lock().unwrap().child = Some(child);
    }

    pub fn push(&self, reply: Reply) {
        self.shared.lock().unwrap().script.push_back(reply);
    }

    #[must_use]
    pub fn received(&self) -> Vec<Received> {
        self.shared.lock().unwrap().received.clone()
    }

    #[must_use]
    pub fn sends(&self) -> usize {
        self.received().len()
    }
}

fn serve(stream: TcpStream, shared: &Arc<Mutex<Shared>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let path = line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let mut headers = Vec::new();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 {
            return;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_owned());
            if name == "content-length" {
                length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let reply = {
        let mut shared = shared.lock().unwrap();
        shared.received.push(Received {
            path,
            headers,
            body: serde_json::from_slice(&body).unwrap_or(Value::Null),
        });
        shared
            .script
            .pop_front()
            .unwrap_or_else(|| Reply::Raw(500, b"{\"error\":\"script exhausted\"}".to_vec()))
    };
    let mut stream = stream;
    let mut reply = reply;
    while let Reply::WriteThen(path, contents, next) = reply {
        std::fs::write(path, contents).unwrap();
        reply = *next;
    }
    match reply {
        Reply::Raw(status, body) => {
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
        Reply::Hang(duration) => thread::sleep(duration),
        Reply::KillClient => {
            let pid = shared
                .lock()
                .unwrap()
                .child
                .as_ref()
                .map_or(0, |child| child.load(Ordering::SeqCst));
            assert_ne!(pid, 0, "no consumer pass to kill");
            let _ = Command::new("/bin/kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            thread::sleep(Duration::from_millis(200));
        }
        Reply::WriteThen(..) => unreachable!(),
    }
}
