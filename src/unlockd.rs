//! Protocol and client for rbw-unlockd.
//!
//! rbw-unlockd is the system service that holds native unlock credentials
//! for `broker` enrollments. It runs as root, so
//! programs running as the user cannot read the credentials; it identifies
//! the caller from the socket's peer credentials and only releases a
//! credential after fprintd verifies one of that user's fingers.
//!
//! One request per connection, as newline-delimited JSON: the client sends a
//! `Request`, the service streams `Event::Status` lines while scanning and
//! ends with a single `Event::Done` or `Event::Error`. Closing the
//! connection cancels a scan.

use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroizing;

use crate::unlock_ui::FingerprintStatus;

pub const DEFAULT_SOCKET: &str = "/run/rbw-unlockd.sock";
/// Largest request line the service accepts (a master password plus JSON).
pub const MAX_LINE: usize = 16 * 1024;

pub fn socket_path() -> std::path::PathBuf {
    std::env::var_os("RBW_UNLOCKD_SOCKET")
        .filter(|path| !path.is_empty())
        .map_or_else(|| DEFAULT_SOCKET.into(), Into::into)
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Scan a finger, then seal `password` for this user under `id`.
    Enroll {
        id: String,
        store: crate::config::UnlockStore,
        secure_boot: bool,
        password: String,
    },
    /// Scan a finger, then return the credential saved under `id`.
    Unlock { id: String },
    /// Delete the credential saved under `id`.
    Remove { id: String },
    /// Report whether a credential is saved under `id`.
    Status { id: String },
}

impl Request {
    pub fn id(&self) -> &str {
        match self {
            Self::Enroll { id, .. }
            | Self::Unlock { id }
            | Self::Remove { id }
            | Self::Status { id } => id,
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Self::Enroll { password, .. } = self {
            zeroize::Zeroize::zeroize(password);
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Status {
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        finger: Option<String>,
    },
    Done {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        enrolled: Option<bool>,
    },
    Error {
        message: String,
    },
}

impl Drop for Event {
    fn drop(&mut self) {
        if let Self::Done {
            password: Some(password),
            ..
        } = self
        {
            zeroize::Zeroize::zeroize(password);
        }
    }
}

/// Enrollment ids are UUIDs (rbw generates them); the service uses them as
/// file names, so anything else is rejected.
pub fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id)
        .is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
}

/// Serializes `value` as one JSON line into a buffer that is wiped on drop.
pub fn encode_line(
    value: &impl serde::Serialize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::with_capacity(256));
    serde_json::to_writer(&mut *line, value)?;
    line.push(b'\n');
    Ok(line)
}

/// Reads one line of at most `MAX_LINE` bytes into a wiped buffer; `None`
/// at end of stream.
pub async fn read_line(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut line = Zeroizing::new(Vec::with_capacity(256));
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let (chunk, done) = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or((available, None), |end| {
                (&available[..end], Some(end + 1))
            });
        anyhow::ensure!(
            line.len() + chunk.len() <= MAX_LINE,
            "rbw-unlockd message too long"
        );
        line.extend_from_slice(chunk);
        let consumed = done.unwrap_or(available.len());
        reader.consume(consumed);
        if done.is_some() {
            return Ok(Some(line));
        }
    }
}

/// Sends `request` to rbw-unlockd and waits for its answer, forwarding scan
/// progress to `feedback`. Resolving `cancel` closes the connection, which
/// stops the scan. Returns the `Done` event.
pub async fn call(
    request: &Request,
    feedback: Option<&tokio::sync::watch::Sender<FingerprintStatus>>,
    cancel: impl std::future::Future<Output = ()>,
) -> anyhow::Result<Event> {
    let path = socket_path();
    let stream =
        tokio::net::UnixStream::connect(&path)
            .await
            .with_context(|| {
                format!(
            "could not reach rbw-unlockd at {}; is the service enabled?",
            path.display()
        )
            })?;
    let (reader, mut writer) = stream.into_split();
    writer.write_all(&encode_line(request)?).await?;
    let mut reader = tokio::io::BufReader::new(reader);
    let answer = async {
        loop {
            let line = read_line(&mut reader).await?.context(
                "rbw-unlockd closed the connection without answering",
            )?;
            let event: Event = serde_json::from_slice(&line)
                .context("invalid answer from rbw-unlockd")?;
            match &event {
                Event::Status { status, finger } => {
                    if let Some(feedback) = feedback {
                        feedback.send_replace(FingerprintStatus::from_wire(
                            status,
                            finger.as_deref(),
                        ));
                    }
                }
                Event::Done { .. } => return Ok(event),
                Event::Error { message } => {
                    anyhow::bail!("rbw-unlockd: {message}")
                }
            }
        }
    };
    tokio::select! {
        result = answer => result,
        () = cancel => anyhow::bail!("fingerprint unlock cancelled"),
    }
}

/// `call` for `Request::Unlock`: the credential, as a string.
pub async fn unlock(
    id: &str,
    feedback: Option<&tokio::sync::watch::Sender<FingerprintStatus>>,
    cancel: impl std::future::Future<Output = ()>,
) -> anyhow::Result<Zeroizing<String>> {
    let mut event =
        call(&Request::Unlock { id: id.to_string() }, feedback, cancel)
            .await?;
    match &mut event {
        Event::Done {
            password: Some(password),
            ..
        } => Ok(Zeroizing::new(std::mem::take(password))),
        _ => anyhow::bail!("rbw-unlockd returned no credential"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_must_be_canonical_uuids() {
        assert!(valid_id("343950a5-866a-44a7-af6f-b495014ec4bb"));
        assert!(!valid_id("343950A5-866A-44A7-AF6F-B495014EC4BB"));
        assert!(!valid_id("../../etc/shadow"));
        assert!(!valid_id(""));
    }

    #[test]
    fn requests_and_events_round_trip() {
        let request = Request::Enroll {
            id: "343950a5-866a-44a7-af6f-b495014ec4bb".to_string(),
            store: crate::config::UnlockStore::Tpm2,
            secure_boot: true,
            password: "pw".to_string(),
        };
        let line = encode_line(&request).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        let parsed: Request =
            serde_json::from_slice(&line[..line.len() - 1]).unwrap();
        assert_eq!(parsed, request);
        let event: Event = serde_json::from_str(
            r#"{"event":"status","status":"selected","finger":"left-thumb"}"#,
        )
        .unwrap();
        assert_eq!(
            event,
            Event::Status {
                status: "selected".to_string(),
                finger: Some("left-thumb".to_string())
            }
        );
    }

    #[tokio::test]
    async fn read_line_limits_length() {
        let data = vec![b'a'; MAX_LINE + 1];
        let mut reader = tokio::io::BufReader::new(&data[..]);
        assert!(read_line(&mut reader).await.is_err());
        let mut reader = tokio::io::BufReader::new(&b"one\ntwo"[..]);
        assert_eq!(
            read_line(&mut reader).await.unwrap().unwrap().as_slice(),
            b"one"
        );
        assert_eq!(
            read_line(&mut reader).await.unwrap().unwrap().as_slice(),
            b"two"
        );
        assert!(read_line(&mut reader).await.unwrap().is_none());
    }

    #[test]
    fn fingerprint_status_survives_the_wire() {
        for status in [
            FingerprintStatus::Ready,
            FingerprintStatus::selected("right-index-finger"),
            FingerprintStatus::Retry,
            FingerprintStatus::NoMatch,
            FingerprintStatus::Checking,
        ] {
            let (kind, finger) = status.to_wire();
            assert_eq!(FingerprintStatus::from_wire(kind, finger), status);
        }
    }
}
