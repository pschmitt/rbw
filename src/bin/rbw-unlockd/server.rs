use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use rbw::config::UnlockStore;
use rbw::unlock_ui::FingerprintStatus;
use rbw::unlockd::{encode_line, read_line, valid_id, Event, Request};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const DEFAULT_STATE_DIR: &str = "/var/lib/rbw-unlockd";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
// Failed scans (no match, timeout) before a user is locked out, and the
// longest lockout. Each further failure doubles the wait.
const FREE_FAILURES: u32 = 3;
const MAX_LOCKOUT: Duration = Duration::from_secs(300);

pub type Cancel<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
pub type Verified<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;

/// Checks a finger of `user`. fprintd in production, a fake in tests.
pub trait Verifier: Send + Sync {
    fn verify<'a>(
        &'a self,
        user: &'a str,
        feedback: &'a tokio::sync::watch::Sender<FingerprintStatus>,
        cancel: Cancel<'a>,
    ) -> Verified<'a>;
}

struct Fprintd;

impl Verifier for Fprintd {
    fn verify<'a>(
        &'a self,
        user: &'a str,
        feedback: &'a tokio::sync::watch::Sender<FingerprintStatus>,
        cancel: Cancel<'a>,
    ) -> Verified<'a> {
        Box::pin(rbw::desktop::fingerprint_for_user(user, feedback, cancel))
    }
}

#[derive(Default)]
struct Failures {
    count: u32,
    last: Option<Instant>,
}

impl Failures {
    fn locked_for(&self, now: Instant) -> Option<Duration> {
        let excess = self.count.checked_sub(FREE_FAILURES)?;
        let lockout = Duration::from_secs(30)
            .saturating_mul(1 << excess.min(10))
            .min(MAX_LOCKOUT);
        let elapsed = now.duration_since(self.last?);
        lockout.checked_sub(elapsed).filter(|wait| !wait.is_zero())
    }
}

pub struct Context {
    pub state_dir: std::path::PathBuf,
    pub verifier: Box<dyn Verifier>,
    failures: Mutex<HashMap<u32, Failures>>,
}

impl Context {
    pub fn new(
        state_dir: std::path::PathBuf,
        verifier: Box<dyn Verifier>,
    ) -> Self {
        Self {
            state_dir,
            verifier,
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn file(
        &self,
        uid: u32,
        id: &str,
        store: UnlockStore,
    ) -> std::path::PathBuf {
        self.state_dir.join(uid.to_string()).join(format!(
            "{id}.{}",
            if store == UnlockStore::Tpm2 {
                "cred"
            } else {
                "secret"
            }
        ))
    }

    // Where `id` is saved for `uid`, if anywhere.
    fn find(
        &self,
        uid: u32,
        id: &str,
    ) -> Option<(UnlockStore, std::path::PathBuf)> {
        [UnlockStore::Tpm2, UnlockStore::File]
            .into_iter()
            .map(|store| (store, self.file(uid, id, store)))
            .find(|(_, path)| path.exists())
    }

    fn check_lockout(&self, uid: u32) -> anyhow::Result<()> {
        let failures = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(wait) = failures
            .get(&uid)
            .and_then(|f| f.locked_for(Instant::now()))
        {
            anyhow::bail!(
                "too many failed fingerprint scans; try again in {} seconds",
                wait.as_secs().max(1)
            );
        }
        Ok(())
    }

    fn record(&self, uid: u32, success: bool) {
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if success {
            failures.remove(&uid);
        } else {
            let entry = failures.entry(uid).or_default();
            entry.count += 1;
            entry.last = Some(Instant::now());
        }
    }
}

pub fn credential_name(uid: u32, id: &str) -> String {
    format!("rbw-unlockd-{uid}-{id}")
}

fn user_name(uid: u32) -> anyhow::Result<String> {
    let mut buffer = vec![0u8; 4096];
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; `buffer` outlives `passwd`.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &raw mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut result,
        )
    };
    anyhow::ensure!(status == 0 && !result.is_null(), "unknown user {uid}");
    // SAFETY: getpwuid_r succeeded, so pw_name is a valid C string in buffer.
    let name = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) };
    Ok(name.to_str().context("user name is not UTF-8")?.to_string())
}

async fn send(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    event: &Event,
) -> anyhow::Result<()> {
    writer.write_all(&encode_line(event)?).await?;
    Ok(())
}

// Runs the verifier for `user`, streaming its progress to the client. The
// client closing its end (or sending anything more) cancels the scan.
async fn scan(
    ctx: &Context,
    user: &str,
    reader: &mut (impl tokio::io::AsyncRead + Unpin + Send),
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> anyhow::Result<()> {
    let (feedback, mut progress) =
        tokio::sync::watch::channel(FingerprintStatus::Starting);
    let cancel: Cancel<'_> = Box::pin(async move {
        let mut byte = [0u8; 1];
        let _ = reader.read(&mut byte).await;
    });
    let verify = ctx.verifier.verify(user, &feedback, cancel);
    tokio::pin!(verify);
    // A client that went away cancels the scan through `reader`, so write
    // errors here are ignored.
    let report = |status: FingerprintStatus| {
        let (status, finger) = status.to_wire();
        Event::Status {
            status: status.to_string(),
            finger: finger.map(str::to_string),
        }
    };
    loop {
        tokio::select! {
            biased;
            changed = progress.changed() => {
                if changed.is_ok() {
                    let event = report(*progress.borrow_and_update());
                    let _ = send(writer, &event).await;
                }
            }
            result = &mut verify => {
                // Deliver the last update even if the scan finished first.
                if progress.has_changed().unwrap_or(false) {
                    let event = report(*progress.borrow_and_update());
                    let _ = send(writer, &event).await;
                }
                return result;
            }
        }
    }
}

async fn handle_request(
    ctx: &Context,
    uid: u32,
    request: &Request,
    reader: &mut (impl tokio::io::AsyncRead + Unpin + Send),
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> anyhow::Result<Event> {
    let id = request.id();
    anyhow::ensure!(valid_id(id), "invalid enrollment id");
    match request {
        Request::Status { .. } => Ok(Event::Done {
            password: None,
            enrolled: Some(ctx.find(uid, id).is_some()),
        }),
        Request::Remove { .. } => {
            for store in [UnlockStore::Tpm2, UnlockStore::File] {
                match std::fs::remove_file(ctx.file(uid, id, store)) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        return Err(e.into())
                    }
                    _ => {}
                }
            }
            Ok(Event::Done {
                password: None,
                enrolled: Some(false),
            })
        }
        Request::Enroll {
            store,
            secure_boot,
            password,
            ..
        } => {
            anyhow::ensure!(
                *store != UnlockStore::Keyring,
                "rbw-unlockd stores credentials in tpm2 or file, not the keyring"
            );
            anyhow::ensure!(
                !password.is_empty()
                    && password.len() <= rbw::locked::CAPACITY,
                "invalid credential size"
            );
            anyhow::ensure!(
                *store == UnlockStore::Tpm2 || !secure_boot,
                "Secure Boot binding needs the tpm2 store"
            );
            ctx.check_lockout(uid)?;
            let user = user_name(uid)?;
            let scanned = scan(ctx, &user, reader, writer).await;
            ctx.record(uid, scanned.is_ok());
            scanned?;
            let path = ctx.file(uid, id, *store);
            let dir = path.parent().context("no credential directory")?;
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(
                dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )?;
            // Never keep a credential in two stores at once.
            for other in [UnlockStore::Tpm2, UnlockStore::File] {
                if other != *store {
                    let _ = std::fs::remove_file(ctx.file(uid, id, other));
                }
            }
            match store {
                UnlockStore::Tpm2 => {
                    rbw::creds::encrypt(
                        rbw::creds::Scope::System,
                        &credential_name(uid, id),
                        password.as_bytes(),
                        *secure_boot,
                        &path,
                    )
                    .await?;
                }
                _ => rbw::creds::write_private(&path, password.as_bytes())?,
            }
            Ok(Event::Done {
                password: None,
                enrolled: Some(true),
            })
        }
        Request::Unlock { .. } => {
            let (store, path) = ctx
                .find(uid, id)
                .context("no credential is enrolled under this id")?;
            ctx.check_lockout(uid)?;
            let user = user_name(uid)?;
            let scanned = scan(ctx, &user, reader, writer).await;
            ctx.record(uid, scanned.is_ok());
            scanned?;
            let bytes = if store == UnlockStore::Tpm2 {
                rbw::creds::decrypt(
                    rbw::creds::Scope::System,
                    &credential_name(uid, id),
                    &path,
                )
                .await?
            } else {
                rbw::creds::read_private(&path)?
            };
            let password = rbw::desktop::credential_string(&bytes)?;
            Ok(Event::Done {
                password: Some(password),
                enrolled: None,
            })
        }
    }
}

fn describe(request: &Request) -> &'static str {
    match request {
        Request::Enroll { .. } => "enroll",
        Request::Unlock { .. } => "unlock",
        Request::Remove { .. } => "remove",
        Request::Status { .. } => "status",
    }
}

pub async fn handle(
    ctx: &Context,
    stream: tokio::net::UnixStream,
    uid: u32,
    pid: Option<i32>,
) {
    let exe = pid
        .and_then(|pid| std::fs::read_link(format!("/proc/{pid}/exe")).ok())
        .map_or_else(|| "?".to_string(), |path| path.display().to_string());
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let request =
        tokio::time::timeout(REQUEST_TIMEOUT, read_line(&mut reader))
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for a request"))
            .and_then(|line| line?.context("empty request"))
            .and_then(|line| {
                serde_json::from_slice::<Request>(&line)
                    .context("invalid request")
            });
    let (op, event) = match request {
        Ok(request) => (
            describe(&request),
            handle_request(ctx, uid, &request, &mut reader, &mut writer)
                .await,
        ),
        Err(error) => ("?", Err(error)),
    };
    match &event {
        Ok(_) => log::info!("uid={uid} pid={pid:?} exe={exe} op={op}: ok"),
        Err(error) => {
            log::warn!("uid={uid} pid={pid:?} exe={exe} op={op}: {error:#}");
        }
    }
    let event = event.unwrap_or_else(|error| Event::Error {
        message: format!("{error:#}"),
    });
    let _ = send(&mut writer, &event).await;
    let _ = writer.shutdown().await;
}

// The socket systemd passed us (socket activation), else one we bind.
fn listener() -> anyhow::Result<tokio::net::UnixListener> {
    use std::os::fd::FromRawFd as _;
    let activated = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok())
        == Some(std::process::id())
        && std::env::var("LISTEN_FDS").ok().as_deref() == Some("1");
    let listener = if activated {
        // SAFETY: systemd hands over fd 3 as the listening socket.
        unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) }
    } else {
        let path = rbw::unlockd::socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path)
            .with_context(|| {
                format!("could not listen on {}", path.display())
            })?;
        std::fs::set_permissions(
            &path,
            std::os::unix::fs::PermissionsExt::from_mode(0o666),
        )?;
        listener
    };
    listener.set_nonblocking(true)?;
    Ok(tokio::net::UnixListener::from_std(listener)?)
}

pub async fn run() -> anyhow::Result<()> {
    anyhow::ensure!(
        rustix::process::geteuid().is_root(),
        "rbw-unlockd must run as root to keep credentials from the users it serves"
    );
    let state_dir = std::env::var("STATE_DIRECTORY")
        .ok()
        .and_then(|dirs| dirs.split(':').next().map(std::path::PathBuf::from))
        .unwrap_or_else(|| DEFAULT_STATE_DIR.into());
    std::fs::create_dir_all(&state_dir)?;
    std::fs::set_permissions(
        &state_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let ctx = Arc::new(Context::new(state_dir, Box::new(Fprintd)));
    let listener = listener()?;
    log::info!("rbw-unlockd ready");
    loop {
        let (stream, _) = listener.accept().await?;
        let credentials = match stream.peer_cred() {
            Ok(credentials) => credentials,
            Err(error) => {
                log::warn!("could not identify a client: {error}");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            handle(&ctx, stream, credentials.uid(), credentials.pid()).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(bool);

    impl Verifier for Fake {
        fn verify<'a>(
            &'a self,
            _user: &'a str,
            feedback: &'a tokio::sync::watch::Sender<FingerprintStatus>,
            _cancel: Cancel<'a>,
        ) -> Verified<'a> {
            Box::pin(async move {
                feedback.send_replace(FingerprintStatus::Ready);
                tokio::task::yield_now().await;
                anyhow::ensure!(self.0, "fingerprint did not match");
                Ok(())
            })
        }
    }

    const ID: &str = "343950a5-866a-44a7-af6f-b495014ec4bb";

    async fn request(ctx: &Context, request: &Request) -> Vec<Event> {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let uid = rustix::process::getuid().as_raw();
        let (mut reader, mut writer) = client.into_split();
        writer
            .write_all(&encode_line(request).unwrap())
            .await
            .unwrap();
        let task = async { handle(ctx, server, uid, None).await };
        let read = async {
            let mut out = Vec::new();
            reader.read_to_end(&mut out).await.unwrap();
            out
        };
        let ((), out) = tokio::join!(task, read);
        out.split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    fn enroll(password: &str) -> Request {
        Request::Enroll {
            id: ID.to_string(),
            store: UnlockStore::File,
            secure_boot: false,
            password: password.to_string(),
        }
    }

    #[tokio::test]
    async fn enroll_unlock_and_remove_need_a_finger() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::new(dir.path().into(), Box::new(Fake(true)));
        let events = request(&ctx, &enroll("hunter2")).await;
        assert!(
            matches!(
                events.last(),
                Some(Event::Done {
                    enrolled: Some(true),
                    ..
                })
            ),
            "{events:?}"
        );
        let events =
            request(&ctx, &Request::Unlock { id: ID.to_string() }).await;
        assert!(
            matches!(events.first(), Some(Event::Status { .. })),
            "{events:?}"
        );
        assert!(
            matches!(events.last(), Some(Event::Done { password: Some(p), .. }) if p == "hunter2"),
            "{events:?}"
        );
        let events =
            request(&ctx, &Request::Remove { id: ID.to_string() }).await;
        assert!(matches!(events.last(), Some(Event::Done { .. })));
        let events =
            request(&ctx, &Request::Status { id: ID.to_string() }).await;
        assert!(matches!(
            events.last(),
            Some(Event::Done {
                enrolled: Some(false),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn failed_scans_release_nothing_and_lock_out() {
        let dir = tempfile::tempdir().unwrap();
        let good = Context::new(dir.path().into(), Box::new(Fake(true)));
        request(&good, &enroll("hunter2")).await;
        let ctx = Context::new(dir.path().into(), Box::new(Fake(false)));
        for _ in 0..=FREE_FAILURES {
            let events =
                request(&ctx, &Request::Unlock { id: ID.to_string() }).await;
            assert!(
                matches!(events.last(), Some(Event::Error { .. })),
                "{events:?}"
            );
            assert!(!events.iter().any(|e| matches!(e, Event::Done { .. })));
        }
        let events =
            request(&ctx, &Request::Unlock { id: ID.to_string() }).await;
        assert!(
            matches!(events.last(), Some(Event::Error { message }) if message.contains("too many")),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn bad_ids_and_keyring_store_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context::new(dir.path().into(), Box::new(Fake(true)));
        let events = request(
            &ctx,
            &Request::Unlock {
                id: "../x".to_string(),
            },
        )
        .await;
        assert!(matches!(events.last(), Some(Event::Error { .. })));
        let events = request(
            &ctx,
            &Request::Enroll {
                id: ID.to_string(),
                store: UnlockStore::Keyring,
                secure_boot: false,
                password: "pw".to_string(),
            },
        )
        .await;
        assert!(matches!(events.last(), Some(Event::Error { .. })));
        let events =
            request(&ctx, &Request::Unlock { id: ID.to_string() }).await;
        assert!(
            matches!(events.last(), Some(Event::Error { message }) if message.contains("no credential")),
            "{events:?}"
        );
    }

    #[test]
    fn lockout_grows_and_caps() {
        let now = Instant::now();
        let failures = |count| Failures {
            count,
            last: Some(now),
        };
        assert!(failures(FREE_FAILURES - 1).locked_for(now).is_none());
        assert_eq!(
            failures(FREE_FAILURES).locked_for(now),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            failures(FREE_FAILURES + 1).locked_for(now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            failures(FREE_FAILURES + 20).locked_for(now),
            Some(MAX_LOCKOUT)
        );
    }
}
