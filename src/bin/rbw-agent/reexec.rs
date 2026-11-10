#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

// Replacing the agent with another `rbw-agent` binary without locking
// (`Action::Reexec`, `rbw agent restart`).
//
// The running agent waits until it serves no other request (connections that
// arrive meanwhile are held, not served), writes its unlocked state into a
// memfd, and execs the new binary in place: same pid, and it keeps the
// listening socket, the held connections and the memfd open across the exec.
// The new agent reads the keys from the memfd, wipes it and carries on. The
// keys never touch the filesystem and no other process sees them.

use std::os::fd::{AsRawFd as _, FromRawFd as _};

use anyhow::Context as _;

// The first argument that makes `rbw-agent` take over from the agent that
// exec'd it, followed by `MEMFD,LISTENER[,CONNECTION...]` (fd numbers).
pub const ARG: &str = "--reexec";

const MAGIC: &[u8; 4] = b"RBWH";
// Bump when the handover layout changes. A new agent that can't read the
// handover starts locked, like a plain restart.
const FORMAT: u32 = 1;
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const NO_TIMEOUT: u64 = u64::MAX;

// Requests (and background syncs) in progress, each counted by a `Busy`.
static IN_FLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
// While a re-exec drains, connections accepted meanwhile wait here and go to
// the new agent (or are served after all if the re-exec fails).
static GATE: std::sync::Mutex<Gate> = std::sync::Mutex::new(Gate {
    draining: false,
    held: Vec::new(),
});
static LISTENER_FD: std::sync::OnceLock<std::os::fd::RawFd> =
    std::sync::OnceLock::new();

struct Gate {
    draining: bool,
    held: Vec<tokio::net::UnixStream>,
}

#[must_use]
pub struct Busy(());

impl Drop for Busy {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub fn busy() -> Busy {
    IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Busy(())
}

pub fn set_listener(listener: &tokio::net::UnixListener) {
    let _ = LISTENER_FD.set(listener.as_raw_fd());
}

// The connection to serve now, or `None` when a re-exec is draining and
// holds it for the next agent.
pub fn admit(
    stream: tokio::net::UnixStream,
) -> Option<tokio::net::UnixStream> {
    let mut gate = GATE.lock().unwrap();
    if gate.draining {
        gate.held.push(stream);
        None
    } else {
        Some(stream)
    }
}

// Stop draining and serve the held connections here after all.
fn resume(state: &std::sync::Arc<tokio::sync::Mutex<crate::state::State>>) {
    let held = {
        let mut gate = GATE.lock().unwrap();
        gate.draining = false;
        std::mem::take(&mut gate.held)
    };
    for stream in held {
        crate::agent::serve(stream, state.clone());
    }
}

// Only a binary that you or root own and nobody else can change, so the
// socket can't be used to make the agent run anything else. (A socket client
// can already decrypt everything; this keeps it from becoming code
// execution with the keys in memory.)
fn trusted_exe(exe: &str) -> anyhow::Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt as _;

    let path = std::path::Path::new(exe);
    anyhow::ensure!(path.is_absolute(), "not an absolute path: {exe}");
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("failed to resolve {exe}"))?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    anyhow::ensure!(
        name.contains("rbw-agent"),
        "{} is not an rbw-agent",
        path.display()
    );
    let uid = rustix::process::getuid().as_raw();
    let dir = path.parent().context("rbw-agent has no parent directory")?;
    for p in [path.as_path(), dir] {
        let meta = std::fs::metadata(p)
            .with_context(|| format!("failed to stat {}", p.display()))?;
        anyhow::ensure!(
            meta.uid() == 0 || meta.uid() == uid,
            "{} is owned by another user",
            p.display()
        );
        anyhow::ensure!(
            meta.mode() & 0o022 == 0,
            "{} is writable by others",
            p.display()
        );
    }
    let meta = std::fs::metadata(&path)?;
    anyhow::ensure!(
        meta.is_file() && meta.mode() & 0o100 != 0,
        "{} is not an executable file",
        path.display()
    );
    Ok(path)
}

// Wait until this request is the only one left (other requests finish,
// held connections wait).
async fn drain() -> bool {
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
    while IN_FLIGHT.load(std::sync::atomic::Ordering::SeqCst) > 1 {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    true
}

fn set_cloexec(fd: std::os::fd::RawFd, cloexec: bool) -> std::io::Result<()> {
    // SAFETY: the caller keeps `fd` open for this call.
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    rustix::io::fcntl_setfd(
        fd,
        if cloexec {
            rustix::io::FdFlags::CLOEXEC
        } else {
            rustix::io::FdFlags::empty()
        },
    )?;
    Ok(())
}

pub async fn reexec(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    exe: &str,
    client: Option<String>,
) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sock, state, exe, client);
        anyhow::bail!("replacing the agent in place needs Linux");
    }
    #[cfg(target_os = "linux")]
    {
        let exe = trusted_exe(exe)?;
        let listener =
            *LISTENER_FD.get().context("the agent socket is unknown")?;
        {
            let mut gate = GATE.lock().unwrap();
            anyhow::ensure!(
                !gate.draining,
                "the agent is already restarting"
            );
            gate.draining = true;
        }
        if !drain().await {
            resume(&state);
            anyhow::bail!(
                "the agent is busy (another request is still running); \
                 try again"
            );
        }
        let handover = write_handover(&*state.lock().await);
        let memfd = match handover {
            Ok(memfd) => memfd,
            Err(e) => {
                resume(&state);
                return Err(e);
            }
        };
        sock.send(&rbw::protocol::Response::Ack).await?;
        log::info!("agent re-executing {}", exe.display());
        record_reexec("success", client.as_deref());

        let held: Vec<std::os::fd::RawFd> = GATE
            .lock()
            .unwrap()
            .held
            .iter()
            .map(std::os::fd::AsRawFd::as_raw_fd)
            .collect();
        let inherited: Vec<std::os::fd::RawFd> =
            [memfd.as_raw_fd(), listener]
                .into_iter()
                .chain(held.iter().copied())
                .collect();
        let error = inherited
            .iter()
            .try_for_each(|fd| set_cloexec(*fd, false))
            .err()
            .unwrap_or_else(|| {
                use std::os::unix::process::CommandExt as _;
                let fds = inherited
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                // Only returns if the exec failed.
                std::process::Command::new(&exe).arg(ARG).arg(fds).exec()
            });

        log::error!("failed to re-exec {}: {error}", exe.display());
        for fd in &inherited {
            let _ = set_cloexec(*fd, true);
        }
        drop(memfd);
        record_reexec("failure", client.as_deref());
        resume(&state);
        // The client got `Ack` and waits for the connection to close; tell
        // it instead that this agent is still the old one.
        sock.send(&rbw::protocol::Response::Error {
            error: format!("failed to run {}: {error}", exe.display()),
        })
        .await?;
        Ok(())
    }
}

fn record_reexec(outcome: &'static str, client: Option<&str>) {
    if let Ok(config) = rbw::config::Config::load() {
        let mut event =
            rbw::audit::Event::new("agent", "agent.reexec", outcome)
                .with_version(env!("CARGO_PKG_VERSION"));
        if let Some(client) = client {
            event = event.with_client(client);
        }
        rbw::audit::record_best_effort(&config.audit, &event);
    }
}

// ---- the handover --------------------------------------------------------

pub struct Handover {
    // Left of the lock timeout; `None` when none was running.
    pub lock_remaining: Option<std::time::Duration>,
    pub accounts:
        std::collections::HashMap<String, crate::state::AccountKeys>,
}

// What an agent started with `ARG` takes over.
pub struct Inherited {
    pub listener: std::os::unix::net::UnixListener,
    pub connections: Vec<std::os::unix::net::UnixStream>,
    // `None` when the handover couldn't be read: the agent starts locked.
    pub handover: Option<Handover>,
}

#[cfg(target_os = "linux")]
fn write_handover(
    state: &crate::state::State,
) -> anyhow::Result<std::os::fd::OwnedFd> {
    use std::io::{Seek as _, Write as _};

    let buf = encode(state);
    let fd = rustix::fs::memfd_create(
        "rbw-agent-handover",
        rustix::fs::MemfdFlags::CLOEXEC,
    )
    .context("failed to create the handover memfd")?;
    let mut file = std::fs::File::from(fd);
    file.write_all(&buf)
        .and_then(|()| file.rewind())
        .context("failed to write the handover")?;
    Ok(file.into())
}

fn encode(state: &crate::state::State) -> zeroize::Zeroizing<Vec<u8>> {
    let mut w = Writer(zeroize::Zeroizing::new(Vec::with_capacity(16384)));
    w.bytes_raw(MAGIC);
    w.u32(FORMAT);
    w.u64(state.timeout.remaining().map_or(NO_TIMEOUT, |left| {
        u64::try_from(left.as_millis()).unwrap_or(NO_TIMEOUT - 1)
    }));
    w.len(state.accounts.len());
    for (name, keys) in &state.accounts {
        w.bytes(name.as_bytes());
        w.opt(keys.priv_key.as_ref().map(rbw::locked::Keys::as_bytes));
        match &keys.org_keys {
            None => w.u8(0),
            Some(org_keys) => {
                w.u8(1);
                w.len(org_keys.len());
                for (id, key) in org_keys {
                    w.bytes(id.as_bytes());
                    w.bytes(key.as_bytes());
                }
            }
        }
        w.opt(
            keys.rsa_private_key
                .as_ref()
                .map(rbw::locked::PrivateKey::private_key),
        );
        w.u8(u8::from(keys.master_password_reprompt_initialized));
        w.len(keys.master_password_reprompt.len());
        for hash in &keys.master_password_reprompt {
            w.bytes_raw(hash);
        }
    }
    w.0
}

struct Writer(zeroize::Zeroizing<Vec<u8>>);

impl Writer {
    fn bytes_raw(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }

    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u32(&mut self, v: u32) {
        self.bytes_raw(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.bytes_raw(&v.to_le_bytes());
    }

    fn len(&mut self, len: usize) {
        self.u32(u32::try_from(len).unwrap_or(u32::MAX));
    }

    fn bytes(&mut self, b: &[u8]) {
        self.len(b.len());
        self.bytes_raw(b);
    }

    fn opt(&mut self, b: Option<&[u8]>) {
        match b {
            None => self.u8(0),
            Some(b) => {
                self.u8(1);
                self.bytes(b);
            }
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        anyhow::ensure!(self.0.len() >= n, "handover is truncated");
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> anyhow::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }

    fn u64(&mut self) -> anyhow::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }

    fn len(&mut self) -> anyhow::Result<usize> {
        Ok(usize::try_from(self.u32()?)?)
    }

    fn bytes(&mut self) -> anyhow::Result<&'a [u8]> {
        let len = self.len()?;
        self.take(len)
    }

    fn string(&mut self) -> anyhow::Result<String> {
        Ok(std::str::from_utf8(self.bytes()?)?.to_owned())
    }

    fn locked(&mut self) -> anyhow::Result<rbw::locked::Vec> {
        let b = self.bytes()?;
        anyhow::ensure!(
            b.len() <= rbw::locked::CAPACITY,
            "handover key is too large"
        );
        let mut v = rbw::locked::Vec::new();
        v.extend(b.iter().copied());
        Ok(v)
    }

    fn opt_locked(&mut self) -> anyhow::Result<Option<rbw::locked::Vec>> {
        Ok(match self.u8()? {
            0 => None,
            _ => Some(self.locked()?),
        })
    }
}

fn decode(buf: &[u8]) -> anyhow::Result<Handover> {
    let mut r = Reader(buf);
    anyhow::ensure!(r.take(4)? == MAGIC, "not an rbw-agent handover");
    let format = r.u32()?;
    anyhow::ensure!(format == FORMAT, "unknown handover format {format}");
    let lock_remaining = match r.u64()? {
        NO_TIMEOUT => None,
        ms => Some(std::time::Duration::from_millis(ms)),
    };
    let mut accounts = std::collections::HashMap::new();
    for _ in 0..r.len()? {
        let name = r.string()?;
        let priv_key = r.opt_locked()?.map(rbw::locked::Keys::new);
        let org_keys = if r.u8()? == 0 {
            None
        } else {
            let mut org_keys = std::collections::HashMap::new();
            for _ in 0..r.len()? {
                let id = r.string()?;
                org_keys.insert(id, rbw::locked::Keys::new(r.locked()?));
            }
            Some(org_keys)
        };
        let rsa_private_key =
            r.opt_locked()?.map(rbw::locked::PrivateKey::new);
        let master_password_reprompt_initialized = r.u8()? != 0;
        let mut master_password_reprompt = std::collections::HashSet::new();
        for _ in 0..r.len()? {
            master_password_reprompt.insert(r.take(32)?.try_into()?);
        }
        accounts.insert(
            name,
            crate::state::AccountKeys {
                priv_key,
                org_keys,
                rsa_private_key,
                master_password_reprompt,
                master_password_reprompt_initialized,
            },
        );
    }
    anyhow::ensure!(r.0.is_empty(), "handover has trailing data");
    Ok(Handover {
        lock_remaining,
        accounts,
    })
}

fn read_handover(fd: std::os::fd::OwnedFd) -> anyhow::Result<Handover> {
    use std::io::Read as _;

    let mut file = std::fs::File::from(fd);
    let len = usize::try_from(file.metadata()?.len())?;
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(len));
    file.read_to_end(&mut buf)?;
    // Free the memfd's pages now rather than when the last fd closes.
    let _ = file.set_len(0);
    decode(&buf)
}

// Take over the fds named by `arg` (from `ARG`).
pub fn inherit(arg: &str) -> anyhow::Result<Inherited> {
    let fds = arg
        .split(',')
        .map(str::parse::<std::os::fd::RawFd>)
        .collect::<Result<Vec<_>, _>>()
        .context("malformed --reexec argument")?;
    let [memfd, listener, connections @ ..] = fds.as_slice() else {
        anyhow::bail!("malformed --reexec argument");
    };
    // SAFETY: the agent that exec'd us passed these fds open, for us only.
    let (memfd, listener, connections) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(*memfd),
            std::os::unix::net::UnixListener::from_raw_fd(*listener),
            connections
                .iter()
                .map(|fd| std::os::unix::net::UnixStream::from_raw_fd(*fd))
                .collect::<Vec<_>>(),
        )
    };
    for fd in std::iter::once(listener.as_raw_fd())
        .chain(connections.iter().map(std::os::fd::AsRawFd::as_raw_fd))
    {
        set_cloexec(fd, true)?;
    }
    let handover = read_handover(memfd)
        .inspect_err(|e| {
            log::warn!("starting locked, can't read the handover: {e:#}");
        })
        .ok();
    Ok(Inherited {
        listener,
        connections,
        handover,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked(b: &[u8]) -> rbw::locked::Vec {
        let mut v = rbw::locked::Vec::new();
        v.extend(b.iter().copied());
        v
    }

    #[tokio::test]
    async fn handover_roundtrips_every_account() {
        let (timeout, _timer) = crate::timeout::Timeout::new();
        let (sync_timeout, _sync) = crate::timeout::Timeout::new();
        let mut state = crate::state::State {
            accounts: std::collections::HashMap::new(),
            timeout,
            timeout_duration: std::time::Duration::from_secs(3600),
            sync_timeout,
            sync_timeout_duration: std::time::Duration::ZERO,
            notifications_handler: crate::notifications::Handler::new(),
            last_environment: rbw::protocol::Environment::from_process(None),
            #[cfg(feature = "clipboard")]
            clipboard: None,
        };
        state.set_unlocked(
            "work",
            rbw::locked::Keys::new(locked(&[7; 64])),
            std::collections::HashMap::from([(
                "org".to_owned(),
                rbw::locked::Keys::new(locked(&[9; 64])),
            )]),
            rbw::locked::PrivateKey::new(locked(&[3; 1200])),
        );
        state.account_mut("work").master_password_reprompt =
            std::collections::HashSet::from([[1; 32], [2; 32]]);
        state
            .account_mut("work")
            .master_password_reprompt_initialized = true;
        state.account_mut("home").priv_key =
            Some(rbw::locked::Keys::new(locked(&[5; 64])));
        state.set_timeout();

        let handover = decode(&encode(&state)).unwrap();
        let left = handover.lock_remaining.unwrap();
        assert!(left > std::time::Duration::from_secs(3590));
        assert!(left <= std::time::Duration::from_secs(3600));
        let work = &handover.accounts["work"];
        assert_eq!(work.priv_key.as_ref().unwrap().as_bytes(), &[7; 64]);
        assert_eq!(
            work.org_keys.as_ref().unwrap()["org"].as_bytes(),
            &[9; 64]
        );
        assert_eq!(
            work.rsa_private_key.as_ref().unwrap().private_key(),
            &[3; 1200][..]
        );
        assert_eq!(work.master_password_reprompt.len(), 2);
        assert!(work.master_password_reprompt_initialized);
        let home = &handover.accounts["home"];
        assert!(home.org_keys.is_none() && home.rsa_private_key.is_none());
    }

    #[test]
    fn handover_rejects_garbage_and_other_formats() {
        assert!(decode(b"").is_err());
        assert!(decode(b"RBWH\x02\0\0\0").is_err());
        let mut buf = b"RBWH\x01\0\0\0".to_vec();
        buf.extend(NO_TIMEOUT.to_le_bytes());
        buf.extend(0u32.to_le_bytes());
        let handover = decode(&buf).unwrap();
        assert!(handover.lock_remaining.is_none());
        assert!(handover.accounts.is_empty());
        buf.push(0);
        assert!(decode(&buf).is_err());
    }

    #[test]
    fn only_trusted_agents_are_executed() {
        use std::os::unix::fs::PermissionsExt as _;

        assert!(trusted_exe("rbw-agent").is_err());
        assert!(trusted_exe("/bin/sh").is_err());
        assert!(trusted_exe("/nonexistent/rbw-agent").is_err());
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("rbw-agent");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            dir.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            &exe,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(trusted_exe(exe.to_str().unwrap()).is_ok());
        std::fs::set_permissions(
            &exe,
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(trusted_exe(exe.to_str().unwrap()).is_err());
    }
}
