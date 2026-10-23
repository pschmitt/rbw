//! Unlock UI: only public status and a constant mask reach render buffers.
//! Password input has no Debug implementation and is kept in locked memory.
#[cfg(feature = "gtk-ui")]
mod gtk;
mod terminal;

use anyhow::Context as _;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch};

#[derive(Clone, Copy)]
pub struct Options {
    pub mode: crate::config::UnlockUi,
    pub no_echo: bool,
}

// Keep logging from any background task off the interactive display. The
// guard is created before the frontend, so the frontend restores the terminal
// before logging is re-enabled on success, errors, or cancellation.
struct QuietLogs(log::LevelFilter);
impl QuietLogs {
    fn new() -> Self {
        let previous = log::max_level();
        log::set_max_level(log::LevelFilter::Off);
        Self(previous)
    }
}
impl Drop for QuietLogs {
    fn drop(&mut self) {
        log::set_max_level(self.0);
    }
}

pub type Validator =
    Arc<dyn Fn(&crate::locked::Password) -> anyhow::Result<()> + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintStatus {
    Disabled,
    Starting,
    Ready,
    Selected(&'static str),
    Retry,
    NoMatch,
    Checking,
    Accepted,
    Unavailable,
}

const FINGERS: [(&str, &str); 10] = [
    ("left-thumb", "Touch the reader with your left thumb"),
    ("right-thumb", "Touch the reader with your right thumb"),
    (
        "left-index-finger",
        "Touch the reader with your left index finger",
    ),
    (
        "right-index-finger",
        "Touch the reader with your right index finger",
    ),
    (
        "left-middle-finger",
        "Touch the reader with your left middle finger",
    ),
    (
        "right-middle-finger",
        "Touch the reader with your right middle finger",
    ),
    (
        "left-ring-finger",
        "Touch the reader with your left ring finger",
    ),
    (
        "right-ring-finger",
        "Touch the reader with your right ring finger",
    ),
    (
        "left-little-finger",
        "Touch the reader with your left little finger",
    ),
    (
        "right-little-finger",
        "Touch the reader with your right little finger",
    ),
];

impl FingerprintStatus {
    pub fn selected(finger: &str) -> Self {
        FINGERS
            .iter()
            .find(|(name, _)| *name == finger)
            .map_or(Self::Ready, |(_, text)| Self::Selected(text))
    }

    /// The status as rbw-unlockd sends it: a kind, plus the fprintd finger
    /// name for `selected`.
    pub fn to_wire(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::Disabled => ("disabled", None),
            Self::Starting => ("starting", None),
            Self::Ready => ("ready", None),
            Self::Selected(text) => (
                "selected",
                FINGERS
                    .iter()
                    .find(|(_, t)| *t == text)
                    .map(|(name, _)| *name),
            ),
            Self::Retry => ("retry", None),
            Self::NoMatch => ("no_match", None),
            Self::Checking => ("checking", None),
            Self::Accepted => ("accepted", None),
            Self::Unavailable => ("unavailable", None),
        }
    }

    pub fn from_wire(kind: &str, finger: Option<&str>) -> Self {
        match kind {
            "disabled" => Self::Disabled,
            "starting" => Self::Starting,
            "selected" => Self::selected(finger.unwrap_or("")),
            "retry" => Self::Retry,
            "no_match" => Self::NoMatch,
            "checking" => Self::Checking,
            "accepted" => Self::Accepted,
            "unavailable" => Self::Unavailable,
            _ => Self::Ready,
        }
    }

    pub const fn text(self) -> &'static str {
        match self {
            Self::Disabled => "Fingerprint not configured.",
            Self::Starting => "Connecting to fingerprint reader…",
            Self::Ready => "Touch the reader with any enrolled finger",
            Self::Selected(message) => message,
            Self::Retry => "Lift your finger, then try a fresh scan",
            Self::NoMatch => "Not recognized. Try your finger again",
            Self::Checking => "Fingerprint matched. Checking vault access…",
            Self::Accepted => "Fingerprint verified",
            Self::Unavailable => "Fingerprint unavailable.",
        }
    }
}

pub struct SecretInput {
    bytes: crate::locked::Vec,
}

impl SecretInput {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            bytes: crate::locked::Vec::try_new()
                .context("could not lock password input memory")?,
        })
    }
    pub fn char_count(&self) -> usize {
        self.bytes
            .data()
            .iter()
            .filter(|byte| **byte & 0xc0 != 0x80)
            .count()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.data().is_empty()
    }
    pub fn push(&mut self, byte: u8) -> bool {
        if self.bytes.data().len() == crate::locked::CAPACITY {
            return false;
        }
        self.bytes.extend(std::iter::once(byte));
        true
    }
    pub fn clear(&mut self) {
        self.bytes.truncate(0);
    }
    pub fn backspace(&mut self) {
        let data = self.bytes.data();
        if let Some(mut index) = data.len().checked_sub(1) {
            while index > 0 && data[index] & 0xc0 == 0x80 {
                index -= 1;
            }
            self.bytes.truncate(index);
        }
    }
    pub fn take(&mut self) -> anyhow::Result<crate::locked::Password> {
        let next = crate::locked::Vec::try_new()
            .context("could not lock password input memory")?;
        Ok(crate::locked::Password::new(std::mem::replace(
            &mut self.bytes,
            next,
        )))
    }
}

pub(crate) enum Action {
    Submit(crate::locked::Password),
    Cancel,
}

pub(crate) struct View<'a> {
    pub title: &'a str,
    pub fingerprint: FingerprintStatus,
    pub checking: bool,
    pub success: bool,
    pub error: Option<&'static str>,
    pub tick: u64,
}

pub(crate) trait Frontend {
    fn poll(&mut self) -> anyhow::Result<Option<Action>>;
    fn render(&mut self, view: &View<'_>) -> anyhow::Result<()>;
    fn clear_secret(&mut self);
}

#[allow(
    clippy::future_not_send,
    reason = "the frontend stays on the UI thread"
)]
async fn show_confirmation(
    frontend: &mut dyn Frontend,
    title: &str,
    fingerprint: FingerprintStatus,
) -> anyhow::Result<()> {
    frontend.clear_secret();
    let until = Instant::now() + Duration::from_millis(450);
    let mut tick = 0;
    while Instant::now() < until {
        frontend.render(&View {
            title,
            fingerprint,
            checking: false,
            success: true,
            error: None,
            tick,
        })?;
        // Pump GTK events while showing the noninteractive confirmation.
        let _ = frontend.poll()?;
        tick += 1;
        tokio::time::sleep(Duration::from_millis(16)).await;
    }
    Ok(())
}

pub fn resolve(
    mode: crate::config::UnlockUi,
) -> anyhow::Result<crate::config::UnlockUi> {
    use crate::config::UnlockUi;
    use std::io::IsTerminal as _;
    let mode = if mode == UnlockUi::Auto {
        if std::io::stdin().is_terminal() {
            UnlockUi::Terminal
        } else if cfg!(feature = "gtk-ui")
            && (std::env::var_os("WAYLAND_DISPLAY").is_some()
                || std::env::var_os("DISPLAY").is_some())
        {
            UnlockUi::Gtk
        } else {
            UnlockUi::Pinentry
        }
    } else {
        mode
    };
    if mode == UnlockUi::Gtk && !cfg!(feature = "gtk-ui") {
        anyhow::bail!(
            "GTK unlock requires an rbw build with the gtk-ui feature"
        );
    }
    Ok(mode)
}

/// Prevent same-user ptrace/proc memory reads and core dumps for this process.
pub(crate) fn protect_process() -> anyhow::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes a scalar argument and no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not disable process memory dumps");
    }
    Ok(())
}

#[allow(
    clippy::future_not_send,
    reason = "GTK widgets and terminal ownership stay on the calling thread"
)]
pub async fn prompt(
    options: Options,
    title: &str,
    timeout_seconds: u64,
    mut status: watch::Receiver<FingerprintStatus>,
    validate: Validator,
    mut cancel: oneshot::Receiver<()>,
    session_cancel: oneshot::Sender<()>,
) -> anyhow::Result<String> {
    protect_process()?;
    let _quiet_logs = QuietLogs::new();
    let title: String = title
        .chars()
        .filter(|character| !character.is_control())
        .take(100)
        .collect();
    let frontend: anyhow::Result<Box<dyn Frontend>> = match options.mode {
        crate::config::UnlockUi::Terminal => {
            terminal::TerminalDialog::new(options.no_echo)
                .map(|dialog| -> Box<dyn Frontend> { Box::new(dialog) })
        }
        #[cfg(feature = "gtk-ui")]
        crate::config::UnlockUi::Gtk => gtk::GtkDialog::new(options.no_echo)
            .map(|dialog| -> Box<dyn Frontend> { Box::new(dialog) }),
        _ => Err(anyhow::anyhow!("unsupported custom unlock interface")),
    };
    let mut frontend = match frontend {
        Ok(frontend) => frontend,
        Err(error) => {
            let _ = session_cancel.send(());
            return Err(error);
        }
    };
    let deadline = (timeout_seconds != 0)
        .then(|| Instant::now() + Duration::from_secs(timeout_seconds));
    let mut worker: Option<
        tokio::task::JoinHandle<anyhow::Result<crate::locked::Password>>,
    > = None;
    let mut error = None;
    let mut tick = 0;
    let mut timer = tokio::time::interval(Duration::from_millis(16));
    let mut session_cancel = Some(session_cancel);
    let result = async { loop {
        tokio::select! {
            _ = &mut cancel => {
                let fingerprint = *status.borrow_and_update();
                if fingerprint == FingerprintStatus::Accepted {
                    show_confirmation(frontend.as_mut(), &title, fingerprint).await?;
                }
                break Err(anyhow::anyhow!("unlock prompt cancelled"));
            },
            _ = timer.tick() => {},
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            if let Some(cancel) = session_cancel.take() { let _ = cancel.send(()); }
            break Err(anyhow::anyhow!("unlock prompt timed out"));
        }
        if worker.as_ref().is_some_and(tokio::task::JoinHandle::is_finished) {
            let result = worker.take().expect("worker was present").await.context("password verification worker failed")?;
            match result {
                Ok(password) => {
                    let fingerprint = *status.borrow_and_update();
                    show_confirmation(frontend.as_mut(), &title, fingerprint).await?;
                    break std::str::from_utf8(password.password()).map(str::to_owned).map_err(|_| anyhow::anyhow!("master password is not UTF-8"));
                },
                Err(failure) if matches!(failure.downcast_ref::<crate::error::Error>(), Some(crate::error::Error::IncorrectPassword { .. })) => {
                    error = Some("That password didn’t unlock the vault. Try again.");
                }
                Err(_) => {
                    error = Some("Could not verify this password. Cancel and try pinentry.");
                }
            }
        }
        match frontend.poll()? {
            Some(Action::Cancel) => {
                if let Some(cancel) = session_cancel.take() { let _ = cancel.send(()); }
                break Err(anyhow::anyhow!("unlock cancelled"));
            }
            Some(Action::Submit(password)) if worker.is_none() => {
                error = None;
                let validate = validate.clone();
                worker = Some(tokio::task::spawn_blocking(move || {
                    validate(&password)?;
                    Ok(password)
                }));
            }
            Some(Action::Submit(_)) | None => {},
        }
        frontend.render(&View { title: &title, fingerprint: *status.borrow_and_update(), checking: worker.is_some(), success: false, error, tick })?;
        tick = tick.wrapping_add(1);
    }
    } .await;
    if result.is_err() {
        if let Some(cancel) = session_cancel.take() {
            let _ = cancel.send(());
        }
    }
    frontend.clear_secret();
    // Blocking KDF work cannot safely be interrupted. Drain it before leaving
    // so its locked password allocation is wiped before the dialog returns.
    if let Some(worker) = worker {
        let _ = worker.await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires a controlling terminal and disposable test input"]
    fn live_terminal_password() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (_status, receiver) = watch::channel(FingerprintStatus::Disabled);
        let (_stop, cancel) = oneshot::channel();
        let (session_cancel, _cancelled) = oneshot::channel();
        let password = runtime
            .block_on(prompt(
                Options {
                    mode: crate::config::UnlockUi::Terminal,
                    no_echo: std::env::var_os("RBW_TEST_UI_NO_ECHO")
                        .is_some(),
                },
                "Disposable UI test",
                10,
                receiver,
                Arc::new(|password| {
                    anyhow::ensure!(
                        password.password() == b"disposable UI test input",
                        "unexpected test input"
                    );
                    Ok(())
                }),
                cancel,
                session_cancel,
            ))
            .unwrap();
        let password = zeroize::Zeroizing::new(password);
        assert_eq!(password.as_bytes(), b"disposable UI test input");
    }

    #[test]
    fn no_echo_is_opt_in_and_roundtrips() {
        let default: crate::config::Config =
            serde_yaml::from_str("{}").unwrap();
        assert!(!default.unlock_no_echo);
        let enabled: crate::config::Config =
            serde_yaml::from_str("unlockNoEcho: true").unwrap();
        assert!(enabled.unlock_no_echo);
        let restored: crate::config::Config =
            serde_yaml::from_str(&serde_yaml::to_string(&enabled).unwrap())
                .unwrap();
        assert!(restored.unlock_no_echo);
    }

    #[test]
    fn ui_modes_roundtrip_and_invalid_modes_fail() {
        for (name, mode) in [
            ("auto", crate::config::UnlockUi::Auto),
            ("terminal", crate::config::UnlockUi::Terminal),
            ("gtk", crate::config::UnlockUi::Gtk),
            ("pinentry", crate::config::UnlockUi::Pinentry),
        ] {
            assert_eq!(mode.as_str(), name);
            assert_eq!(
                serde_yaml::from_str::<crate::config::UnlockUi>(name)
                    .unwrap(),
                mode
            );
        }
        assert!(serde_yaml::from_str::<crate::config::UnlockUi>("unknown")
            .is_err());
        #[cfg(not(feature = "gtk-ui"))]
        assert!(resolve(crate::config::UnlockUi::Gtk).is_err());
    }

    #[test]
    fn unicode_backspace_and_clear_do_not_expose_input() {
        let mut input = SecretInput::new().unwrap();
        for byte in "aé🦊".bytes() {
            assert!(input.push(byte));
        }
        input.backspace();
        let password = input.take().unwrap();
        assert_eq!(password.password(), "aé".as_bytes());
        assert!(input.is_empty());
        input.push(b'x');
        input.clear();
        assert!(input.is_empty());
    }
    #[test]
    fn input_limit_is_checked_before_writing() {
        let mut input = SecretInput::new().unwrap();
        for _ in 0..crate::locked::CAPACITY {
            assert!(input.push(b'x'));
        }
        assert!(!input.push(b'x'));
        input.clear();
        assert!(input.is_empty());
    }
}
