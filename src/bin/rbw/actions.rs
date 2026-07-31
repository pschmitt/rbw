use std::{io::Read as _, os::unix::ffi::OsStringExt as _};

use anyhow::Context as _;

// The account every request targets, set from --account / RBW_ACCOUNT in main,
// and re-set per operation by the multi-account TUI. `None` means the primary
// account (also the default for older agents that ignore the field).
static ACCOUNT: std::sync::RwLock<Option<String>> =
    std::sync::RwLock::new(None);

pub fn set_account(account: Option<String>) {
    *ACCOUNT.write().unwrap() = account;
}

pub fn current_account() -> Option<String> {
    ACCOUNT.read().unwrap().clone()
}

// Point both the agent requests (this module) and the direct lib api calls at
// `account` (by name), or the primary account when `None`. Used by the
// multi-account TUI to route each operation to the account that owns the entry.
pub fn set_active_account(account: Option<String>) -> anyhow::Result<()> {
    set_account(account.clone());
    match account {
        Some(name) => {
            let config = rbw::config::Config::load()?;
            rbw::actions::set_client_account(config.account(Some(&name))?);
        }
        None => rbw::actions::clear_client_account(),
    }
    Ok(())
}

pub fn register(
    client_id: Option<String>,
    client_secret: Option<String>,
) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Register {
        client_id,
        client_secret,
    })
}

pub fn login(
    password: Option<String>,
    totp: Option<String>,
) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Login { password, totp })
}

pub fn unlock(password: Option<String>) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Unlock { password })
}

pub fn purge_vault(password: Option<String>) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::PurgeVault { password })
}

pub fn create_org(name: &str) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::with_account(
        get_environment(),
        current_account(),
        rbw::protocol::Action::CreateOrg {
            name: name.to_string(),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::CreateOrg { id } => Ok(id),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to create organization: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn delete_org(
    org_id: &str,
    password: Option<String>,
) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::DeleteOrg {
        org_id: org_id.to_string(),
        password,
    })
}

pub fn confirm_org_user(
    org_id: &str,
    user_id: &str,
    public_key_der_b64: &str,
) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ConfirmOrgUser {
        org_id: org_id.to_string(),
        user_id: user_id.to_string(),
        public_key_der_b64: public_key_der_b64.to_string(),
    })
}

pub fn unlocked() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&rbw::protocol::Request::with_account(
                get_environment(),
                current_account(),
                rbw::protocol::Action::CheckLock,
            ))?;

            let res = sock.recv()?;
            match res {
                rbw::protocol::Response::Ack => Ok(()),
                rbw::protocol::Response::Error { error } => {
                    Err(anyhow::anyhow!("{error}"))
                }
                _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
            }
        }
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
            ) {
                anyhow::bail!("agent not running");
            }
            Err(e.into())
        }
    }
}

pub fn sync() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Sync)
}

pub fn lock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Lock)
}

// Lock every configured account: send the request without an account so the
// agent clears all of them, regardless of --account/RBW_ACCOUNT.
pub fn lock_all() -> anyhow::Result<()> {
    simple_action_as(None, rbw::protocol::Action::Lock)
}

pub fn quit() -> anyhow::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let pid = agent_pid()?;
            sock.send(&rbw::protocol::Request::with_account(
                get_environment(),
                current_account(),
                rbw::protocol::Action::Quit,
            ))?;
            wait_for_exit(pid);
            Ok(())
        }
        Err(e) => match e.kind() {
            // if the socket doesn't exist, or the socket exists but nothing
            // is listening on it, the agent must already be not running
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

pub fn kill() -> anyhow::Result<()> {
    let pid = match agent_pid() {
        Ok(pid) => pid,
        Err(e)
            if e.downcast_ref::<std::io::Error>().is_some_and(|e| {
                e.kind() == std::io::ErrorKind::NotFound
            }) =>
        {
            return Ok(())
        }
        Err(e) => return Err(e),
    };
    match rustix::process::kill_process(pid, rustix::process::Signal::KILL) {
        Ok(()) => wait_for_exit(pid),
        Err(e) if e == rustix::io::Errno::SRCH => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

pub fn decrypt(
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    decrypt_with_attachment_key(cipherstring, entry_key, org_id, None)
}

// Like `decrypt`, but for a cipherstring wrapped in an attachment's own key
// (e.g. an attachment file name) rather than directly in the entry's key.
pub fn decrypt_with_attachment_key(
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    attachment_key: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::with_account(
        get_environment(),
        current_account(),
        rbw::protocol::Action::Decrypt {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
            attachment_key: attachment_key
                .map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Decrypt { plaintext } => Ok(plaintext),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn decrypt_batch(
    requests: Vec<rbw::protocol::DecryptRequest>,
) -> anyhow::Result<Vec<rbw::protocol::DecryptResult>> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::with_account(
        get_environment(),
        current_account(),
        rbw::protocol::Action::DecryptBatch { entries: requests },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::DecryptBatch { results } => Ok(results),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn decrypt_attachment(
    data: Vec<u8>,
    attachment_key: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::with_account(
        get_environment(),
        current_account(),
        rbw::protocol::Action::DecryptAttachment {
            data,
            attachment_key: attachment_key
                .map(std::string::ToString::to_string),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::DecryptAttachment { data } => Ok(data),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to decrypt attachment: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn encrypt_attachment(
    data: Vec<u8>,
    filename: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<(Vec<u8>, String, String)> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::with_account(
        get_environment(),
        current_account(),
        rbw::protocol::Action::EncryptAttachment {
            data,
            filename: filename.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;
    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::EncryptAttachment {
            encrypted_data,
            encrypted_key,
            encrypted_filename,
        } => Ok((encrypted_data, encrypted_key, encrypted_filename)),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to encrypt attachment: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

pub fn encrypt(
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::with_account(
        get_environment(),
        current_account(),
        rbw::protocol::Action::Encrypt {
            plaintext: plaintext.to_string(),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Encrypt { cipherstring } => Ok(cipherstring),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to encrypt: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

// Dispatches to the OSC 52 escape sequence (`crate::osc52`), the system
// clipboard (`arboard`, via the agent), or both -- per
// `rbw::config::ClipboardMechanism`. In `Auto` (the default), OSC 52 is a
// best-effort supplement: its failure (e.g. stdout isn't a terminal) is
// only surfaced if the system clipboard *also* fails, so the reported
// error stays the same as before this option existed.
pub fn clipboard_store(text: &str) -> anyhow::Result<()> {
    let mechanism = rbw::config::Config::load()
        .map(|config| config.clipboard)
        .unwrap_or_default();

    match mechanism {
        rbw::config::ClipboardMechanism::Osc52 => crate::osc52::copy(text),
        rbw::config::ClipboardMechanism::System => {
            system_clipboard_store(text)
        }
        rbw::config::ClipboardMechanism::Auto => {
            let osc52_result = crate::osc52::copy(text);
            let system_result = system_clipboard_store(text);
            if osc52_result.is_ok() || system_result.is_ok() {
                Ok(())
            } else {
                system_result
            }
        }
    }
}

fn system_clipboard_store(text: &str) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ClipboardStore {
        text: text.to_string(),
    })
}

pub fn version() -> anyhow::Result<u32> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request::with_account(
        get_environment(),
        current_account(),
        rbw::protocol::Action::Version,
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Version { version } => Ok(version),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to get version: {error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn simple_action(action: rbw::protocol::Action) -> anyhow::Result<()> {
    simple_action_as(current_account(), action)
}

fn simple_action_as(
    account: Option<String>,
    action: rbw::protocol::Action,
) -> anyhow::Result<()> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request::with_account(
        get_environment(),
        account,
        action,
    ))?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("{error}"))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {res:?}")),
    }
}

fn connect() -> anyhow::Result<crate::sock::Sock> {
    crate::sock::Sock::connect().with_context(|| {
        let log = rbw::dirs::agent_stderr_file();
        format!(
            "failed to connect to rbw-agent \
            (this often means that the agent failed to start; \
            check {} for agent logs)",
            log.display()
        )
    })
}

fn agent_pid() -> anyhow::Result<rustix::process::Pid> {
    let mut pid = String::new();
    std::fs::File::open(rbw::dirs::pid_file())?.read_to_string(&mut pid)?;
    let Some(pid) = rustix::process::Pid::from_raw(pid.trim_end().parse()?)
    else {
        anyhow::bail!("failed to read pid from pidfile");
    };
    Ok(pid)
}

fn wait_for_exit(pid: rustix::process::Pid) {
    loop {
        if rustix::process::test_kill_process(pid).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub fn get_environment() -> rbw::protocol::Environment {
    let tty = std::env::var_os("RBW_TTY").or_else(|| {
        rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .map(|p| std::ffi::OsString::from_vec(p.as_bytes().to_vec()))
    });

    let env_vars = std::env::vars_os()
        .filter(|(var_name, _)| {
            (*rbw::protocol::ENVIRONMENT_VARIABLES_OS).contains(var_name)
        })
        .collect();
    rbw::protocol::Environment::new(tty, env_vars)
}
