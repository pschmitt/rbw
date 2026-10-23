// The implementation of the `rbw` subcommands, split by area. The modules
// share one namespace: each has `pub(super)` items and `use super::*`, and
// this module re-exports them, so the rest of the binary keeps calling
// `commands::name`.
//
//   query_types, cipher_view   search/filter types, decrypted entries and their display
//   output, data_types         tables, colors, progress; entry data and editable types
//   config_cmds, native_unlock_cmds, account_cmds, session
//                              `config`, native unlock, `account`, login/unlock/sync
//   read_cmds, search_cmds, attachment_cmds, send_cmds
//                              list/get/show/search/code, attachments, sends
//   write_cmds, set_cmds, archive_cmds, security_cmds
//                              add/edit/remove/generate, `set`, archive/restore,
//                              password/KDF/key changes
//   export_cmds, import_types, file_vault, import_cmds
//                              export, import, `--from-file` vaults
//   collection_cmds            collections, organizations, move/mirror
//   history_audit, process_cmds, find, decrypt, convert
//                              history/audit, agent/process helpers, entry lookup
//                              (fzf), decryption plans, type conversions
//   tui_bridge, store, totp, inject
//                              what the TUI calls, the local db, TOTP, `inject`/`run`

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::{fmt::Write as _, io::Write as _, os::unix::ffi::OsStrExt as _};

use anyhow::Context as _;
use is_terminal::IsTerminal as _;

/// A remote write succeeded; repeating it can overwrite data or create duplicates.
#[derive(Debug)]
struct WriteCommitted;

impl std::fmt::Display for WriteCommitted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a server write succeeded, but follow-up work failed; run `rbw sync` and inspect the vault before retrying")
    }
}
impl std::error::Error for WriteCommitted {}

pub fn write_committed_error(err: anyhow::Error) -> anyhow::Error {
    err.context(WriteCommitted)
}

pub fn exit_status(err: &anyhow::Error) -> i32 {
    if err.is::<WriteCommitted>() {
        2
    } else {
        1
    }
}

pub fn after_server_write(
    db: &mut rbw::db::Db,
    tokens: Option<rbw::actions::RefreshedTokens>,
) -> anyhow::Result<()> {
    if let Some(tokens) = tokens {
        db.access_token = Some(tokens.access_token);
        if let Some(refresh_token) = tokens.refresh_token {
            db.refresh_token = Some(refresh_token);
        }
        save_db(db).context(WriteCommitted)?;
    }
    crate::actions::sync().context(WriteCommitted)?;
    *db = load_db().context(WriteCommitted)?;
    Ok(())
}

fn after_editor<T>(
    contents: &str,
    interactive: bool,
    result: anyhow::Result<T>,
) -> anyhow::Result<T> {
    result.map_err(|err| {
        if !interactive || err.is::<WriteCommitted>() {
            return err;
        }
        match rbw::edit::save_unsaved(contents) {
            Ok(path) => err.context(format!(
                "unsaved plaintext edit kept in {}; delete it after recovery",
                path.display()
            )),
            Err(save_err) => err.context(format!(
                "could not preserve unsaved edit: {save_err}"
            )),
        }
    })
}

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

const MISSING_CONFIG_HELP: &str =
    "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        rbw config set baseUrl <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
    rbw config set identityUrl <url>\n";

const EXPORT_PASSPHRASE_ENV: &str = "RBW_EXPORT_PASSPHRASE";

struct RestoreEcho {
    fd: std::os::fd::RawFd,
    original: libc::termios,
}

impl Drop for RestoreEcho {
    fn drop(&mut self) {
        let _ = tcsetattr(self.fd, &self.original);
    }
}

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod query_types;
pub use query_types::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod cipher_view;
pub use cipher_view::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod output;
#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
use output::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod data_types;
pub use data_types::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod config_cmds;
pub use config_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod native_unlock_cmds;
pub use native_unlock_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod account_cmds;
pub use account_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod session;
pub use session::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod read_cmds;
pub use read_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod attachment_cmds;
pub use attachment_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod send_cmds;
pub use send_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod search_cmds;
pub use search_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod write_cmds;
pub use write_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod security_cmds;
pub use security_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod archive_cmds;
pub use archive_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod set_cmds;
pub use set_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod export_cmds;
pub use export_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod import_types;
pub use import_types::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod file_vault;
pub use file_vault::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod import_cmds;
pub use import_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod collection_cmds;
pub use collection_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod history_audit;
pub use history_audit::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod process_cmds;
pub use process_cmds::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod find;
pub use find::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod decrypt;
pub use decrypt::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod convert;
pub use convert::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod tui_bridge;
pub use tui_bridge::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod store;
pub use store::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod totp;
pub use totp::*;

#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
mod inject;
#[allow(
    clippy::wildcard_imports,
    reason = "the command modules share one namespace, as they did in a single file"
)]
use inject::*;

#[cfg(test)]
mod test;
