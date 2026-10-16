//! Reuse CLI import/export formats against the same agent. No vault data is
//! returned to the browser or exposed through process arguments.
use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::{ensure, Context as _};
use serde_json::{json, Value};

use crate::{actions, commands};

fn command() -> anyhow::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .env_remove("RUST_LOG")
        .env_remove("RBW_EXPORT_PASSPHRASE")
        .env_remove("RBW_ACCOUNT");
    if let Some(account) = actions::current_account() {
        command.arg("--account").arg(account);
    }
    command.stdout(Stdio::null()).stderr(Stdio::piped());
    Ok(command)
}

pub fn export(
    format: &str,
    password: Option<&str>,
    attachments: bool,
) -> anyhow::Result<Value> {
    ensure!(
        [
            "bitwarden-encrypted-json",
            "bitwarden-json",
            "bitwarden-zip",
            "bitwarden-csv",
            "rbw"
        ]
        .contains(&format),
        "invalid export format"
    );
    if format == "bitwarden-encrypted-json" {
        ensure!(
            password.is_some_and(|p| !p.is_empty()),
            "export password required"
        );
    }
    let downloads = directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(std::path::Path::to_owned))
        .context("no Downloads directory configured")?;
    std::fs::create_dir_all(&downloads)?;
    let file = tempfile::NamedTempFile::new_in(&downloads)?;
    let mut child = command()?;
    child
        .arg("export")
        .arg("--format")
        .arg(format)
        .arg("--output")
        .arg(file.path())
        .stdin(Stdio::null());
    if attachments {
        child.arg("--attachments");
    }
    if let Some(password) = password {
        child.env("RBW_EXPORT_PASSPHRASE", password);
    }
    ensure!(child.output()?.status.success(), "export failed");
    let extension = if format == "bitwarden-zip" {
        "zip"
    } else if format == "bitwarden-csv" {
        "csv"
    } else {
        "json"
    };
    let destination = downloads.join(format!(
        "rbw-export-{}.{}",
        uuid::Uuid::new_v4(),
        extension
    ));
    file.persist_noclobber(&destination)?;
    Ok(json!({"path": destination.to_string_lossy()}))
}

pub fn import(
    transfers: &mut super::attachments::Transfers,
    token: &str,
    password: Option<&str>,
    overwrite: bool,
) -> anyhow::Result<Value> {
    let (bytes, _) = transfers.take(token)?;
    let mut child = command()?;
    child.arg("import").stdin(Stdio::piped());
    if overwrite {
        child.arg("--overwrite");
    }
    if let Some(password) = password {
        child
            .arg("--decrypt")
            .env("RBW_EXPORT_PASSPHRASE", password);
    }
    let mut child = child.spawn()?;
    let outcome = child
        .stdin
        .take()
        .context("missing import input")?
        .write_all(&bytes);
    let result = child.wait_with_output()?;
    if result.status.code() == Some(2) {
        return Err(commands::write_committed_error(anyhow::anyhow!(
            "partial import"
        )));
    }
    outcome?;
    ensure!(result.status.success(), "import failed");
    Ok(json!(true))
}
