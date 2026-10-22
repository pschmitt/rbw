use std::collections::HashMap;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::{ensure, Context as _};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};

use crate::{actions, commands};

struct Upload {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    file: std::fs::File,
    account: Option<String>,
    item: String,
    size: u64,
    received: u64,
    started: std::time::Instant,
}

#[derive(Default)]
pub struct Transfers {
    uploads: HashMap<String, Upload>,
}

impl Transfers {
    pub fn clear(&mut self) {
        self.uploads.clear();
    }
    pub fn prune(&mut self) {
        self.uploads
            .retain(|_, v| v.started.elapsed().as_secs() < 600);
    }

    pub fn begin(
        &mut self,
        db: &rbw::db::Db,
        item: &str,
        name: &str,
        size: u64,
    ) -> anyhow::Result<Value> {
        self.uploads
            .retain(|_, v| v.started.elapsed().as_secs() < 600);
        ensure!(
            self.uploads.len() < 2 && size <= 100 * 1024 * 1024,
            "upload limit exceeded"
        );
        if !item.is_empty() {
            super::entry(db, item)?;
        }
        let name = std::path::Path::new(name)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .filter(|n| !n.is_empty() && *n != "." && *n != "..")
            .context("invalid filename")?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join(name);
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        let token = uuid::Uuid::new_v4().to_string();
        self.uploads.insert(
            token.clone(),
            Upload {
                _directory: directory,
                path,
                file,
                account: actions::current_account(),
                item: item.to_owned(),
                size,
                received: 0,
                started: std::time::Instant::now(),
            },
        );
        Ok(json!(token))
    }
    /// The account an upload was started for, so its later chunks can be
    /// routed there when the extension doesn't name one.
    pub fn upload_account(&self, token: &str) -> Option<String> {
        self.uploads.get(token)?.account.clone()
    }
    pub fn chunk(
        &mut self,
        token: &str,
        offset: u64,
        data: &str,
    ) -> anyhow::Result<Value> {
        let upload = self.uploads.get_mut(token).context("upload expired")?;
        ensure!(
            upload.account == actions::current_account()
                && upload.started.elapsed().as_secs() < 600,
            "wrong upload account or expired"
        );
        let data = B64.decode(data)?;
        let len = u64::try_from(data.len())?;
        ensure!(
            data.len() <= 192 * 1024
                && offset == upload.received
                && upload.received + len <= upload.size,
            "invalid upload chunk"
        );
        upload.file.write_all(&data)?;
        upload.received += len;
        Ok(json!(upload.received))
    }
    pub fn finish(
        &mut self,
        db: &mut rbw::db::Db,
        token: &str,
    ) -> anyhow::Result<Value> {
        let mut upload =
            self.uploads.remove(token).context("upload expired")?;
        ensure!(
            upload.account == actions::current_account()
                && upload.received == upload.size
                && upload.started.elapsed().as_secs() < 600,
            "incomplete upload"
        );
        upload.file.flush()?;
        let entry = super::entry(db, &upload.item)?.clone();
        commands::tui_attachment_create(db, &entry, &upload.path)?;
        Ok(json!(true))
    }
    pub fn take(&mut self, token: &str) -> anyhow::Result<(Vec<u8>, String)> {
        let mut upload =
            self.uploads.remove(token).context("upload expired")?;
        ensure!(
            upload.item.is_empty()
                && upload.account == actions::current_account()
                && upload.received == upload.size
                && upload.started.elapsed().as_secs() < 600,
            "incomplete Send upload"
        );
        upload.file.flush()?;
        let name = upload
            .path
            .file_name()
            .context("missing file name")?
            .to_string_lossy()
            .into_owned();
        Ok((std::fs::read(&upload.path)?, name))
    }
    pub fn cancel(&mut self, token: &str) {
        self.uploads.remove(token);
    }
}

pub fn download(
    db: &mut rbw::db::Db,
    item: &str,
    attachment: &str,
) -> anyhow::Result<Value> {
    let entry = super::entry(db, item)?.clone();
    let decrypted = commands::decrypt_cipher(&entry)?;
    let temp = tempfile::tempdir()?;
    let path = commands::tui_attachment_get(
        db,
        &entry,
        &decrypted,
        attachment,
        temp.path(),
    )?;
    let downloads = directories::UserDirs::new()
        .and_then(|d| d.download_dir().map(std::path::Path::to_owned))
        .context("no downloads directory configured")?;
    std::fs::create_dir_all(&downloads)?;
    let name = path.file_name().context("missing filename")?;
    let mut output = tempfile::NamedTempFile::new_in(&downloads)?;
    std::io::copy(&mut std::fs::File::open(&path)?, &mut output)?;
    let destination = downloads.join(format!(
        "{}-{}",
        uuid::Uuid::new_v4(),
        name.to_string_lossy()
    ));
    output.persist_noclobber(&destination)?;
    Ok(json!({"path": destination.to_string_lossy()}))
}
