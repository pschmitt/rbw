//! Credentials sealed with `systemd-creds` for the `tpm2` unlock store.
//!
//! They are sealed to this machine's TPM and host key. Per-user credentials
//! (`Scope::User`) go through systemd's credential service and only decrypt
//! for the same user; rbw-unlockd seals system-scope credentials as root.

use anyhow::Context as _;
use tokio::io::AsyncWriteExt as _;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    System,
}

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn command(scope: Scope) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("systemd-creds");
    if scope == Scope::User {
        command.arg("--user");
    }
    command
        .env_remove("SYSTEMD_CREDENTIAL_SECRET")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    command
}

fn failure(action: &str, output: &std::process::Output) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::anyhow!(
        "systemd-creds {action} failed ({}): {}",
        output.status,
        stderr.trim()
    )
}

/// Seals `secret` into `path` with the TPM and host key, embedding `name` so
/// the file only decrypts under that name. `secure_boot` also binds it to
/// PCR 7 (the Secure Boot policy).
pub async fn encrypt(
    scope: Scope,
    name: &str,
    secret: &[u8],
    secure_boot: bool,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    let mut command = command(scope);
    command
        .arg("encrypt")
        .arg("--with-key=host+tpm2")
        .arg(format!("--name={name}"));
    if secure_boot {
        command.arg("--tpm2-pcrs=7");
    }
    let mut child = command
        .arg("-")
        .arg(path)
        .spawn()
        .context("could not run systemd-creds; is systemd installed?")?;
    let mut stdin =
        child.stdin.take().context("systemd-creds has no stdin")?;
    stdin.write_all(secret).await?;
    drop(stdin);
    let output = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .context("systemd-creds encrypt timed out")??;
    if !output.status.success() {
        return Err(failure("encrypt", &output));
    }
    Ok(())
}

/// Decrypts a credential sealed by `encrypt` under the same `name`.
pub async fn decrypt(
    scope: Scope,
    name: &str,
    path: &std::path::Path,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let child = command(scope)
        .arg("decrypt")
        .arg(format!("--name={name}"))
        .arg(path)
        .arg("-")
        .stdin(std::process::Stdio::null())
        .spawn()
        .context("could not run systemd-creds; is systemd installed?")?;
    let mut output = tokio::time::timeout(TIMEOUT, child.wait_with_output())
        .await
        .context("systemd-creds decrypt timed out")??;
    let secret = Zeroizing::new(std::mem::take(&mut output.stdout));
    if !output.status.success() {
        return Err(failure("decrypt", &output));
    }
    Ok(secret)
}

/// Writes `secret` to `path` readable only by its owner, replacing any
/// existing file atomically.
pub fn write_private(
    path: &std::path::Path,
    secret: &[u8],
) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = path.parent().context("credential path has no directory")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("could not create {}", dir.display()))?;
    std::fs::set_permissions(
        dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let temp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("could not write {}", temp.display()))?;
    file.write_all(secret)?;
    file.sync_all()?;
    std::fs::rename(&temp, path)
        .with_context(|| format!("could not write {}", path.display()))
}

/// Reads a file written by `write_private`, refusing one that others could
/// read or write.
pub fn read_private(
    path: &std::path::Path,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    let shared = metadata.mode() & 0o077;
    anyhow::ensure!(
        shared == 0,
        "{} is accessible by other users; refusing to use it",
        path.display()
    );
    std::fs::read(path)
        .map(Zeroizing::new)
        .with_context(|| format!("could not read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, read_private, write_private, Scope};

    // Seals and unseals a disposable value with the real TPM: per-user, and
    // system-wide (as rbw-unlockd does) when run as root.
    #[tokio::test]
    #[ignore = "requires systemd-creds and a TPM"]
    async fn live_tpm2_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let scope = if rustix::process::geteuid().is_root() {
            Scope::System
        } else {
            Scope::User
        };
        for secure_boot in [false, true] {
            let path = dir.path().join(format!("{secure_boot}.cred"));
            encrypt(scope, "rbw-test", b"disposable", secure_boot, &path)
                .await
                .unwrap();
            assert_eq!(
                decrypt(scope, "rbw-test", &path).await.unwrap().as_slice(),
                b"disposable"
            );
            assert!(decrypt(scope, "other-name", &path).await.is_err());
        }
    }

    #[test]
    fn private_files_round_trip_and_reject_loose_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unlock").join("id.secret");
        write_private(&path, b"secret").unwrap();
        assert_eq!(read_private(&path).unwrap().as_slice(), b"secret");
        write_private(&path, b"replaced").unwrap();
        assert_eq!(read_private(&path).unwrap().as_slice(), b"replaced");
        std::fs::set_permissions(
            &path,
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        assert!(read_private(&path).is_err());
    }
}
