use crate::prelude::*;

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

pub fn make_all() -> Result<()> {
    create_dir_all_with_permissions(&cache_dir(), 0o700)?;
    create_dir_all_with_permissions(&runtime_dir(), 0o700)?;
    create_dir_all_with_permissions(&data_dir(), 0o700)?;

    Ok(())
}

pub(crate) fn create_dir_all_with_permissions(
    path: &std::path::Path,
    mode: u32,
) -> Result<()> {
    // ensure the initial directory creation happens with the correct mode,
    // to avoid race conditions
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    // but also make sure to forcibly set the mode, in case the directory
    // already existed
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    Ok(())
}

pub fn config_file() -> std::path::PathBuf {
    config_file_in(&config_dir())
}

pub fn config_yaml_file() -> std::path::PathBuf {
    config_dir().join("config.yaml")
}

fn config_file_in(dir: &std::path::Path) -> std::path::PathBuf {
    let yaml = dir.join("config.yaml");
    let json = dir.join("config.json");
    if yaml.exists() || !json.exists() {
        yaml
    } else {
        json
    }
}

const INVALID_PATH: &percent_encoding::AsciiSet =
    &percent_encoding::CONTROLS.add(b'/').add(b'%').add(b':');
pub fn db_file(server: &str, email: &str) -> std::path::PathBuf {
    let server =
        percent_encoding::percent_encode(server.as_bytes(), INVALID_PATH)
            .to_string();
    cache_dir().join(format!("{server}:{email}.json"))
}

pub fn pid_file() -> std::path::PathBuf {
    runtime_dir().join("pidfile")
}

pub fn agent_stdout_file() -> std::path::PathBuf {
    data_dir().join("agent.out")
}

pub fn agent_stderr_file() -> std::path::PathBuf {
    data_dir().join("agent.err")
}

pub fn device_id_file() -> std::path::PathBuf {
    data_dir().join("device_id")
}

/// Directory for rbw's generated remote API CA, server certificate and client credentials.
pub fn remote_api_dir() -> std::path::PathBuf {
    data_dir().join("remote-api")
}

/// Directory for rbw's local security audit log.
pub fn audit_dir() -> std::path::PathBuf {
    data_dir().join("audit")
}

pub fn socket_file() -> std::path::PathBuf {
    runtime_dir().join("socket")
}

pub fn ssh_agent_socket_file() -> std::path::PathBuf {
    runtime_dir().join("ssh-agent-socket")
}

fn config_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.config_dir().to_path_buf()
}

fn cache_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.cache_dir().to_path_buf()
}

fn data_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.data_dir().to_path_buf()
}

fn runtime_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs
        .runtime_dir()
        .map(std::path::Path::to_path_buf)
        .or_else(session_runtime_dir)
        .unwrap_or_else(|| {
            format!(
                "{}/{}-{}",
                std::env::temp_dir().to_string_lossy(),
                profile(),
                rustix::process::getuid().as_raw()
            )
            .into()
        })
}

// Without `XDG_RUNTIME_DIR` (cron, `ssh host rbw ...`, a system service),
// the user's own runtime directory when systemd-logind keeps one: so such a
// caller talks to the agent the desktop session already unlocked instead of
// starting a second one in the temp directory.
#[cfg(not(target_os = "android"))]
#[allow(clippy::verbose_bit_mask)] // "no group/other bits" reads clearer
fn session_runtime_dir() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt as _;

    let uid = rustix::process::getuid().as_raw();
    let dir = std::path::PathBuf::from(format!("/run/user/{uid}"));
    let meta = std::fs::metadata(&dir).ok()?;
    (meta.is_dir() && meta.uid() == uid && meta.mode() & 0o077 == 0)
        .then(|| dir.join(profile()))
}

// Termux has no `/run/user`; its sessions set `TMPDIR` to `$PREFIX/tmp`,
// which the temp-directory fallback uses. Where `TMPDIR` is missing
// (Termux:Boot, the job scheduler, a bare `sh -c`), Rust's temp directory
// is `/data/local/tmp`, which apps can't write to: use the same
// `$PREFIX/tmp` path a Termux session would.
#[cfg(target_os = "android")]
fn session_runtime_dir() -> Option<std::path::PathBuf> {
    if std::env::var_os("TMPDIR").is_some() {
        return None;
    }
    termux_runtime_dir(std::env::var_os("PREFIX"))
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn termux_runtime_dir(
    prefix: Option<std::ffi::OsString>,
) -> Option<std::path::PathBuf> {
    let prefix = prefix.map_or_else(
        || std::path::PathBuf::from("/data/data/com.termux/files/usr"),
        std::path::PathBuf::from,
    );
    let tmp = prefix.join("tmp");
    tmp.is_dir().then(|| {
        tmp.join(format!(
            "{}-{}",
            profile(),
            rustix::process::getuid().as_raw()
        ))
    })
}

pub fn profile() -> String {
    match std::env::var("RBW_PROFILE") {
        Ok(profile) if !profile.is_empty() => format!("rbw-{profile}"),
        _ => "rbw".to_string(),
    }
}

// A user-held native unlock credential (`tpm2` or `file` store).
pub fn unlock_credential_file(
    id: &str,
    extension: &str,
) -> std::path::PathBuf {
    data_dir().join("unlock").join(format!("{id}.{extension}"))
}

pub fn unsaved_edit_dir() -> std::path::PathBuf {
    data_dir().join("unsaved-edits")
}

#[cfg(test)]
mod tests {
    use super::config_file_in;

    #[test]
    fn yaml_config_takes_precedence_over_json() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = dir.path().join("config.yaml");
        let json = dir.path().join("config.json");

        std::fs::write(&json, "{}").unwrap();
        assert_eq!(config_file_in(dir.path()), json);

        std::fs::write(&yaml, "{}").unwrap();
        assert_eq!(config_file_in(dir.path()), yaml);
    }

    #[test]
    fn yaml_is_the_default_config_filename() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            config_file_in(dir.path()),
            dir.path().join("config.yaml")
        );
    }
}

#[test]
fn termux_runtime_dir_lives_in_prefix_tmp() {
    let prefix = tempfile::tempdir().unwrap();
    assert!(termux_runtime_dir(Some(prefix.path().into())).is_none());
    std::fs::create_dir(prefix.path().join("tmp")).unwrap();
    let dir = termux_runtime_dir(Some(prefix.path().into())).unwrap();
    assert_eq!(dir.parent().unwrap(), prefix.path().join("tmp"));
    assert!(dir
        .file_name()
        .unwrap()
        .to_string_lossy()
        .ends_with(&format!("-{}", rustix::process::getuid().as_raw())));
}
