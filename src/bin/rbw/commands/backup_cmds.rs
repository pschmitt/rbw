use super::*;

// `rbw backup DIR`: a rotated, optionally encrypted export of the active
// account into a directory -- what unattended backup jobs need, without a
// wrapper script:
//
//   DIR/bw-export-<UTC timestamp>.json          (or .tar.gz.gpg, encrypted)
//   DIR/bw-export-latest -> the newest export
//   DIR/LAST_BACKUP          unix time of the last successful backup
//
// The export is written under a temporary name and renamed into place, so a
// failed run never leaves a truncated file behind that looks like a backup.
const BACKUP_PREFIX: &str = "bw-export-";
const BACKUP_LATEST: &str = "bw-export-latest";
const BACKUP_STAMP: &str = "LAST_BACKUP";

pub fn backup(
    dir: &std::path::Path,
    retention_days: u64,
    attachments: bool,
    passphrase_file: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let c = stdout_supports_color();
    let passphrase = match passphrase_file {
        Some(file) => Some(rbw::config::FileUnlock::read(file)?),
        None => std::env::var("RBW_EXPORT_PASSPHRASE")
            .ok()
            .filter(|p| !p.is_empty()),
    };
    if passphrase.is_none() {
        eprintln!(
            "{} no passphrase given; the backup is not encrypted",
            style::warning("Warning:", c),
        );
    }

    unlock(None, None)?;
    crate::actions::sync()?;

    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;
    let now = std::time::SystemTime::now();
    let stamp = humantime::format_rfc3339_seconds(now).to_string();
    let ext = if passphrase.is_some() {
        "tar.gz.gpg"
    } else {
        "json"
    };
    let name = format!("{BACKUP_PREFIX}{stamp}.{ext}");
    let path = dir.join(&name);
    let partial = dir.join(format!(".{name}.partial"));

    let vault = build_exported_vault(attachments, None, None, false, false)?;
    let db = load_db()?;
    let written = write_exported_vault(
        crate::import_bitwarden::ExportFormat::Rbw,
        passphrase,
        Some(&partial),
        &vault,
        Some(&db),
    );
    if let Err(e) = written {
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }
    std::fs::rename(&partial, &path).with_context(|| {
        format!("failed to move the backup into place at {}", path.display())
    })?;

    let latest = dir.join(BACKUP_LATEST);
    let latest_tmp = dir.join(format!(".{BACKUP_LATEST}.tmp"));
    let _ = std::fs::remove_file(&latest_tmp);
    std::os::unix::fs::symlink(&name, &latest_tmp)?;
    std::fs::rename(&latest_tmp, &latest)?;

    let unix = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    std::fs::write(dir.join(BACKUP_STAMP), format!("{unix}\n"))?;
    eprintln!(
        "{} {} ({} entries)",
        style::success("Backed up:", c),
        path.display(),
        vault.entries.len(),
    );

    let removed = prune_backups(dir, retention_days, &name, now)?;
    if removed > 0 {
        eprintln!(
            "{} {removed} backup(s) older than {retention_days} days",
            style::section("Removed:", c),
        );
    }
    Ok(())
}

// Deletes the backups in `dir` older than `retention_days` days (0 keeps
// everything). `keep` -- the backup just written -- is never deleted, even
// with a wrong clock.
pub(super) fn prune_backups(
    dir: &std::path::Path,
    retention_days: u64,
    keep: &str,
    now: std::time::SystemTime,
) -> anyhow::Result<usize> {
    if retention_days == 0 {
        return Ok(0);
    }
    let max_age =
        std::time::Duration::from_secs(retention_days.saturating_mul(86_400));
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_backup_file_name(name) || name == keep {
            continue;
        }
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        let age = meta
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .unwrap_or_default();
        if age > max_age {
            std::fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub(super) fn is_backup_file_name(name: &str) -> bool {
    name.starts_with(BACKUP_PREFIX) && name != BACKUP_LATEST
}
