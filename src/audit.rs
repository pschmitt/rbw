//! Local security audit events for rbw operations.

use crate::config::AuditConfig;
use anyhow::Context as _;
use fs2::FileExt as _;
use serde::Serialize;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::time::{SystemTime, UNIX_EPOCH};

/// A secret-free security event. Callers must pass only fixed operation and
/// outcome labels, never command arguments, item contents, or raw errors.
#[derive(Debug, Serialize)]
pub struct Event {
    timestamp: String,
    actor: String,
    operation: String,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_id: Option<String>,
}

impl Event {
    pub fn new(
        actor: impl Into<String>,
        operation: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: humantime::format_rfc3339(SystemTime::now())
                .to_string(),
            actor: actor.into(),
            operation: operation.into(),
            outcome: outcome.into(),
            item_id: None,
        }
    }

    /// Attach a canonical UUID target without accepting names or arbitrary
    /// route tokens as audit metadata.
    #[must_use]
    pub fn with_item_id(mut self, value: &str) -> Self {
        if let Ok(id) = uuid::Uuid::parse_str(value) {
            let canonical = id.hyphenated().to_string();
            if canonical == value {
                self.item_id = Some(canonical);
            }
        }
        self
    }
}

/// Append an event to the private, profile-scoped audit log and prune expired
/// daily files. File writes are serialized across rbw processes.
pub fn append(config: &AuditConfig, event: &Event) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let today = u32::try_from(now.as_secs() / 86_400)
        .context("current UTC day is out of audit filename range")?;
    append_at(&crate::dirs::audit_dir(), today, config, event)
}

fn append_at(
    directory: &std::path::Path,
    today: u32,
    config: &AuditConfig,
    event: &Event,
) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    crate::dirs::create_dir_all_with_permissions(directory, 0o700)?;

    let lock_path = directory.join("audit.lock");
    let lock = open_private(&lock_path, true, false)
        .context("failed to open audit log lock")?;
    std::fs::set_permissions(
        &lock_path,
        std::fs::Permissions::from_mode(0o600),
    )?;
    lock.lock_exclusive().context("failed to lock audit log")?;

    let prune_result = prune_expired(directory, today, config.retention_days);

    let path = directory.join(format!("audit-{today}.jsonl"));
    let mut file = open_private(&path, true, true)
        .context("failed to open audit log file")?;
    serde_json::to_writer(&mut file, event)
        .context("failed to serialize audit event")?;
    file.write_all(b"\n")
        .context("failed to append audit event")?;
    file.sync_data().context("failed to sync audit event")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    prune_result?;
    Ok(())
}

/// Record an event without making audit storage availability a dependency of
/// the operation being audited. Errors are reported without raw OS details.
pub fn record_best_effort(config: &AuditConfig, event: &Event) {
    if let Err(error) = append(config, event) {
        log::warn!("audit event could not be recorded: {error:#}");
    }
}

/// Record an event from an async service without blocking its executor thread.
pub async fn record_async_best_effort(config: AuditConfig, event: Event) {
    match tokio::task::spawn_blocking(move || append(&config, &event)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            log::warn!("audit event could not be recorded: {error:#}");
        }
        Err(_) => log::warn!("audit event writer task failed"),
    }
}

fn open_private(
    path: &std::path::Path,
    create: bool,
    append: bool,
) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(!append)
        .write(true)
        .create(create)
        .append(append)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn prune_expired(
    directory: &std::path::Path,
    today: u32,
    retention_days: u16,
) -> anyhow::Result<()> {
    let oldest_day =
        today.saturating_sub(u32::from(retention_days.max(1)) - 1);
    for entry in
        std::fs::read_dir(directory).context("failed to list audit files")?
    {
        let entry = entry.context("failed to read audit directory entry")?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(day) = name
            .strip_prefix("audit-")
            .and_then(|name| name.strip_suffix(".jsonl"))
            .and_then(|day| day.parse::<u32>().ok())
        else {
            continue;
        };
        if day < oldest_day {
            std::fs::remove_file(entry.path())
                .context("failed to remove expired audit file")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prunes_only_expired_regular_audit_files() {
        let directory = tempfile::tempdir().unwrap();
        for name in [
            "audit-100.jsonl",
            "audit-101.jsonl",
            "audit-102.jsonl",
            "other-100.jsonl",
        ] {
            std::fs::write(directory.path().join(name), b"event\n").unwrap();
        }

        prune_expired(directory.path(), 102, 2).unwrap();

        assert!(!directory.path().join("audit-100.jsonl").exists());
        assert!(directory.path().join("audit-101.jsonl").exists());
        assert!(directory.path().join("audit-102.jsonl").exists());
        assert!(directory.path().join("other-100.jsonl").exists());
    }

    #[test]
    fn event_serialization_contains_only_audit_metadata() {
        let event = Event {
            timestamp: "2026-11-01T00:00:00Z".to_owned(),
            actor: "cli".to_owned(),
            operation: "get".to_owned(),
            outcome: "success".to_owned(),
            item_id: None,
        };

        let serialized = serde_json::to_string(&event).unwrap();

        assert_eq!(
            serialized,
            r#"{"timestamp":"2026-11-01T00:00:00Z","actor":"cli","operation":"get","outcome":"success"}"#
        );

        assert_eq!(
            Event::new("api", "api.field_read", "success")
                .with_item_id("Item name")
                .item_id,
            None
        );
        assert_eq!(
            Event::new("api", "api.field_read", "success")
                .with_item_id("550e8400-e29b-41d4-a716-446655440000")
                .item_id
                .as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    fn enabled_config(retention_days: u16) -> AuditConfig {
        AuditConfig {
            enabled: true,
            retention_days,
        }
    }

    #[test]
    fn disabled_audit_does_not_create_storage() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("audit");
        let config = AuditConfig {
            enabled: false,
            retention_days: 15,
        };

        append_at(
            &directory,
            123,
            &config,
            &Event::new("cli", "get", "success"),
        )
        .unwrap();

        assert!(!directory.exists());
    }

    #[cfg(unix)]
    #[test]
    fn audit_files_and_lock_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("audit");

        append_at(
            &directory,
            123,
            &enabled_config(15),
            &Event::new("cli", "get", "success"),
        )
        .unwrap();

        for path in [
            directory.clone(),
            directory.join("audit.lock"),
            directory.join("audit-123.jsonl"),
        ] {
            let mode =
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, if mode == 0o700 { 0o700 } else { 0o600 });
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_audit_log_symlinks() {
        use std::os::unix::fs::symlink;
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("audit");
        std::fs::create_dir(&directory).unwrap();
        let target = parent.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        symlink(&target, directory.join("audit-123.jsonl")).unwrap();

        assert!(append_at(
            &directory,
            123,
            &enabled_config(15),
            &Event::new("cli", "get", "success")
        )
        .is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }

    #[test]
    fn concurrent_appends_keep_every_record_intact() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("audit");
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let directory = directory.clone();
                scope.spawn(move || {
                    for index in 0..20 {
                        let event = Event::new(
                            "cli",
                            format!("operation-{worker}-{index}"),
                            "success",
                        );
                        append_at(
                            &directory,
                            123,
                            &enabled_config(15),
                            &event,
                        )
                        .unwrap();
                    }
                });
            }
        });
        let content =
            std::fs::read_to_string(directory.join("audit-123.jsonl"))
                .unwrap();
        let events = content
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(events.len(), 160);
    }

    #[test]
    fn retention_is_applied_when_appending() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("audit");
        std::fs::create_dir(&directory).unwrap();
        for day in 100..=102 {
            std::fs::write(
                directory.join(format!("audit-{day}.jsonl")),
                b"old\n",
            )
            .unwrap();
        }

        append_at(
            &directory,
            102,
            &enabled_config(2),
            &Event::new("cli", "get", "success"),
        )
        .unwrap();

        assert!(!directory.join("audit-100.jsonl").exists());
        assert!(directory.join("audit-101.jsonl").exists());
        assert!(directory.join("audit-102.jsonl").exists());
    }
}
