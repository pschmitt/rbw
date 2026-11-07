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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Event {
    pub timestamp: String,
    pub actor: String,
    pub operation: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
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
            item_name: None,
            account: None,
            field: None,
            origin: None,
            reason: None,
            version: None,
            client: None,
        }
    }

    /// Attach a fixed reason label (why an agent stopped, which accounts a
    /// lock cleared). Only static labels, so no caller data can reach it.
    #[must_use]
    pub fn with_reason(mut self, reason: &'static str) -> Self {
        self.reason = Some(reason.to_owned());
        self
    }

    /// Attach the program that asked for the event (the agent socket's peer,
    /// such as `rbw-2.40.0/bin/rbw`). Only path-like characters are kept, so
    /// it can't carry anything but a program name.
    #[must_use]
    pub fn with_client(mut self, client: &str) -> Self {
        let client = client
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "._+-/:".contains(*c))
            .take(128)
            .collect::<String>();
        if !client.is_empty() {
            self.client = Some(client);
        }
        self
    }

    /// Attach the version of the rbw binary that recorded the event.
    #[must_use]
    pub fn with_version(mut self, version: &'static str) -> Self {
        self.version = Some(version.to_owned());
        self
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

    /// Attach a sanitized vault item display name (never secret field values).
    #[must_use]
    pub fn with_item_name(mut self, value: &str) -> Self {
        if let Some(cleaned) = sanitize_label(value, 128) {
            self.item_name = Some(cleaned);
        }
        self
    }

    /// Attach the vault account name involved in the operation.
    #[must_use]
    pub fn with_account(mut self, value: &str) -> Self {
        if let Some(cleaned) = sanitize_label(value, 64) {
            self.account = Some(cleaned);
        }
        self
    }

    /// Attach the field name accessed on the vault item (for example
    /// `password`, `username`, `totp`, or a custom field label).
    #[must_use]
    pub fn with_field(mut self, value: &str) -> Self {
        if let Some(cleaned) = sanitize_label(value, 64) {
            self.field = Some(cleaned);
        }
        self
    }

    /// Attach a web origin (`https://example.com`) or relying-party ID
    /// (`example.com`), stripping any URL path, query string, or credentials.
    #[must_use]
    pub fn with_origin(mut self, value: &str) -> Self {
        let trimmed = value.trim();
        if let Ok(url) = url::Url::parse(trimmed) {
            if matches!(url.scheme(), "https" | "http")
                && url.host_str().is_some()
            {
                let origin = url.origin().ascii_serialization();
                if origin != "null" && origin.len() <= 128 {
                    self.origin = Some(origin);
                }
                return self;
            }
        }
        if !trimmed.is_empty()
            && trimmed.len() <= 128
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
        {
            self.origin = Some(trimmed.to_ascii_lowercase());
        }
        self
    }
}

fn sanitize_label(value: &str, max_chars: usize) -> Option<String> {
    let cleaned = value
        .chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect::<String>();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

#[derive(Default)]
struct AuditContext {
    item_id: Option<String>,
    item_name: Option<String>,
    account: Option<String>,
    field: Option<String>,
    origin: Option<String>,
}

thread_local! {
    static AUDIT_CONTEXT: std::cell::RefCell<AuditContext> =
        std::cell::RefCell::new(AuditContext::default());
}

/// Clear any thread-local audit metadata accumulated during a previous command.
pub fn clear_context() {
    AUDIT_CONTEXT.with(|ctx| *ctx.borrow_mut() = AuditContext::default());
}

/// Record resolved item metadata in the current thread's audit context.
pub fn note_item(
    account: Option<&str>,
    item_id: &str,
    item_name: Option<&str>,
) {
    AUDIT_CONTEXT.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        if let Some(account) = account.filter(|s| !s.trim().is_empty()) {
            ctx.account = Some(account.to_owned());
        }
        if !item_id.is_empty() {
            ctx.item_id = Some(item_id.to_owned());
        }
        if let Some(name) = item_name.filter(|s| !s.trim().is_empty()) {
            ctx.item_name = Some(name.to_owned());
        }
    });
}

/// Record the vault account name in the current thread's audit context.
pub fn note_account(account: &str) {
    if !account.trim().is_empty() {
        AUDIT_CONTEXT.with(|ctx| {
            ctx.borrow_mut().account = Some(account.to_owned());
        });
    }
}

/// Record the accessed field name in the current thread's audit context.
pub fn note_field(field: &str) {
    if !field.trim().is_empty() {
        AUDIT_CONTEXT.with(|ctx| {
            ctx.borrow_mut().field = Some(field.to_owned());
        });
    }
}

/// Record the web origin or relying-party ID in the current thread's audit context.
pub fn note_origin(origin: &str) {
    if !origin.trim().is_empty() {
        AUDIT_CONTEXT.with(|ctx| {
            ctx.borrow_mut().origin = Some(origin.to_owned());
        });
    }
}

/// Apply and clear any thread-local audit metadata onto `event`.
#[must_use]
pub fn apply_context(mut event: Event) -> Event {
    let ctx = AUDIT_CONTEXT.with(std::cell::RefCell::take);
    if event.item_id.is_none() {
        if let Some(id) = ctx.item_id.as_deref() {
            event = event.with_item_id(id);
        }
    }
    if event.item_name.is_none() {
        if let Some(name) = ctx.item_name.as_deref() {
            event = event.with_item_name(name);
        }
    }
    if event.account.is_none() {
        if let Some(account) = ctx.account.as_deref() {
            event = event.with_account(account);
        }
    }
    if event.field.is_none() {
        if let Some(field) = ctx.field.as_deref() {
            event = event.with_field(field);
        }
    }
    if event.origin.is_none() {
        if let Some(origin) = ctx.origin.as_deref() {
            event = event.with_origin(origin);
        }
    }
    event
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

/// The most recent event that locked the vault, as far as the audit log
/// knows: an explicit lock, an idle timeout, a server logout, a key
/// rotation, or the agent stopping.
#[derive(Debug, PartialEq, Eq)]
pub struct LastLock {
    pub timestamp: String,
    pub operation: String,
    pub reason: Option<String>,
    pub client: Option<String>,
}

impl LastLock {
    /// A short human-readable explanation of the lock.
    #[must_use]
    pub fn describe(&self) -> String {
        let text = self.describe_event();
        match &self.client {
            Some(client) => format!("{text} (by {client})"),
            None => text,
        }
    }

    fn describe_event(&self) -> String {
        let reason = self.reason.as_deref();
        match (self.operation.as_str(), reason) {
            ("agent.timeout_lock", _) => {
                "locked after the idle timeout".to_owned()
            }
            ("agent.server_logout", _) => {
                "the server ended the session (logout notification)"
                    .to_owned()
            }
            ("agent.key_rotation_lock", _) => {
                "locked after the account key was rotated".to_owned()
            }
            ("socket.lock", Some("one_account")) => {
                "locked by `rbw lock` (one account)".to_owned()
            }
            ("socket.lock", _) => "locked by `rbw lock`".to_owned(),
            ("agent.stop", Some(reason)) => {
                format!("the agent stopped: {}", describe_stop(reason))
            }
            ("agent.stop", None) => "the agent stopped".to_owned(),
            ("agent.start", _) => "the previous agent ended without a stop \
                 record (killed, crashed, or an rbw older than 2.43)"
                .to_owned(),
            (operation, _) => operation.to_owned(),
        }
    }
}

fn describe_stop(reason: &str) -> &str {
    match reason {
        "stop_agent" => "`rbw stop-agent`",
        "outdated" => "replaced by a newer rbw client",
        "unresponsive" => "a client could not get its version",
        "config_change" => "the configuration or an account changed",
        "purge" => "`rbw purge`",
        "native_unlock_change" => "a native unlock setting changed",
        "sigterm" => "SIGTERM (service stop or restart)",
        "sigint" => "SIGINT",
        "sighup" => "SIGHUP",
        "unspecified" => "quit request from an rbw older than 2.43",
        other => other,
    }
}

#[derive(serde::Deserialize)]
struct RecordedEvent {
    timestamp: String,
    operation: String,
    outcome: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    client: Option<String>,
}

const LOCK_OPERATIONS: &[&str] = &[
    "agent.timeout_lock",
    "agent.server_logout",
    "agent.key_rotation_lock",
    "agent.stop",
    "socket.lock",
];

/// Find the most recent lock in the audit log, if it recorded one.
#[must_use]
pub fn last_lock() -> Option<LastLock> {
    last_lock_in(&crate::dirs::audit_dir())
}

fn last_lock_in(directory: &std::path::Path) -> Option<LastLock> {
    let mut days = std::fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_prefix("audit-")?
                .strip_suffix(".jsonl")?
                .parse::<u32>()
                .ok()
        })
        .collect::<Vec<_>>();
    days.sort_unstable_by(|a, b| b.cmp(a));

    // A start whose agent's predecessor left no stop record: report the
    // start unless an older stop explains it.
    let mut pending_start: Option<LastLock> = None;
    for day in days {
        let Ok(content) = std::fs::read_to_string(
            directory.join(format!("audit-{day}.jsonl")),
        ) else {
            continue;
        };
        for line in content.lines().rev() {
            let Ok(event) = serde_json::from_str::<RecordedEvent>(line)
            else {
                continue;
            };
            if event.outcome != "success" {
                continue;
            }
            let record = LastLock {
                timestamp: event.timestamp,
                operation: event.operation,
                reason: event.reason,
                client: event.client,
            };
            if record.operation == "agent.start" {
                if pending_start.is_some() {
                    // Two starts in a row: the newer one is unexplained.
                    return pending_start;
                }
                pending_start = Some(record);
                continue;
            }
            if record.operation == "agent.stop" {
                return Some(record);
            }
            if LOCK_OPERATIONS.contains(&record.operation.as_str()) {
                // A lock while the newest agent was already running wins;
                // one from before its start is older than the restart.
                return Some(pending_start.unwrap_or(record));
            }
        }
    }
    pending_start
}

const NOTABLE_OPERATIONS: &[&str] = &[
    "api.field_read",
    "api.items_listed",
    "api.unlock",
    "api.authorization",
    "get",
    "show",
    "raw",
    "code",
    "inject",
    "run",
    "passkey",
    "passkey assert",
    "passkey inject",
    "attachment get",
    "attachment download",
    "unlock",
    "login",
    "lock",
    "purge",
    "browser.credential",
    "browser.totp",
    "browser.copy",
    "browser.passkey_get",
    "browser.passkey_create",
    "browser.attachment_download",
    "browser.unlock",
    "browser.lock",
    "browser.authorization",
    "ssh_agent.sign",
    "agent.timeout_lock",
    "agent.server_logout",
    "agent.key_rotation_lock",
    "agent.stop",
];

fn is_notable_operation(operation: &str) -> bool {
    NOTABLE_OPERATIONS.contains(&operation)
}

fn line_operation(line: &str) -> Option<&str> {
    let (_, rest) = line.split_once(r#""operation":""#)?;
    let (operation, _) = rest.split_once('"')?;
    Some(operation)
}

/// Return up to `limit` recent notable audit events in chronological order.
///
/// Includes credential reads, passkey assertions, TOTP reads, SSH signatures,
/// lock/unlock events, and authorization denials, filtered to
/// `allowed_accounts` and with API client IDs resolved via `client_names`.
#[must_use]
pub fn recent_events(
    limit: usize,
    allowed_accounts: &[String],
    client_names: &std::collections::BTreeMap<String, String>,
) -> Vec<Event> {
    recent_events_in(
        &crate::dirs::audit_dir(),
        limit,
        allowed_accounts,
        client_names,
    )
}

#[must_use]
pub fn recent_events_in(
    directory: &std::path::Path,
    limit: usize,
    allowed_accounts: &[String],
    client_names: &std::collections::BTreeMap<String, String>,
) -> Vec<Event> {
    if limit == 0 || allowed_accounts.is_empty() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut days = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_prefix("audit-")?
                .strip_suffix(".jsonl")?
                .parse::<u32>()
                .ok()
        })
        .collect::<Vec<_>>();
    days.sort_unstable_by(|a, b| b.cmp(a));

    let mut events = Vec::with_capacity(limit);
    for day in days.into_iter().take(2) {
        let Ok(content) = std::fs::read_to_string(
            directory.join(format!("audit-{day}.jsonl")),
        ) else {
            continue;
        };
        for line in content.lines().rev() {
            if let Some(op) = line_operation(line) {
                if !is_notable_operation(op) {
                    continue;
                }
            }
            let Ok(mut event) = serde_json::from_str::<Event>(line) else {
                continue;
            };
            if !is_notable_operation(&event.operation) {
                continue;
            }
            if let Some(ref account) = event.account {
                if !allowed_accounts.iter().any(|allowed| allowed == account)
                {
                    continue;
                }
            }
            if let Some(name) =
                client_names.get(&event.actor).filter(|s| !s.is_empty())
            {
                event.actor.clone_from(name);
            }
            events.push(event);
            if events.len() >= limit {
                events.reverse();
                return events;
            }
        }
    }
    events.reverse();
    events
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
            item_name: None,
            account: None,
            field: None,
            origin: None,
            reason: None,
            version: None,
            client: None,
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

    #[test]
    fn reason_and_version_are_serialized_when_set() {
        let event = Event::new("agent", "agent.stop", "success")
            .with_reason("sigterm")
            .with_version("2.43.0")
            .with_client("rbw-2.40.0/bin/rbw; rm -rf ~");
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["client"], "rbw-2.40.0/bin/rbwrm-rf");
        assert_eq!(value["reason"], "sigterm");
        assert_eq!(value["version"], "2.43.0");
    }

    #[test]
    fn context_and_origin_sanitization_strip_paths_and_controls() {
        clear_context();
        note_item(
            Some("wiit\n"),
            "550e8400-e29b-41d4-a716-446655440000",
            Some("Microsoft\tAccount"),
        );
        note_field("password\r\n");
        note_origin("https://login.microsoftonline.com/common/oauth2?code=secret#frag");

        let event = apply_context(Event::new(
            "firefox",
            "browser.credential",
            "success",
        ));
        assert_eq!(
            event.item_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        assert_eq!(event.item_name.as_deref(), Some("MicrosoftAccount"));
        assert_eq!(event.account.as_deref(), Some("wiit"));
        assert_eq!(event.field.as_deref(), Some("password"));
        assert_eq!(
            event.origin.as_deref(),
            Some("https://login.microsoftonline.com")
        );
    }

    #[test]
    fn recent_events_filters_noise_and_resolves_client_names() {
        let directory = tempfile::tempdir().unwrap();
        let noisy =
            Event::new("local-agent-socket", "socket.decrypt", "success");
        let api_event = Event {
            timestamp: "2026-11-06T12:00:00Z".to_owned(),
            actor: "08ba601a9f0b4ea19f1ab6d494402342".to_owned(),
            operation: "api.field_read".to_owned(),
            outcome: "success".to_owned(),
            item_id: Some("550e8400-e29b-41d4-a716-446655440000".to_owned()),
            item_name: Some("Microsoft".to_owned()),
            account: Some("wiit".to_owned()),
            field: Some("password".to_owned()),
            origin: None,
            reason: None,
            version: None,
            client: Some("msteams".to_owned()),
        };
        let other_account_event = Event {
            timestamp: "2026-11-06T12:01:00Z".to_owned(),
            actor: "firefox".to_owned(),
            operation: "browser.credential".to_owned(),
            outcome: "success".to_owned(),
            item_id: None,
            item_name: Some("Private".to_owned()),
            account: Some("secret-acc".to_owned()),
            field: Some("password".to_owned()),
            origin: Some("https://example.com".to_owned()),
            reason: None,
            version: None,
            client: None,
        };
        write_events(
            directory.path(),
            100,
            &[
                &serde_json::to_string(&noisy).unwrap(),
                &serde_json::to_string(&api_event).unwrap(),
                &serde_json::to_string(&other_account_event).unwrap(),
            ],
        );

        let mut names = std::collections::BTreeMap::new();
        names.insert(
            "08ba601a9f0b4ea19f1ab6d494402342".to_owned(),
            "home-assistant".to_owned(),
        );
        let events = recent_events_in(
            directory.path(),
            10,
            &["default".to_owned(), "wiit".to_owned()],
            &names,
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, "home-assistant");
        assert_eq!(events[0].client.as_deref(), Some("msteams"));
        assert_eq!(events[0].item_name.as_deref(), Some("Microsoft"));
    }

    fn write_events(directory: &std::path::Path, day: u32, events: &[&str]) {
        let mut content = events.join("\n");
        content.push('\n');
        std::fs::write(directory.join(format!("audit-{day}.jsonl")), content)
            .unwrap();
    }

    fn event(time: &str, operation: &str, reason: Option<&str>) -> String {
        let mut value = serde_json::json!({
            "timestamp": time,
            "actor": "agent",
            "operation": operation,
            "outcome": "success",
        });
        if let Some(reason) = reason {
            value["reason"] = reason.into();
        }
        value.to_string()
    }

    #[test]
    fn last_lock_explains_a_restart_with_the_stop_before_it() {
        let directory = tempfile::tempdir().unwrap();
        write_events(
            directory.path(),
            100,
            &[
                &event("t1", "agent.timeout_lock", None),
                &event("t2", "socket.unlock", None),
                &event("t3", "agent.stop", Some("outdated")),
            ],
        );
        write_events(
            directory.path(),
            101,
            &[
                &event("t4", "agent.start", None),
                &event("t5", "socket.unlock", None),
                &serde_json::json!({
                    "timestamp": "t6",
                    "actor": "cli",
                    "operation": "unlocked",
                    "outcome": "failure",
                })
                .to_string(),
            ],
        );
        let lock = last_lock_in(directory.path()).unwrap();
        assert_eq!(lock.timestamp, "t3");
        assert_eq!(lock.reason.as_deref(), Some("outdated"));
        assert!(lock.describe().contains("newer rbw client"));
    }

    #[test]
    fn last_lock_prefers_a_lock_after_the_agent_started() {
        let directory = tempfile::tempdir().unwrap();
        write_events(
            directory.path(),
            100,
            &[
                &event("t1", "agent.stop", Some("sigterm")),
                &event("t2", "agent.start", None),
                &event("t3", "socket.lock", Some("all_accounts")),
            ],
        );
        let lock = last_lock_in(directory.path()).unwrap();
        assert_eq!(lock.operation, "socket.lock");
    }

    #[test]
    fn last_lock_reports_an_unexplained_restart() {
        let directory = tempfile::tempdir().unwrap();
        write_events(
            directory.path(),
            100,
            &[
                &event("t1", "agent.start", None),
                &event("t2", "agent.start", None),
            ],
        );
        let lock = last_lock_in(directory.path()).unwrap();
        assert_eq!(lock.timestamp, "t2");
        assert!(lock.describe().contains("without a stop record"));
        assert_eq!(last_lock_in(&directory.path().join("missing")), None);
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
