// Application state and behaviour for the interactive vault browser.
//
// `App` owns the local db plus a batch-decrypted search index (parallel to
// `db.entries`) and drives all interaction. Rendering lives in `super::ui`,
// which reads the public(-in-module) state exposed here.

use std::collections::HashMap;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::commands::{
    self, DecryptedCipher, DecryptedData, DecryptedSearchCipher,
    EditableCipher, EditableData, EditableUri,
};

use super::input::Input;
use super::keymap::{Keymap, TuiAction};

// What the event loop should do after a keypress. Everything except spawning
// an external editor is handled inline (agent round-trips are synchronous and
// safe while the alternate screen is active); `$EDITOR` needs the real terminal
// back, so it is bounced up to the loop.
pub enum Action {
    None,
    Quit,
    OpenEditor,
    // Unlock the named account; bounced to the event loop because pinentry
    // needs the real terminal (like OpenEditor).
    UnlockAccount(String),
    // Unlock the named account and immediately sync it afterwards.
    UnlockAndSyncAccount(String),
    // Sync the named account entirely inside the TUI.
    SyncAccount(String),
    // Auto-unlock a linked account and sync it entirely inside the TUI.
    AutoUnlockAndSyncAccount(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

pub struct Status {
    pub text: String,
    pub level: Level,
}

pub enum Mode {
    Normal,
    Search,
    Edit(EditForm),
    ConfirmDelete,
    Attachments(AttachmentView),
    Accounts(AccountsView),
    // Confirm clearing the named account's `credential_source` link, from
    // the accounts panel. Carries the account name since this mode replaces
    // `Mode::Accounts` (and its cursor/list) while the dialog is up.
    ConfirmClearCredentialSource(String),
    Prompt(Prompt),
    // A filterable single-select list overlay -- currently only the
    // two-step credential_source account/item picker (see `PickerKind`).
    Picker(PickerView),
    Settings(SettingsView),
    Help,
    // The agent locked the named account out from under us (another process
    // ran `rbw lock`/`rbw stop-agent`, or `lock_timeout` fired) — see
    // `App::poll_agent_lock`. Blocks normal interaction until the user
    // re-unlocks (or quits), same as the other modal overlays.
    LockedPrompt(String),
    // A sync for the named account failed because its refresh token was
    // rejected by the server (`Error::SessionExpired`) -- the local vault
    // is still unlocked and readable, but talking to the server again
    // needs a fresh interactive login, not just a pinentry-cached unlock.
    // Set from the `tui/mod.rs` sync helpers, which recognize the error by
    // its message (the only thing that survives the agent IPC boundary).
    SessionExpiredPrompt(String),
}

// The accounts/settings panel: every configured account with its lock state
// and primary marker, plus a cursor.
pub struct AccountsView {
    pub accounts: Vec<commands::TuiAccount>,
    pub selected: usize,
}

// What a filled-in `Prompt` should do on submit.
pub enum PromptKind {
    // Upload the entered file path as an attachment on the entry with `id` in
    // the vault `owner`.
    AttachmentUpload { owner: usize, id: String },
    // Add a new account from the entered name / email / server-url fields.
    AddAccount,
}

pub struct PromptField {
    pub label: &'static str,
    pub input: Input,
}

// Which step of a multi-step `Mode::Picker` flow is showing, and what to do
// once its selection is confirmed. Currently only the credential_source
// account/item picker (opened from the accounts panel's `l`), but the shape
// generalizes to any other "pick one of these strings" flow later.
pub enum PickerKind {
    // Step 1: choose which *other* configured account holds `name`'s master
    // password. Confirming advances to a `CredentialSourceItem` picker
    // scoped to the chosen account rather than submitting anything yet.
    CredentialSourceAccount {
        name: String,
    },
    // Step 2: choose which Login item, in `source_account`'s vault, holds
    // it. Confirming calls `commands::tui_account_set_credential_source`.
    CredentialSourceItem {
        name: String,
        source_account: String,
    },
}

const CREDENTIAL_SOURCE_AUTO_ITEM: &str = "(auto by URI)";

// A filterable, single-select list overlay: a typed filter narrows `items`
// down to `filtered`, arrow keys move the highlight within it, and Enter
// confirms. If nothing in `items` matches the typed text (most commonly
// because `items` is empty to begin with -- see `PickerKind`'s doc comment
// on why a locked source account has no candidates to list), Enter instead
// confirms the raw typed text, so the flow degrades to plain free-text entry
// rather than getting stuck.
pub struct PickerView {
    pub title: String,
    pub hint: &'static str,
    items: Vec<String>,
    pub filter: Input,
    filtered: Vec<usize>,
    pub selected: usize,
    kind: PickerKind,
}

impl PickerView {
    pub fn new(
        title: String,
        hint: &'static str,
        items: Vec<String>,
        prefill: Option<String>,
        kind: PickerKind,
    ) -> Self {
        let mut view = Self {
            title,
            hint,
            items,
            filter: Input::new(prefill.unwrap_or_default()),
            filtered: Vec::new(),
            selected: 0,
            kind,
        };
        view.recompute_filter();
        view
    }

    fn recompute_filter(&mut self) {
        let needle = self.filter.value().to_ascii_lowercase();
        self.filtered = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                needle.is_empty()
                    || item.to_ascii_lowercase().contains(&needle)
            })
            .map(|(i, _)| i)
            .collect();
        self.selected =
            self.selected.min(self.filtered.len().saturating_sub(1));
    }

    fn move_selected(&mut self, delta: isize) {
        if self.filtered.is_empty() {
            return;
        }
        let cur = isize::try_from(self.selected).unwrap_or(0);
        let last = isize::try_from(self.filtered.len() - 1).unwrap_or(0);
        self.selected =
            usize::try_from((cur + delta).clamp(0, last)).unwrap_or(0);
    }

    // The highlighted item's string, keyed through `filtered`/`items` so
    // callers never see a stale index. Empty only once `items` itself is
    // (an empty `filtered` with a non-empty `items` can't happen: a filter
    // that matches nothing still keeps the previous selection clamped into
    // range by `recompute_filter`, but an all-items-excluded state isn't
    // reachable since an empty needle always matches everything).
    fn highlighted(&self) -> Option<&str> {
        self.filtered
            .get(self.selected)
            .and_then(|&i| self.items.get(i))
            .map(String::as_str)
    }

    // The value Enter should confirm: the highlighted item if the filter
    // matched anything in `items`, else the raw typed text -- see the
    // struct's doc comment for why that fallback matters.
    fn current_value(&self) -> String {
        self.highlighted().map_or_else(
            || self.filter.value().to_string(),
            ToString::to_string,
        )
    }

    // Rows to render: every filtered item's display string, paired with
    // whether it's the highlighted one.
    pub fn rows(&self) -> impl Iterator<Item = (bool, &str)> {
        self.filtered
            .iter()
            .enumerate()
            .map(|(row, &i)| (row == self.selected, self.items[i].as_str()))
    }
}

// A small labelled multi-field text prompt shown as an overlay (file path for
// attachment upload, or the fields for a new account).
pub struct Prompt {
    pub title: String,
    pub hint: &'static str,
    pub fields: Vec<PromptField>,
    pub focus: usize,
    kind: PromptKind,
}

impl Prompt {
    fn attachment_upload(owner: usize, id: String, entry_name: &str) -> Self {
        Self {
            title: format!("Upload attachment → {entry_name}"),
            hint: "⏎ upload · esc cancel",
            fields: vec![PromptField {
                label: "File path",
                input: Input::default(),
            }],
            focus: 0,
            kind: PromptKind::AttachmentUpload { owner, id },
        }
    }

    pub fn add_account() -> Self {
        Self {
            title: "Add account".to_string(),
            hint:
                "⏎ save · ⇥ next · esc cancel · Server blank = bitwarden.com",
            fields: vec![
                PromptField {
                    label: "Name",
                    input: Input::default(),
                },
                PromptField {
                    label: "Email",
                    input: Input::default(),
                },
                PromptField {
                    label: "Server",
                    input: Input::default(),
                },
            ],
            focus: 0,
            kind: PromptKind::AddAccount,
        }
    }

    fn focus_next(&mut self) {
        if !self.fields.is_empty() {
            self.focus = (self.focus + 1) % self.fields.len();
        }
    }

    fn focus_prev(&mut self) {
        if !self.fields.is_empty() {
            self.focus =
                (self.focus + self.fields.len() - 1) % self.fields.len();
        }
    }

    fn value(&self, i: usize) -> String {
        self.fields
            .get(i)
            .map_or_else(String::new, |f| f.input.value().to_string())
    }
}

// What `submit_prompt` should carry out, extracted from the prompt's fields so
// the (immutable) prompt borrow is released before the app mutates itself.
enum PromptSubmit {
    Upload {
        owner: usize,
        id: String,
        path: String,
    },
    AddAccount {
        name: String,
        email: Option<String>,
        base_url: Option<String>,
    },
}

// Ctrl+C dismisses any modal overlay the same way Esc does. Raw mode means
// the terminal's usual SIGINT-on-Ctrl+C mapping never fires here -- it
// arrives as a plain keypress like any other -- but users instinctively
// reach for it to back out of a dialog, so every overlay handler treats it
// as an alias for its own Esc/close behavior rather than leaving it a
// silent no-op.
fn is_ctrl_c(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('c')
        && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn expand_tilde(p: &str) -> std::path::PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::Path::new(&home).join(rest);
        }
    }
    std::path::PathBuf::from(p)
}

// A single row in the attachment picker.
pub struct AttachmentItem {
    pub id: String,
    pub name: String,
    pub size: Option<String>,
}

// The attachment picker overlay: the current entry's attachments plus a cursor.
// `pending_delete` arms a two-press confirm for `d` (so an accidental keypress
// doesn't drop an attachment).
pub struct AttachmentView {
    pub items: Vec<AttachmentItem>,
    pub selected: usize,
    pub pending_delete: bool,
}

// One unlocked account and its local db plus decrypted search index. The
// index is parallel to `db.entries`; the flattened `App::search` (built by
// `rebuild_flat`) concatenates these across all vaults.
struct AccountVault {
    name: String,
    db: rbw::db::Db,
    search: Vec<DecryptedSearchCipher>,
}

pub struct App {
    // Every currently-unlocked account.
    vaults: Vec<AccountVault>,
    // Configured accounts that are still locked, offered for lazy unlock from
    // the accounts panel.
    locked: Vec<String>,
    // More than one account is configured: controls account badges and the
    // add-target picker.
    multi: bool,

    // Flattened, index-aligned view across all vaults. `search[i]` describes
    // the entry at `vaults[owner[i]].db.entries[slot[i]]`.
    pub search: Vec<DecryptedSearchCipher>,
    owner: Vec<usize>,
    slot: Vec<usize>,

    // Full per-entry detail, decrypted lazily, keyed by (owning vault, id).
    detail_cache: HashMap<(usize, String), DecryptedCipher>,
    pub filter: Input,
    // Indices into the flattened view, filtered by the search term and sorted
    // by (folder, name, user).
    pub filtered: Vec<usize>,
    pub selected: usize,
    pub mode: Mode,
    pub reveal: bool,
    pub status: Option<Status>,
    pub detail_scroll: u16,
    // How far `detail_scroll` can go before the preview stops growing (set
    // by the renderer each frame, from the actual wrapped line count vs. the
    // pane's height). Lets scroll input clamp itself so that scrolling a
    // preview that already fits the pane is a no-op in both directions,
    // rather than accepting keypresses a visible scroll never catches up to.
    pub detail_max_scroll: std::cell::Cell<u16>,
    // Right arrow (or a detail-pane click) moves focus here so Up/Down
    // scroll the preview instead of moving the list selection; Left/Esc (or
    // a list-pane click) moves it back. Only meaningful in `Mode::Normal`.
    pub detail_focused: bool,
    // Resolved once at startup from `tui_keybindings` (config.json) merged
    // over the built-in defaults (see `keymap::Keymap::resolve`). `super::ui`
    // reads it to render live keybinding hints instead of hardcoded text.
    pub keymap: Keymap,
    // Throttle for `poll_agent_lock`: the IPC round trip to the agent is
    // cheap, but there's no need to make it on every ~500ms UI tick, so we
    // only actually check once `LOCK_CHECK_INTERVAL` has elapsed.
    last_lock_check: std::time::Instant,
}

// How often `poll_agent_lock` actually round-trips to the agent, throttled
// against the UI's ~500ms redraw tick (see `tui::TICK`) so an idle session
// isn't hammering the agent with redundant "are you still unlocked" checks.
const LOCK_CHECK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(3);

impl App {
    pub fn new(open: commands::TuiOpen, initial_term: Option<&str>) -> Self {
        let keymap = rbw::config::Config::load().map_or_else(
            |_| Keymap::resolve(&std::collections::HashMap::new()),
            |config| Keymap::resolve(&config.tui_keybindings),
        );
        Self::with_keymap(open, initial_term, keymap)
    }

    // Split out from `new` so tests (including `super::ui`'s) can supply a
    // deterministic keymap instead of picking up whatever the machine
    // running them happens to have in `~/.config/rbw/config.json`.
    pub(crate) fn with_keymap(
        open: commands::TuiOpen,
        initial_term: Option<&str>,
        keymap: Keymap,
    ) -> Self {
        let vaults = open
            .vaults
            .into_iter()
            .map(|v| AccountVault {
                name: v.account,
                db: v.db,
                search: v.search,
            })
            .collect();
        let mut app = Self {
            vaults,
            locked: open.locked,
            multi: open.multi,
            search: Vec::new(),
            owner: Vec::new(),
            slot: Vec::new(),
            detail_cache: HashMap::new(),
            filter: initial_term.map_or_else(Input::default, Input::new),
            filtered: Vec::new(),
            selected: 0,
            // Start focused on the filter so typing narrows the list immediately
            // (fzf-style); Tab / Enter drops into the list for single-key actions.
            mode: Mode::Search,
            reveal: false,
            status: None,
            detail_scroll: 0,
            detail_max_scroll: std::cell::Cell::new(0),
            detail_focused: false,
            keymap,
            // The account(s) handed to us were just unlocked by `tui_open`
            // moments ago, so there's no point re-checking immediately.
            last_lock_check: std::time::Instant::now(),
        };
        app.rebuild_flat();
        app.recompute_filter();
        app.ensure_detail();
        app
    }

    // ---- multi-account view ---------------------------------------------

    // Rebuild the flattened search index (and its owner/slot maps) from the
    // per-vault indices. Called after any vault is loaded or reloaded.
    fn rebuild_flat(&mut self) {
        self.search.clear();
        self.owner.clear();
        self.slot.clear();
        for (vi, vault) in self.vaults.iter().enumerate() {
            for (si, cipher) in vault.search.iter().enumerate() {
                self.search.push(cipher.clone());
                self.owner.push(vi);
                self.slot.push(si);
            }
        }
    }

    // The vault owning the current selection.
    fn current_owner(&self) -> Option<usize> {
        self.current_index()
            .and_then(|i| self.owner.get(i).copied())
    }

    // The account name owning the current selection.
    fn current_account_name(&self) -> Option<String> {
        self.current_owner().map(|o| self.vaults[o].name.clone())
    }

    // The account badge to show for flattened row `i`, or `None` when only one
    // account is configured (so single-account users see no badge column).
    pub fn badge(&self, i: usize) -> Option<&str> {
        if !self.multi {
            return None;
        }
        self.owner.get(i).map(|&o| self.vaults[o].name.as_str())
    }

    // Point the agent + lib api calls at the account owning the current
    // selection before an operation on it.
    fn activate_current(&self) -> anyhow::Result<()> {
        crate::actions::set_active_account(self.current_account_name())
    }

    // ---- selection / filtering ------------------------------------------

    fn recompute_filter(&mut self) {
        let term = self.filter.value().to_string();
        let mut filtered: Vec<usize> = self
            .search
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                term.is_empty() || c.search_match(&term, None, false)
            })
            .map(|(i, _)| i)
            .collect();
        filtered.sort_by(|&a, &b| {
            let ca = &self.search[a];
            let cb = &self.search[b];
            ca.folder
                .cmp(&cb.folder)
                .then_with(|| {
                    ca.name.to_lowercase().cmp(&cb.name.to_lowercase())
                })
                .then_with(|| {
                    ca.user
                        .as_deref()
                        .unwrap_or("")
                        .cmp(cb.user.as_deref().unwrap_or(""))
                })
        });
        self.filtered = filtered;
        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
    }

    fn current_index(&self) -> Option<usize> {
        self.filtered.get(self.selected).copied()
    }

    pub fn current_search(&self) -> Option<&DecryptedSearchCipher> {
        self.current_index().map(|i| &self.search[i])
    }

    fn current_entry(&self) -> Option<rbw::db::Entry> {
        let i = self.current_index()?;
        let o = *self.owner.get(i)?;
        let s = *self.slot.get(i)?;
        self.vaults.get(o)?.db.entries.get(s).cloned()
    }

    pub fn current_detail(&self) -> Option<&DecryptedCipher> {
        let i = self.current_index()?;
        let o = *self.owner.get(i)?;
        let id = self.search[i].id.clone();
        self.detail_cache.get(&(o, id))
    }

    fn select(&mut self, pos: usize) {
        let new = pos.min(self.filtered.len().saturating_sub(1));
        if new != self.selected {
            self.selected = new;
            self.detail_scroll = 0;
        }
        self.ensure_detail();
    }

    fn move_by(&mut self, delta: isize) {
        if self.filtered.is_empty() {
            return;
        }
        let len = self.filtered.len();
        let cur = isize::try_from(self.selected).unwrap_or(0);
        let mut next = cur + delta;
        let last = isize::try_from(len - 1).unwrap_or(0);
        if next < 0 {
            next = 0;
        } else if next > last {
            next = last;
        }
        self.select(usize::try_from(next).unwrap_or(0));
    }

    // Up/Down: scroll the detail preview while it's focused, otherwise move
    // the list selection as usual.
    fn move_or_scroll(&mut self, delta: isize) {
        if self.detail_focused && matches!(self.mode, Mode::Normal) {
            self.scroll_detail(delta);
        } else {
            self.move_by(delta);
        }
    }

    // Adjusts `detail_scroll`, clamped to what the last-rendered pane could
    // actually show, so scrolling past the end of a short preview doesn't
    // silently rack up keypresses a visible scroll never catches up to.
    fn scroll_detail(&mut self, delta: isize) {
        let max = isize::try_from(self.detail_max_scroll.get())
            .unwrap_or(isize::MAX);
        let cur = isize::try_from(self.detail_scroll).unwrap_or(0);
        let next = (cur + delta).clamp(0, max);
        self.detail_scroll = u16::try_from(next).unwrap_or(0);
    }

    // Decrypt full detail for the current selection if not already cached.
    // Routes the decrypt to the owning account.
    fn ensure_detail(&mut self) {
        let Some(i) = self.current_index() else {
            return;
        };
        let o = self.owner[i];
        let id = self.search[i].id.clone();
        if self.detail_cache.contains_key(&(o, id.clone())) {
            return;
        }
        let entry = self.vaults[o].db.entries[self.slot[i]].clone();
        if let Err(e) = crate::actions::set_active_account(Some(
            self.vaults[o].name.clone(),
        )) {
            self.set_status(Level::Error, format!("{e:#}"));
            return;
        }
        match commands::decrypt_cipher(&entry) {
            Ok(detail) => {
                self.detail_cache.insert((o, id), detail);
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    // ---- status ---------------------------------------------------------

    fn set_status(&mut self, level: Level, text: impl Into<String>) {
        self.status = Some(Status {
            text: text.into(),
            level,
        });
    }

    // Surface an error in the status line (used by the event loop after the
    // external editor returns).
    pub fn set_error(&mut self, msg: String) {
        self.set_status(Level::Error, msg);
    }

    // ---- clipboard / open -----------------------------------------------

    fn copy(&mut self, label: &str, value: Option<String>) {
        match value {
            Some(v) if !v.is_empty() => self.copy_value(label, &v),
            _ => self.set_status(Level::Warn, format!("no {label} to copy")),
        }
    }

    fn copy_password(&mut self) {
        let value = self.current_detail().and_then(detail_password);
        self.copy("password", value);
    }

    fn copy_username(&mut self) {
        let value = self.current_detail().and_then(detail_username);
        self.copy("username", value);
    }

    fn copy_totp(&mut self) {
        let secret = self.current_detail().and_then(detail_totp_secret);
        match secret {
            Some(secret) => match commands::generate_totp(&secret) {
                Ok(code) => self.copy_value("TOTP code", &code),
                Err(e) => self.set_status(Level::Error, format!("{e:#}")),
            },
            None => self.set_status(Level::Warn, "no TOTP secret"),
        }
    }

    fn copy_value(&mut self, label: &str, value: &str) {
        match crate::actions::clipboard_store(value) {
            Ok(()) => {
                self.set_status(Level::Success, format!("copied {label}"));
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    fn open_uri(&mut self) {
        let uri =
            self.current_detail()
                .and_then(detail_first_uri)
                .or_else(|| {
                    self.current_search()
                        .and_then(|s| s.uris.first().map(|(u, _)| u.clone()))
                });
        match uri {
            Some(uri) if !uri.is_empty() => match open::that(&uri) {
                Ok(()) => {
                    self.set_status(Level::Info, format!("opened {uri}"));
                }
                Err(e) => self.set_status(Level::Error, format!("{e:#}")),
            },
            _ => self.set_status(Level::Warn, "no URL to open"),
        }
    }

    // ---- attachments ----------------------------------------------------

    fn open_attachments(&mut self) {
        self.ensure_detail();
        let Some(detail) = self.current_detail() else {
            self.set_status(Level::Warn, "nothing selected");
            return;
        };
        let empty = detail.attachments.is_empty();
        let items = detail
            .attachments
            .iter()
            .map(|a| AttachmentItem {
                id: a.id.clone(),
                name: a.file_name.clone().unwrap_or_else(|| a.id.clone()),
                size: a.size_name.clone().or_else(|| a.size.clone()),
            })
            .collect();
        if empty {
            self.set_status(
                Level::Info,
                "no attachments · press a to upload one",
            );
        }
        self.mode = Mode::Attachments(AttachmentView {
            items,
            selected: 0,
            pending_delete: false,
        });
    }

    fn attachment_move(&mut self, delta: isize) {
        if let Mode::Attachments(view) = &mut self.mode {
            let len = view.items.len();
            if len == 0 {
                return;
            }
            let cur = isize::try_from(view.selected).unwrap_or(0);
            let last = isize::try_from(len - 1).unwrap_or(0);
            let next = (cur + delta).clamp(0, last);
            view.selected = usize::try_from(next).unwrap_or(0);
        }
    }

    // Download the highlighted attachment into the current working directory.
    fn download_attachment(&mut self) {
        let att_id = match &self.mode {
            Mode::Attachments(view) => {
                view.items.get(view.selected).map(|i| i.id.clone())
            }
            _ => None,
        };
        let Some(att_id) = att_id else {
            return;
        };
        let Some(o) = self.current_owner() else {
            return;
        };
        let Some(entry) = self.current_entry() else {
            return;
        };
        self.ensure_detail();
        let Some(detail) =
            self.detail_cache.get(&(o, entry.id.clone())).cloned()
        else {
            self.set_status(Level::Error, "could not decrypt entry");
            return;
        };
        if let Err(e) = self.activate_current() {
            self.set_status(Level::Error, format!("{e:#}"));
            return;
        }
        let dest = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        match commands::tui_attachment_get(
            &mut self.vaults[o].db,
            &entry,
            &detail,
            &att_id,
            &dest,
        ) {
            Ok(path) => {
                self.mode = Mode::Normal;
                self.set_status(
                    Level::Success,
                    format!("saved {}", path.display()),
                );
            }
            // Keep the picker open so another attachment can be tried.
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    // ---- mutations ------------------------------------------------------

    // (owning vault, id) of the current selection, for restoring it after the
    // flattened view is rebuilt.
    fn current_key(&self) -> Option<(usize, String)> {
        let i = self.current_index()?;
        Some((self.owner[i], self.search[i].id.clone()))
    }

    fn restore_selection(&mut self, keep: Option<(usize, String)>) {
        if let Some((o, id)) = keep {
            if let Some(pos) = self
                .filtered
                .iter()
                .position(|&i| self.owner[i] == o && self.search[i].id == id)
            {
                self.selected = pos;
            }
        }
    }

    // Reload a single vault from its local db and rebuild the flattened view.
    fn reload_vault(&mut self, owner: usize) {
        if let Err(e) = crate::actions::set_active_account(Some(
            self.vaults[owner].name.clone(),
        )) {
            self.set_status(Level::Error, format!("{e:#}"));
            return;
        }
        match commands::tui_reload() {
            Ok((db, search)) => {
                let keep = self.current_key();
                self.vaults[owner].db = db;
                self.vaults[owner].search = search;
                self.detail_cache.retain(|(o, _), _| *o != owner);
                self.rebuild_flat();
                self.recompute_filter();
                self.restore_selection(keep);
                self.ensure_detail();
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    // Ctrl-S: pull remote changes for every unlocked account, then rebuild.
    fn sync(&mut self) {
        let keep = self.current_key();
        let names: Vec<String> =
            self.vaults.iter().map(|v| v.name.clone()).collect();
        let mut synced = Vec::new();
        let mut errors = Vec::new();
        // First account whose session expired, if any -- surfaced as the
        // modal prompt below rather than buried in the status line, since
        // it needs an explicit action (a fresh login) to actually recover.
        let mut expired = None;
        for name in names {
            match commands::tui_account_sync(&name) {
                Ok(v) => {
                    if let Some(slot) =
                        self.vaults.iter_mut().find(|x| x.name == name)
                    {
                        slot.db = v.db;
                        slot.search = v.search;
                    }
                    synced.push(name);
                }
                Err(e) => {
                    if expired.is_none() && Self::is_session_expired_error(&e)
                    {
                        expired = Some(name.clone());
                    }
                    errors.push(format!("{name}: {e:#}"));
                }
            }
        }
        self.detail_cache.clear();
        self.rebuild_flat();
        self.recompute_filter();
        self.restore_selection(keep);
        self.ensure_detail();
        if let Some(name) = expired {
            self.show_session_expired(name);
        } else if errors.is_empty() {
            self.set_status(
                Level::Success,
                format!("synced {}", synced.join(", ")),
            );
        } else if synced.is_empty() {
            self.set_status(Level::Error, errors.join("; "));
        } else {
            self.set_status(
                Level::Error,
                format!(
                    "synced {}; failed: {}",
                    synced.join(", "),
                    errors.join("; ")
                ),
            );
        }
    }

    fn start_edit(&mut self) {
        let Some(owner) = self.current_owner() else {
            self.set_status(Level::Warn, "nothing selected");
            return;
        };
        let Some(detail) = self.current_detail() else {
            self.set_status(Level::Warn, "nothing selected");
            return;
        };
        let base = commands::decrypted_to_editable(detail);
        let title = format!("Edit · {}", base.name);
        self.mode = Mode::Edit(EditForm::new(
            title,
            Some(detail.id.clone()),
            owner,
            base,
        ));
    }

    // New entries land in the account owning the current selection, else the
    // first unlocked account. With more than one account the target is shown
    // in the form title.
    fn add_target_owner(&self) -> Option<usize> {
        self.current_owner().or(if self.vaults.is_empty() {
            None
        } else {
            Some(0)
        })
    }

    fn start_add(&mut self) {
        let Some(owner) = self.add_target_owner() else {
            self.set_status(Level::Warn, "no unlocked account to add to");
            return;
        };
        let base = EditableCipher {
            name: String::new(),
            folder: None,
            notes: None,
            data: EditableData::Login {
                username: Some(String::new()),
                password: Some(String::new()),
                uris: Vec::new(),
                totp: None,
            },
            fields: Vec::new(),
        };
        let title = if self.multi {
            format!("New login → {}", self.vaults[owner].name)
        } else {
            "New login".to_string()
        };
        self.mode = Mode::Edit(EditForm::new(title, None, owner, base));
    }

    fn submit_form(&mut self) {
        let Mode::Edit(form) = &self.mode else {
            return;
        };
        let mut base = form.rebuild_editable();
        let is_new = form.entry_id.is_none();
        let entry_id = form.entry_id.clone();
        let owner = form.owner;

        if let Err(e) = crate::actions::set_active_account(Some(
            self.vaults[owner].name.clone(),
        )) {
            self.set_status(Level::Error, format!("{e:#}"));
            return;
        }
        let result = if is_new {
            commands::tui_save_add(&mut self.vaults[owner].db, &base)
        } else if let Some(id) = &entry_id {
            self.vaults[owner]
                .db
                .entries
                .iter()
                .find(|e| &e.id == id)
                .cloned()
                .map_or_else(
                    || Err(anyhow::anyhow!("entry no longer exists")),
                    |entry| {
                        commands::tui_save_edit(
                            &mut self.vaults[owner].db,
                            &entry,
                            &base,
                        )
                    },
                )
        } else {
            Ok(())
        };
        // `base` is consumed only for its name in the status message.
        let name = std::mem::take(&mut base.name);

        match result {
            Ok(()) => {
                self.mode = Mode::Normal;
                self.reload_vault(owner);
                self.set_status(
                    Level::Success,
                    if is_new {
                        format!("created '{name}'")
                    } else {
                        format!("saved '{name}'")
                    },
                );
            }
            // Keep the form open on failure so the edit isn't lost.
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    fn confirm_delete(&mut self) {
        let Some(owner) = self.current_owner() else {
            self.mode = Mode::Normal;
            return;
        };
        let Some(entry) = self.current_entry() else {
            self.mode = Mode::Normal;
            return;
        };
        let name = self
            .current_search()
            .map_or_else(String::new, |s| s.name.clone());
        if let Err(e) = self.activate_current() {
            self.mode = Mode::Normal;
            self.set_status(Level::Error, format!("{e:#}"));
            return;
        }
        match commands::tui_delete(&mut self.vaults[owner].db, &entry) {
            Ok(()) => {
                self.mode = Mode::Normal;
                self.reload_vault(owner);
                self.set_status(Level::Success, format!("deleted '{name}'"));
            }
            Err(e) => {
                self.mode = Mode::Normal;
                self.set_status(Level::Error, format!("{e:#}"));
            }
        }
    }

    // Called by the event loop once the real terminal has been restored.
    pub fn edit_in_editor(&mut self) -> anyhow::Result<()> {
        let Some(owner) = self.current_owner() else {
            return Ok(());
        };
        let Some(entry) = self.current_entry() else {
            return Ok(());
        };
        self.ensure_detail();
        let Some(detail) =
            self.detail_cache.get(&(owner, entry.id.clone())).cloned()
        else {
            anyhow::bail!("could not decrypt entry");
        };
        self.activate_current()?;
        let changed = commands::tui_edit_in_editor(
            &mut self.vaults[owner].db,
            &entry,
            &detail,
        )?;
        self.mode = Mode::Normal;
        if changed {
            self.reload_vault(owner);
            self.set_status(Level::Success, "saved changes from editor");
        } else {
            self.set_status(Level::Info, "no changes");
        }
        Ok(())
    }

    // ---- accounts panel -------------------------------------------------

    fn open_accounts(&mut self) {
        match commands::tui_accounts() {
            Ok(accounts) => {
                self.mode = Mode::Accounts(AccountsView {
                    accounts,
                    selected: 0,
                });
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    // Rebuild the panel contents in place after a lock-state or primary change,
    // keeping the cursor position.
    fn refresh_accounts_view(&mut self) {
        if let Mode::Accounts(view) = &self.mode {
            let selected = view.selected;
            if let Ok(accounts) = commands::tui_accounts() {
                let selected = selected.min(accounts.len().saturating_sub(1));
                self.mode =
                    Mode::Accounts(AccountsView { accounts, selected });
            }
        }
    }

    fn accounts_move(&mut self, delta: isize) {
        if let Mode::Accounts(view) = &mut self.mode {
            let len = view.accounts.len();
            if len == 0 {
                return;
            }
            let cur = isize::try_from(view.selected).unwrap_or(0);
            let last = isize::try_from(len - 1).unwrap_or(0);
            view.selected =
                usize::try_from((cur + delta).clamp(0, last)).unwrap_or(0);
        }
    }

    fn selected_account(&self) -> Option<(String, bool)> {
        if let Mode::Accounts(view) = &self.mode {
            view.accounts
                .get(view.selected)
                .map(|a| (a.name.clone(), a.unlocked))
        } else {
            None
        }
    }

    // The highlighted account's name and current `credential_source` link,
    // if any.
    fn selected_account_credential_source(
        &self,
    ) -> Option<(String, Option<(String, Option<String>)>)> {
        if let Mode::Accounts(view) = &self.mode {
            view.accounts
                .get(view.selected)
                .map(|a| (a.name.clone(), a.credential_source.clone()))
        } else {
            None
        }
    }

    fn selected_account_is_linked(&self) -> Option<bool> {
        if let Mode::Accounts(view) = &self.mode {
            view.accounts
                .get(view.selected)
                .map(|a| a.credential_source.is_some())
        } else {
            None
        }
    }

    // Sync the highlighted account. If it's locked and linked via
    // `credential_source`, unlock+sync can usually happen entirely inside
    // the TUI with no pinentry round-trip; otherwise the event loop handles
    // the unlock on the real terminal, then syncs immediately afterwards.
    fn sync_selected_account(&self) -> Action {
        let Some((name, unlocked)) = self.selected_account() else {
            return Action::None;
        };
        if !unlocked {
            if self.selected_account_is_linked() == Some(true) {
                return Action::AutoUnlockAndSyncAccount(name);
            }
            return Action::UnlockAndSyncAccount(name);
        }
        Action::SyncAccount(name)
    }

    fn set_primary_selected_account(&mut self) {
        let Some((name, _)) = self.selected_account() else {
            return;
        };
        match commands::tui_set_primary(&name) {
            Ok(()) => {
                self.set_status(Level::Success, format!("primary → {name}"));
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
        self.refresh_accounts_view();
    }

    // Called by the event loop (terminal restored) to unlock an account and
    // fold its entries into the merged list. Doubles as the accept action for
    // both the accounts panel's lazy unlock (account not loaded yet: pushed
    // as a new vault) and the agent lock-detection modal's re-unlock (account
    // already loaded, just locked out from under us: replaced in place, like
    // `reload_vault`, rather than pushed as a duplicate).
    pub fn unlock_account(&mut self, name: &str) -> anyhow::Result<()> {
        let vault = commands::tui_unlock_account(name)?;
        let keep = self.current_key();
        if let Some(pos) = self.vaults.iter().position(|v| v.name == name) {
            self.vaults[pos].db = vault.db;
            self.vaults[pos].search = vault.search;
            self.detail_cache.retain(|(o, _), _| *o != pos);
        } else {
            self.vaults.push(AccountVault {
                name: vault.account,
                db: vault.db,
                search: vault.search,
            });
        }
        self.locked.retain(|n| n != name);
        self.rebuild_flat();
        self.recompute_filter();
        self.restore_selection(keep);
        self.ensure_detail();
        self.refresh_accounts_view();
        // Resolves the lock-detection modal, if that's what triggered this
        // unlock.
        if matches!(&self.mode, Mode::LockedPrompt(locked) if locked == name)
        {
            self.mode = Mode::Normal;
        }
        Ok(())
    }

    pub fn sync_account(&mut self, name: &str) -> anyhow::Result<()> {
        let vault = commands::tui_account_sync(name)?;
        if let Some(slot) = self.vaults.iter_mut().find(|x| x.name == name) {
            slot.db = vault.db;
            slot.search = vault.search;
        } else {
            self.vaults.push(AccountVault {
                name: vault.account,
                db: vault.db,
                search: vault.search,
            });
        }
        self.detail_cache.clear();
        self.rebuild_flat();
        self.recompute_filter();
        self.ensure_detail();
        self.refresh_accounts_view();
        Ok(())
    }

    pub fn set_unlocked_status(&mut self, name: &str) {
        self.set_status(Level::Success, format!("unlocked {name}"));
    }

    pub fn set_synced_status(&mut self, name: &str) {
        self.set_status(Level::Success, format!("synced {name}"));
    }

    pub fn set_unlocking_status(&mut self, name: &str) {
        self.set_status(Level::Info, format!("unlocking {name}..."));
    }

    pub fn set_syncing_status(&mut self, name: &str) {
        self.set_status(Level::Info, format!("syncing {name}..."));
    }

    // ---- agent lock detection --------------------------------------------

    // Called once per iteration of the event loop's ~500ms tick (see
    // `tui::TICK`/`run_loop`); throttles itself to `LOCK_CHECK_INTERVAL` so
    // it isn't round-tripping to the agent on every redraw.
    //
    // Only the account owning the current selection is checked (falling back
    // to the first loaded vault if nothing is selected, e.g. an empty search
    // result). That's simpler than polling every loaded account and is
    // enough to catch the common case (this account's `lock_timeout` firing,
    // or the user running `rbw lock` themselves in another terminal), but it
    // does mean a *different*, currently-unselected account getting locked
    // out from under a multi-account session won't be noticed until the user
    // selects one of its entries. A more thorough version would loop over
    // every `self.vaults` entry here; left as-is since the IPC round trip,
    // while cheap, still isn't free, and this covers the common single- and
    // active-account cases.
    pub fn poll_agent_lock(&mut self) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_lock_check) < LOCK_CHECK_INTERVAL {
            return;
        }
        self.last_lock_check = now;

        // Already showing the prompt for a lock we detected on an earlier
        // tick; nothing new to do until the user resolves it.
        if matches!(self.mode, Mode::LockedPrompt(_)) {
            return;
        }

        let Some(name) = self
            .current_account_name()
            .or_else(|| self.vaults.first().map(|v| v.name.clone()))
        else {
            // Nothing unlocked yet (e.g. every configured account uses the
            // `never` unlock policy and is still sitting in `self.locked`).
            return;
        };

        // Anything other than a confirmed `Ok(true)` (including an IPC
        // error, e.g. the agent process died) is treated as "can no longer
        // be trusted as unlocked" and triggers the same recovery flow.
        let unlocked =
            matches!(commands::tui_account_unlocked(&name), Ok(true));
        if !unlocked {
            self.handle_agent_locked(name);
        }
    }

    // The transition made when a lock is detected: drop cached secrets and
    // switch to the re-unlock modal. Split out from `poll_agent_lock` so it's
    // directly unit-testable without a real agent/IPC round trip.
    fn handle_agent_locked(&mut self, name: String) {
        // Full per-entry detail (passwords, TOTP secrets, notes, attachment
        // contents) — always drop it. The lightweight search index
        // (`AccountVault::search`/`DecryptedSearchCipher`: names, usernames,
        // folder) is left alone; it's not secret material and keeping it
        // lets the list stay populated (read-only) while the modal is up.
        self.detail_cache.clear();
        // Force anything currently displayed unmasked back to hidden.
        self.reveal = false;
        self.mode = Mode::LockedPrompt(name);
    }

    // A sync error's message is the only thing that survives the round
    // trip through the agent (see `Response::Error` and `simple_action`) --
    // matched against `Error::SessionExpired`'s own message rather than a
    // duplicated string literal, so the two can't drift apart.
    pub fn is_session_expired_error(e: &anyhow::Error) -> bool {
        e.to_string() == rbw::error::Error::SessionExpired.to_string()
    }

    // The transition made when a sync fails with `Error::SessionExpired`:
    // by this point the agent has already cleared the account's dead
    // refresh token, so all that's left is prompting for the fresh login
    // that will actually re-authenticate it.
    pub fn show_session_expired(&mut self, name: String) {
        self.mode = Mode::SessionExpiredPrompt(name);
    }

    // y/Y/Enter accepts (bounced to the event loop, same as `AccountUnlock`,
    // since pinentry needs the real terminal); anything else dismisses back
    // to `Normal`, mirroring `ConfirmDelete`'s y/n convention. Deliberately
    // not routed through the keymap: like `ConfirmDelete`'s y/n and Help's
    // "any key closes", this is a small binary confirm tied to the widget's
    // own semantics rather than a freely rebindable action (see the doc
    // comment at the top of `keymap.rs`).
    //
    // Dismissing doesn't leave the session silently half-locked: the agent
    // is still locked, so `poll_agent_lock` pops the prompt right back up on
    // its next tick (at most `LOCK_CHECK_INTERVAL` later) for as long as that
    // remains true.
    fn handle_locked_prompt(&mut self, key: KeyEvent) -> Action {
        let Mode::LockedPrompt(name) = &self.mode else {
            return Action::None;
        };
        match key.code {
            KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                Action::UnlockAccount(name.clone())
            }
            _ => {
                self.mode = Mode::Normal;
                Action::None
            }
        }
    }

    // Same y/Y/Enter-accepts, anything-else-dismisses convention as
    // `handle_locked_prompt`. Accepting fires the same `UnlockAccount`
    // action -- by the time this prompt exists, the agent has already
    // cleared the account's dead refresh token (see `sync` in
    // rbw-agent/actions.rs), so the login half of that action now performs
    // a real interactive re-login instead of silently no-opping.
    fn handle_session_expired_prompt(&mut self, key: KeyEvent) -> Action {
        let Mode::SessionExpiredPrompt(name) = &self.mode else {
            return Action::None;
        };
        match key.code {
            KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                Action::UnlockAccount(name.clone())
            }
            _ => {
                self.mode = Mode::Normal;
                Action::None
            }
        }
    }

    fn handle_accounts(&mut self, key: KeyEvent) -> Action {
        let action = if is_ctrl_c(key) {
            Some(TuiAction::AccountClose)
        } else {
            self.keymap.action_in(key, true, TuiAction::ACCOUNT)
        };
        match action {
            Some(TuiAction::AccountClose) => self.mode = Mode::Normal,
            Some(TuiAction::AccountMoveDown) => self.accounts_move(1),
            Some(TuiAction::AccountMoveUp) => self.accounts_move(-1),
            Some(TuiAction::AccountUnlock) => {
                // Unlock the highlighted account if it is locked; the loop
                // handles it (pinentry needs the terminal).
                if let Some((name, unlocked)) = self.selected_account() {
                    if unlocked {
                        self.set_status(
                            Level::Info,
                            format!("{name} already unlocked"),
                        );
                    } else {
                        return Action::UnlockAccount(name);
                    }
                }
            }
            Some(TuiAction::AccountSync) => {
                return self.sync_selected_account();
            }
            Some(TuiAction::AccountSetPrimary) => {
                self.set_primary_selected_account();
            }
            Some(TuiAction::AccountAdd) => self.start_add_account(),
            Some(TuiAction::AccountSetCredentialSource) => {
                self.start_set_credential_source();
            }
            Some(TuiAction::AccountClearCredentialSource) => {
                self.start_clear_credential_source();
            }
            _ => {}
        }
        Action::None
    }

    // ---- prompts (attachment upload / add account) ----------------------

    fn start_attachment_upload(&mut self) {
        let Some(owner) = self.current_owner() else {
            return;
        };
        let Some(entry) = self.current_entry() else {
            return;
        };
        let name = self
            .current_search()
            .map_or_else(String::new, |s| s.name.clone());
        self.mode =
            Mode::Prompt(Prompt::attachment_upload(owner, entry.id, &name));
    }

    fn start_add_account(&mut self) {
        self.mode = Mode::Prompt(Prompt::add_account());
    }

    // Open the account picker (step 1 of linking `credential_source`) for
    // the highlighted account, with the current source account (if any)
    // prefilled into the filter so re-confirming it is a no-op edit. Reads
    // the candidate account list from the already-open accounts panel
    // rather than re-querying `commands::tui_accounts` (which would hit the
    // real config file -- see `app_on_accounts_panel`'s doc comment).
    fn start_set_credential_source(&mut self) {
        let Some((name, current)) = self.selected_account_credential_source()
        else {
            return;
        };
        let Mode::Accounts(view) = &self.mode else {
            return;
        };
        let accounts = view
            .accounts
            .iter()
            .map(|a| a.name.clone())
            .filter(|n| n != &name)
            .collect();
        let prefill_account = current.map(|(account, _)| account);
        self.mode = Mode::Picker(PickerView::new(
            format!("Link '{name}' → account"),
            "type to filter · ↑/↓ select · ⏎ next · esc cancel",
            accounts,
            prefill_account,
            PickerKind::CredentialSourceAccount { name },
        ));
    }

    // Login-item names available to link `name`'s master password to, in
    // `source_account`'s vault -- from that account's already-loaded search
    // index if it's currently unlocked (one of `self.vaults`), else empty.
    // An empty list isn't an error: `PickerView`'s filter degrades to plain
    // free-text entry in that case, since a locked vault's contents can't be
    // enumerated without unlocking it first.
    fn credential_source_item_candidates(
        &self,
        source_account: &str,
    ) -> Vec<String> {
        self.vaults
            .iter()
            .find(|v| v.name == source_account)
            .map_or_else(
                || vec![CREDENTIAL_SOURCE_AUTO_ITEM.to_string()],
                |v| {
                    let mut items =
                        vec![CREDENTIAL_SOURCE_AUTO_ITEM.to_string()];
                    items.extend(
                        v.search
                            .iter()
                            .filter(|s| s.entry_type == "Login")
                            .map(|s| s.name.clone()),
                    );
                    items
                },
            )
    }

    fn handle_picker(&mut self, key: KeyEvent) -> Action {
        let Mode::Picker(view) = &mut self.mode else {
            return Action::None;
        };
        if is_ctrl_c(key) {
            self.mode = Mode::Normal;
            return Action::None;
        }
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => self.submit_picker(),
            KeyCode::Up => view.move_selected(-1),
            KeyCode::Down => view.move_selected(1),
            _ => {
                if view.filter.handle_key(key) {
                    view.recompute_filter();
                }
            }
        }
        Action::None
    }

    fn submit_picker(&mut self) {
        let Mode::Picker(view) = &self.mode else {
            return;
        };
        match &view.kind {
            PickerKind::CredentialSourceAccount { name } => {
                let value = view.current_value();
                if value.trim().is_empty() {
                    self.set_status(Level::Warn, "nothing selected");
                    return;
                }
                let name = name.clone();
                let items = self.credential_source_item_candidates(&value);
                let hint =
                    "type to filter · ↑/↓ select · blank/(auto by URI) = auto-detect · ⏎ save · esc cancel";
                self.mode = Mode::Picker(PickerView::new(
                    format!("Link '{name}' → item in '{value}'"),
                    hint,
                    items,
                    None,
                    PickerKind::CredentialSourceItem {
                        name,
                        source_account: value,
                    },
                ));
            }
            PickerKind::CredentialSourceItem {
                name,
                source_account,
            } => {
                let value = view.current_value();
                let name = name.clone();
                let source_account = source_account.clone();
                let source_item = match value.trim() {
                    "" | CREDENTIAL_SOURCE_AUTO_ITEM => None,
                    item => Some(item),
                };
                match commands::tui_account_set_credential_source(
                    &name,
                    &source_account,
                    source_item,
                ) {
                    Ok(()) => {
                        let link = source_item.map_or_else(
                            || format!("{source_account}/(auto by URI)"),
                            |item| format!("{source_account}/{item}"),
                        );
                        self.set_status(
                            Level::Success,
                            format!("linked '{name}' → {link}"),
                        );
                        // Back to the (refreshed) accounts panel.
                        self.open_accounts();
                    }
                    Err(e) => self.set_status(Level::Error, format!("{e:#}")),
                }
            }
        }
    }

    // Ask for confirmation before clearing the highlighted account's
    // `credential_source` link; a no-op (with a status message) if it has
    // none to clear.
    fn start_clear_credential_source(&mut self) {
        let Some((name, current)) = self.selected_account_credential_source()
        else {
            return;
        };
        if current.is_none() {
            self.set_status(
                Level::Info,
                format!("{name} has no credential_source set"),
            );
            return;
        }
        self.mode = Mode::ConfirmClearCredentialSource(name);
    }

    fn handle_prompt(&mut self, key: KeyEvent) -> Action {
        let Mode::Prompt(prompt) = &mut self.mode else {
            return Action::None;
        };
        if is_ctrl_c(key) {
            self.mode = Mode::Normal;
            return Action::None;
        }
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => self.submit_prompt(),
            KeyCode::Tab | KeyCode::Down => prompt.focus_next(),
            KeyCode::BackTab | KeyCode::Up => prompt.focus_prev(),
            _ => {
                if let Some(field) = prompt.fields.get_mut(prompt.focus) {
                    let _ = field.input.handle_key(key);
                }
            }
        }
        Action::None
    }

    fn submit_prompt(&mut self) {
        // Pull the field values out first so the prompt borrow is released
        // before we mutate the app / vaults below.
        let submit = {
            let Mode::Prompt(p) = &self.mode else {
                return;
            };
            match &p.kind {
                PromptKind::AttachmentUpload { owner, id } => {
                    PromptSubmit::Upload {
                        owner: *owner,
                        id: id.clone(),
                        path: p.value(0),
                    }
                }
                PromptKind::AddAccount => PromptSubmit::AddAccount {
                    name: p.value(0).trim().to_string(),
                    email: non_empty(p.value(1).trim().to_string()),
                    base_url: non_empty(p.value(2).trim().to_string()),
                },
            }
        };
        match submit {
            PromptSubmit::Upload { owner, id, path } => {
                if path.trim().is_empty() {
                    self.set_status(Level::Warn, "no file path given");
                    return;
                }
                let Some(entry) = self.vaults[owner]
                    .db
                    .entries
                    .iter()
                    .find(|e| e.id == id)
                    .cloned()
                else {
                    self.mode = Mode::Normal;
                    self.set_status(Level::Error, "entry no longer exists");
                    return;
                };
                if let Err(e) = crate::actions::set_active_account(Some(
                    self.vaults[owner].name.clone(),
                )) {
                    self.set_status(Level::Error, format!("{e:#}"));
                    return;
                }
                match commands::tui_attachment_create(
                    &mut self.vaults[owner].db,
                    &entry,
                    &expand_tilde(path.trim()),
                ) {
                    Ok(()) => {
                        self.mode = Mode::Normal;
                        self.reload_vault(owner);
                        self.set_status(
                            Level::Success,
                            "attachment uploaded",
                        );
                    }
                    Err(e) => self.set_status(Level::Error, format!("{e:#}")),
                }
            }
            PromptSubmit::AddAccount {
                name,
                email,
                base_url,
            } => match commands::tui_account_add(&name, email, base_url) {
                Ok(()) => {
                    self.set_status(
                        Level::Success,
                        format!("added account '{name}'"),
                    );
                    // Back to the (refreshed) accounts panel.
                    self.open_accounts();
                }
                Err(e) => self.set_status(Level::Error, format!("{e:#}")),
            },
        }
    }

    // ---- settings panel ---------------------------------------------------

    fn open_settings(&mut self) {
        let policy = commands::tui_password_gen_policy();
        self.mode = Mode::Settings(SettingsView::new(&policy));
    }

    fn handle_settings(&mut self, key: KeyEvent) -> Action {
        let Mode::Settings(view) = &mut self.mode else {
            return Action::None;
        };
        if is_ctrl_c(key) {
            self.mode = Mode::Normal;
            return Action::None;
        }
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => self.submit_settings(),
            KeyCode::Tab | KeyCode::Down => view.focus_next(),
            KeyCode::BackTab | KeyCode::Up => view.focus_prev(),
            KeyCode::Char(' ') => view.toggle_focused(),
            _ => view.handle_input(key),
        }
        Action::None
    }

    fn submit_settings(&mut self) {
        // Pull the rebuilt policy out first so the `Mode::Settings` borrow is
        // released before saving/closing mutate the app.
        let policy = {
            let Mode::Settings(view) = &self.mode else {
                return;
            };
            view.rebuild_policy()
        };
        match policy {
            Ok(policy) => {
                match commands::tui_save_password_gen_policy(policy) {
                    Ok(()) => {
                        self.mode = Mode::Normal;
                        self.set_status(
                            Level::Success,
                            "saved password-gen settings",
                        );
                    }
                    Err(e) => self.set_status(Level::Error, format!("{e:#}")),
                }
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    // ---- mouse handling ---------------------------------------------------

    // Right-arrow equivalent (also used for a detail-pane click): focus the
    // detail pane so Up/Down scroll it instead of moving the list selection.
    pub fn focus_detail(&mut self) {
        if matches!(self.mode, Mode::Normal) && !self.filtered.is_empty() {
            self.detail_focused = true;
        }
    }

    // Left-arrow/Esc equivalent (also used for a list-pane click): focus
    // back on the list.
    pub fn focus_list(&mut self) {
        if matches!(self.mode, Mode::Normal) {
            self.detail_focused = false;
        }
    }

    // Mouse wheel over the detail pane.
    pub fn mouse_scroll_detail(&mut self, delta: isize) {
        if matches!(self.mode, Mode::Normal) {
            self.scroll_detail(delta);
        }
    }

    // Mouse wheel over the list pane.
    pub fn mouse_scroll_list(&mut self, delta: isize) {
        if matches!(self.mode, Mode::Normal | Mode::Search) {
            self.move_by(delta);
        }
    }

    // ---- key handling ---------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        // Checked before any per-mode dispatch (and so before any dialog
        // gets a chance to treat it as its own "close" key instead) so a
        // configured `force_quit` chord exits the whole TUI from any mode.
        // No default chord (see `TuiAction::ForceQuit`), so this is a no-op
        // for anyone who hasn't opted in via `tui_keybindings`.
        if self.keymap.action_for(key, true) == Some(TuiAction::ForceQuit) {
            return Action::Quit;
        }

        // Any interaction clears the transient status line.
        self.status = None;
        match &mut self.mode {
            Mode::Normal => self.handle_normal(key),
            Mode::Search => self.handle_search(key),
            Mode::Edit(_) => self.handle_edit(key),
            Mode::ConfirmDelete => {
                self.handle_confirm(key);
                Action::None
            }
            Mode::Attachments(_) => {
                self.handle_attachments(key);
                Action::None
            }
            Mode::Accounts(_) => self.handle_accounts(key),
            Mode::ConfirmClearCredentialSource(_) => {
                self.handle_confirm_clear_credential_source(key);
                Action::None
            }
            Mode::Prompt(_) => self.handle_prompt(key),
            Mode::Picker(_) => self.handle_picker(key),
            Mode::Settings(_) => self.handle_settings(key),
            Mode::Help => {
                self.mode = Mode::Normal;
                Action::None
            }
            Mode::LockedPrompt(_) => self.handle_locked_prompt(key),
            Mode::SessionExpiredPrompt(_) => {
                self.handle_session_expired_prompt(key)
            }
        }
    }

    // Keys that behave identically whether the search bar or the list is
    // focused: list navigation, secret reveal, the external editor, and the
    // Alt-modified quick actions (so a power user never has to leave the
    // filter). Returns `Some` when the key was consumed here.
    // Only resolves actions whose chord isn't a plain, unmodified character
    // (`Keymap::action_for(key, false)`), so a caller with a text-input
    // widget (the search filter) never has typing swallowed by an action.
    fn handle_shared(&mut self, key: KeyEvent) -> Option<Action> {
        match self.keymap.action_for(key, false)? {
            TuiAction::MoveUp => self.move_or_scroll(-1),
            TuiAction::MoveDown => self.move_or_scroll(1),
            TuiAction::PageUp => self.move_by(-10),
            TuiAction::PageDown => self.move_by(10),
            TuiAction::Quit => return Some(Action::Quit),
            TuiAction::OpenEditor => return Some(Action::OpenEditor),
            TuiAction::Sync => self.sync(),
            TuiAction::ToggleReveal => self.reveal = !self.reveal,
            TuiAction::CopyPassword => self.copy_password(),
            TuiAction::CopyUsername => self.copy_username(),
            TuiAction::CopyTotp => self.copy_totp(),
            TuiAction::OpenUri => self.open_uri(),
            TuiAction::OpenAttachments => self.open_attachments(),
            TuiAction::ScrollDetailDown => self.scroll_detail(1),
            TuiAction::ScrollDetailUp => self.scroll_detail(-1),
            _ => return None,
        }
        Some(Action::None)
    }

    fn handle_normal(&mut self, key: KeyEvent) -> Action {
        if let Some(action) = self.handle_shared(key) {
            return action;
        }
        // Esc backs out one level: first out of a focused detail pane, then
        // (a near-universal convention worth keeping even if `quit` is
        // rebound away from it) out of Normal mode entirely.
        if key.code == KeyCode::Esc {
            if self.detail_focused {
                self.detail_focused = false;
                return Action::None;
            }
            return Action::Quit;
        }
        match self.keymap.action_for(key, true) {
            Some(TuiAction::Quit) => return Action::Quit,
            Some(TuiAction::MoveDown) => self.move_or_scroll(1),
            Some(TuiAction::MoveUp) => self.move_or_scroll(-1),
            Some(TuiAction::JumpFirst) => self.select(0),
            Some(TuiAction::JumpLast) => self.select(self.filtered.len()),
            Some(TuiAction::ScrollDetailDown) => self.scroll_detail(1),
            Some(TuiAction::ScrollDetailUp) => self.scroll_detail(-1),
            Some(TuiAction::FocusDetail) => self.focus_detail(),
            Some(TuiAction::FocusList) => self.focus_list(),
            Some(TuiAction::ToggleSearch) => self.mode = Mode::Search,
            Some(TuiAction::ToggleReveal) => self.reveal = !self.reveal,
            Some(TuiAction::CopyPassword) => self.copy_password(),
            Some(TuiAction::CopyUsername) => self.copy_username(),
            Some(TuiAction::CopyTotp) => self.copy_totp(),
            Some(TuiAction::OpenUri) => self.open_uri(),
            Some(TuiAction::OpenAttachments) => self.open_attachments(),
            Some(TuiAction::StartEdit) => self.start_edit(),
            Some(TuiAction::OpenEditor) => return Action::OpenEditor,
            Some(TuiAction::StartAdd) => self.start_add(),
            Some(TuiAction::OpenAccounts) => self.open_accounts(),
            Some(TuiAction::OpenSettings) => self.open_settings(),
            Some(TuiAction::DeleteEntry)
                if self.current_search().is_some() =>
            {
                self.mode = Mode::ConfirmDelete;
            }
            Some(TuiAction::Sync) => self.sync(),
            Some(TuiAction::Help) => self.mode = Mode::Help,
            _ => {}
        }
        Action::None
    }

    fn handle_search(&mut self, key: KeyEvent) -> Action {
        if let Some(action) = self.handle_shared(key) {
            return action;
        }
        match key.code {
            KeyCode::Esc => {
                // First Esc clears a non-empty filter; a second one quits.
                if self.filter.value().is_empty() {
                    return Action::Quit;
                }
                self.filter.clear();
                self.recompute_filter();
                self.select(0);
            }
            // Hand off to the list so single-key actions become available.
            KeyCode::Enter | KeyCode::Tab => self.mode = Mode::Normal,
            _ => {
                if self.filter.handle_key(key) {
                    self.recompute_filter();
                    self.select(0);
                }
            }
        }
        Action::None
    }

    fn handle_attachments(&mut self, key: KeyEvent) {
        let action = if is_ctrl_c(key) {
            Some(TuiAction::AttachmentClose)
        } else {
            self.keymap.action_in(key, true, TuiAction::ATTACHMENT)
        };
        // Any key other than a repeated delete cancels a pending confirm.
        if action != Some(TuiAction::AttachmentDelete) {
            if let Mode::Attachments(v) = &mut self.mode {
                v.pending_delete = false;
            }
        }
        match action {
            Some(TuiAction::AttachmentClose) => self.mode = Mode::Normal,
            Some(TuiAction::AttachmentMoveDown) => self.attachment_move(1),
            Some(TuiAction::AttachmentMoveUp) => self.attachment_move(-1),
            Some(TuiAction::AttachmentDownload) => self.download_attachment(),
            Some(TuiAction::AttachmentUpload) => {
                self.start_attachment_upload();
            }
            Some(TuiAction::AttachmentDelete) => {
                self.attachment_delete_pressed();
            }
            _ => {}
        }
    }

    // `d` in the picker: first press arms the confirm, second deletes.
    fn attachment_delete_pressed(&mut self) {
        let (armed, att_id) = if let Mode::Attachments(v) = &self.mode {
            (
                v.pending_delete,
                v.items.get(v.selected).map(|i| i.id.clone()),
            )
        } else {
            (false, None)
        };
        let Some(att_id) = att_id else {
            return;
        };
        if !armed {
            if let Mode::Attachments(v) = &mut self.mode {
                v.pending_delete = true;
            }
            self.set_status(Level::Warn, "press d again to confirm delete");
            return;
        }
        let Some(owner) = self.current_owner() else {
            return;
        };
        let Some(entry) = self.current_entry() else {
            return;
        };
        if let Err(e) = self.activate_current() {
            self.set_status(Level::Error, format!("{e:#}"));
            return;
        }
        match commands::tui_attachment_delete(
            &mut self.vaults[owner].db,
            &entry,
            &att_id,
        ) {
            Ok(()) => {
                self.reload_vault(owner);
                self.set_status(Level::Success, "attachment deleted");
                // Reopen the picker so the remaining attachments refresh.
                self.open_attachments();
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    fn handle_edit(&mut self, key: KeyEvent) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // Editor fallback only applies to an existing entry.
        if ctrl && matches!(key.code, KeyCode::Char('e')) {
            if let Mode::Edit(form) = &self.mode {
                if form.entry_id.is_some() {
                    return Action::OpenEditor;
                }
            }
            return Action::None;
        }

        if ctrl && matches!(key.code, KeyCode::Char('c')) {
            self.mode = Mode::Normal;
            return Action::None;
        }

        let Mode::Edit(form) = &mut self.mode else {
            return Action::None;
        };
        match key.code {
            KeyCode::Esc => self.mode = Mode::Normal,
            KeyCode::Enter => self.submit_form(),
            KeyCode::Tab | KeyCode::Down => form.focus_next(),
            KeyCode::BackTab | KeyCode::Up => form.focus_prev(),
            KeyCode::Char('r') if ctrl => form.reveal = !form.reveal,
            _ => {
                form.handle_input(key);
            }
        }
        Action::None
    }

    fn handle_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                self.confirm_delete();
            }
            _ => self.mode = Mode::Normal,
        }
    }

    // Either way (confirm or cancel), back out to the (refreshed) accounts
    // panel rather than all the way to `Mode::Normal` -- this dialog is only
    // reachable from there.
    fn handle_confirm_clear_credential_source(&mut self, key: KeyEvent) {
        let Mode::ConfirmClearCredentialSource(name) = &self.mode else {
            return;
        };
        let name = name.clone();
        if matches!(key.code, KeyCode::Char('y' | 'Y') | KeyCode::Enter) {
            match commands::tui_account_clear_credential_source(&name) {
                Ok(()) => self.set_status(
                    Level::Success,
                    format!("cleared credential_source for '{name}'"),
                ),
                Err(e) => self.set_status(Level::Error, format!("{e:#}")),
            }
        }
        self.open_accounts();
    }
}

// ---- form ---------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Name,
    Username,
    Password,
    Totp,
    Url,
    Folder,
    Notes,
    Cardholder,
    CardNumber,
    Brand,
    ExpMonth,
    ExpYear,
    Cvv,
    FirstName,
    LastName,
    Email,
    Phone,
}

pub struct FormField {
    pub label: &'static str,
    pub kind: FieldKind,
    pub input: Input,
    pub secret: bool,
    // Notes containing newlines are shown read-only (edit via $EDITOR) so the
    // single-line field can't silently flatten them.
    pub editable: bool,
}

impl FormField {
    fn text(label: &'static str, kind: FieldKind, value: &str) -> Self {
        Self {
            label,
            kind,
            input: Input::new(value),
            secret: false,
            editable: true,
        }
    }

    fn secret(label: &'static str, kind: FieldKind, value: &str) -> Self {
        Self {
            label,
            kind,
            input: Input::new(value),
            secret: true,
            editable: true,
        }
    }
}

pub struct EditForm {
    pub title: String,
    entry_id: Option<String>,
    // Which vault the entry belongs to (for an edit) or will be created in (for
    // an add). Used to route the save to the right account.
    owner: usize,
    // The original editable, preserved so fields the inline form doesn't expose
    // (extra URIs, custom fields, full identity/ssh data) survive a save.
    base: EditableCipher,
    pub fields: Vec<FormField>,
    pub focus: usize,
    pub reveal: bool,
}

impl EditForm {
    fn new(
        title: String,
        entry_id: Option<String>,
        owner: usize,
        base: EditableCipher,
    ) -> Self {
        let fields = build_fields(&base);
        Self {
            title,
            entry_id,
            owner,
            base,
            fields,
            focus: 0,
            reveal: false,
        }
    }

    fn focus_next(&mut self) {
        if !self.fields.is_empty() {
            self.focus = (self.focus + 1) % self.fields.len();
        }
    }

    fn focus_prev(&mut self) {
        if !self.fields.is_empty() {
            self.focus =
                (self.focus + self.fields.len() - 1) % self.fields.len();
        }
    }

    fn handle_input(&mut self, key: KeyEvent) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            if field.editable {
                let _consumed = field.input.handle_key(key);
            }
        }
    }

    // Fold the edited field values back into a copy of the original editable.
    fn rebuild_editable(&self) -> EditableCipher {
        let mut base = clone_editable(&self.base);
        for field in &self.fields {
            let v = field.input.value().to_string();
            apply_field(&mut base, field.kind, v, field.editable);
        }
        base
    }
}

fn build_fields(base: &EditableCipher) -> Vec<FormField> {
    let mut f = vec![FormField::text("Name", FieldKind::Name, &base.name)];
    match &base.data {
        EditableData::Login {
            username,
            password,
            uris,
            totp,
        } => {
            f.push(FormField::text(
                "Username",
                FieldKind::Username,
                opt(username),
            ));
            f.push(FormField::secret(
                "Password",
                FieldKind::Password,
                opt(password),
            ));
            f.push(FormField::secret("TOTP", FieldKind::Totp, opt(totp)));
            let url = uris.first().map_or("", |u| u.uri.as_str());
            f.push(FormField::text("URL", FieldKind::Url, url));
        }
        EditableData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            f.push(FormField::text(
                "Cardholder",
                FieldKind::Cardholder,
                opt(cardholder_name),
            ));
            f.push(FormField::secret(
                "Number",
                FieldKind::CardNumber,
                opt(number),
            ));
            f.push(FormField::text("Brand", FieldKind::Brand, opt(brand)));
            f.push(FormField::text(
                "Exp month",
                FieldKind::ExpMonth,
                opt(exp_month),
            ));
            f.push(FormField::text(
                "Exp year",
                FieldKind::ExpYear,
                opt(exp_year),
            ));
            f.push(FormField::secret("CVV", FieldKind::Cvv, opt(code)));
        }
        EditableData::Identity {
            first_name,
            last_name,
            email,
            phone,
            ..
        } => {
            f.push(FormField::text(
                "First name",
                FieldKind::FirstName,
                opt(first_name),
            ));
            f.push(FormField::text(
                "Last name",
                FieldKind::LastName,
                opt(last_name),
            ));
            f.push(FormField::text("Email", FieldKind::Email, opt(email)));
            f.push(FormField::text("Phone", FieldKind::Phone, opt(phone)));
        }
        EditableData::SecureNote | EditableData::SshKey { .. } => {}
    }
    f.push(FormField::text(
        "Folder",
        FieldKind::Folder,
        base.folder.as_deref().unwrap_or(""),
    ));
    let notes = base.notes.as_deref().unwrap_or("");
    let editable = !notes.contains('\n');
    f.push(FormField {
        label: "Notes",
        kind: FieldKind::Notes,
        input: Input::new(if editable { notes } else { "" }),
        secret: false,
        editable,
    });
    f
}

fn apply_field(
    base: &mut EditableCipher,
    kind: FieldKind,
    v: String,
    editable: bool,
) {
    match kind {
        FieldKind::Name => base.name = v,
        FieldKind::Folder => base.folder = non_empty(v),
        FieldKind::Notes => {
            if editable {
                base.notes = non_empty(v);
            }
        }
        FieldKind::Username => {
            if let EditableData::Login { username, .. } = &mut base.data {
                *username = non_empty(v);
            } else if let EditableData::Identity { username, .. } =
                &mut base.data
            {
                *username = non_empty(v);
            }
        }
        FieldKind::Password => {
            if let EditableData::Login { password, .. } = &mut base.data {
                *password = non_empty(v);
            }
        }
        FieldKind::Totp => {
            if let EditableData::Login { totp, .. } = &mut base.data {
                *totp = non_empty(v);
            }
        }
        FieldKind::Url => {
            if let EditableData::Login { uris, .. } = &mut base.data {
                if let Some(first) = uris.first_mut() {
                    first.uri = v;
                } else if !v.is_empty() {
                    uris.push(EditableUri {
                        uri: v,
                        match_type: None,
                    });
                }
            }
        }
        FieldKind::Cardholder => {
            if let EditableData::Card {
                cardholder_name, ..
            } = &mut base.data
            {
                *cardholder_name = non_empty(v);
            }
        }
        FieldKind::CardNumber => {
            if let EditableData::Card { number, .. } = &mut base.data {
                *number = non_empty(v);
            }
        }
        FieldKind::Brand => {
            if let EditableData::Card { brand, .. } = &mut base.data {
                *brand = non_empty(v);
            }
        }
        FieldKind::ExpMonth => {
            if let EditableData::Card { exp_month, .. } = &mut base.data {
                *exp_month = non_empty(v);
            }
        }
        FieldKind::ExpYear => {
            if let EditableData::Card { exp_year, .. } = &mut base.data {
                *exp_year = non_empty(v);
            }
        }
        FieldKind::Cvv => {
            if let EditableData::Card { code, .. } = &mut base.data {
                *code = non_empty(v);
            }
        }
        FieldKind::FirstName => {
            if let EditableData::Identity { first_name, .. } = &mut base.data
            {
                *first_name = non_empty(v);
            }
        }
        FieldKind::LastName => {
            if let EditableData::Identity { last_name, .. } = &mut base.data {
                *last_name = non_empty(v);
            }
        }
        FieldKind::Email => {
            if let EditableData::Identity { email, .. } = &mut base.data {
                *email = non_empty(v);
            }
        }
        FieldKind::Phone => {
            if let EditableData::Identity { phone, .. } = &mut base.data {
                *phone = non_empty(v);
            }
        }
    }
}

// ---- settings panel -------------------------------------------------------
//
// A general key/value settings editor, currently populated with just the
// password-generation policy (see `rbw::config::PasswordGenPolicy`). Meant
// to grow other config.json knobs later (e.g. the not-yet-implemented
// cross-account credential linking noted in TODO.md) by adding cases to
// `SettingKind`/`build_settings_fields`/`SettingsView::rebuild_policy`
// rather than restructuring the panel.

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingKind {
    Length,
    NoSymbols,
    OnlyNumbers,
    Nonconfusables,
    Diceware,
}

// A field's current value: free text (with its own cursor) or an on/off
// toggle. `render_settings` (in `ui.rs`) draws these differently and
// `SettingsView::handle_input`/`toggle_focused` route keys to the right one.
pub enum SettingValue {
    Text(Input),
    Toggle(bool),
}

pub struct SettingsField {
    pub label: &'static str,
    kind: SettingKind,
    pub value: SettingValue,
}

// The settings panel: a flat, navigable list of editable fields plus a
// cursor. Opened from `Mode::Normal` via `TuiAction::OpenSettings`; mirrors
// `EditForm`'s focus/submit/cancel shape (see `handle_settings` in `App`).
pub struct SettingsView {
    pub fields: Vec<SettingsField>,
    pub focus: usize,
}

impl SettingsView {
    pub fn new(policy: &rbw::config::PasswordGenPolicy) -> Self {
        Self {
            fields: build_settings_fields(policy),
            focus: 0,
        }
    }

    fn focus_next(&mut self) {
        if !self.fields.is_empty() {
            self.focus = (self.focus + 1) % self.fields.len();
        }
    }

    fn focus_prev(&mut self) {
        if !self.fields.is_empty() {
            self.focus =
                (self.focus + self.fields.len() - 1) % self.fields.len();
        }
    }

    // Space toggles the focused field if it's a `Toggle`; a no-op on a
    // `Text` field (typing a literal space into the length field has no
    // legitimate use, so this can't shadow real input).
    fn toggle_focused(&mut self) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            if let SettingValue::Toggle(b) = &mut field.value {
                *b = !*b;
            }
        }
    }

    fn handle_input(&mut self, key: KeyEvent) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            if let SettingValue::Text(input) = &mut field.value {
                let _consumed = input.handle_key(key);
            }
        }
    }

    // Fold the edited fields back into a policy, validating the free-text
    // length field along the way.
    fn rebuild_policy(
        &self,
    ) -> anyhow::Result<rbw::config::PasswordGenPolicy> {
        let mut policy = rbw::config::PasswordGenPolicy::default();
        for field in &self.fields {
            match (field.kind, &field.value) {
                (SettingKind::Length, SettingValue::Text(input)) => {
                    let v = input.value().trim();
                    policy.length = if v.is_empty() {
                        None
                    } else {
                        Some(v.parse().map_err(|_| {
                            anyhow::anyhow!(
                                "length must be a positive whole number"
                            )
                        })?)
                    };
                }
                (SettingKind::NoSymbols, SettingValue::Toggle(b)) => {
                    policy.no_symbols = *b;
                }
                (SettingKind::OnlyNumbers, SettingValue::Toggle(b)) => {
                    policy.only_numbers = *b;
                }
                (SettingKind::Nonconfusables, SettingValue::Toggle(b)) => {
                    policy.nonconfusables = *b;
                }
                (SettingKind::Diceware, SettingValue::Toggle(b)) => {
                    policy.diceware = *b;
                }
                // Kinds and values always pair up as built by
                // `build_settings_fields`; nothing else to match.
                _ => {}
            }
        }
        Ok(policy)
    }
}

fn build_settings_fields(
    policy: &rbw::config::PasswordGenPolicy,
) -> Vec<SettingsField> {
    vec![
        SettingsField {
            label: "Length",
            kind: SettingKind::Length,
            value: SettingValue::Text(Input::new(
                policy.length.map_or_else(String::new, |l| l.to_string()),
            )),
        },
        SettingsField {
            label: "No symbols",
            kind: SettingKind::NoSymbols,
            value: SettingValue::Toggle(policy.no_symbols),
        },
        SettingsField {
            label: "Only numbers",
            kind: SettingKind::OnlyNumbers,
            value: SettingValue::Toggle(policy.only_numbers),
        },
        SettingsField {
            label: "Non-confusables",
            kind: SettingKind::Nonconfusables,
            value: SettingValue::Toggle(policy.nonconfusables),
        },
        SettingsField {
            label: "Diceware",
            kind: SettingKind::Diceware,
            value: SettingValue::Toggle(policy.diceware),
        },
    ]
}

// ---- small helpers ------------------------------------------------------

#[allow(clippy::ref_option)]
fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("")
}

fn non_empty(v: String) -> Option<String> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

// `EditableCipher` isn't `Clone` (it lives in `commands`); round-trip through
// its serde representation to get an independent copy for editing.
fn clone_editable(base: &EditableCipher) -> EditableCipher {
    serde_yaml::from_str(&serde_yaml::to_string(base).unwrap_or_default())
        .unwrap_or_else(|_| EditableCipher {
            name: base.name.clone(),
            folder: base.folder.clone(),
            notes: base.notes.clone(),
            data: EditableData::SecureNote,
            fields: Vec::new(),
        })
}

fn detail_password(detail: &DecryptedCipher) -> Option<String> {
    match &detail.data {
        DecryptedData::Login { password, .. } => password.clone(),
        DecryptedData::Card { number, .. } => number.clone(),
        _ => detail
            .notes
            .clone()
            .filter(|_| matches!(detail.data, DecryptedData::SecureNote)),
    }
}

fn detail_username(detail: &DecryptedCipher) -> Option<String> {
    match &detail.data {
        DecryptedData::Login { username, .. }
        | DecryptedData::Identity { username, .. } => username.clone(),
        _ => None,
    }
}

fn detail_totp_secret(detail: &DecryptedCipher) -> Option<String> {
    match &detail.data {
        DecryptedData::Login { totp, .. } => totp.clone(),
        _ => None,
    }
}

fn detail_first_uri(detail: &DecryptedCipher) -> Option<String> {
    match &detail.data {
        DecryptedData::Login {
            uris: Some(uris), ..
        } => uris.first().map(|u| u.uri.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::{
        AccountsView, Action, App, AttachmentItem, AttachmentView, Keymap,
        Mode, PickerKind, Prompt, SettingValue,
    };
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn app() -> App {
        App::with_keymap(
            crate::commands::TuiOpen {
                vaults: vec![crate::commands::TuiVault {
                    account: "default".to_string(),
                    db: rbw::db::Db::new(),
                    search: Vec::new(),
                }],
                locked: Vec::new(),
                multi: false,
            },
            None,
            Keymap::resolve(&std::collections::HashMap::new()),
        )
    }

    // Like `app()`, but with `force_quit` bound -- for the one test that
    // needs it configured, since it has no default chord.
    fn app_with_force_quit_bound() -> App {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("force_quit".to_string(), vec!["alt-Q".to_string()]);
        App::with_keymap(
            crate::commands::TuiOpen {
                vaults: vec![crate::commands::TuiVault {
                    account: "default".to_string(),
                    db: rbw::db::Db::new(),
                    search: Vec::new(),
                }],
                locked: Vec::new(),
                multi: false,
            },
            None,
            Keymap::resolve(&overrides),
        )
    }

    // Like `app()`, but with `n` selectable entries and focus already handed
    // to the list, for tests that need something to focus/scroll onto. The
    // entries never actually decrypt (no agent in a unit test), but
    // `ensure_detail` still indexes into `db.entries` before finding that
    // out, so a same-length placeholder `Entry` per search result is needed
    // to avoid an out-of-bounds panic.
    fn app_with_entries(n: usize) -> App {
        let mut search = Vec::new();
        let mut entries = Vec::new();
        for i in 0..n {
            let id = format!("entry-{i}");
            search.push(crate::commands::DecryptedSearchCipher::test_entry(
                &id,
            ));
            entries.push(rbw::db::Entry {
                id: id.clone(),
                org_id: None,
                folder: None,
                folder_id: None,
                name: id,
                data: rbw::db::EntryData::Login {
                    username: None,
                    password: None,
                    totp: None,
                    uris: vec![],
                },
                fields: vec![],
                notes: None,
                history: vec![],
                key: None,
                master_password_reprompt: rbw::api::CipherRepromptType::None,
                collection_ids: vec![],
                attachments: vec![],
            });
        }
        let mut db = rbw::db::Db::new();
        db.entries = entries;
        let mut a = App::with_keymap(
            crate::commands::TuiOpen {
                vaults: vec![crate::commands::TuiVault {
                    account: "default".to_string(),
                    db,
                    search,
                }],
                locked: Vec::new(),
                multi: false,
            },
            None,
            Keymap::resolve(&std::collections::HashMap::new()),
        );
        a.mode = Mode::Normal;
        a
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    // Search is the default focus and bare characters filter immediately.
    #[test]
    fn starts_in_search_and_types_to_filter() {
        let mut a = app();
        assert!(matches!(a.mode, Mode::Search));
        a.handle_key(key(KeyCode::Char('g')));
        a.handle_key(key(KeyCode::Char('h')));
        assert_eq!(a.filter.value(), "gh");
        assert!(matches!(a.mode, Mode::Search));
    }

    // Ctrl-E must reach the external editor whether the search bar or the list
    // holds focus.
    #[test]
    fn ctrl_e_opens_editor_from_any_focus() {
        let mut a = app();
        assert!(matches!(a.handle_key(ctrl('e')), Action::OpenEditor));
        a.handle_key(key(KeyCode::Tab)); // hand off to the list
        assert!(matches!(a.mode, Mode::Normal));
        assert!(matches!(a.handle_key(ctrl('e')), Action::OpenEditor));
    }

    // Tab drops into the list for single-key actions; `/` returns to the filter.
    #[test]
    fn tab_and_slash_toggle_focus() {
        let mut a = app();
        a.handle_key(key(KeyCode::Tab));
        assert!(matches!(a.mode, Mode::Normal));
        a.handle_key(key(KeyCode::Char('/')));
        assert!(matches!(a.mode, Mode::Search));
    }

    // The first Esc clears a non-empty filter; a second one quits.
    #[test]
    fn esc_clears_filter_then_quits() {
        let mut a = app();
        a.handle_key(key(KeyCode::Char('x')));
        assert_eq!(a.filter.value(), "x");
        assert!(matches!(a.handle_key(key(KeyCode::Esc)), Action::None));
        assert_eq!(a.filter.value(), "");
        assert!(matches!(a.handle_key(key(KeyCode::Esc)), Action::Quit));
    }

    // Right arrow focuses the detail pane; Left returns focus to the list.
    #[test]
    fn right_and_left_arrows_toggle_detail_focus() {
        let mut a = app_with_entries(2);
        assert!(!a.detail_focused);
        a.handle_key(key(KeyCode::Right));
        assert!(a.detail_focused);
        a.handle_key(key(KeyCode::Left));
        assert!(!a.detail_focused);
    }

    // Right arrow is a no-op with nothing in the list to show.
    #[test]
    fn right_arrow_is_a_noop_on_an_empty_list() {
        let mut a = app_with_entries(0);
        a.handle_key(key(KeyCode::Right));
        assert!(!a.detail_focused);
    }

    // Esc on a focused detail pane backs out to the list instead of quitting;
    // a second Esc then quits as usual.
    #[test]
    fn esc_backs_out_of_detail_focus_before_quitting() {
        let mut a = app_with_entries(2);
        a.handle_key(key(KeyCode::Right));
        assert!(a.detail_focused);
        assert!(matches!(a.handle_key(key(KeyCode::Esc)), Action::None));
        assert!(!a.detail_focused);
        assert!(matches!(a.handle_key(key(KeyCode::Esc)), Action::Quit));
    }

    // Up/Down move the list selection normally, but scroll the detail pane
    // instead once it's focused.
    #[test]
    fn up_down_scroll_detail_instead_of_moving_selection_when_focused() {
        let mut a = app_with_entries(3);
        a.detail_max_scroll.set(5);
        a.handle_key(key(KeyCode::Down));
        assert_eq!(a.selected, 1);
        assert_eq!(a.detail_scroll, 0);

        a.handle_key(key(KeyCode::Right));
        a.handle_key(key(KeyCode::Down));
        assert_eq!(a.selected, 1, "selection shouldn't move while focused");
        assert_eq!(a.detail_scroll, 1);

        a.handle_key(key(KeyCode::Up));
        assert_eq!(a.detail_scroll, 0);
    }

    // A preview that already fits the pane (`detail_max_scroll` still at its
    // default 0) doesn't accumulate scroll either direction.
    #[test]
    fn detail_scroll_is_a_noop_when_nothing_overflows_the_pane() {
        let mut a = app_with_entries(1);
        a.handle_key(key(KeyCode::Right));
        a.handle_key(key(KeyCode::Down));
        assert_eq!(a.detail_scroll, 0);
    }

    // Detail scroll never exceeds what the renderer last reported as
    // scrollable, so repeated Down presses can't rack up a backlog that
    // later Up presses have to silently eat through.
    #[test]
    fn detail_scroll_is_clamped_to_the_rendered_max() {
        let mut a = app_with_entries(1);
        a.detail_max_scroll.set(2);
        a.handle_key(key(KeyCode::Right));
        for _ in 0..10 {
            a.handle_key(key(KeyCode::Down));
        }
        assert_eq!(a.detail_scroll, 2);
    }

    // Mouse: clicking into a pane focuses it, same as the arrow keys.
    #[test]
    fn mouse_focus_matches_arrow_key_focus() {
        let mut a = app_with_entries(2);
        a.focus_detail();
        assert!(a.detail_focused);
        a.focus_list();
        assert!(!a.detail_focused);
    }

    #[test]
    fn mouse_scroll_over_detail_only_affects_detail_scroll() {
        let mut a = app_with_entries(2);
        a.detail_max_scroll.set(5);
        a.mouse_scroll_detail(1);
        assert_eq!(a.detail_scroll, 1);
        assert_eq!(a.selected, 0);
    }

    // `S` opens the settings panel from Normal mode; Esc backs out without
    // touching anything (mirrors the Accounts/Prompt panels' cancel path).
    #[test]
    fn s_opens_settings_and_esc_closes_it() {
        let mut a = app_with_entries(1);
        assert!(matches!(a.mode, Mode::Normal));
        a.handle_key(key(KeyCode::Char('S')));
        assert!(matches!(a.mode, Mode::Settings(_)));
        a.handle_key(key(KeyCode::Esc));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Ctrl+C dismisses the settings panel exactly like Esc -- raw mode means
    // it never becomes a real SIGINT, so every modal overlay must treat it
    // as an explicit "close" key instead of leaving it a silent no-op.
    #[test]
    fn s_opens_settings_and_ctrl_c_closes_it() {
        let mut a = app_with_entries(1);
        a.handle_key(key(KeyCode::Char('S')));
        assert!(matches!(a.mode, Mode::Settings(_)));
        a.handle_key(ctrl('c'));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Same regression, for the add/edit entry form.
    #[test]
    fn edit_form_ctrl_c_cancels() {
        let mut a = app_with_entries(1);
        a.handle_key(key(KeyCode::Char('a'))); // start_add -> Mode::Edit
        assert!(matches!(a.mode, Mode::Edit(_)));
        a.handle_key(ctrl('c'));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Tab moves focus to the next field, and Space toggles a focused boolean
    // field in place -- doesn't touch the (unfocused) length field.
    #[test]
    fn settings_tab_and_space_toggle_a_boolean_field() {
        let mut a = app_with_entries(1);
        a.handle_key(key(KeyCode::Char('S')));

        let Mode::Settings(view) = &a.mode else {
            panic!("expected settings mode");
        };
        assert!(matches!(view.fields[1].value, SettingValue::Toggle(false)));

        a.handle_key(key(KeyCode::Tab)); // Length -> No symbols
        a.handle_key(key(KeyCode::Char(' '))); // toggle it on

        let Mode::Settings(view) = &a.mode else {
            panic!("expected settings mode");
        };
        assert!(matches!(view.fields[1].value, SettingValue::Toggle(true)));
        // Toggling only affects the focused field.
        let SettingValue::Text(length) = &view.fields[0].value else {
            panic!("expected the length field to stay text");
        };
        assert!(length.value().is_empty());
    }

    // Typed digits land in the (initially focused) length field.
    #[test]
    fn settings_length_field_accepts_typed_digits() {
        let mut a = app_with_entries(1);
        a.handle_key(key(KeyCode::Char('S')));
        a.handle_key(key(KeyCode::Char('3')));
        a.handle_key(key(KeyCode::Char('2')));

        let Mode::Settings(view) = &a.mode else {
            panic!("expected settings mode");
        };
        let SettingValue::Text(length) = &view.fields[0].value else {
            panic!("expected the length field to be text");
        };
        assert_eq!(length.value(), "32");
    }

    // What Enter would persist: edits to the length field and a toggle both
    // fold into the rebuilt policy correctly. Stops short of actually
    // exercising `commands::tui_save_password_gen_policy` (which Enter also
    // triggers), since that writes the real config.json -- same reason
    // `tui_account_add`/`tui_set_primary` aren't exercised end-to-end here
    // either.
    #[test]
    fn settings_rebuild_policy_reflects_edits() {
        let mut a = app_with_entries(1);
        a.handle_key(key(KeyCode::Char('S')));
        a.handle_key(key(KeyCode::Char('2')));
        a.handle_key(key(KeyCode::Char('4')));
        a.handle_key(key(KeyCode::Tab)); // Length -> No symbols
        a.handle_key(key(KeyCode::Char(' '))); // toggle it on

        let Mode::Settings(view) = &a.mode else {
            panic!("expected settings mode");
        };
        let policy = view.rebuild_policy().unwrap();
        assert_eq!(policy.length, Some(24));
        assert!(policy.no_symbols);
        assert!(!policy.only_numbers);
        assert!(!policy.nonconfusables);
        assert!(!policy.diceware);
    }

    // A non-numeric length is rejected rather than silently discarded, so a
    // typo can't quietly wipe out the configured length.
    #[test]
    fn settings_rebuild_policy_rejects_non_numeric_length() {
        let mut a = app_with_entries(1);
        a.handle_key(key(KeyCode::Char('S')));
        a.handle_key(key(KeyCode::Char('x')));

        let Mode::Settings(view) = &a.mode else {
            panic!("expected settings mode");
        };
        assert!(view.rebuild_policy().is_err());
    }

    // ---- agent lock detection --------------------------------------------

    // The transition triggered when a lock is detected: cached detail and
    // the reveal flag are dropped (nothing secret stays on screen), and the
    // modal takes over. This is the directly-testable half of lock
    // detection; `poll_agent_lock` itself needs a real agent round trip and
    // isn't exercised here (see its doc comment).
    #[test]
    fn detecting_a_lock_clears_secrets_and_shows_the_prompt() {
        let mut a = app_with_entries(1);
        a.detail_cache.insert(
            (0, "entry-0".to_string()),
            crate::commands::DecryptedCipher {
                id: "entry-0".to_string(),
                folder: None,
                name: "entry-0".to_string(),
                data: crate::commands::DecryptedData::Login {
                    username: None,
                    password: Some("hunter2".to_string()),
                    totp: None,
                    uris: None,
                },
                fields: Vec::new(),
                notes: None,
                history: Vec::new(),
                attachments: Vec::new(),
                attachment_metadata: crate::commands::AttachmentMetadata {
                    attachment_count: 0,
                },
                account: None,
            },
        );
        a.reveal = true;

        a.handle_agent_locked("default".to_string());

        assert!(a.detail_cache.is_empty());
        assert!(!a.reveal);
        assert!(
            matches!(&a.mode, Mode::LockedPrompt(name) if name == "default")
        );
        // The search index (names/usernames, not secrets) is deliberately
        // left alone so the list stays populated while the modal is up.
        assert_eq!(a.search.len(), 1);
    }

    // Enter/y/Y accepts and bounces to the event loop (pinentry needs the
    // real terminal), same as `AccountUnlock` in the accounts panel.
    #[test]
    fn locked_prompt_accept_keys_request_unlock() {
        let mut a = app_with_entries(1);
        a.handle_agent_locked("default".to_string());

        for k in [
            key(KeyCode::Enter),
            key(KeyCode::Char('y')),
            key(KeyCode::Char('Y')),
        ] {
            a.mode = Mode::LockedPrompt("default".to_string());
            match a.handle_key(k) {
                Action::UnlockAccount(name) => assert_eq!(name, "default"),
                _ => panic!("expected Action::UnlockAccount"),
            }
        }
    }

    // Any other key (Esc/n/anything) dismisses back to Normal, mirroring
    // `ConfirmDelete`'s y/n convention; the periodic poll re-triggers the
    // prompt on its next tick as long as the agent is still locked, so this
    // isn't a way to silently keep working half-locked.
    #[test]
    fn locked_prompt_other_keys_dismiss_to_normal() {
        let mut a = app_with_entries(1);
        a.handle_agent_locked("default".to_string());
        assert!(matches!(a.handle_key(key(KeyCode::Esc)), Action::None));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Same accept/dismiss keybinds as the lock-detection modal, but reached
    // via a failed sync rather than `poll_agent_lock`.
    #[test]
    fn session_expired_prompt_accept_keys_request_unlock() {
        let mut a = app_with_entries(1);
        a.show_session_expired("default".to_string());

        for k in [
            key(KeyCode::Enter),
            key(KeyCode::Char('y')),
            key(KeyCode::Char('Y')),
        ] {
            a.mode = Mode::SessionExpiredPrompt("default".to_string());
            match a.handle_key(k) {
                Action::UnlockAccount(name) => assert_eq!(name, "default"),
                _ => panic!("expected Action::UnlockAccount"),
            }
        }
    }

    #[test]
    fn session_expired_prompt_other_keys_dismiss_to_normal() {
        let mut a = app_with_entries(1);
        a.show_session_expired("default".to_string());
        assert!(matches!(a.handle_key(key(KeyCode::Esc)), Action::None));
        assert!(matches!(a.mode, Mode::Normal));
    }

    #[test]
    fn is_session_expired_error_matches_only_that_error() {
        assert!(App::is_session_expired_error(&anyhow::anyhow!(
            rbw::error::Error::SessionExpired
        )));
        assert!(!App::is_session_expired_error(&anyhow::anyhow!(
            "some other failure"
        )));
    }

    // A poll that hasn't reached `LOCK_CHECK_INTERVAL` yet is a pure no-op —
    // in particular it never reaches the IPC call, so this is safe to assert
    // deterministically without a running agent.
    #[test]
    fn poll_agent_lock_is_throttled() {
        let mut a = app_with_entries(1);
        // `with_keymap` just set `last_lock_check` to "now".
        a.poll_agent_lock();
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Once the modal is already up, further polls leave it alone (no need to
    // re-detect a lock we're already surfacing) instead of re-running the
    // check.
    #[test]
    fn poll_agent_lock_skips_while_prompt_already_showing() {
        let mut a = app_with_entries(1);
        a.mode = Mode::LockedPrompt("default".to_string());
        a.last_lock_check = std::time::Instant::now()
            .checked_sub(super::LOCK_CHECK_INTERVAL * 2)
            .unwrap();
        a.poll_agent_lock();
        assert!(
            matches!(&a.mode, Mode::LockedPrompt(name) if name == "default")
        );
    }

    // Builds an `App` already sitting on `Mode::Accounts` with the
    // highlighted "work" account plus one other ("personal", needed as a
    // pickable candidate by the credential_source account-picker tests),
    // bypassing `open_accounts`/`commands::tui_accounts` (which would hit
    // the real config file) since only the accounts-panel keybinding logic
    // is under test here, not the account listing itself.
    fn app_on_accounts_panel(
        credential_source: Option<(String, Option<String>)>,
    ) -> App {
        let mut a = app();
        a.mode = Mode::Accounts(AccountsView {
            accounts: vec![
                crate::commands::TuiAccount {
                    name: "work".to_string(),
                    email: None,
                    server: "bitwarden.com".to_string(),
                    unlocked: false,
                    primary: false,
                    credential_source,
                },
                crate::commands::TuiAccount {
                    name: "personal".to_string(),
                    email: None,
                    server: "bitwarden.com".to_string(),
                    unlocked: false,
                    primary: true,
                    credential_source: None,
                },
            ],
            selected: 0,
        });
        a
    }

    // `s` (sync) on a locked account now requests the event loop's
    // unlock+sync path instead of just refusing with a "locked" status.
    #[test]
    fn accounts_s_on_a_locked_account_requests_unlock_and_sync() {
        let mut a = app_on_accounts_panel(None);
        assert!(matches!(
            a.handle_key(key(KeyCode::Char('s'))),
            Action::UnlockAndSyncAccount(name) if name == "work"
        ));
    }

    #[test]
    fn accounts_s_on_a_linked_locked_account_uses_auto_unlock_path() {
        let mut a = app_on_accounts_panel(Some((
            "personal".to_string(),
            Some("vault".to_string()),
        )));
        assert!(matches!(
            a.handle_key(key(KeyCode::Char('s'))),
            Action::AutoUnlockAndSyncAccount(name) if name == "work"
        ));
    }

    // Regression test: `q`/arrow-down must resolve to `AccountClose`/
    // `AccountMoveDown`, not silently no-op by resolving to the global
    // `Quit`/`MoveDown` (which `handle_accounts` has no arm for) -- see
    // `action_in_scopes_to_the_given_actions_not_the_global_default` in
    // `keymap.rs` for the underlying bug this exercises end to end.
    #[test]
    fn accounts_q_and_down_arrow_are_not_swallowed_by_global_defaults() {
        let mut a = app();
        a.mode = Mode::Accounts(AccountsView {
            accounts: vec![
                crate::commands::TuiAccount {
                    name: "first".to_string(),
                    email: None,
                    server: "bitwarden.com".to_string(),
                    unlocked: false,
                    primary: true,
                    credential_source: None,
                },
                crate::commands::TuiAccount {
                    name: "second".to_string(),
                    email: None,
                    server: "bitwarden.com".to_string(),
                    unlocked: false,
                    primary: false,
                    credential_source: None,
                },
            ],
            selected: 0,
        });

        a.handle_key(key(KeyCode::Down));
        let Mode::Accounts(view) = &a.mode else {
            panic!("expected still Mode::Accounts after moving down");
        };
        assert_eq!(view.selected, 1);

        a.handle_key(key(KeyCode::Char('q')));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Ctrl+C closes the accounts panel too, same as `q`/Esc -- it's not
    // bound to `AccountClose` (or any account action) by default, so
    // without `handle_accounts` special-casing it explicitly it would
    // otherwise be a silent no-op (there's no global `Quit` for it to
    // accidentally resolve to here, unlike the `q`/arrow-key regression
    // above -- this is a distinct gap, not the same bug).
    #[test]
    fn accounts_ctrl_c_closes_panel() {
        let mut a = app();
        a.mode = Mode::Accounts(AccountsView {
            accounts: vec![crate::commands::TuiAccount {
                name: "first".to_string(),
                email: None,
                server: "bitwarden.com".to_string(),
                unlocked: false,
                primary: true,
                credential_source: None,
            }],
            selected: 0,
        });
        a.handle_key(ctrl('c'));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Same regression as `accounts_q_and_down_arrow_are_not_swallowed_by_global_defaults`,
    // for the attachments panel: `AttachmentClose`/`AttachmentMoveDown`
    // share default chords with `Quit`/`MoveDown` too.
    #[test]
    fn attachments_q_and_down_arrow_are_not_swallowed_by_global_defaults() {
        let mut a = app();
        a.mode = Mode::Attachments(AttachmentView {
            items: vec![
                AttachmentItem {
                    id: "1".to_string(),
                    name: "first".to_string(),
                    size: None,
                },
                AttachmentItem {
                    id: "2".to_string(),
                    name: "second".to_string(),
                    size: None,
                },
            ],
            selected: 0,
            pending_delete: false,
        });

        a.handle_key(key(KeyCode::Down));
        let Mode::Attachments(view) = &a.mode else {
            panic!("expected still Mode::Attachments after moving down");
        };
        assert_eq!(view.selected, 1);

        a.handle_key(key(KeyCode::Char('q')));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Ctrl+C closes the attachments panel too, same as `q`/Esc.
    #[test]
    fn attachments_ctrl_c_closes_panel() {
        let mut a = app();
        a.mode = Mode::Attachments(AttachmentView {
            items: vec![AttachmentItem {
                id: "1".to_string(),
                name: "first".to_string(),
                size: None,
            }],
            selected: 0,
            pending_delete: false,
        });
        a.handle_key(ctrl('c'));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // `l` on a highlighted account opens the account picker (step 1 of
    // linking `credential_source`), prefilled with its current source
    // account (if any) so re-confirming it is a no-op edit, and listing
    // every *other* configured account as a candidate.
    #[test]
    fn accounts_l_opens_account_picker_prefilled_with_current_source() {
        let mut a = app_on_accounts_panel(Some((
            "personal".to_string(),
            Some("Work master password".to_string()),
        )));
        a.handle_key(key(KeyCode::Char('l')));

        let Mode::Picker(picker) = &a.mode else {
            panic!("expected Mode::Picker after 'l'");
        };
        assert!(matches!(
            &picker.kind,
            PickerKind::CredentialSourceAccount { name } if name == "work"
        ));
        assert_eq!(picker.filter.value(), "personal");
        assert_eq!(
            picker.rows().map(|(_, s)| s).collect::<Vec<_>>(),
            vec!["personal"]
        );
    }

    // Confirming the account picker advances to the item picker, scoped to
    // the chosen account and prefilled with the current item (if any).
    // Neither account has a loaded vault in this fixture, so the item list
    // is empty and the filter doubles as free-text entry -- confirming it
    // directly (without picking anything from a list) must still call
    // through to `tui_account_set_credential_source`, which fails here
    // (no real config file) but that's fine: only the transition and status
    // side effect are under test, not the config write.
    #[test]
    fn accounts_l_then_enter_advances_to_item_picker() {
        let mut a = app_on_accounts_panel(Some((
            "personal".to_string(),
            Some("Work master password".to_string()),
        )));
        a.handle_key(key(KeyCode::Char('l')));
        a.handle_key(key(KeyCode::Enter));

        let Mode::Picker(picker) = &a.mode else {
            panic!(
                "expected still Mode::Picker after confirming the account"
            );
        };
        assert!(matches!(
            &picker.kind,
            PickerKind::CredentialSourceItem { name, source_account }
                if name == "work" && source_account == "personal"
        ));
        // No vault loaded for "personal" in this fixture, so only the
        // synthetic auto-discovery choice is listed.
        assert_eq!(
            picker.rows().map(|(_, s)| s).collect::<Vec<_>>(),
            vec![super::CREDENTIAL_SOURCE_AUTO_ITEM]
        );
    }

    // Ctrl+C cancels the credential_source picker (either step) same as Esc.
    #[test]
    fn picker_ctrl_c_cancels() {
        let mut a = app_on_accounts_panel(None);
        a.handle_key(key(KeyCode::Char('l')));
        assert!(matches!(a.mode, Mode::Picker(_)));
        a.handle_key(ctrl('c'));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // Ctrl+C cancels the add-account prompt too.
    #[test]
    fn add_account_prompt_ctrl_c_cancels() {
        let mut a = app_on_accounts_panel(None);
        a.handle_key(key(KeyCode::Char('a')));
        assert!(matches!(a.mode, Mode::Prompt(_)));
        a.handle_key(ctrl('c'));
        assert!(matches!(a.mode, Mode::Normal));
    }

    // A configured `force_quit` chord exits the whole TUI immediately even
    // from inside a dialog -- unlike every other close/cancel key, which
    // only backs out of the current overlay (see the various `_ctrl_c_`
    // tests above). Checked here from `Mode::Prompt`, but the check lives
    // in `handle_key` before any mode dispatch, so it applies uniformly.
    #[test]
    fn force_quit_exits_immediately_even_from_a_dialog() {
        let mut a = app_with_force_quit_bound();
        a.mode = Mode::Prompt(Prompt::add_account());
        let alt_shift_q = KeyEvent::new(
            KeyCode::Char('Q'),
            KeyModifiers::ALT | KeyModifiers::SHIFT,
        );
        assert!(matches!(a.handle_key(alt_shift_q), Action::Quit));
    }

    // Unconfigured (no default chord), the same keypress does nothing
    // dialog-specific -- it's not secretly bound to anything else either.
    #[test]
    fn force_quit_is_a_noop_when_unconfigured() {
        let mut a = app();
        a.mode = Mode::Prompt(Prompt::add_account());
        let alt_shift_q = KeyEvent::new(
            KeyCode::Char('Q'),
            KeyModifiers::ALT | KeyModifiers::SHIFT,
        );
        assert!(matches!(a.handle_key(alt_shift_q), Action::None));
        assert!(matches!(a.mode, Mode::Prompt(_)));
    }

    // `l` with no existing `credential_source` opens the same picker with a
    // blank filter (nothing prefilled).
    #[test]
    fn accounts_l_with_no_credential_source_opens_blank_picker() {
        let mut a = app_on_accounts_panel(None);
        a.handle_key(key(KeyCode::Char('l')));

        let Mode::Picker(picker) = &a.mode else {
            panic!("expected Mode::Picker after 'l'");
        };
        assert_eq!(picker.filter.value(), "");
    }

    // `L` (shift-l) with no `credential_source` to clear is a no-op that
    // just surfaces a status message -- it must not open the confirm dialog
    // (there'd be nothing to confirm).
    #[test]
    fn accounts_shift_l_with_no_credential_source_is_a_noop_with_status() {
        let mut a = app_on_accounts_panel(None);
        a.handle_key(key(KeyCode::Char('L')));

        assert!(matches!(a.mode, Mode::Accounts(_)));
        assert!(a.status.is_some());
    }

    // `L` with a `credential_source` set opens the clear-confirm dialog,
    // carrying the account name along (the dialog replaces `Mode::Accounts`
    // and its cursor/list while it's up).
    #[test]
    fn accounts_shift_l_with_credential_source_opens_confirm() {
        let mut a = app_on_accounts_panel(Some((
            "personal".to_string(),
            Some("item".to_string()),
        )));
        a.handle_key(key(KeyCode::Char('L')));

        assert!(matches!(
            &a.mode,
            Mode::ConfirmClearCredentialSource(name) if name == "work"
        ));
    }
}
