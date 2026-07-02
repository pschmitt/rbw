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
    Prompt(Prompt),
    Help,
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
    keymap: Keymap,
}

impl App {
    pub fn new(open: commands::TuiOpen, initial_term: Option<&str>) -> Self {
        let keymap = rbw::config::Config::load().map_or_else(
            |_| Keymap::resolve(&std::collections::HashMap::new()),
            |config| Keymap::resolve(&config.tui_keybindings),
        );
        Self::with_keymap(open, initial_term, keymap)
    }

    // Split out from `new` so tests can supply a deterministic keymap
    // instead of picking up whatever the machine running them happens to
    // have in `~/.config/rbw/config.json`.
    fn with_keymap(
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
                Err(e) => errors.push(format!("{name}: {e:#}")),
            }
        }
        self.detail_cache.clear();
        self.rebuild_flat();
        self.recompute_filter();
        self.restore_selection(keep);
        self.ensure_detail();
        if errors.is_empty() {
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

    // Sync the highlighted account (must be unlocked) and refresh its entries.
    fn sync_selected_account(&mut self) {
        let Some((name, unlocked)) = self.selected_account() else {
            return;
        };
        if !unlocked {
            self.set_status(Level::Warn, format!("{name} is locked"));
            return;
        }
        match commands::tui_account_sync(&name) {
            Ok(v) => {
                if let Some(slot) =
                    self.vaults.iter_mut().find(|x| x.name == name)
                {
                    slot.db = v.db;
                    slot.search = v.search;
                }
                self.detail_cache.clear();
                self.rebuild_flat();
                self.recompute_filter();
                self.ensure_detail();
                self.set_status(Level::Success, format!("synced {name}"));
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
        self.refresh_accounts_view();
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

    // Called by the event loop (terminal restored) to lazily unlock an account
    // and fold its entries into the merged list.
    pub fn unlock_account(&mut self, name: &str) -> anyhow::Result<()> {
        let vault = commands::tui_unlock_account(name)?;
        let keep = self.current_key();
        self.vaults.push(AccountVault {
            name: vault.account,
            db: vault.db,
            search: vault.search,
        });
        self.locked.retain(|n| n != name);
        self.rebuild_flat();
        self.recompute_filter();
        self.restore_selection(keep);
        self.ensure_detail();
        self.refresh_accounts_view();
        Ok(())
    }

    pub fn set_unlocked_status(&mut self, name: &str) {
        self.set_status(Level::Success, format!("unlocked {name}"));
    }

    fn handle_accounts(&mut self, key: KeyEvent) -> Action {
        match self.keymap.action_for(key, true) {
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
            Some(TuiAction::AccountSync) => self.sync_selected_account(),
            Some(TuiAction::AccountSetPrimary) => {
                self.set_primary_selected_account();
            }
            Some(TuiAction::AccountAdd) => self.start_add_account(),
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

    fn handle_prompt(&mut self, key: KeyEvent) -> Action {
        let Mode::Prompt(prompt) = &mut self.mode else {
            return Action::None;
        };
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
            Mode::Prompt(_) => self.handle_prompt(key),
            Mode::Help => {
                self.mode = Mode::Normal;
                Action::None
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
            Some(TuiAction::DeleteEntry) => {
                if self.current_search().is_some() {
                    self.mode = Mode::ConfirmDelete;
                }
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
        let action = self.keymap.action_for(key, true);
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
    use super::{Action, App, Keymap, Mode};
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
}
