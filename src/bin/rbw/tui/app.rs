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

// What the event loop should do after a keypress. Everything except spawning
// an external editor is handled inline (agent round-trips are synchronous and
// safe while the alternate screen is active); `$EDITOR` needs the real terminal
// back, so it is bounced up to the loop.
pub enum Action {
    None,
    Quit,
    OpenEditor,
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
    Help,
}

// A single row in the attachment picker.
pub struct AttachmentItem {
    pub id: String,
    pub name: String,
    pub size: Option<String>,
}

// The attachment picker overlay: the current entry's attachments plus a cursor.
pub struct AttachmentView {
    pub items: Vec<AttachmentItem>,
    pub selected: usize,
}

pub struct App {
    db: rbw::db::Db,
    // Parallel to `db.entries`: lightweight decrypted fields for list/search.
    pub search: Vec<DecryptedSearchCipher>,
    // Full per-entry detail, decrypted lazily on selection, keyed by entry id.
    detail_cache: HashMap<String, DecryptedCipher>,
    pub filter: Input,
    // Indices into `db.entries`/`search`, filtered by the search term and
    // sorted by (folder, name).
    pub filtered: Vec<usize>,
    pub selected: usize,
    pub mode: Mode,
    pub reveal: bool,
    pub status: Option<Status>,
    pub detail_scroll: u16,
}

impl App {
    pub fn new(
        db: rbw::db::Db,
        search: Vec<DecryptedSearchCipher>,
        initial_term: Option<&str>,
    ) -> Self {
        let mut app = Self {
            db,
            search,
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
        };
        app.recompute_filter();
        app.ensure_detail();
        app
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
        self.current_index().map(|i| self.db.entries[i].clone())
    }

    pub fn current_detail(&self) -> Option<&DecryptedCipher> {
        let id = &self.current_search()?.id;
        self.detail_cache.get(id)
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

    // Decrypt full detail for the current selection if not already cached.
    fn ensure_detail(&mut self) {
        let Some(idx) = self.current_index() else {
            return;
        };
        let id = self.db.entries[idx].id.clone();
        if self.detail_cache.contains_key(&id) {
            return;
        }
        let entry = self.db.entries[idx].clone();
        match commands::decrypt_cipher(&entry) {
            Ok(detail) => {
                self.detail_cache.insert(id, detail);
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
        if detail.attachments.is_empty() {
            self.set_status(Level::Warn, "no attachments");
            return;
        }
        let items = detail
            .attachments
            .iter()
            .map(|a| AttachmentItem {
                id: a.id.clone(),
                name: a.file_name.clone().unwrap_or_else(|| a.id.clone()),
                size: a.size_name.clone().or_else(|| a.size.clone()),
            })
            .collect();
        self.mode = Mode::Attachments(AttachmentView { items, selected: 0 });
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
        let Some(entry) = self.current_entry() else {
            return;
        };
        self.ensure_detail();
        let Some(detail) = self.detail_cache.get(&entry.id).cloned() else {
            self.set_status(Level::Error, "could not decrypt entry");
            return;
        };
        let dest = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        match commands::tui_attachment_get(
            &mut self.db,
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

    fn reload(&mut self) {
        match commands::tui_reload() {
            Ok((db, search)) => self.replace_vault(db, search),
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    // Pull remote changes from the server, then reload the local view. Runs
    // synchronously (like save/delete), so the UI briefly blocks on the network.
    fn sync(&mut self) {
        match commands::tui_sync() {
            Ok((db, search)) => {
                self.replace_vault(db, search);
                self.set_status(Level::Success, "synced");
            }
            Err(e) => self.set_status(Level::Error, format!("{e:#}")),
        }
    }

    // Swap in a freshly loaded db/search index, preserving the selection by
    // entry id where possible.
    fn replace_vault(
        &mut self,
        db: rbw::db::Db,
        search: Vec<DecryptedSearchCipher>,
    ) {
        let keep_id = self.current_search().map(|s| s.id.clone());
        self.db = db;
        self.search = search;
        self.detail_cache.clear();
        self.recompute_filter();
        if let Some(id) = keep_id {
            if let Some(pos) =
                self.filtered.iter().position(|&i| self.search[i].id == id)
            {
                self.selected = pos;
            }
        }
        self.ensure_detail();
    }

    fn start_edit(&mut self) {
        let Some(detail) = self.current_detail() else {
            self.set_status(Level::Warn, "nothing selected");
            return;
        };
        let base = commands::decrypted_to_editable(detail);
        let title = format!("Edit · {}", base.name);
        self.mode =
            Mode::Edit(EditForm::new(title, Some(detail.id.clone()), base));
    }

    fn start_add(&mut self) {
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
        self.mode =
            Mode::Edit(EditForm::new("New login".to_string(), None, base));
    }

    fn submit_form(&mut self) {
        let Mode::Edit(form) = &self.mode else {
            return;
        };
        let mut base = form.rebuild_editable();
        let is_new = form.entry_id.is_none();
        let entry_id = form.entry_id.clone();

        let result = if is_new {
            commands::tui_save_add(&mut self.db, &base)
        } else if let Some(id) = &entry_id {
            self.db
                .entries
                .iter()
                .find(|e| &e.id == id)
                .cloned()
                .map_or_else(
                    || Err(anyhow::anyhow!("entry no longer exists")),
                    |entry| {
                        commands::tui_save_edit(&mut self.db, &entry, &base)
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
                self.reload();
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
        let Some(entry) = self.current_entry() else {
            self.mode = Mode::Normal;
            return;
        };
        let name = self
            .current_search()
            .map_or_else(String::new, |s| s.name.clone());
        match commands::tui_delete(&mut self.db, &entry) {
            Ok(()) => {
                self.mode = Mode::Normal;
                self.reload();
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
        let Some(entry) = self.current_entry() else {
            return Ok(());
        };
        self.ensure_detail();
        let Some(detail) = self.detail_cache.get(&entry.id).cloned() else {
            anyhow::bail!("could not decrypt entry");
        };
        let changed =
            commands::tui_edit_in_editor(&mut self.db, &entry, &detail)?;
        self.mode = Mode::Normal;
        if changed {
            self.reload();
            self.set_status(Level::Success, "saved changes from editor");
        } else {
            self.set_status(Level::Info, "no changes");
        }
        Ok(())
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
    fn handle_shared(&mut self, key: KeyEvent) -> Option<Action> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Up => self.move_by(-1),
            KeyCode::Down => self.move_by(1),
            KeyCode::PageUp => self.move_by(-10),
            KeyCode::PageDown => self.move_by(10),
            KeyCode::Char('p') if ctrl => self.move_by(-1),
            KeyCode::Char('n') if ctrl => self.move_by(1),
            KeyCode::Char('c') if ctrl => return Some(Action::Quit),
            KeyCode::Char('e') if ctrl => return Some(Action::OpenEditor),
            KeyCode::Char('s') if ctrl => self.sync(),
            KeyCode::Char('r') if ctrl => self.reveal = !self.reveal,
            KeyCode::Char('p') if alt => self.copy_password(),
            KeyCode::Char('u') if alt => self.copy_username(),
            KeyCode::Char('t') if alt => self.copy_totp(),
            KeyCode::Char('o') if alt => self.open_uri(),
            KeyCode::Char('s') if alt => self.open_attachments(),
            KeyCode::Char('j') if alt => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
            }
            KeyCode::Char('k') if alt => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
            }
            _ => return None,
        }
        Some(Action::None)
    }

    fn handle_normal(&mut self, key: KeyEvent) -> Action {
        if let Some(action) = self.handle_shared(key) {
            return action;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('j') => self.move_by(1),
            KeyCode::Char('k') => self.move_by(-1),
            KeyCode::Char('g') | KeyCode::Home => self.select(0),
            KeyCode::Char('G') | KeyCode::End => {
                self.select(self.filtered.len());
            }
            KeyCode::Char('J') => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
            }
            KeyCode::Char('K') => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
            }
            KeyCode::Char('/' | 'i') | KeyCode::Tab => {
                self.mode = Mode::Search;
            }
            KeyCode::Char('r') => self.reveal = !self.reveal,
            KeyCode::Char('p' | 'y') => self.copy_password(),
            KeyCode::Char('u') => self.copy_username(),
            KeyCode::Char('t') => self.copy_totp(),
            KeyCode::Char('o') => self.open_uri(),
            KeyCode::Char('s') => self.open_attachments(),
            KeyCode::Char('e') | KeyCode::Enter => self.start_edit(),
            KeyCode::Char('E') => return Action::OpenEditor,
            KeyCode::Char('a') => self.start_add(),
            KeyCode::Char('d') => {
                if self.current_search().is_some() {
                    self.mode = Mode::ConfirmDelete;
                }
            }
            KeyCode::Char('?') => self.mode = Mode::Help,
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
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Normal,
            KeyCode::Down | KeyCode::Char('j') => self.attachment_move(1),
            KeyCode::Up | KeyCode::Char('k') => self.attachment_move(-1),
            KeyCode::Char('n') if ctrl => self.attachment_move(1),
            KeyCode::Char('p') if ctrl => self.attachment_move(-1),
            KeyCode::Enter => self.download_attachment(),
            _ => {}
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
        base: EditableCipher,
    ) -> Self {
        let fields = build_fields(&base);
        Self {
            title,
            entry_id,
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
    use super::{Action, App, Mode};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn app() -> App {
        App::new(rbw::db::Db::new(), Vec::new(), None)
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
}
