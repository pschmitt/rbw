// User-configurable TUI keybindings: named actions mapped to key chords
// (e.g. "ctrl-y", "alt-p", "g", "pagedown"), loaded from config.json's
// `tui_keybindings` and merged on top of the built-in defaults below. An
// action not mentioned in the user's config keeps its default chords; one
// that *is* mentioned has its defaults fully replaced (not appended to) by
// the configured chords.
//
// Deliberately out of scope, and not reachable through this map: the search
// filter's own text input, the Edit/Prompt overlays' field navigation, and
// small binary confirms (`ConfirmDelete`'s y/n,
// `ConfirmClearCredentialSource`'s y/n, Help's "any key closes") — these are
// tied to the widget's own semantics rather than being freely rebindable
// single actions.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyChord {
    code: KeyCode,
    modifiers: KeyModifiers,
}

impl KeyChord {
    // Real terminals (crossterm included) report `KeyModifiers::SHIFT`
    // alongside a `Char` code whenever the produced character required
    // shift to type (e.g. 'A', '!') — the character itself already fully
    // encodes that, so a default chord like "A" (parsed with no explicit
    // modifiers, see `parse`'s doc comment) would otherwise never match a
    // real keypress of Shift+A. Shift is only a meaningful, independent
    // modifier for non-`Char` codes (arrows, function keys, etc.), where it
    // doesn't already show up baked into the reported character.
    fn matches(self, key: KeyEvent) -> bool {
        if self.code != key.code {
            return false;
        }
        let mask = if matches!(self.code, KeyCode::Char(_)) {
            KeyModifiers::CONTROL | KeyModifiers::ALT
        } else {
            KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT
        };
        (self.modifiers & mask) == (key.modifiers & mask)
    }

    // A chord that a text-input context (the search filter) never sees as
    // an action trigger — a plain, unmodified character key, which is
    // swallowed by the input widget instead. Mirrors the `allow_plain`
    // check in `Keymap::action_for`.
    fn usable_while_typing(self) -> bool {
        !matches!(self.code, KeyCode::Char(_))
            || self
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    }

    // Renders back to the terse glyph style used in the TUI's own hints
    // (status bar / help screen): `^`/`⌥`/`⇧` prefixes for ctrl/alt/shift,
    // arrows for the arrow keys, `⏎`/`⇥`/`⇤` for Enter/Tab/BackTab, and the
    // key's own name or character otherwise. `parse` accepts exactly this
    // form back (see `parse_glyphs`), as well as the more verbose
    // "ctrl-alt-key" form it documents, so a chord shown in the UI can be
    // pasted straight back into `tui_keybindings`.
    pub fn display(&self) -> String {
        let mut out = String::new();
        if self.modifiers.contains(KeyModifiers::CONTROL) {
            out.push('^');
        }
        if self.modifiers.contains(KeyModifiers::ALT) {
            out.push('⌥');
        }
        if self.modifiers.contains(KeyModifiers::SHIFT) {
            out.push('⇧');
        }
        match self.code {
            KeyCode::Up => out.push('↑'),
            KeyCode::Down => out.push('↓'),
            KeyCode::Left => out.push('←'),
            KeyCode::Right => out.push('→'),
            KeyCode::PageUp => out.push_str("pageup"),
            KeyCode::PageDown => out.push_str("pagedown"),
            KeyCode::Home => out.push_str("home"),
            KeyCode::End => out.push_str("end"),
            KeyCode::Enter => out.push('⏎'),
            KeyCode::Esc => out.push_str("esc"),
            KeyCode::Tab => out.push('⇥'),
            KeyCode::BackTab => out.push('⇤'),
            KeyCode::Char(' ') => out.push_str("space"),
            KeyCode::Char(c) => out.push(c),
            other => out.push_str(&format!("{other:?}").to_lowercase()),
        }
        out
    }

    // Parses e.g. "ctrl-y", "alt-shift-g", "pagedown", "g", "G". Modifier and
    // special-key names are case-insensitive; a lone trailing character is
    // taken literally (so "G" alone is enough for Shift+g — no need to write
    // "shift-g"; `KeyChord::matches` ignores the redundant `SHIFT` modifier
    // a real terminal reports alongside the already-uppercase `Char('G')`).
    fn parse(s: &str) -> Option<Self> {
        if let Some(chord) = Self::parse_glyphs(s) {
            return Some(chord);
        }

        let parts: Vec<&str> = s.split('-').collect();
        let (mods, key) = parts.split_at(parts.len().saturating_sub(1));
        let key = key.first()?;
        if key.is_empty() {
            return None;
        }

        let mut modifiers = KeyModifiers::NONE;
        for m in mods {
            match m.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => modifiers |= KeyModifiers::CONTROL,
                "alt" | "opt" | "option" => modifiers |= KeyModifiers::ALT,
                "shift" => modifiers |= KeyModifiers::SHIFT,
                _ => return None,
            }
        }

        let code = match key.to_ascii_lowercase().as_str() {
            "up" => KeyCode::Up,
            "down" => KeyCode::Down,
            "left" => KeyCode::Left,
            "right" => KeyCode::Right,
            "pageup" | "page_up" => KeyCode::PageUp,
            "pagedown" | "page_down" => KeyCode::PageDown,
            "home" => KeyCode::Home,
            "end" => KeyCode::End,
            "enter" | "return" => KeyCode::Enter,
            "esc" | "escape" => KeyCode::Esc,
            "tab" => KeyCode::Tab,
            "backtab" => KeyCode::BackTab,
            "space" => KeyCode::Char(' '),
            _ => {
                let mut chars = key.chars();
                let c = chars.next()?;
                if chars.next().is_some() {
                    return None;
                }
                KeyCode::Char(c)
            }
        };
        Some(Self { code, modifiers })
    }

    // Accepts the terse glyph form `display` emits — a run of modifier
    // glyphs (`^` ctrl, `⌥` alt, `⇧` shift) with no separator, followed by a
    // plain character or one of the named glyphs below — so a chord shown
    // in the UI can be pasted straight back into `tui_keybindings`. Returns
    // `None` (falling back to the textual "ctrl-alt-key" parser above) for
    // anything that isn't in this form, including a glyph-free string.
    fn parse_glyphs(s: &str) -> Option<Self> {
        let mut modifiers = KeyModifiers::NONE;
        let mut rest = s;
        loop {
            rest = if let Some(r) = rest.strip_prefix('^') {
                modifiers |= KeyModifiers::CONTROL;
                r
            } else if let Some(r) = rest.strip_prefix('⌥') {
                modifiers |= KeyModifiers::ALT;
                r
            } else if let Some(r) = rest.strip_prefix('⇧') {
                modifiers |= KeyModifiers::SHIFT;
                r
            } else {
                break;
            };
        }

        let code = match rest {
            "↑" => KeyCode::Up,
            "↓" => KeyCode::Down,
            "←" => KeyCode::Left,
            "→" => KeyCode::Right,
            "⏎" => KeyCode::Enter,
            "⇥" => KeyCode::Tab,
            "⇤" => KeyCode::BackTab,
            _ if modifiers != KeyModifiers::NONE => {
                let mut chars = rest.chars();
                let c = chars.next()?;
                if chars.next().is_some() {
                    return None;
                }
                KeyCode::Char(c)
            }
            _ => return None,
        };
        Some(Self { code, modifiers })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TuiAction {
    // Exit the whole TUI immediately from *any* mode, including from inside
    // a dialog/prompt/picker -- unlike `Quit`, which `App::handle_key`
    // checks per-mode and which most overlay handlers intercept as their
    // own "close this dialog" key instead of letting it propagate. Opt-in
    // only (no default chord, see `defaults`): there's no universally
    // sensible one-key-quits-everything binding, since it'd otherwise be
    // too easy to lose an in-progress edit by fat-fingering it.
    ForceQuit,
    Quit,
    MoveDown,
    MoveUp,
    PageDown,
    PageUp,
    JumpFirst,
    JumpLast,
    ScrollDetailDown,
    ScrollDetailUp,
    FocusDetail,
    FocusList,
    ToggleSearch,
    ToggleReveal,
    CopyPassword,
    CopyUsername,
    CopyTotp,
    OpenUri,
    OpenAttachments,
    StartEdit,
    OpenEditor,
    StartAdd,
    OpenAccounts,
    OpenSettings,
    DeleteEntry,
    Sync,
    Help,
    AttachmentClose,
    AttachmentMoveDown,
    AttachmentMoveUp,
    AttachmentDownload,
    AttachmentUpload,
    AttachmentDelete,
    AccountClose,
    AccountMoveDown,
    AccountMoveUp,
    AccountUnlock,
    AccountSync,
    AccountSetPrimary,
    AccountAdd,
    // Link (or edit) the highlighted account's `credential_source` to a
    // Login entry in another account's vault.
    AccountSetCredentialSource,
    // Clear the highlighted account's `credential_source` link.
    AccountClearCredentialSource,
}

impl TuiAction {
    // Every action, in the priority order used to resolve a keypress — if a
    // user's config gives two actions the same chord, whichever comes first
    // here wins.
    const ALL: &'static [Self] = &[
        Self::ForceQuit,
        Self::Quit,
        Self::MoveDown,
        Self::MoveUp,
        Self::PageDown,
        Self::PageUp,
        Self::JumpFirst,
        Self::JumpLast,
        Self::ScrollDetailDown,
        Self::ScrollDetailUp,
        Self::FocusDetail,
        Self::FocusList,
        Self::ToggleSearch,
        Self::ToggleReveal,
        Self::CopyPassword,
        Self::CopyUsername,
        Self::CopyTotp,
        Self::OpenUri,
        Self::OpenAttachments,
        Self::StartEdit,
        Self::OpenEditor,
        Self::StartAdd,
        Self::OpenAccounts,
        Self::OpenSettings,
        Self::DeleteEntry,
        Self::Sync,
        Self::Help,
        Self::AttachmentClose,
        Self::AttachmentMoveDown,
        Self::AttachmentMoveUp,
        Self::AttachmentDownload,
        Self::AttachmentUpload,
        Self::AttachmentDelete,
        Self::AccountClose,
        Self::AccountMoveDown,
        Self::AccountMoveUp,
        Self::AccountUnlock,
        Self::AccountSync,
        Self::AccountSetPrimary,
        Self::AccountAdd,
        Self::AccountSetCredentialSource,
        Self::AccountClearCredentialSource,
    ];

    // The actions `App::handle_accounts` understands -- pass to
    // `Keymap::action_in` rather than the unscoped `action_for`, since
    // `AccountClose`/`AccountMoveDown`/`AccountMoveUp` share default chords
    // with the earlier-in-`ALL` `Quit`/`MoveDown`/`MoveUp`.
    pub const ACCOUNT: &'static [Self] = &[
        Self::AccountClose,
        Self::AccountMoveDown,
        Self::AccountMoveUp,
        Self::AccountUnlock,
        Self::AccountSync,
        Self::AccountSetPrimary,
        Self::AccountAdd,
        Self::AccountSetCredentialSource,
        Self::AccountClearCredentialSource,
    ];

    // The actions `App::handle_attachments` understands -- see `ACCOUNT`'s
    // doc comment for why this needs to be scoped rather than going through
    // the unscoped `action_for`.
    pub const ATTACHMENT: &'static [Self] = &[
        Self::AttachmentClose,
        Self::AttachmentMoveDown,
        Self::AttachmentMoveUp,
        Self::AttachmentDownload,
        Self::AttachmentUpload,
        Self::AttachmentDelete,
    ];

    // The config.json key used to override this action's chords.
    fn config_key(self) -> &'static str {
        match self {
            Self::ForceQuit => "force_quit",
            Self::Quit => "quit",
            Self::MoveDown => "move_down",
            Self::MoveUp => "move_up",
            Self::PageDown => "page_down",
            Self::PageUp => "page_up",
            Self::JumpFirst => "jump_first",
            Self::JumpLast => "jump_last",
            Self::ScrollDetailDown => "scroll_detail_down",
            Self::ScrollDetailUp => "scroll_detail_up",
            Self::FocusDetail => "focus_detail",
            Self::FocusList => "focus_list",
            Self::ToggleSearch => "toggle_search",
            Self::ToggleReveal => "toggle_reveal",
            Self::CopyPassword => "copy_password",
            Self::CopyUsername => "copy_username",
            Self::CopyTotp => "copy_totp",
            Self::OpenUri => "open_uri",
            Self::OpenAttachments => "open_attachments",
            Self::StartEdit => "edit",
            Self::OpenEditor => "open_editor",
            Self::StartAdd => "add",
            Self::OpenAccounts => "open_accounts",
            Self::OpenSettings => "open_settings",
            Self::DeleteEntry => "delete",
            Self::Sync => "sync",
            Self::Help => "help",
            Self::AttachmentClose => "attachment_close",
            Self::AttachmentMoveDown => "attachment_move_down",
            Self::AttachmentMoveUp => "attachment_move_up",
            Self::AttachmentDownload => "attachment_download",
            Self::AttachmentUpload => "attachment_upload",
            Self::AttachmentDelete => "attachment_delete",
            Self::AccountClose => "account_close",
            Self::AccountMoveDown => "account_move_down",
            Self::AccountMoveUp => "account_move_up",
            Self::AccountUnlock => "account_unlock",
            Self::AccountSync => "account_sync",
            Self::AccountSetPrimary => "account_set_primary",
            Self::AccountAdd => "account_add",
            Self::AccountSetCredentialSource => {
                "account_set_credential_source"
            }
            Self::AccountClearCredentialSource => {
                "account_clear_credential_source"
            }
        }
    }

    // Default chord strings for this action.
    fn defaults(self) -> &'static [&'static str] {
        match self {
            // Opt-in only -- see the doc comment on the variant.
            Self::ForceQuit => &[],
            Self::Quit => &["q", "ctrl-c"],
            Self::MoveDown => &["j", "down", "ctrl-n"],
            Self::MoveUp => &["k", "up", "ctrl-p"],
            Self::PageDown => &["pagedown"],
            Self::PageUp => &["pageup"],
            Self::JumpFirst => &["g", "home"],
            Self::JumpLast => &["G", "end"],
            Self::ScrollDetailDown => &["J", "alt-j"],
            Self::ScrollDetailUp => &["K", "alt-k"],
            Self::FocusDetail => &["right"],
            Self::FocusList => &["left"],
            Self::ToggleSearch => &["/", "i", "tab"],
            Self::ToggleReveal => &["r", "ctrl-r"],
            Self::CopyPassword => &["p", "y", "alt-p", "ctrl-y"],
            Self::CopyUsername => &["u", "alt-u"],
            Self::CopyTotp => &["t", "alt-t"],
            Self::OpenUri => &["o", "alt-o"],
            Self::OpenAttachments => &["s", "alt-s"],
            Self::StartEdit => &["e", "enter"],
            Self::OpenEditor => &["E", "ctrl-e"],
            Self::StartAdd | Self::AccountAdd => &["a"],
            Self::OpenAccounts => &["A"],
            Self::OpenSettings => &["S"],
            Self::Sync => &["ctrl-s"],
            Self::Help => &["?"],
            Self::AttachmentClose | Self::AccountClose => &["esc", "q"],
            Self::AttachmentMoveDown | Self::AccountMoveDown => {
                &["down", "j", "ctrl-n"]
            }
            Self::AttachmentMoveUp | Self::AccountMoveUp => {
                &["up", "k", "ctrl-p"]
            }
            Self::AttachmentDownload => &["enter"],
            Self::AttachmentUpload => &["a", "u"],
            Self::AttachmentDelete | Self::DeleteEntry => &["d"],
            Self::AccountUnlock => &["enter", "u"],
            Self::AccountSync => &["s"],
            Self::AccountSetPrimary => &["p"],
            Self::AccountSetCredentialSource => &["l"],
            Self::AccountClearCredentialSource => &["L"],
        }
    }
}

pub struct Keymap {
    // Priority-ordered, matching `TuiAction::ALL`.
    bindings: Vec<(TuiAction, Vec<KeyChord>)>,
}

impl Keymap {
    // Built-in defaults, with any action present in `overrides` having its
    // chords fully replaced by the configured ones. A chord string that
    // fails to parse is skipped (logged, not fatal) so a config typo can't
    // lock the user out of the TUI.
    pub fn resolve(
        overrides: &std::collections::HashMap<String, Vec<String>>,
    ) -> Self {
        let bindings = TuiAction::ALL
            .iter()
            .map(|&action| {
                let parse_all = |chords: &[String]| -> Vec<KeyChord> {
                    chords
                        .iter()
                        .filter_map(|s| {
                            let chord = KeyChord::parse(s);
                            if chord.is_none() {
                                log::warn!(
                                    "ignoring invalid keybinding {s:?} for {}",
                                    action.config_key()
                                );
                            }
                            chord
                        })
                        .collect()
                };
                let chords = overrides.get(action.config_key()).map_or_else(
                    || {
                        action
                            .defaults()
                            .iter()
                            .filter_map(|s| KeyChord::parse(s))
                            .collect()
                    },
                    |custom| parse_all(custom),
                );
                (action, chords)
            })
            .collect();
        Self { bindings }
    }

    // The first action (in `TuiAction::ALL` order) bound to `key`, or `None`.
    // Pass `allow_plain = false` from a text-input context (the search
    // filter) so a plain, unmodified letter/digit is never swallowed by an
    // action lookup and reaches the input widget instead.
    //
    // Global in scope: considers every action, not just ones relevant to the
    // caller's current mode. Fine for `handle_normal`/`handle_shared`, which
    // want exactly that (they're the "everything" handlers) -- but never use
    // this from a mode-specific handler (`handle_accounts`,
    // `handle_attachments`, ...) that only understands a subset of actions.
    // Several unrelated actions intentionally reuse the same default chords
    // across modes (every panel's own "close" defaults to "esc"/"q", every
    // panel's own "move down" to "down"/"j"/"ctrl-n"), and since `Quit`/
    // `MoveDown` sort earlier in `TuiAction::ALL` than `AccountClose`/
    // `AccountMoveDown`, this would resolve to the wrong (global) action --
    // which such a handler has no arm for, so it'd silently no-op every key
    // that collides with an earlier global default. Use `action_in` with an
    // explicit scope instead.
    pub fn action_for(
        &self,
        key: KeyEvent,
        allow_plain: bool,
    ) -> Option<TuiAction> {
        self.action_in(key, allow_plain, TuiAction::ALL)
    }

    // Like `action_for`, but only resolves to an action listed in `scope` --
    // see `action_for`'s doc comment for why mode-specific handlers need
    // this instead of the unscoped global lookup.
    pub fn action_in(
        &self,
        key: KeyEvent,
        allow_plain: bool,
        scope: &[TuiAction],
    ) -> Option<TuiAction> {
        if !allow_plain
            && matches!(key.code, KeyCode::Char(_))
            && !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return None;
        }
        self.bindings
            .iter()
            .filter(|(action, _)| scope.contains(action))
            .find(|(_, chords)| chords.iter().any(|c| c.matches(key)))
            .map(|(action, _)| *action)
    }

    // Every chord currently resolved for `action` (post override), as
    // display strings in priority order — for building live hint text
    // instead of a hardcoded default. Empty only if a config typo dropped
    // every chord for an action the user did try to override.
    pub fn display_chords(&self, action: TuiAction) -> Vec<String> {
        self.bindings
            .iter()
            .find(|(a, _)| *a == action)
            .map(|(_, chords)| chords.iter().map(KeyChord::display).collect())
            .unwrap_or_default()
    }

    // The first (highest-priority) resolved chord for `action`, for a
    // compact single-chord hint. Falls back to `"?"` so a hint never
    // renders empty if a config typo left the action with no chords at all.
    pub fn primary_chord(&self, action: TuiAction) -> String {
        self.display_chords(action)
            .into_iter()
            .next()
            .unwrap_or_else(|| "?".to_string())
    }

    // Like `primary_chord`, but skips chords a text-input context would
    // swallow before they ever reach `action_for` (see its `allow_plain`
    // parameter and `KeyChord::usable_while_typing`) — for hints shown
    // while the search filter has focus.
    pub fn primary_chord_while_typing(&self, action: TuiAction) -> String {
        self.bindings
            .iter()
            .find(|(a, _)| *a == action)
            .and_then(|(_, chords)| {
                chords.iter().find(|c| c.usable_while_typing())
            })
            .map_or_else(|| "?".to_string(), KeyChord::display)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_plain_and_modified_chords() {
        assert_eq!(
            KeyChord::parse("g"),
            Some(KeyChord {
                code: KeyCode::Char('g'),
                modifiers: KeyModifiers::NONE
            })
        );
        assert_eq!(
            KeyChord::parse("G"),
            Some(KeyChord {
                code: KeyCode::Char('G'),
                modifiers: KeyModifiers::NONE
            })
        );
        assert_eq!(
            KeyChord::parse("ctrl-y"),
            Some(KeyChord {
                code: KeyCode::Char('y'),
                modifiers: KeyModifiers::CONTROL
            })
        );
        assert_eq!(
            KeyChord::parse("alt-shift-g"),
            Some(KeyChord {
                code: KeyCode::Char('g'),
                modifiers: KeyModifiers::ALT | KeyModifiers::SHIFT
            })
        );
        assert_eq!(
            KeyChord::parse("pagedown"),
            Some(KeyChord {
                code: KeyCode::PageDown,
                modifiers: KeyModifiers::NONE
            })
        );
        assert_eq!(KeyChord::parse(""), None);
        assert_eq!(KeyChord::parse("ctrl-nope-way-too-long"), None);
    }

    #[test]
    fn override_replaces_defaults_entirely() {
        let mut overrides = std::collections::HashMap::new();
        overrides
            .insert("copy_password".to_string(), vec!["ctrl-y".to_string()]);
        let keymap = Keymap::resolve(&overrides);

        // The configured chord works.
        let ctrl_y = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL);
        assert_eq!(
            keymap.action_for(ctrl_y, true),
            Some(TuiAction::CopyPassword)
        );

        // A default chord that wasn't re-listed no longer works.
        let plain_p = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE);
        assert_ne!(
            keymap.action_for(plain_p, true),
            Some(TuiAction::CopyPassword)
        );
    }

    #[test]
    fn unmentioned_actions_keep_their_defaults() {
        let keymap = Keymap::resolve(&std::collections::HashMap::new());
        let j = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE);
        assert_eq!(keymap.action_for(j, true), Some(TuiAction::MoveDown));
    }

    // `ForceQuit` has no default chord (opt-in only) -- unconfigured, it
    // must never resolve, not even to a chord that happens to include Alt.
    #[test]
    fn force_quit_has_no_default_chord() {
        let keymap = Keymap::resolve(&std::collections::HashMap::new());
        let alt_shift_q =
            KeyEvent::new(KeyCode::Char('Q'), KeyModifiers::ALT);
        assert_ne!(
            keymap.action_for(alt_shift_q, true),
            Some(TuiAction::ForceQuit)
        );
    }

    // Once configured, `force_quit` resolves like any other action --
    // including a real terminal's redundant `SHIFT` bit alongside the
    // already-uppercase `Char('Q')` (see
    // `uppercase_letter_defaults_match_a_real_shift_reported_keypress`).
    #[test]
    fn force_quit_resolves_once_configured() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("force_quit".to_string(), vec!["alt-Q".to_string()]);
        let keymap = Keymap::resolve(&overrides);

        let alt_shift_q = KeyEvent::new(
            KeyCode::Char('Q'),
            KeyModifiers::ALT | KeyModifiers::SHIFT,
        );
        assert_eq!(
            keymap.action_for(alt_shift_q, true),
            Some(TuiAction::ForceQuit)
        );
    }

    // Regression test: real terminals (crossterm included) report
    // `KeyModifiers::SHIFT` alongside a `Char` code whenever the produced
    // character required shift to type, so a real keypress of Shift+A
    // arrives as `KeyEvent { code: Char('A'), modifiers: SHIFT }` — not
    // `modifiers: NONE`, which is what `KeyChord::parse("A")` (the default
    // binding for `open_accounts`) stores. Without stripping the redundant
    // shift bit for `Char` codes in `KeyChord::matches`, this default (and
    // every other single-uppercase-letter default: "S", "L", "G", "E", "J",
    // "K", ...) would never fire from a real keypress, only from
    // hand-crafted `KeyModifiers::NONE` test events.
    #[test]
    fn uppercase_letter_defaults_match_a_real_shift_reported_keypress() {
        let keymap = Keymap::resolve(&std::collections::HashMap::new());
        let shift_a = KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT);
        assert_eq!(
            keymap.action_for(shift_a, true),
            Some(TuiAction::OpenAccounts)
        );
        let shift_s = KeyEvent::new(KeyCode::Char('S'), KeyModifiers::SHIFT);
        assert_eq!(
            keymap.action_for(shift_s, true),
            Some(TuiAction::OpenSettings)
        );
    }

    #[test]
    fn plain_keys_are_hidden_from_text_input_contexts() {
        let keymap = Keymap::resolve(&std::collections::HashMap::new());
        let j = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE);
        assert_eq!(keymap.action_for(j, false), None);

        let ctrl_y = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL);
        assert_eq!(
            keymap.action_for(ctrl_y, false),
            Some(TuiAction::CopyPassword)
        );

        let pagedown = KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(
            keymap.action_for(pagedown, false),
            Some(TuiAction::PageDown)
        );
    }

    // Regression test: `AccountClose`/`AccountMoveDown` share their default
    // chords ("q"/"esc", "down"/"j") with the earlier-in-`TuiAction::ALL`
    // `Quit`/`MoveDown`. The unscoped `action_for` always resolves to the
    // global action first, which `App::handle_accounts` has no arm for --
    // silently swallowing every keypress in the accounts panel that
    // collides with a global default (this is exactly what happened live:
    // "q", the arrow keys, and "ctrl-c" all appeared to do nothing once the
    // accounts panel was reachable at all -- see
    // `uppercase_letter_defaults_match_a_real_shift_reported_keypress` for
    // the bug that made the accounts panel reachable in the first place).
    // `action_in`, scoped to
    // `TuiAction::ACCOUNT`, must resolve to the mode-appropriate action
    // instead.
    #[test]
    fn action_in_scopes_to_the_given_actions_not_the_global_default() {
        let keymap = Keymap::resolve(&std::collections::HashMap::new());

        let q = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(keymap.action_for(q, true), Some(TuiAction::Quit));
        assert_eq!(
            keymap.action_in(q, true, TuiAction::ACCOUNT),
            Some(TuiAction::AccountClose)
        );

        let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(keymap.action_for(down, true), Some(TuiAction::MoveDown));
        assert_eq!(
            keymap.action_in(down, true, TuiAction::ACCOUNT),
            Some(TuiAction::AccountMoveDown)
        );

        // A key with no `ACCOUNT`-scoped binding at all (e.g. the global
        // "sync" chord doesn't collide with anything account-scoped here)
        // still correctly resolves to nothing rather than falling back to
        // the global action.
        let s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE);
        assert_eq!(
            keymap.action_in(s, true, TuiAction::ACCOUNT),
            Some(TuiAction::AccountSync)
        );
    }

    #[test]
    fn display_round_trips_through_parse() {
        for s in ["g", "G", "ctrl-y", "alt-p", "pagedown", "enter", "tab"] {
            let chord = KeyChord::parse(s).unwrap_or_else(|| {
                panic!("test fixture {s:?} should itself parse")
            });
            let displayed = chord.display();
            assert_eq!(
                KeyChord::parse(&displayed),
                Some(chord),
                "{s:?} displayed as {displayed:?}, which didn't round-trip"
            );
        }
    }

    #[test]
    fn display_matches_the_established_glyph_style() {
        assert_eq!(KeyChord::parse("g").unwrap().display(), "g");
        assert_eq!(KeyChord::parse("ctrl-y").unwrap().display(), "^y");
        assert_eq!(KeyChord::parse("alt-p").unwrap().display(), "⌥p");
        assert_eq!(
            KeyChord::parse("pagedown").unwrap().display(),
            "pagedown"
        );
        assert_eq!(KeyChord::parse("enter").unwrap().display(), "⏎");
        assert_eq!(KeyChord::parse("tab").unwrap().display(), "⇥");
    }

    #[test]
    fn resolved_keymap_reports_the_overridden_chord_not_the_default() {
        let mut overrides = std::collections::HashMap::new();
        overrides
            .insert("copy_password".to_string(), vec!["ctrl-y".to_string()]);
        let keymap = Keymap::resolve(&overrides);

        assert_eq!(keymap.primary_chord(TuiAction::CopyPassword), "^y");
        assert_eq!(
            keymap.display_chords(TuiAction::CopyPassword),
            vec!["^y".to_string()]
        );

        // An action nobody configured still reports its built-in default.
        assert_eq!(keymap.primary_chord(TuiAction::CopyUsername), "u");
    }

    #[test]
    fn primary_chord_while_typing_skips_plain_char_chords() {
        let keymap = Keymap::resolve(&std::collections::HashMap::new());
        // `copy_password`'s defaults are ["p", "y", "alt-p", "ctrl-y"]; the
        // first two are plain chars that a text-input context swallows, so
        // the first chord usable there is "alt-p".
        assert_eq!(
            keymap.primary_chord_while_typing(TuiAction::CopyPassword),
            "⌥p"
        );
        // `move_down`'s defaults are ["j", "down", "ctrl-n"]; "down" isn't a
        // char at all, so it's usable while typing even though it isn't the
        // first (highest-priority) chord.
        assert_eq!(
            keymap.primary_chord_while_typing(TuiAction::MoveDown),
            "↓"
        );
    }
}
