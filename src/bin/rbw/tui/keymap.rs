// User-configurable TUI keybindings: named actions mapped to key chords
// (e.g. "ctrl-y", "alt-p", "g", "pagedown"), loaded from config.json's
// `tui_keybindings` and merged on top of the built-in defaults below. An
// action not mentioned in the user's config keeps its default chords; one
// that *is* mentioned has its defaults fully replaced (not appended to) by
// the configured chords.
//
// Deliberately out of scope, and not reachable through this map: the search
// filter's own text input, the Edit/Prompt overlays' field navigation, and
// small binary confirms (`ConfirmDelete`'s y/n, Help's "any key closes") —
// these are tied to the widget's own semantics rather than being freely
// rebindable single actions.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyChord {
    code: KeyCode,
    modifiers: KeyModifiers,
}

impl KeyChord {
    fn matches(self, key: KeyEvent) -> bool {
        self.code == key.code && self.modifiers == key.modifiers
    }

    // Parses e.g. "ctrl-y", "alt-shift-g", "pagedown", "g", "G". Modifier and
    // special-key names are case-insensitive; a lone trailing character is
    // taken literally (so "G" alone already implies shift, same as the
    // terminal reports it — no need to write "shift-g").
    fn parse(s: &str) -> Option<Self> {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TuiAction {
    Quit,
    MoveDown,
    MoveUp,
    PageDown,
    PageUp,
    JumpFirst,
    JumpLast,
    ScrollDetailDown,
    ScrollDetailUp,
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
}

impl TuiAction {
    // Every action, in the priority order used to resolve a keypress — if a
    // user's config gives two actions the same chord, whichever comes first
    // here wins.
    const ALL: &'static [Self] = &[
        Self::Quit,
        Self::MoveDown,
        Self::MoveUp,
        Self::PageDown,
        Self::PageUp,
        Self::JumpFirst,
        Self::JumpLast,
        Self::ScrollDetailDown,
        Self::ScrollDetailUp,
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
    ];

    // The config.json key used to override this action's chords.
    fn config_key(self) -> &'static str {
        match self {
            Self::Quit => "quit",
            Self::MoveDown => "move_down",
            Self::MoveUp => "move_up",
            Self::PageDown => "page_down",
            Self::PageUp => "page_up",
            Self::JumpFirst => "jump_first",
            Self::JumpLast => "jump_last",
            Self::ScrollDetailDown => "scroll_detail_down",
            Self::ScrollDetailUp => "scroll_detail_up",
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
        }
    }

    // Default chord strings for this action.
    fn defaults(self) -> &'static [&'static str] {
        match self {
            Self::Quit => &["q", "ctrl-c"],
            Self::MoveDown => &["j", "down", "ctrl-n"],
            Self::MoveUp => &["k", "up", "ctrl-p"],
            Self::PageDown => &["pagedown"],
            Self::PageUp => &["pageup"],
            Self::JumpFirst => &["g", "home"],
            Self::JumpLast => &["G", "end"],
            Self::ScrollDetailDown => &["J", "alt-j"],
            Self::ScrollDetailUp => &["K", "alt-k"],
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
    pub fn action_for(
        &self,
        key: KeyEvent,
        allow_plain: bool,
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
            .find(|(_, chords)| chords.iter().any(|c| c.matches(key)))
            .map(|(action, _)| *action)
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
}
