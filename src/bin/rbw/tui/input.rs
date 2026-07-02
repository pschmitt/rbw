// A minimal single-line text field with a character cursor, used by the search
// bar and the edit form. Kept deliberately small: enough editing affordances to
// feel native (arrows, home/end, word/line kill) without pulling in a widget
// crate.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use unicode_width::UnicodeWidthStr as _;

#[derive(Clone, Default)]
pub struct Input {
    value: String,
    // Cursor position measured in characters (not bytes), in `0..=char_len`.
    cursor: usize,
}

impl Input {
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.chars().count();
        Self { value, cursor }
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    // Display width (in terminal cells) of the text preceding the cursor, used
    // to place the hardware cursor.
    pub fn cursor_display_col(&self) -> usize {
        self.value
            .chars()
            .take(self.cursor)
            .collect::<String>()
            .width()
    }

    fn char_len(&self) -> usize {
        self.value.chars().count()
    }

    // Byte offset of a character index (or the end of the string).
    fn byte_at(&self, char_idx: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_idx)
            .map_or(self.value.len(), |(i, _)| i)
    }

    fn insert(&mut self, c: char) {
        let idx = self.byte_at(self.cursor);
        self.value.insert(idx, c);
        self.cursor += 1;
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            let idx = self.byte_at(self.cursor);
            self.value.remove(idx);
        }
    }

    fn delete(&mut self) {
        if self.cursor < self.char_len() {
            let idx = self.byte_at(self.cursor);
            self.value.remove(idx);
        }
    }

    // Delete from the cursor back to the start of the previous word.
    fn kill_word(&mut self) {
        let mut end = self.cursor;
        let chars: Vec<char> = self.value.chars().collect();
        while end > 0 && chars[end - 1].is_whitespace() {
            end -= 1;
        }
        while end > 0 && !chars[end - 1].is_whitespace() {
            end -= 1;
        }
        let start_byte = self.byte_at(end);
        let end_byte = self.byte_at(self.cursor);
        self.value.replace_range(start_byte..end_byte, "");
        self.cursor = end;
    }

    fn kill_to_start(&mut self) {
        let end_byte = self.byte_at(self.cursor);
        self.value.replace_range(0..end_byte, "");
        self.cursor = 0;
    }

    // Apply an editing keypress. Returns true if the key was consumed (i.e. it
    // changed the text or moved the cursor), so callers can tell edits apart
    // from navigation keys they still want to handle themselves.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char(c) if ctrl => match c {
                'u' => self.kill_to_start(),
                'w' => self.kill_word(),
                'a' => self.cursor = 0,
                'e' => self.cursor = self.char_len(),
                _ => return false,
            },
            KeyCode::Char(c) => self.insert(c),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => {
                if self.cursor < self.char_len() {
                    self.cursor += 1;
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.char_len(),
            _ => return false,
        }
        true
    }
}

#[cfg(test)]
mod test {
    use super::Input;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn press(input: &mut Input, code: KeyCode) {
        input.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn ctrl(input: &mut Input, c: char) {
        input.handle_key(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::CONTROL,
        ));
    }

    #[test]
    fn insert_move_and_delete() {
        let mut input = Input::default();
        for c in "abc".chars() {
            press(&mut input, KeyCode::Char(c));
        }
        assert_eq!(input.value(), "abc");

        press(&mut input, KeyCode::Left);
        press(&mut input, KeyCode::Char('X'));
        assert_eq!(input.value(), "abXc");

        press(&mut input, KeyCode::Backspace);
        assert_eq!(input.value(), "abc");
    }

    #[test]
    fn kill_word_stops_at_previous_word() {
        let mut input = Input::new("hello world");
        press(&mut input, KeyCode::End);
        ctrl(&mut input, 'w');
        assert_eq!(input.value(), "hello ");
    }

    #[test]
    fn cursor_column_counts_display_cells_not_chars() {
        // Two wide (CJK) characters occupy four terminal cells.
        let input = Input::new("你好");
        assert_eq!(input.cursor_display_col(), 4);
    }
}
