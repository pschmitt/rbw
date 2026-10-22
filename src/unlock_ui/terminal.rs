use super::{Action, FingerprintStatus, Frontend, SecretInput, View};
use anyhow::Context as _;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::{
    cursor::{Hide, Show},
    event::{DisableBracketedPaste, EnableBracketedPaste},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap},
    Frame, Terminal,
};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::time::{Duration, Instant};
use zeroize::{Zeroize as _, Zeroizing};

const BG: Color = Color::Rgb(13, 17, 27);
const CARD: Color = Color::Rgb(21, 27, 42);
const BORDER: Color = Color::Rgb(45, 57, 79);
const ACCENT: Color = Color::Rgb(181, 154, 255);
const INK: Color = Color::Rgb(232, 238, 249);
const MUTED: Color = Color::Rgb(149, 163, 187);
const CYAN: Color = Color::Rgb(113, 220, 229);
const ERROR: Color = Color::Rgb(255, 154, 166);

pub(super) struct TerminalDialog {
    terminal: Terminal<CrosstermBackend<File>>,
    input: File,
    original: libc::termios,
    state: InputState,
    no_echo: bool,
}

struct InputState {
    secret: SecretInput,
    escape: [u8; 8],
    escape_len: usize,
    escape_started: Option<Instant>,
    paste: bool,
    blocked: bool,
    busy: bool,
    issue: Option<&'static str>,
}

impl TerminalDialog {
    pub fn new(no_echo: bool) -> anyhow::Result<Self> {
        // Allocate input before entering raw mode: failure leaves the TTY intact.
        let state = InputState::new()?;
        let input = OpenOptions::new().read(true).write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open("/dev/tty")
            .context("terminal unlock needs a controlling terminal; use --ui gtk or --pinentry")?;
        let output =
            OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        // SAFETY: the termios output points to initialized, writable storage.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(input.as_raw_fd(), &raw mut original) }
            != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("could not read terminal settings");
        }
        let mut raw = original;
        // SAFETY: raw points to our termios copy; fd is a live terminal.
        unsafe {
            libc::cfmakeraw(&raw mut raw);
        }
        if unsafe {
            libc::tcsetattr(
                input.as_raw_fd(),
                libc::TCSAFLUSH,
                &raw const raw,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("could not secure terminal input");
        }
        let terminal = Terminal::new(CrosstermBackend::new(output));
        let terminal = match terminal {
            Ok(terminal) => terminal,
            Err(error) => {
                // SAFETY: restore the settings read from this same terminal.
                unsafe {
                    libc::tcsetattr(
                        input.as_raw_fd(),
                        libc::TCSAFLUSH,
                        &raw const original,
                    );
                }
                return Err(error.into());
            }
        };
        let mut dialog = Self {
            terminal,
            input,
            original,
            state,
            no_echo,
        };
        execute!(
            dialog.terminal.backend_mut(),
            EnterAlternateScreen,
            EnableBracketedPaste,
            Hide
        )?;
        execute!(
            dialog.terminal.backend_mut(),
            ratatui::crossterm::terminal::Clear(
                ratatui::crossterm::terminal::ClearType::All
            ),
            ratatui::crossterm::cursor::MoveTo(0, 0)
        )?;
        Ok(dialog)
    }
}

impl InputState {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            secret: SecretInput::new()?,
            escape: [0; 8],
            escape_len: 0,
            escape_started: None,
            paste: false,
            blocked: false,
            busy: false,
            issue: None,
        })
    }

    fn input_byte(&mut self, byte: u8) -> anyhow::Result<Option<Action>> {
        if self.escape_started.is_some() {
            if self.escape_len == self.escape.len() {
                self.escape_started = None;
                self.block_input(
                    "Unsupported control sequence. Ctrl+U clears input.",
                );
                return Ok(None);
            }
            self.escape[self.escape_len] = byte;
            self.escape_len += 1;
            if self.escape_len == 1 && byte != b'[' {
                return Ok(Some(Action::Cancel));
            }
            if self.escape_len > 1 && (0x40..=0x7e).contains(&byte) {
                match &self.escape[..self.escape_len] {
                    b"[200~" if !self.paste => self.paste = true,
                    b"[201~" if self.paste => self.paste = false,
                    _ if self.paste => self.block_input("Paste contains control characters. Ctrl+U clears input."),
                    _ => {},
                }
                self.escape_started = None;
                self.escape_len = 0;
            }
            return Ok(None);
        }
        if byte == 0x1b {
            self.escape_started = Some(Instant::now());
            self.escape_len = 0;
            return Ok(None);
        }
        if matches!(byte, 3 | 4) {
            return Ok(Some(Action::Cancel));
        }
        if self.busy {
            return Ok(None);
        }
        if byte == 21 && !self.paste {
            self.secret.clear();
            self.blocked = false;
            self.issue = None;
        } else if matches!(byte, 8 | 127) && !self.paste {
            self.secret.backspace();
        } else if matches!(byte, b'\r' | b'\n') && !self.paste {
            if !self.blocked && !self.secret.is_empty() {
                let password = self.secret.take()?;
                if std::str::from_utf8(password.password()).is_err() {
                    self.block_input(
                        "Input is not valid UTF-8. Ctrl+U clears input.",
                    );
                } else {
                    return Ok(Some(Action::Submit(password)));
                }
            }
        } else if byte < 32 || byte == 127 {
            self.block_input(
                "Paste contains control characters. Ctrl+U clears input.",
            );
        } else if !self.blocked && !self.secret.push(byte) {
            self.block_input("Password is too long. Ctrl+U clears input.");
        }
        Ok(None)
    }

    fn block_input(&mut self, message: &'static str) {
        self.secret.clear();
        self.blocked = true;
        self.issue = Some(message);
    }
}

impl Drop for InputState {
    fn drop(&mut self) {
        self.secret.clear();
        self.escape.zeroize();
    }
}

impl Frontend for TerminalDialog {
    fn poll(&mut self) -> anyhow::Result<Option<Action>> {
        if self
            .state
            .escape_started
            .is_some_and(|start| start.elapsed() >= Duration::from_millis(80))
        {
            return Ok(Some(Action::Cancel));
        }
        // Read bytes directly into a wiped stack buffer. Terminal libraries
        // and paste events must never allocate a String containing the password.
        let mut buffer = Zeroizing::new([0u8; 256]);
        let length = match self.input.read(&mut buffer[..]) {
            Ok(0) => return Ok(Some(Action::Cancel)),
            Ok(length) => length,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(None)
            }
            Err(error) => return Err(error.into()),
        };
        for byte in &buffer[..length] {
            if let Some(action) = self.state.input_byte(*byte)? {
                return Ok(Some(action));
            }
        }
        Ok(None)
    }
    fn render(&mut self, view: &View<'_>) -> anyhow::Result<()> {
        let area = self.terminal.size()?;
        self.state.busy = view.checking
            || view.success
            || area.width < 40
            || area.height < 27;
        let mask = (!self.no_echo).then(|| self.state.secret.char_count());
        let issue = self.state.issue;
        self.terminal.draw(|frame| draw(frame, view, mask, issue))?;
        Ok(())
    }
    fn clear_secret(&mut self) {
        self.state.secret.clear();
        self.state.issue = None;
    }
}

impl Drop for TerminalDialog {
    fn drop(&mut self) {
        self.state.secret.clear();
        let _ = execute!(
            self.terminal.backend_mut(),
            DisableBracketedPaste,
            Show,
            LeaveAlternateScreen
        );
        // SAFETY: original belongs to this live TTY. Flush pending keystrokes
        // so they cannot be echoed into the shell after cancellation.
        unsafe {
            libc::tcsetattr(
                self.input.as_raw_fd(),
                libc::TCSAFLUSH,
                &raw const self.original,
            );
        }
    }
}

fn row(area: Rect, offset: u16, height: u16) -> Rect {
    Rect::new(
        area.x + 3,
        area.y + offset,
        area.width.saturating_sub(6),
        height,
    )
}

fn draw(
    frame: &mut Frame<'_>,
    view: &View<'_>,
    mask: Option<usize>,
    issue: Option<&'static str>,
) {
    let area = frame.area();
    frame
        .render_widget(Block::default().style(Style::default().bg(BG)), area);
    if area.width < 40 || area.height < 27 {
        frame.render_widget(Paragraph::new("Unlock rbw\n\nEnlarge this window to continue.\nEsc or Ctrl+C cancels.").style(Style::default().fg(INK)).alignment(Alignment::Center), area);
        return;
    }
    let width = area.width.saturating_sub(4).min(66);
    let height = 25.min(area.height.saturating_sub(2));
    let card = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    let verified_color = [
        Color::Rgb(45, 57, 79),
        Color::Rgb(56, 110, 92),
        Color::Rgb(88, 177, 128),
        Color::Rgb(134, 239, 172),
    ][usize::try_from((view.tick / 6).min(3)).unwrap_or(3)];
    frame.render_widget(Clear, card);
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(if view.success {
                verified_color
            } else {
                BORDER
            }))
            .style(Style::default().bg(CARD)),
        card,
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "◇  RBW",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("    YOUR VAULT", Style::default().fg(MUTED)),
        ])),
        row(card, 1, 1),
    );
    frame.render_widget(
        Paragraph::new(if view.success {
            "✓ Credential verified"
        } else {
            "Welcome back"
        })
        .style(Style::default().fg(INK).add_modifier(Modifier::BOLD)),
        row(card, 3, 1),
    );
    frame.render_widget(
        Paragraph::new(view.title)
            .style(Style::default().fg(MUTED))
            .wrap(Wrap { trim: true }),
        {
            let mut title = row(card, 4, 2);
            if width >= 58 {
                title.width = title.width.saturating_sub(17);
            }
            title
        },
    );
    if width >= 58 {
        let art = [
            "    ⢀⣀⣀⣀⣀⡀    ",
            "  ⣠⠾⣛⡯⣥⣬⢽⣛⢷⣄  ",
            " ⢸⠏⡞⣵⠟⠃⠸⡝⡎⢧⢻⠇ ",
            " ⠘⠸⡅⣿ ⡇ ⡇ ⠈⢸  ",
            "   ⠁⠻⠳⡙⢦⡙⢦ ⠉  ",
            "      ⠉ ⠁     ",
        ];
        let lines: Vec<Line<'_>> = art
            .iter()
            .enumerate()
            .map(|(index, line)| {
                let color = if view.success {
                    if index <= usize::try_from(view.tick / 4).unwrap_or(6) {
                        Color::Rgb(134, 239, 172)
                    } else {
                        CYAN
                    }
                } else if view.fingerprint == FingerprintStatus::Disabled {
                    BORDER
                } else if index
                    == usize::try_from((view.tick / 10) % 6).unwrap_or(0)
                {
                    ACCENT
                } else {
                    CYAN
                };
                Line::styled(*line, Style::default().fg(color))
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines),
            Rect::new(card.right() - 17, card.y + 1, 14, 6),
        );
    }
    let indicator = if view.checking
        || matches!(
            view.fingerprint,
            FingerprintStatus::Starting | FingerprintStatus::Checking
        ) {
        ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            [usize::try_from((view.tick / 5) % 10).unwrap_or(0)]
    } else {
        "◎"
    };
    frame.render_widget(
        Paragraph::new(if view.success {
            "✓  Verified. Finishing unlock…".to_string()
        } else if view.checking {
            format!("{indicator}  Checking master password…")
        } else {
            format!("{indicator}  {}", view.fingerprint.text())
        })
        .style(Style::default().fg(if view.success {
            Color::Rgb(134, 239, 172)
        } else {
            CYAN
        }))
        .wrap(Wrap { trim: true }),
        row(card, 7, 2),
    );
    let field = Block::default()
        .title(if mask.is_none() {
            " Master password (no echo) "
        } else {
            " Master password "
        })
        .borders(Borders::ALL)
        .padding(Padding::new(2, 2, 1, 1))
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if view.success {
            verified_color
        } else if view.checking {
            BORDER
        } else {
            ACCENT
        }));
    // Only a mask reaches Ratatui buffers, never the password. No-echo mode
    // renders an empty field regardless of whether any input is present.
    frame.render_widget(
        Paragraph::new(match mask {
            None => String::new(),
            Some(0) if view.success => "✓ Verified".to_string(),
            Some(0) if view.checking => "Checking password…".to_string(),
            Some(0) => "Type your password…".to_string(),
            Some(length) => "•".repeat(length.min(60)),
        })
        .style(Style::default().fg(if mask == Some(0) { MUTED } else { INK }))
        .block(field),
        row(card, 10, 5),
    );
    let message = issue.or(view.error).unwrap_or(if view.success {
        "✓ Verified. Finishing unlock…"
    } else if view.checking {
        "Checking password…"
    } else {
        "Enter to unlock   ·   Esc to cancel   ·   Ctrl+U to clear"
    });
    frame.render_widget(
        Paragraph::new(message)
            .style(Style::default().fg(if issue.or(view.error).is_some() {
                ERROR
            } else {
                MUTED
            }))
            .wrap(Wrap { trim: true }),
        row(card, 16, 2),
    );
    if card.height >= 24 {
        frame.render_widget(
            Paragraph::new(
                if view.fingerprint == FingerprintStatus::Disabled {
                    "PASSWORD UNLOCK"
                } else {
                    "PASSWORD OR FINGERPRINT · EITHER CAN UNLOCK"
                },
            )
            .alignment(Alignment::Center)
            .style(Style::default().fg(MUTED)),
            row(card, 21, 1),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    #[test]
    fn bracketed_paste_cannot_submit_or_keep_a_truncated_password() {
        let mut input = InputState::new().unwrap();
        for byte in b"\x1b[200~one\ntwo\x1b[201~\r" {
            assert!(input.input_byte(*byte).unwrap().is_none());
        }
        assert!(input.blocked);
        assert!(input.secret.is_empty());
        input.input_byte(21).unwrap();
        for byte in b"\x1b[200~good\x1b[201~" {
            assert!(input.input_byte(*byte).unwrap().is_none());
        }
        let Some(Action::Submit(password)) = input.input_byte(b'\r').unwrap()
        else {
            panic!("expected submit")
        };
        assert_eq!(password.password(), b"good");
    }

    #[test]
    fn overflow_requires_clearing_before_retyping() {
        let mut input = InputState::new().unwrap();
        for _ in 0..=crate::locked::CAPACITY {
            input.input_byte(b'x').unwrap();
        }
        assert!(input.blocked);
        assert!(input.secret.is_empty());
        assert!(input.input_byte(b'\r').unwrap().is_none());
        input.input_byte(21).unwrap();
        input.input_byte(b'a').unwrap();
        assert!(matches!(
            input.input_byte(b'\r').unwrap(),
            Some(Action::Submit(_))
        ));
    }

    #[test]
    fn invalid_utf8_is_never_submitted() {
        let mut input = InputState::new().unwrap();
        input.input_byte(0xff).unwrap();
        assert!(input.input_byte(b'\r').unwrap().is_none());
        assert!(input.blocked);
        assert!(input.secret.is_empty());
    }

    #[test]
    fn dialog_renders_only_masked_input_and_public_status() {
        let mut terminal = Terminal::new(TestBackend::new(90, 28)).unwrap();
        let view = View {
            title: "Unlock demo vault",
            fingerprint: FingerprintStatus::Ready,
            checking: false,
            success: false,
            error: None,
            tick: 0,
        };
        terminal
            .draw(|frame| draw(frame, &view, Some(12), None))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(text.contains("Welcome back"));
        assert!(text.contains("••••••••••••"));
        assert!(text.contains("any enrolled finger"));
    }
    #[test]
    fn no_echo_renders_no_password_mask() {
        let mut terminal = Terminal::new(TestBackend::new(90, 28)).unwrap();
        terminal
            .draw(|frame| {
                draw(
                    frame,
                    &View {
                        title: "Demo",
                        fingerprint: FingerprintStatus::Disabled,
                        checking: false,
                        success: false,
                        error: None,
                        tick: 0,
                    },
                    None,
                    None,
                );
            })
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(!text.contains('•'));
        assert!(text.contains("no echo"));
    }

    #[test]
    fn tiny_terminals_render_without_panicking() {
        let mut terminal = Terminal::new(TestBackend::new(12, 6)).unwrap();
        terminal
            .draw(|frame| {
                draw(
                    frame,
                    &View {
                        title: "Demo",
                        fingerprint: FingerprintStatus::Disabled,
                        checking: false,
                        success: false,
                        error: None,
                        tick: 0,
                    },
                    Some(0),
                    None,
                );
            })
            .unwrap();
    }
}
