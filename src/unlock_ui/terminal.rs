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
    layout::Rect,
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

// The pixel-art crab of the logo: one char per pixel, two pixel rows per
// terminal row (half blocks). `.` is transparent.
const CRAB: [&str; 18] = [
    "...nnn........nnn...",
    "..nbmnn......nnmbn..",
    ".nbmnn........nnmmn.",
    ".lmmnmmmn..nmm.nmmn.",
    "nmmmmmmbn..nbmmmmmmn",
    "nbmmmmbn....nbmmmmbn",
    "nbmmmbnnnnnnnnbmmmbn",
    ".nbmbnnnmmmmnnnbbbn.",
    "..nbnnmmmmmmmmnnbn..",
    "...nnnnnmmmmnnnnn...",
    "..nnnnwnnnnnnwnnnn..",
    ".nmmnnwwnnnnwwnnmmn.",
    "nbbnnmwwnnnnwwmnnbbn",
    "nn.nnnmmmmmmmmnnn..n",
    "..nmn.nbmmmmbn.nmn..",
    "..nbn..nnbbnn..nbn..",
    "...n............n...",
    "....................",
];
// The same crab, for terminals with little room.
const CRAB_TINY: [&str; 8] = [
    ".nn....nn.",
    "nmnm..mnmn",
    "bmmb..bmmb",
    "nmnnmmnnbn",
    ".nnnmmnnn.",
    "mbnwnnwnbm",
    "nnnmmmmnn.",
    ".n..nn..n.",
];
const CRAB_WIDTH: u16 = 20;
const CRAB_ROWS: u16 = 9;
const CRAB_TINY_WIDTH: u16 = 10;
const CRAB_TINY_ROWS: u16 = 4;
// Card width from which the crab fits beside the form.
const CRAB_CARD_WIDTH: u16 = 76;

fn crab_color(pixel: u8) -> Option<Color> {
    Some(match pixel {
        b'n' => Color::Rgb(7, 20, 53),
        b'm' => Color::Rgb(61, 154, 253),
        b'b' => Color::Rgb(22, 104, 232),
        b'l' => Color::Rgb(136, 202, 254),
        b'd' => Color::Rgb(8, 79, 199),
        b'w' => Color::Rgb(255, 255, 255),
        _ => return None,
    })
}

// The same pixel as a shade of green, for the unlock animation.
fn crab_green(color: Color) -> Color {
    let Color::Rgb(r, g, b) = color else {
        return color;
    };
    let luma =
        (u32::from(r) * 30 + u32::from(g) * 59 + u32::from(b) * 11) / 100;
    let channel = |value: u32| u8::try_from(value.min(255)).unwrap_or(255);
    Color::Rgb(
        channel(luma * 45 / 100),
        channel(70 + luma * 70 / 100),
        channel(luma * 55 / 100),
    )
}

// How many rows of an art `rows` tall the unlock animation has tinted green
// by now: it sweeps the whole art in ten frames, however tall it is, and the
// rest of the confirmation holds it green.
fn green_rows(view: &View<'_>, rows: u16) -> usize {
    if !view.success {
        return 0;
    }
    usize::try_from((view.tick + 1) * u64::from(rows) / 10)
        .unwrap_or(usize::MAX)
}

// A crab as terminal rows; the first `green_rows` of them are tinted green.
fn crab_lines(sprite: &[&str], green_rows: usize) -> Vec<Line<'static>> {
    sprite
        .chunks(2)
        .enumerate()
        .map(|(index, pair)| {
            let tint = |color: Color| {
                if index < green_rows {
                    crab_green(color)
                } else {
                    color
                }
            };
            Line::from(
                pair[0]
                    .bytes()
                    .zip(pair[1].bytes())
                    .map(|(top, bottom)| {
                        let (top, bottom) =
                            (crab_color(top), crab_color(bottom));
                        match (top, bottom) {
                            (None, None) => Span::raw(" "),
                            (Some(color), None) => Span::styled(
                                "▀",
                                Style::default().fg(tint(color)).bg(CARD),
                            ),
                            (None, Some(color)) => Span::styled(
                                "▄",
                                Style::default().fg(tint(color)).bg(CARD),
                            ),
                            (Some(top), Some(bottom)) if top == bottom => {
                                Span::styled(
                                    "█",
                                    Style::default().fg(tint(top)),
                                )
                            }
                            (Some(top), Some(bottom)) => Span::styled(
                                "▀",
                                Style::default()
                                    .fg(tint(top))
                                    .bg(tint(bottom)),
                            ),
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

pub(super) struct TerminalDialog {
    terminal: Terminal<CrosstermBackend<File>>,
    input: File,
    original: libc::termios,
    state: InputState,
}

struct InputState {
    secret: SecretInput,
    escape: [u8; 8],
    escape_len: usize,
    escape_started: Option<Instant>,
    paste: bool,
    // Tab toggles it; it starts from the `unlock_no_echo` setting.
    no_echo: bool,
    blocked: bool,
    busy: bool,
    issue: Option<&'static str>,
}

impl TerminalDialog {
    pub fn new(no_echo: bool) -> anyhow::Result<Self> {
        // Allocate input before entering raw mode: failure leaves the TTY intact.
        let mut state = InputState::new()?;
        state.no_echo = no_echo;
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
            no_echo: false,
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
        } else if byte == b'\t' && !self.paste {
            self.no_echo = !self.no_echo;
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
            || size_class(area.width, area.height) == SizeClass::TooSmall;
        let mask =
            (!self.state.no_echo).then(|| self.state.secret.char_count());
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeClass {
    // The full card with the fingerprint art.
    Full,
    // Narrow or short terminals (tmux splits, phones): the same content as
    // plain stacked lines, dropping decoration as space runs out.
    Compact,
    // Not even the compact layout fits; input is paused until it does.
    TooSmall,
}

fn size_class(width: u16, height: u16) -> SizeClass {
    if width >= 40 && height >= 17 {
        SizeClass::Full
    } else if width >= 16 && height >= 4 {
        SizeClass::Compact
    } else {
        SizeClass::TooSmall
    }
}

fn status_text(view: &View<'_>) -> String {
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
    if view.hide_disabled
        && view.fingerprint == FingerprintStatus::Disabled
        && !view.success
        && !view.checking
    {
        String::new()
    } else if view.success {
        "✓ Unlocked".to_string()
    } else if view.checking {
        format!("{indicator} Checking master password…")
    } else {
        format!("{indicator} {}", view.fingerprint.text())
    }
}

fn mask_text(
    view: &View<'_>,
    mask: Option<usize>,
    max: usize,
    short: bool,
) -> String {
    match mask {
        None => String::new(),
        Some(0) if view.success => String::new(),
        Some(0) if view.checking => "Checking password…".to_string(),
        Some(0) if short => "Type password…".to_string(),
        Some(0) => "Type your password…".to_string(),
        Some(length) => "•".repeat(length.min(max)),
    }
}

// The most detailed key hint that fits `width` columns: one line, or two
// when `two_rows` (the card has a second row for it).
fn key_hint(width: u16, two_rows: bool) -> &'static str {
    let tiers: &[&str] = if two_rows {
        &[
            "Enter to unlock   ·   Esc to cancel   ·   Ctrl+U to clear\nTab toggles the dots",
            "Enter unlock · Esc cancel · ^U clear\nTab toggles the dots",
        ]
    } else {
        &[
            "Enter unlock · Esc cancel · ^U clear · Tab dots",
            "Enter unlock · Esc cancel · ^U clear",
        ]
    };
    tiers
        .iter()
        .find(|hint| {
            hint.split('\n')
                .all(|line| line.chars().count() <= usize::from(width))
        })
        .copied()
        .unwrap_or("⏎ unlock · Esc cancel")
}

// Rows of `text` wrapped at `width` columns, at least one.
fn wrapped_rows(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let rows = text
        .split('\n')
        .map(|line| line.chars().count().div_ceil(width).max(1))
        .sum::<usize>();
    u16::try_from(rows).unwrap_or(u16::MAX)
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
    match size_class(area.width, area.height) {
        SizeClass::Full => draw_full(frame, view, mask, issue),
        SizeClass::Compact => draw_compact(frame, view, mask, issue),
        SizeClass::TooSmall => frame.render_widget(
            Paragraph::new("rbw: enlarge window. Esc cancels.")
                .style(Style::default().fg(INK))
                .wrap(Wrap { trim: true }),
            area,
        ),
    }
}

// Stacks header, status, password field and hint, top to bottom, giving
// up the field border, then wrapping, then the status and hint lines as the
// height shrinks. The password field is never dropped.
fn draw_compact(
    frame: &mut Frame<'_>,
    view: &View<'_>,
    mask: Option<usize>,
    issue: Option<&'static str>,
) {
    let area = frame.area();
    let margin = u16::from(area.width >= 24);
    let width = area.width.saturating_sub(2 * margin).min(66);
    let x = area.x + (area.width - width) / 2;
    let status = status_text(view);
    let error = issue.or(view.error);
    let hint = error.map_or_else(
        || {
            if view.success {
                ""
            } else if view.checking {
                "Checking password…"
            } else {
                key_hint(width, false)
            }
        },
        |error| error,
    );

    // Fixed rows: header and a one-line field. Spend the rest, in order, on
    // the status line and the hint (an error first, so it stays visible),
    // a bordered field, then a second row for each when it wraps.
    let mut free = area.height.saturating_sub(2);
    let mut take = |rows: u16| {
        let fits = free >= rows;
        if fits {
            free -= rows;
        }
        fits
    };
    let (hint_shown, status_shown) = if error.is_some() {
        let hint = take(1);
        (hint, take(1))
    } else {
        let status = take(1);
        (take(1), status)
    };
    let boxed = take(2);
    let status_rows = if status_shown {
        1 + u16::from(wrapped_rows(&status, width) > 1 && take(1))
    } else {
        0
    };
    let hint_rows = if hint_shown {
        1 + u16::from(wrapped_rows(hint, width) > 1 && take(1))
    } else {
        0
    };
    let field_rows = if boxed { 3 } else { 1 };
    let total = 1 + status_rows + field_rows + hint_rows;
    let mut y = area.y + (area.height - total) / 2;
    // A tiny crab above the stack when five spare rows allow it.
    if y - area.y > CRAB_TINY_ROWS && width >= CRAB_TINY_WIDTH {
        frame.render_widget(
            Paragraph::new(crab_lines(
                &CRAB_TINY,
                green_rows(view, CRAB_TINY_ROWS),
            )),
            Rect::new(
                area.x + (area.width - CRAB_TINY_WIDTH) / 2,
                y - CRAB_TINY_ROWS - 1,
                CRAB_TINY_WIDTH,
                CRAB_TINY_ROWS,
            ),
        );
    }

    let mut header = vec![
        Span::styled(
            "◇ RBW",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            concat!(" ", env!("CARGO_PKG_VERSION"), "  "),
            Style::default().fg(MUTED).add_modifier(Modifier::DIM),
        ),
    ];
    header.push(Span::styled(view.title, Style::default().fg(MUTED)));
    frame.render_widget(
        Paragraph::new(Line::from(header)),
        Rect::new(x, y, width, 1),
    );
    y += 1;
    let border = if view.success {
        Color::Rgb(134, 239, 172)
    } else if view.checking {
        BORDER
    } else {
        ACCENT
    };
    let short = width < 30;
    if view.success {
        // Unlocked: the status takes the password field's place.
        frame.render_widget(
            Paragraph::new(status.as_str()).style(
                Style::default()
                    .fg(Color::Rgb(134, 239, 172))
                    .add_modifier(Modifier::BOLD),
            ),
            Rect::new(x, y + field_rows / 2, width, 1),
        );
    } else if boxed {
        let field = Block::default()
            .title(match (mask.is_none(), short) {
                (true, true) => " Password (no echo) ",
                (true, false) => " Master password (no echo) ",
                (false, true) => " Password ",
                (false, false) => " Master password ",
            })
            .borders(Borders::ALL)
            .padding(Padding::horizontal(1))
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border));
        let max = usize::from(width.saturating_sub(4));
        frame.render_widget(
            Paragraph::new(mask_text(view, mask, max, short))
                .style(Style::default().fg(if mask == Some(0) {
                    MUTED
                } else {
                    INK
                }))
                .block(field),
            Rect::new(x, y, width, 3),
        );
    } else {
        let label = if short { "› " } else { "Password › " };
        let max = usize::from(width).saturating_sub(label.chars().count());
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(label, Style::default().fg(border)),
                Span::styled(
                    mask_text(view, mask, max, true),
                    Style::default().fg(if mask == Some(0) {
                        MUTED
                    } else {
                        INK
                    }),
                ),
            ])),
            Rect::new(x, y, width, 1),
        );
    }
    y += field_rows;
    if status_rows > 0 && !view.success {
        frame.render_widget(
            Paragraph::new(status)
                .style(Style::default().fg(if view.success {
                    Color::Rgb(134, 239, 172)
                } else {
                    CYAN
                }))
                .wrap(Wrap { trim: true }),
            Rect::new(x, y, width, status_rows),
        );
        y += status_rows;
    }
    if hint_rows > 0 {
        frame.render_widget(
            Paragraph::new(hint)
                .style(Style::default().fg(if error.is_some() {
                    ERROR
                } else {
                    MUTED
                }))
                .wrap(Wrap { trim: true }),
            Rect::new(x, y, width, hint_rows),
        );
    }
}

fn draw_full(
    frame: &mut Frame<'_>,
    view: &View<'_>,
    mask: Option<usize>,
    issue: Option<&'static str>,
) {
    let area = frame.area();
    let width = area.width.saturating_sub(4).min(CRAB_CARD_WIDTH);
    let crab = width >= CRAB_CARD_WIDTH;
    let height = 15.min(area.height.saturating_sub(2));
    let card = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    // With the crab beside it, the form keeps to the right column.
    let content = |offset: u16, height: u16| {
        let mut area = row(card, offset, height);
        if crab {
            area.x += CRAB_WIDTH + 2;
            area.width = area.width.saturating_sub(CRAB_WIDTH + 2);
        }
        area
    };
    let verified_color = [
        Color::Rgb(45, 57, 79),
        Color::Rgb(56, 110, 92),
        Color::Rgb(88, 177, 128),
        Color::Rgb(134, 239, 172),
    ][usize::try_from((view.tick / 3).min(3)).unwrap_or(3)];
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
            Span::styled(
                concat!(" ", env!("CARGO_PKG_VERSION")),
                Style::default().fg(MUTED).add_modifier(Modifier::DIM),
            ),
        ])),
        content(1, 1),
    );
    frame.render_widget(
        Paragraph::new(view.title)
            .style(Style::default().fg(MUTED))
            .wrap(Wrap { trim: true }),
        {
            let mut title = content(3, 2);
            if width >= 58 && !crab {
                title.width = title.width.saturating_sub(17);
            }
            title
        },
    );
    if crab {
        frame.render_widget(
            Paragraph::new(crab_lines(&CRAB, green_rows(view, CRAB_ROWS))),
            Rect::new(card.x + 3, card.y + 3, CRAB_WIDTH, CRAB_ROWS),
        );
    } else if width >= 58 {
        let art = [
            "⣴⣾⣦⣶⡀⠀⠀⠀⠀⢀⣶⣴⣷⣦",
            "⢻⣿⣿⣿⢃⣀⣀⣀⣀⡘⣿⣿⣿⡟",
            "⠀⠈⠉⠟⣿⡟⠛⠛⢻⣿⠻⠉⠁⠀",
            "⢀⣠⣤⣬⣿⣧⣤⣤⣼⣿⣥⣤⣄⡀",
            "⠈⠶⠆⠈⠛⠻⠿⠿⠟⠛⠁⠰⠶⠁",
        ];
        let lines: Vec<Line<'_>> = art
            .iter()
            .enumerate()
            .map(|(index, line)| {
                let color = if view.success {
                    if index < green_rows(view, 5) {
                        Color::Rgb(134, 239, 172)
                    } else {
                        ACCENT
                    }
                } else {
                    ACCENT
                };
                Line::styled(*line, Style::default().fg(color))
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines),
            Rect::new(card.right() - 17, card.y + 1, 14, 5),
        );
    }
    if view.success {
        // Unlocked: the status takes the password field's place.
        let slot = content(6, 3);
        frame.render_widget(
            Paragraph::new(status_text(view)).style(
                Style::default()
                    .fg(Color::Rgb(134, 239, 172))
                    .add_modifier(Modifier::BOLD),
            ),
            Rect::new(
                slot.x + 1,
                slot.y + 1,
                slot.width.saturating_sub(2),
                1,
            ),
        );
    } else {
        let field = Block::default()
            .title(if mask.is_none() {
                " Master password (no echo) "
            } else {
                " Master password "
            })
            .borders(Borders::ALL)
            .padding(Padding::horizontal(1))
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
            Paragraph::new(mask_text(
                view,
                mask,
                usize::from(content(6, 3).width.saturating_sub(4)),
                false,
            ))
            .style(Style::default().fg(if mask == Some(0) {
                MUTED
            } else {
                INK
            }))
            .block(field),
            content(6, 3),
        );
        frame.render_widget(
            Paragraph::new(status_text(view))
                .style(Style::default().fg(if view.success {
                    Color::Rgb(134, 239, 172)
                } else {
                    CYAN
                }))
                .wrap(Wrap { trim: true }),
            content(10, 2),
        );
    }
    let message = issue.or(view.error).unwrap_or_else(|| {
        if view.success {
            ""
        } else if view.checking {
            "Checking password…"
        } else {
            key_hint(content(12, 2).width, true)
        }
    });
    frame.render_widget(
        Paragraph::new(message)
            .style(Style::default().fg(if issue.or(view.error).is_some() {
                ERROR
            } else {
                MUTED
            }))
            .wrap(Wrap { trim: true }),
        content(12, 2),
    );
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
    fn tab_toggles_the_dots_but_not_inside_a_paste() {
        let mut input = InputState::new().unwrap();
        assert!(!input.no_echo);
        input.input_byte(b'\t').unwrap();
        assert!(input.no_echo);
        input.input_byte(b'\t').unwrap();
        assert!(!input.no_echo);
        assert!(!input.blocked);
        for byte in b"\x1b[200~a\tb\x1b[201~" {
            input.input_byte(*byte).unwrap();
        }
        assert!(input.blocked);
        assert!(!input.no_echo);
    }

    #[test]
    fn the_card_mentions_the_tab_shortcut() {
        let text = render(90, 28, &DEMO, Some(3), None).join("\n");
        assert!(text.contains("Tab toggles the dots"), "{text}");
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
            hide_disabled: false,
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
                        hide_disabled: false,
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

    fn render(
        width: u16,
        height: u16,
        view: &View<'_>,
        mask: Option<usize>,
        issue: Option<&'static str>,
    ) -> Vec<String> {
        let mut terminal =
            Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| draw(frame, view, mask, issue))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    const DEMO: View<'static> = View {
        title: "Unlock account default",
        fingerprint: FingerprintStatus::Ready,
        hide_disabled: false,
        checking: false,
        success: false,
        error: None,
        tick: 0,
    };

    #[test]
    fn narrow_and_short_terminals_keep_the_password_field() {
        for (width, height) in
            [(16, 4), (20, 5), (30, 6), (36, 10), (39, 40), (120, 12)]
        {
            assert_eq!(size_class(width, height), SizeClass::Compact);
            let text = render(width, height, &DEMO, Some(5), None).join("\n");
            assert!(text.contains("RBW"), "{width}x{height}:\n{text}");
            assert!(text.contains("•••••"), "{width}x{height}:\n{text}");
        }
        // Errors outrank the status line when only one of them fits.
        let text =
            render(30, 4, &DEMO, Some(0), Some("Wrong password")).join("\n");
        assert!(text.contains("Wrong password"), "{text}");
        assert_eq!(size_class(15, 20), SizeClass::TooSmall);
        assert_eq!(size_class(80, 3), SizeClass::TooSmall);
        assert_eq!(size_class(40, 27), SizeClass::Full);
    }

    // `cargo test print_compact_layouts -- --ignored --nocapture` shows
    // what the compact layout looks like at a few sizes.
    #[test]
    #[ignore = "prints layouts for manual review"]
    fn print_compact_layouts() {
        for (width, height) in
            [(16, 4), (24, 6), (30, 8), (36, 12), (60, 12), (90, 28)]
        {
            println!("--- {width}x{height}");
            for line in render(width, height, &DEMO, Some(7), None) {
                println!("|{line:width$}|", width = usize::from(width));
            }
        }
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
                        hide_disabled: false,
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
