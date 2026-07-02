// Rendering for the vault browser. Pure view code: it reads `App` state and
// draws, never mutating. Layout math needs a few numeric casts that the crate's
// strict lints would otherwise flag; they're bounded by terminal dimensions.
#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, ListState,
        Paragraph, Wrap,
    },
    Frame,
};
use unicode_width::UnicodeWidthStr as _;

use crate::commands::{
    self, DecryptedCipher, DecryptedData, DecryptedSearchCipher,
};

use super::app::{
    AccountsView, App, AttachmentView, EditForm, Level, Mode, Prompt,
};

const ACCENT: Color = Color::Cyan;
const SELECT_BG: Color = Color::Rgb(38, 44, 66);
const DIM: Color = Color::Rgb(128, 132, 148);
// Foreground (not background) so it stays legible layered under the list's
// own row-selection highlight. Same red the CLI's `list`/`search` use for
// grep-style match highlighting (ANSI "1;31").
const MATCH: Color = Color::Red;
const MASK: &str = "••••••••";
const SEARCH_PROMPT: &str = "❯ ";
const LABEL_W: usize = 12;
// Below this many columns the side-by-side list/details split gets too cramped,
// so we stack them vertically instead.
const NARROW_WIDTH: u16 = 80;

pub fn render(f: &mut Frame, app: &App) {
    // Search bar sits at the bottom (fzf-style), just above the status line.
    let [main, search, status] = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(f.area());

    // On a wide terminal, put the list and details side by side. When there
    // isn't room for a readable details column, stack them instead — details
    // on top, list below (so the selection and its details stay together).
    if main.width >= NARROW_WIDTH {
        let [list_area, detail_area] = Layout::horizontal([
            Constraint::Percentage(40),
            Constraint::Min(0),
        ])
        .areas(main);
        render_list(f, app, list_area);
        render_detail(f, app, detail_area);
    } else {
        let [detail_area, list_area] = Layout::vertical([
            Constraint::Percentage(50),
            Constraint::Min(0),
        ])
        .areas(main);
        render_detail(f, app, detail_area);
        render_list(f, app, list_area);
    }
    render_search(f, app, search);
    render_status(f, app, status);

    match &app.mode {
        Mode::Edit(form) => render_form(f, form, main),
        Mode::ConfirmDelete => render_confirm(f, app, main),
        Mode::Attachments(view) => render_attachments(f, view, main),
        Mode::Accounts(view) => render_accounts(f, view, main),
        Mode::Prompt(prompt) => render_prompt(f, prompt, main),
        Mode::Help => render_help(f, main),
        Mode::Normal | Mode::Search => {}
    }
}

fn block(title: &str, focused: bool) -> Block<'_> {
    let border = if focused { ACCENT } else { DIM };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border))
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(if focused { ACCENT } else { DIM })
                .bold(),
        ))
}

fn render_search(f: &mut Frame, app: &App, area: Rect) {
    let searching = matches!(app.mode, Mode::Search);
    let prompt_color = if searching { ACCENT } else { DIM };
    let value = app.filter.value();
    let text = if value.is_empty() && !searching {
        Line::from(vec![
            Span::styled(SEARCH_PROMPT, Style::default().fg(prompt_color)),
            Span::styled(
                "type to search · tab for actions",
                Style::default().fg(DIM).italic(),
            ),
        ])
    } else {
        let mut spans = vec![Span::styled(
            SEARCH_PROMPT,
            Style::default().fg(prompt_color),
        )];
        spans.extend(styled_ranges(
            value,
            &commands::scope_prefix_ranges(value),
            Style::default(),
            Style::default().fg(ACCENT).bold(),
        ));
        Line::from(spans)
    };
    f.render_widget(Paragraph::new(text), area);

    if searching {
        let x = area.x
            + SEARCH_PROMPT.width() as u16
            + app.filter.cursor_display_col() as u16;
        f.set_cursor_position((
            x.min(area.right().saturating_sub(1)),
            area.y,
        ));
    }
}

fn type_marker(kind: &str) -> Span<'static> {
    let color = match kind {
        "Login" => Color::Green,
        "Card" => Color::Yellow,
        "Identity" => Color::Magenta,
        "SecureNote" => Color::Blue,
        "SshKey" => ACCENT,
        _ => DIM,
    };
    Span::styled("● ", Style::default().fg(color))
}

fn render_list(f: &mut Frame, app: &App, area: Rect) {
    let focused = matches!(app.mode, Mode::Normal | Mode::Search);
    let total = app.search.len();
    let count = app.filtered.len();
    let title = if count == total {
        format!("rbw · {total} entries")
    } else {
        format!("rbw · {count}/{total}")
    };
    let b = block(&title, focused);
    let inner = b.inner(area);
    f.render_widget(b, area);

    if app.filtered.is_empty() {
        let msg = Paragraph::new(Text::styled(
            "\n  no matching entries",
            Style::default().fg(DIM).italic(),
        ));
        f.render_widget(msg, inner);
        return;
    }

    let width = inner.width as usize;
    let query = app.filter.value();
    let items: Vec<ListItem> = app
        .filtered
        .iter()
        .map(|&i| list_item(&app.search[i], app.badge(i), width, query))
        .collect();

    let list = List::new(items)
        .highlight_style(
            Style::default().bg(SELECT_BG).fg(Color::White).bold(),
        )
        .highlight_symbol("▌");

    let mut state = ListState::default();
    state.select(Some(app.selected));
    f.render_stateful_widget(list, inner, &mut state);
}

// Splits `text` into styled spans, painting the byte ranges in `ranges`
// (already merged/sorted, from `commands::highlight_ranges`) with
// `base_style` patched to `MATCH` foreground + bold, and everything else
// with `base_style` plain. Known limitation: on the currently-selected row,
// `List`'s own highlight style wins outright and this doesn't show through —
// acceptable since that row is already visually distinct (background +
// marker) and its full detail is in the side pane.
fn highlighted_spans(
    text: &str,
    ranges: &[(usize, usize)],
    base_style: Style,
) -> Vec<Span<'static>> {
    styled_ranges(text, ranges, base_style, base_style.fg(MATCH).bold())
}

// Splits `text` into styled spans: the byte ranges in `ranges` (sorted,
// non-overlapping) get `range_style`, everything else gets `base_style`.
fn styled_ranges(
    text: &str,
    ranges: &[(usize, usize)],
    base_style: Style,
    range_style: Style,
) -> Vec<Span<'static>> {
    if ranges.is_empty() {
        return vec![Span::styled(text.to_string(), base_style)];
    }
    let mut spans = Vec::new();
    let mut pos = 0;
    for &(s, e) in ranges {
        if s > pos {
            spans.push(Span::styled(text[pos..s].to_string(), base_style));
        }
        spans.push(Span::styled(text[s..e].to_string(), range_style));
        pos = e;
    }
    if pos < text.len() {
        spans.push(Span::styled(text[pos..].to_string(), base_style));
    }
    spans
}

fn list_item(
    entry: &DecryptedSearchCipher,
    badge: Option<&str>,
    width: usize,
    query: &str,
) -> ListItem<'static> {
    let marker = type_marker(&entry.entry_type);
    let name = entry.name.clone();
    let user = entry.user.clone();

    // Account badge (only present when more than one account is configured).
    let badge_text = badge.map(|b| format!("{b} "));
    let badge_w = badge_text
        .as_deref()
        .map_or(0, unicode_width::UnicodeWidthStr::width);

    let mut left = vec![marker];
    if let Some(badge_text) = &badge_text {
        left.push(Span::styled(
            badge_text.clone(),
            Style::default().fg(Color::Magenta),
        ));
    }
    left.extend(highlighted_spans(
        &name,
        &commands::highlight_ranges(
            query,
            commands::SearchField::Name,
            &name,
        ),
        Style::default(),
    ));
    if let Some(user) = &user {
        left.push(Span::raw("  "));
        left.extend(highlighted_spans(
            user,
            &commands::highlight_ranges(
                query,
                commands::SearchField::User,
                user,
            ),
            Style::default().fg(DIM),
        ));
    }
    let folder = entry.folder.clone();

    // Right-align the folder tag within the row when there's room.
    let left_w: usize = 2 // marker
        + badge_w
        + name.width()
        + user.as_deref().map_or(0, |u| u.width() + 2);
    if let Some(folder) = folder {
        let tag = format!("{folder} ");
        let tag_w = tag.width() + 1;
        // 2 accounts for the highlight symbol / left padding.
        if left_w + tag_w + 2 < width {
            let pad = width - left_w - tag_w - 1;
            left.push(Span::raw(" ".repeat(pad)));
            left.extend(highlighted_spans(
                &tag,
                &commands::highlight_ranges(
                    query,
                    commands::SearchField::Folder,
                    &tag,
                ),
                Style::default().fg(Color::Blue),
            ));
        }
    }

    ListItem::new(Line::from(left))
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let b = block("details", false);
    let inner = b.inner(area);
    f.render_widget(b, area);

    let Some(detail) = app.current_detail() else {
        let msg = if app.current_search().is_some() {
            "  decrypting…"
        } else {
            "  select an entry"
        };
        f.render_widget(
            Paragraph::new(Text::styled(
                format!("\n{msg}"),
                Style::default().fg(DIM).italic(),
            )),
            inner,
        );
        return;
    };

    let lines = detail_lines(detail, app.reveal, app.filter.value());
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));
    f.render_widget(para, inner);
}

fn row(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:>LABEL_W$}  "),
            Style::default().fg(DIM),
        ),
        Span::raw(value.into()),
    ])
}

// Like `row`, but highlights the parts of `value` that matched `query` (see
// `commands::highlight_ranges`) instead of rendering it plain.
fn highlighted_row(
    label: &str,
    value: &str,
    query: &str,
    field: commands::SearchField,
) -> Line<'static> {
    let mut spans = vec![Span::styled(
        format!("{label:>LABEL_W$}  "),
        Style::default().fg(DIM),
    )];
    spans.extend(highlighted_spans(
        value,
        &commands::highlight_ranges(query, field, value),
        Style::default(),
    ));
    Line::from(spans)
}

// Like `highlighted_row`, but for a value that's masked until `reveal`:
// revealed, it highlights matches the same as any other field; masked, the
// value itself stays hidden but a red " *" after the mask still tells you
// it's *why* this entry matched (mirrors `search_match`'s own scan of
// hidden/sensitive fields, which already counts them — this just makes that
// visible).
fn secret_row(
    label: &str,
    value: &str,
    reveal: bool,
    query: &str,
    field: commands::SearchField,
) -> Line<'static> {
    let ranges = commands::highlight_ranges(query, field, value);
    let mut spans = vec![Span::styled(
        format!("{label:>LABEL_W$}  "),
        Style::default().fg(DIM),
    )];
    if reveal {
        spans.extend(highlighted_spans(
            value,
            &ranges,
            Style::default().fg(Color::Yellow),
        ));
    } else {
        spans.push(Span::styled(
            MASK.to_string(),
            Style::default().fg(Color::Yellow),
        ));
        if !ranges.is_empty() {
            spans.push(Span::styled(" *", Style::default().fg(MATCH).bold()));
        }
    }
    Line::from(spans)
}

#[allow(clippy::ref_option)]
fn opt_row(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: &Option<String>,
) {
    if let Some(v) = value {
        if !v.is_empty() {
            lines.push(row(label, v.clone()));
        }
    }
}

fn detail_lines(
    detail: &DecryptedCipher,
    reveal: bool,
    query: &str,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    lines.push(Line::from(highlighted_spans(
        &detail.name,
        &commands::highlight_ranges(
            query,
            commands::SearchField::Name,
            &detail.name,
        ),
        Style::default().fg(ACCENT).bold(),
    )));
    lines.push(Line::from(Span::styled(
        type_name(&detail.data).to_string(),
        Style::default().fg(DIM).italic(),
    )));
    if let Some(folder) = &detail.folder {
        lines.push(highlighted_row(
            "folder",
            folder,
            query,
            commands::SearchField::Folder,
        ));
    }
    lines.push(Line::raw(""));

    match &detail.data {
        DecryptedData::Login {
            username,
            password,
            totp,
            uris,
        } => {
            if let Some(username) = username {
                lines.push(highlighted_row(
                    "username",
                    username,
                    query,
                    commands::SearchField::User,
                ));
            }
            if let Some(pw) = password {
                lines.push(secret_row(
                    "password",
                    pw,
                    reveal,
                    query,
                    commands::SearchField::Secret,
                ));
            }
            if let Some(totp) = totp {
                lines.push(totp_line(totp, reveal));
            }
            if let Some(uris) = uris {
                for (i, uri) in uris.iter().enumerate() {
                    let label = if i == 0 { "url" } else { "" };
                    lines.push(highlighted_row(
                        label,
                        &uri.uri,
                        query,
                        commands::SearchField::Uri,
                    ));
                }
            }
        }
        DecryptedData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => {
            opt_row(&mut lines, "cardholder", cardholder_name);
            if let Some(number) = number {
                lines.push(secret_row(
                    "number",
                    number,
                    reveal,
                    query,
                    commands::SearchField::Secret,
                ));
            }
            opt_row(&mut lines, "brand", brand);
            if exp_month.is_some() || exp_year.is_some() {
                let m = exp_month.as_deref().unwrap_or("--");
                let y = exp_year.as_deref().unwrap_or("----");
                lines.push(row("expires", format!("{m}/{y}")));
            }
            if let Some(code) = code {
                lines.push(secret_row(
                    "cvv",
                    code,
                    reveal,
                    query,
                    commands::SearchField::Secret,
                ));
            }
        }
        DecryptedData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            username,
            ..
        } => {
            let name: Vec<&str> = [title, first_name, middle_name, last_name]
                .into_iter()
                .filter_map(|v| v.as_deref())
                .collect();
            if !name.is_empty() {
                lines.push(row("name", name.join(" ")));
            }
            if let Some(username) = username {
                lines.push(highlighted_row(
                    "username",
                    username,
                    query,
                    commands::SearchField::User,
                ));
            }
            opt_row(&mut lines, "email", email);
            opt_row(&mut lines, "phone", phone);
            opt_row(&mut lines, "address", address1);
            opt_row(&mut lines, "city", city);
            opt_row(&mut lines, "state", state);
            opt_row(&mut lines, "zip", postal_code);
            opt_row(&mut lines, "country", country);
        }
        DecryptedData::SecureNote => {}
        DecryptedData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => {
            opt_row(&mut lines, "fingerprint", fingerprint);
            opt_row(&mut lines, "public key", public_key);
            if let Some(pk) = private_key {
                lines.push(secret_row(
                    "private key",
                    pk,
                    reveal,
                    query,
                    commands::SearchField::Secret,
                ));
            }
        }
    }

    if !detail.fields.is_empty() {
        lines.push(Line::raw(""));
        lines.push(section("custom fields"));
        for field in &detail.fields {
            let label = field.name.clone().unwrap_or_default();
            let value = field.value.clone().unwrap_or_default();
            let hidden =
                matches!(field.ty, Some(rbw::api::FieldType::Hidden));
            if hidden {
                lines.push(secret_row(
                    &label,
                    &value,
                    reveal,
                    query,
                    commands::SearchField::Field,
                ));
            } else {
                lines.push(highlighted_row(
                    &label,
                    &value,
                    query,
                    commands::SearchField::Field,
                ));
            }
        }
    }

    if let Some(notes) = &detail.notes {
        if !notes.is_empty() {
            lines.push(Line::raw(""));
            lines.push(section("notes"));
            for line in notes.lines() {
                lines.push(Line::from(highlighted_spans(
                    line,
                    &commands::highlight_ranges(
                        query,
                        commands::SearchField::Notes,
                        line,
                    ),
                    Style::default(),
                )));
            }
        }
    }

    let att = detail.attachment_metadata.attachment_count;
    if att > 0 || !detail.history.is_empty() {
        lines.push(Line::raw(""));
        let mut meta = Vec::new();
        if att > 0 {
            meta.push(format!("{att} attachment(s)"));
        }
        if !detail.history.is_empty() {
            meta.push(format!("{} past password(s)", detail.history.len()));
        }
        lines.push(Line::from(Span::styled(
            format!("  {}", meta.join(" · ")),
            Style::default().fg(DIM).italic(),
        )));
    }

    lines
}

fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))
}

fn totp_line(secret: &str, reveal: bool) -> Line<'static> {
    let value = if reveal {
        crate::commands::generate_totp(secret).map_or_else(
            |_| "invalid TOTP".to_string(),
            |code| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let remaining = 30 - (now % 30);
                format!("{code}   ({remaining}s)")
            },
        )
    } else {
        format!("{MASK}   (t to copy)")
    };
    Line::from(vec![
        Span::styled(
            format!("{:>LABEL_W$}  ", "totp"),
            Style::default().fg(DIM),
        ),
        Span::styled(value, Style::default().fg(Color::Green)),
    ])
}

fn type_name(data: &DecryptedData) -> &'static str {
    match data {
        DecryptedData::Login { .. } => "Login",
        DecryptedData::Card { .. } => "Card",
        DecryptedData::Identity { .. } => "Identity",
        DecryptedData::SecureNote => "Secure note",
        DecryptedData::SshKey { .. } => "SSH key",
    }
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    if let Some(status) = &app.status {
        let color = match status.level {
            Level::Info => ACCENT,
            Level::Success => Color::Green,
            Level::Warn => Color::Yellow,
            Level::Error => Color::Red,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {}", status.text),
                Style::default().fg(color).bold(),
            ))),
            area,
        );
        return;
    }

    let hint = match &app.mode {
        Mode::Search => {
            "type to filter · ↑/↓ select · ⇥ actions · ⌥p/u/t/o copy · ^E editor · esc clear"
        }
        Mode::Edit(_) => "⏎ save · esc cancel · ⇥ next field · ^R reveal · ^E editor",
        Mode::ConfirmDelete => "y confirm · n/esc cancel",
        Mode::Attachments(_) => {
            "⏎ download · a upload · d delete · ↑/↓ select · esc cancel"
        }
        Mode::Accounts(_) => {
            "⏎/u unlock · s sync · p primary · a add · ↑/↓ select · esc close"
        }
        Mode::Prompt(prompt) => prompt.hint,
        Mode::Help => "any key to close",
        Mode::Normal => {
            "/ search · e edit · a add · d delete · p/u/t copy · o open · s attach · A accounts · ^S sync · r reveal · ? help · q quit"
        }
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(" {hint}"),
            Style::default().fg(DIM),
        ))),
        area,
    );
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    let [row] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    let [col] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(row);
    col
}

fn render_form(f: &mut Frame, form: &EditForm, area: Rect) {
    let width = 72u16.min(area.width.saturating_sub(4));
    let height =
        (form.fields.len() as u16 + 4).min(area.height.saturating_sub(2));
    let rect = centered(width, height, area);

    f.render_widget(Clear, rect);
    let b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            format!(" {} ", form.title),
            Style::default().fg(ACCENT).bold(),
        ));
    let inner = b.inner(rect);
    f.render_widget(b, rect);

    let mut lines: Vec<Line> = Vec::new();
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let prefix = if focused { "❯ " } else { "  " };
        let value = if field.secret && !form.reveal && !field.input.is_empty()
        {
            MASK.to_string()
        } else {
            field.input.value().to_string()
        };
        let mut spans = vec![
            Span::styled(
                prefix,
                Style::default().fg(if focused { ACCENT } else { DIM }),
            ),
            Span::styled(
                format!("{:<9}", field.label),
                Style::default().fg(if focused { Color::White } else { DIM }),
            ),
            Span::raw("  "),
            Span::styled(
                value,
                Style::default().fg(if field.secret {
                    Color::Yellow
                } else {
                    Color::White
                }),
            ),
        ];
        if !field.editable {
            spans.push(Span::styled(
                "  (edit via ^E)",
                Style::default().fg(DIM).italic(),
            ));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "⏎ save   esc cancel   ⇥ next   ^R reveal   ^E editor",
        Style::default().fg(DIM),
    )));

    f.render_widget(Paragraph::new(lines), inner);

    // Place the cursor in the focused, editable field.
    if let Some(field) = form.fields.get(form.focus) {
        if field.editable {
            let x =
                inner.x + 2 + 9 + 2 + field.input.cursor_display_col() as u16;
            let y = inner.y + form.focus as u16;
            f.set_cursor_position((
                x.min(inner.right().saturating_sub(1)),
                y,
            ));
        }
    }
}

fn render_prompt(f: &mut Frame, prompt: &Prompt, area: Rect) {
    // Widest label, so values line up in a column.
    let label_w = prompt
        .fields
        .iter()
        .map(|field| field.label.width())
        .max()
        .unwrap_or(0);
    let width = 72u16.min(area.width.saturating_sub(4));
    let height =
        (prompt.fields.len() as u16 + 4).min(area.height.saturating_sub(2));
    let rect = centered(width, height, area);

    f.render_widget(Clear, rect);
    let b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            format!(" {} ", prompt.title),
            Style::default().fg(ACCENT).bold(),
        ));
    let inner = b.inner(rect);
    f.render_widget(b, rect);

    let mut lines: Vec<Line> = Vec::new();
    for (i, field) in prompt.fields.iter().enumerate() {
        let focused = i == prompt.focus;
        let prefix = if focused { "❯ " } else { "  " };
        lines.push(Line::from(vec![
            Span::styled(
                prefix,
                Style::default().fg(if focused { ACCENT } else { DIM }),
            ),
            Span::styled(
                format!("{:<label_w$}", field.label),
                Style::default().fg(if focused { Color::White } else { DIM }),
            ),
            Span::raw("  "),
            Span::styled(
                field.input.value().to_string(),
                Style::default().fg(Color::White),
            ),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        prompt.hint,
        Style::default().fg(DIM),
    )));

    f.render_widget(Paragraph::new(lines), inner);

    // Cursor in the focused field.
    if let Some(field) = prompt.fields.get(prompt.focus) {
        let x = inner.x
            + 2
            + label_w as u16
            + 2
            + field.input.cursor_display_col() as u16;
        let y = inner.y + prompt.focus as u16;
        f.set_cursor_position((x.min(inner.right().saturating_sub(1)), y));
    }
}

fn render_confirm(f: &mut Frame, app: &App, area: Rect) {
    let name = app
        .current_search()
        .map_or_else(|| "this entry".to_string(), |s| s.name.clone());
    let rect = centered(50, 5, area);
    f.render_widget(Clear, rect);
    let b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Red))
        .title(Span::styled(
            " delete entry ",
            Style::default().fg(Color::Red).bold(),
        ));
    let inner = b.inner(rect);
    f.render_widget(b, rect);
    let text = Text::from(vec![
        Line::from(vec![
            Span::raw("Delete "),
            Span::styled(
                format!("'{name}'"),
                Style::default().fg(Color::White).bold(),
            ),
            Span::raw("?"),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            "y confirm · n/esc cancel",
            Style::default().fg(DIM),
        )),
    ]);
    f.render_widget(Paragraph::new(text).alignment(Alignment::Center), inner);
}

fn render_attachments(f: &mut Frame, view: &AttachmentView, area: Rect) {
    let height =
        (view.items.len() as u16 + 4).clamp(5, area.height.saturating_sub(2));
    let rect = centered(64.min(area.width.saturating_sub(4)), height, area);
    f.render_widget(Clear, rect);
    let b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " attachments ",
            Style::default().fg(ACCENT).bold(),
        ));
    let inner = b.inner(rect);
    f.render_widget(b, rect);

    let mut lines: Vec<Line> = Vec::new();
    for (i, item) in view.items.iter().enumerate() {
        let selected = i == view.selected;
        let prefix = if selected { "❯ " } else { "  " };
        let mut spans = vec![
            Span::styled(
                prefix,
                Style::default().fg(if selected { ACCENT } else { DIM }),
            ),
            Span::styled(
                item.name.clone(),
                Style::default().fg(if selected {
                    Color::White
                } else {
                    DIM
                }),
            ),
        ];
        if let Some(size) = &item.size {
            spans.push(Span::styled(
                format!("  ({size})"),
                Style::default().fg(DIM),
            ));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::raw(""));
    let hint = if view.pending_delete {
        Line::from(Span::styled(
            "press d again to confirm delete · any other key cancels",
            Style::default().fg(Color::Red).bold(),
        ))
    } else {
        Line::from(Span::styled(
            "⏎ download · a upload · d delete · esc cancel",
            Style::default().fg(DIM),
        ))
    };
    lines.push(hint);

    f.render_widget(Paragraph::new(lines), inner);
}

fn render_accounts(f: &mut Frame, view: &AccountsView, area: Rect) {
    let height = (view.accounts.len() as u16 + 5)
        .clamp(6, area.height.saturating_sub(2));
    let rect = centered(70.min(area.width.saturating_sub(4)), height, area);
    f.render_widget(Clear, rect);
    let b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " accounts ",
            Style::default().fg(ACCENT).bold(),
        ));
    let inner = b.inner(rect);
    f.render_widget(b, rect);

    let mut lines: Vec<Line> = Vec::new();
    for (i, acct) in view.accounts.iter().enumerate() {
        let selected = i == view.selected;
        let prefix = if selected { "❯ " } else { "  " };
        let lock = if acct.unlocked { "🔓" } else { "🔒" };
        let primary = if acct.primary { " ⭐" } else { "" };
        let mut spans = vec![
            Span::styled(
                prefix,
                Style::default().fg(if selected { ACCENT } else { DIM }),
            ),
            Span::raw(format!("{lock} ")),
            Span::styled(
                acct.name.clone(),
                Style::default()
                    .fg(if selected { Color::White } else { DIM })
                    .bold(),
            ),
            Span::styled(primary, Style::default().fg(Color::Yellow)),
        ];
        if let Some(email) = &acct.email {
            spans.push(Span::styled(
                format!("  {email}"),
                Style::default().fg(DIM),
            ));
        }
        spans.push(Span::styled(
            format!("  ({})", acct.server),
            Style::default().fg(Color::Blue),
        ));
        lines.push(Line::from(spans));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "⏎/u unlock · s sync · p set primary · a add · esc close",
        Style::default().fg(DIM),
    )));

    f.render_widget(Paragraph::new(lines), inner);
}

fn render_help(f: &mut Frame, area: Rect) {
    let rect = centered(
        56.min(area.width.saturating_sub(2)),
        22.min(area.height.saturating_sub(2)),
        area,
    );
    f.render_widget(Clear, rect);
    let b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            " keybindings ",
            Style::default().fg(ACCENT).bold(),
        ));
    let inner = b.inner(rect);
    f.render_widget(b, rect);

    let entries = [
        ("type", "filter the list (search is always live)"),
        ("  u:/uri:/n:/f:", "scope a word to user/uri/name/folder"),
        ("↑/↓ · ^p/^n", "move selection (works while searching)"),
        ("⇥ · /", "toggle search bar ↔ list"),
        ("g / G", "jump to top / bottom"),
        ("⌥j / ⌥k · J/K", "scroll details"),
        ("r · ^r", "reveal / hide secrets"),
        ("p·y · ⌥p", "copy password"),
        ("u · ⌥u", "copy username"),
        ("t · ⌥t", "copy TOTP code"),
        ("o · ⌥o", "open URL in browser"),
        ("s · ⌥s", "browse / download attachments"),
        ("^s", "sync with the server (any focus)"),
        ("e · ⏎", "edit entry (inline form)"),
        ("^e · E", "edit entry in $EDITOR (any focus)"),
        ("a", "add a new login"),
        ("A", "accounts: unlock / sync / set primary"),
        ("d", "delete entry"),
        ("?", "this help"),
        ("q · esc", "quit"),
    ];
    let lines: Vec<Line> = entries
        .into_iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(
                    format!("  {k:<14}"),
                    Style::default().fg(ACCENT),
                ),
                Span::raw(v),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod test {
    use super::{detail_lines, render, MATCH};
    use crate::commands::{
        AttachmentMetadata, DecryptedCipher, DecryptedData, DecryptedField,
        DecryptedUri,
    };
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;

    fn press(app: &mut App, code: KeyCode) {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    // Render the current state to an off-screen buffer; panics (layout math,
    // out-of-bounds cursor) would fail the test. Draws at both a wide and a
    // narrow width to exercise the side-by-side and stacked layouts.
    fn draw(app: &App) {
        for (w, h) in [(80u16, 24u16), (48, 30)] {
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|f| render(f, app)).unwrap();
        }
    }

    #[test]
    fn renders_all_modes_without_panicking() {
        use crate::tui::app::{AttachmentItem, AttachmentView, Mode};

        // Empty vault keeps the fixture trivial while still exercising the
        // full chrome, popups, and cursor placement.
        let mut app = App::new(
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
        );
        draw(&app); // opens focused on the live search bar

        press(&mut app, KeyCode::Char('x')); // type into the filter
        draw(&app);
        press(&mut app, KeyCode::Esc); // clear filter, stay in search

        press(&mut app, KeyCode::Tab); // hand off to the list
        press(&mut app, KeyCode::Char('a')); // add form + cursor
        draw(&app);
        press(&mut app, KeyCode::Tab); // next field
        draw(&app);
        press(&mut app, KeyCode::Esc); // close form

        press(&mut app, KeyCode::Char('?')); // help
        draw(&app);
        press(&mut app, KeyCode::Esc); // close help

        // Attachment picker overlay.
        app.mode = Mode::Attachments(AttachmentView {
            items: vec![AttachmentItem {
                id: "att-id".to_string(),
                name: "invoice.pdf".to_string(),
                size: Some("12.3 KB".to_string()),
            }],
            selected: 0,
            pending_delete: false,
        });
        draw(&app);

        // Text prompt overlay (add-account fields).
        app.mode = Mode::Prompt(crate::tui::app::Prompt::add_account());
        draw(&app);

        // Accounts / settings panel overlay.
        app.mode = Mode::Accounts(crate::tui::app::AccountsView {
            accounts: vec![
                crate::commands::TuiAccount {
                    name: "personal".to_string(),
                    email: Some("me@example.com".to_string()),
                    server: "bitwarden.com".to_string(),
                    unlocked: true,
                    primary: true,
                },
                crate::commands::TuiAccount {
                    name: "work".to_string(),
                    email: Some("me@corp.com".to_string()),
                    server: "https://vault.corp.com".to_string(),
                    unlocked: false,
                    primary: false,
                },
            ],
            selected: 0,
        });
        draw(&app);
    }

    #[test]
    fn detail_lines_cover_a_full_login() {
        let cipher = DecryptedCipher {
            id: "id".to_string(),
            folder: Some("Dev".to_string()),
            name: "GitHub".to_string(),
            data: DecryptedData::Login {
                username: Some("octocat".to_string()),
                password: Some("hunter2".to_string()),
                totp: None,
                uris: Some(vec![DecryptedUri {
                    uri: "https://github.com".to_string(),
                    match_type: None,
                }]),
            },
            fields: vec![DecryptedField {
                name: Some("api-token".to_string()),
                value: Some("secret".to_string()),
                ty: Some(rbw::api::FieldType::Hidden),
            }],
            notes: Some("line one\nline two".to_string()),
            history: Vec::new(),
            attachments: Vec::new(),
            attachment_metadata: AttachmentMetadata {
                attachment_count: 0,
            },
            account: None,
        };

        // Masked: the password value must not appear in plain text.
        let masked = detail_lines(&cipher, false, "");
        let masked_text: String = masked
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(masked_text.contains("octocat"));
        assert!(!masked_text.contains("hunter2"));

        // Revealed: the password value is shown.
        let shown = detail_lines(&cipher, true, "");
        let shown_text: String = shown
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(shown_text.contains("hunter2"));
    }

    #[test]
    fn detail_lines_highlight_the_matched_field() {
        let cipher = DecryptedCipher {
            id: "id".to_string(),
            folder: Some("Dev".to_string()),
            name: "GitHub".to_string(),
            data: DecryptedData::Login {
                username: Some("octocat".to_string()),
                password: None,
                totp: None,
                uris: Some(vec![DecryptedUri {
                    uri: "https://github.com".to_string(),
                    match_type: None,
                }]),
            },
            fields: vec![DecryptedField {
                name: Some("scope".to_string()),
                value: Some("repo-admin".to_string()),
                ty: None,
            }],
            notes: Some("rotate this token yearly".to_string()),
            history: Vec::new(),
            attachments: Vec::new(),
            attachment_metadata: AttachmentMetadata {
                attachment_count: 0,
            },
            account: None,
        };

        // A span whose content is exactly `text` and whose style carries the
        // match color — the marker `highlighted_spans` uses for a match.
        let has_highlight = |lines: &[super::Line<'_>], text: &str| {
            lines.iter().flat_map(|l| l.spans.iter()).any(|s| {
                s.content.as_ref() == text && s.style.fg == Some(MATCH)
            })
        };

        assert!(has_highlight(&detail_lines(&cipher, false, "n:git"), "Git"));
        assert!(has_highlight(&detail_lines(&cipher, false, "u:cat"), "cat"));
        assert!(has_highlight(
            &detail_lines(&cipher, false, "uri:github"),
            "github"
        ));
        assert!(has_highlight(&detail_lines(&cipher, false, "f:dev"), "Dev"));
        assert!(has_highlight(
            &detail_lines(&cipher, false, "field:admin"),
            "admin"
        ));
        assert!(has_highlight(
            &detail_lines(&cipher, false, "notes:yearly"),
            "yearly"
        ));

        // A scoped query with no field match highlights nothing.
        assert!(!has_highlight(
            &detail_lines(&cipher, false, "u:git"),
            "Git"
        ));
    }

    #[test]
    fn detail_lines_mark_a_matching_secret_without_revealing_it() {
        let cipher = DecryptedCipher {
            id: "id".to_string(),
            folder: None,
            name: "GitHub".to_string(),
            data: DecryptedData::Login {
                username: None,
                password: Some("correct-horse-battery".to_string()),
                totp: None,
                uris: None,
            },
            fields: vec![],
            notes: None,
            history: Vec::new(),
            attachments: Vec::new(),
            attachment_metadata: AttachmentMetadata {
                attachment_count: 0,
            },
            account: None,
        };

        let text_of = |lines: &[super::Line<'_>]| -> String {
            lines
                .iter()
                .flat_map(|l| l.spans.iter())
                .map(|s| s.content.as_ref())
                .collect()
        };

        // Masked + matching: the mask stays, but a red " *" marker is
        // appended — the actual value is never in the rendered text.
        let masked_match = detail_lines(&cipher, false, "battery");
        let masked_match_text = text_of(&masked_match);
        assert!(!masked_match_text.contains("correct-horse-battery"));
        assert!(masked_match.iter().flat_map(|l| l.spans.iter()).any(|s| {
            s.content.as_ref() == " *" && s.style.fg == Some(MATCH)
        }));

        // Masked, no match: no marker.
        let masked_no_match = detail_lines(&cipher, false, "nope");
        assert!(!masked_no_match
            .iter()
            .flat_map(|l| l.spans.iter())
            .any(|s| s.content.as_ref() == " *"));

        // Revealed + matching: the real value shows, highlighted like any
        // other field, no separate marker needed.
        let revealed = detail_lines(&cipher, true, "battery");
        assert!(text_of(&revealed).contains("correct-horse-battery"));
        assert!(revealed.iter().flat_map(|l| l.spans.iter()).any(|s| {
            s.content.as_ref() == "battery" && s.style.fg == Some(MATCH)
        }));
    }
}
