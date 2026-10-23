use super::*;

// What `rbw show --mask` prints instead of a secret value.
pub(super) const MASKED_SECRET: &str = "••••••••";

// serde's `skip_serializing_if` requires a `fn(&T) -> bool`.
#[allow(clippy::trivially_copy_pass_by_ref)]
pub(super) fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
pub(super) fn is_false(value: &bool) -> bool {
    !*value
}

pub(super) fn stdout_supports_color() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && (stdout_is_terminal() || color_forced())
}

// `CLICOLOR_FORCE` (any value but "0") colours output that isn't going to a
// terminal, e.g. `rbw show` rendered into the `--fzf` preview pane.
// `NO_COLOR` still wins.
pub(super) fn color_forced() -> bool {
    std::env::var_os("CLICOLOR_FORCE")
        .is_some_and(|v| !v.is_empty() && v != "0")
}

pub(super) fn stdout_is_terminal() -> bool {
    std::io::stdout().is_terminal()
}

pub(super) fn stderr_supports_color() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && (std::io::stderr().is_terminal() || color_forced())
}

// Prints a line to stderr above `pb`. Unlike `ProgressBar::println`, which is
// a no-op on a hidden bar, this still prints when `item_progress_bar` hid
// the bar because stderr isn't a terminal -- per-item results and errors
// must reach scripts and logs too.
pub(super) fn pb_println(pb: &indicatif::ProgressBar, msg: impl AsRef<str>) {
    pb.suspend(|| eprintln!("{}", msg.as_ref()));
}

// A `{position}/{len} items` progress bar on stderr for long per-item loops
// (bulk import/mirror creates, collection purges). Renders nothing (every
// method becomes a no-op) when stderr isn't a terminal, so piped/logged
// output stays exactly as before -- no half-drawn bar frames in a log file.
#[allow(clippy::literal_string_with_formatting_args)]
pub(super) fn item_progress_bar(len: u64) -> indicatif::ProgressBar {
    if !std::io::stderr().is_terminal() {
        return indicatif::ProgressBar::hidden();
    }
    let pb = indicatif::ProgressBar::new(len);
    pb.set_draw_target(indicatif::ProgressDrawTarget::stderr());
    if let Ok(style) = indicatif::ProgressStyle::with_template(
        "{spinner} {msg} [{bar:30}] {pos:>5}/{len:5} items",
    ) {
        pb.set_style(style.progress_chars("=> "));
    }
    // Without this, indicatif only redraws when `inc`/`set_message` are
    // called -- once per item, i.e. once per network round-trip -- so the
    // spinner visibly stutters instead of animating. A steady background
    // tick decouples the redraw rate from the actual work rate.
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

// The fixed display width `item_progress_bar`'s `{msg}` is held to (via
// `fit_to_width` below) -- otherwise everything after it (the bar, the
// counter) visibly shifts left/right as different items' names scroll
// through at different lengths.
pub(super) const PROGRESS_MSG_WIDTH: usize = 40;

// Truncates (with a trailing "...") or space-pads `text` to exactly `width`
// display columns, measuring with `unicode_width` so multi-byte/wide
// characters don't throw off a fixed-width single-line progress message.
pub(super) fn fit_to_width(text: &str, width: usize) -> String {
    let text_width = unicode_width::UnicodeWidthStr::width(text);
    if text_width <= width {
        return format!("{text}{}", " ".repeat(width - text_width));
    }

    let mut out = String::new();
    let mut out_width = 0;
    for ch in text.chars() {
        let ch_width =
            unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if out_width + ch_width > width.saturating_sub(3) {
            break;
        }
        out.push(ch);
        out_width += ch_width;
    }
    out.push_str("...");
    out_width += 3;
    out.push_str(&" ".repeat(width.saturating_sub(out_width)));
    out
}

// Ask for confirmation before a destructive operation. Only prompts when
// stdin is a tty, so scripts and pipelines keep the historical no-prompt
// behavior; interactive callers can skip the prompt with `-y`/`--yes`.
// Returns false (after printing "Aborted.") when the user declines.
pub(super) fn confirm(prompt: &str) -> anyhow::Result<bool> {
    use std::io::Write as _;

    if !std::io::stdin().is_terminal() {
        return Ok(true);
    }

    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("failed to read confirmation")?;
    if matches!(answer.trim(), "y" | "Y") {
        Ok(true)
    } else {
        eprintln!("Aborted.");
        Ok(false)
    }
}

// Central style palette.  Every coloured output in rbw goes through
// these functions so that each semantic type always looks the same
// regardless of which command produced it.
pub(super) mod style {
    fn paint(text: &str, code: &str, color: bool) -> String {
        if color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    // Semantic roles → ANSI style
    // uid     dim cyan       — long, secondary, but distinctive
    pub fn uid(s: &str, c: bool) -> String {
        paint(s, "2;36", c)
    }
    // name    bold           — most prominent field
    pub fn name(s: &str, c: bool) -> String {
        paint(s, "1", c)
    }
    // user    green          — "who" (accounts)
    pub fn user(s: &str, c: bool) -> String {
        paint(s, "32", c)
    }
    // secret  yellow         — sensitive / caution
    pub fn secret(s: &str, c: bool) -> String {
        paint(s, "33", c)
    }
    // folder  blue           — organisation / location
    pub fn folder(s: &str, c: bool) -> String {
        paint(s, "34", c)
    }
    // uri     cyan           — links / references
    pub fn uri(s: &str, c: bool) -> String {
        paint(s, "36", c)
    }
    // entry_type  magenta    — category label
    pub fn entry_type(s: &str, c: bool) -> String {
        paint(s, "35", c)
    }
    // label   bold cyan      — field-name label in aligned display
    pub fn label(s: &str, c: bool) -> String {
        paint(s, "1;36", c)
    }
    // section bold white     — section headers (FIELDS / NOTES / …)
    pub fn section(s: &str, c: bool) -> String {
        paint(s, "1", c)
    }
    // dim     dim            — secondary / decorative text
    pub fn dim(s: &str, c: bool) -> String {
        paint(s, "2", c)
    }
    // empty   dim italic     — "none" / "N/A" placeholder values
    pub fn empty(s: &str, c: bool) -> String {
        paint(s, "2;3", c)
    }
    // success bold green     — action verbs ("Created", "Attached", …)
    pub fn success(s: &str, c: bool) -> String {
        paint(s, "1;32", c)
    }
    // old_val dim red        — value about to be replaced
    pub fn old_val(s: &str, c: bool) -> String {
        paint(s, "2;31", c)
    }
    // new_val green          — replacement / updated value
    pub fn new_val(s: &str, c: bool) -> String {
        paint(s, "32", c)
    }
    // warning bold yellow    — warnings / notices
    pub fn warning(s: &str, c: bool) -> String {
        paint(s, "1;33", c)
    }
    // danger  bold red       — locked / blocked / failed states
    pub fn danger(s: &str, c: bool) -> String {
        paint(s, "1;31", c)
    }
    // size    dim            — file sizes (same weight as dim)
    pub fn size(s: &str, c: bool) -> String {
        paint(s, "2", c)
    }
    // header  bold white     — table column headers
    pub fn header(s: &str, c: bool) -> String {
        paint(s, "1;37", c)
    }
    // raw escape for the rare case where a specific code is needed
    pub fn paint_raw(s: &str, code: &str, c: bool) -> String {
        paint(s, code, c)
    }

    // Like `paint`, but the byte ranges in `ranges` (e.g. from
    // `highlight_ranges`) are painted bold red — grep's own default match
    // color — instead of `code`, which still applies to the rest of the
    // text. `code` may be empty for a column with no color of its own.
    pub fn paint_with_matches(
        text: &str,
        code: &str,
        ranges: &[(usize, usize)],
        c: bool,
    ) -> String {
        if !c || ranges.is_empty() {
            return if code.is_empty() {
                text.to_string()
            } else {
                paint(text, code, c)
            };
        }
        let based = |s: &str| {
            if code.is_empty() {
                s.to_string()
            } else {
                paint(s, code, true)
            }
        };
        let mut out = String::new();
        let mut pos = 0;
        for &(s, e) in ranges {
            if s > pos {
                out.push_str(&based(&text[pos..s]));
            }
            out.push_str(&paint(&text[s..e], "1;31", true));
            pos = e;
        }
        if pos < text.len() {
            out.push_str(&based(&text[pos..]));
        }
        out
    }
}

pub(super) fn write_yaml_pretty<T>(
    value: &T,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    let context = context.into();
    serde_yaml::to_writer(std::io::stdout(), value).context(context)?;
    println!();

    Ok(())
}

pub(super) fn write_json_pretty<T>(
    value: &T,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    let context = context.into();
    if stdout_supports_color() {
        let value = serde_json::to_value(value).context(context.clone())?;
        let rendered = colored_json::to_colored_json_auto(&value)
            .map_err(|err| anyhow::anyhow!(err.to_string()))
            .context(context)?;
        println!("{rendered}");
    } else {
        serde_json::to_writer_pretty(std::io::stdout(), value)
            .context(context)?;
        println!();
    }

    Ok(())
}

pub(super) fn attachment_rows(
    attachments: &[DecryptedAttachment],
    color: bool,
) -> Vec<String> {
    attachments
        .iter()
        .map(|attachment| {
            format!(
                "{}\t{}\t{}",
                style::uid(&attachment.id, color),
                style::name(
                    &attachment.file_name.clone().unwrap_or_default(),
                    color,
                ),
                style::size(
                    &attachment
                        .size_name
                        .clone()
                        .or_else(|| attachment.size.clone())
                        .unwrap_or_default(),
                    color,
                )
            )
        })
        .collect()
}

pub(super) fn attachments_cell(attachment_count: usize) -> String {
    if attachment_count == 0 {
        "none".to_string()
    } else if attachment_count == 1 {
        "📎".to_string()
    } else {
        format!("📎 x{attachment_count}")
    }
}

pub(super) fn output_is_structured(output: OutputMode) -> bool {
    matches!(output, OutputMode::Json | OutputMode::Yaml)
}

pub(super) fn write_serialized_pretty<T>(
    value: &T,
    output: OutputMode,
    context: impl Into<String>,
) -> anyhow::Result<()>
where
    T: serde::Serialize,
{
    match output {
        OutputMode::Json => write_json_pretty(value, context),
        OutputMode::Yaml => write_yaml_pretty(value, context),
        OutputMode::Default | OutputMode::Name => {
            Err(anyhow::anyhow!("unsupported serialized output mode"))
        }
    }
}

pub(super) fn format_ambiguous_entry(
    entry: &DecryptedSearchCipher,
    c: bool,
) -> String {
    let mut details = vec![format!("uid: {}", style::uid(&entry.id, c))];
    if let Some(user) = &entry.user {
        details.push(format!("username: {}", style::user(user, c)));
    }
    if let Some(folder) = &entry.folder {
        details.push(format!("folder: {}", style::folder(folder, c)));
    }
    if entry.attachment_count > 0 {
        details.push(format!("attachments: {}", entry.attachment_count));
    }

    format!(
        "  - {} ({})",
        style::name(&entry.name, c),
        details.join(" | ")
    )
}

// The `SearchField` a table column's cells should be matched against for
// grep-style highlighting, or `None` for a column search doesn't reason
// about at all (id, password, type, …). The `uri` column is the only one
// rendered with `TableColumnStyle::Default` today.
pub(super) fn search_field_for_column(
    style: TableColumnStyle,
) -> Option<SearchField> {
    match style {
        TableColumnStyle::Name => Some(SearchField::Name),
        TableColumnStyle::User => Some(SearchField::User),
        TableColumnStyle::Folder => Some(SearchField::Folder),
        TableColumnStyle::Default => Some(SearchField::Uri),
        _ => None,
    }
}

pub(super) fn colorize_table_cell(
    text: &str,
    col_style: TableColumnStyle,
    color: bool,
    ranges: &[(usize, usize)],
) -> String {
    if text.is_empty() {
        return String::new();
    }

    if (col_style == TableColumnStyle::User && text == "N/A")
        || (col_style == TableColumnStyle::Attachments && text == "none")
    {
        return style::empty(text, color);
    }

    if col_style == TableColumnStyle::Status {
        return if text == "unlocked" {
            style::success(text, color)
        } else {
            style::danger(text, color)
        };
    }

    // The primary-account marker (`rbw account list`): bold yellow star,
    // distinct from the name's own bold-only styling.
    if col_style == TableColumnStyle::Name {
        if let Some(rest) = text.strip_suffix('*') {
            let mut out = style::name(rest, color);
            out.push_str(&style::warning("*", color));
            return out;
        }
    }

    let code = match col_style {
        TableColumnStyle::Id => "2;36",
        TableColumnStyle::Name => "1",
        TableColumnStyle::User => "32",
        TableColumnStyle::Password => "33",
        TableColumnStyle::Folder => "34",
        TableColumnStyle::EntryType => "35",
        TableColumnStyle::Collections
        | TableColumnStyle::Size
        | TableColumnStyle::Account => "2",
        TableColumnStyle::Attachments => "36",
        TableColumnStyle::Status | TableColumnStyle::Default => "",
    };
    style::paint_with_matches(text, code, ranges, color)
}

pub(super) fn table_cell_width(text: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(text)
}

pub(super) fn compute_table_widths(
    columns: &[TableColumn<'_>],
    rows: &[Vec<String>],
) -> Vec<usize> {
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let header_width =
                table_cell_width(&column.header.to_uppercase());
            let row_width = rows
                .iter()
                .filter_map(|row| row.get(index))
                .map(|cell| table_cell_width(cell))
                .max()
                .unwrap_or(0);
            header_width.max(row_width)
        })
        .collect()
}

pub(super) fn render_table_row<F>(
    cells: &[String],
    widths: &[usize],
    mut render_cell: F,
) -> String
where
    F: FnMut(usize, &str) -> String,
{
    let last_index = cells.len().saturating_sub(1);
    let mut rendered = String::new();

    for (index, cell) in cells.iter().enumerate() {
        rendered.push_str(&render_cell(index, cell));

        if index != last_index {
            let padding =
                widths[index].saturating_sub(table_cell_width(cell));
            rendered.push_str(&" ".repeat(padding + 2));
        }
    }

    rendered
}

// `term` is the search/filter query behind these rows, if any (empty for a
// plain `rbw list`) — matched substrings are painted grep-style (bold red)
// within a cell's usual color, same match logic as `search_match`.
pub(super) fn print_table(
    columns: &[TableColumn<'_>],
    rows: &[Vec<String>],
    term: &str,
) -> anyhow::Result<()> {
    if stdout_is_terminal() {
        let widths = compute_table_widths(columns, rows);
        let header_cells = columns
            .iter()
            .map(|column| column.header.to_uppercase())
            .collect::<Vec<_>>();
        let header = render_table_row(&header_cells, &widths, |_, cell| {
            style::header(cell, stdout_supports_color())
        });
        println!("{header}");
        for row in rows {
            let rendered = render_table_row(row, &widths, |index, cell| {
                columns.get(index).map_or_else(String::new, |column| {
                    let ranges = search_field_for_column(column.style)
                        .map(|field| highlight_ranges(term, field, cell))
                        .unwrap_or_default();
                    colorize_table_cell(
                        cell,
                        column.style,
                        stdout_supports_color(),
                        &ranges,
                    )
                })
            });
            println!("{rendered}");
        }
    } else {
        for row in rows {
            match writeln!(&mut std::io::stdout(), "{}", row.join("\t")) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    return Ok(());
                }
                res => res?,
            }
        }
    }

    Ok(())
}

pub(super) fn available_attachments_error(
    entry_name: &str,
    attachments: &[DecryptedAttachment],
    reason: &str,
) -> anyhow::Error {
    if attachments.is_empty() {
        return anyhow::anyhow!(
            "{reason}\nNo attachments are available for '{entry_name}'."
        );
    }

    let mut message = String::new();
    let _ = writeln!(&mut message, "{reason}");
    let _ =
        writeln!(&mut message, "Available attachments for '{entry_name}':");
    for row in attachment_rows(attachments, false) {
        let _ = writeln!(&mut message, "{row}");
    }
    let _ = write!(
        &mut message,
        "Use `rbw attachment get <entry> --attachment <id-or-filename>` to download one."
    );
    anyhow::anyhow!(message)
}

pub(super) fn val_display_or_store(clipboard: bool, password: &str) -> bool {
    if clipboard {
        match clipboard_store(password) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        }
    } else {
        println!("{password}");
        true
    }
}
