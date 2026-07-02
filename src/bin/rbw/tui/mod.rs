// Interactive terminal UI for browsing, searching, and editing the vault.
//
// `run` unlocks the vault and loads the search index *before* taking over the
// screen (so pinentry works on the real terminal), then drives a draw/read
// loop. Agent round-trips (decrypt, save, sync, clipboard) happen synchronously
// inside the loop; only `$EDITOR` needs the real terminal back, so it briefly
// suspends and restores the UI around the editor invocation.

mod app;
mod input;
mod keymap;
mod ui;

use std::time::Duration;

use ratatui::crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind,
        MouseButton, MouseEventKind,
    },
    execute,
};

use app::{Action, App};

// A ~2 Hz tick keeps the live TOTP code and its countdown fresh without needing
// a keypress.
const TICK: Duration = Duration::from_millis(500);

// Mouse capture is opt-in on top of `ratatui::init`/`restore`, and doesn't
// survive a re-init (e.g. dropping out to $EDITOR), so every init/restore
// pair below is bracketed with these.
fn enable_mouse() {
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
}

fn disable_mouse() {
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
}

pub fn run(initial_term: Option<&str>, all: bool) -> anyhow::Result<()> {
    let open = crate::commands::tui_open(all)?;
    let mut app = App::new(open, initial_term);

    let mut terminal = ratatui::init();
    enable_mouse();
    let res = run_loop(&mut terminal, &mut app);
    disable_mouse();
    ratatui::restore();
    res
}

fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|f| ui::render(f, app))?;

        if !event::poll(TICK)? {
            continue;
        }

        match event::read()? {
            Event::Key(key) => {
                // Ignore key-release/repeat noise from enhanced keyboard
                // protocols; act only on presses.
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match app.handle_key(key) {
                    Action::None => {}
                    Action::Quit => return Ok(()),
                    Action::OpenEditor => open_editor(terminal, app),
                    Action::UnlockAccount(name) => {
                        unlock_account(terminal, app, &name);
                    }
                }
            }
            Event::Mouse(mouse) => {
                let size = terminal.size()?;
                let full =
                    ratatui::layout::Rect::new(0, 0, size.width, size.height);
                let pane = ui::pane_at(full, mouse.column, mouse.row);
                match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) => match pane {
                        Some(ui::Pane::Detail) => app.focus_detail(),
                        Some(ui::Pane::List) => app.focus_list(),
                        None => {}
                    },
                    MouseEventKind::ScrollDown => match pane {
                        Some(ui::Pane::Detail) => {
                            app.mouse_scroll_detail(1);
                        }
                        Some(ui::Pane::List) | None => {
                            app.mouse_scroll_list(1);
                        }
                    },
                    MouseEventKind::ScrollUp => match pane {
                        Some(ui::Pane::Detail) => {
                            app.mouse_scroll_detail(-1);
                        }
                        Some(ui::Pane::List) | None => {
                            app.mouse_scroll_list(-1);
                        }
                    },
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

// Drop out of the alternate screen, run the entry through `$EDITOR`, then
// rebuild the UI. Any failure is surfaced in the status line rather than
// aborting the session.
fn open_editor(terminal: &mut ratatui::DefaultTerminal, app: &mut App) {
    disable_mouse();
    ratatui::restore();
    if let Err(e) = app.edit_in_editor() {
        app.set_error(format!("{e:#}"));
    }
    *terminal = ratatui::init();
    enable_mouse();
    let _ = terminal.clear();
}

// Unlocking an account runs pinentry, which needs the real terminal, so drop
// out of the alternate screen for it (like the editor) and rebuild afterwards.
fn unlock_account(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    name: &str,
) {
    disable_mouse();
    ratatui::restore();
    let res = app.unlock_account(name);
    *terminal = ratatui::init();
    enable_mouse();
    let _ = terminal.clear();
    match res {
        Ok(()) => app.set_unlocked_status(name),
        Err(e) => app.set_error(format!("{e:#}")),
    }
}
