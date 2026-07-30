// Interactive terminal UI for browsing, searching, and editing the vault.
//
// `run` unlocks the target account on the real terminal first (so pinentry
// works), then brings up a tiny loading screen while loading the remaining
// vault state and updating its footer with progress. Agent round-trips
// (decrypt, save, sync, clipboard) happen synchronously inside the loop; only
// `$EDITOR` needs the real terminal back, so it briefly suspends and restores
// the UI around the editor invocation.

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
use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
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

pub fn run(
    initial_term: Option<&str>,
    all: bool,
    from_file: Option<&std::path::Path>,
    write: bool,
    from_file_passphrase: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = from_file {
        let vault = crate::commands::tui_vault_from_file(
            path,
            write,
            from_file_passphrase,
        )?;
        let mut terminal = ratatui::init();
        enable_mouse();
        let mut app = App::new_from_file(vault, initial_term);
        let res = run_loop(&mut terminal, &mut app);
        disable_mouse();
        ratatui::restore();
        return res;
    }

    crate::commands::tui_unlock_target()?;
    let mut terminal = ratatui::init();
    enable_mouse();
    draw_loading(&mut terminal, "loading vaults...")?;
    let open = crate::commands::tui_open_with_progress(all, true, |msg| {
        let _ = draw_loading(&mut terminal, msg);
    })?;
    let mut app = App::new(open, initial_term);
    let res = run_loop(&mut terminal, &mut app);
    disable_mouse();
    ratatui::restore();
    res
}

fn draw_loading(
    terminal: &mut ratatui::DefaultTerminal,
    status: &str,
) -> anyhow::Result<()> {
    terminal.draw(|f| {
        let [main, _search, footer] = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(f.area());
        let [center] = Layout::vertical([Constraint::Length(1)])
            .flex(Flex::Center)
            .areas(main);

        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "rbw",
                Style::default().fg(Color::Cyan).bold(),
            )))
            .alignment(Alignment::Center),
            center,
        );
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {status}"),
                Style::default().fg(Color::Cyan).bold(),
            ))),
            footer,
        );
    })?;
    Ok(())
}

fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
) -> anyhow::Result<()> {
    loop {
        // Piggyback agent-lock detection on this same ~2Hz tick (throttled
        // internally to every few seconds) rather than adding a second timer.
        app.poll_agent_lock();
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
                    Action::UnlockAndSyncAccount(name) => {
                        unlock_and_sync_account(terminal, app, &name);
                    }
                    Action::SyncAccount(name) => {
                        sync_account(terminal, app, &name)?;
                    }
                    Action::AutoUnlockAndSyncAccount(name) => {
                        auto_unlock_and_sync_account(terminal, app, &name)?;
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
                        Some(ui::Pane::List) => {
                            app.focus_list();
                            if let Some(index) = ui::list_index_at(
                                full,
                                app,
                                mouse.column,
                                mouse.row,
                            ) {
                                app.mouse_select_list(index);
                            }
                        }
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

fn draw_app(
    terminal: &mut ratatui::DefaultTerminal,
    app: &App,
) -> anyhow::Result<()> {
    terminal.draw(|f| ui::render(f, app))?;
    Ok(())
}

// Unlocking an account runs pinentry, which needs the real terminal, so drop
// out of the alternate screen for it (like the editor) and rebuild afterwards.
fn unlock_account(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    name: &str,
) {
    app.set_unlocking_status(name);
    let _ = draw_app(terminal, app);
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

fn unlock_and_sync_account(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    name: &str,
) {
    app.set_unlocking_status(name);
    let _ = draw_app(terminal, app);
    disable_mouse();
    ratatui::restore();
    let unlock_res = app.unlock_account(name);
    *terminal = ratatui::init();
    enable_mouse();
    let _ = terminal.clear();
    match unlock_res {
        Ok(()) => {
            app.set_syncing_status(name);
            let _ = draw_app(terminal, app);
            match app.sync_account(name) {
                Ok(()) => app.set_synced_status(name),
                Err(e) if App::is_session_expired_error(&e) => {
                    app.show_session_expired(name.to_string());
                }
                Err(e) => app.set_error(format!("{e:#}")),
            }
        }
        Err(e) => app.set_error(format!("{e:#}")),
    }
}

fn sync_account(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    name: &str,
) -> anyhow::Result<()> {
    app.set_syncing_status(name);
    draw_app(terminal, app)?;
    match app.sync_account(name) {
        Ok(()) => app.set_synced_status(name),
        Err(e) if App::is_session_expired_error(&e) => {
            app.show_session_expired(name.to_string());
        }
        Err(e) => app.set_error(format!("{e:#}")),
    }
    Ok(())
}

fn auto_unlock_and_sync_account(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    name: &str,
) -> anyhow::Result<()> {
    app.set_unlocking_status(name);
    draw_app(terminal, app)?;
    match app.unlock_account(name) {
        Ok(()) => {
            app.set_syncing_status(name);
            draw_app(terminal, app)?;
            match app.sync_account(name) {
                Ok(()) => app.set_synced_status(name),
                Err(e) if App::is_session_expired_error(&e) => {
                    app.show_session_expired(name.to_string());
                }
                Err(e) => app.set_error(format!("{e:#}")),
            }
        }
        Err(e) => app.set_error(format!("{e:#}")),
    }
    Ok(())
}
