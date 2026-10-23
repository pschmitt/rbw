use super::{Action, Frontend, SecretInput, View};
use anyhow::Context as _;
use gtk::prelude::*;
use gtk4 as gtk;
use std::cell::Cell;
use std::ffi::CStr;
use std::rc::Rc;

pub(super) struct GtkDialog {
    window: gtk::Window,
    entry: gtk::PasswordEntry,
    title: gtk::Label,
    status: gtk::Label,
    error: gtk::Label,
    button: gtk::Button,
    button_label: gtk::Label,
    button_icon: gtk::Image,
    spinner: gtk::Spinner,
    cancel_button: gtk::Button,
    busy: bool,
    logo: gtk::DrawingArea,
    animation: Rc<Cell<LogoAnimation>>,
    submit: Rc<Cell<bool>>,
    cancel: Rc<Cell<bool>>,
    issue: Option<&'static str>,
}

#[derive(Clone, Copy, Default)]
struct LogoAnimation {
    tick: u64,
    success: bool,
    active: bool,
}

// The same dotted crab the terminal dialog draws, one dot per cell.
const CRAB: [&str; 20] = [
    "........................................................",
    "....#..#..#......................................#..#..#......",
    "..#..#..#..#....#..............................#....#..#..#..#....",
    "..#..#..#..#..#..#..............................#..#..#..#..#..#....",
    "..#..#..#..#..#..#..............................#..#..#..#..#..#....",
    "..#..#..#..#..#..#..............................#..#..#..#..#..#....",
    "....#..#..#..#..........#..#..#..#..#..#..#..#..........#..#..#..#......",
    "........#..#....#..#..#..#..#..#..#..#..#..#..#..#..#..#....#..#..........",
    "..........#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#............",
    "..........#..#..#..#..#....#..#..#..#..#..#....#..#..#..#..#............",
    "..........#..#..#..#........#..#..#..#........#..#..#..#............",
    "........#..#..#..#..#..#....#..#..#..#..#..#....#..#..#..#..#..#..........",
    "..........#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#............",
    "..........#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#............",
    "............#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..............",
    "......#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..#..........",
    "........#..#..#..#......#..#..#..#..#..#..#..#....#..#..#..#............",
    "......#....#..#............................#..#....#..........",
    "........#....................................#............",
    "......#........................................#..........",
];

fn logo(animation: Rc<Cell<LogoAnimation>>) -> gtk::DrawingArea {
    let icon = gtk::DrawingArea::builder()
        .content_width(112)
        .content_height(80)
        .valign(gtk::Align::Center)
        .build();
    let animate = gtk::Settings::default().is_none_or(|settings| {
        settings.property::<bool>("gtk-enable-animations")
    });
    icon.set_draw_func(move |_, context, width, height| {
        let animation = animation.get();
        let pitch = f64::from(width) / 28.0;
        let top = (f64::from(height) - pitch * 20.0) / 2.0;
        let time =
            f64::from(u32::try_from(animation.tick % 1000).unwrap_or(0));
        for (y, row) in (0_u32..).zip(CRAB) {
            let pending = animation.success
                && animate
                && u64::from(y) > animation.tick / 2;
            for (x, cell) in (0_u32..).zip(row.bytes()) {
                if cell != b'#' {
                    continue;
                }
                let (fx, fy) = (f64::from(x), f64::from(y));
                if animation.success && !pending {
                    context.set_source_rgb(0.18, 0.76, 0.49);
                } else if animation.active && animate {
                    let phase = (time / 8.0 + (fx + fy) / 6.0).sin().abs();
                    context.set_source_rgba(
                        0.61,
                        0.45,
                        0.90,
                        0.35_f64.mul_add(phase, 0.65),
                    );
                } else {
                    context.set_source_rgb(0.61, 0.45, 0.90);
                }
                context.arc(
                    (fx + 0.5) * pitch,
                    (fy + 0.5).mul_add(pitch, top),
                    pitch * 0.36,
                    0.0,
                    std::f64::consts::TAU,
                );
                let _ = context.fill();
            }
        }
    });
    icon
}

impl GtkDialog {
    pub fn new(no_echo: bool) -> anyhow::Result<Self> {
        gtk::init().context("could not open GTK unlock window")?;
        let application = gtk::Application::builder()
            .application_id("org.rbw.Unlock")
            .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
            .build();
        application
            .register(None::<&gtk::gio::Cancellable>)
            .context("could not register the unlock dialog")?;
        let window = gtk::Window::builder()
            .application(&application)
            .modal(true)
            .resizable(false)
            .title("Unlock rbw")
            .default_width(540)
            .build();
        window.set_icon_name(Some("rbw"));
        // Standard GNOME dialog layout: Cancel and the suggested action live
        // in the header bar; the body follows the system light/dark theme.
        let header = gtk::HeaderBar::new();
        header.set_show_title_buttons(false);
        let title = gtk::Label::new(None);
        title.add_css_class("title");
        header.set_title_widget(Some(&title));
        let cancel_button = gtk::Button::with_label("Cancel");
        header.pack_start(&cancel_button);
        let button = gtk::Button::new();
        button.add_css_class("suggested-action");
        let button_content = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        let button_icon =
            gtk::Image::from_icon_name("changes-allow-symbolic");
        let button_label = gtk::Label::new(Some("Unlock"));
        let spinner = gtk::Spinner::new();
        spinner.set_visible(false);
        button_content.append(&spinner);
        button_content.append(&button_icon);
        button_content.append(&button_label);
        button.set_child(Some(&button_content));
        header.pack_end(&button);
        window.set_titlebar(Some(&header));
        let animation = Rc::new(Cell::new(LogoAnimation::default()));
        let logo = logo(animation.clone());
        // GtkPasswordEntry uses GtkPasswordEntryBuffer, backed by GTK's secure
        // allocator. No reveal button, undo history, or app clipboard actions.
        let entry = gtk::PasswordEntry::builder()
            .placeholder_text("Master password")
            .show_peek_icon(false)
            .hexpand(true)
            .build();
        entry.set_enable_undo(false);
        if no_echo {
            let text = entry
                .delegate()
                .and_then(|delegate| delegate.downcast::<gtk::Text>().ok())
                .context(
                    "GTK password input does not support no-echo mode",
                )?;
            text.set_invisible_char('\0');
        }
        let status = gtk::Label::new(None);
        status.add_css_class("dim-label");
        status.add_css_class("caption");
        status.set_wrap(true);
        status.set_xalign(0.0);
        let error = gtk::Label::new(None);
        error.add_css_class("error");
        error.add_css_class("caption");
        error.set_wrap(true);
        error.set_xalign(0.0);
        let form = gtk::Box::new(gtk::Orientation::Vertical, 8);
        form.set_valign(gtk::Align::Center);
        form.set_hexpand(true);
        form.append(&entry);
        form.append(&status);
        form.append(&error);
        let body = gtk::Box::new(gtk::Orientation::Horizontal, 24);
        body.set_margin_top(24);
        body.set_margin_bottom(24);
        body.set_margin_start(24);
        body.set_margin_end(24);
        body.append(&logo);
        body.append(&form);
        window.set_child(Some(&body));
        let submit = Rc::new(Cell::new(false));
        let cancel = Rc::new(Cell::new(false));
        let signal = submit.clone();
        entry.connect_activate(move |_| signal.set(true));
        let signal = submit.clone();
        button.connect_clicked(move |_| signal.set(true));
        let signal = cancel.clone();
        cancel_button.connect_clicked(move |_| signal.set(true));
        let signal = cancel.clone();
        window.connect_close_request(move |_| {
            signal.set(true);
            gtk::glib::Propagation::Stop
        });
        let keys = gtk::EventControllerKey::new();
        let signal = cancel.clone();
        keys.connect_key_pressed(move |_, key, _, modifiers| {
            if key == gtk::gdk::Key::Escape
                || (key == gtk::gdk::Key::c
                    && modifiers
                        .contains(gtk::gdk::ModifierType::CONTROL_MASK))
            {
                signal.set(true);
                gtk::glib::Propagation::Stop
            } else {
                gtk::glib::Propagation::Proceed
            }
        });
        window.add_controller(keys);
        window.present();
        entry.grab_focus();
        Ok(Self {
            window,
            entry,
            title,
            status,
            error,
            button,
            button_label,
            button_icon,
            spinner,
            cancel_button,
            busy: false,
            logo,
            animation,
            submit,
            cancel,
            issue: None,
        })
    }
}

impl Frontend for GtkDialog {
    fn poll(&mut self) -> anyhow::Result<Option<Action>> {
        let context = gtk::glib::MainContext::default();
        for _ in 0..32 {
            if !context.pending() {
                break;
            }
            context.iteration(false);
        }
        if self.cancel.get() {
            return Ok(Some(Action::Cancel));
        }
        if self.submit.replace(false) && !self.busy {
            let mut input = SecretInput::new()?;
            // SAFETY: GTK is initialized and this entry stays alive on this
            // thread. GTK owns the NUL-terminated buffer; borrow it only long
            // enough to copy directly into locked memory, never a Rust String.
            let bytes = unsafe {
                let pointer = gtk::ffi::gtk_editable_get_text(
                    self.entry.as_ptr().cast(),
                );
                CStr::from_ptr(pointer).to_bytes()
            };
            let too_long = bytes.len() > crate::locked::CAPACITY;
            if !too_long {
                for byte in bytes {
                    input.push(*byte);
                }
            }
            self.entry.set_text("");
            if too_long {
                self.issue = Some("Password is too long. Please try again.");
            } else if !input.is_empty() {
                self.issue = None;
                self.busy = true;
                self.entry.set_sensitive(false);
                self.button.set_sensitive(false);
                return Ok(Some(Action::Submit(input.take()?)));
            }
        }
        Ok(None)
    }
    fn render(&mut self, view: &View<'_>) -> anyhow::Result<()> {
        self.title.set_label(view.title);
        self.animation.set(LogoAnimation {
            tick: view.tick,
            success: view.success,
            active: !matches!(
                view.fingerprint,
                super::FingerprintStatus::Disabled
                    | super::FingerprintStatus::Unavailable
            ),
        });
        self.logo.queue_draw();
        self.status.set_label(if view.success {
            "✓ Unlocked"
        } else {
            view.fingerprint.text()
        });
        if view.success {
            self.status.remove_css_class("dim-label");
            self.status.add_css_class("success");
            self.button.remove_css_class("suggested-action");
        }
        self.busy = view.checking || view.success;
        self.button_label.set_label(if view.success {
            "Unlocked"
        } else if view.checking {
            "Checking…"
        } else {
            "Unlock"
        });
        self.spinner.set_visible(view.checking);
        if view.checking {
            self.spinner.start();
        } else {
            self.spinner.stop();
        }
        self.button_icon.set_visible(!view.checking);
        self.button_icon.set_icon_name(Some(if view.success {
            "object-select-symbolic"
        } else {
            "changes-allow-symbolic"
        }));
        self.cancel_button.set_sensitive(!view.success);
        self.error.set_label(self.issue.or(view.error).unwrap_or(
            if view.checking {
                "Checking password…"
            } else {
                ""
            },
        ));
        self.entry.set_sensitive(!self.busy);
        self.button.set_sensitive(!self.busy);
        Ok(())
    }
    fn clear_secret(&mut self) {
        self.entry.set_text("");
        self.issue = None;
    }
}

impl Drop for GtkDialog {
    fn drop(&mut self) {
        self.entry.set_text("");
        self.window.destroy();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a real desktop display"]
    fn live_gtk_password_and_cancel() {
        for no_echo in [false, true] {
            let mut dialog = GtkDialog::new(no_echo).unwrap();
            dialog
                .render(&View {
                    title: "Disposable UI test",
                    fingerprint: super::super::FingerprintStatus::Ready,
                    checking: false,
                    success: false,
                    error: None,
                    tick: 0,
                })
                .unwrap();
            if no_echo {
                let text = dialog
                    .entry
                    .delegate()
                    .unwrap()
                    .downcast::<gtk::Text>()
                    .unwrap();
                assert_eq!(text.invisible_char(), '\0');
            }
            dialog.entry.set_text("disposable UI test input");
            dialog.button.emit_clicked();
            let Some(Action::Submit(password)) = dialog.poll().unwrap()
            else {
                panic!("expected password submission")
            };
            assert_eq!(password.password(), b"disposable UI test input");
            // Only inspect empty widget text after extraction, never a live secret.
            assert!(dialog.entry.text().is_empty());
            dialog.cancel.set(true);
            assert!(matches!(dialog.poll().unwrap(), Some(Action::Cancel)));
        }
    }
}
