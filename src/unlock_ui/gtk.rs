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
    fingerprint_icon: gtk::DrawingArea,
    animation: Rc<Cell<FingerprintAnimation>>,
    submit: Rc<Cell<bool>>,
    cancel: Rc<Cell<bool>>,
    issue: Option<&'static str>,
}

#[derive(Clone, Copy, Default)]
struct FingerprintAnimation {
    tick: u64,
    success: bool,
    active: bool,
}

fn fingerprint_icon(
    animation: Rc<Cell<FingerprintAnimation>>,
) -> gtk::DrawingArea {
    let icon = gtk::DrawingArea::builder()
        .content_width(64)
        .content_height(64)
        .build();
    let animate = gtk::Settings::default().is_none_or(|settings| {
        settings.property::<bool>("gtk-enable-animations")
    });
    icon.set_draw_func(move |_, context, width, height| {
        let animation = animation.get();
        let scale = f64::from(width.min(height)) / 64.0;
        context.scale(scale, scale);
        if animation.success {
            context.set_source_rgb(0.53, 0.94, 0.67);
        } else {
            context.set_source_rgb(0.44, 0.86, 0.90);
        }
        context.set_line_width(2.5);
        context.set_line_cap(gtk::cairo::LineCap::Round);
        for (start, controls) in [
            ((7.0, 29.0), [10.0, 1.0, 54.0, 1.0, 57.0, 29.0]),
            ((7.0, 37.0), [7.0, 18.0, 17.0, 13.0, 28.0, 12.0]),
            ((36.0, 12.0), [55.0, 13.0, 57.0, 33.0, 53.0, 45.0]),
            ((14.0, 44.0), [5.0, 10.0, 51.0, 8.0, 49.0, 34.0]),
            ((21.0, 49.0), [9.0, 20.0, 40.0, 11.0, 43.0, 30.0]),
            ((31.0, 56.0), [16.0, 40.0, 19.0, 24.0, 29.0, 24.0]),
            ((35.0, 26.0), [43.0, 32.0, 31.0, 42.0, 46.0, 52.0]),
            ((29.0, 32.0), [26.0, 42.0, 32.0, 49.0, 38.0, 55.0]),
        ] {
            context.move_to(start.0, start.1);
            context.curve_to(
                controls[0],
                controls[1],
                controls[2],
                controls[3],
                controls[4],
                controls[5],
            );
            let _ = context.stroke();
        }
        if animation.success {
            let progress = if animate {
                f64::from(u32::try_from(animation.tick.min(20)).unwrap_or(20))
                    / 20.0
            } else {
                1.0
            };
            context.set_line_width(2.0);
            context.arc(
                32.0,
                32.0,
                30.0,
                -std::f64::consts::FRAC_PI_2,
                std::f64::consts::TAU
                    .mul_add(progress, -std::f64::consts::FRAC_PI_2),
            );
            let _ = context.stroke();
        } else if animate && animation.active {
            let y =
                f64::from(u32::try_from(animation.tick % 90).unwrap_or(0))
                    .mul_add(0.6, 5.0);
            context.set_source_rgba(0.71, 0.60, 1.0, 0.8);
            context.set_line_width(1.5);
            context.move_to(6.0, y);
            context.line_to(58.0, y);
            let _ = context.stroke();
        }
    });
    icon
}

impl GtkDialog {
    pub fn new(no_echo: bool) -> anyhow::Result<Self> {
        gtk::init().context("could not open GTK unlock window")?;
        let provider = gtk::CssProvider::new();
        provider.load_from_data(r"
            window.rbw-unlock { background: #0d111b; color: #e8eef9; }
            .rbw-card { background: #151b2a; border: 1px solid #2d394f; border-radius: 24px; padding: 34px; margin: 24px; }
            .rbw-brand { color: #b59aff; font-weight: 800; letter-spacing: 3px; font-size: 12px; }
            .rbw-title { font-size: 30px; font-weight: 800; margin-top: 12px; }
            .rbw-subtitle { color: #95a3bb; font-size: 14px; }
            .rbw-status { color: #71dce5; background: #182e39; border-radius: 14px; padding: 16px; margin-top: 12px; margin-bottom: 10px; }
            .rbw-unlock passwordentry { background: #0d111b; color: #e8eef9; border: 1px solid #b59aff; border-radius: 12px; padding: 14px; caret-color: #b59aff; }
            .rbw-error { color: #ff9aa6; font-size: 12px; }
            .rbw-primary { transition: background-color 180ms ease-in-out, color 180ms ease-in-out, opacity 120ms ease-in-out; background: #b59aff; color: #161120; font-weight: 700; border-radius: 12px; padding: 12px 20px; border: none; }
            .rbw-primary:disabled { opacity: 0.55; }
            .rbw-primary.rbw-confirmed { background: #86efac; color: #10241b; opacity: 1; }
            .rbw-verified { color: #86efac; }
            .rbw-secondary { color: #95a3bb; background: transparent; border: none; }
            .rbw-footer { color: #95a3bb; font-size: 11px; margin-top: 8px; }
        ");
        let display = gtk::gdk::Display::default()
            .context("no display available for GTK unlock")?;
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
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
            .default_width(500)
            .default_height(510)
            .build();
        window.set_icon_name(Some("rbw"));
        window.add_css_class("rbw-unlock");
        let card = gtk::Box::new(gtk::Orientation::Vertical, 14);
        card.add_css_class("rbw-card");
        let brand = gtk::Label::new(Some("◇  RBW  ·  YOUR VAULT"));
        brand.add_css_class("rbw-brand");
        brand.set_xalign(0.0);
        let app_icon = gtk::gdk_pixbuf::Pixbuf::from_read(
            std::io::Cursor::new(include_bytes!("assets/rbw.png").as_slice()),
        )
        .context("could not load rbw app icon")?;
        let app_icon = gtk::Image::from_pixbuf(Some(&app_icon));
        app_icon.set_pixel_size(48);
        let branding = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        branding.append(&app_icon);
        branding.append(&brand);
        let heading = gtk::Label::new(Some("Welcome back"));
        heading.add_css_class("rbw-title");
        heading.set_xalign(0.0);
        let title = gtk::Label::new(None);
        title.add_css_class("rbw-subtitle");
        title.set_xalign(0.0);
        title.set_wrap(true);
        let status = gtk::Label::new(None);
        let fingerprint = gtk::Box::new(gtk::Orientation::Horizontal, 16);
        fingerprint.add_css_class("rbw-status");
        let animation = Rc::new(Cell::new(FingerprintAnimation::default()));
        let fingerprint_icon = fingerprint_icon(animation.clone());
        fingerprint.append(&fingerprint_icon);
        fingerprint.append(&status);
        status.set_wrap(true);
        status.set_xalign(0.0);
        // GtkPasswordEntry uses GtkPasswordEntryBuffer, backed by GTK's secure
        // allocator. No reveal button, undo history, or app clipboard actions.
        let entry = gtk::PasswordEntry::builder()
            .placeholder_text("Master password")
            .show_peek_icon(false)
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
        let error = gtk::Label::new(None);
        error.add_css_class("rbw-error");
        error.set_wrap(true);
        error.set_xalign(0.0);
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        actions.set_halign(gtk::Align::End);
        let cancel_button = gtk::Button::with_label("Cancel");
        cancel_button.add_css_class("rbw-secondary");
        let button = gtk::Button::new();
        button.set_width_request(176);
        let button_content = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let button_icon =
            gtk::Image::from_icon_name("changes-allow-symbolic");
        let button_label = gtk::Label::new(Some("Unlock vault"));
        let spinner = gtk::Spinner::new();
        spinner.set_visible(false);
        button_content.append(&spinner);
        button_content.append(&button_icon);
        button_content.append(&button_label);
        button.set_child(Some(&button_content));
        button.add_css_class("rbw-primary");
        actions.append(&cancel_button);
        actions.append(&button);
        let footer = gtk::Label::new(Some("Enter to unlock · Esc to cancel"));
        footer.add_css_class("rbw-footer");
        card.append(&branding);
        card.append(&heading);
        card.append(&title);
        card.append(&fingerprint);
        card.append(&entry);
        card.append(&error);
        card.append(&actions);
        card.append(&footer);
        window.set_child(Some(&card));
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
            fingerprint_icon,
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
        self.animation.set(FingerprintAnimation {
            tick: view.tick,
            success: view.success,
            active: !matches!(
                view.fingerprint,
                super::FingerprintStatus::Disabled
                    | super::FingerprintStatus::Unavailable
            ),
        });
        self.fingerprint_icon.queue_draw();
        self.status.set_label(if view.success {
            "✓ Verified. Finishing unlock…"
        } else {
            view.fingerprint.text()
        });
        if view.success {
            self.status.add_css_class("rbw-verified");
            self.button.add_css_class("rbw-confirmed");
        }
        self.busy = view.checking || view.success;
        self.button_label.set_label(if view.success {
            "Verified"
        } else if view.checking {
            "Checking…"
        } else {
            "Unlock vault"
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
