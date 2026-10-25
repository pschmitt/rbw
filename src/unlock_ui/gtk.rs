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
    error_row: gtk::Box,
    // The form, a spinner while the password is checked, then the result:
    // the input goes away on submit and comes back only after a failure.
    pages: gtk::Stack,
    spinner: gtk::Spinner,
    button: gtk::Button,
    cancel_button: gtk::Button,
    busy: bool,
    submit: Rc<Cell<bool>>,
    cancel: Rc<Cell<bool>>,
    issue: Option<&'static str>,
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
            .title(concat!("Unlock rbw ", env!("CARGO_PKG_VERSION")))
            .default_width(540)
            .build();
        window.set_icon_name(Some("rbw"));
        // Cancel lives in the header bar, Unlock next to the password field;
        // the body follows the system light/dark theme.
        let header = gtk::HeaderBar::new();
        header.set_show_title_buttons(false);
        let title = gtk::Label::new(None);
        title.add_css_class("title");
        header.set_title_widget(Some(&title));
        let cancel_button = gtk::Button::with_label("Cancel");
        header.pack_start(&cancel_button);
        window.set_titlebar(Some(&header));
        let logo = gtk::gdk_pixbuf::Pixbuf::from_read(std::io::Cursor::new(
            include_bytes!("../../assets/rbw.png").as_slice(),
        ))
        .context("could not load rbw logo")?;
        let logo = gtk::Image::from_pixbuf(Some(&logo));
        logo.set_pixel_size(64);
        logo.set_valign(gtk::Align::Center);
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
        error.set_wrap(true);
        error.set_xalign(0.0);
        error.set_hexpand(true);
        let error_icon = gtk::Image::from_icon_name("dialog-error-symbolic");
        error_icon.add_css_class("error");
        let error_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        error_row.append(&error_icon);
        error_row.append(&error);
        error_row.set_visible(false);
        let form = gtk::Box::new(gtk::Orientation::Vertical, 8);
        form.set_valign(gtk::Align::Center);
        let button = gtk::Button::with_label("Unlock");
        button.add_css_class("suggested-action");
        let input_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        input_row.append(&entry);
        input_row.append(&button);
        form.append(&input_row);
        form.append(&error_row);
        form.append(&status);
        let spinner = gtk::Spinner::new();
        spinner.set_size_request(32, 32);
        let checking = result_page(
            spinner.upcast_ref(),
            "Checking password…",
            "dim-label",
        );
        let done = gtk::Image::from_icon_name("object-select-symbolic");
        done.set_pixel_size(40);
        let done = result_page(done.upcast_ref(), "Unlocked", "success");
        let pages = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .transition_duration(150)
            .hexpand(true)
            .vhomogeneous(true)
            .build();
        pages.add_named(&form, Some("form"));
        pages.add_named(&checking, Some("checking"));
        pages.add_named(&done, Some("done"));
        let body = gtk::Box::new(gtk::Orientation::Horizontal, 24);
        body.set_margin_top(24);
        body.set_margin_bottom(24);
        body.set_margin_start(24);
        body.set_margin_end(24);
        body.append(&logo);
        body.append(&pages);
        window.set_child(Some(&body));
        // The red outline of a rejected password goes once the user types.
        entry.connect_changed(|entry| entry.remove_css_class("error"));
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
            error_row,
            pages,
            spinner,
            button,
            cancel_button,
            busy: false,
            submit,
            cancel,
            issue: None,
        })
    }
}

// A centred icon (or spinner) above a short message, both styled with
// `class` (themes color labels and icons, not their container).
fn result_page(icon: &gtk::Widget, text: &str, class: &str) -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 10);
    page.set_valign(gtk::Align::Center);
    page.set_halign(gtk::Align::Center);
    icon.set_halign(gtk::Align::Center);
    icon.add_css_class(class);
    page.append(icon);
    let label = gtk::Label::new(Some(text));
    label.add_css_class("heading");
    label.add_css_class(class);
    page.append(&label);
    page
}

// Runs whatever GTK has queued, including the Wayland/X11 requests that map,
// redraw or remove the window, without blocking.
fn pump() {
    let context = gtk::glib::MainContext::default();
    for _ in 0..32 {
        if !context.pending() {
            break;
        }
        context.iteration(false);
    }
}

impl Frontend for GtkDialog {
    fn poll(&mut self) -> anyhow::Result<Option<Action>> {
        pump();
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
        self.status.set_label(view.fingerprint.text());
        self.status.set_visible(
            !(view.fingerprint == super::FingerprintStatus::Disabled
                && view.hide_disabled),
        );
        self.busy = view.checking || view.success;
        let page = if view.success {
            "done"
        } else if view.checking {
            "checking"
        } else {
            "form"
        };
        let previous = self.pages.visible_child_name();
        if previous.as_deref() != Some(page) {
            self.pages.set_visible_child_name(page);
            if view.checking {
                self.spinner.start();
            } else {
                self.spinner.stop();
            }
            if page == "form" {
                // Back from checking: the password was refused.
                if self.issue.or(view.error).is_some() {
                    self.entry.add_css_class("error");
                }
                self.entry.grab_focus();
            }
        }
        let error = self.issue.or(view.error);
        self.error.set_label(error.unwrap_or_default());
        self.error_row.set_visible(error.is_some());
        self.cancel_button.set_sensitive(!view.success);
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
        // Hand the removal to the compositor now: the caller goes on to
        // unlock and sync without running GTK, and a window left mapped
        // meanwhile stops answering pings ("not responding").
        pump();
        if let Some(display) = gtk::gdk::Display::default() {
            display.flush();
        }
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
                    hide_disabled: false,
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
