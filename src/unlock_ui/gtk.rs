use super::{Action, Frontend, SetupCredentials, View, SETUP_FIELDS};
use anyhow::Context as _;
use gtk::prelude::*;
use gtk4 as gtk;
use std::cell::{Cell, OnceCell};
use std::ffi::CStr;
use std::rc::Rc;

thread_local! {
    // A sign-in opens several dialogs on this thread. Keep the registered
    // application alive and reuse it across those windows.
    static APPLICATION: OnceCell<gtk::Application> = const { OnceCell::new() };
}

fn application() -> anyhow::Result<gtk::Application> {
    APPLICATION.with(|cell| {
        if let Some(application) = cell.get() {
            return Ok(application.clone());
        }
        let application = gtk::Application::builder()
            .application_id("org.rbw.Unlock")
            .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
            .build();
        application
            .register(None::<&gtk::gio::Cancellable>)
            .context("could not register the unlock dialog")?;
        Ok(cell.get_or_init(|| application).clone())
    })
}

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
    pub fn new(
        no_echo: bool,
        server_auth: bool,
        setup: bool,
    ) -> anyhow::Result<Self> {
        let login = server_auth || setup;
        gtk::init().context("could not open GTK unlock window")?;
        let application = application()?;
        let window = gtk::Window::builder()
            .application(&application)
            .modal(true)
            .resizable(false)
            .title(if login {
                "Sign in to rbw"
            } else {
                concat!("Unlock rbw ", env!("CARGO_PKG_VERSION"))
            })
            .default_width(if login { 420 } else { 540 })
            .build();
        window.set_icon_name(Some("rbw"));
        // Cancel lives in the header bar, Unlock next to the password field;
        // the body follows the system light/dark theme.
        let header = gtk::HeaderBar::new();
        header.set_show_title_buttons(false);
        let title = gtk::Label::new(None);
        title.add_css_class("title");
        if login {
            title.set_wrap(true);
            title.set_max_width_chars(36);
        }
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
        let submit = Rc::new(Cell::new(false));
        // GtkPasswordEntry uses GtkPasswordEntryBuffer, backed by GTK's secure
        // allocator. No reveal button, undo history, or app clipboard actions.
        let entry = gtk::PasswordEntry::builder()
            .placeholder_text(if server_auth && !setup {
                "Enter response"
            } else {
                "Master password"
            })
            .show_peek_icon(false)
            .hexpand(true)
            .build();
        entry.set_enable_undo(false);
        let text = entry
            .delegate()
            .and_then(|delegate| delegate.downcast::<gtk::Text>().ok())
            .context("GTK password input does not support no-echo mode")?;
        if no_echo {
            text.set_invisible_char('\0');
        }
        // Tab shows or hides the dots, as in systemd-ask-password. It starts
        // from the `unlock_no_echo` setting.
        let hidden = Rc::new(Cell::new(no_echo));
        let toggle = gtk::EventControllerKey::new();
        toggle.set_propagation_phase(gtk::PropagationPhase::Capture);
        toggle.connect_key_pressed(move |_, key, _, modifiers| {
            if key == gtk::gdk::Key::Tab
                && !modifiers.intersects(
                    gtk::gdk::ModifierType::CONTROL_MASK
                        | gtk::gdk::ModifierType::ALT_MASK,
                )
            {
                if hidden.replace(!hidden.get()) {
                    text.unset_invisible_char();
                } else {
                    text.set_invisible_char('\0');
                }
                gtk::glib::Propagation::Stop
            } else {
                gtk::glib::Propagation::Proceed
            }
        });
        if !setup {
            entry.add_controller(toggle);
            entry.set_tooltip_text(Some("Tab shows or hides the dots"));
        }
        let signal = submit.clone();
        entry.connect_activate(move |_| signal.set(true));
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
        let button = gtk::Button::with_label(if login {
            "Continue"
        } else {
            "Unlock"
        });
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
        let cancel = Rc::new(Cell::new(false));
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
        // Capture phase: the entry would otherwise take Ctrl+Delete for
        // "delete next word".
        let clear = gtk::EventControllerKey::new();
        clear.set_propagation_phase(gtk::PropagationPhase::Capture);
        let input = entry.downgrade();
        clear.connect_key_pressed(move |_, key, _, modifiers| {
            if matches!(key, gtk::gdk::Key::Delete | gtk::gdk::Key::KP_Delete)
                && modifiers.contains(gtk::gdk::ModifierType::CONTROL_MASK)
            {
                if let Some(input) = input.upgrade() {
                    input.set_text("");
                }
                gtk::glib::Propagation::Stop
            } else {
                gtk::glib::Propagation::Proceed
            }
        });
        entry.add_controller(clear);
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
fn editable_bytes<T: IsA<gtk::Editable>>(entry: &T) -> &[u8] {
    let entry = entry.as_ref();
    // SAFETY: this borrow is bounded by the GTK editable reference. Callers
    // copy or validate it before changing the entry or pumping GTK events.
    unsafe {
        CStr::from_ptr(gtk::ffi::gtk_editable_get_text(entry.as_ptr().cast()))
            .to_bytes()
    }
}

fn locked_input(bytes: &[u8]) -> anyhow::Result<crate::locked::Password> {
    anyhow::ensure!(
        bytes.len() <= crate::locked::CAPACITY,
        "sign-in input is too long"
    );
    let mut bytes_locked = crate::locked::Vec::try_new()?;
    bytes_locked.extend(bytes.iter().copied());
    Ok(crate::locked::Password::new(bytes_locked))
}

#[allow(
    clippy::future_not_send,
    reason = "GTK widgets stay on the calling thread"
)]
pub(super) async fn setup(
    no_echo: bool,
    server_hint: &str,
    deadline: Option<std::time::Instant>,
) -> anyhow::Result<SetupCredentials> {
    let dialog = GtkDialog::new(no_echo, true, true)?;
    dialog.title.set_label("Sign in to Bitwarden");
    dialog.button.set_label("Sign in");
    let form = dialog
        .pages
        .child_by_name("form")
        .and_downcast::<gtk::Box>()
        .context("missing sign-in form")?;
    let row = dialog
        .button
        .parent()
        .and_downcast::<gtk::Box>()
        .context("missing sign-in button row")?;
    row.remove(&dialog.button);
    let url = gtk::Entry::builder()
        .placeholder_text(server_hint)
        .hexpand(true)
        .build();
    let email = gtk::Entry::builder()
        .placeholder_text(SETUP_FIELDS[1])
        .hexpand(true)
        .build();
    let totp = gtk::PasswordEntry::builder()
        .placeholder_text(SETUP_FIELDS[3])
        .show_peek_icon(false)
        .hexpand(true)
        .build();
    totp.set_enable_undo(false);
    if no_echo {
        let text = totp
            .delegate()
            .and_downcast::<gtk::Text>()
            .context("GTK code input does not support no-echo mode")?;
        text.set_invisible_char('\0');
    }
    let url_label = gtk::Label::new(Some(SETUP_FIELDS[0]));
    url_label.set_xalign(0.0);
    form.prepend(&email);
    form.prepend(&url);
    form.prepend(&url_label);
    form.insert_child_after(&totp, Some(&row));
    form.insert_child_after(&dialog.button, Some(&totp));
    for entry in [&url, &email] {
        let submit = dialog.submit.clone();
        entry.connect_activate(move |_| submit.set(true));
    }
    let submit = dialog.submit.clone();
    totp.connect_activate(move |_| submit.set(true));
    url.grab_focus();
    let mut timer =
        tokio::time::interval(std::time::Duration::from_millis(16));
    let result = loop {
        pump();
        if deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            break Err(anyhow::anyhow!("sign-in setup timed out"));
        }
        if dialog.cancel.get() {
            break Err(anyhow::anyhow!("sign-in setup cancelled"));
        }
        if dialog.submit.replace(false) {
            let password = editable_bytes(&dialog.entry);
            let code = editable_bytes(&totp);
            if password.len() > crate::locked::CAPACITY {
                dialog.error.set_label("Master password is too long.");
                dialog.error_row.set_visible(true);
            } else {
                match super::setup_account(
                    &url.text(),
                    &email.text(),
                    password,
                    code,
                ) {
                    Ok((base_url, email)) => {
                        break Ok(SetupCredentials {
                            base_url,
                            email,
                            password: locked_input(password)?,
                            totp: if code.is_empty() {
                                None
                            } else {
                                Some(locked_input(code)?)
                            },
                        });
                    }
                    Err(error) => {
                        dialog.error.set_label(error);
                        dialog.error_row.set_visible(true);
                    }
                }
            }
        }
        timer.tick().await;
    };
    totp.set_text("");
    result
}

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
            let bytes = editable_bytes(&self.entry);
            let too_long = bytes.len() > crate::locked::CAPACITY;
            let input = (!too_long && !bytes.is_empty())
                .then(|| locked_input(bytes))
                .transpose()?;
            self.entry.set_text("");
            if too_long {
                self.issue = Some("Password is too long. Please try again.");
            } else if let Some(input) = input {
                self.issue = None;
                self.busy = true;
                self.entry.set_sensitive(false);
                self.button.set_sensitive(false);
                return Ok(Some(Action::Submit(input)));
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
            let mut dialog = GtkDialog::new(no_echo, false, false).unwrap();
            dialog
                .render(&View {
                    server_auth: false,
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
