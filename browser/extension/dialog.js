/* In-page confirmation sheet for the popup and options pages, replacing
   window.confirm(). Resolves true only when the confirm button is used;
   Escape, Cancel and clicking the backdrop all resolve false. */
function confirmDialog({ title, text = "", confirm = "Confirm", danger = false, icon: iconName = danger ? "trash" : "check" } = {}) {
  return new Promise(resolve => {
    const dialog = document.createElement("dialog");
    dialog.className = `confirm-dialog${danger ? " is-danger" : ""}`;
    dialog.setAttribute("aria-labelledby", "confirm-dialog-title");
    const form = document.createElement("form"); form.method = "dialog";
    const badge = document.createElement("span"); badge.className = "confirm-dialog-icon"; badge.append(icon(iconName));
    const heading = document.createElement("h2"); heading.id = "confirm-dialog-title"; heading.textContent = title;
    const body = document.createElement("p"); body.textContent = text; body.hidden = !text;
    const actions = document.createElement("div"); actions.className = "confirm-dialog-actions";
    const cancel = document.createElement("button"); cancel.value = "cancel"; cancel.textContent = "Cancel";
    const ok = document.createElement("button"); ok.value = "ok"; ok.textContent = confirm; ok.className = danger ? "danger-solid" : "primary";
    actions.append(cancel, ok); form.append(badge, heading, body, actions); dialog.append(form);
    dialog.addEventListener("click", event => { if (event.target === dialog) dialog.close("cancel"); });
    dialog.addEventListener("close", () => { resolve(dialog.returnValue === "ok"); dialog.remove(); }, { once: true });
    document.body.append(dialog); dialog.showModal();
    // Destructive actions start on Cancel, so Enter never deletes by accident.
    (danger ? cancel : ok).focus();
  });
}
// Locking rbw-agent affects every client of it, not just this browser.
function confirmLock() {
  return confirmDialog({
    title: "Lock the vault?",
    text: "This locks rbw-agent for everything using it, including the command line, until you unlock it again.",
    confirm: "Lock vault",
    icon: "lock",
  });
}
