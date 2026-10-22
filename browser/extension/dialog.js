/* In-page confirmation sheet for the popup and options pages, replacing
   window.confirm(). Resolves true only when the confirm button is used;
   Escape, Cancel and clicking the backdrop all resolve false. */
function confirmDialog({ title, text = "", confirm = "Confirm", choices = null, choiceLabel = "", danger = false, icon: iconName = danger ? "trash" : "check" } = {}) {
  return new Promise(resolve => {
    const dialog = document.createElement("dialog");
    dialog.className = `confirm-dialog${danger ? " is-danger" : ""}`;
    dialog.setAttribute("aria-labelledby", "confirm-dialog-title");
    const form = document.createElement("form"); form.method = "dialog";
    const badge = document.createElement("span"); badge.className = "confirm-dialog-icon"; badge.append(icon(iconName));
    const heading = document.createElement("h2"); heading.id = "confirm-dialog-title"; heading.textContent = title;
    const body = document.createElement("p"); body.textContent = text; body.hidden = !text;
    // With `choices` ([{ value, label }]) the dialog resolves to the chosen value.
    let select = null, choiceRow = null;
    if (choices) {
      select = document.createElement("select"); select.setAttribute("aria-label", choiceLabel || title);
      for (const choice of choices) select.append(new Option(choice.label, choice.value));
      choiceRow = document.createElement("label"); choiceRow.className = "confirm-dialog-choice"; choiceRow.append(choiceLabel, select);
    }
    const actions = document.createElement("div"); actions.className = "confirm-dialog-actions";
    const cancel = document.createElement("button"); cancel.value = "cancel"; cancel.textContent = "Cancel";
    const ok = document.createElement("button"); ok.value = "ok"; ok.textContent = confirm; ok.className = danger ? "danger-solid" : "primary";
    actions.append(cancel, ok); form.append(badge, heading, body, ...(choiceRow ? [choiceRow] : []), actions); dialog.append(form);
    dialog.addEventListener("click", event => { if (event.target === dialog) dialog.close("cancel"); });
    dialog.addEventListener("close", () => { resolve(dialog.returnValue === "ok" ? (select ? select.value : true) : false); dialog.remove(); }, { once: true });
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
// Locks the controls of preferences set by browser policy (managed storage),
// noting why in the control's settings row. `controls` maps preference keys
// to control ids.
function lockManagedControls(managed, controls) {
  for (const [key, id] of Object.entries(controls)) {
    if (!Object.hasOwn(managed, key)) continue;
    const control = document.getElementById(id); if (!control) continue;
    control.disabled = true;
    const label = control.closest(".switch-row")?.querySelector("span");
    if (label && !label.querySelector(".managed-note")) {
      const note = document.createElement("small"); note.className = "managed-note"; note.textContent = "Managed by your browser configuration.";
      label.append(note);
    }
  }
}
