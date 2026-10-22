const api = globalThis.browser || chrome;
const $ = id => document.getElementById(id);
for (const el of document.querySelectorAll("[data-icon]")) el.replaceChildren(icon(el.dataset.icon));
document.querySelector("[data-extension-version]").textContent = `v${api?.runtime?.getManifest?.()?.version || "0.2.27"}`;
async function request(action, values = {}) {
  const response = await api.runtime.sendMessage({ action, account: ["import", "export", "folders"].includes(action) ? $("account").value || null : null, ...values });
  if (!response || response.error) throw new Error(response?.error || "Background unavailable.");
  return response.result;
}
async function attempt(fn) { $("message").classList.remove("is-error"); $("message").setAttribute("role", "status"); try { await fn(); } catch (error) { $("message").textContent = error.message; $("message").classList.add("is-error"); $("message").setAttribute("role", "alert"); } }
function theme(value) { document.documentElement.dataset.theme = value === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : value; }
const uriMatchNames = { domain: "Domain and subdomains", base_domain: "Base domain", host: "Host", starts_with: "Starts with", exact: "Exact", regular_expression: "Regular expression", never: "Never" };
function showPolicy(policy) {
  $("agent-policy").textContent = `Automatic lock: ${policy.lockTimeout} seconds. Sync: every ${policy.syncInterval} seconds. Clipboard: ${policy.clipboard}. Generator default length: ${policy.passwordGen.length || 20}. URI matching: ${uriMatchNames[policy.defaultUriMatch] || uriMatchNames.domain}.`;
  $("uri-match").options[0].textContent = `Use rbw default (${uriMatchNames[policy.defaultUriMatch] || uriMatchNames.domain})`;
}
// Which accounts the extension covers: the rbw CLI's choice, or the ones
// ticked here (two or more are merged). The legacy single `account`
// preference counts as a selection of one.
function chosenAccounts(prefs) { return Array.isArray(prefs.accounts) && prefs.accounts.length ? prefs.accounts : prefs.account ? [prefs.account] : []; }
function renderAccountChoices(state, prefs) {
  const names = state.accounts || [], chosen = chosenAccounts(prefs).filter(name => names.includes(name));
  $("accounts-section").hidden = names.length < 2;
  $("accounts-cli").checked = !chosen.length;
  const list = $("accounts-list"); list.hidden = !chosen.length && $("accounts-cli").checked;
  list.replaceChildren(...names.map(name => {
    const label = document.createElement("label"); label.className = "switch-row";
    const text = document.createElement("span"); text.textContent = state.primary === name ? `${name} (primary)` : name;
    const input = document.createElement("input"); input.type = "checkbox"; input.className = "switch"; input.value = name; input.checked = chosen.includes(name); input.disabled = $("accounts-cli").checked;
    label.append(text, input); return label;
  }));
  const picked = chosen.length ? chosen : names;
  $("account-target-row").hidden = names.length < 2;
  $("account").replaceChildren(...picked.map(name => new Option(name === state.primary ? `${name} *` : name, name)));
  $("account").value = picked.includes($("account").value) ? $("account").value : picked.includes(state.primary) ? state.primary : picked[0];
}
async function saveAccountChoice() {
  const chosen = $("accounts-cli").checked ? [] : [...$("accounts-list").querySelectorAll("input:checked")].map(input => input.value);
  if (!$("accounts-cli").checked && !chosen.length) { $("accounts-cli").checked = true; }
  const prefs = await request("set_preferences", { preferences: { accounts: chosen, account: "" } });
  renderAccountChoices(await status(), prefs); $("message").textContent = "Accounts saved.";
}
$("accounts-cli").onchange = () => attempt(async () => {
  // Turning the CLI default off starts from every account selected.
  if (!$("accounts-cli").checked) for (const input of $("accounts-list").querySelectorAll("input")) input.checked = true;
  await saveAccountChoice();
});
$("accounts-list").onchange = () => attempt(saveAccountChoice);
async function status() {
  const state = await request("status"); $("connection").textContent = "Connected to rbw native messaging"; $("lock-state").textContent = state.unlocked ? "Unlocked" : "Locked";
  return state;
}
for (const id of ["passkeys", "inline", "autofill", "allow-http-fill", "autofill-blocklist", "animations", "animation-speed", "card-security-code", "copy-totp", "autofill-totp", "save-prompts", "theme", "show-generator", "show-send", "show-health", "favicons", "uri-match"]) $(id).onchange = () => attempt(async () => {
  const preferences = { passkeys: $("passkeys").checked, savePrompts: $("save-prompts").checked, inlineSuggestions: $("inline").checked, autoFill: $("autofill").checked, allowHttpFill: $("allow-http-fill").checked, autofillBlocklist: $("autofill-blocklist").value, animations: $("animations").value, animationSpeed: $("animation-speed").value, cardSecurityCode: $("card-security-code").value, copyTotp: $("copy-totp").checked, autofillTotp: $("autofill-totp").checked, theme: $("theme").value, showGenerator: $("show-generator").checked, showSend: $("show-send").checked, showHealth: $("show-health").checked, favicons: $("favicons").checked, uriMatchDefault: $("uri-match").value };
  await request("set_preferences", { preferences }); $("animation-speed").disabled = preferences.animations === "off"; $("animation-speed").closest(".switch-row").hidden = preferences.animations === "off"; theme(preferences.theme); $("message").textContent = "Settings saved."; await status();
  showPolicy(await request("agent_settings"));
});
for (const action of ["sync", "lock"]) $(action).onclick = () => attempt(async () => {
  if (action === "lock" && !await confirmLock()) return;
  // The sync icon spins while syncing, like the popup's header button.
  const button = $(action); if (action === "sync") { button.classList.add("is-syncing"); button.disabled = true; }
  try { await request(action); } finally { button.classList.remove("is-syncing"); button.disabled = false; }
  await status(); $("message").textContent = action === "sync" ? "Vault synchronized." : "Vault locked."; });
// Firefox can't open about:addons from an extension, but has its own API
// for the shortcut settings (Firefox 137+); Chromium opens its page. A
// failure is explained right below the button.
$("shortcuts").onclick = async () => {
  $("shortcuts-hint").hidden = true;
  try {
    if (api.commands?.openShortcutSettings) await api.commands.openShortcutSettings();
    else await api.tabs.create({ url: "chrome://extensions/shortcuts" });
  } catch (_) { $("shortcuts-hint").hidden = false; }
};
attempt(async () => {
  const prefs = await request("preferences"); theme(prefs.theme);
  const managedPreferences = await request("managed_preferences");
  $("favicons").checked = prefs.favicons; $("show-generator").checked = prefs.showGenerator; $("show-send").checked = prefs.showSend; $("show-health").checked = prefs.showHealth;
  const state = await status();
  renderAccountChoices(state, prefs);
  $("autofill").checked = prefs.autoFill; $("copy-totp").checked = prefs.copyTotp === true; $("autofill-totp").checked = prefs.autofillTotp === true; $("allow-http-fill").checked = prefs.allowHttpFill === true; $("allow-http-fill").disabled = Object.hasOwn(managedPreferences, "allowHttpFill"); $("allow-http-fill-managed").hidden = !Object.hasOwn(managedPreferences, "allowHttpFill"); $("autofill-blocklist").value = prefs.autofillBlocklist || ""; $("animations").value = prefs.animations; $("animation-speed").value = prefs.animationSpeed; $("animation-speed").disabled = prefs.animations === "off"; $("animation-speed").closest(".switch-row").hidden = prefs.animations === "off"; $("card-security-code").value = ["fill", "clipboard"].includes(prefs.cardSecurityCode) ? prefs.cardSecurityCode : "off"; $("inline").checked = prefs.inlineSuggestions; $("passkeys").checked = prefs.passkeys; $("save-prompts").checked = prefs.savePrompts; $("theme").value = prefs.theme; $("uri-match").value = prefs.uriMatchDefault || ""; await status();
  lockManagedControls(managedPreferences, { copyTotp: "copy-totp", autofillTotp: "autofill-totp", cardSecurityCode: "card-security-code" });
  showPolicy(await request("agent_settings"));
});
// Independent of the panels above, so their failures don't leave it loading.
folders().catch(() => { $("folders").replaceChildren(Object.assign(document.createElement("p"), { className: "hint", textContent: "Unlock the vault to manage folders." })); });

// One row per folder: its name with icon-only rename and delete buttons.
// Rename edits the name in place (Enter saves, Escape cancels).
function iconButton(name, label, onclick, className = "") {
  const button = document.createElement("button"); button.type = "button"; button.className = `icon ${className}`.trim();
  button.title = label; button.setAttribute("aria-label", label); button.append(icon(name)); button.onclick = onclick;
  return button;
}
function folderRow(folder) {
  const row = document.createElement("div"); row.className = "switch-row folder-row";
  const name = document.createElement("span"); name.className = "folder-name"; name.append(icon("folder"), document.createTextNode(folder.name));
  const actions = document.createElement("span"); actions.className = "folder-actions";
  const view = () => {
    actions.replaceChildren(
      iconButton("edit", `Rename “${folder.name}”`, edit),
      iconButton("trash", `Delete “${folder.name}”`, () => attempt(async () => {
        if (!await confirmDialog({ title: `Delete the folder “${folder.name}”?`, text: "Its items stay in your vault.", confirm: "Delete folder", danger: true })) return;
        await request("folders", { method: "delete", id: folder.id }); await folders();
      }), "danger"));
    row.replaceChildren(name, actions);
  };
  const edit = () => {
    const input = document.createElement("input"); input.value = folder.name; input.maxLength = 1024; input.setAttribute("aria-label", "Folder name");
    const save = () => attempt(async () => {
      const value = input.value.trim();
      if (!value || value === folder.name) { view(); return; }
      await request("folders", { method: "rename", id: folder.id, name: value }); await folders();
    });
    input.onkeydown = event => { if (event.key === "Enter") { event.preventDefault(); save(); } else if (event.key === "Escape") { event.preventDefault(); view(); } };
    actions.replaceChildren(iconButton("check", "Save", save), iconButton("close", "Cancel", view));
    row.replaceChildren(input, actions); input.focus(); input.select();
  };
  view(); return row;
}
async function folders() {
  const list = (await request("folders", { method: "list" })).slice().sort((x, y) => x.name.localeCompare(y.name, undefined, { sensitivity: "base" }));
  $("folder-count").textContent = list.length ? `${list.length}` : "";
  $("folders").replaceChildren(...(list.length ? list.map(folderRow) : [Object.assign(document.createElement("p"), { className: "hint", textContent: "No folders yet." })]));
}
$("folder-form").onsubmit = event => { event.preventDefault(); attempt(async () => { const name = $("folder-name").value.trim(); if (!name) return; await request("folders", { method: "create", name }); $("folder-name").value = ""; await folders(); }); };

// Only the encrypted Bitwarden format takes (and requires) an export password.
function syncExportPassword() {
  const encrypted = $("export-format").value === "bitwarden-encrypted-json";
  $("export-password-field").hidden = !encrypted; $("export-password").required = encrypted;
  if (!encrypted) $("export-password").value = "";
}
$("export-format").onchange = syncExportPassword; syncExportPassword();
$("export-form").onsubmit = event => { event.preventDefault(); attempt(async () => {
  const format = $("export-format").value;
  const password = $("export-password").value; $("export-password").value = "";
  if (format === "bitwarden-encrypted-json" && !password) throw new Error("Enter an export password.");
  if (format !== "bitwarden-encrypted-json" && !await confirmDialog({ title: "Export unencrypted secrets?", text: "This export contains your passwords and private keys in plain text. It will be saved to your Downloads directory.", confirm: "Export", icon: "download", danger: true })) return;
  $("message").textContent = "Exporting vault…";
  const result = await request("export", { format, password: password || null, attachments: $("export-attachments").checked }); $("message").textContent = `Export saved to ${result.path}`;
}); };
$("import-form").onsubmit = event => { event.preventDefault(); attempt(async () => {
  const file = $("import-file").files[0]; if (!file) throw new Error("Choose an export file.");
  if (!await confirmDialog({ title: "Import this file?", text: `${file.name} is imported into the selected account.`, confirm: "Import", icon: "upload" })) return;
  const password = $("import-password").value; $("import-password").value = "";
  const token = await request("upload_begin", { item: "", name: file.name, size: file.size });
  try {
    for (let offset = 0; offset < file.size; offset += 192 * 1024) {
      const bytes = new Uint8Array(await file.slice(offset, offset + 192 * 1024).arrayBuffer()); let text = ""; for (const byte of bytes) text += String.fromCharCode(byte);
      await request("upload_chunk", { token, offset, data: btoa(text) }); $("message").textContent = "Transferring import to rbw…";
    }
    $("message").textContent = "Importing and synchronizing…";
    await request("import", { token, password: password || null, overwrite: $("import-overwrite").checked }); $("import-file").value = ""; $("message").textContent = "Vault import completed.";
  } finally { await request("upload_cancel", { token }).catch(() => {}); }
}); };
