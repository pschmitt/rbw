const api = globalThis.browser || chrome;
const $ = id => document.getElementById(id);
for (const el of document.querySelectorAll("[data-icon]")) el.replaceChildren(icon(el.dataset.icon));
document.querySelector("[data-extension-version]").textContent = `v${api?.runtime?.getManifest?.()?.version || "0.2.27"}`;
async function request(action, values = {}) {
  const response = await api.runtime.sendMessage({ action, account: $("account").value, ...values });
  if (!response || response.error) throw new Error(response?.error || "Background unavailable.");
  return response.result;
}
async function attempt(fn) { $("message").classList.remove("is-error"); $("message").setAttribute("role", "status"); try { await fn(); } catch (error) { $("message").textContent = error.message; $("message").classList.add("is-error"); $("message").setAttribute("role", "alert"); } }
function theme(value) { document.documentElement.dataset.theme = value === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : value; }
const uriMatchNames = { domain: "Base domain", host: "Host", starts_with: "Starts with", exact: "Exact", regular_expression: "Regular expression", never: "Never" };
function showPolicy(policy) {
  $("agent-policy").textContent = `Automatic lock: ${policy.lockTimeout} seconds. Sync: every ${policy.syncInterval} seconds. Clipboard: ${policy.clipboard}. Generator default length: ${policy.passwordGen.length || 20}. URI matching: ${uriMatchNames[policy.defaultUriMatch] || "Base domain"}.`;
  $("uri-match").options[0].textContent = `Use rbw default (${uriMatchNames[policy.defaultUriMatch] || "Base domain"})`;
}
async function status() {
  const state = await request("status"); $("connection").textContent = "Connected to rbw native messaging"; $("lock-state").textContent = state.unlocked ? "Unlocked" : "Locked";
  return state;
}
for (const id of ["account", "passkeys", "inline", "autofill", "autofill-blocklist", "animations", "animation-speed", "card-security-code", "save-prompts", "theme", "show-generator", "show-send", "show-health", "favicons", "uri-match"]) $(id).onchange = () => attempt(async () => {
  const preferences = { account: $("account").value, passkeys: $("passkeys").checked, savePrompts: $("save-prompts").checked, inlineSuggestions: $("inline").checked, autoFill: $("autofill").checked, autofillBlocklist: $("autofill-blocklist").value, animations: $("animations").value, animationSpeed: $("animation-speed").value, cardSecurityCode: $("card-security-code").value, theme: $("theme").value, showGenerator: $("show-generator").checked, showSend: $("show-send").checked, showHealth: $("show-health").checked, favicons: $("favicons").checked, uriMatchDefault: $("uri-match").value };
  await request("set_preferences", { preferences }); $("animation-speed").disabled = preferences.animations === "off"; theme(preferences.theme); $("message").textContent = "Settings saved."; await status();
  showPolicy(await request("agent_settings"));
});
for (const action of ["sync", "lock"]) $(action).onclick = () => attempt(async () => { await request(action); await status(); $("message").textContent = action === "sync" ? "Vault synchronized." : "Vault locked."; });
$("shortcuts").onclick = () => { const firefox = !!globalThis.browser; api.tabs.create({ url: firefox ? "about:addons" : "chrome://extensions/shortcuts" }).catch(() => { $("message").textContent = "Open your browser’s extension manager to change shortcuts."; }); };
attempt(async () => {
  const prefs = await request("preferences"); theme(prefs.theme);
  $("favicons").checked = prefs.favicons; $("show-generator").checked = prefs.showGenerator; $("show-send").checked = prefs.showSend; $("show-health").checked = prefs.showHealth;
  const state = await status();
  $("account").replaceChildren(...(state.accounts || []).map(a => new Option(a === state.primary ? `${a} *` : a, a)));
  $("account").value = prefs.account || state.primary || "";
  $("autofill").checked = prefs.autoFill; $("autofill-blocklist").value = prefs.autofillBlocklist || ""; $("animations").value = prefs.animations; $("animation-speed").value = prefs.animationSpeed; $("animation-speed").disabled = prefs.animations === "off"; $("card-security-code").value = ["fill", "clipboard"].includes(prefs.cardSecurityCode) ? prefs.cardSecurityCode : "off"; $("inline").checked = prefs.inlineSuggestions; $("passkeys").checked = prefs.passkeys; $("save-prompts").checked = prefs.savePrompts; $("theme").value = prefs.theme; $("uri-match").value = prefs.uriMatchDefault || ""; await status();
  showPolicy(await request("agent_settings"));
});

async function folders() {
  const list = await request("folders", { method: "list" }); $("folders").replaceChildren();
  for (const folder of list) {
    const row = document.createElement("div"); row.className = "actions";
    const input = document.createElement("input"); input.value = folder.name; input.setAttribute("aria-label", "Folder name");
    const rename = document.createElement("button"); rename.append(icon("edit"), document.createTextNode("Rename")); rename.onclick = () => attempt(async () => { await request("folders", { method: "rename", id: folder.id, name: input.value }); await folders(); });
    const remove = document.createElement("button"); remove.append(icon("trash"), document.createTextNode("Delete")); remove.className = "danger"; remove.onclick = () => attempt(async () => { if (!confirm("Delete this folder? Its items will remain in your vault.")) return; await request("folders", { method: "delete", id: folder.id }); await folders(); });
    row.append(input, rename, remove); $("folders").append(row);
  }
}
$("load-folders").onclick = () => attempt(folders);
$("folder-form").onsubmit = event => { event.preventDefault(); attempt(async () => { await request("folders", { method: "create", name: $("folder-name").value }); $("folder-name").value = ""; await folders(); }); };

$("export-form").onsubmit = event => { event.preventDefault(); attempt(async () => {
  const format = $("export-format").value;
  const password = $("export-password").value; $("export-password").value = "";
  if (format === "bitwarden-encrypted-json" && !password) throw new Error("Enter an export password.");
  if (format !== "bitwarden-encrypted-json" && !confirm("This export will contain unencrypted vault secrets, including passwords and private keys. Save it to your Downloads directory?")) return;
  $("message").textContent = "Exporting vault…";
  const result = await request("export", { format, password: password || null, attachments: $("export-attachments").checked }); $("message").textContent = `Export saved to ${result.path}`;
}); };
$("import-form").onsubmit = event => { event.preventDefault(); attempt(async () => {
  const file = $("import-file").files[0]; if (!file) throw new Error("Choose an export file.");
  if (!confirm("Import this file into the selected account?")) return;
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
