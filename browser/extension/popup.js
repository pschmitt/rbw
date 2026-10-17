if (new URLSearchParams(location.search).get("surface") === "window") document.documentElement.dataset.surface = "window";
const api = globalThis.browser || chrome;
const $ = id => document.getElementById(id);
for (const label of document.querySelectorAll("[data-extension-version]")) {
  label.textContent = `v${api.runtime.getManifest().version}`;
  label.title = "Loaded rbw extension version";
}
const labels = { login: "Login", card: "Card", identity: "Identity", secure_note: "Secure note", ssh_key: "SSH key" };
const icons = { login: "key", card: "card", identity: "identity", secure_note: "note", ssh_key: "terminal" };
for (const el of document.querySelectorAll("[data-icon]")) el.replaceChildren(icon(el.dataset.icon));
const schema = {
  login: ["username", "password", "totp"],
  card: ["cardholder_name", "number", "brand", "exp_month", "exp_year", "code"],
  identity: ["title", "first_name", "middle_name", "last_name", "address1", "address2", "address3", "city", "state", "postal_code", "country", "phone", "email", "username", "ssn", "license_number", "passport_number"],
  secure_note: [], ssh_key: ["public_key", "fingerprint", "private_key"],
};
const secret = name => ["password", "totp", "code", "number", "ssn", "license_number", "passport_number", "private_key"].includes(name);
let sendId = null;
let epoch = 0, timer, currentPage = "vault", currentItem = null, currentDetail = null, unlocked = false, preference = {}, approvalId = new URLSearchParams(location.search).get("request");
let loadingRequests = 0;
function loading(active) { loadingRequests = Math.max(0, loadingRequests + (active ? 1 : -1)); $("loading").hidden = !loadingRequests; document.querySelector("main").setAttribute("aria-busy", String(!!loadingRequests)); }
async function request(action, values = {}) {
  const busy = !["preferences", "pending", "save_offers", "popup_notice", "status", "favicon"].includes(action);
  if (busy) loading(true);
  try {
    const response = await api.runtime.sendMessage({ action, account: $("account").value, ...values });
    if (response?.error) throw new Error(response.error);
    if (!response) throw new Error("Extension background unavailable.");
    return response.result;
  } finally { if (busy) loading(false); }
}
function message(text, error = false) {
  $("message").textContent = text;
  $("message").classList.toggle("is-error", error);
  $("message").setAttribute("role", error ? "alert" : "status");
}
async function attempt(fn) { try { await fn(); } catch (error) {
  if (error.message.startsWith("Browser access denied.")) {
    unlocked = false; clearVault(); show("locked");
    $("unlock-panel").hidden = true; $("locked").hidden = true;
  }
  message(error.message, true);
} }
function element(tag, text, cls) { const el = document.createElement(tag); if (text != null) el.textContent = text; if (cls) el.className = cls; return el; }
function button(label, action, cls) { const el = element("button", label, cls); el.type = "button"; el.onclick = () => attempt(async () => { el.disabled = true; try { await action(); } finally { el.disabled = false; } }); return el; }
function pretty(value) { return value.replaceAll("_", " ").replace(/^./, c => c.toUpperCase()); }
function show(page) {
  currentPage = page;
  $("back").hidden = !["detail", "editor", "send-editor"].includes(page);
  $("unlock-panel").hidden = unlocked || !["locked", "approval"].includes(page);
  for (const id of ["vault", "generator", "send", "send-editor", "health", "settings", "detail", "editor", "approval", "locked"]) $(id).hidden = id !== page;
  $("title").textContent = ({ vault: "Vault", generator: "Generator", health: "Vault health", settings: "Settings", send: "Send", "send-editor": "Edit Send", detail: "Item", editor: currentItem ? "Edit item" : "New item", approval: "Passkey", locked: "Vault" })[page];
  $("add").hidden = !["vault", "send"].includes(page) || !unlocked;
  document.querySelectorAll("footer button").forEach(el => el.classList.toggle("selected", el.dataset.page === page));
}
function applyTabs() {
  const visibility = { generator: preference.showGenerator !== false, send: preference.showSend === true, health: preference.showHealth === true };
  for (const el of document.querySelectorAll("footer button")) el.hidden = visibility[el.dataset.page] === false;
  for (const [page, visible] of Object.entries(visibility)) $("setting-" + page).checked = visible;
  if (visibility[currentPage === "send-editor" ? "send" : currentPage] === false) show(unlocked ? "vault" : "locked");
}
api.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.preferences) return;
  preference = { ...preference, ...changes.preferences.newValue };
  applyTheme(preference.theme); applyTabs();
});
function clearVault() {
  faviconObserver.disconnect();
  ++epoch; currentItem = null; currentDetail = null;
  for (const id of ["items", "suggestions", "detail-content", "edit-fields", "custom-fields", "audit-results", "approval-items", "send-items"]) $(id).replaceChildren();
  $("send-file").value = "";
  for (const id of ["unlock-password", "approval-password", "generated", "edit-name", "edit-folder", "edit-uris", "edit-notes", "send-name", "send-text", "send-notes", "send-password"]) $(id).value = "";
}
function selectOptions(id, values, label) {
  const selected = $(id).value;
  $(id).replaceChildren(new Option(label, ""), ...values.map(v => new Option(typeof v === "string" ? v : v.name, typeof v === "string" ? v : v.id)));
  $(id).value = selected;
}
async function activeApproval() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  const requests = await request("pending");
  return requests.find(p => p.tabId === tab?.id)?.id || null;
}
async function finishApproval(text) {
  approvalId = null; message(text);
  if (document.documentElement.dataset.surface !== "window") window.close();
  else await refresh();
}
async function refresh() {
  loading(true);
  try {
  clearVault();
  const status = await request("status"); unlocked = status.unlocked;
  selectOptions("account", status.accounts, "Primary account");
  $("state").textContent = unlocked ? "Unlocked · shared rbw-agent" : "Locked";
  $("unlock").disabled = unlocked; $("lock").disabled = !unlocked;
  if (approvalId) { await showApproval(approvalId); return; }
  if (!unlocked) { show("locked"); return; }
  show("vault"); await search(); await suggestions();
  } finally { loading(false); }
}
async function search() {
  const current = ++epoch;
  const result = await request("search", { query: $("query").value, kind: $("kind").value, folder: $("folder").value, collection: $("collection").value, view: $("view").value });
  if (current !== epoch) return;
  selectOptions("folder", result.folders, "Folder"); selectOptions("collection", result.collections, "Collection");
  $("folder-list").replaceChildren(...result.folders.map(f => new Option(f)));
  const groups = new Map();
  for (const item of result.items) {
    const group = item.matched ? "Autofill suggestions" : item.type === "card" ? "Cards" : item.type === "identity" ? "Identities" : item.type === "secure_note" ? "Secure notes" : item.type === "ssh_key" ? "SSH keys" : "Logins";
    if (!groups.has(group)) groups.set(group, []); groups.get(group).push(item);
  }
  faviconObserver.disconnect(); $("items").replaceChildren();
  for (const [title, items] of groups) {
    $("items").append(element("h3", `${title} · ${items.length}`));
    for (const item of items) $("items").append(itemRow(item));
  }
  if (!result.items.length) $("items").append(element("p", "No items found.", "empty"));
  $("count").textContent = result.total > result.limit ? `${result.limit} of ${result.total} items. Narrow your search to see more.` : `${result.total} items`;
}
function actionButton(label, name, action, cls) {
  const el = button("", action, cls); el.append(icon(name), element("span", label)); el.title = label; el.setAttribute("aria-label", label); return el;
}
const faviconObserver = new IntersectionObserver(entries => {
  for (const entry of entries) if (entry.isIntersecting) {
    faviconObserver.unobserve(entry.target);
    const target = entry.target;
    request("favicon", { origin: target.dataset.origin }).then(value => {
      if (!value || !target.isConnected) return;
      const image = element("img"); image.alt = ""; image.src = value; image.width = 24; image.height = 24;
      image.onerror = () => target.replaceChildren(icon(target.dataset.fallback)); target.replaceChildren(image);
    }).catch(() => {});
  }
}, { root: document.querySelector("main"), rootMargin: "80px" });
function itemRow(item) {
  const row = element("article"); const image = element("span", null, "item-icon");
  image.dataset.fallback = item.passkeys ? "key" : icons[item.type]; image.append(icon(image.dataset.fallback)); row.append(image);
  if (preference.favicons && item.iconOrigin) { image.dataset.origin = item.iconOrigin; faviconObserver.observe(image); }
  const main = button("", async () => { if (item.deleted) return; await openDetail(item.id); }, "item-main");
  const title = element("div", null, "item-title");
  if (item.favorite) { const star = icon("star"); star.classList.add("favorite-icon"); title.append(star); }
  title.append(element("strong", item.name)); main.append(title, element("small", item.username || labels[item.type])); row.append(main);
  const actions = element("div", null, "item-actions");
  if (item.deleted) actions.append(button("Restore", async () => { await request("mutate", { item: item.id, mutation: "restore" }); await search(); }));
  else {
    if (item.matched || ["card", "identity"].includes(item.type)) { const fill = actionButton("Fill", "fill", async () => { const n = await request("fill", { item: item.id, type: item.type }); message(`Filled ${n} fields. Submit the form when ready.`); }); fill.title = "Fill"; fill.setAttribute("aria-label", `Fill ${item.name}`); actions.append(fill); }
    const field = item.type === "login" ? "password" : item.type === "card" ? "number" : item.type === "identity" ? "email" : item.type === "ssh_key" ? "public_key" : "notes";
    const copy = actionButton("Copy", "copy", () => copyField(item.id, field)); copy.title = "Copy"; copy.setAttribute("aria-label", `Copy ${field}`); actions.append(copy);
    const menu = element("details", null, "menu"); const summary = element("summary"); summary.append(icon("more")); summary.setAttribute("aria-label", `Actions for ${item.name}`); menu.append(summary);
    const entries = element("div");
    entries.append(actionButton("View item", "note", () => openDetail(item.id)), actionButton("Edit", "edit", async () => { await openDetail(item.id); editItem(); }));
    if (item.type === "login") for (const [label, field] of [["Copy username", "username"], ["Copy password", "password"], ["Copy verification code", "totp"]]) entries.append(button(label, () => copyField(item.id, field)));
    entries.append(actionButton(item.favorite ? "Remove favorite" : "Favorite", "star", async () => { await request("mutate", { item: item.id, mutation: "favorite" }); await search(); }),
      actionButton(item.archived ? "Unarchive" : "Archive", "archive", async () => { await request("mutate", { item: item.id, mutation: "archive" }); await search(); }),
      actionButton("Move to trash", "trash", async () => { if (!confirm("Move this item to trash?")) return; await request("mutate", { item: item.id, mutation: "delete" }); await search(); }, "danger"));
    menu.append(entries); actions.append(menu);
  }
  row.append(actions); return row;
}
async function copyField(item, field) { await request("copy", { item, field }); message("Copied. rbw clipboard clearing policy applies."); }
function detailField(label, value, item, field, hidden = false) {
  const section = element("div", null, "field"); section.append(element("span", label));
  const row = element("div", null, "field-value"); const input = element("input"); input.readOnly = true; input.value = value; input.type = hidden ? "password" : "text"; input.setAttribute("aria-label", label); row.append(input);
  if (hidden) row.append(button("Show", async () => { input.type = input.type === "password" ? "text" : "password"; }));
  if (field) row.append(button("Copy", () => copyField(item, field)));
  section.append(row); return section;
}
function noteField(text, item) {
  const section = element("section", null, "field note-field"); const toolbar = element("div", null, "note-toolbar"); toolbar.append(element("strong", "Notes"));
  const content = element("div", null, "markdown"); let raw = false;
  const render = () => {
    if (raw) { content.replaceChildren(element("pre", text)); return; }
    const fragment = DOMPurify.sanitize(marked.parse(text, { gfm: true, breaks: true }), {
      RETURN_DOM_FRAGMENT: true, USE_PROFILES: { html: true }, FORBID_TAGS: ["img", "style", "form", "input", "button", "textarea", "select", "video", "audio", "source"], FORBID_ATTR: ["style", "id", "name", "src", "srcset", "background", "poster", "ping"],
    });
    for (const link of fragment.querySelectorAll("a")) {
      const href = link.getAttribute("href") || "";
      if (!/^(https?:|mailto:)/i.test(href)) { link.replaceWith(...link.childNodes); continue; }
      link.target = "_blank"; link.rel = "noopener noreferrer"; link.referrerPolicy = "no-referrer";
    }
    content.replaceChildren(fragment);
  };
  const toggle = button("Plain text", async () => { raw = !raw; toggle.textContent = raw ? "Markdown" : "Plain text"; render(); });
  toolbar.append(toggle, actionButton("Copy", "copy", () => copyField(item, "notes"))); section.append(toolbar, content); render(); return section;
}
async function openDetail(item) {
  const current = ++epoch;
  const detail = await request("detail", { item }); if (current !== epoch) return;
  currentItem = item; currentDetail = detail; show("detail");
  const content = $("detail-content"); content.replaceChildren(element("h2", detail.cipher.name));
  const data = detail.cipher.data;
  for (const [field, value] of Object.entries(data)) {
    if (["type", "uris", "fido2_credentials"].includes(field) || value == null || value === "") continue;
    content.append(detailField(field === "totp" ? "Authenticator key" : pretty(field), String(value), item, field, secret(field)));
  }
  if (data.totp) content.append(button("Copy verification code", () => copyField(item, "totp")));
  for (const uri of data.uris || []) content.append(detailField("Website", uri.uri, item));
  if (detail.cipher.notes) content.append(noteField(detail.cipher.notes, item));
  for (const [i, field] of (detail.cipher.fields || []).entries()) content.append(detailField(field.name || "Custom field", field.value || "", item, `custom/${i}`, field.type === "hidden"));
  for (const passkey of detail.passkeys) { content.append(element("h3", "Passkey"), element("p", `${passkey.rp} · ${passkey.user || ""}`), element("p", `Created ${passkey.created || "unknown"}`, "hint")); }
  if (detail.history.length) { const history = element("details"); history.append(element("summary", `Password history · ${detail.history.length}`)); for (const entry of detail.history) history.append(detailField(entry.last_used_date, entry.password, item, null, true)); content.append(history); }
  content.append(element("h3", "Attachments"));
  for (const attachment of detail.attachments) {
    const row = element("div", null, "field"); row.append(element("p", `${attachment.file_name || "Attachment"} · ${attachment.size_name || attachment.size || ""}`));
    row.append(button("Download", async () => { const result = await request("attachment_download", { item, attachment: attachment.id }); message(`Saved to ${result.path}`); }), button("Delete", async () => { if (!confirm("Delete this attachment permanently?")) return; await request("attachment_delete", { item, attachment: attachment.id }); await openDetail(item); }, "danger")); content.append(row);
  }
  const upload = element("input"); upload.type = "file"; upload.setAttribute("aria-label", "Upload attachment");
  upload.onchange = () => attempt(async () => {
    const file = upload.files[0]; if (!file) return;
    const token = await request("upload_begin", { item, name: file.name, size: file.size });
    try {
      for (let offset = 0; offset < file.size; offset += 192 * 1024) {
        const bytes = new Uint8Array(await file.slice(offset, offset + 192 * 1024).arrayBuffer());
        let text = ""; for (const byte of bytes) text += String.fromCharCode(byte);
        await request("upload_chunk", { token, offset, data: btoa(text) });
        message(`Uploading ${Math.round(Math.min(offset + bytes.length, file.size) / file.size * 100)}%…`);
      }
      await request("upload_finish", { token }); message("Attachment uploaded."); await openDetail(item);
    } finally { await request("upload_cancel", { token }).catch(() => {}); }
  }); content.append(upload);
  if (detail.collection_options?.length) {
    content.append(element("h3", "Collections"));
    const dropdown = element("details", null, "collection-picker"); const summary = element("summary");
    const updateSummary = () => { const count = dropdown.querySelectorAll("input:checked").length; summary.textContent = count ? `${count} collection${count === 1 ? "" : "s"} selected` : "Choose collections"; };
    dropdown.append(summary);
    for (const collection of detail.collection_options) {
      const label = element("label"); const input = element("input"); input.type = "checkbox"; input.value = collection.id; input.checked = detail.collection_ids.includes(collection.id); input.onchange = updateSummary; label.append(input, document.createTextNode(" " + collection.name)); dropdown.append(label);
    }
    updateSummary(); content.append(dropdown, actionButton("Save collections", "collections", async () => { await request("set_collections", { item, collections: Array.from(dropdown.querySelectorAll("input:checked"), input => input.value) }); message("Collections updated."); await openDetail(item); }));
  }
  $("favorite").replaceChildren(icon("star"), document.createTextNode(detail.favorite ? " Unfavorite" : " Favorite"));
  $("favorite").classList.toggle("is-favorite", detail.favorite);
  $("archive").replaceChildren(icon("archive"), document.createTextNode(detail.archived ? " Unarchive" : " Archive"));
}
function renderEditFields(data = {}) {
  const type = $("edit-type").value; $("edit-fields").replaceChildren();
  for (const name of schema[type]) {
    const label = element("label", pretty(name)); const input = element(name === "private_key" || name === "public_key" ? "textarea" : "input");
    input.id = `field-${name}`; input.value = data[name] || ""; input.autocomplete = "off"; input.spellcheck = false;
    if (input.tagName === "INPUT") input.type = secret(name) ? "password" : "text";
    label.append(input);
    if (name === "password") label.append(button("Generate password", async () => { input.value = await request("generate"); message("Generated password added to this form. Save to keep it."); }));
    $("edit-fields").append(label);
  }
  $("uri-label").hidden = type !== "login";
}
function addCustom(field = {}) {
  const row = element("div", null, "custom-row");
  const name = element("input"); name.placeholder = "Name / HTML id"; name.value = field.name || ""; name.setAttribute("aria-label", "Custom field name");
  const value = element("input"); value.placeholder = "Value"; value.value = field.value || ""; value.type = field.type === "hidden" ? "password" : "text"; value.setAttribute("aria-label", "Custom field value");
  const type = element("select"); for (const kind of ["text", "hidden", "boolean", "linked"]) type.append(new Option(kind, kind)); type.value = field.type || "text"; type.setAttribute("aria-label", "Custom field type");
  type.onchange = () => { value.type = type.value === "hidden" ? "password" : "text"; };
  row.append(name, value, type, button("×", async () => row.remove())); $("custom-fields").append(row);
}
function editItem(fresh = false) {
  if (fresh) { currentItem = null; currentDetail = null; }
  const cipher = currentDetail?.cipher || { name: "", data: { type: "login" } };
  $("edit-name").value = cipher.name; $("edit-folder").value = cipher.folder || ""; $("edit-notes").value = cipher.notes || "";
  $("edit-type").value = cipher.data.type; $("edit-type").disabled = !!currentDetail?.passkeys.length;
  $("edit-uris").value = (cipher.data.uris || []).map(uri => uri.uri).join("\n");
  $("custom-fields").replaceChildren(); for (const field of cipher.fields || []) addCustom(field);
  $("edit-passkeys").textContent = currentDetail?.passkeys.length ? "Existing passkeys are preserved by rbw. Their private keys never enter this editor." : "";
  renderEditFields(cipher.data); show("editor"); $("edit-name").focus();
}
$("edit-form").onsubmit = event => { event.preventDefault(); attempt(async () => {
  const type = $("edit-type").value; const data = { type };
  for (const name of schema[type]) data[name] = $(`field-${name}`).value || null;
  if (type === "login") data.uris = $("edit-uris").value.split("\n").map(uri => uri.trim()).filter(Boolean).map(uri => currentDetail?.cipher.data.uris?.find(old => old.uri === uri) || { uri });
  const fields = [...$("custom-fields").children].map(row => ({ name: row.children[0].value, value: row.children[1].value, type: row.children[2].value }));
  await request("save", { item: currentItem, revision: currentDetail?.revision, cipher: { name: $("edit-name").value, folder: $("edit-folder").value || null, notes: $("edit-notes").value || null, data, fields } });
  message("Saved and synchronized."); await refresh();
}); };
async function suggestions() {
  const area = $("suggestions"); area.replaceChildren();
  for (const pending of await request("pending")) area.append(button(`⚿ ${pending.method === "create" ? "Save passkey" : "Sign in"} · ${pending.origin}`, () => showApproval(pending.id)));
  for (const offer of await request("save_offers")) {
    const card = element("div", null, "field"); card.append(element("strong", `Save login for ${offer.origin}?`), element("p", offer.username || "No username"));
    card.append(button("Save new", async () => { await request("save_offer_apply", { tabId: offer.tabId }); await refresh(); }));
    const select = element("select"); select.append(new Option("Update an existing login…", ""));
    const logins = await request("search", { query: offer.username, kind: "login" });
    for (const item of logins.items) select.append(new Option(item.name, item.id));
    card.append(select, button("Update", async () => { if (!select.value) throw new Error("Choose an existing login."); await request("save_offer_apply", { tabId: offer.tabId, item: select.value }); await refresh(); }), button("Dismiss", async () => { await request("save_offer_dismiss", { tabId: offer.tabId }); await suggestions(); })); area.append(card);
  }
}
async function showApproval(id) {
  approvalId = id; show("approval"); $("approval-items").replaceChildren();
  const pending = (await request("pending")).find(p => p.id === id);
  if (!pending) { approvalId = null; message("Passkey request expired or completed."); show(unlocked ? "vault" : "locked"); return; }
  $("approval-title").textContent = pending.method === "create" ? "Save a passkey" : "Sign in with a passkey";
  $("approval-origin").textContent = pending.origin;
  $("approval-description").textContent = pending.method === "create" ? `Create a passkey for ${pending.user || "this account"}. Relying party: ${pending.rp}.` : `Choose a passkey for ${pending.rp}.`;
  $("approval-verify-label").hidden = !unlocked || pending.verification === "discouraged";
  $("approval-password").value = "";
  $("approval-verify-hint").textContent = pending.verification === "required" ? "This site requires master password verification before using the passkey." : "Optional. Leave blank for presence-only authentication, or verify with your master password.";
  if (!unlocked) { $("unlock-password").focus(); return; }
  const result = await request("passkey_choices", { request: id });
  const approve = async item => {
    const password = $("approval-password").value; $("approval-password").value = "";
    if (pending.verification === "required" && !password) { $("approval-password").focus(); throw new Error("Enter your master password to verify this passkey operation."); }
    message("Waiting for rbw…"); await request("passkey_approve", { request: id, item, password: password || null }); await finishApproval("Passkey request completed."); };
  if (pending.method === "create") $("approval-items").append(button("Create in a new login", () => approve(null), "primary"));
  for (const item of result.items) $("approval-items").append(button(`${pending.method === "create" ? "Add to" : "Use"} ${item.name} · ${item.username || ""}`, () => approve(item.id)));
  if (pending.method === "get" && !result.items.length) $("approval-items").append(element("p", "No matching passkeys in this account. Try another account or authenticator.", "hint"));
}
$("use-device").onclick = () => attempt(async () => { await request("passkey_decline", { request: approvalId, fallback: true }); await finishApproval("Passkey request declined."); });
$("cancel-passkey").onclick = () => attempt(async () => { await request("passkey_decline", { request: approvalId }); await finishApproval("Passkey request declined."); });
for (const action of ["unlock", "lock", "sync"]) $(action).onclick = () => attempt(async () => { message("Working…"); await request(action); message(""); await refresh(); });
$("unlock-form").onsubmit = event => {
  event.preventDefault();
  const password = $("unlock-password").value; $("unlock-password").value = "";
  attempt(async () => { message("Unlocking…"); await request("unlock", { password }); message(""); await refresh(); });
};
$("unlock-configured").onclick = $("unlock").onclick;
$("unlock").onclick = () => { show(approvalId ? "approval" : "locked"); $("account-menu").hidden = true; $("unlock-password").focus(); };
$("settings-sync").onclick = $("sync").onclick; $("settings-lock").onclick = $("lock").onclick;
$("account-toggle").onclick = () => { $("account-menu").hidden = !$("account-menu").hidden; };
$("account").onchange = () => attempt(async () => { await request("set_preferences", { preferences: { account: $("account").value } }); await refresh(); });
$("filter-toggle").onclick = () => { $("filters").hidden = !$("filters").hidden; };
$("query").oninput = () => { clearTimeout(timer); ++epoch; timer = setTimeout(() => attempt(search), 180); };
for (const id of ["kind", "view", "folder", "collection"]) $(id).onchange = () => attempt(search);
$("add").onclick = () => { if (currentPage === "send") editSend(); else editItem(true); }; $("edit").onclick = () => editItem(); $("edit-type").onchange = () => renderEditFields(); $("add-custom").onclick = () => addCustom();
$("cancel-edit").onclick = () => attempt(async () => { if (currentItem) await openDetail(currentItem); else await refresh(); });
$("back").onclick = () => attempt(async () => { if (currentPage === "editor" && currentItem) await openDetail(currentItem); else if (currentPage === "send-editor") await loadSends(); else await refresh(); });
for (const mutation of ["favorite", "archive", "delete"]) $(mutation).onclick = () => attempt(async () => {
  if (mutation === "delete" && !confirm("Move this item to trash? You can restore it from the Trash view.")) return;
  await request("mutate", { item: currentItem, mutation }); await refresh();
});
$("popout").onclick = () => api.windows.create({ url: api.runtime.getURL("popup.html?surface=window"), type: "popup", width: 460, height: 680 });
for (const el of document.querySelectorAll("footer button")) el.onclick = () => attempt(async () => {
  const page = el.dataset.page;
  if (page === "vault") await refresh(); else if (page === "send") await loadSends(); else show(page);
});
$("generate").onclick = () => attempt(async () => {
  const value = $("length").value;
  $("generated").value = await request("generate", { length: value ? Number(value) : null, passphrase: $("gen-mode").value === "passphrase", mode: $("gen-mode").value });
});
$("copy-generated").onclick = () => attempt(async () => { if (!$("generated").value) throw new Error("Generate a value first."); await request("copy_text", { text: $("generated").value }); message("Copied generated value with rbw clipboard clearing."); });
$("audit").onclick = () => attempt(async () => {
  message("Checking vault locally…"); const result = await request("audit");
  $("audit-results").replaceChildren(element("h3", `Reused passwords · ${result.reused.length} groups`));
  for (const group of result.reused) $("audit-results").append(element("p", group.join(", ")));
  $("audit-results").append(element("h3", `Passwords shorter than 12 characters · ${result.short.length}`));
  for (const name of result.short) $("audit-results").append(element("p", name));
  $("audit-results").append(element("p", `${result.without_totp} password logins have no TOTP saved. This does not indicate whether the site has other 2FA enabled.`, "hint")); message("");
});
$("open-sidebar").onclick = () => attempt(async () => {
  if (api.sidebarAction) await api.sidebarAction.open();
  else { const window = await api.windows.getCurrent(); await api.sidePanel.open({ windowId: window.id }); }
});
$("open-options").onclick = () => api.runtime.openOptionsPage();
function applyTheme(theme) { document.documentElement.dataset.theme = theme === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : theme; }
for (const id of ["setting-passkeys", "setting-save", "theme", "setting-generator", "setting-send", "setting-health", "setting-favicons"]) $(id).onchange = () => attempt(async () => {
  preference = await request("set_preferences", { preferences: { passkeys: $("setting-passkeys").checked, savePrompts: $("setting-save").checked, theme: $("theme").value, showGenerator: $("setting-generator").checked, showSend: $("setting-send").checked, showHealth: $("setting-health").checked, favicons: $("setting-favicons").checked } }); applyTheme(preference.theme); applyTabs();
});
setInterval(() => attempt(async () => {
  if (!approvalId) {
    const id = await activeApproval();
    if (id) { approvalId = id; await refresh(); return; }
  }
  const status = await request("status");
  if (!unlocked && status.unlocked) { await refresh(); return; }
  if (unlocked && !status.unlocked) { unlocked = false; clearVault(); show("locked"); message("Vault locked by rbw-agent."); }
}), 3000);
attempt(async () => {
  preference = await request("preferences"); applyTheme(preference.theme); applyTabs();
  $("setting-passkeys").checked = preference.passkeys; $("setting-save").checked = preference.savePrompts; $("theme").value = preference.theme; $("setting-favicons").checked = preference.favicons;
  if (!approvalId) approvalId = await activeApproval();
  // Populate the account selector before applying a remembered selection.
  const status = await request("status"); selectOptions("account", status.accounts, "Primary account"); $("account").value = preference.account;
  await refresh();
  const notice = await request("popup_notice");
  if (notice && !approvalId) message(notice.text, notice.error);
});

async function send(method, data = {}) { return request("send", { method, data }); }
async function loadSends() {
  show("send"); message("Loading Sends…");
  const items = await send("list"); $("send-items").replaceChildren();
  for (const item of items) {
    const row = element("article"); row.append(element("span", item.type === 1 ? "▤" : "➤", "item-icon"));
    const main = button("", async () => editSend(await send("detail", { id: item.id })), "item-main");
    main.append(element("strong", item.name), element("small", `${item.disabled ? "Disabled · " : ""}${item.accessCount || 0} accesses · ${item.deletionDate?.slice(0, 10) || ""}`)); row.append(main);
    row.append(button("Copy link", async () => { await send("copy", { id: item.id }); message("Send link copied using rbw clipboard settings."); }));
    row.append(button("×", async () => { if (!confirm("Permanently delete this Send?")) return; await send("delete", { id: item.id }); await loadSends(); }, "danger"));
    if (item.hasPassword) row.append(button("Remove password", async () => { if (!confirm("Remove this Send’s access password?")) return; await send("remove_password", { id: item.id }); await loadSends(); }));
    $("send-items").append(row);
  }
  if (!items.length) $("send-items").append(element("p", "No Sends yet. Choose Add to share encrypted text or a file.", "empty")); message("");
}
function editSend(item = null) {
  sendId = item?.id || null;
  for (const [id, value] of [["send-name", item?.name], ["send-text", item?.text], ["send-notes", item?.notes], ["send-password", ""], ["send-max", item?.maxAccessCount], ["send-expiration", item?.expirationDate ? new Date(new Date(item.expirationDate).getTime() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : ""]]) $(id).value = value || "";
  $("send-file").value = ""; $("send-file").disabled = !!item; $("send-text").disabled = item?.type === 1;
  $("send-days").disabled = !!item; $("send-days").value = 7;
  $("send-hidden").checked = !!item?.hidden; $("send-hide-email").checked = item?.hideEmail !== false; $("send-disabled").checked = !!item?.disabled;
  show("send-editor");
}
$("refresh-sends").onclick = () => attempt(loadSends); $("cancel-send").onclick = () => attempt(loadSends);
$("send-form").onsubmit = event => { event.preventDefault(); attempt(async () => {
  let token;
  try {
    const file = $("send-file").files[0];
    if (file) {
      token = await request("upload_begin", { item: "", name: file.name, size: file.size });
      for (let offset = 0; offset < file.size; offset += 192 * 1024) {
        const bytes = new Uint8Array(await file.slice(offset, offset + 192 * 1024).arrayBuffer());
        let text = ""; for (const byte of bytes) text += String.fromCharCode(byte);
        await request("upload_chunk", { token, offset, data: btoa(text) }); message("Uploading file to rbw…");
      }
    }
    const password = $("send-password").value; $("send-password").value = "";
    await send("save", { id: sendId, name: $("send-name").value, text: $("send-text").value, notes: $("send-notes").value, password, days: Number($("send-days").value), maxAccessCount: $("send-max").value ? Number($("send-max").value) : null, expirationDate: $("send-expiration").value ? new Date($("send-expiration").value).toISOString() : null, hidden: $("send-hidden").checked, hideEmail: $("send-hide-email").checked, disabled: $("send-disabled").checked, file_token: token || null });
    $("send-text").value = ""; $("send-notes").value = ""; $("send-file").value = ""; await loadSends(); message("Send saved.");
  } finally { if (token) await request("upload_cancel", { token }).catch(() => {}); }
}); };
