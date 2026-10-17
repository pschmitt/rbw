if (new URLSearchParams(location.search).get("surface") === "window") document.documentElement.dataset.surface = "window";
const api = globalThis.browser || chrome;
const $ = id => document.getElementById(id);
for (const label of document.querySelectorAll("[data-extension-version]")) {
  label.textContent = `v${api.runtime.getManifest().version}`;
  label.title = "Loaded rbw extension version";
}
const labels = { login: "Login", card: "Card", identity: "Identity", secure_note: "Secure note", ssh_key: "SSH key" };
const icons = { login: "key", card: "card", identity: "identity", secure_note: "note", ssh_key: "terminal" };
function getCardBrandIcon(brand, name = "") {
  const str = `${brand || ""} ${name || ""}`.toLowerCase();
  if (str.includes("visa")) return "visa";
  if (str.includes("master") || str.includes("mc")) return "mastercard";
  if (str.includes("amex") || str.includes("american express")) return "amex";
  return "card";
}
for (const el of document.querySelectorAll("[data-icon]")) el.replaceChildren(icon(el.dataset.icon));
const schema = {
  login: ["username", "password", "totp"],
  card: ["cardholder_name", "number", "brand", "exp_month", "exp_year", "code"],
  identity: ["title", "first_name", "middle_name", "last_name", "address1", "address2", "address3", "city", "state", "postal_code", "country", "phone", "email", "username", "ssn", "license_number", "passport_number"],
  secure_note: [], ssh_key: ["public_key", "fingerprint", "private_key"],
};
const secret = name => ["password", "totp", "code", "number", "ssn", "license_number", "passport_number", "private_key"].includes(name);
let sendId = null;
let totpTimer;
function stopTotp() { clearTimeout(totpTimer); }
let epoch = 0, timer, currentPage = "vault", currentItem = null, currentDetail = null, unlocked = false, preference = {}, approvalId = new URLSearchParams(location.search).get("request");
let loadingRequests = 0, loadingTimer, notificationTimer, stateTimer, ready = false;
const filterIds = ["query", "kind", "folder", "collection", "view"];
function remember() {
  if (!ready || !unlocked || approvalId || ["approval", "locked"].includes(currentPage)) return;
  const page = currentPage === "editor" ? (currentItem ? "detail" : "vault") : currentPage === "send-editor" ? "send" : currentPage;
  const state = { page, item: currentItem, expanded: !$("filters").hidden, scroll: document.querySelector("main").scrollTop,
    filters: Object.fromEntries(filterIds.map(id => [id, $(id).value])) };
  request("save_popup_state", { state }).catch(() => {});
}
function loading(active) {
  loadingRequests = Math.max(0, loadingRequests + (active ? 1 : -1));
  clearTimeout(loadingTimer);
  if (!loadingRequests) $("loading").hidden = true;
  else loadingTimer = setTimeout(() => { $("loading").hidden = false; }, 150);
  document.querySelector("main").setAttribute("aria-busy", String(!!loadingRequests));
}
window.addEventListener("pagehide", remember);
document.addEventListener("visibilitychange", () => { if (document.hidden) remember(); });
document.querySelector("main").addEventListener("scroll", () => { clearTimeout(stateTimer); stateTimer = setTimeout(remember, 80); }, { passive: true });
async function request(action, values = {}) {
  const busy = !["preferences", "pending", "save_offers", "popup_notice", "status", "favicon", "popup_state", "save_popup_state", "totp"].includes(action);
  if (busy) loading(true);
  try {
    const response = await api.runtime.sendMessage({ action, account: $("account").value, ...values });
    if (response?.error) throw new Error(response.error);
    if (!response) throw new Error("Extension background unavailable.");
    return response.result;
  } finally { if (busy) loading(false); }
}
function message(text, error = false) {
  clearTimeout(notificationTimer);
  if (!error && /^(Working|Unlocking|Waiting for rbw|Checking vault locally|Loading Sends|Uploading)/.test(text)) return;
  $("message-text").textContent = text;
  $("message").hidden = !text;
  $("message").classList.toggle("is-error", error);
  $("message").setAttribute("role", error ? "alert" : "status");
  if (text && !error) notificationTimer = setTimeout(() => { $("message").hidden = true; }, 4500);
}
$("dismiss-message").onclick = () => message("");
async function attempt(fn) { try { await fn(); } catch (error) {
  if (error.message.startsWith("Browser access denied.")) {
    unlocked = false; clearVault(); show("locked");
    $("unlock-panel").hidden = true; $("locked").hidden = true;
  }
  message(error.message, true);
} }
function element(tag, text, cls) { const el = document.createElement(tag); if (text != null) el.textContent = text; if (cls) el.className = cls; return el; }
function button(label, action, cls) { const el = element("button", label, cls); el.type = "button"; el.onclick = () => attempt(async () => { el.disabled = true; try { await action(); } finally { el.disabled = false; } }); return el; }
function actionButton(label, name, action, cls) {
  const el = button("", action, cls); el.append(icon(name)); if (label && !cls?.split(" ").includes("icon")) el.append(element("span", label)); el.title = label; el.setAttribute("aria-label", label); return el;
}
function pretty(value) { return value.replaceAll("_", " ").replace(/^./, c => c.toUpperCase()); }
function show(page) {
  stopTotp();
  remember();
  currentPage = page;
  const subpage = ["detail", "editor", "send-editor"].includes(page);
  $("back").hidden = !subpage;
  $("account-toggle").classList.toggle("is-subpage", subpage);
  $("account-toggle").setAttribute("aria-label", subpage ? "Back" : "Account menu");
  $("account-toggle").title = `${subpage ? "Back" : "Account menu"} · Double-click to open in a window`;
  $("unlock-panel").hidden = unlocked || !["locked", "approval"].includes(page);
  for (const id of ["vault", "generator", "send", "send-editor", "health", "settings", "detail", "editor", "approval", "locked"]) $(id).hidden = id !== page;
  $("title").textContent = ({ vault: "Vault", generator: "Generator", health: "Vault health", settings: "Settings", send: "Send", "send-editor": "Edit Send", detail: "Item", editor: currentItem ? "Edit item" : "New item", approval: "Passkey", locked: "Vault" })[page];
  $("add").hidden = !["vault", "send"].includes(page) || !unlocked;
  $("detail-header-actions").hidden = page !== "detail";
  $("edit-header-actions").hidden = page !== "editor";
  $("send-header-actions").hidden = page !== "send-editor";
  document.querySelectorAll("footer button").forEach(el => el.classList.toggle("selected", el.dataset.page === page));
  document.querySelector("main").scrollTop = 0;
  remember();
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
  stopTotp();
  faviconObserver.disconnect();
  ++epoch; currentItem = null; currentDetail = null;
  for (const id of ["items", "suggestions", "detail-content", "edit-fields", "custom-fields", "edit-attachments", "audit-results", "approval-items", "send-items"]) $(id).replaceChildren();
  $("send-file").value = "";
  for (const id of ["unlock-password", "approval-password", "generated", "edit-name", "edit-folder", "edit-uris", "edit-notes", "send-name", "send-text", "send-notes", "send-password"]) $(id).value = "";
}
function selectOptions(id, values, label) {
  const selected = $(id).value;
  $(id).replaceChildren(new Option(label, ""), ...values.map(v => new Option(typeof v === "string" ? v : v.name, typeof v === "string" ? v : v.id)));
  $(id).value = selected;
}
function renderAccounts(accounts, primary, chosen) {
  const select = $("account");
  const active = chosen || preference.account || primary || (accounts[0] || "");
  select.replaceChildren(...accounts.map(name => {
    const isPrimary = name === primary;
    return new Option(isPrimary ? `${name} *` : name, name);
  }));
  select.value = active;
  preference.account = select.value;
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
async function refresh(knownStatus = null, skipList = false) {
  loading(true);
  try {
  clearVault();
  const status = knownStatus || await request("status"); unlocked = status.unlocked;
  renderAccounts(status.accounts || [], status.primary, preference.account);
  $("state").textContent = unlocked ? "Unlocked · shared rbw-agent" : "Locked";
  $("unlock").disabled = unlocked; $("lock").disabled = !unlocked;
  if (approvalId) { await showApproval(approvalId); return; }
  if (!unlocked) { show("locked"); return; }
  show("vault"); if (!skipList) { await search(); await suggestions(); }
  remember();
  } finally { loading(false); }
}
async function search() {
  const current = ++epoch;
  const filters = { query: $("query").value, kind: $("kind").value, folder: $("folder").value, collection: $("collection").value, view: $("view").value };
  const snapshot = await request("search", { ...filters, snapshot: true });
  if (current !== epoch) return;
  if (snapshot) renderSearch(snapshot);
  const result = await request("search", filters);
  if (current !== epoch) return;
  renderSearch(result); remember();
}
function renderSearch(result) {
  selectOptions("folder", result.folders, "Folder"); selectOptions("collection", result.collections, "Collection");
  $("folder-list").replaceChildren(...result.folders.map(f => new Option(f)));
  const favorites = $("view").value === "favorites" || ($("view").value === "home" && !$("query").value);
  const sections = [
    ["suggestions", "Autofill suggestions"], ["card", "Cards"], ["login", "Logins"],
    ["secure_note", "Secure notes"], ["identity", "Identities"], ["ssh_key", "SSH keys"],
  ];
  const groups = new Map(sections.map(([key]) => [key, []]));
  for (const item of result.items) (groups.get(item.matched ? "suggestions" : item.type) || groups.get("login")).push(item);
  faviconObserver.disconnect(); $("items").replaceChildren();
  for (const [key, title] of sections) {
    const items = groups.get(key); if (!items.length) continue;
    const heading = favorites && key !== "suggestions" ? `Favorite ${key === "ssh_key" ? "SSH keys" : title.toLowerCase()}` : title;
    $("items").append(element("h3", `${heading} · ${items.length}`));
    for (const item of items) $("items").append(itemRow(item));
  }
  if (!result.items.length) $("items").append(element("p", "No items found.", "empty"));
  $("count").textContent = result.total > result.limit ? `${result.limit} of ${result.total} items. Narrow your search to see more.` : `${result.total} items`;
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
  const fallback = item.type === "card"
    ? getCardBrandIcon(item.brand || item.username?.split(",")?.[0], item.name)
    : (item.passkeys ? "key" : (icons[item.type] || "note"));
  image.dataset.fallback = fallback; image.append(icon(fallback)); row.append(image);
  if (preference.favicons && item.iconOrigin) { image.dataset.origin = item.iconOrigin; faviconObserver.observe(image); }
  const main = button("", async () => { if (item.deleted) return; await openDetail(item.id); }, "item-main");
  const title = element("div", null, "item-title");
  if (item.favorite) { const star = icon("star"); star.classList.add("favorite-icon"); title.append(star); }
  title.append(element("strong", item.name)); main.append(title, element("small", item.username || labels[item.type])); row.append(main);
  const actions = element("div", null, "item-actions");
  if (item.deleted) actions.append(actionButton("Restore", "archive", async () => { await request("mutate", { item: item.id, mutation: "restore" }); await search(); }));
  else {
    if (item.matched || ["card", "identity"].includes(item.type)) { const fill = actionButton("Fill", "fill", async () => { const n = await request("fill", { item: item.id, type: item.type }); message(`Filled ${n} fields. Submit the form when ready.`); }); fill.title = "Fill"; fill.setAttribute("aria-label", `Fill ${item.name}`); actions.append(fill); }
    const field = item.type === "login" ? "password" : item.type === "card" ? "number" : item.type === "identity" ? "email" : item.type === "ssh_key" ? "public_key" : "notes";
    const copy = actionButton("Copy", "copy", () => copyField(item.id, field, true)); copy.title = "Copy"; copy.setAttribute("aria-label", `Copy ${field}`); actions.append(copy);
    const menu = element("details", null, "menu"); const summary = element("summary"); summary.append(icon("more")); summary.setAttribute("aria-label", `Actions for ${item.name}`); menu.append(summary);
    const entries = element("div");
    entries.append(actionButton("View item", "note", () => openDetail(item.id)), actionButton("Edit", "edit", async () => { await openDetail(item.id); editItem(); }));
    if (item.type === "login") {
      entries.append(
        actionButton("Copy username", "identity", () => copyField(item.id, "username")),
        actionButton("Copy password", "key", () => copyField(item.id, "password")),
        actionButton("Copy verification code", "generator", () => copyField(item.id, "totp"))
      );
    }
    entries.append(actionButton(item.favorite ? "Remove favorite" : "Favorite", "star", async () => { await request("mutate", { item: item.id, mutation: "favorite" }); await search(); }),
      actionButton(item.archived ? "Unarchive" : "Archive", "archive", async () => { await request("mutate", { item: item.id, mutation: "archive" }); await search(); }),
      actionButton("Move to trash", "trash", async () => { if (!confirm("Move this item to trash?")) return; await request("mutate", { item: item.id, mutation: "delete" }); await search(); }, "danger"));
    menu.append(entries); actions.append(menu);
  }
  row.append(actions); return row;
}
async function copyField(item, field, allowFallback = false) {
  try {
    await request("copy", { item, field });
    message("Copied to clipboard.");
  } catch (err) {
    if (!allowFallback) throw err;
    if (field === "notes") {
      try {
        await request("copy", { item, field: "custom/0" });
        message("Copied to clipboard.");
        return;
      } catch (_) {}
    } else if (field === "password") {
      for (const alt of ["totp", "username", "custom/0"]) {
        try {
          await request("copy", { item, field: alt });
          message(`Copied ${alt === "totp" ? "verification code" : alt === "username" ? "username" : "field"} to clipboard.`);
          return;
        } catch (_) {}
      }
    }
    throw err;
  }
}
function detailField(label, value, item, field, hidden = false, isUrl = false) {
  const section = element("div", null, "field"); section.append(element("span", label));
  const row = element("div", null, "field-value");
  let input, textDisplay;
  if (hidden) {
    input = element("input"); input.readOnly = true; input.value = value; input.type = "password"; input.setAttribute("aria-label", label); row.append(input);
  } else {
    textDisplay = element("div", value, "field-text-wrapped"); textDisplay.setAttribute("aria-label", label); textDisplay.tabIndex = 0; row.append(textDisplay);
  }
  const actions = element("div", null, "field-actions");
  if (hidden) {
    let revealed = false;
    const showBtn = actionButton("Show", "eye", () => {
      revealed = !revealed;
      if (revealed) {
        showBtn.replaceChildren(icon("eye-off")); showBtn.title = "Hide"; showBtn.setAttribute("aria-label", "Hide");
        if (input) input.hidden = true;
        if (!textDisplay) { textDisplay = element("div", value, "field-text-wrapped"); textDisplay.tabIndex = 0; row.prepend(textDisplay); }
        else textDisplay.hidden = false;
      } else {
        showBtn.replaceChildren(icon("eye")); showBtn.title = "Show"; showBtn.setAttribute("aria-label", "Show");
        if (textDisplay) textDisplay.hidden = true;
        if (input) input.hidden = false;
      }
    }, "icon");
    actions.append(showBtn);
  }
  if (isUrl && value && /^https?:\/\//i.test(value)) {
    const visitBtn = actionButton("Visit website", "popout", () => { api.tabs.create({ url: value }); }, "icon");
    actions.append(visitBtn);
  }
  if (field) {
    const copyBtn = actionButton("Copy", "copy", () => copyField(item, field), "icon");
    actions.append(copyBtn);
  }
  row.append(actions); section.append(row); return section;
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
  const toggle = actionButton("Plain text", "note", async () => { raw = !raw; toggle.replaceChildren(icon("note"), element("span", raw ? "Markdown" : "Plain text")); render(); });
  toolbar.append(toggle, actionButton("Copy", "copy", () => copyField(item, "notes"))); section.append(toolbar, content); render(); return section;
}
function totpField(item) {
  const section = element("div", null, "field totp-field"); section.append(element("span", "Verification code"));
  const row = element("div", null, "field-value"); const code = element("div", "••• •••", "totp-code");
  const actions = element("div", null, "field-actions");
  const copy = actionButton("Copy verification code", "copy", () => copyField(item, "totp"), "icon"); copy.disabled = true;
  actions.append(copy); row.append(code, actions);
  const countdown = element("small", "Generating code…", "hint"); const progress = element("progress"); progress.setAttribute("aria-label", "Verification code validity");
  section.append(row, countdown, progress);
  let state;
  const current = () => section.isConnected && currentPage === "detail" && currentItem === item && unlocked;
  const tick = async () => {
    if (!current()) return;
    if (document.hidden) { totpTimer = setTimeout(tick, 1000); return; }
    try {
      if (!state || state.expiresAt * 1000 <= Date.now()) {
        copy.disabled = true; code.textContent = "••• •••";
        state = await request("totp", { item });
        if (!current()) return;
        code.textContent = /^\d{6}$/.test(state.code) ? `${state.code.slice(0, 3)} ${state.code.slice(3)}` : state.code;
        copy.disabled = false;
      }
      const remaining = Math.max(0, Math.ceil(state.expiresAt - Date.now() / 1000));
      countdown.textContent = `${remaining}s remaining`; progress.max = state.period; progress.value = remaining;
    } catch (_) {
      if (!current()) return;
      state = null; code.textContent = "Unavailable"; copy.disabled = true; countdown.textContent = "Could not generate verification code.";
    }
    if (current()) totpTimer = setTimeout(tick, state ? 500 : 3000);
  };
  // The detail DOM is attached by the caller in the current task.
  totpTimer = setTimeout(tick, 0); return section;
}
function revealButton(input) {
  const toggle = actionButton("Show", "eye", () => {
    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";
    toggle.replaceChildren(icon(reveal ? "eye-off" : "eye"));
    toggle.title = reveal ? "Hide" : "Show"; toggle.setAttribute("aria-label", toggle.title); toggle.setAttribute("aria-pressed", String(reveal));
  }, "icon reveal-secret"); toggle.setAttribute("aria-controls", input.id); toggle.setAttribute("aria-pressed", "false"); return toggle;
}
async function openDetail(item) {
  const current = ++epoch;
  const detail = await request("detail", { item }); if (current !== epoch) return;
  currentItem = item; currentDetail = detail; show("detail");
  const content = $("detail-content"); content.replaceChildren(element("h2", detail.cipher.name));
  const data = detail.cipher.data;
  for (const [field, value] of Object.entries(data)) {
    if (["type", "uris", "fido2_credentials", "totp"].includes(field) || value == null || value === "") continue;
    content.append(detailField(field === "totp" ? "Authenticator key" : pretty(field), String(value), item, field, secret(field)));
  }
  if (data.totp) content.append(totpField(item));
  for (const uri of data.uris || []) content.append(detailField("Website", uri.uri, item, null, false, true));
  if (detail.cipher.notes) content.append(noteField(detail.cipher.notes, item));
  for (const [i, field] of (detail.cipher.fields || []).entries()) content.append(detailField(field.name || "Custom field", field.value || "", item, `custom/${i}`, field.type === "hidden"));
  for (const passkey of detail.passkeys) { content.append(element("h3", "Passkey"), element("p", `${passkey.rp} · ${passkey.user || ""}`), element("p", `Created ${passkey.created || "unknown"}`, "hint")); }
  if (detail.history.length) { const history = element("details"); history.append(element("summary", `Password history · ${detail.history.length}`)); for (const [index, entry] of detail.history.entries()) history.append(detailField(entry.last_used_date, entry.password, item, `history/${index}`, true)); content.append(history); }
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
  $("header-favorite-label").textContent = detail.favorite ? "Unfavorite" : "Favorite";
  $("header-favorite").classList.toggle("is-favorite", detail.favorite);
  $("header-archive-label").textContent = detail.archived ? "Unarchive" : "Archive";
}
let attachmentBusy = false;
async function attachmentOperation(item, operation) {
  if (attachmentBusy) throw new Error("Wait for the current attachment operation to finish.");
  attachmentBusy = true; $("header-save-edit").disabled = true;
  try {
    await operation();
    const fresh = await request("detail", { item });
    if (currentPage !== "editor" || currentItem !== item) return;
    // Accept our attachment-only revision change, but preserve the guard if
    // another client also changed the editable fields while the editor was open.
    if (JSON.stringify(fresh.cipher) === JSON.stringify(currentDetail.cipher)) currentDetail = fresh;
    else message("This item changed elsewhere. Reload it before saving your edits.", true);
    renderAttachments(fresh, item);
  } finally { attachmentBusy = false; $("header-save-edit").disabled = false; }
}
function renderAttachments(detail, item) {
  const content = $("edit-attachments"); content.replaceChildren(element("h3", "Attachments"));
  if (!item) { content.append(element("p", "Save this item before adding attachments.", "hint")); return; }
  content.append(element("p", "Attachment changes are saved immediately.", "hint"));
  for (const attachment of detail.attachments || []) {
    const row = element("div", null, "field"); row.append(element("p", `${attachment.file_name || "Attachment"} · ${attachment.size_name || attachment.size || ""}`));
    const actions = element("div", null, "actions");
    actions.append(actionButton("Download", "download", async () => { const result = await request("attachment_download", { item, attachment: attachment.id }); message(`Saved to ${result.path}`); }), actionButton("Delete", "trash", async () => {
      if (!confirm("Delete this attachment permanently?")) return;
      await attachmentOperation(item, () => request("attachment_delete", { item, attachment: attachment.id }));
    }, "danger")); row.append(actions); content.append(row);
  }
  const upload = element("input"); upload.type = "file"; upload.hidden = true; upload.setAttribute("aria-label", "Upload attachment");
  upload.onchange = () => attempt(async () => {
    const file = upload.files[0]; if (!file) return;
    await attachmentOperation(item, async () => {
      const token = await request("upload_begin", { item, name: file.name, size: file.size });
      try {
        for (let offset = 0; offset < file.size; offset += 192 * 1024) {
          const bytes = new Uint8Array(await file.slice(offset, offset + 192 * 1024).arrayBuffer());
          let text = ""; for (const byte of bytes) text += String.fromCharCode(byte);
          await request("upload_chunk", { token, offset, data: btoa(text) });
        }
        await request("upload_finish", { token }); message("Attachment uploaded.");
      } finally { await request("upload_cancel", { token }).catch(() => {}); }
    });
  });
  content.append(upload, actionButton("Add attachment", "upload", () => upload.click()));
}
function renderEditFields(data = {}) {
  const type = $("edit-type").value; $("edit-fields").replaceChildren();
  for (const name of schema[type]) {
    const label = element("label", name === "totp" ? "Authenticator key" : pretty(name)); const input = element(name === "private_key" || name === "public_key" ? "textarea" : "input");
    input.id = `field-${name}`; input.value = data[name] || ""; input.autocomplete = "off"; input.spellcheck = false;
    if (input.tagName === "INPUT") input.type = secret(name) ? "password" : "text";
    if (input.type === "password") {
      const row = element("div", null, "editor-secret"); row.append(input, revealButton(input)); label.append(row);
    } else label.append(input);
    if (name === "password") label.append(actionButton("Generate password", "generator", async () => { input.value = await request("generate"); message("Generated password added to this form. Save to keep it."); }));
    $("edit-fields").append(label);
  }
  $("uri-label").hidden = type !== "login";
}
function addCustom(field = {}) {
  const card = element("div", null, "custom-card");
  const header = element("div", null, "custom-card-header");
  const nameLabel = element("label", null, "custom-name-label");
  nameLabel.append(element("span", "Field name / key", "custom-mini-label"));
  const name = element("input", null, "custom-name-input");
  name.placeholder = "e.g. PIN, ID Number, Secret";
  name.value = field.name || "";
  name.setAttribute("aria-label", "Custom field name");
  nameLabel.append(name);
  const removeBtn = actionButton("Remove field", "trash", () => card.remove(), "icon danger remove-custom-btn");
  header.append(nameLabel, removeBtn);

  const body = element("div", null, "custom-card-body");
  const valueLabel = element("label", null, "custom-value-label");
  valueLabel.append(element("span", "Value", "custom-mini-label"));
  const value = element("input", null, "custom-value-input");
  value.placeholder = "Value";
  value.value = field.value || "";
  value.type = field.type === "hidden" ? "password" : "text";
  value.setAttribute("aria-label", "Custom field value");
  value.id = `custom-secret-${crypto.randomUUID()}`;
  const valueRow = element("div", null, "editor-secret"); const reveal = revealButton(value); reveal.hidden = field.type !== "hidden";
  valueRow.append(value, reveal); valueLabel.append(valueRow);

  const typeLabel = element("label", null, "custom-type-label");
  typeLabel.append(element("span", "Type", "custom-mini-label"));
  const type = element("select", null, "custom-type-select");
  for (const kind of ["text", "hidden", "boolean", "linked"]) {
    type.append(new Option(kind.charAt(0).toUpperCase() + kind.slice(1), kind));
  }
  type.value = field.type || "text";
  type.setAttribute("aria-label", "Custom field type");
  type.onchange = () => { value.type = type.value === "hidden" ? "password" : "text"; reveal.hidden = type.value !== "hidden"; reveal.replaceChildren(icon("eye")); reveal.title = "Show"; reveal.setAttribute("aria-label", "Show"); reveal.setAttribute("aria-pressed", "false"); };
  typeLabel.append(type);

  body.append(valueLabel, typeLabel);
  card.append(header, body);
  $("custom-fields").append(card);
}
function editItem(fresh = false) {
  if (fresh) { currentItem = null; currentDetail = null; }
  const cipher = currentDetail?.cipher || { name: "", data: { type: "login" } };
  $("edit-name").value = cipher.name; $("edit-folder").value = cipher.folder || ""; $("edit-notes").value = cipher.notes || "";
  $("edit-type").value = cipher.data.type; $("edit-type").disabled = !!currentDetail?.passkeys.length;
  $("edit-uris").value = (cipher.data.uris || []).map(uri => uri.uri).join("\n");
  $("custom-fields").replaceChildren(); for (const field of cipher.fields || []) addCustom(field);
  $("edit-passkeys").textContent = currentDetail?.passkeys.length ? "Existing passkeys are preserved by rbw. Their private keys never enter this editor." : "";
  renderAttachments(currentDetail, currentItem);
  renderEditFields(cipher.data); show("editor"); $("edit-name").focus();
}
$("edit-form").onsubmit = event => { event.preventDefault(); attempt(async () => {
  if (attachmentBusy) throw new Error("Wait for the attachment operation to finish before saving.");
  const type = $("edit-type").value; const data = { type };
  for (const name of schema[type]) data[name] = $(`field-${name}`).value || null;
  if (type === "login") data.uris = $("edit-uris").value.split("\n").map(uri => uri.trim()).filter(Boolean).map(uri => currentDetail?.cipher.data.uris?.find(old => old.uri === uri) || { uri });
  const fields = [...$("custom-fields").children].map(card => ({
    name: card.querySelector(".custom-name-input")?.value || "",
    value: card.querySelector(".custom-value-input")?.value || "",
    type: card.querySelector(".custom-type-select")?.value || "text"
  }));
  await request("save", { item: currentItem, revision: currentDetail?.revision, cipher: { name: $("edit-name").value, folder: $("edit-folder").value || null, notes: $("edit-notes").value || null, data, fields } });
  message("Saved and synchronized."); await refresh();
}); };
async function suggestions() {
  const area = $("suggestions"); area.replaceChildren();
  for (const pending of await request("pending")) area.append(actionButton(`${pending.method === "create" ? "Save passkey" : "Sign in"} · ${pending.origin}`, "key", () => showApproval(pending.id)));
  for (const offer of await request("save_offers")) {
    const card = element("div", null, "field"); card.append(element("strong", `Save login for ${offer.origin}?`), element("p", offer.username || "No username"));
    card.append(actionButton("Save new", "plus", async () => { await request("save_offer_apply", { tabId: offer.tabId }); await refresh(); }));
    const select = element("select"); select.append(new Option("Update an existing login…", ""));
    const logins = await request("search", { query: offer.username, kind: "login" });
    for (const item of logins.items) select.append(new Option(item.name, item.id));
    card.append(select, actionButton("Update", "check", async () => { if (!select.value) throw new Error("Choose an existing login."); await request("save_offer_apply", { tabId: offer.tabId, item: select.value }); await refresh(); }), actionButton("Dismiss", "close", async () => { await request("save_offer_dismiss", { tabId: offer.tabId }); await suggestions(); })); area.append(card);
  }
}
async function showApproval(id) {
  approvalId = id; show("approval"); $("approval-items").replaceChildren();
  const pending = (await request("pending")).find(p => p.id === id);
  if (!pending) { approvalId = null; message("Passkey request expired or completed."); show(unlocked ? "vault" : "locked"); return; }
  const title = pending.method === "create" ? "Save a passkey" : "Sign in with a passkey";
  $("approval-title").textContent = title;
  $("approval-origin").textContent = pending.origin;
  $("approval-description").textContent = pending.method === "create" ? `Save a passkey for ${pending.user || "this account"} in your vault.` : "Choose an account to continue.";
  $("approval-verification").hidden = true; $("approval-items").hidden = false; $("approval-password").value = ""; $("approval-password").type = "password";
  $("approval-reveal").replaceChildren(icon("eye")); $("approval-reveal").title = "Show"; $("approval-reveal").setAttribute("aria-label", "Show");
  if (!unlocked) { $("unlock-password").focus(); return; }
  const result = await request("passkey_choices", { request: id });
  const complete = async (item, password = null) => {
    await request("passkey_approve", { request: id, item, password }); await finishApproval("Passkey request completed.");
  };
  const approve = async item => {
    if (pending.verification !== "required") { await complete(item); return; }
    // Required WebAuthn verification is a separate step after account selection.
    // An unlocked agent alone must never be reported as user verification.
    $("approval-items").hidden = true; $("approval-verification").hidden = false;
    $("approval-password").focus();
    $("approval-verification").onsubmit = event => {
      event.preventDefault(); const password = $("approval-password").value; $("approval-password").value = "";
      attempt(async () => { await complete(item, password); });
    };
  };
  $("approval-verify-back").onclick = () => { $("approval-password").value = ""; $("approval-verification").hidden = true; $("approval-items").hidden = false; };
  $("approval-reveal").onclick = () => { const input = $("approval-password"); const reveal = input.type === "password"; input.type = reveal ? "text" : "password"; $("approval-reveal").replaceChildren(icon(reveal ? "eye-off" : "eye")); $("approval-reveal").title = reveal ? "Hide" : "Show"; $("approval-reveal").setAttribute("aria-label", $("approval-reveal").title); };
  const choice = (name, username, item, create = false) => {
    const row = button("", () => approve(item), "passkey-choice");
    const emblem = element("span", null, "passkey-choice-icon"); emblem.append(icon(create ? "plus" : "key"));
    const text = element("span", null, "passkey-choice-text"); text.append(element("strong", name)); if (username) text.append(element("small", username));
    row.append(emblem, text, icon("fill")); return row;
  };
  if (pending.method === "create") $("approval-items").append(choice("Create a new login", pending.user || "Save in your vault", null, true));
  for (const item of result.items) $("approval-items").append(choice(item.name, item.username || (pending.method === "create" ? "Add to this login" : "Saved passkey"), item.id));
  if (pending.method === "get" && !result.items.length) {
    const empty = element("div", null, "passkey-empty"); empty.append(icon("key"), element("strong", "No saved passkey"), element("p", "Try another vault account or use a different authenticator.", "hint")); $("approval-items").append(empty);
  }
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
let accountMenuTimer;
$("account-toggle").onclick = event => {
  clearTimeout(accountMenuTimer);
  const toggle = () => { if (!$("back").hidden) attempt(navigateBack); else $("account-menu").hidden = !$("account-menu").hidden; };
  if (event.detail === 0) toggle();
  else if (event.detail === 1) accountMenuTimer = setTimeout(toggle, 250);
};
$("account-toggle").ondblclick = () => {
  clearTimeout(accountMenuTimer); $("account-menu").hidden = true; remember();
  attempt(async () => {
    await api.windows.create({ url: api.runtime.getURL("popup.html?surface=window"), type: "popup", width: 460, height: 680 });
    if (document.documentElement.dataset.surface !== "window") window.close();
  });
};
$("account").onchange = () => attempt(async () => { await request("set_preferences", { preferences: { account: $("account").value } }); await refresh(); });
$("filter-toggle").onclick = () => { $("filters").hidden = !$("filters").hidden; $("filter-toggle").setAttribute("aria-expanded", String(!$("filters").hidden)); remember(); };
$("query").oninput = () => { remember(); clearTimeout(timer); ++epoch; timer = setTimeout(() => attempt(search), 180); };
for (const id of ["kind", "view", "folder", "collection"]) $(id).onchange = () => { remember(); attempt(search); };
$("add").onclick = () => { if (currentPage === "send") editSend(); else editItem(true); };
$("header-edit").onclick = () => editItem();
$("header-favorite").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  await request("mutate", { item: currentItem, mutation: "favorite" });
  await openDetail(currentItem);
});
$("header-archive").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  await request("mutate", { item: currentItem, mutation: "archive" });
  await openDetail(currentItem);
});
$("header-delete").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  if (!confirm("Move this item to trash? You can restore it from the Trash view.")) return;
  await request("mutate", { item: currentItem, mutation: "delete" });
  await refresh();
});
$("header-cancel-edit").onclick = () => attempt(async () => {
  if (currentItem) await openDetail(currentItem);
  else await refresh();
});
$("header-save-edit").onclick = () => $("edit-form").requestSubmit();
$("header-cancel-send").onclick = () => attempt(loadSends);
$("header-save-send").onclick = () => $("send-form").requestSubmit();

$("edit-type").onchange = () => renderEditFields();
$("add-custom").onclick = () => addCustom();
async function navigateBack() { if (currentPage === "editor" && currentItem) await openDetail(currentItem); else if (currentPage === "send-editor") await loadSends(); else await refresh(); }
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
for (const id of ["setting-autofill", "setting-passkeys", "setting-save", "theme", "setting-generator", "setting-send", "setting-health", "setting-favicons"]) $(id).onchange = () => attempt(async () => {
  preference = await request("set_preferences", { preferences: { autoFill: $("setting-autofill").checked, passkeys: $("setting-passkeys").checked, savePrompts: $("setting-save").checked, theme: $("theme").value, showGenerator: $("setting-generator").checked, showSend: $("setting-send").checked, showHealth: $("setting-health").checked, favicons: $("setting-favicons").checked } }); applyTheme(preference.theme); applyTabs();
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
  loading(true);
  try {
    const initial = await request("bootstrap");
    preference = initial.preferences; applyTheme(preference.theme); applyTabs();
    $("setting-autofill").checked = preference.autoFill !== false;
    $("setting-passkeys").checked = preference.passkeys; $("setting-save").checked = preference.savePrompts; $("theme").value = preference.theme; $("setting-favicons").checked = preference.favicons;
    if (!approvalId) approvalId = await activeApproval();
    const status = initial.status;
    renderAccounts(status.accounts || [], status.primary, preference.account);
    const saved = status.unlocked && !approvalId ? initial.saved : null;
    if (saved) {
      for (const id of filterIds) {
        const value = saved.filters[id];
        if (value && ["folder", "collection"].includes(id)) $(id).append(new Option(value, value));
        $(id).value = value || (id === "view" ? "home" : "");
      }
      $("filters").hidden = !saved.expanded; $("filter-toggle").setAttribute("aria-expanded", String(saved.expanded));
    }
    await refresh(status, !!saved && saved.page !== "vault");
    if (saved && unlocked && !approvalId) {
      if (saved.page === "detail" && saved.item) await openDetail(saved.item);
      else if (saved.page === "send" && preference.showSend) await loadSends();
      else if (["settings", "generator", "health"].includes(saved.page)) {
        show(saved.page); applyTabs();
      }
      document.querySelector("main").scrollTop = saved.scroll;
    }
    ready = true; remember();
    const notice = await request("popup_notice");
    if (notice && !approvalId) message(notice.text, notice.error);
  } finally { loading(false); }
});

async function send(method, data = {}) { return request("send", { method, data }); }
async function loadSends() {
  show("send"); message("Loading Sends…");
  const items = await send("list"); $("send-items").replaceChildren();
  for (const item of items) {
    const row = element("article"); const image = element("span", null, "item-icon"); image.append(icon(item.type === 1 ? "note" : "send")); row.append(image);
    const main = button("", async () => editSend(await send("detail", { id: item.id })), "item-main");
    main.append(element("strong", item.name), element("small", `${item.disabled ? "Disabled · " : ""}${item.accessCount || 0} accesses · ${item.deletionDate?.slice(0, 10) || ""}`)); row.append(main);
    row.append(actionButton("Copy link", "copy", async () => { await send("copy", { id: item.id }); message("Send link copied using rbw clipboard settings."); }));
    row.append(actionButton("Delete", "trash", async () => { if (!confirm("Permanently delete this Send?")) return; await send("delete", { id: item.id }); await loadSends(); }, "danger"));
    if (item.hasPassword) row.append(actionButton("Remove password", "key", async () => { if (!confirm("Remove this Send’s access password?")) return; await send("remove_password", { id: item.id }); await loadSends(); }));
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
$("refresh-sends").onclick = () => attempt(loadSends);
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
