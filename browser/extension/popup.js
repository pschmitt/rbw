if (new URLSearchParams(location.search).get("surface") === "window") document.documentElement.dataset.surface = "window";
const api = globalThis.browser || chrome;
const $ = id => document.getElementById(id);
for (const label of document.querySelectorAll("[data-extension-version]")) {
  label.textContent = `v${api?.runtime?.getManifest?.()?.version || "0.2.27"}`;
  label.title = "Loaded rbw extension version";
}
const labels = { login: "Login", card: "Card", identity: "Identity", secure_note: "Secure note", ssh_key: "SSH key" };
const icons = { login: "key", card: "card", identity: "identity", secure_note: "note", ssh_key: "terminal" };
const cardFieldOrder = ["cardholder_name", "brand", "number", "exp_month", "exp_year", "code"];
const cardFieldLabels = {
  cardholder_name: "Cardholder",
  number: "Card number",
  exp_month: "Expiry month",
  exp_year: "Expiry year",
  code: "CVV",
};
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
  card: cardFieldOrder,
  identity: ["title", "first_name", "middle_name", "last_name", "address1", "address2", "address3", "city", "state", "postal_code", "country", "phone", "email", "username", "ssn", "license_number", "passport_number"],
  secure_note: [], ssh_key: ["public_key", "fingerprint", "private_key"],
};
const secret = name => ["password", "totp", "code", "number", "ssn", "license_number", "passport_number", "private_key"].includes(name);
let sendId = null;
let totpTimer;
function stopTotp() { clearTimeout(totpTimer); }
const initialSearch = new URLSearchParams(location.search).get("search");
const initialSettings = new URLSearchParams(location.search).get("settings") === "1";
const initialGenerator = new URLSearchParams(location.search).get("page") === "generator";
let epoch = 0, timer, currentPage = "vault", currentItem = null, currentDetail = null, detailFrom = null, healthScroll = 0, sendCount = 0, healthState = "idle", healthRun = 0, unlocked = false, preference = {}, approvalId = new URLSearchParams(location.search).get("request");
let accountNames = [], accountStates = [], allAccounts = [], cliAccountColors = {}, primaryAccount = "";
const colorOf = name => accountColor(name, allAccounts, preference.accountColors, cliAccountColors);
const needsPassword = new Set(); // locked accounts whose row shows a password field
let loadingRequests = 0, loadingTimer, notificationTimer, notificationLeaving, stateTimer, ready = false;
const filterIds = ["query", "kind", "folder", "collection", "view"];
function remember() {
  if (!ready || !unlocked || approvalId || initialSearch || ["approval", "locked", "diagnostic"].includes(currentPage)) return;
  const page = currentPage === "editor" ? (currentItem ? "detail" : "vault") : currentPage === "send-editor" ? "send" : currentPage;
  const state = { page, item: currentItem, expanded: !$("filters").hidden, scroll: document.querySelector("main").scrollTop,
    filters: Object.fromEntries(filterIds.map(id => [id, $(id).value])) };
  request("save_popup_state", { state }).catch(() => {});
}
function loading(active) {
  loadingRequests = Math.max(0, loadingRequests + (active ? 1 : -1));
  document.querySelector("main")?.setAttribute("aria-busy", String(!!loadingRequests));
}
function updateFab() {
  const main = document.querySelector("main");
  const fab = $("add");
  const threshold = fab.classList.contains("collapsed") ? 8 : 24;
  fab.classList.toggle("collapsed", main.scrollTop > threshold);
}
window.addEventListener("pagehide", remember);
document.addEventListener("visibilitychange", () => { if (document.hidden) remember(); });
document.querySelector("main").addEventListener("scroll", () => {
  for (const m of document.querySelectorAll("details.menu[open]")) m.open = false;
  updateFab();
  clearTimeout(stateTimer);
  stateTimer = setTimeout(remember, 80);
}, { passive: true });
async function request(action, values = {}) {
  const busy = !["preferences", "pending", "save_offers", "popup_notice", "passkey_sync_failure", "status", "favicon", "popup_state", "save_popup_state", "edit_draft", "save_edit_draft", "totp"].includes(action);
  if (busy) loading(true);
  try {
    const response = await api.runtime.sendMessage({ action, account: $("account").value, ...values });
    if (response?.error) {
      const error = new Error(response.error);
      if (response.diagnostic) error.diagnostic = response.diagnostic;
      throw error;
    }
    if (!response) throw new Error("Extension background unavailable.");
    return response.result;
  } finally { if (busy) loading(false); }
}
// An optional action ({ label, run }) adds a button and keeps the notification
// open until it is used or dismissed.
function message(text, error = false, action = null) {
  clearTimeout(notificationTimer);
  if (!error && /^(Working|Unlocking|Waiting for rbw|Checking vault locally|Loading Sends|Uploading)/.test(text)) return;
  const kind = error ? "error"
    : /^(Vault unlocked|Vault synced|Copied\b|Filled \d+ fields|Saved\b|Updated\b|Archived|Unarchived|Added to favorites|Removed from favorites|Moved to trash|Restored|Deleted|Collections updated|Attachment uploaded|Generated password (added|filled)|New password filled|Send link copied|Resumed your unsaved edit|Restarted from the current vault state)/i.test(text) ? "success"
      : /^(Vault locked|This item changed|Your unsaved edit|Passkey request expired)/i.test(text) ? "warning" : "info";
  const notification = $("message");
  notification.dataset.kind = kind;
  $("message-icon").replaceChildren(icon(kind === "success" ? "check" : kind === "info" ? "info" : "warning"));
  $("message-text").textContent = text;
  $("message-action").hidden = !action; $("message-action").textContent = action?.label || "";
  $("message-action").onclick = action ? () => { message(""); attempt(action.run); } : null;
  notification.classList.toggle("is-error", error);
  notification.setAttribute("role", error ? "alert" : "status");
  clearTimeout(notificationLeaving); notification.classList.remove("is-leaving");
  if (!text) { hideNotification(); return; }
  const appearing = notification.hidden;
  notification.hidden = false;
  notification.classList.remove("is-entering", "is-swapping");
  if (bannerAnimated()) { void notification.offsetWidth; notification.classList.add(appearing ? "is-entering" : "is-swapping"); }
  // The bar under the notice counts down the time it has left.
  notification.classList.remove("is-timed"); void notification.offsetWidth;
  if (!error && !action) { notification.classList.add("is-timed"); notificationTimer = setTimeout(hideNotification, 4500); }
}
// Notices are banners (like the locked-accounts one): they slide out when done.
function hideNotification() {
  const notification = $("message");
  if (notification.hidden) return;
  if (!bannerAnimated()) { notification.hidden = true; return; }
  notification.classList.add("is-leaving");
  clearTimeout(notificationLeaving); notificationLeaving = setTimeout(() => { notification.hidden = true; notification.classList.remove("is-leaving"); }, 330);
}
$("dismiss-message").onclick = () => message("");
async function attempt(fn) { try { await fn(); } catch (error) {
  if (error.diagnostic) { showDiagnostic(error.diagnostic, error.message); return; }
  if (error.message.startsWith("Browser access denied.")) {
    unlocked = false; clearVault(); show("locked");
    $("unlock-panel").hidden = true; $("locked").hidden = true;
  }
  if (error.message === "rbw does not fill passwords into insecure HTTP pages.") {
    message("HTTP is unencrypted. Change this in rbw settings.", true, { label: "Open settings", run: async () => show("settings") });
    return;
  }
  message(error.message, true);
} }
function showDiagnostic(diagnostic, summary) {
  const trace = {
    ...diagnostic,
    summary,
    extension: {
      id: api.runtime.id,
      version: api.runtime.getManifest()?.version || "unknown",
    },
    browser: navigator.userAgent,
    platform: navigator.platform,
  };
  $("diagnostic-summary").textContent = summary;
  $("diagnostic-trace").textContent = JSON.stringify(trace, null, 2);
  $("diagnostic-copy-status").textContent = "";
  show("diagnostic");
}
$("diagnostic-copy").onclick = () => {
  const trace = $("diagnostic-trace").textContent;
  const field = element("textarea");
  field.value = trace; field.setAttribute("readonly", "");
  field.style.position = "fixed"; field.style.opacity = "0";
  document.body.append(field); field.select();
  const copied = document.execCommand("copy"); field.remove();
  $("diagnostic-copy-status").textContent = copied ? "Diagnostic trace copied." : "Copy failed. Select the trace above and copy it manually.";
};
$("diagnostic-retry").onclick = () => window.location.reload();
function element(tag, text, cls) { const el = document.createElement(tag); if (text != null) el.textContent = text; if (cls) el.className = cls; return el; }
function button(label, action, cls) { const el = element("button", label, cls); el.type = "button"; el.onclick = () => attempt(async () => { el.disabled = true; try { await action(); } finally { el.disabled = false; } }); return el; }
function actionButton(label, name, action, cls) {
  const el = button("", action, cls); el.append(icon(name));
  // Copy buttons are never disabled while copying: spamming replays the confirmation.
  if (name === "copy") el.onclick = () => attempt(action);
  if (label && !cls?.split(" ").includes("icon")) el.append(element("span", label)); el.title = label; el.setAttribute("aria-label", label); return el;
}
function pretty(value) { return value.replaceAll("_", " ").replace(/^./, c => c.toUpperCase()); }
function countVisibleTabs() {
  const visibility = { generator: preference.showGenerator !== false, send: preference.showSend === true, health: preference.showHealth === true };
  let count = 0;
  for (const el of document.querySelectorAll("#title-dropdown button")) {
    if (el.dataset.tab === "vault" || visibility[el.dataset.tab] !== false) count++;
  }
  return count;
}
function updateTitleMenuState() {
  const isTopTab = ["vault", "generator", "send", "health"].includes(currentPage) && unlocked;
  const hasMultiple = countVisibleTabs() > 1 && isTopTab;
  $("title-chevron").hidden = !hasMultiple;
  $("title-menu").classList.toggle("is-disabled", !hasMultiple);
  if (!hasMultiple && $("title-menu").open) $("title-menu").open = false;
}
function show(page) {
  stopTotp();
  if (page === "vault") requestAnimationFrame(() => { if (currentPage === "vault" && !$("vault").hidden && document.activeElement?.closest?.("#vault") == null) $("query").focus({ preventScroll: true }); });
  // Resume and discard prompts only make sense inside the editor.
  if (currentPage === "editor" && page !== "editor") { forgetEditDraft(); if (!$("message-action").hidden) message(""); }
  if (currentPage !== page) { $("account-menu").hidden = true; $("account-details").open = false; }
  remember();
  currentPage = page; document.documentElement.dataset.page = page;
  if (!["detail", "editor"].includes(page)) detailFrom = null;
  if (page === "generator") { if (!generatedValue) regenerateSoon(); renderGeneratorSite().catch(() => {}); }
  else if (!$("gen-picker").hidden) closeGeneratorPicker();
  const subpage = ["detail", "editor", "send-editor", "settings", "diagnostic"].includes(page);
  $("back").hidden = !subpage;
  $("account-toggle").classList.toggle("is-subpage", subpage);
  $("account-toggle").setAttribute("aria-label", subpage ? "Back" : "Account menu");
  $("account-toggle").title = `${subpage ? "Back" : "Account menu"} · Double-click to open in a window`;
  $("unlock-panel").hidden = unlocked || !["locked", "approval"].includes(page);
  for (const id of ["vault", "generator", "send", "send-editor", "health", "settings", "detail", "editor", "approval", "locked", "diagnostic"]) $(id).hidden = id !== page;
  $("title").textContent = ({ vault: "Vault", generator: "Generator", health: "Vault health", settings: "Settings", send: "Send", "send-editor": "Edit Send", detail: "Item", editor: currentItem ? "Edit item" : "New item", approval: "Passkey request", locked: "Vault", diagnostic: "Connection problem" })[page];
  // The Send list only offers Add once it has entries; until it has loaded (or on a refresh) the last count decides, so the button doesn't flash.
  $("add").hidden = !["vault", "send"].includes(page) || !unlocked || (page === "send" && !sendCount);
  $("add").classList.remove("collapsed");
  $("open-options").hidden = subpage;
  $("detail-header-actions").hidden = page !== "detail";
  $("edit-header-actions").hidden = page !== "editor";
  $("send-header-actions").hidden = page !== "send-editor";
  $("send-list-header-actions").hidden = page !== "send";
  $("health-header-actions").hidden = page !== "health";
  // The check runs when the view opens; going back from an item keeps its results.
  if (page === "health" && healthState === "idle") attempt(runAudit);
  $("settings-header-actions").hidden = page !== "settings";
  if ($("title-menu").open) $("title-menu").open = false;
  const tab = ["detail", "editor", "approval", "locked", "diagnostic"].includes(page) ? "vault" : page === "send-editor" ? "send" : page;
  document.querySelectorAll("#title-dropdown button").forEach(el => {
    const selected = el.dataset.tab === tab; el.classList.toggle("selected", selected);
    if (selected) el.setAttribute("aria-current", "page"); else el.removeAttribute("aria-current");
  });
  updateTitleMenuState();
  document.querySelector("main").scrollTop = 0;
  remember();
}
function applyTabs() {
  const visibility = { generator: preference.showGenerator !== false, send: preference.showSend === true, health: preference.showHealth === true };
  for (const el of document.querySelectorAll("#title-dropdown button")) {
    el.hidden = el.dataset.tab !== "vault" && visibility[el.dataset.tab] === false;
  }
  for (const [page, visible] of Object.entries(visibility)) {
    const el = $("setting-" + page);
    if (el) el.checked = visible;
  }
  updateTitleMenuState();
  if (["generator", "send", "health"].includes(currentPage) && visibility[currentPage] === false) show(unlocked ? "vault" : "locked");
}
api?.storage?.onChanged?.addListener((changes, area) => {
  if (area !== "local" || !changes.preferences) return;
  preference = { ...preference, ...changes.preferences.newValue };
  applyTheme(preference.theme); applyTabs();
});
function clearVault() {
  vaultListed = false; stopTotp(); sendCount = 0; document.documentElement.removeAttribute("data-send-empty"); healthState = "idle"; ++healthRun;
  faviconObserver.disconnect();
  ++epoch; currentItem = null; currentDetail = null;
  for (const id of ["items", "suggestions", "detail-content", "edit-fields", "custom-fields", "edit-attachments", "edit-collections", "audit-results", "approval-items", "send-items"]) $(id).replaceChildren();
  $("send-file").value = "";
  generatedValue = ""; $("generated").replaceChildren(); closeGeneratorPicker(); delete $("generated").closest(".gen-card").dataset.strength;
  for (const id of ["unlock-password", "approval-password", "edit-name", "edit-folder", "edit-notes", "send-name", "send-text", "send-notes", "send-password"]) $(id).value = "";
}
// The filters are chips that open a menu. What a menu offers depends on the
// others: the account narrows the folders and collections to its own.
const VIEW_ICONS = { home: "home", vault: "grid", favorites: "star", archive: "archive", trash: "trash" };
const VIEWS = [["home", "Favorites + suggestions"], ["vault", "All items"], ["favorites", "Favorites"], ["archive", "Archive"], ["trash", "Trash"]];
const KINDS = [["", "All types"], ["login", "Login"], ["passkey", "Passkey"], ["card", "Card"], ["identity", "Identity"], ["secure_note", "Secure note"], ["ssh_key", "SSH key"]];
const filterInput = { view: "view", account: "account-filter", collection: "collection", folder: "folder", kind: "kind" };
const filterTitle = { view: "View", account: "Account", collection: "Collection", folder: "Folder", kind: "Type" };
const filterDefaults = { view: "home", account: "", collection: "", folder: "", kind: "" };
let facets = { folders: [], collections: [] }; // folders: {name, accounts}; collections: {id, name, account}
let openMenu = null;
const several = () => accountNames.length > 1;
// Entries of a chip's menu: {value, label, group, color, dots, indent}.
function menuEntries(filter) {
  const all = label => ({ value: "", label });
  if (filter === "view") return VIEWS.map(([value, label]) => ({ value, label }));
  if (filter === "kind") return KINDS.map(([value, label]) => ({ value, label }));
  if (filter === "account") return [all("All accounts"), ...accountNames.map(name => ({ value: name, label: name === primaryAccount ? `${name} *` : name, color: colorOf(name) }))];
  const byAccount = several() && !$("account-filter").value;
  if (filter === "folder") {
    const names = new Set(facets.folders.map(f => f.name));
    return [all("All folders"), ...[...facets.folders].sort((a, b) => a.name.localeCompare(b.name)).map(({ name, accounts }) => {
      const parts = name.split("/"); let depth = 0;
      for (let i = 1; i < parts.length; i++) if (names.has(parts.slice(0, i).join("/"))) depth = i;
      return { value: name, label: parts.slice(depth).join("/"), indent: depth, dots: byAccount ? accounts.map(account => colorOf(account)) : [] };
    })];
  }
  const sorted = [...facets.collections].sort((a, b) => a.name.localeCompare(b.name));
  const entries = [all("All collections")];
  const accounts = byAccount ? [...new Set(sorted.map(c => c.account))].sort() : [null];
  for (const account of accounts) {
    if (account) entries.push({ group: account, color: colorOf(account) });
    for (const c of sorted) if (!account || c.account === account) entries.push({ value: c.id, label: c.name });
  }
  return entries;
}
function filterLabel(filter) {
  const value = $(filterInput[filter]).value;
  // The view always names itself: "Favorites + suggestions" is not "All items".
  if (filter === "view") return VIEWS.find(([id]) => id === value)?.[1] || value;
  if (value === filterDefaults[filter]) return filterTitle[filter];
  if (filter === "collection") return facets.collections.find(c => c.id === value)?.name || filterTitle.collection;
  return menuEntries(filter).find(entry => entry.value === value)?.label || value;
}
function showFilters(shown) {
  $("filters").hidden = !shown; $("filter-toggle").setAttribute("aria-expanded", String(shown));
}
function syncChips() {
  let active = 0;
  for (const chip of document.querySelectorAll("#filters .chip")) {
    const filter = chip.dataset.filter, value = $(filterInput[filter]).value, set = value !== filterDefaults[filter];
    chip.querySelector(".chip-text").textContent = filterLabel(filter);
    if (filter === "view" && chip.dataset.icon !== value) { chip.dataset.icon = value; chip.firstElementChild.replaceWith(icon(VIEW_ICONS[value] || "star")); }
    chip.classList.toggle("is-set", filter === "view" ? value !== "vault" : set); // any view but "All items" narrows the list if (set && filter !== "view") active++;
    const account = filter === "account" ? value : filter === "collection" ? facets.collections.find(c => c.id === value)?.account : null;
    if (set && account && several()) { chip.style.setProperty("--account-color", colorOf(account)); chip.classList.add("has-account"); }
    else { chip.style.removeProperty("--account-color"); chip.classList.remove("has-account"); }
  }
  active += $("view").value !== "home" ? 1 : 0;
  $("filters-clear").hidden = !active;
  if (active) showFilters(true); // an active filter is never hidden
  $("filter-toggle").classList.toggle("has-filters", active > 0);
}
function closeMenu() {
  if (!openMenu) return;
  openMenu.menu.remove(); openMenu.chip.setAttribute("aria-expanded", "false"); openMenu = null;
}
function showMenu(chip) {
  const filter = chip.dataset.filter, again = openMenu?.chip === chip;
  closeMenu(); if (again) return;
  const menu = element("div", null, "filter-menu"); menu.setAttribute("role", "listbox"); menu.setAttribute("aria-label", filterTitle[filter]);
  const current = $(filterInput[filter]).value;
  for (const entry of menuEntries(filter)) {
    if (entry.group) { const head = element("div", null, "filter-menu-group"); head.style.setProperty("--account-color", entry.color); head.append(element("span", null, "dot"), element("span", entry.group)); menu.append(head); continue; }
    const item = element("button", null, "filter-menu-item"); item.type = "button"; item.setAttribute("role", "option");
    const selected = entry.value === current; item.setAttribute("aria-selected", String(selected)); item.classList.toggle("is-selected", selected);
    if (entry.indent) item.style.paddingLeft = `${8 + entry.indent * 14}px`;
    if (entry.color) { const dot = element("span", null, "dot"); dot.style.setProperty("--account-color", entry.color); item.append(dot); }
    if (filter === "view") item.append(icon(VIEW_ICONS[entry.value] || "star"));
    item.append(element("span", entry.label, "filter-menu-label"));
    for (const color of entry.dots || []) { const dot = element("span", null, "dot small"); dot.style.setProperty("--account-color", color); item.append(dot); }
    item.append(selected ? icon("check") : element("span", null, "filter-menu-check"));
    item.onclick = () => { closeMenu(); chooseFilter(filter, entry.value); };
    menu.append(item);
  }
  document.body.append(menu);
  const rect = chip.getBoundingClientRect();
  menu.style.top = `${rect.bottom + 4}px`; menu.style.maxHeight = `${window.innerHeight - rect.bottom - 12}px`;
  menu.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - menu.offsetWidth - 8))}px`;
  chip.setAttribute("aria-expanded", "true"); openMenu = { chip, menu };
  (menu.querySelector(".is-selected") || menu.querySelector("button"))?.focus();
}
function chooseFilter(filter, value) {
  $(filterInput[filter]).value = value;
  if (filter === "account") { $("collection").value = ""; $("folder").value = ""; $("account").value = value; $("account").onchange(); return; }
  syncChips(); remember(); attempt(search);
}
// The folders and collections on offer: those of the chosen account (or each
// one's), for the current search words, type and view.
async function loadFacets(result) {
  const filter = $("account-filter").value, accounts = filter ? [filter] : accountNames;
  if (!several()) {
    facets = { folders: result.folders.map(name => ({ name, accounts: [] })), collections: result.collections };
    return;
  }
  const base = { query: $("query").value, kind: $("kind").value, view: ({ home: "vault", vault: "all" })[$("view").value] || $("view").value };
  const parts = await Promise.all(accounts.map(account => request("search", { ...base, account }).then(r => [account, r], () => null)));
  const folders = new Map(), collections = [];
  for (const part of parts) {
    if (!part) continue;
    for (const name of part[1].folders) folders.set(name, [...(folders.get(name) || []), part[0]]);
    for (const c of part[1].collections) collections.push({ ...c, account: part[0] });
  }
  facets = { folders: [...folders].map(([name, accounts]) => ({ name, accounts })), collections };
}
// A folder or collection the other filters leave out is dropped.
function validFilters() {
  let changed = false;
  if ($("folder").value && !facets.folders.some(f => f.name === $("folder").value)) { $("folder").value = ""; changed = true; }
  if ($("collection").value && !facets.collections.some(c => c.id === $("collection").value)) { $("collection").value = ""; changed = true; }
  return !changed;
}
// With several accounts the empty value means "All accounts" (the default);
// with one, the account is always named.
function renderAccounts(accounts, primary, chosen, states = [], cliColors = {}) {
  cliAccountColors = cliColors || {}; primaryAccount = primary || "";
  allAccounts = accounts.slice(); // every configured account: default colors go by this list
  // Only the accounts picked in the settings (if any) are on offer.
  const picked = Array.isArray(preference.accounts) ? preference.accounts.filter(name => accounts.includes(name)) : [];
  if (picked.length) accounts = picked;
  const select = $("account"), multiple = accounts.length > 1;
  trackFollowers(states);
  accountNames = accounts; accountStates = states.filter(state => accounts.includes(state.name));
  const active = multiple ? (chosen ?? preference.popupAccount ?? "") : (chosen || preference.popupAccount || primary || (accounts[0] || ""));
  select.replaceChildren(...(multiple ? [new Option("All accounts", "")] : []), ...accounts.map(name => new Option(name === primary ? `${name} *` : name, name)));
  select.value = active;
  preference.popupAccount = select.value;
  $("account-filter").value = select.value;
  document.querySelector('#filters [data-filter="account"]').hidden = !multiple; syncChips();
  renderAccountStates(primary);
}
// An account whose master password lives in another account's vault is
// unlocked by rbw-agent in the background right after that one. When this
// popup sees the source get unlocked, its locked followers show as
// "Unlocking…" instead of locked for a while, so the locked warning doesn't
// flash; one that is still locked after that gets the warning as usual.
const followGrace = 15000;
let followPending = new Map(), lockStatesSeen = null, followTimer;
function trackFollowers(states) {
  const before = lockStatesSeen, now = Date.now();
  lockStatesSeen = new Map(states.map(state => [state.name, state.unlocked]));
  for (const state of states) {
    if (state.unlocked || !state.follows || !lockStatesSeen.get(state.follows) || (followPending.get(state.name) ?? Infinity) <= now) { followPending.delete(state.name); continue; }
    if (!followPending.has(state.name) && before?.get(state.follows) === false) followPending.set(state.name, now + followGrace);
  }
  clearTimeout(followTimer);
  if (followPending.size) followTimer = setTimeout(() => attempt(checkFollowers), 1000);
}
const isUnlocking = account => (followPending.get(account.name) ?? 0) > Date.now();
// Lists the newly unlocked followers' items, or re-renders the account
// states (the warning, once the grace is over) while they're still pending.
async function checkFollowers() {
  if (!unlocked || !followPending.size) return;
  const status = await request("status");
  if (!status.unlocked) return;
  const pending = [...followPending.keys()];
  if ((status.accountStates || []).some(state => pending.includes(state.name) && state.unlocked)) { await refresh(status); return; }
  renderAccounts(status.accounts || [], status.primary, $("account").value, status.accountStates || [], status.accountColors);
}
// Merged view: which accounts are locked, each with a way to unlock it.
function renderAccountStates(primary) {
  const list = $("account-states"), details = $("account-details");
  details.hidden = $("account").value !== "" || accountStates.length < 2;
  // Collapsed by default so several accounts don't crowd the popup; the
  // summary says how many are unlocked, and a password prompt opens it.
  const unlockedCount = accountStates.filter(account => account.unlocked).length;
  const summary = $("account-summary");
  summary.replaceChildren(...accountStates.map(account => { const dot = element("span", null, account.unlocked ? "account-dot is-unlocked" : "account-dot"); dot.style.setProperty("--account-color", colorOf(account.name)); dot.title = `${account.name}: ${account.unlocked ? "unlocked" : "locked"}`; return dot; }), element("span", `${unlockedCount} of ${accountStates.length} accounts unlocked`, "account-summary-text"));
  if (needsPassword.size && accountStates.some(account => needsPassword.has(account.name) && !account.unlocked)) details.open = true;
  list.replaceChildren(...accountStates.map(account => {
    const row = element("li", null, account.unlocked ? "is-unlocked" : "is-locked");
    const nameLabel = element("span", account.name === primary ? `${account.name} *` : account.name); nameLabel.style.setProperty("--account-color", colorOf(account.name)); nameLabel.classList.add("account-name");
    const status = element("small", account.excluded ? "Excluded from search" : account.unlocked ? "Unlocked" : isUnlocking(account) ? "Unlocking…" : "Locked"); status.dataset.state = account.excluded ? "excluded" : account.unlocked ? "unlocked" : isUnlocking(account) ? "unlocking" : "locked";
    row.append(element("div", null, "account-info"));
    row.firstChild.append(nameLabel, status);
    if (!account.unlocked) {
      // Unlock tries the account's own policy first (as `rbw unlock` does: a
      // credential source, a phone approval, chained unlocking); the key
      // button, or a failed attempt, opens a password field in the row.
      const form = element("form", null, "account-unlock"), input = element("input"), submit = element("button", "Unlock");
      input.type = "password"; input.dataset.noEcho = ""; input.title = "Tab shows or hides the typed characters"; input.placeholder = `Master password for ${account.name}`; input.autocomplete = "off"; input.maxLength = 4096; input.required = true; input.spellcheck = false;
      submit.type = "submit"; form.append(input, submit); form.hidden = !needsPassword.has(account.name);
      form.onsubmit = event => {
        event.preventDefault(); const password = input.value; input.value = "";
        attempt(async () => { message("Unlocking…"); await request("unlock", { account: account.name, password }); needsPassword.delete(account.name); await refresh(); if (accountStates.every(a => a.unlocked || a.excluded)) { $("account-menu").hidden = true; $("account-details").open = false; } });
      };
      const unlock = actionButton("Unlock", "unlock", async () => {
        try { await request("unlock", { account: account.name }); needsPassword.delete(account.name); await refresh(); if (accountStates.every(a => a.unlocked || a.excluded)) { $("account-menu").hidden = true; $("account-details").open = false; } }
        catch (_) { needsPassword.add(account.name); form.hidden = false; input.focus(); message(`${account.name} needs its master password.`); }
      }, "primary");
      unlock.title = `Unlock ${account.name} with its configured unlock method`;
      const key = actionButton("Use password", "key", () => { form.hidden = !form.hidden; if (!form.hidden) input.focus(); }, "icon");
      key.title = "Unlock with a master password";
      const actions = element("div", null, "account-actions");
      // An account with an enrolled fingerprint also offers the scan.
      if (account.fingerprint) {
        const scan = actionButton("Fingerprint", "fingerprint", () => fingerprintUnlock(account.name), "icon");
        scan.title = `Unlock ${account.name} with the fingerprint reader`; actions.append(scan);
      }
      actions.append(key, unlock);
      row.append(actions, form);
    }
    return row;
  }));
  const locked = accountStates.filter(account => !account.unlocked && !account.excluded && !isUnlocking(account)).map(account => account.name);
  renderLockedBanner(locked);
  const bulk = $("account-bulk");
  bulk.hidden = details.hidden || locked.length < 2;
  bulk.replaceChildren(...(locked.length > 1 ? [actionButton(`Unlock all ${locked.length} accounts`, "unlock", () => unlockAccounts(locked), "primary")] : []));
}
// Warns above the list that locked accounts' items are missing from it.
// The warning above the list turns, in place, into an "unlocked" notice when
// an account gets unlocked, and goes away (or back to the warning for the
// accounts still locked) after a moment.
let lockedSeen = null, bannerHoldUntil = 0, bannerTimer, bannerLeaving;
function bannerAnimated() { return preference.animations !== "off" && !matchMedia("(prefers-reduced-motion: reduce)").matches; }
// Shows the banner (sliding in when it wasn't visible; a swap pop when it only changes).
function showBanner(kind, ...children) {
  const banner = $("locked-accounts");
  clearTimeout(bannerLeaving); banner.classList.remove("is-leaving");
  const wasVisible = !banner.hidden && banner.dataset.kind !== kind;
  const appearing = banner.hidden;
  banner.dataset.kind = kind; banner.hidden = false;
  banner.replaceChildren(...children);
  if (!bannerAnimated()) return;
  banner.classList.remove("is-entering", "is-swapping"); void banner.offsetWidth;
  banner.classList.add(appearing ? "is-entering" : wasVisible ? "is-swapping" : "is-entering");
}
function hideBanner() {
  const banner = $("locked-accounts");
  if (banner.hidden) return;
  if (!bannerAnimated()) { banner.hidden = true; return; }
  banner.classList.add("is-leaving");
  clearTimeout(bannerLeaving); bannerLeaving = setTimeout(() => { banner.hidden = true; banner.classList.remove("is-leaving"); }, 330);
}
function renderLockedBanner(locked) {
  const unlockedNow = lockedSeen ? lockedSeen.filter(name => !locked.includes(name)) : [];
  lockedSeen = locked;
  if ($("account").value !== "") { clearTimeout(bannerTimer); hideBanner(); return; }
  if (unlockedNow.length) {
    bannerHoldUntil = Date.now() + 2500;
    clearTimeout(bannerTimer); bannerTimer = setTimeout(() => { bannerHoldUntil = 0; renderLockedBanner(lockedSeen); }, 2600);
    showBanner("success", icon("check"), element("span", `${unlockedNow.join(", ")} unlocked`));
    return;
  }
  if (Date.now() < bannerHoldUntil) return; // still showing the notice
  if (!locked.length) { hideBanner(); return; }
  const text = element("span", locked.length === 1 ? `${locked[0]} is locked; its items aren't listed.` : `${locked.join(", ")} are locked; their items aren't listed.`);
  showBanner("warning", icon("lock"), text, button("Unlock", () => unlockAccounts(locked), "banner-unlock"));
}
// Unlocks each account by its own policy; the ones that need a password
// are reported (use their Unlock button).
async function unlockAccounts(names) {
  const failed = [];
  for (const name of names) {
    message(`Unlocking ${name}…`);
    try { await request("unlock", { account: name }); needsPassword.delete(name); } catch (_) { failed.push(name); needsPassword.add(name); }
  }
  await refresh();
  $("account-menu").hidden = !failed.length; // their rows now ask for a password
  message(failed.length ? `${failed.join(", ")} need${failed.length === 1 ? "s" : ""} a master password: enter it in the account menu.` : "", failed.length > 0);
}
// Accounts an item could be saved or moved to.
function fillAccountSelect(select, except = null, preferred = null) {
  select.replaceChildren(...accountNames.filter(name => name !== except).map(name => new Option(name, name)));
  const primary = accountStates.find(a => a.primary)?.name;
  select.value = [preferred, $("account").value, primary].find(name => name && name !== except && accountNames.includes(name)) || select.options[0]?.value || "";
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
// A popup restored onto another page skips the vault search; leaving that
// page for the vault must load it then.
let vaultListed = false;
async function refresh(knownStatus = null, skipList = false) {
  loading(true);
  try {
  clearVault();
  const status = knownStatus || await request("status"); unlocked = status.unlocked;
  renderAccounts(status.accounts || [], status.primary, preference.popupAccount, status.accountStates || [], status.accountColors);
  $("state").textContent = unlocked ? (status.merged ? `${status.accountStates.filter(a => a.unlocked).length} of ${status.accountStates.length} accounts unlocked · shared rbw-agent` : "Unlocked · shared rbw-agent") : "Locked";
  $("unlock").disabled = unlocked; $("lock").disabled = !unlocked;
  $("header-lock").disabled = !unlocked;
  if (!$("header-sync").classList.contains("is-syncing")) $("header-sync").disabled = !unlocked;
  $("unlock-fingerprint").hidden = unlocked || !status.fingerprint;
  if (!unlocked && status.fingerprint_auto_start && !fingerprintAutoStarted.has($("account").value)) {
    fingerprintAutoStarted.add($("account").value); fingerprintUnlock();
  }
  if (approvalId) { await showApproval(approvalId); return; }
  // Locked: show the accounts (with Unlock buttons) right away.
  // With several accounts each row has its own unlock, so the page-level one and
  // the (pointless while locked) Lock button go away and the hero shrinks.
  const several = accountStates.length > 1;
  $("unlock").hidden = several; $("lock").hidden = !unlocked; $("state").hidden = several;
  // The host replaces an older agent itself; one it can't use is newer than
  // the host, i.e. the browser still runs the host from before an upgrade.
  const stale = !unlocked && status.staleAgent;
  $("locked").classList.toggle("is-multi", several && !unlocked && !stale);
  $("locked").classList.toggle("is-stale", Boolean(stale));
  $("locked").querySelector("h2").textContent = stale ? "Browser host out of date" : "Vault locked";
  $("unlock-title").hidden = Boolean(stale);
  const staleNote = $("locked").querySelector("p");
  staleNote.hidden = !stale;
  staleNote.textContent = stale ? `rbw-agent is ${status.staleAgent}, but this browser still runs rbw ${status.hostVersion}. Restart the browser.` : "";
  if (!unlocked) {
    show("locked"); if (several) $("account-menu").hidden = false;
    // The master password is what the popup is for; leave focus alone only if
    // it's already in an account row's own password field.
    if (!document.activeElement?.closest?.("#account-states")) $("unlock-password").focus();
    return;
  }
  vaultListed = !skipList;
  show("vault"); if (!skipList) { await search(); await suggestions(); }
  remember();
  } finally { loading(false); }
}
async function search(retry = false) {
  const current = ++epoch;
  const filters = { query: $("query").value, kind: $("kind").value, folder: $("folder").value, collection: $("collection").value, view: $("view").value === "vault" ? "all" : $("view").value };
  const snapshot = await request("search", { ...filters, snapshot: true });
  if (current !== epoch) return;
  if (snapshot) renderSearch(snapshot);
  const result = await request("search", filters);
  if (current !== epoch) return;
  renderSearch(result); remember();
  // The menus follow after the list is shown.
  await loadFacets(result); if (current !== epoch) return;
  if (!validFilters() && !retry) { syncChips(); return search(true); }
  syncChips();
}
function renderSearch(result) {
  syncChips();
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
  if (!result.items.length) {
    const empty = element("div", null, "empty");
    // Favorites + suggestions is empty for an account without favorites: offer the rest.
    if ($("view").value === "home" && !$("query").value) {
      const all = element("button", "Show all items"); all.type = "button";
      all.onclick = () => { $("view").value = "vault"; syncChips(); remember(); attempt(search); };
      empty.append(element("p", "No favorites or suggestions."), all);
    } else empty.append(element("p", "No items found."));
    $("items").append(empty);
  }
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
function itemRow(item, from) {
  const row = element("article"); const image = element("span", null, "item-icon");
  const fallback = item.type === "card"
    ? getCardBrandIcon(item.brand || item.username?.split(",")?.[0], item.name)
    : (item.passkeys ? "key" : (icons[item.type] || "note"));
  image.dataset.fallback = fallback; image.append(icon(fallback));
  // With several accounts, an emblem on the icon's corner says which one holds the item.
  const lead = element("span", null, "item-lead"); lead.append(image);
  // The primary account is the default one: its items carry no emblem. A search
  // of a single account does not tag its items, so the chosen one stands in.
  const account = item.account || $("account").value;
  if (account && accountNames.length > 1 && account !== primaryAccount) {
    const emblem = element("span", account.slice(0, 2).toUpperCase(), "account-emblem"); const color = colorOf(account);
    emblem.style.setProperty("--account-color", color); emblem.style.setProperty("--emblem-text", accountTextColor(color)); emblem.title = account; emblem.setAttribute("aria-label", `Account ${account}`);
    lead.append(emblem);
  }
  row.append(lead);
  if (preference.favicons && item.iconOrigin) { image.dataset.origin = item.iconOrigin; faviconObserver.observe(image); }
  const main = button("", async () => { if (from === "health") healthScroll = document.querySelector("main").scrollTop; await openDetail(item.id, item.deleted, from); }, "item-main");
  const title = element("div", null, "item-title");
  if (item.favorite) { const star = icon("star"); star.classList.add("favorite-icon"); title.append(star); }
  title.append(element("strong", item.name));
  // Archived and trashed items can show up beside live ones (search, the trash view).
  const status = item.deleted ? ["Trash", "trash"] : item.archived ? ["Archived", "archive"] : null;
  if (status) {
    const badge = element("span", null, "item-status"); badge.dataset.status = status[1]; badge.append(icon(status[1]), status[0]);
    title.append(badge); row.classList.add("is-inactive");
  }
  main.append(title, element("small", item.username || labels[item.type])); row.append(main);
  const autofillExcluded = Array.isArray(preference.autofillExcludedItems) && preference.autofillExcludedItems.includes(item.id);
  if (autofillExcluded) title.append(element("small", "Autofill off", "item-autofill-disabled"));
  const actions = element("div", null, "item-actions");
  if (item.deleted) actions.append(
    actionButton("Restore", "undo", async () => { await restoreItem(item.id); await search(); }),
    actionButton("Delete permanently", "trash", async () => { if (await purgeItem(item.id, item.name)) await search(); }, "danger"));
  else {
    if (!autofillExcluded && (item.matched || ["card", "identity"].includes(item.type))) { const fill = actionButton("Fill", "fill", async () => { try { await request("fill", { item: item.id, type: item.type }); flashCopied(fill, "", "ok"); } catch (_) { flashCopied(fill, "", "error"); } }); fill.title = "Fill"; fill.classList.add("item-fill"); fill.setAttribute("aria-label", `Fill ${item.name}`); actions.append(fill); }
    const field = item.type === "login" ? "password" : item.type === "card" ? "number" : item.type === "identity" ? "email" : item.type === "ssh_key" ? "public_key" : "notes";
    const copy = actionButton("Copy", "copy", () => copyField(item.id, field, true, copy)); copy.title = "Copy"; copy.setAttribute("aria-label", `Copy ${field}`); actions.append(copy);
    const menu = element("details", null, "menu"); const summary = element("summary"); summary.append(icon("more")); summary.setAttribute("aria-label", `Actions for ${item.name}`); menu.append(summary);
    const entries = element("div");
    menu.addEventListener("toggle", () => {
      if (menu.open) {
        for (const other of document.querySelectorAll("details.menu[open]")) {
          if (other !== menu) other.open = false;
        }
        const rect = summary.getBoundingClientRect();
        const menuHeight = entries.offsetHeight || 220;
        const spaceBelow = window.innerHeight - rect.bottom;
        const spaceAbove = rect.top;
        if (spaceBelow < menuHeight + 10 && spaceAbove > spaceBelow) {
          menu.classList.add("drop-up");
        } else {
          menu.classList.remove("drop-up");
        }
      } else {
        menu.classList.remove("drop-up");
      }
    });
    entries.addEventListener("click", event => {
      if (event.target.closest("button")) menu.open = false;
    });
    // Fill the active page from here; "and save" also adds the page's URL to the login.
    if (!autofillExcluded && ["login", "card", "identity"].includes(item.type)) {
      entries.append(actionButton("Autofill", "fill", () => autofillItem(item.id, item.type)));
      if (item.type === "login") entries.append(actionButton("Autofill and save", "plus", async () => { if (await autofillAndSave(item.id)) await search(); }));
    }
    entries.append(actionButton("View item", "note", () => openDetail(item.id)), actionButton("Edit", "edit", async () => { await openDetail(item.id); editItem(); }));
    entries.append(actionButton("Duplicate", "copy", () => duplicateItem(item.id)));
    if (item.type === "login") {
      entries.append(
        actionButton("Copy username", "identity", () => copyField(item.id, "username")),
        actionButton("Copy password", "key", () => copyField(item.id, "password")),
        actionButton("Copy TOTP", "generator", () => copyField(item.id, "totp"))
      );
    }
    entries.append(actionButton(item.favorite ? "Remove favorite" : "Favorite", "star", async () => { await mutateItem(item.id, "favorite", item.favorite); await search(); }),
      actionButton(item.archived ? "Unarchive" : "Archive", "archive", async () => { await mutateItem(item.id, "archive", item.archived, row); await search(); }),
      actionButton("Move to trash", "trash", async () => { if (!await confirmDialog({ title: `Move “${item.name}” to trash?`, text: "You can restore it from the Trash view.", confirm: "Move to trash", danger: true })) return; await mutateItem(item.id, "delete", false, row); await search(); }, "danger"));
    menu.append(entries); actions.append(menu);
  }
  row.append(actions); return row;
}
if (typeof window !== "undefined") window.itemRow = itemRow;
const copyNames = { password: "password", username: "username", totp: "TOTP", number: "card number", email: "email", public_key: "public key", notes: "notes" };
// A copy button confirms in place (feedback.js); a toast is only used where
// there is no button to change, like the row's menu.
function flashCopied(trigger, text, kind = "ok") {
  const speed = { slow: 1.6, fast: 0.65 }[preference.animationSpeed] || 1;
  if (!stampResult(trigger, { kind, motion: bannerAnimated(), speed })) message(text);
}
async function copyField(item, field, allowFallback = false, trigger = null) {
  try {
    await request("copy", { item, field });
    flashCopied(trigger, `Copied ${copyNames[field] || "field"}`);
  } catch (err) {
    if (!allowFallback) throw err;
    if (field === "notes") {
      try {
        await request("copy", { item, field: "custom/0" });
        flashCopied(trigger, "Copied field");
        return;
      } catch (_) {}
    } else if (field === "password") {
      for (const alt of ["totp", "username", "custom/0"]) {
        try {
          await request("copy", { item, field: alt });
          flashCopied(trigger, `Copied ${copyNames[alt] || "field"}`);
          return;
        } catch (_) {}
      }
    }
    throw err;
  }
}
// With "Show favicons" on, a URI row starts with the site's favicon, or an
// Android logo for androidapp:// URIs (drawn locally; Play Store icons would
// mean asking Google about every app in the vault).
function uriIcon(uri, row, stillCurrent) {
  let url;
  try { url = new URL(uri); } catch (_) { return; }
  if (url.protocol === "androidapp:") {
    const badge = element("span", null, "uri-icon uri-icon-android"); badge.title = "Android app";
    badge.append(icon("android")); row.prepend(badge); return;
  }
  if (!["http:", "https:"].includes(url.protocol)) return;
  // A globe stands in until (or unless) the favicon loads.
  const placeholder = element("span", null, "uri-icon uri-icon-placeholder"); placeholder.append(icon("globe")); row.prepend(placeholder);
  request("favicon", { origin: url.origin }).then(favicon => {
    if (!favicon || !stillCurrent()) return;
    const image = element("img", null, "uri-icon"); image.src = favicon; image.alt = "";
    image.onload = () => placeholder.replaceWith(image); // a broken image keeps the globe
  }).catch(() => {});
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
    const copyBtn = actionButton("Copy", "copy", () => copyField(item, field, false, copyBtn), "icon");
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
  const copyNotes = actionButton("Copy", "copy", () => copyField(item, "notes", false, copyNotes)); toolbar.append(toggle, copyNotes); section.append(toolbar, content); render(); return section;
}
function totpField(item) {
  const section = element("div", null, "field totp-field"); section.append(element("span", "TOTP"));
  const row = element("div", null, "field-value"); const code = element("div", "••• •••", "totp-code");
  const actions = element("div", null, "field-actions");
  const copy = actionButton("Copy TOTP", "copy", () => copyField(item, "totp", false, copy), "icon"); copy.disabled = true;
  actions.append(copy); row.append(code, actions);
  const countdown = element("small", "Generating code…", "hint");
  // A continuously shrinking bar, like the inline dialogs' auto-close progress.
  const progress = element("div", null, "totp-progress"); progress.setAttribute("role", "progressbar"); progress.setAttribute("aria-label", "TOTP validity");
  const fill = element("span", null, "totp-progress-fill"); progress.append(fill);
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
      const left = Math.max(0, state.expiresAt - Date.now() / 1000), remaining = Math.ceil(left);
      countdown.textContent = `${remaining}s remaining`;
      progress.setAttribute("aria-valuemax", String(state.period)); progress.setAttribute("aria-valuenow", String(remaining));
      fill.style.transform = `scaleX(${Math.min(1, left / state.period)})`; progress.classList.toggle("is-expiring", remaining <= 5);
    } catch (_) {
      if (!current()) return;
      state = null; code.textContent = "Unavailable"; copy.disabled = true; countdown.textContent = "Could not generate the TOTP.";
    }
    if (current()) totpTimer = setTimeout(tick, state ? 250 : 3000);
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
// Archive, favorite and trash changes: say what happened, offer Undo where it
// hides the item, and slide the row out of the list when it leaves the view.
const MUTATION_NOTICES = {
  favorite: wasSet => wasSet ? "Removed from favorites." : "Added to favorites.",
  archive: wasSet => wasSet ? "Unarchived." : "Archived.",
  delete: () => "Moved to trash."
};
async function mutateItem(item, mutation, wasSet, row = null) {
  await request("mutate", { item, mutation });
  const undo = mutation === "favorite" ? null : { label: "Undo", run: async () => {
    await request("mutate", { item, mutation: mutation === "delete" ? "restore" : mutation });
    message(mutation === "delete" ? "Restored from the trash." : wasSet ? "Archived." : "Unarchived.");
    await refresh();
  } };
  message(MUTATION_NOTICES[mutation](wasSet), false, undo);
  // Rows leave the list when the change takes the item out of the current view.
  const view = $("view").value;
  const leaves = mutation === "delete" ? view !== "vault"
    : mutation === "archive" && (wasSet ? view === "archive" : ["home", "favorites"].includes(view));
  if (row && leaves && bannerAnimated()) {
    row.style.height = `${row.offsetHeight}px`; void row.offsetHeight; row.classList.add("is-leaving");
    await new Promise(resolve => setTimeout(resolve, 260));
  }
}
// Trash actions: restore, or delete for good after confirming.
async function restoreItem(item) {
  await request("mutate", { item, mutation: "restore" }); message("Restored from the trash.");
}
async function purgeItem(item, name) {
  if (!await confirmDialog({ title: `Delete “${name}” permanently?`, text: "This cannot be undone.", confirm: "Delete permanently", danger: true })) return false;
  await request("mutate", { item, mutation: "purge" }); message("Deleted permanently."); return true;
}
// `trashed` opens an item from the trash: read-only, without copy actions
// (the native host only serves those for items outside the trash).
async function openDetail(item, trashed = false, from) {
  const current = ++epoch;
  const detail = await request("detail", { item, trashed }); if (current !== epoch) return;
  if (from !== undefined) detailFrom = from;
  currentItem = item; currentDetail = detail; show("detail");
  $("detail-header-actions").hidden = trashed;
  const copyable = field => trashed ? null : field;
  $("header-move").hidden = accountNames.length < 2;
  // Filling the page applies to logins (and cards/identities) outside the trash.
  const itemType = detail.cipher.data.type;
  const fillable = !trashed && ["login", "card", "identity"].includes(itemType);
  $("header-autofill").hidden = !fillable; $("header-autofill-save").hidden = !fillable || itemType !== "login";
  const content = $("detail-content");
  const data = detail.cipher.data;
  const title = element("h2", null, "detail-title");
  title.append(element("span", detail.cipher.name));
  let trashBanner = null;
  if (trashed) {
    const banner = element("div", null, "trash-banner");
    const text = element("p"); text.append(icon("trash"), element("span", "This item is in the trash."));
    const actions = element("div", null, "trash-banner-actions");
    actions.append(
      actionButton("Restore", "undo", async () => { await restoreItem(item); await openDetail(item); }, ""),
      actionButton("Delete permanently", "trash", async () => { if (await purgeItem(item, detail.cipher.name)) { show("vault"); await search(); } }, "danger"));
    banner.append(text, actions); trashBanner = banner;
  }
  const firstUri = (data.uris || []).find(uri => {
    try { return ["http:", "https:"].includes(new URL(uri.uri).protocol); } catch (_) { return false; }
  });
  content.replaceChildren(title, ...(trashBanner ? [trashBanner] : []));
  // Where the item lives: folder, account (with several) and collections.
  const collectionNames = (detail.collection_options || []).filter(c => detail.collection_ids?.includes(c.id)).map(c => c.name);
  const meta = [["folder", "Folder", detail.cipher.folder], ["vault", "Account", accountNames.length > 1 ? detail.account : null], ["collections", collectionNames.length === 1 ? "Collection" : "Collections", collectionNames.join(", ")]].filter(([, , value]) => value);
  if (meta.length) {
    const row = element("div", null, "detail-meta");
    for (const [name, label, value] of meta) { const chip = element("span", null, "meta-chip"); if (label === "Account") chip.style.setProperty("--account-color", colorOf(value)); chip.title = `${label}: ${value}`; chip.append(icon(name), element("small", label), element("strong", value)); row.append(chip); }
    content.append(row);
  }
  if (preference.favicons && firstUri) {
    request("favicon", { origin: new URL(firstUri.uri).origin }).then(favicon => {
      if (!favicon || current !== epoch || currentItem !== item) return;
      const image = element("img", null, "detail-favicon"); image.src = favicon; image.alt = "";
      image.onerror = () => image.remove(); title.prepend(image);
    }).catch(() => {});
  }
  const entries = Object.entries(data);
  const orderedEntries = data.type === "login"
    ? ["username", "password"].map(name => entries.find(([field]) => field === name)).filter(Boolean)
      .concat(entries.filter(([field]) => !["username", "password"].includes(field)))
    : data.type === "card"
      ? cardFieldOrder.map(name => entries.find(([field]) => field === name)).filter(Boolean)
        .concat(entries.filter(([field]) => !cardFieldOrder.includes(field)))
      : entries;
  for (const [field, value] of orderedEntries) {
    if (["type", "uris", "fido2_credentials", "totp"].includes(field) || value == null || value === "") continue;
    const label = data.type === "card" ? cardFieldLabels[field] || pretty(field) : field === "totp" ? "TOTP" : pretty(field);
    content.append(detailField(label, String(value), item, copyable(field), secret(field)));
  }
  if (data.totp && !trashed) content.append(totpField(item));
  if (data.uris?.length) {
    content.append(element("h3", "URIs"));
    for (const uri of data.uris) {
      const field = detailField(uri.match_type in uriMatchNames ? `URI · ${uriMatchNames[uri.match_type]}` : "URI", uri.uri, item, null, false, true);
      if (preference.favicons) uriIcon(uri.uri, field.querySelector(".field-value"), () => current === epoch && currentItem === item);
      content.append(field);
    }
  }
  if (detail.cipher.notes) content.append(noteField(detail.cipher.notes, item));
  const customFields = detail.cipher.fields || [];
  const orderedCustomFields = data.type === "card"
    ? customFields.map((field, index) => ({ field, index })).sort((left, right) => {
        const leftIsPin = left.field.name?.trim().toLowerCase() === "pin";
        const rightIsPin = right.field.name?.trim().toLowerCase() === "pin";
        return Number(leftIsPin) - Number(rightIsPin);
      }).map(({ field, index }) => ({ ...field, originalIndex: index }))
    : customFields;
  for (const [i, field] of orderedCustomFields.entries()) {
    const sourceIndex = data.type === "card" ? field.originalIndex : i;
    content.append(detailField(field.name || "Custom field", field.value || "", item, copyable(`custom/${sourceIndex}`), field.type === "hidden"));
  }
  if (detail.attachments?.length) {
    content.append(element("h3", `Attachments · ${detail.attachments.length}`));
    for (const attachment of detail.attachments) {
      const row = element("div", null, "field attachment-row");
      const label = element("div", null, "attachment-info");
      label.append(icon("note"), element("strong", attachment.file_name || "Attachment"), element("small", attachment.size_name || (attachment.size ? `${attachment.size} bytes` : "")));
      row.append(label);
      if (!trashed) row.append(actionButton("Download", "download", async () => { const result = await request("attachment_download", { item, attachment: attachment.id }); message(`Saved to ${result.path}`); }, "icon"));
      content.append(row);
    }
  }
  for (const passkey of detail.passkeys) { content.append(element("h3", "Passkey"), element("p", `${passkey.rp} · ${passkey.user || ""}`), element("p", `Created ${passkey.created || "unknown"}`, "hint")); }
  if (detail.history.length) { const history = element("details", null, "history-section"); const historyHeader = element("summary"); historyHeader.append(element("h3", `Password history · ${detail.history.length}`), icon("chevron-down")); history.append(historyHeader); for (const [index, entry] of detail.history.entries()) history.append(detailField(entry.last_used_date, entry.password, item, copyable(`history/${index}`), true)); content.append(history); }
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
    if (JSON.stringify(fresh.cipher) === JSON.stringify(currentDetail.cipher)) {
      if (editRevision === currentDetail.revision) editRevision = fresh.revision;
      currentDetail = fresh;
    }
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
      if (!await confirmDialog({ title: "Delete this attachment?", text: `${attachment.file_name || "The attachment"} is removed permanently.`, confirm: "Delete", danger: true })) return;
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
    const label = element("label", type === "card" ? cardFieldLabels[name] || pretty(name) : name === "totp" ? "TOTP" : pretty(name)); const input = element(name === "private_key" || name === "public_key" ? "textarea" : "input");
    input.id = `field-${name}`; input.value = data[name] || ""; input.autocomplete = "off"; input.spellcheck = false;
    if (input.tagName === "INPUT") input.type = secret(name) ? "password" : "text";
    if (input.type === "password") {
      const row = element("div", null, "editor-secret"); row.append(input);
      if (name === "password") {
        const generate = actionButton("Generate password", "generator", async () => {
          input.value = await request("generate");
          message("Generated password added to this form. Save to keep it.");
        }, "icon");
        generate.classList.add("generate-password"); row.append(generate);
      }
      row.append(revealButton(input)); label.append(row);
    } else label.append(input);
    $("edit-fields").append(label);
  }
  $("uri-label").hidden = type !== "login";
  $("edit-advanced").hidden = !["login", "card", "identity"].includes(type);
}
// Per-URI match detection, as in Bitwarden. "Default" follows this browser's
// override of rbw's defaultUriMatch (see the add-on options).
const uriMatchNames = { domain: "Base domain", host: "Host", starts_with: "Starts with", exact: "Exact", regular_expression: "Regular expression", never: "Never" };
function uriMatchSelect(value = "") {
  const select = element("select", null, "uri-match"); select.setAttribute("aria-label", "Match detection");
  select.append(new Option("Default", ""), ...Object.entries(uriMatchNames).map(([key, name]) => new Option(name, key)));
  select.value = value in uriMatchNames ? value : "";
  return select;
}
function addUri(uri = {}) {
  const row = element("div", null, "uri-row");
  const input = element("input", null, "uri-input"); input.value = uri.uri || ""; input.placeholder = "https://example.com"; input.spellcheck = false; input.setAttribute("aria-label", "Website URI");
  // The site's favicon (or the Android icon for androidapp://) leads the URI; it follows what's typed.
  const lead = element("span", null, "uri-edit-icon"); let iconTimer, iconToken = 0;
  const refreshIcon = () => {
    const token = ++iconToken; lead.replaceChildren();
    const value = input.value.trim();
    if (value.startsWith("androidapp:") || preference.favicons) uriIcon(value, lead, () => token === iconToken);
    if (!lead.childElementCount) { const globe = element("span", null, "uri-icon uri-icon-placeholder"); globe.append(icon("globe")); lead.append(globe); }
  };
  input.addEventListener("input", () => { clearTimeout(iconTimer); iconTimer = setTimeout(refreshIcon, 400); });
  refreshIcon();
  const top = element("div", null, "uri-top"); top.append(lead, input);
  // Match detection and remove sit on a line below the URI.
  const meta = element("div", null, "uri-meta");
  meta.append(element("span", "Match detection", "uri-meta-label"), uriMatchSelect(uri.match_type || ""), actionButton("Remove URI", "trash", () => row.remove(), "icon danger"));
  row.append(top, meta);
  $("edit-uris").append(row);
  return input;
}
async function labelUriDefaults() {
  const [prefs, policy] = await Promise.all([request("preferences"), request("agent_settings")]);
  // Defaults also include rbw's own host-and-subdomains matching, which a
  // single URI cannot select (its "domain" is Bitwarden's base domain).
  const defaultNames = { ...uriMatchNames, domain: "Domain and subdomains", base_domain: "Base domain" };
  const uriDefaultName = defaultNames[prefs.uriMatchDefault || policy.defaultUriMatch] || defaultNames.domain;
  $("uri-default").textContent = `Default is ${uriDefaultName}${prefs.uriMatchDefault ? " (this browser's override)" : " (rbw setting)"}.`;
}
$("add-uri").onclick = () => addUri().focus();
$("uri-apply-all").append(new Option("Default", ""), ...Object.entries(uriMatchNames).map(([key, name]) => new Option(name, key)));
$("uri-apply-all").onchange = () => {
  if ($("uri-apply-all").value !== "keep") for (const select of document.querySelectorAll(".uri-match")) select.value = $("uri-apply-all").value;
  $("uri-apply-all").value = "keep";
};
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
// The editor's folder: a select of the account's folders (from the last
// search), "No folder", or "New folder…", which reveals a name field; saving
// an unknown name creates that folder.
const NEW_FOLDER = "\u0000new";
function fillFolderSelect(names, selected) {
  const sorted = [...new Set(names.concat(selected ? [selected] : []))]
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  const select = $("edit-folder-select");
  select.replaceChildren(new Option("No folder", ""), ...sorted.map(folder => new Option(folder, folder)), new Option("New folder…", NEW_FOLDER));
  select.value = selected;
}
function setEditFolder(name) {
  fillFolderSelect([...$("folder-list").options].map(option => option.value), name);
  $("edit-folder").value = ""; $("edit-folder").required = false; $("edit-folder-new").hidden = true;
  // The editor can open before any search filled the list; fetch it.
  request("folders", { method: "list" }).then(list => {
    const select = $("edit-folder-select");
    if (select.value === NEW_FOLDER) return;
    fillFolderSelect(list.map(folder => folder.name), select.value);
  }).catch(() => {});
}
function editFolder() {
  const select = $("edit-folder-select");
  if (select.value !== NEW_FOLDER) return select.value || null;
  return $("edit-folder").value.trim() || null;
}
$("edit-folder-select").onchange = () => {
  const creating = $("edit-folder-select").value === NEW_FOLDER;
  $("edit-folder-new").hidden = !creating; $("edit-folder").required = creating;
  if (creating) $("edit-folder").focus();
};
// Collections are edited with the item, not in the read-only view.
function renderEditCollections(detail) {
  const box = $("edit-collections"); box.replaceChildren();
  if (!currentItem || !detail?.collection_options?.length) return;
  box.append(element("h3", "Collections"));
  const card = element("div", null, "settings-card switch-list");
  for (const collection of detail.collection_options) {
    const row = element("label", null, "switch-row"); const input = element("input", null, "switch"); input.type = "checkbox"; input.value = collection.id; input.checked = (detail.collection_ids || []).includes(collection.id);
    row.append(element("span", collection.name), input); card.append(row);
  }
  box.append(card);
}
function editedCollections() {
  const inputs = [...$("edit-collections").querySelectorAll("input")];
  return inputs.length ? inputs.filter(input => input.checked).map(input => input.value) : null;
}
function editItem(fresh = false, draft = null) {
  if (fresh) { currentItem = null; currentDetail = null; }
  const cipher = draft?.cipher || currentDetail?.cipher || { name: "", data: { type: "login" } };
  $("edit-name").value = cipher.name; setEditFolder(cipher.folder || ""); $("edit-notes").value = cipher.notes || "";
  // New items choose their account; existing ones stay where they are.
  $("edit-account-row").hidden = !!currentItem || accountNames.length < 2;
  if (!$("edit-account-row").hidden) fillAccountSelect($("edit-account"), null, draft?.account);
  $("edit-type").value = cipher.data.type; $("edit-type").disabled = !!currentDetail?.passkeys.length;
  $("edit-uris").replaceChildren(); for (const uri of cipher.data.uris || []) addUri(uri);
  if (!$("edit-uris").children.length) addUri();
  labelUriDefaults().catch(() => {});
  $("custom-fields").replaceChildren(); for (const field of cipher.fields || []) addCustom(field);
  // Autofill exclusion is a browser preference keyed by item ID, so new items get it after saving.
  $("edit-no-autofill").checked = !!currentItem && (draft ? draft.noAutofill : Array.isArray(preference.autofillExcludedItems) && preference.autofillExcludedItems.includes(currentItem));
  $("edit-no-autofill").disabled = !currentItem;
  $("edit-no-autofill-hint").textContent = currentItem ? "Inline suggestions, on-load autofill and the fill shortcut skip this item." : "Save the item first to exclude it from autofill.";
  $("edit-passkeys").textContent = currentDetail?.passkeys.length ? "Existing passkeys are preserved by rbw. Their private keys never enter this editor." : "";
  renderAttachments(currentDetail, currentItem);
  renderEditCollections(currentDetail);
  renderEditFields(cipher.data); show("editor"); $("edit-name").focus();
  // A resumed draft keeps the revision it started from, so saving still
  // refuses to overwrite changes made elsewhere in the meantime.
  editRevision = draft ? draft.revision : currentDetail?.revision || null;
  editBase = draft ? "" : JSON.stringify(editorDraft());
}
// One unsaved edit survives closing the popup. The background page keeps it
// in memory until it is saved, cancelled or restarted, or the vault locks.
let editBase = null, editRevision = null, draftTimer;
function editorCipher() {
  const type = $("edit-type").value; const data = { type };
  for (const name of schema[type]) data[name] = $(`field-${name}`).value || null;
  if (type === "login") data.uris = [...$("edit-uris").children].map(row => ({ uri: row.querySelector(".uri-input").value.trim(), match_type: row.querySelector(".uri-match").value || undefined })).filter(uri => uri.uri);
  const fields = [...$("custom-fields").children].map(card => ({
    name: card.querySelector(".custom-name-input")?.value || "",
    value: card.querySelector(".custom-value-input")?.value || "",
    type: card.querySelector(".custom-type-select")?.value || "text"
  }));
  return { name: $("edit-name").value, folder: editFolder(), notes: $("edit-notes").value || null, data, fields };
}
function editorDraft() { return { account: $("edit-account-row").hidden ? null : $("edit-account").value, item: currentItem, revision: editRevision, cipher: editorCipher(), noAutofill: $("edit-no-autofill").checked }; }
function rememberEditDraft() {
  clearTimeout(draftTimer);
  if (currentPage !== "editor" || editSaving || editBase === null) return;
  const draft = editorDraft();
  request("save_edit_draft", { draft: JSON.stringify(draft) === editBase ? null : draft }).catch(() => {});
}
// Leaving the editor with changes asks first; the same exit again (or the
// notification's Discard) confirms.
const discardText = "Discard your unsaved changes?";
async function leaveEditor(go) {
  const asked = !$("message").hidden && $("message-text").textContent === discardText;
  if (currentPage !== "editor" || editBase === null || asked || JSON.stringify(editorDraft()) === editBase) { if (asked) message(""); await go(); return; }
  message(discardText, false, { label: "Discard", run: go });
}
function forgetEditDraft() {
  clearTimeout(draftTimer); editBase = null;
  request("save_edit_draft", { draft: null }).catch(() => {});
}
for (const type of ["input", "change", "click"]) $("edit-form").addEventListener(type, () => { clearTimeout(draftTimer); draftTimer = setTimeout(rememberEditDraft, 300); });
window.addEventListener("pagehide", rememberEditDraft);
document.addEventListener("visibilitychange", () => { if (document.hidden) rememberEditDraft(); });
async function resumeEditDraft(draft) {
  try {
    if (draft.item) await openDetail(draft.item);
  } catch (_) {
    forgetEditDraft(); message("Your unsaved edit could not be resumed: the item is no longer in the vault.", true); return;
  }
  const changed = !!draft.item && draft.revision !== currentDetail?.revision;
  editItem(!draft.item, draft);
  message(changed ? "Resumed your unsaved edit. The item changed in the vault since; restart to edit the current version." : "Resumed your unsaved edit.", false, {
    label: "Restart", run: async () => { forgetEditDraft(); if (draft.item) { await openDetail(draft.item); editItem(); } else editItem(true); message("Restarted from the current vault state."); }
  });
}
let editSaving = false;
// Saving waits for rbw to write and sync, which can take a few seconds, so
// show progress and lock the form instead of leaving the popup looking stuck.
function setEditSaving(active) {
  editSaving = active;
  const save = $("header-save-edit");
  // Keep the button's width, so "Saving…" does not make the header jump.
  if (active) save.style.minWidth = `${save.offsetWidth}px`; else save.style.minWidth = "";
  save.classList.toggle("is-saving", active);
  save.disabled = active || attachmentBusy; $("header-cancel-edit").disabled = active;
  save.replaceChildren(...(active ? [element("span", null, "spinner"), " Saving…"] : [icon("check"), " Save"]));
  $("editor").classList.toggle("is-saving", active); $("editor").inert = active;
  $("editor").setAttribute("aria-busy", String(active));
}
$("edit-form").onsubmit = event => { event.preventDefault(); if (editSaving) return; attempt(async () => {
  if (attachmentBusy) throw new Error("Wait for the attachment operation to finish before saving.");
  setEditSaving(true);
  try {
    const cipher = editorCipher(), type = cipher.data.type;
    const collections = currentItem ? editedCollections() : null, before = currentDetail?.collection_ids || [];
    await request("save", { item: currentItem, revision: editRevision, cipher, ...(!currentItem && !$("edit-account-row").hidden ? { account: $("edit-account").value } : {}) });
    if (collections && (collections.length !== before.length || collections.some(id => !before.includes(id)))) await request("set_collections", { item: currentItem, collections });
    if (currentItem && ["login", "card", "identity"].includes(type)) {
      const excluded = new Set(Array.isArray(preference.autofillExcludedItems) ? preference.autofillExcludedItems : []);
      if ($("edit-no-autofill").checked) excluded.add(currentItem); else excluded.delete(currentItem);
      if (excluded.size !== (preference.autofillExcludedItems || []).length) preference = await request("set_preferences", { preferences: { autofillExcludedItems: [...excluded] } });
    }
    message("Saved and synchronized."); await refresh();
  } finally { setEditSaving(false); }
}); };
async function suggestions() {
  const area = $("suggestions"); area.replaceChildren();
  for (const pending of await request("pending")) area.append(actionButton(`${pending.method === "create" ? "Save passkey" : "Sign in"} · ${pending.origin}`, "key", () => showApproval(pending.id)));
  // Save suggestions that were dismissed or expired stay here until saved or
  // dismissed. Their passwords never leave the background page.
  const unsaved = await request("unsaved_logins").catch(() => []);
  if (!unsaved.length) return;
  area.append(element("h3", `Unsaved logins · ${unsaved.length}`));
  for (const entry of unsaved) {
    const row = element("article", null, "unsaved-login"), main = element("div", null, "item-main"), actions = element("div", null, "item-actions");
    main.append(element("strong", entry.host), element("small", `${entry.username || "No username"} · ${entry.update ? `changed password for ${entry.update.name}` : "new login"}`));
    const target = element("select", null, "save-account"); target.setAttribute("aria-label", "Save to account");
    if (accountNames.length > 1 && !entry.update) fillAccountSelect(target); else target.hidden = true;
    const apply = async (item, text) => { await request("unsaved_login_apply", { id: entry.id, item, ...(!item && !target.hidden ? { account: target.value } : {}) }); message(text); await refresh(); };
    if (entry.update) actions.append(actionButton(`Update ${entry.update.name}`, "check", () => apply(entry.update.id, `Updated ${entry.update.name}.`), "icon"));
    actions.append(actionButton(entry.update ? "Save as a new login" : "Save login", entry.update ? "plus" : "check", () => apply(null, `Saved a login for ${entry.host}.`), "icon"));
    actions.append(actionButton("Dismiss", "close", async () => { await request("unsaved_login_dismiss", { id: entry.id }); await suggestions(); }, "icon"));
    row.append(icon("key"), main, target, actions); area.append(row);
  }
}
// One page: the site, the matching accounts (a click signs in with that one,
// after the master password when the site requires verification), another
// authenticator, or cancel. The chosen row shows the progress.
function setApprovalBusy(busy, text = null) {
  $("approval-items").classList.toggle("is-busy", busy);
  $("approval-alternatives").hidden = busy;
  if (text != null) { $("approval-description").textContent = text; $("approval-description").classList.remove("is-done"); }
}
async function showApproval(id) {
  approvalId = id; show("approval"); $("approval-items").replaceChildren();
  const pending = (await request("pending")).find(p => p.id === id);
  if (!pending) { approvalId = null; message("Passkey request expired or completed."); show(unlocked ? "vault" : "locked"); return; }
  const create = pending.method === "create";
  const host = new URL(pending.origin).host;
  $("title").textContent = create ? "Passkey registration requested" : "Passkey login requested";
  $("approval-title").textContent = create ? "Save a passkey" : "Sign in with a passkey";
  $("approval-origin").textContent = host;
  $("approval-emblem").replaceChildren(icon("key"));
  request("favicon", { origin: pending.origin }).then(favicon => {
    if (!favicon || approvalId !== id) return;
    const image = document.createElement("img"); image.src = favicon; image.alt = "";
    $("approval-emblem").replaceChildren(image);
  }).catch(() => {});
  const intro = create ? `Save a passkey for ${pending.user || "this account"} in your vault.` : "Choose an account to continue.";
  $("approval-verification").hidden = true; $("approval-items").classList.remove("is-verifying");
  $("approval-password").value = ""; $("approval-password").type = "password";
  $("approval-reveal").replaceChildren(icon("eye")); $("approval-reveal").title = "Show"; $("approval-reveal").setAttribute("aria-label", "Show");
  setApprovalBusy(false, intro);
  if (!unlocked) { $("unlock-password").focus(); return; }
  const result = await request("passkey_choices", { request: id });
  const state = (row, content) => row.querySelector(".passkey-choice-state").replaceChildren(content);
  const reset = row => {
    row.classList.remove("is-selected"); state(row, icon("chevron-left"));
    $("approval-items").classList.remove("is-verifying"); $("approval-verification").hidden = true;
    setApprovalBusy(false, intro);
  };
  const complete = async (row, item, password = null) => {
    $("approval-verification").hidden = true; $("approval-items").classList.remove("is-verifying");
    row.classList.add("is-selected"); state(row, element("span", null, "spinner"));
    setApprovalBusy(true, create ? "Saving the passkey to your vault…" : `Signing in${row.dataset.username ? ` as ${row.dataset.username}` : ""}…`);
    try { await request("passkey_approve", { request: id, item, password }); }
    catch (err) { reset(row); throw err; }
    row.classList.add("is-done"); state(row, icon("check"));
    $("approval-description").textContent = create ? "Passkey saved." : "Signed in."; $("approval-description").classList.add("is-done");
    // Let the checkmark show before the popup closes.
    await new Promise(resolve => setTimeout(resolve, 600));
    await finishApproval("Passkey request completed.");
  };
  const approve = async (item, row) => {
    if (pending.verification !== "required") return complete(row, item);
    // Required WebAuthn verification comes after choosing the account: an
    // unlocked agent alone must never be reported as user verification.
    row.classList.add("is-selected");
    $("approval-items").classList.add("is-verifying"); $("approval-verification").hidden = false;
    $("approval-description").textContent = `Verify it is you to use ${row.dataset.name}.`;
    $("approval-password").focus();
    $("approval-verify-back").onclick = () => { $("approval-password").value = ""; reset(row); };
    $("approval-verification").onsubmit = event => {
      event.preventDefault(); const password = $("approval-password").value; $("approval-password").value = "";
      attempt(() => complete(row, item, password));
    };
  };
  $("approval-reveal").onclick = () => { const input = $("approval-password"); const reveal = input.type === "password"; input.type = reveal ? "text" : "password"; $("approval-reveal").replaceChildren(icon(reveal ? "eye-off" : "eye")); $("approval-reveal").title = reveal ? "Hide" : "Show"; $("approval-reveal").setAttribute("aria-label", $("approval-reveal").title); };
  const choice = (name, username, item, isNew = false, iconOrigin = null) => {
    let row;
    row = button("", () => approve(item, row), "passkey-choice");
    row.dataset.name = name;
    row.dataset.username = username || "";
    const emblem = element("span", null, "passkey-choice-icon"); emblem.append(icon(isNew ? "plus" : "key"));
    const text = element("span", null, "passkey-choice-text"); text.append(element("strong", name)); if (username) text.append(element("small", username));
    const trailing = element("span", null, "passkey-choice-state"); trailing.append(icon("chevron-left"));
    row.append(emblem, text, trailing);
    if (iconOrigin) request("favicon", { origin: iconOrigin }).then(favicon => {
      if (!favicon || !row.isConnected) return;
      const image = document.createElement("img"); image.src = favicon; image.alt = "";
      emblem.replaceChildren(image);
    }).catch(() => {});
    return row;
  };
  if (create) $("approval-items").append(choice("Create a new login", pending.user || "Save in your vault", null, true, pending.origin));
  for (const item of result.items) $("approval-items").append(choice(item.name, item.username || (create ? "Add to this login" : ""), item.id, false, item.iconOrigin));
  if (!create && !result.items.length) {
    $("approval-description").textContent = "";
    const empty = element("div", null, "passkey-empty"); empty.append(icon("key"), element("strong", `No passkey for ${host}`), element("p", "Try another vault account or use a different authenticator.", "hint")); $("approval-items").append(empty);
  }
}
async function declineApproval(fallback) {
  setApprovalBusy(true, fallback ? "Switching to another authenticator…" : "Canceling the passkey request…");
  try {
    await request("passkey_decline", { request: approvalId, ...(fallback ? { fallback: true } : {}) });
    await finishApproval("Passkey request declined.");
  } catch (err) { setApprovalBusy(false, ""); throw err; }
}
$("use-device").onclick = () => attempt(() => declineApproval(true));
$("cancel-passkey").onclick = () => attempt(() => declineApproval(false));
for (const action of ["lock", "sync"]) $(action).onclick = () => attempt(async () => { if (action === "lock" && !await confirmLock()) return; message("Working…"); await request(action); message(""); await refresh(); });
// The master password is tried on every locked account when "All accounts" is
// selected (accounts with a different password just stay locked); with one
// account chosen it unlocks that one.
async function unlockWithPassword(password) {
  const targets = $("account").value === "" ? accountStates.filter(account => !account.unlocked && !account.excluded).map(account => account.name) : [];
  if (targets.length < 2) { await request("unlock", { password }); return; }
  let unlockedAny = false, lastError;
  for (const name of targets) {
    try { await request("unlock", { password, account: name }); unlockedAny = true; } catch (error) { lastError = error; }
  }
  if (!unlockedAny) throw lastError;
}
$("unlock-form").onsubmit = event => {
  event.preventDefault();
  const password = $("unlock-password").value; $("unlock-password").value = "";
  attempt(async () => { await cancelFingerprint(); message("Unlocking…"); await unlockWithPassword(password); lockedSeen = null; await refresh(); message("Vault unlocked."); });
};
// Fingerprint unlock runs in rbw-browser (fprintd, then the enrolled keyring
// password); the popup only sees the outcome. The "rbw-fingerprint" port lets
// the background cancel the scan when this popup closes.
let fingerprintPort = null, fingerprintCancelled = false;
const fingerprintAutoStarted = new Set();
function fingerprintScanning(scanning) {
  $("unlock-fingerprint").disabled = scanning;
  $("unlock-fingerprint").classList.toggle("is-scanning", scanning);
  $("unlock-fingerprint-label").textContent = scanning ? "Touch the fingerprint sensor…" : "Fingerprint";
}
async function cancelFingerprint() {
  if (!fingerprintPort) return;
  fingerprintCancelled = true;
  await request("cancel_unlock").catch(() => {});
}
async function fingerprintUnlock(account = null) {
  if (fingerprintPort) return;
  fingerprintPort = api.runtime.connect({ name: "rbw-fingerprint" }); fingerprintCancelled = false;
  if (account) message(`Touch the fingerprint sensor to unlock ${account}…`); else fingerprintScanning(true);
  try {
    await attempt(async () => {
      try { await request("unlock", account ? { fingerprint: true, account } : { fingerprint: true }); }
      catch (error) { if (fingerprintCancelled) return; throw error; }
      lockedSeen = null; await refresh();
      if (accountStates.every(a => a.unlocked || a.excluded)) { $("account-menu").hidden = true; $("account-details").open = false; }
      message("Vault unlocked.");
    });
  } finally { fingerprintPort.disconnect(); fingerprintPort = null; if (!account) fingerprintScanning(false); }
}
$("unlock-fingerprint").onclick = () => fingerprintUnlock();
$("unlock").onclick = () => { show(approvalId ? "approval" : "locked"); $("account-menu").hidden = true; $("unlock-password").focus(); };
$("header-lock").onclick = $("lock").onclick;
// Syncs in place (the settings page stays open), spinning the icon meanwhile.
$("header-sync").onclick = () => attempt(async () => {
  const button = $("header-sync");
  button.classList.add("is-syncing"); button.disabled = true;
  try { await request("sync"); message("Vault synced."); }
  finally { button.classList.remove("is-syncing"); button.disabled = !unlocked; }
});
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
$("account").onchange = () => attempt(async () => { await request("set_preferences", { preferences: { popupAccount: $("account").value } }); await refresh(); });
$("filter-toggle").onclick = () => { showFilters($("filters").hidden || !$("filters-clear").hidden); remember(); };
// Keyboard navigation: arrows move a highlight through the item cards (from
// the search field or the list), Enter opens the highlighted item and
// Shift+Enter fills it where filling is offered.
let activeRow = -1;
const itemRows = () => [...$("items").querySelectorAll("article")];
function highlightRow(index, focus) {
  const rows = itemRows(); activeRow = index >= 0 && rows.length ? Math.min(index, rows.length - 1) : -1;
  rows.forEach((row, i) => row.classList.toggle("is-active", i === activeRow));
  rows[activeRow]?.scrollIntoView({ block: "nearest" });
  if (focus) (rows[activeRow]?.querySelector(".item-main") || $("query")).focus({ preventScroll: true });
}
new MutationObserver(() => { activeRow = -1; }).observe($("items"), { childList: true });
$("vault").addEventListener("keydown", event => {
  if (currentPage !== "vault" || event.altKey || event.ctrlKey || event.metaKey) return;
  const inSearch = event.target === $("query"), row = event.target.closest?.("#items article");
  if (!inSearch && !row) return;
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    // In the search field the highlight moves while typing continues; in the
    // list, focus follows the rows (up from the first returns to search).
    const current = row ? itemRows().indexOf(row) : activeRow;
    highlightRow(current < 0 ? (event.key === "ArrowDown" ? 0 : -1) : current + (event.key === "ArrowDown" ? 1 : -1), !inSearch);
  } else if (event.key === "Enter" && (inSearch || event.shiftKey)) {
    const target = row || itemRows()[activeRow >= 0 ? activeRow : 0]; if (!target) return;
    event.preventDefault();
    (event.shiftKey ? target.querySelector(".item-fill") : target.querySelector(".item-main"))?.click();
  }
});
$("query").oninput = () => { remember(); clearTimeout(timer); ++epoch; timer = setTimeout(() => attempt(search), 180); };
for (const chip of document.querySelectorAll("#filters .chip")) chip.onclick = () => showMenu(chip);
$("filters-clear").onclick = () => { for (const [id, value] of Object.entries({ view: "home", folder: "", collection: "", kind: "" })) $(id).value = value; syncChips(); remember(); attempt(search); };
document.addEventListener("pointerdown", event => { if (openMenu && !openMenu.menu.contains(event.target) && !openMenu.chip.contains(event.target)) closeMenu(); });
document.addEventListener("keydown", event => {
  if (!openMenu) return;
  if (event.key === "Escape") { event.stopPropagation(); openMenu.chip.focus(); closeMenu(); }
  else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault(); const items = [...openMenu.menu.querySelectorAll("button")], at = items.indexOf(document.activeElement);
    items[(at + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length]?.focus();
  }
}, true);
$("add").onclick = () => { if (currentPage === "send") editSend(); else editItem(true); };
$("header-edit").onclick = () => editItem();
// A duplicate is a new item prefilled from the original; it exists once saved.
// Attachments and passkeys stay with the original.
async function duplicateItem(item) {
  const detail = await request("detail", { item });
  const cipher = { ...detail.cipher, name: `${detail.cipher.name} (copy)` };
  editItem(true, { account: detail.account, revision: null, noAutofill: false, cipher });
}
$("header-duplicate").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  await duplicateItem(currentItem);
});
$("header-favorite").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  await mutateItem(currentItem, "favorite", currentDetail.favorite);
  await openDetail(currentItem);
});
$("header-archive").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  await mutateItem(currentItem, "archive", currentDetail.archived);
  await openDetail(currentItem);
});
// Fills the active page with an item.
async function autofillItem(item, type) {
  const n = await request("fill", { item, type });
  message(`Filled ${n} fields`);
}
// Like autofillItem, but first adds the page's URL (without query and
// fragment) to the login when it has no URI for that site yet, so it matches
// from now on. Returns whether a URI was added.
async function autofillAndSave(item, knownDetail = null) {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  let url; try { url = new URL(tab?.url || ""); } catch (error) { throw new Error("Open an HTTP or HTTPS page first.", { cause: error }); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Open an HTTP or HTTPS page first.");
  const detail = knownDetail || await request("detail", { item });
  const data = detail.cipher.data, uris = data.uris || [];
  const known = uris.some(entry => { try { return new URL(entry.uri).hostname === url.hostname; } catch (_) { return false; } });
  if (!known) await request("save", { item, revision: detail.revision, cipher: { ...detail.cipher, data: { ...data, uris: [...uris, { uri: `${url.origin}${url.pathname}` }] } } });
  const n = await request("fill", { item, type: data.type });
  message(known ? `Filled ${n} fields` : `Added ${url.hostname}; filled ${n} fields`);
  return !known;
}
$("header-autofill").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  await autofillItem(currentItem, currentDetail.cipher.data.type);
});
$("header-autofill-save").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  if (await autofillAndSave(currentItem, currentDetail)) await openDetail(currentItem);
});
$("header-move").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  const from = currentDetail?.account, name = currentDetail?.cipher.name || "this item";
  const choices = accountNames.filter(account => account !== from).map(account => ({ value: account, label: account }));
  if (!from || !choices.length) return;
  const to = await confirmDialog({ title: `Move “${name}” to another account?`, text: `It is copied from ${from} to the account below; the original goes to ${from}'s trash.`, confirm: "Move", icon: "upload", choices, choiceLabel: "Move to " });
  if (!to) return;
  await request("move", { item: currentItem, to });
  message(`Moved to ${to}. The original is in ${from}'s trash.`); await refresh();
});
$("header-delete").onclick = () => attempt(async () => {
  $("detail-menu").removeAttribute("open");
  if (!await confirmDialog({ title: "Move this item to trash?", text: "You can restore it from the Trash view.", confirm: "Move to trash", danger: true })) return;
  await mutateItem(currentItem, "delete", false);
  await refresh();
});
$("header-cancel-edit").onclick = () => attempt(() => leaveEditor(async () => {
  if (currentItem) await openDetail(currentItem);
  else await refresh();
}));
$("header-save-edit").onclick = () => $("edit-form").requestSubmit();
$("header-cancel-send").onclick = () => attempt(loadSends);
$("header-save-send").onclick = () => $("send-form").requestSubmit();

$("edit-type").onchange = () => renderEditFields();
$("add-custom").onclick = () => addCustom();
async function navigateBack() { if (currentPage === "detail" && detailFrom === "health") { show("health"); document.querySelector("main").scrollTop = healthScroll; } else if (currentPage === "editor") await leaveEditor(() => currentItem ? openDetail(currentItem) : refresh()); else if (currentPage === "send-editor") await loadSends(); else if (currentPage === "settings" && vaultListed) show("vault"); else await refresh(); }
for (const el of document.querySelectorAll("#title-dropdown button")) el.onclick = () => attempt(async () => {
  $("title-menu").open = false;
  const tab = el.dataset.tab;
  await leaveEditor(async () => { if (tab === "vault") await refresh(); else if (tab === "send") await loadSends(); else show(tab); });
});
$("title-summary").onclick = event => {
  if ($("title-menu").classList.contains("is-disabled")) event.preventDefault();
};
document.addEventListener("click", event => {
  if (!event.target.closest("#title-menu")) $("title-menu").open = false;
  for (const m of document.querySelectorAll("details.menu[open]")) {
    if (!m.contains(event.target)) m.open = false;
  }
});
window.addEventListener("keydown", event => {
  // Left arrow goes back from read-only subpages, like the header chevron.
  // Text controls keep it for the caret, and editors never discard edits on it.
  if (event.key === "ArrowLeft" && !event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && !$("back").hidden && !["editor", "send-editor"].includes(currentPage)) {
    const target = event.target;
    if (target.isContentEditable || target.closest?.("input,textarea,select,details.menu[open]")) return;
    event.preventDefault(); attempt(navigateBack); return;
  }
  // Ctrl+C on the generator page copies the generated value, unless some text is selected.
  if ((event.key === "c" || event.key === "C") && (event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey && currentPage === "generator" && !$("copy-generated").disabled) {
    const selected = window.getSelection()?.toString() || "";
    const field = event.target;
    const fieldSelected = typeof field?.selectionStart === "number" && field.selectionStart !== field.selectionEnd;
    if (!selected && !fieldSelected) { event.preventDefault(); $("copy-generated").click(); return; }
  }
  // "e" edits the open item (not while typing, with a menu or dialog open, or in the trash).
  if (event.key === "e" && !event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && currentPage === "detail" && !$("detail-header-actions").hidden) {
    const target = event.target;
    if (target.isContentEditable || target.closest?.("input,textarea,select,dialog[open],details.menu[open]")) return;
    event.preventDefault(); $("header-edit").click(); return;
  }
  if (event.key === "Escape") {
    if ($("title-menu").open) $("title-menu").open = false;
    for (const m of document.querySelectorAll("details.menu[open]")) {
      m.open = false;
    }
  }
});
// Generator: alphabet sizes match rbw's pwgen (src/pwgen.rs); passphrases
// draw from the 7776-word EFF long list.
const GENERATOR_TYPES = {
  password: { label: "Characters", min: 8, max: 128, initial: 40 },
  passphrase: { label: "Words", min: 3, max: 12, initial: 6 },
  pin: { label: "Digits", min: 4, max: 32, initial: 8 },
};
const generator = (() => {
  const fallback = { type: "password", lengths: {}, symbols: true, readable: false };
  try { return { ...fallback, ...JSON.parse(localStorage.getItem("rbw-generator") || "{}") }; } catch (_) { return fallback; }
})();
let generatedValue = ""; let generateTimer = null; let copiedTimer = null;
function saveGenerator() { try { localStorage.setItem("rbw-generator", JSON.stringify(generator)); } catch (_) { /* Per-viewer convenience only. */ } }
function generatorMode() {
  if (generator.type === "passphrase") return "passphrase";
  if (generator.type === "pin") return "numbers";
  return generator.readable ? "nonconfusables" : generator.symbols ? "all" : "no_symbols";
}
function generatorLength() {
  const spec = GENERATOR_TYPES[generator.type];
  const length = Number(generator.lengths[generator.type]);
  return Number.isInteger(length) ? Math.min(spec.max, Math.max(spec.min, length)) : spec.initial;
}
function renderGeneratorControls() {
  const spec = GENERATOR_TYPES[generator.type]; const length = generatorLength();
  for (const option of $("gen-type").querySelectorAll("button")) option.setAttribute("aria-checked", String(option.dataset.type === generator.type));
  Object.assign($("length"), { min: spec.min, max: spec.max, value: length });
  $("length").style.setProperty("--fill", `${(length - spec.min) / (spec.max - spec.min) * 100}%`);
  $("gen-length-label").textContent = spec.label; $("gen-length-value").textContent = length;
  $("gen-range-min").textContent = spec.min; $("gen-range-max").textContent = spec.max;
  $("gen-password-options").hidden = generator.type !== "password";
  $("gen-symbols").checked = generator.symbols && !generator.readable; $("gen-symbols").disabled = generator.readable;
  $("gen-symbols").closest(".switch-row").classList.toggle("is-disabled", generator.readable);
  $("gen-readable").checked = generator.readable;
}
function renderGenerated(value) {
  generatedValue = value; const out = $("generated");
  out.classList.toggle("is-passphrase", generator.type === "passphrase");
  if (generator.type === "passphrase") out.replaceChildren(...value.split(" ").map(word => element("span", word, "w")));
  else out.replaceChildren(...[...value].map(c => /[0-9]/.test(c) ? element("span", c, "d") : /[A-Za-z]/.test(c) ? document.createTextNode(c) : element("span", c, "s")));
  out.classList.remove("is-fresh"); void out.offsetWidth; out.classList.add("is-fresh");
  const pool = { all: 94, no_symbols: 62, numbers: 10, nonconfusables: 24, passphrase: 7776 }[generatorMode()];
  const units = generator.type === "passphrase" ? value.split(" ").length : value.length;
  const bits = Math.round(units * Math.log2(pool));
  const [strength, label] = bits < 45 ? ["weak", "Weak"] : bits < 65 ? ["fair", "Fair"] : bits < 100 ? ["strong", "Strong"] : ["excellent", "Excellent"];
  $("generated").closest(".gen-card").dataset.strength = strength;
  $("gen-meter-fill").style.width = `${Math.min(100, Math.max(6, bits / 160 * 100))}%`;
  $("gen-strength-label").textContent = label; $("gen-entropy").textContent = `${bits} bits`;
}
async function generatePassword() {
  clearTimeout(generateTimer);
  $("generate").classList.remove("is-spinning"); void $("generate").offsetWidth; $("generate").classList.add("is-spinning");
  renderGenerated(await request("generate", { length: generatorLength(), passphrase: generator.type === "passphrase", mode: generatorMode() }));
}
function regenerateSoon(delay = 0) { clearTimeout(generateTimer); generateTimer = setTimeout(() => attempt(generatePassword), delay); }
renderGeneratorControls();
$("gen-type").onclick = event => {
  const type = event.target.closest("button")?.dataset.type; if (!type || type === generator.type) return;
  generator.type = type; saveGenerator(); renderGeneratorControls(); regenerateSoon();
};
$("length").oninput = () => {
  generator.lengths[generator.type] = Number($("length").value); renderGeneratorControls(); regenerateSoon(120);
};
$("length").onchange = () => { saveGenerator(); regenerateSoon(); };
$("gen-symbols").onchange = () => { generator.symbols = $("gen-symbols").checked; saveGenerator(); renderGeneratorControls(); regenerateSoon(); };
$("gen-readable").onchange = () => { generator.readable = $("gen-readable").checked; saveGenerator(); renderGeneratorControls(); regenerateSoon(); };
$("generate").onclick = () => attempt(generatePassword);
// Save the generated value: into a new login for the current site, or as the
// new password of an existing login. Both open the editor for review.
async function generatorSite() {
  for (const query of [{ active: true, currentWindow: true }, { active: true, lastFocusedWindow: true }]) {
    try { const [tab] = await api.tabs.query(query); if (/^https?:\/\//.test(tab?.url || "")) return new URL(tab.url); } catch (_) { /* Try the next window. */ }
  }
  return null;
}
async function renderGeneratorSite() {
  const site = await generatorSite();
  $("gen-save-site").textContent = site ? `Save for ${site.hostname.replace(/^www\./, "")}` : "Save as a new vault item";
}
function requireGenerated() {
  if (!generatedValue) throw new Error("Generate a value first.");
  if (!unlocked) throw new Error("Unlock the vault to save it.");
  return generatedValue;
}
function closeGeneratorPicker() { $("gen-picker").hidden = true; $("gen-save-existing").setAttribute("aria-expanded", "false"); }
$("gen-save-new").onclick = () => attempt(async () => {
  const password = requireGenerated(); const site = await generatorSite();
  const cipher = { name: site ? site.hostname.replace(/^www\./, "") : "", folder: null, notes: null, data: { type: "login", username: "", password, uris: site ? [{ uri: site.origin }] : [] }, fields: [] };
  closeGeneratorPicker(); editItem(true, { item: null, revision: null, cipher, noAutofill: false });
  $("field-username")?.focus();
  message("Generated password filled in. Add a username and save.");
});
let pickerEpoch = 0; let pickerTimer = null;
async function loadGeneratorPicker() {
  const current = ++pickerEpoch; const query = $("gen-picker-query").value.trim();
  const result = await request("search", query ? { query, kind: "login", view: "vault" } : { query: "", siteOnly: true, kind: "login" });
  if (current !== pickerEpoch) return;
  const items = result.items.filter(item => item.type === "login" && !item.deleted).slice(0, 50);
  const list = $("gen-picker-items"); list.replaceChildren();
  if (items.length) list.append(element("h4", query ? "Matching logins" : "Logins for this site"));
  for (const item of items) {
    const choice = element("button"); choice.type = "button";
    choice.append(element("strong", item.name), element("small", item.username || "No username"));
    choice.onclick = () => attempt(() => updateWithGenerated(item.id)); list.append(choice);
  }
  if (!items.length) list.append(element("p", query ? "No logins match." : "No logins for this site. Search your vault above.", "empty"));
}
async function updateWithGenerated(id) {
  const password = requireGenerated();
  await openDetail(id);
  const cipher = structuredClone(currentDetail.cipher); cipher.data = { ...cipher.data, password };
  const noAutofill = Array.isArray(preference.autofillExcludedItems) && preference.autofillExcludedItems.includes(id);
  closeGeneratorPicker(); editItem(false, { item: id, revision: currentDetail.revision, cipher, noAutofill });
  message("New password filled in. Review and save to update this login.");
}
$("gen-save-existing").onclick = () => attempt(async () => {
  requireGenerated();
  if (!$("gen-picker").hidden) { closeGeneratorPicker(); return; }
  $("gen-picker").hidden = false; $("gen-save-existing").setAttribute("aria-expanded", "true");
  $("gen-picker-query").value = ""; await loadGeneratorPicker(); $("gen-picker-query").focus();
});
$("gen-picker-query").oninput = () => { clearTimeout(pickerTimer); pickerTimer = setTimeout(() => attempt(loadGeneratorPicker), 150); };
$("copy-generated").onclick = () => attempt(async () => {
  if (!generatedValue) throw new Error("Generate a value first.");
  await request("copy_text", { text: generatedValue });
  clearTimeout(copiedTimer); $("copy-generated").classList.remove("is-copied"); $("copy-generated").dataset.motion = bannerAnimated() ? "on" : "off"; void $("copy-generated").offsetWidth; $("copy-generated").classList.add("is-copied"); $("copy-generated-label").textContent = "Copied";
  copiedTimer = setTimeout(() => { $("copy-generated").classList.remove("is-copied"); $("copy-generated-label").textContent = "Copy"; }, 1600);
});
// Vault health: tiles that jump to the sections below, each listing the logins
// to open. Long lists show a page at a time.
const AUDIT_PAGE = { groups: 12, items: 25 };
function auditItem(item) {
  // The vault list's own card; older hosts send names only, which can't be opened.
  if (item.id) return itemRow(item, "health");
  const row = element("div", null, "health-item"); row.append(element("strong", item.name)); return row;
}
function auditPaged(container, entries, size, render) {
  const more = element("button", null, "health-more"); more.type = "button"; let shown = 0;
  const step = () => {
    for (const entry of entries.slice(shown, shown + size)) container.insertBefore(render(entry), more);
    shown = Math.min(entries.length, shown + size);
    if (shown >= entries.length) more.remove(); else more.textContent = `Show ${Math.min(size, entries.length - shown)} more · ${entries.length - shown} left`;
  };
  more.onclick = step; container.append(more); step();
}
function auditSection(id, iconName, title, tone, count, note, fill) {
  const section = element(count ? "details" : "div", null, `health-section tone-${count ? tone : "ok"}`); section.id = id;
  const head = element(count ? "summary" : "div", null, count ? "" : "health-head");
  const badge = element("span", null, "health-badge small"); badge.append(icon(count ? iconName : "check"));
  const text = element("span", null, "health-section-title"); text.append(element("strong", title), element("small", count ? note : "All clear"));
  head.append(badge, text);
  if (!count) { section.append(head); return section; }
  const chevron = element("span", null, "health-chevron"); chevron.append(icon("chevron-down"));
  head.append(element("span", String(count), "health-count"), chevron); section.append(head);
  const body = element("div", null, "health-body"); fill(body); section.append(body);
  return section;
}
function renderAudit(result) {
  // Older hosts only list names: show those, without links.
  const named = items => items.map(item => typeof item === "string" ? { name: item } : item);
  const reused = result.reused_items || result.reused.map(named), short = result.short_items || named(result.short);
  const noTotp = result.without_totp_items || [], noTotpCount = result.without_totp_items ? noTotp.length : result.without_totp;
  const sharing = reused.reduce((total, group) => total + group.length, 0);
  const card = (body, entries) => { const box = element("div", null, "health-group"); body.append(box); auditPaged(box, entries, AUDIT_PAGE.items, auditItem); };
  const sections = [
    auditSection("health-reused", "warning", "Reused passwords", "danger", reused.length, `${sharing} logins share ${reused.length} ${reused.length === 1 ? "password" : "passwords"}`, body => auditPaged(body, reused, AUDIT_PAGE.groups, group => {
      const box = element("div", null, "health-group"); box.append(element("div", `Shared by ${group.length} logins`, "health-group-head"), ...group.map(auditItem)); return box;
    })),
    auditSection("health-short", "lock", "Short passwords", "warn", short.length, "Fewer than 12 characters", body => card(body, short)),
    auditSection("health-totp", "shield", "No authenticator code", "warn", noTotpCount, "Says nothing about the site’s other 2FA options", body => {
      if (noTotp.length) card(body, noTotp); else body.append(element("p", `${noTotpCount} password logins have no TOTP saved.`, "hint"));
    }),
  ];
  const tiles = element("div", null, "health-tiles");
  for (const [label, count, tone, section] of [["Reused", reused.length, "danger", sections[0]], ["Short", short.length, "warn", sections[1]], ["No TOTP", noTotpCount, "warn", sections[2]]]) {
    const tile = element("button", null, `health-tile tone-${count ? tone : "ok"}`); tile.type = "button"; tile.append(element("strong", String(count)), element("small", label));
    tile.onclick = () => { if (section.tagName === "DETAILS") section.open = true; section.scrollIntoView({ block: "start", behavior: "smooth" }); };
    tiles.append(tile);
  }
  const note = result.logins == null ? "Checked locally." : `${result.logins} ${result.logins === 1 ? "login" : "logins"} checked locally.`;
  $("audit-results").replaceChildren(tiles, ...sections, element("p", `${note} Passwords never leave rbw.`, "hint health-foot"));
  const first = sections.find(section => section.tagName === "DETAILS"); if (first) first.open = true;
}
function renderAuditLoading() {
  const box = element("div", null, "health-loading"), spin = element("span", null, "health-spinner"); spin.append(icon("refresh"));
  box.append(spin, element("strong", "Checking your vault"), element("small", "Looking for reused and short passwords. This stays on this device."));
  $("audit-results").replaceChildren(box);
}
async function runAudit() {
  if (healthState === "loading") return;
  healthState = "loading"; const run = healthRun;
  // A re-check keeps the old results in view while it runs.
  if (!$("audit-results").children.length) renderAuditLoading();
  $("audit").classList.add("is-syncing"); $("audit").disabled = true;
  try {
    const result = await request("audit");
    if (run !== healthRun) return;
    renderAudit(result); healthState = "done";
  } catch (error) {
    if (run === healthRun) { healthState = "idle"; $("audit-results").replaceChildren(); }
    throw error;
  } finally { $("audit").classList.remove("is-syncing"); $("audit").disabled = false; }
}
$("audit").onclick = () => attempt(runAudit);
$("open-options").onclick = event => {
  if (event.ctrlKey || event.metaKey || event.shiftKey) api.runtime.openOptionsPage();
  else show("settings");
};
$("settings-open-options").onclick = () => api.runtime.openOptionsPage();
function applyTheme(theme) { document.documentElement.dataset.theme = theme === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : theme; }
for (const id of ["setting-autofill", "setting-http-fill", "setting-animations", "setting-animation-speed", "setting-card-code", "setting-copy-totp", "setting-autofill-totp", "setting-passkeys", "setting-save", "theme", "setting-generator", "setting-send", "setting-health", "setting-favicons"]) $(id).onchange = () => attempt(async () => {
  $("setting-animation-speed").disabled = $("setting-animations").value === "off";
  $("setting-animation-speed").closest(".switch-row").hidden = $("setting-animations").value === "off";
  preference = await request("set_preferences", { preferences: { autoFill: $("setting-autofill").checked, allowHttpFill: $("setting-http-fill").checked, animations: $("setting-animations").value, animationSpeed: $("setting-animation-speed").value, cardSecurityCode: $("setting-card-code").value, copyTotp: $("setting-copy-totp").checked, autofillTotp: $("setting-autofill-totp").checked, passkeys: $("setting-passkeys").checked, savePrompts: $("setting-save").checked, theme: $("theme").value, showGenerator: $("setting-generator").checked, showSend: $("setting-send").checked, showHealth: $("setting-health").checked, favicons: $("setting-favicons").checked } }); applyTheme(preference.theme); applyTabs();
});
setInterval(() => attempt(async () => {
  if (!approvalId) {
    const id = await activeApproval();
    if (id) { approvalId = id; await refresh(); return; }
  }
  const status = await request("status");
  if (!unlocked && status.unlocked) { await refresh(); message("Vault unlocked."); return; }
  if (unlocked && !status.unlocked) { unlocked = false; clearVault(); show("locked"); message("Vault locked by rbw-agent."); }
}), 3000);
attempt(async () => {
  loading(true);
  try {
    const initial = await request("bootstrap");
    preference = initial.preferences; applyTheme(preference.theme); applyTabs();
    $("setting-autofill").checked = preference.autoFill === true;
    $("setting-http-fill").checked = preference.allowHttpFill === true;
    const managedPreferences = await request("managed_preferences");
    if (Object.hasOwn(managedPreferences, "allowHttpFill")) {
      $("setting-http-fill").disabled = true;
      $("setting-http-fill-managed").hidden = false;
    }
    lockManagedControls(managedPreferences, { copyTotp: "setting-copy-totp", autofillTotp: "setting-autofill-totp", cardSecurityCode: "setting-card-code" });
    $("setting-animations").value = preference.animations;
    $("setting-animation-speed").value = preference.animationSpeed; $("setting-animation-speed").disabled = preference.animations === "off"; $("setting-animation-speed").closest(".switch-row").hidden = preference.animations === "off";
    $("setting-card-code").value = ["fill", "clipboard"].includes(preference.cardSecurityCode) ? preference.cardSecurityCode : "off";
    $("setting-passkeys").checked = preference.passkeys; $("setting-copy-totp").checked = preference.copyTotp === true; $("setting-autofill-totp").checked = preference.autofillTotp === true; $("setting-save").checked = preference.savePrompts; $("theme").value = preference.theme; $("setting-favicons").checked = preference.favicons;
    if (!approvalId) approvalId = await activeApproval();
    const status = initial.status;
    renderAccounts(status.accounts || [], status.primary, preference.popupAccount, status.accountStates || [], status.accountColors);
    const saved = status.unlocked && !approvalId && !initialSearch ? initial.saved : null;
    if (initialSearch) {
      $("view").value = "vault";
      $("kind").value = initialSearch === "cards" ? "card" : initialSearch === "logins" ? "login" : "";
      $("filters").hidden = false;
      $("filter-toggle").setAttribute("aria-expanded", "true");
    }
    if (saved) {
      for (const id of filterIds) {
        const value = saved.filters[id];
        $(id).value = value || (id === "view" ? "home" : "");
      }
      showFilters(saved.expanded); syncChips();
    }
    await refresh(status, !!saved && saved.page !== "vault");
    if (initialSettings) show("settings"); else if (initialGenerator && unlocked) show("generator");
    else if (saved && unlocked && !approvalId) {
      if (saved.page === "detail" && saved.item) await openDetail(saved.item);
      else if (saved.page === "send" && preference.showSend) await loadSends();
      else if (["settings", "generator", "health"].includes(saved.page)) {
        show(saved.page); applyTabs();
      }
      document.querySelector("main").scrollTop = saved.scroll;
      updateFab();
    }
    ready = true; remember();
    const draft = unlocked && !approvalId && !initialSearch ? await request("edit_draft") : null;
    if (draft) await resumeEditDraft(draft);
    const notice = await request("popup_notice");
    if (notice && !approvalId && !draft) message(notice.text, notice.error);
    const syncFailure = !notice && !approvalId && !draft ? await request("passkey_sync_failure").catch(() => null) : null;
    if (syncFailure) message(`The vault could not sync after signing in to ${new URL(syncFailure.origin).host} with a passkey. Sync before using that passkey again.`, true, { label: "Sync now", run: async () => { message("Working…"); await request("sync"); message(""); await refresh(); } });
  } finally { loading(false); }
});

async function send(method, data = {}) { return request("send", { method, data }); }
const SEND_DAYS = [1, 2, 3, 7, 14, 30];
let sendType = "text";
function relativeDays(date) {
  const hours = (new Date(date).getTime() - Date.now()) / 3600000;
  if (hours < 1) return "within the hour";
  if (hours < 24) return `in ${Math.round(hours)} hours`;
  const days = Math.round(hours / 24);
  return days === 1 ? "in 1 day" : `in ${days} days`;
}
async function loadSends() {
  const refresh = $("refresh-sends"); refresh.classList.add("is-syncing"); refresh.disabled = true;
  try { await listSends(); } finally { refresh.classList.remove("is-syncing"); refresh.disabled = false; }
}
async function listSends() {
  show("send"); message("Loading Sends…");
  const items = await send("list"); $("send-items").replaceChildren();
  // With nothing to list, the empty state's own button is the way in, and the popup only needs its height.
  sendCount = items.length; document.documentElement.toggleAttribute("data-send-empty", !items.length); $("add").hidden = !items.length;
  const files = items.filter(item => item.type === 1).length;
  $("send-summary").textContent = items.length ? `${items.length} active · ${files} ${files === 1 ? "file" : "files"}` : "";
  for (const item of items) {
    const row = element("article", null, `send-row${item.disabled ? " is-disabled" : ""}`);
    const badge = element("span", null, "send-badge"); badge.append(icon(item.type === 1 ? "upload" : "note")); row.append(badge);
    const main = button("", async () => editSend(await send("detail", { id: item.id })), "item-main");
    const meta = element("div", null, "send-meta");
    const chip = (text, cls, name) => { const el = element("span", null, cls); if (name) el.append(icon(name)); el.append(document.createTextNode(text)); meta.append(el); };
    if (item.disabled) chip("Disabled", "is-off");
    if (item.deletionDate) { const soon = new Date(item.deletionDate).getTime() - Date.now() < 86400000 * 2; chip(`Deletes ${relativeDays(item.deletionDate)}`, soon ? "is-soon" : ""); }
    chip(item.maxAccessCount ? `${item.accessCount || 0}/${item.maxAccessCount} views` : `${item.accessCount || 0} views`, item.maxAccessCount && (item.accessCount || 0) >= item.maxAccessCount ? "is-off" : "");
    if (item.hasPassword) chip("Password", "", "lock");
    main.append(element("strong", item.name), meta); row.append(main);
    const actions = element("div", null, "item-actions");
    actions.append(actionButton("Copy link", "copy", async () => { await send("copy", { id: item.id }); message("Send link copied using rbw clipboard settings."); }));
    if (item.hasPassword) actions.append(actionButton("Remove password", "unlock", async () => { if (!await confirmDialog({ title: "Remove the access password?", text: `Anyone with the link to “${item.name}” can open it without a password.`, confirm: "Remove password", icon: "unlock", danger: true })) return; await send("remove_password", { id: item.id }); await loadSends(); }));
    actions.append(actionButton("Delete", "trash", async () => { if (!await confirmDialog({ title: `Delete “${item.name}”?`, text: "The link stops working immediately. This can’t be undone.", confirm: "Delete Send", danger: true })) return; await send("delete", { id: item.id }); await loadSends(); }, "danger"));
    row.append(actions);
    $("send-items").append(row);
  }
  if (!items.length) {
    const empty = element("div", null, "send-empty"); const art = element("span", null, "send-empty-art"); art.append(icon("send"));
    const create = actionButton("New Send", "plus", async () => editSend(), "primary");
    empty.append(art, element("h3", "Share something securely"), element("p", "Send end-to-end encrypted text or files with a link that expires on its own."), create);
    $("send-items").append(empty);
  }
  message("");
}
function setSendType(type) {
  sendType = type;
  for (const option of $("send-type").querySelectorAll("button")) option.setAttribute("aria-checked", String(option.dataset.type === type));
  $("send-text-field").hidden = type !== "text"; $("send-file-field").hidden = type !== "file";
}
function setSendDays(days) {
  $("send-days").value = days;
  for (const chip of $("send-days-chips").children) chip.setAttribute("aria-checked", String(Number(chip.dataset.days) === days));
}
function renderSendFile() {
  const file = $("send-file").files[0]; const locked = $("send-file").disabled;
  $("send-file-field").classList.toggle("has-file", !!file); $("send-file-field").classList.toggle("is-locked", locked);
  $("send-file-name").textContent = file ? file.name : locked ? "File can’t be replaced" : "Choose a file";
  $("send-file-hint").textContent = file ? `${(file.size / 1048576).toFixed(file.size < 1048576 ? 2 : 1)} MB · encrypted before upload` : locked ? "Create a new Send to share another file" : "or drop it here · encrypted before upload";
}
function editSend(item = null) {
  sendId = item?.id || null;
  for (const [id, value] of [["send-name", item?.name], ["send-text", item?.text], ["send-notes", item?.notes], ["send-password", ""], ["send-max", item?.maxAccessCount], ["send-expiration", item?.expirationDate ? new Date(new Date(item.expirationDate).getTime() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : ""]]) $(id).value = value || "";
  $("send-file").value = ""; $("send-file").disabled = !!item; $("send-text").disabled = item?.type === 1;
  $("send-password").type = "password"; $("send-password").placeholder = item ? "Leave blank to keep the current one" : "Optional"; $("send-password-reveal").replaceChildren(icon("eye"));
  setSendType(item?.type === 1 ? "file" : "text");
  for (const option of $("send-type").querySelectorAll("button")) option.disabled = !!item;
  setSendDays(7);
  for (const chip of $("send-days-chips").children) chip.disabled = !!item;
  $("send-days").disabled = !!item; $("send-days-chips").closest(".send-card").querySelector(".send-field-label").textContent = item ? `Deletes ${relativeDays(item.deletionDate)}` : "Delete after";
  $("send-hidden").checked = !!item?.hidden; $("send-hide-email").checked = item?.hideEmail !== false; $("send-disabled").checked = !!item?.disabled;
  renderSendFile();
  show("send-editor");
}
for (const days of SEND_DAYS) {
  const chip = element("button", `${days}d`); chip.type = "button"; chip.setAttribute("aria-label", days === 1 ? "1 day" : `${days} days`); chip.dataset.days = days; chip.setAttribute("role", "radio");
  chip.onclick = () => setSendDays(days); $("send-days-chips").append(chip);
}
$("send-type").onclick = event => { const option = event.target.closest("button"); if (option && !option.disabled) setSendType(option.dataset.type); };
$("send-file").onchange = renderSendFile;
for (const [type, dragging] of [["dragenter", true], ["dragover", true], ["dragleave", false], ["drop", false]]) $("send-file-field").addEventListener(type, () => $("send-file-field").classList.toggle("is-dragging", dragging));
$("send-password-reveal").onclick = () => { const input = $("send-password"); const reveal = input.type === "password"; input.type = reveal ? "text" : "password"; $("send-password-reveal").replaceChildren(icon(reveal ? "eye-off" : "eye")); $("send-password-reveal").title = reveal ? "Hide" : "Show"; $("send-password-reveal").setAttribute("aria-label", $("send-password-reveal").title); };
$("refresh-sends").onclick = () => attempt(loadSends);
$("send-form").onsubmit = event => { event.preventDefault(); attempt(async () => {
  let token;
  try {
    if (sendType === "file" && !sendId && !$("send-file").files[0]) throw new Error("Choose a file to send.");
    const file = sendType === "file" ? $("send-file").files[0] : null;
    if (file) {
      token = await request("upload_begin", { item: "", name: file.name, size: file.size });
      for (let offset = 0; offset < file.size; offset += 192 * 1024) {
        const bytes = new Uint8Array(await file.slice(offset, offset + 192 * 1024).arrayBuffer());
        let text = ""; for (const byte of bytes) text += String.fromCharCode(byte);
        await request("upload_chunk", { token, offset, data: btoa(text) }); message("Uploading file to rbw…");
      }
    }
    const password = $("send-password").value; $("send-password").value = "";
    await send("save", { id: sendId, name: $("send-name").value, text: sendType === "text" ? $("send-text").value : "", notes: $("send-notes").value, password, days: Number($("send-days").value), maxAccessCount: $("send-max").value ? Number($("send-max").value) : null, expirationDate: $("send-expiration").value ? new Date($("send-expiration").value).toISOString() : null, hidden: $("send-hidden").checked, hideEmail: $("send-hide-email").checked, disabled: $("send-disabled").checked, file_token: token || null });
    $("send-text").value = ""; $("send-notes").value = ""; $("send-file").value = ""; await loadSends(); message("Send saved.");
  } finally { if (token) await request("upload_cancel", { token }).catch(() => {}); }
}); };

// Hovering an entry for a couple of seconds scrolls the names and subtitles
// that the row cuts off with an ellipsis, so the rest can be read; leaving
// puts them back.
const MARQUEE_DELAY = 2000, MARQUEE_PAUSE = 900, MARQUEE_SPEED = 45; // ms, ms, px/s
let marqueeRow = null, marqueeTimer = 0, marqueeFrame = 0, marqueeTexts = [];
function stopMarquee() {
  clearTimeout(marqueeTimer); cancelAnimationFrame(marqueeFrame);
  for (const text of marqueeTexts) { text.scrollLeft = 0; text.style.textOverflow = ""; }
  marqueeTexts = [];
}
function startMarquee(row) {
  marqueeTexts = [...row.querySelectorAll("strong, small")].filter(text => text.scrollWidth > text.clientWidth);
  if (!marqueeTexts.length) return;
  for (const text of marqueeTexts) text.style.textOverflow = "clip";
  const distances = marqueeTexts.map(text => text.scrollWidth - text.clientWidth);
  const scrolling = Math.max(...distances) / MARQUEE_SPEED * 1000, period = MARQUEE_PAUSE + scrolling + MARQUEE_PAUSE;
  let begin = null;
  const step = now => {
    if (!row.isConnected) { stopMarquee(); return; }
    begin ??= now;
    const t = (now - begin) % period, progress = Math.min(1, Math.max(0, (t - MARQUEE_PAUSE) / scrolling));
    marqueeTexts.forEach((text, index) => { text.scrollLeft = distances[index] * progress; });
    marqueeFrame = requestAnimationFrame(step);
  };
  marqueeFrame = requestAnimationFrame(step);
}
document.addEventListener("mouseover", event => {
  const row = event.target.closest?.(".item-main") || null;
  if (row === marqueeRow) return;
  stopMarquee(); marqueeRow = row;
  if (row && !matchMedia("(prefers-reduced-motion: reduce)").matches) marqueeTimer = setTimeout(() => startMarquee(row), MARQUEE_DELAY);
});
document.addEventListener("mouseleave", () => { stopMarquee(); marqueeRow = null; });
// Tab on a master password field hides the typed characters altogether (no
// dots), as in the terminal and GTK unlock dialogs; Tab again shows them.
// The choice is kept for the next time the popup opens.
try { if (localStorage.getItem("rbw-no-echo") === "1") document.documentElement.classList.add("no-echo"); } catch (_) { /* Storage unavailable. */ }
document.addEventListener("keydown", event => {
  const field = event.target;
  if (event.key !== "Tab" || event.shiftKey || event.ctrlKey || event.altKey || event.metaKey || !event.isTrusted || !(field instanceof HTMLInputElement) || !("noEcho" in field.dataset)) return;
  event.preventDefault();
  const hidden = document.documentElement.classList.toggle("no-echo");
  try { localStorage.setItem("rbw-no-echo", hidden ? "1" : "0"); } catch (_) { /* Storage unavailable. */ }
}, true);
