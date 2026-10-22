/* Native operations are only exposed to our own UI, never directly to pages. */
if (typeof importScripts === "function") importScripts("fill.js");
const api = globalThis.browser || chrome;
let serial = 0;
let queue = Promise.resolve();
const pending = new Map();
const offers = new Map();
const fillCycles = new Map();
const fillUndos = new Map();
const suggestionCounts = new Map();
const badgeRequests = new Map();
const badgeTabs = new Set();
const popupNotices = new Map();
const shortcutTimers = new Map();
const contentShortcutTimes = new Map();
// Only list metadata lives here. No details, notes, passwords or persistent storage.
const listCache = new Map();
const searchPending = new Map();
// Navigation only; never save forms or item details. Cleared when the vault locks.
const popupStates = new Map();
// The one unsaved item edit, so a closed popup can resume it. Memory only,
// like popupStates, and dropped when the vault locks.
let editDraft = null;
// Save suggestions that were dismissed, expired or lost with their tab, so the
// popup can still offer them. Memory only, newest first, dropped on lock.
let unsavedLogins = [];
// Set when the background sync after a passkey sign-in fails; any later
// successful sync clears it.
let passkeySyncFailure = null;
let vaultUnlocked = null;
function setVaultUnlocked(unlocked) {
  if (vaultUnlocked === unlocked) return;
  vaultUnlocked = unlocked;
  badge();
}
function setPasskeySyncFailure(value) {
  if (!value && !passkeySyncFailure) return;
  passkeySyncFailure = value; badge();
}
function rememberUnsaved(offer) {
  if (!offer) return;
  clearTimeout(offer.timer);
  unsavedLogins = [{ id: crypto.randomUUID(), origin: offer.origin, url: offer.url, username: offer.username, password: offer.password, time: Date.now() },
    ...unsavedLogins.filter(entry => entry.origin !== offer.origin || entry.username !== offer.username)].slice(0, 10);
}
const faviconCache = new Map();
const faviconPending = new Map();
let metadataEpoch = 0;
function clearMetadata() {
  ++metadataEpoch; searchPending.clear();
  const tabs = [...new Set([...suggestionCounts.keys(), ...badgeRequests.keys()])]; suggestionCounts.clear(); badgeRequests.clear();
  for (const tabId of tabs) badge(tabId);
  for (const map of [listCache, faviconCache]) { for (const entry of map.values()) clearTimeout(entry.timer); map.clear(); }
  faviconPending.clear();
}
function cacheFor(map, key, value, milliseconds, maximum) {
  if (map.size >= maximum) { const first = map.keys().next().value; clearTimeout(map.get(first).timer); map.delete(first); }
  clearTimeout(map.get(key)?.timer);
  const entry = { value, expires: Date.now() + milliseconds }; map.set(key, entry);
  entry.timer = setTimeout(() => { if (map.get(key) === entry) map.delete(key); }, milliseconds);
}
// Coalesce focus, on-load, shortcut and popup lookups. Credentials never enter this cache.
async function cachedSearch(values) {
  const query = { action: "search", account: values.account || null, query: values.query || "", url: values.url || null, site_only: !!values.site_only, kind: values.kind || null, folder: values.folder || null, collection: values.collection || null, view: values.view || null };
  const key = JSON.stringify(query);
  if (searchPending.has(key)) return searchPending.get(key);
  const generation = metadataEpoch;
  const operation = (async () => {
    const cached = listCache.get(key);
    if (cached && cached.expires > Date.now()) {
      const state = await native({ action: "status", account: query.account });
      setVaultUnlocked(state.unlocked);
      if (!state.unlocked) { clearMetadata(); popupStates.clear(); editDraft = null; unsavedLogins = []; throw new Error("Vault locked by rbw-agent."); }
      if (generation !== metadataEpoch) throw new Error("Vault changed. Retry the operation.");
      return cached.value;
    }
    const result = await native(query);
    if (generation !== metadataEpoch) throw new Error("Vault changed. Retry the operation.");
    setVaultUnlocked(true);
    cacheFor(listCache, key, result, 300000, 32);
    return result;
  })();
  searchPending.set(key, operation);
  try { return await operation; } finally { if (searchPending.get(key) === operation) searchPending.delete(key); }
}
async function favicon(origin) {
  if (faviconPending.has(origin)) return faviconPending.get(origin);
  const operation = fetchFavicon(origin); faviconPending.set(origin, operation);
  try { return await operation; } finally { if (faviconPending.get(origin) === operation) faviconPending.delete(origin); }
}
// Fetch an icon without cookies or referrer and return it as a bounded data
// URL, or null. SVG is fine: images cannot run scripts.
const ICON_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon", "image/vnd.microsoft.icon", "image/avif", "image/svg+xml"];
async function iconDataUrl(source) {
  try {
    const response = await fetch(source, { credentials: "omit", referrerPolicy: "no-referrer", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(3000) });
    const type = response.headers.get("content-type")?.split(";")[0].trim();
    if (!response.ok || !ICON_TYPES.includes(type)) return null;
    if (Number(response.headers.get("content-length")) > 128 * 1024) return null;
    const reader = response.body.getReader(); let length = 0; const chunks = [];
    while (true) {
      const { done, value: chunk } = await reader.read(); if (done) break;
      length += chunk.length;
      if (length > 128 * 1024) { await reader.cancel(); return null; }
      chunks.push(chunk);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
    return `data:${type};base64,${btoa(binary)}`;
  } catch (_) { return null; /* Missing icons retain the local item-type icon. */ }
}
async function fetchFavicon(origin) {
  const generation = metadataEpoch;
  const url = new URL(origin);
  if (url.origin !== origin || url.username || url.password || !(url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost"))) return null;
  const cached = faviconCache.get(origin); if (cached) return cached.value;
  const value = await iconDataUrl(origin + "/favicon.ico");
  if (generation === metadataEpoch) cacheFor(faviconCache, origin, value, 5 * 60 * 1000, 128); return value;
}
const defaults = { passkeys: true, savePrompts: true, inlineSuggestions: true, autoFill: false, allowHttpFill: false, autofillBlocklist: "", autofillExcludedItems: [], animations: "on", animationSpeed: "normal", cardSecurityCode: "off", copyTotp: false, autofillTotp: false, theme: "dark", popupAccount: "", accounts: [], showGenerator: true, showSend: false, showHealth: false, showSettings: true, favicons: true, uriMatchDefault: "" };
// Empty means "use rbw's defaultUriMatch"; otherwise an override for this browser.
const URI_MATCH_TYPES = ["domain", "base_domain", "host", "starts_with", "exact", "regular_expression", "never"];
let uriMatchOverride = null;
function isAutofillBlocked(pageUrl, blocklist) {
  let page;
  try { page = new URL(pageUrl); } catch (_) { return false; }
  for (const raw of String(blocklist || "").split(/\r?\n/)) {
    const entry = raw.trim();
    if (!entry || entry.startsWith("#")) continue;
    if (/^https?:\/\//i.test(entry)) {
      let target;
      try { target = new URL(entry); } catch (_) { continue; }
      if (page.origin !== target.origin) continue;
      const path = target.pathname.replace(/\/+$/, "") || "/";
      if (path === "/" || page.pathname === path || page.pathname.startsWith(`${path}/`)) return true;
      continue;
    }
    if (entry.includes("/") || entry.includes("?") || entry.includes("#")) continue;
    let domain;
    try { domain = new URL(`https://${entry.replace(/^\*\./, "")}`).hostname.toLowerCase(); } catch (_) { continue; }
    if (page.hostname.toLowerCase() === domain || page.hostname.toLowerCase().endsWith(`.${domain}`)) return true;
  }
  return false;
}
function isItemAutofillExcluded(item, excludedItems) {
  return typeof item === "string" && Array.isArray(excludedItems) && excludedItems.includes(item);
}
// Which accounts requests without an explicit account cover: nothing named
// (the rbw CLI's choice), one account, or a list to merge. The legacy single
// `account` preference counts as a selection of one.
let accountScope = {};
function accountScopeOf(prefs) {
  const names = prefs.accounts || [];
  return names.length === 1 ? { account: names[0] } : names.length > 1 ? { accounts: names } : {};
}
async function settings() {
  const stored = (await api.storage.local.get("preferences")).preferences || {};
  let managed = {};
  try { managed = await api.storage.managed.get(null); } catch (_) { /* Managed storage is optional. */ }
  const result = { ...defaults, ...stored, ...managed };
  result.allowHttpFill = result.allowHttpFill === true;
  result.accounts = Array.isArray(result.accounts) ? result.accounts.filter(name => typeof name === "string" && name) : [];
  accountScope = accountScopeOf(result);
  result.animations = ["off", "on", "plaid"].includes(stored.animations) ? stored.animations : stored.crabify === true ? "plaid" : "on";
  result.animationSpeed = ["slow", "normal", "fast"].includes(stored.animationSpeed) ? stored.animationSpeed : "normal";
  delete result.crabify;
  if (!URI_MATCH_TYPES.includes(result.uriMatchDefault)) result.uriMatchDefault = "";
  uriMatchOverride = result.uriMatchDefault || null;
  return result;
}
async function refreshVaultLockState(preferences = null) {
  try {
    const prefs = preferences || await settings();
    const status = await native({ action: "status", account: null });
    setVaultUnlocked(status.unlocked);
  } catch (_) { /* The toolbar badge is cosmetic; the popup reports connection errors. */ }
}
// Toolbar feedback while the vault syncs: the crab gets a small badge with
// rotating sync arrows in the top-right corner, standing in for the match
// count until the sync ends. Writes sync afterwards, so they count as well.
const SYNCING_ACTIONS = ["sync", "save", "mutate", "import", "set_collections", "upload_finish", "attachment_delete"];
const SYNC_ICON_PATHS = ["M20 7v5h-5M4 17v-5h5", "M6 6a8 8 0 0 1 14 6M4 12a8 8 0 0 0 14 6"];
const syncAnimation = { active: 0, timer: null, frame: 0, bitmaps: null };
async function toolbarBitmaps() {
  const icons = api.runtime.getManifest().action?.default_icon || {};
  syncAnimation.bitmaps ||= Promise.all([16, 32].map(async size => [size, await createImageBitmap(await (await fetch(api.runtime.getURL(icons[size] || `icons/toolbar-${size}.png`))).blob())]));
  return syncAnimation.bitmaps;
}
function syncFrame(bitmap, size, angle) {
  const canvas = new OffscreenCanvas(size, size); const ctx = canvas.getContext("2d");
  ctx.drawImage(bitmap, 0, 0, size, size);
  const r = size * 0.3, cx = size - r - 0.5, cy = r + 0.5;
  ctx.fillStyle = "#1e1e1e"; ctx.strokeStyle = "#e8e8e8"; ctx.lineWidth = Math.max(1, size / 20);
  ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
  // The popup's sync icon (icons.js `refresh`), spinning inside the badge.
  const k = (r * 1.6) / 24;
  ctx.save(); ctx.translate(cx, cy); ctx.rotate(angle); ctx.scale(k, k); ctx.translate(-12, -12);
  ctx.strokeStyle = "#8ab4f8"; ctx.lineWidth = Math.max(1.2, size / 14) / k; ctx.lineCap = "round"; ctx.lineJoin = "round";
  for (const path of SYNC_ICON_PATHS) ctx.stroke(new Path2D(path));
  ctx.restore();
  return ctx.getImageData(0, 0, size, size);
}
async function drawSyncFrame() {
  try {
    const bitmaps = await toolbarBitmaps(); if (!syncAnimation.active) return;
    const angle = (syncAnimation.frame++ % 12) * (Math.PI / 6);
    await api.action.setIcon({ imageData: Object.fromEntries(bitmaps.map(([size, bitmap]) => [size, syncFrame(bitmap, size, angle)])) });
  } catch (_) { /* Cosmetic only. */ }
}
function syncStarted() {
  if (syncAnimation.active++) return;
  badge(); drawSyncFrame(); syncAnimation.timer = setInterval(drawSyncFrame, 120);
}
function syncFinished() {
  if (--syncAnimation.active > 0) return;
  syncAnimation.active = 0; clearInterval(syncAnimation.timer); syncAnimation.timer = null;
  Promise.resolve(api.action.setIcon({ path: api.runtime.getManifest().action?.default_icon })).catch(() => {});
  badge();
}
let nativePort;
const nativeRequests = new Map();
function native(request) {
  if (!request.account) request = { ...request, ...accountScope };
  if (!SYNCING_ACTIONS.includes(request.action) && !(request.action === "folders" && request.method !== "list")) return nativeCall(request);
  syncStarted();
  const call = (async () => nativeCall(request))();
  call.then(syncFinished, syncFinished);
  if (request.action === "sync") call.then(() => setPasskeySyncFailure(null), () => {});
  return call;
}
function nativeCall(request) {
  if (!nativePort) {
    try { nativePort = api.runtime.connectNative("org.rbw.browser"); }
    catch (cause) {
      const error = new Error(`Could not open the rbw native host connection. Check its manifest and installation, then check browser.clients.${cause?.message ? ` Browser detail: ${cause.message}` : ""}`);
      error.diagnostic = { kind: "native-host-connect-error", occurredAt: new Date().toISOString(), host: "org.rbw.browser", browserDetail: cause?.message || null };
      throw error;
    }
    nativePort.onMessage.addListener(response => {
      if (response.code === "browser_not_authorized") {
        clearMetadata(); popupStates.clear(); editDraft = null; unsavedLogins = [];
        const error = new Error(response.error);
        error.diagnostic = { kind: "native-host-authorization-denied", occurredAt: new Date().toISOString(), host: "org.rbw.browser", browserDetail: response.error };
        for (const entry of nativeRequests.values()) entry.reject(error);
        nativeRequests.clear();
        return;
      }
      const entry = nativeRequests.get(response.id); if (!entry) return;
      nativeRequests.delete(response.id);
      if (response.error) entry.reject(new Error(response.error)); else entry.resolve(response.result);
    });
    nativePort.onDisconnect.addListener(() => {
      const browserError = api.runtime.lastError?.message;
      nativePort = null; clearMetadata(); popupStates.clear(); editDraft = null; unsavedLogins = [];
      const detail = browserError ? ` Browser detail: ${browserError}` : "";
      const error = new Error(`The rbw native host disconnected before replying. Check that rbw-browser, rbw, and rbw-agent are installed together, that the native host manifest points to rbw-browser, and that this extension is allowed by browser.clients.${detail}`);
      error.diagnostic = {
        kind: "native-host-disconnect",
        occurredAt: new Date().toISOString(),
        host: "org.rbw.browser",
        browserDetail: browserError || null,
      };
      for (const entry of nativeRequests.values()) entry.reject(error);
      nativeRequests.clear();
    });
  }
  return new Promise((resolve, reject) => {
    const id = ++serial; nativeRequests.set(id, { resolve, reject });
    // URI matching follows this browser's override of rbw's default, if set.
    if (["search", "credential"].includes(request.action) && request.match_default === undefined) request = { ...request, match_default: uriMatchOverride };
    try { nativePort.postMessage({ ...request, id }); } catch (error) { nativeRequests.delete(id); reject(error); }
  });
}

// The native host handles one request at a time, so a pending fingerprint
// scan can only be stopped by closing the port: that ends rbw-browser and
// fprintd releases the reader. The next request reconnects.
function cancelNative(reason) {
  if (!nativePort) return;
  const port = nativePort; nativePort = null;
  port.disconnect();
  for (const entry of nativeRequests.values()) entry.reject(new Error(reason));
  nativeRequests.clear();
}

// A popup holds an "rbw-fingerprint" port while its scan runs; closing the
// popup drops the port, which cancels the scan.
let fingerprintScans = 0;
async function fingerprintUnlock(account) {
  fingerprintScans++;
  try { return await native({ action: "unlock", account, password: null, fingerprint: true }); }
  finally { fingerprintScans--; }
}

function reportPasskeyProgress(request, step, retry = false) {
  api.runtime.sendMessage({ action: "passkey_progress", request, step, retry }).catch(() => {});
}

async function syncPasskeyStage(account, request, step, failureMessage) {
  for (let attempt = 0; attempt < 2; attempt++) {
    reportPasskeyProgress(request, step, attempt > 0);
    try {
      return await native({ action: "sync", account });
    } catch (_) {
      if (attempt === 1) throw new Error(failureMessage);
    }
  }
}

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:\/\//.test(tab.url)) throw new Error("Open an HTTP or HTTPS page first.");
  return tab;
}
function isSecureFillUrl(url, allowHttpFill = false) {
  try { const u = new URL(url); return u.protocol === "https:" || (u.protocol === "http:" && (["localhost", "127.0.0.1", "[::1]"].includes(u.hostname) || allowHttpFill)); } catch (_) { return false; }
}
function badge(tabId) {
  const locked = vaultUnlocked === false;
  if (tabId === undefined) {
    Promise.resolve(api.action.setBadgeBackgroundColor({ color: locked ? "#b3261e" : "#555555" })).catch(() => {});
    Promise.resolve(api.action.setBadgeText({ text: locked ? "L" : "" })).catch(() => {});
    Promise.resolve(api.action.setTitle({ title: locked ? "rbw — Vault is locked. Click to unlock." : "rbw" })).catch(() => {});
    for (const id of new Set([...badgeTabs, ...suggestionCounts.keys(), ...[...pending.values()].map(p => p.tabId), ...offers.keys()])) badge(id);
    return;
  }
  badgeTabs.add(tabId);
  const approval = [...pending.values()].some(p => p.tabId === tabId);
  const offer = offers.has(tabId);
  const syncFailed = !!passkeySyncFailure;
  const count = suggestionCounts.get(tabId)?.count || 0;
  Promise.resolve(api.action.setBadgeBackgroundColor({ tabId, color: locked || syncFailed ? "#b3261e" : approval || offer ? "#87642a" : "#555555" })).catch(() => {});
  const text = locked ? "L" : syncAnimation.active ? "" : approval || offer || syncFailed ? "!" : count ? (count > 99 ? "99+" : String(count)) : "";
  Promise.resolve(api.action.setBadgeText({ tabId, text })).catch(() => {});
  Promise.resolve(api.action.setTitle({ tabId, title: locked ? "rbw — Vault is locked. Click to unlock." : approval ? "rbw — Passkey approval waiting. Click to continue." : offer ? "rbw — Login save suggestion is on this page." : syncFailed ? "rbw — Vault sync after passkey sign-in failed. Click to sync." : count ? `rbw — ${count} matching login${count === 1 ? "" : "s"}` : "rbw" })).catch(() => {});
}
async function updateSuggestionsBadge(tabId, knownTab) {
  const token = {}; badgeRequests.set(tabId, token);
  try {
    const tab = knownTab || await api.tabs.get(tabId);
    const url = new URL(tab.url);
    if (!["https:", "http:"].includes(url.protocol)) throw new Error("No login matching on internal pages.");
    const prefs = await settings();
    if (isAutofillBlocked(tab.url, prefs.autofillBlocklist)) {
      if (badgeRequests.get(tabId) !== token) return;
      suggestionCounts.set(tabId, { url: tab.url, count: 0 }); badge(tabId);
      return;
    }
    const result = await cachedSearch({ account: null, url: tab.url, site_only: true, kind: "login" });
    if (badgeRequests.get(tabId) !== token) return;
    const count = result.items.filter(item => !isItemAutofillExcluded(item.id, prefs.autofillExcludedItems)).length;
    suggestionCounts.set(tabId, { url: tab.url, count }); badge(tabId);
  } catch (_) {
    if (badgeRequests.get(tabId) !== token) return;
    suggestionCounts.delete(tabId); badge(tabId);
  } finally { if (badgeRequests.get(tabId) === token) badgeRequests.delete(tabId); }
}
async function refreshActiveBadge() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (tab?.id !== undefined) await updateSuggestionsBadge(tab.id, tab);
}
// Bundled images as data URLs, for UI injected into pages (which cannot load
// extension resources). The toolbar crab brands inline headers.
const bundledIcons = new Map();
function bundledIcon(path) {
  if (!bundledIcons.has(path)) bundledIcons.set(path, fetch(api.runtime.getURL(path)).then(async response => {
    const bytes = new Uint8Array(await response.arrayBuffer()); let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return "data:image/png;base64," + btoa(binary);
  }).catch(() => null));
  return bundledIcons.get(path);
}
const getNotificationIcon = () => bundledIcon("icons/rbw-32.png");
async function notifyFill(tab, notice) {
  // Bundle the local brand image into the isolated notice; no public resources
  // or website requests are needed for notification branding.
  const prefs = await settings();
  return api.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func: showFillNotice, args: [tab.url, { ...notice, animations: prefs.animations, animationSpeed: prefs.animationSpeed, icon: await getNotificationIcon() }] });
}
// Inline UI sessions: a content script opens one and hands its token only to
// the extension frame it created. The frame's port is the sole way to act.
const inlineSessions = new Map();
function openInlineSession(values) {
  for (const [token, session] of inlineSessions) if (session.tabId === values.tabId && session.frameId === values.frameId && session.mode === values.mode) closeInlineSession(token);
  if (inlineSessions.size >= 32) closeInlineSession(inlineSessions.keys().next().value);
  const token = crypto.randomUUID();
  inlineSessions.set(token, { ...values, token, port: null, timer: setTimeout(() => closeInlineSession(token), 600000) });
  return token;
}
function closeInlineSession(token, notify = false) {
  const session = inlineSessions.get(token); if (!session) return;
  inlineSessions.delete(token); clearTimeout(session.timer);
  try { session.port?.disconnect(); } catch (_) { /* Already closed. */ }
  if (notify) api.tabs.sendMessage(session.tabId, { action: "rbw_inline_close", token }, { frameId: session.frameId }).catch(() => {});
}
function closeTabInlineSessions(tabId) { for (const [token, session] of inlineSessions) if (session.tabId === tabId) closeInlineSession(token); }
// Pages can hide or cover the frame. Briefly force every page element to be
// hit-testable (a user-origin !important rule beats any page style, including
// pointer-events:none decoys), then let the content script check that the
// frame is unclipped, untransformed, opaque and topmost at the click point.
async function verifyInlineClick(session, x, y) {
  if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
  const target = { tabId: session.tabId, frameIds: [session.frameId] };
  const css = "*,*::before,*::after{pointer-events:auto!important}";
  try { await api.scripting.insertCSS({ target, css, origin: "USER" }); } catch (_) { return false; }
  try { return (await api.tabs.sendMessage(session.tabId, { action: "rbw_inline_verify", token: session.token, x, y }, { frameId: session.frameId }))?.ok === true; }
  catch (_) { return false; }
  finally { await api.scripting.removeCSS({ target, css, origin: "USER" }).catch(() => {}); }
}
async function inlineMessage(port, message, state) {
  if (!state.session) {
    const session = message?.type === "init" && inlineSessions.get(message.token);
    if (!session || session.port || session.tabId !== port.sender.tab.id) { port.disconnect(); return; }
    session.port = port; state.session = session;
    port.onDisconnect.addListener(() => { if (session.port === port) closeInlineSession(session.token, true); });
    port.postMessage({ type: "init", ...session.payload });
    return;
  }
  const session = state.session;
  const relay = action => api.tabs.sendMessage(session.tabId, { action, token: session.token, height: message.height }, { frameId: session.frameId }).catch(() => {});
  if (message.type === "size") { if (Number.isFinite(message.height)) relay("rbw_inline_size"); return; }
  if (message.type === "close") { closeInlineSession(session.token, true); return; }
  const prefs = await settings(); const account = null;
  if (session.mode === "choices") {
    if (message.type === "icons") {
      if (session.kind !== "login" || !prefs.favicons || isAutofillBlocked(session.url, prefs.autofillBlocklist)) return;
      const result = await cachedSearch({ account, url: session.url, site_only: true, kind: "login" });
      const items = await Promise.all(result.items.filter(item => session.allowed.has(item.id)).slice(0, 50).map(async item => ({ id: item.id, favicon: item.iconOrigin ? await favicon(item.iconOrigin) : null })));
      port.postMessage({ type: "icons", items });
    } else if (message.type === "search") {
      // Logins: only this site's matches, which rbw rechecks natively on fill.
      const query = String(message.query || "").slice(0, 256);
      if (session.kind === "login" && isAutofillBlocked(session.url, prefs.autofillBlocklist)) return;
      const result = await cachedSearch(session.kind === "card" ? { account, query, kind: "card" } : { account, query, url: session.url, site_only: true, kind: "login" });
      const eligible = result.items.filter(item => !item.protected && !isItemAutofillExcluded(item.id, prefs.autofillExcludedItems));
      const items = eligible.slice(0, 50).map(item => session.kind === "card"
        ? { id: item.id, name: item.name, brand: String(item.username || "").split(",", 1)[0].trim() }
        : { id: item.id, name: item.name, username: item.username, favicon: prefs.favicons ? faviconCache.get(item.iconOrigin)?.value || null : null });
      for (const item of items) { session.allowed.add(item.id); session.items.set(item.id, item); }
      port.postMessage({ type: "results", sequence: message.sequence, items, total: Math.max(eligible.length, (result.total ?? result.items.length) - (result.items.length - eligible.length)) });
    } else if (message.type === "fill" && session.allowed.has(message.item)) {
      const item = session.items.get(message.item) || {};
      if (!await verifyInlineClick(session, message.x, message.y)) { port.postMessage({ type: "rejected", error: "rbw could not confirm that its window is fully visible. Click again." }); return; }
      const tab = await activeTab();
      if (tab.id !== session.tabId || new URL(tab.url).origin !== new URL(session.url).origin) throw new Error("Page changed.");
      await api.tabs.sendMessage(session.tabId, { action: "rbw_inline_refocus", token: session.token }, { frameId: session.frameId }).catch(() => {});
      port.postMessage({ type: "state", item: message.item, active: true, name: item.name });
      try {
        const count = await fill({ item: message.item, type: session.kind, displayName: item.name, expectedTab: tab.id, expectedUrl: tab.url }, account);
        port.postMessage({ type: "state", item: message.item, active: false, filled: count > 0, name: item.name });
      } catch (error) { port.postMessage({ type: "state", item: message.item, active: false, error: error.message || "Could not fill this page." }); }
    }
    return;
  }
  const offer = offers.get(session.tabId);
  if (!offer || offer.origin !== session.origin) { port.postMessage({ type: "save_result", error: "Save suggestion expired." }); return; }
  if (message.type === "save_choices") {
    try {
      // Only this site's logins can be updated (rbw rechecks the URI natively).
      const result = await cachedSearch({ account, url: offer.url, site_only: true, kind: "login" });
      const user = (offer.username || "").trim().toLowerCase();
      const items = result.items.filter(item => !item.protected).sort((a, b) => (String(b.username || "").toLowerCase() === user) - (String(a.username || "").toLowerCase() === user));
      port.postMessage({ type: "save_choices", items: items.slice(0, 30).map(item => ({ id: item.id, name: item.name, username: item.username })) });
    } catch (_) { port.postMessage({ type: "save_choices", items: [] }); }
  } else if (message.type === "save") {
    if (!await verifyInlineClick(session, message.x, message.y)) { port.postMessage({ type: "save_result", error: "rbw could not confirm that its window is fully visible. Click again." }); return; }
    try { await applySaveOffer(session.tabId, typeof message.item === "string" ? message.item : null, account); }
    catch (error) { port.postMessage({ type: "save_result", error: error.message || "Could not save login." }); return; }
    closeInlineSession(session.token, true); settings().then(() => refreshActiveBadge()).catch(() => {});
  } else if (message.type === "dismiss") {
    rememberUnsaved(offer); offers.delete(session.tabId); badge();
    closeInlineSession(session.token, true);
  }
}
api.runtime.onConnect.addListener(port => {
  if (port.name === "rbw-fingerprint") {
    if (port.sender?.id !== api.runtime.id || port.sender.url?.split(/[?#]/)[0] !== api.runtime.getURL("popup.html")) { port.disconnect(); return; }
    port.onDisconnect.addListener(() => { if (fingerprintScans) cancelNative("Fingerprint unlock cancelled."); });
    return;
  }
  if (port.name !== "rbw-inline") return;
  const sender = port.sender;
  if (sender?.id !== api.runtime.id || !sender.tab || sender.url?.split(/[?#]/)[0] !== api.runtime.getURL("inline.html")) { port.disconnect(); return; }
  const state = { session: null };
  let chain = Promise.resolve();
  port.onMessage.addListener(message => {
    chain = chain.then(() => inlineMessage(port, message, state)).catch(error => { try { port.postMessage({ type: "rejected", error: error.message || "Request failed." }); } catch (_) { /* Closed. */ } });
  });
});
// Compare a submitted login with this site's stored logins, natively and in
// memory only: identical credentials (e.g. just autofilled) need no prompt; a
// stored username with another password becomes an update suggestion.
// Reprompt-protected logins are never decrypted here, so they never prompt.
async function classifySaveOffer(account, url, username, password) {
  let result;
  try { result = await cachedSearch({ account, url, site_only: true, kind: "login" }); } catch (_) { return { saved: false, update: null }; }
  const user = username.trim().toLowerCase();
  let update = null;
  for (const item of result.items) {
    if (user && String(item.username || "").trim().toLowerCase() !== user) continue;
    if (item.protected) return { saved: true, update: null };
    let stored;
    try { stored = await native({ action: "credential", account, item: item.id, url }); } catch (_) { continue; }
    if (stored.password === password) return { saved: true, update: null };
    if (user && !update) update = { id: item.id, name: item.name, username: item.username || "" };
  }
  return { saved: false, update };
}
// The page's own icon, which the browser already loaded; the user is on this
// site, so unlike vault favicons this reveals nothing new to it.
async function saveOfferIcon(tabId, offer) {
  try {
    const source = (await api.tabs.get(tabId)).favIconUrl;
    if (typeof source === "string" && source.length <= 180000 && /^data:image\/(png|jpeg|gif|webp|x-icon|vnd\.microsoft\.icon|avif|svg\+xml)[;,]/i.test(source)) return source;
    if (typeof source === "string" && /^https:\/\//i.test(source)) {
      const value = await iconDataUrl(source); if (value) return value;
    }
    return await favicon(offer.origin);
  } catch (_) { return null; }
}
async function notifySaveOffer(tabId, offer) {
  const token = openInlineSession({ mode: "save", tabId, frameId: 0, origin: offer.origin, url: offer.url, payload: { mode: "save", host: new URL(offer.origin).host, username: offer.username, update: offer.update || null, favicon: await saveOfferIcon(tabId, offer) } });
  return api.tabs.sendMessage(tabId, { action: "rbw_save_offer", token, origin: offer.origin }, { frameId: 0 });
}

async function applySaveOffer(tabId, item, account) {
  const offer = offers.get(tabId); if (!offer) throw new Error("Save suggestion expired.");
  await saveOfferLogin(offer, item, account);
  clearTimeout(offer.timer); offers.delete(tabId); badge();
  return true;
}
async function saveOfferLogin(offer, item, account) {
  if (item) {
    const detail = await native({ action: "detail", account, item });
    // Recheck the originating site with the same native matcher used for fill.
    await native({ action: "credential", account, item, url: offer.url });
    detail.cipher.data.password = offer.password;
    if (offer.username) detail.cipher.data.username = offer.username;
    await native({ action: "save", account, item, revision: detail.revision, cipher: detail.cipher });
  } else {
    await native({ action: "save", account, item: null, revision: null, cipher: { name: new URL(offer.origin).hostname.replace(/^www\./, ""), data: { type: "login", username: offer.username, password: offer.password, uris: [{ uri: offer.origin }] }, fields: [] } });
  }
  unsavedLogins = unsavedLogins.filter(entry => entry.origin !== offer.origin || entry.username !== offer.username);
  clearMetadata();
}

function finish(id, response) {
  const operation = pending.get(id);
  if (!operation) return;
  clearTimeout(operation.timer); pending.delete(id); badge(); operation.respond(response);
}
function originOf(url) {
  try { return new URL(url).origin; } catch (_) { return null; }
}
async function checkDocument(operation) {
  // Compare origins, not exact URLs: single-page apps (Authelia, ...) rewrite
  // their URL in place, and browsers disagree on when sender.url, tab.url and
  // the frame URL pick that up. A cross-document navigation of the requesting
  // frame cancels the request (webNavigation.onCommitted), and the document ID
  // pins the document down where the browser provides one.
  const tab = await api.tabs.get(operation.tabId);
  const topOrigin = originOf(operation.topUrl);
  if (originOf(tab.url) !== topOrigin) throw new Error(`The requesting page changed (${topOrigin} → ${originOf(tab.url) || "unknown"}).`);
  const frame = await api.webNavigation.getFrame({ tabId: operation.tabId, frameId: operation.frameId });
  if (!frame) throw new Error("The requesting frame is gone.");
  if (originOf(frame.url) !== operation.origin) throw new Error(`The requesting document changed (${operation.origin} → ${originOf(frame.url) || "unknown"}).`);
  if (operation.documentId && frame.documentId && frame.documentId !== operation.documentId) throw new Error("The requesting document was replaced.");
  return tab;
}
async function pageMessage(message, sender, respond) {
  if (sender.id !== api.runtime.id || !sender.tab || !sender.url) return respond({ error: "Invalid sender." });
  const url = new URL(sender.url);
  if (!sender.tab.url || new URL(sender.tab.url).origin !== url.origin) return respond({ fallback: true });
  if (message.action === "open_settings") {
    return api.windows.create({ url: api.runtime.getURL("popup.html?surface=window&settings=1"), type: "popup", width: 460, height: 680 }).then(() => respond({ result: true }), () => respond({ result: false }));
  }
  const prefs = await settings();
  if (!isSecureFillUrl(sender.url, prefs.allowHttpFill)) return respond({ fallback: true });
  if (message.action === "passkey_cancel") {
    for (const [id, p] of pending) if (p.tabId === sender.tab.id && p.pageRequest === message.request) finish(id, { error: "Cancelled." });
    return respond({ result: true });
  }
  if (["undo_fill", "dismiss_fill"].includes(message.action)) {
    const undo = fillUndos.get(sender.tab.id);
    if (!undo || undo.token !== message.token || undo.url !== sender.tab.url || sender.url !== undo.url) return respond({ result: 0 });
    fillUndos.delete(sender.tab.id); clearTimeout(undo.timer);
    let restored = 0;
    for (const frame of undo.frames) {
      try {
        const results = await api.scripting.executeScript({ target: { tabId: sender.tab.id, frameIds: [frame.frameId] }, func: undoPageFill, args: [frame.url, undo.token, message.action === "undo_fill"] });
        restored += results[0]?.result || 0;
      } catch (_) { /* A navigated or removed frame has no surviving undo state. */ }
    }
    return respond({ result: restored });
  }
  const autofillBlocked = isAutofillBlocked(sender.url, prefs.autofillBlocklist);
  if (message.action === "passkey_available") return respond({ result: prefs.passkeys });
  if (message.action === "autofill_load") {
    if (!prefs.autoFill || autofillBlocked || sender.frameId !== 0 || !sender.tab.active) return respond({ result: false });
    const results = await cachedSearch({ account: null, url: sender.url, site_only: true, kind: "login" });
    const eligible = results.items.filter(item => !item.protected && !isItemAutofillExcluded(item.id, prefs.autofillExcludedItems));
    if (!eligible.length) return respond({ result: false });
    if (message.otp) {
      // A 2FA step: fill the code of the login last filled here, else of the
      // first matching login that has an authenticator key.
      if (!prefs.autofillTotp) return respond({ result: false });
      const last = fillCycles.get(sender.tab.id)?.item;
      for (const item of [...eligible].sort((a, b) => (b.id === last) - (a.id === last)).slice(0, 5)) {
        try {
          if ((await native({ action: "credential", account: null, item: item.id, url: sender.url })).hasTotp !== true) continue;
          return respond({ result: await fill({ item: item.id, totpOnly: true, automatic: true, expectedTab: sender.tab.id, expectedUrl: sender.tab.url }, null) });
        } catch (_) { /* Try the next login. */ }
      }
      return respond({ result: false });
    }
    return respond({ result: await fill({ item: eligible[0].id, automatic: true, cycleIndex: 1, cycleCount: eligible.length, expectedTab: sender.tab.id, expectedUrl: sender.tab.url }, null) });
  }
  if (message.action === "inline_open") {
    if (!prefs.inlineSuggestions || autofillBlocked) return respond({ result: null });
    const kind = message.kind === "card" ? "card" : "login";
    // With auto-fill on page load the login is filled for you (the page may
    // focus its field before that has started); only an explicit request
    // (the inline icon) lists logins.
    if (kind === "login" && prefs.autoFill && message.explicit !== true) return respond({ result: null });
    try {
      const result = await cachedSearch(kind === "card"
        ? { account: null, kind: "card" }
        : { account: null, url: sender.url, site_only: true, kind: "login" });
      const eligible = result.items.filter(v => !v.protected && !isItemAutofillExcluded(v.id, prefs.autofillExcludedItems));
      if (!eligible.length) return respond({ result: null });
      const items = eligible.slice(0, 5).map(v => ({ id: v.id, name: v.name, username: v.username, brand: kind === "card" ? String(v.username || "").split(",", 1)[0].trim() : null,
        favicon: kind === "login" && prefs.favicons ? faviconCache.get(v.iconOrigin)?.value || null : null }));
      const total = Math.max(eligible.length, (result.total ?? result.items.length) - (result.items.length - eligible.length));
      const token = openInlineSession({ mode: "choices", kind, tabId: sender.tab.id, frameId: sender.frameId, url: sender.url, allowed: new Set(items.map(v => v.id)), items: new Map(items.map(v => [v.id, v])), payload: { mode: "choices", kind, items, total } });
      return respond({ result: token, appIcon: await bundledIcon("icons/toolbar-48.png") });
    } catch (_) { return respond({ result: null }); }
  }
  if (message.action === "keyboard_fill_shortcut") {
    const tabId = sender.tab.id;
    contentShortcutTimes.set(tabId, Date.now());
    clearTimeout(shortcutTimers.get(tabId)); shortcutTimers.delete(tabId);
    const operation = queue.then(() => fillShortcut(tabId));
    queue = operation.catch(() => {});
    return respond({ result: await operation });
  }
  if (message.action === "save_offer") {
    if (!prefs.savePrompts || typeof message.username !== "string" || typeof message.password !== "string" || message.password.length > 4096 || message.username.length > 1024) return respond({ result: false });
    const tabId = sender.tab.id;
    const known = await classifySaveOffer(null, sender.url, message.username, message.password);
    if (known.saved) return respond({ result: false });
    const previous = offers.get(tabId); if (previous && (previous.origin !== url.origin || previous.username !== message.username)) rememberUnsaved(previous); else if (previous) clearTimeout(previous.timer);
    const offer = { origin: url.origin, url: sender.url, username: message.username, password: message.password, update: known.update, timer: setTimeout(() => { rememberUnsaved(offers.get(tabId)); offers.delete(tabId); badge(); api.tabs.sendMessage(tabId, { action: "rbw_save_offer_clear" }).catch(() => {}); }, 120000) };
    offers.set(tabId, offer);
    notifySaveOffer(tabId, offer).catch(() => {});
    badge(); return respond({ result: true });
  }
  if (!prefs.passkeys) return respond({ fallback: true });
  if (!["get", "create"].includes(message.method) || typeof message.request !== "string" || JSON.stringify(message.options || {}).length > 65536) return respond({ error: "Invalid passkey request." });
  if ([...pending.values()].some(p => p.tabId === sender.tab.id) || pending.size >= 8) return respond({ error: "Another request is already pending." });
  const id = crypto.randomUUID();
  const operation = { id, method: message.method, origin: url.origin, options: structuredClone(message.options), tabId: sender.tab.id, frameId: sender.frameId, documentId: sender.documentId, topUrl: sender.tab.url, url: sender.url, pageRequest: message.request, respond, timer: setTimeout(() => finish(id, { error: "Passkey request expired." }), 120000) };
  pending.set(id, operation); badge();
  if (!message.conditional) {
    try {
      const tab = await api.tabs.get(sender.tab.id);
      const window = await api.windows.getLastFocused();
      // Open the toolbar UI only for the active page in the focused window.
      // If the browser refuses, keep the request badged for a manual click.
      if (pending.has(id) && tab.active && window.focused && tab.windowId === window.id) {
        await api.action.openPopup({ windowId: tab.windowId });
      }
    } catch (_) { /* The toolbar badge remains available until cancellation/expiry. */ }
  }
}
// Writes `text` to the system clipboard from the page's isolated world (a
// background worker has no clipboard access). The textarea fallback lives in
// a closed shadow root so the page can't read the value from the DOM.
async function copyToClipboard(tabId, text) {
  const [result] = await api.scripting.executeScript({ target: { tabId }, args: [text], func: async value => {
    try { await navigator.clipboard.writeText(value); return true; } catch (_) { /* Fall back to execCommand. */ }
    const host = document.createElement("div"); host.style.cssText = "position:fixed;top:-1000px;opacity:0";
    const area = document.createElement("textarea"); area.value = value; area.setAttribute("readonly", "");
    host.attachShadow({ mode: "closed" }).append(area); document.documentElement.append(host);
    area.select(); let ok = false; try { ok = document.execCommand("copy"); } catch (_) { /* Not allowed. */ }
    host.remove(); return ok;
  } });
  if (!result?.result) throw new Error("Could not write to the clipboard.");
}
async function fill(message, account) {
  const tab = await activeTab();
  const prefs = await settings();
  if (!isSecureFillUrl(tab.url, prefs.allowHttpFill)) throw new Error("rbw does not fill passwords into insecure HTTP pages.");
  if (message.expectedTab !== undefined && (tab.id !== message.expectedTab || tab.url !== message.expectedUrl)) throw new Error("The active page changed.");
  if (isAutofillBlocked(tab.url, prefs.autofillBlocklist)) throw new Error("Autofill is blocked for this site in rbw settings.");
  if (isItemAutofillExcluded(message.item, prefs.autofillExcludedItems)) throw new Error("This item is marked Do not autofill.");
  const token = crypto.randomUUID();
  await api.tabs.sendMessage(tab.id, { action: "rbw_fill_state", token, active: true, item: message.item, name: message.displayName }).catch(() => {});
  let count = 0;
  let securityCodeFieldPresent = false;
  try {
    let credential, label, totpCode = null, shownUsername = null;
    if (message.type && message.type !== "login") {
      const detail = await native({ action: "detail", account, item: message.item });
      credential = { ...detail.cipher.data, custom: detail.cipher.fields };
      label = detail.cipher.name;
      if (!["card", "identity"].includes(credential.type)) throw new Error("This item cannot fill a form.");
    } else {
      credential = { type: "login", ...await native({ action: "credential", account, item: message.item, url: tab.url }) };
      if (message.totpOnly && !(credential.hasTotp === true && prefs.autofillTotp)) throw new Error("No authenticator code to fill.");
      // The code is generated per fill and goes to the page like the password.
      if (credential.hasTotp === true && prefs.autofillTotp) totpCode = (await native({ action: "totp", account, item: message.item })).code;
      shownUsername = credential.username; if (message.totpOnly) credential = { type: "login", name: credential.name, totpOnly: true, totpCode };
      else if (totpCode) credential.totpCode = totpCode;
    }
    await api.tabs.sendMessage(tab.id, { action: "rbw_fill_state", token, active: true, item: message.item, name: label || credential.name || message.displayName }).catch(() => {});
    const current = await activeTab();
    if (current.id !== tab.id || current.url !== tab.url) throw new Error("Page changed. Choose Fill again.");
    const frames = await api.webNavigation.getAllFrames({ tabId: tab.id });
    const filledFrames = [];
    const cardSecurityCode = ["fill", "clipboard"].includes(prefs.cardSecurityCode) ? prefs.cardSecurityCode : "off";
    const fillOptions = { automatic: message.automatic === true, animations: prefs.animations, animationSpeed: prefs.animationSpeed, icon: prefs.animations === "plaid" ? await getNotificationIcon() : null, cardSecurityCode };
    for (const frame of frames.filter(f => { try { return new URL(f.url).origin === new URL(tab.url).origin; } catch (_) { return false; } })) {
      try {
        const results = await api.scripting.executeScript({ target: { tabId: tab.id, frameIds: [frame.frameId] }, func: fillPage, args: [frame.url, credential, token, fillOptions] });
        const result = results[0]?.result || {};
        const filled = typeof result === "number" ? result : result.count || 0;
        count += filled;
        securityCodeFieldPresent ||= result.securityCodeFieldPresent === true;
        if (filled) filledFrames.push({ frameId: frame.frameId, url: frame.url });
      } catch (error) { if (frame.frameId === 0 && frames.length === 1) throw error; }
    }
    if (!count) throw new Error("No supported fields found on this page.");
    // Automatic, inline and popup fills all establish the shortcut's position.
    // Remember the item rather than its index: matching order can change.
    if (credential.type === "login") fillCycles.set(tab.id, { url: tab.url, account, item: message.item });
    const hasSecurityCode = credential.type === "card" && typeof credential.code === "string" && credential.code.length > 0;
    let copiedSecurityCode = false;
    let securityCodeCopyFailed = false;
    if (cardSecurityCode === "clipboard" && hasSecurityCode) {
      try { await native({ action: "copy_text", account, text: credential.code }); copiedSecurityCode = true; }
      catch (_) { securityCodeCopyFailed = true; }
    }
    // A login with TOTP: copy the current code (the native host generates and
    // copies it, so it never reaches the extension) for the site's next step.
    let copiedTotp = false;
    let totpCopyFailed = false;
    if (credential.type === "login" && credential.hasTotp === true && prefs.copyTotp) {
      // Copied by the extension itself, not the agent: the agent may have no
      // clipboard (no display), and then reported success without copying.
      try { await copyToClipboard(tab.id, totpCode || (await native({ action: "totp", account, item: message.item })).code); copiedTotp = true; }
      catch (_) { totpCopyFailed = true; }
    }
    clearTimeout(fillUndos.get(tab.id)?.timer);
    fillUndos.set(tab.id, { token, url: tab.url, frames: filledFrames, timer: setTimeout(() => { if (fillUndos.get(tab.id)?.token === token) fillUndos.delete(tab.id); }, 10000) });
    // Only public display metadata goes to the notice, never the credential.
    const notice = { undoToken: token, name: label || credential.name || "Item", username: credential.type === "login" ? credential.username ?? shownUsername : null, position: message.cycleIndex, total: message.cycleCount, message: message.totpOnly ? `${label || credential.name || "Item"} · 2FA code filled` : totpCopyFailed ? "TOTP code could not be copied" : securityCodeCopyFailed ? "Security code could not be copied" : hasSecurityCode && securityCodeFieldPresent && cardSecurityCode === "off" ? "Security code left blank (see settings)." : hasSecurityCode && !securityCodeFieldPresent && cardSecurityCode === "fill" ? "No security-code field found." : null,
      // The line below the title then names the item (and login) whose code is on the clipboard.
      clipboard: copiedTotp ? "TOTP code copied to clipboard" : copiedSecurityCode ? "Card security code copied to clipboard" : null };
    await notifyFill(tab, notice).catch(() => {});
    return count;
  } finally {
    await api.tabs.sendMessage(tab.id, { action: "rbw_fill_state", token, active: false, item: message.item, filled: count > 0 }).catch(() => {});
  }
}
async function handle(message) {
  const account = message.account || null;
  if (["lock", "sync", "save", "mutate", "set_collections", "folders", "import", "save_offer_apply", "unsaved_login_apply", "passkey_approve", "move"].includes(message.action)) clearMetadata();
  switch (message.action) {
    case "bootstrap": {
      const preferences = await settings();
      const account = null;
      const status = await native({ action: "status", account });
      setVaultUnlocked(status.unlocked);
      if (!status.unlocked) { clearMetadata(); popupStates.clear(); editDraft = null; unsavedLogins = []; }
      const selected = status.primary || status.accounts?.[0] || null;
      return { preferences, status, saved: status.unlocked ? popupStates.get(selected) || popupStates.get(account) || null : null };
    }
    case "unlock": {
      const result = message.fingerprint === true
        ? await fingerprintUnlock(account)
        : await native({ action: "unlock", account, password: typeof message.password === "string" ? message.password : null });
      setVaultUnlocked(true);
      return result;
    }
    case "cancel_unlock":
      cancelNative("Fingerprint unlock cancelled.");
      return true;
    case "status": {
      const state = await native({ action: "status", account });
      setVaultUnlocked(state.unlocked);
      if (!state.unlocked) { clearMetadata(); popupStates.clear(); editDraft = null; unsavedLogins = []; } return state;
    }
    case "sync": case "audit":
      return native({ action: message.action, account });
    case "lock":
      fillCycles.clear(); popupNotices.clear(); popupStates.clear(); editDraft = null; unsavedLogins = [];
      for (const id of [...pending.keys()]) finish(id, { error: "Vault locked." });
      for (const offer of offers.values()) clearTimeout(offer.timer); offers.clear();
      const result = await native({ action: "lock", account });
      setVaultUnlocked(false);
      return result;
    case "export": return native({ action: "export", account, format: message.format, password: message.password || null, attachments: !!message.attachments });
    case "import": return native({ action: "import", account, token: message.token, password: message.password || null, overwrite: !!message.overwrite });
    case "agent_settings": return native({ action: "agent_settings", account });
    case "popup_notice": {
      const [tab] = await api.tabs.query({ active: true, currentWindow: true });
      const notice = popupNotices.get(tab?.id); popupNotices.delete(tab?.id);
      return notice && notice.url === tab.url && notice.expires > Date.now() ? notice : null;
    }
    case "passkey_sync_failure": return passkeySyncFailure;
    case "popup_state": return popupStates.get(account) || null;
    case "save_popup_state": {
      const value = message.state || {};
      const page = ["vault", "detail", "generator", "settings", "send", "health"].includes(value.page) ? value.page : "vault";
      const state = { page, item: typeof value.item === "string" ? value.item.slice(0, 128) : null, expanded: value.expanded === true,
        scroll: Math.max(0, Math.min(Number(value.scroll) || 0, 1000000)), filters: {} };
      for (const key of ["query", "kind", "folder", "collection", "view"]) state.filters[key] = typeof value.filters?.[key] === "string" ? value.filters[key].slice(0, 1024) : "";
      if (popupStates.size >= 8 && !popupStates.has(account)) popupStates.delete(popupStates.keys().next().value);
      popupStates.set(account, state); return true;
    }
    case "edit_draft": return editDraft?.account === account ? editDraft.draft : null;
    case "save_edit_draft": {
      const value = message.draft;
      if (!value || typeof value.cipher !== "object" || JSON.stringify(value.cipher).length > 1000000) { editDraft = null; return true; }
      editDraft = { account, draft: { item: typeof value.item === "string" ? value.item.slice(0, 128) : null, revision: typeof value.revision === "string" ? value.revision.slice(0, 128) : null,
        cipher: value.cipher, noAutofill: value.noAutofill === true } };
      return true;
    }
    case "preferences": return settings();
    case "managed_preferences": {
      try { return await api.storage.managed.get(null); } catch (_) { return {}; }
    }
    case "set_preferences": {
      const old = await settings();
      const next = { ...old, ...Object.fromEntries(Object.entries(message.preferences || {}).filter(([k, v]) => (k in defaults) && typeof v === typeof defaults[k])) };
      next.autofillBlocklist = String(next.autofillBlocklist || "").slice(0, 16384);
      next.accounts = Array.isArray(next.accounts) ? [...new Set(next.accounts.filter(name => typeof name === "string" && name.length <= 256))].slice(0, 64) : [];
      next.autofillExcludedItems = Array.isArray(next.autofillExcludedItems) ? [...new Set(next.autofillExcludedItems.filter(item => typeof item === "string" && item.length > 0 && item.length <= 128))].slice(0, 10000) : [];
      if (!["off", "on", "plaid"].includes(next.animations)) next.animations = "on";
      if (!["slow", "normal", "fast"].includes(next.animationSpeed)) next.animationSpeed = "normal";
      if (!["off", "fill", "clipboard"].includes(next.cardSecurityCode)) next.cardSecurityCode = "off";
      if (!URI_MATCH_TYPES.includes(next.uriMatchDefault)) next.uriMatchDefault = "";
      uriMatchOverride = next.uriMatchDefault || null;
      if (next.popupAccount !== old.popupAccount || JSON.stringify(next.accounts) !== JSON.stringify(old.accounts) || !next.favicons || next.uriMatchDefault !== old.uriMatchDefault) clearMetadata();
      await api.storage.local.set({ preferences: next }); return next;
    }
    case "search": {
      let tab; try { tab = await activeTab(); } catch (_) { /* Search also works on internal pages. */ }
      const query = { action: "search", account, query: String(message.query || ""), url: tab?.url || null, site_only: !!message.siteOnly, kind: message.kind || null, folder: message.folder || null, collection: message.collection || null, view: message.view || null };
      const prefs = await settings();
      const blockedPage = query.url && isAutofillBlocked(query.url, prefs.autofillBlocklist);
      if (blockedPage && query.site_only) return { items: [], total: 0 };
      if (query.view === "home" && !query.query && !query.site_only) {
        // Favorites are independent of the active tab; only suggestions need site matching.
        const favoritesQuery = { ...query, url: null, view: "favorites" };
        const snapshotKey = JSON.stringify({ action: "search", account, query: "", url: null, site_only: false, kind: query.kind, folder: query.folder, collection: query.collection, view: "favorites" });
        if (message.snapshot) {
          const entry = listCache.get(snapshotKey);
          const favorites = entry?.expires > Date.now() ? entry.value : null;
          if (!favorites) return null;
          if (blockedPage) return favorites;
          const matchingKey = JSON.stringify({ ...query, site_only: true, kind: query.kind || "login", view: null });
          const site = listCache.get(matchingKey);
          const matching = site?.expires > Date.now() ? site.value : null;
          if (!matching) return favorites;
          const ids = new Set(matching.items.map(item => item.id));
          const items = [...matching.items, ...favorites.items.filter(item => !ids.has(item.id))];
          return { ...favorites, items, total: items.length };
        }
        const [favorites, matching] = await Promise.all([
          cachedSearch(favoritesQuery),
          query.url && !blockedPage ? cachedSearch({ ...query, site_only: true, kind: query.kind || "login", view: null }) : Promise.resolve({ items: [] }),
        ]);
        const eligibleMatches = matching.items.filter(item => !isItemAutofillExcluded(item.id, prefs.autofillExcludedItems));
        const ids = new Set(eligibleMatches.map(item => item.id));
        const items = [...eligibleMatches, ...favorites.items.filter(item => !ids.has(item.id))];
        return { ...favorites, items, total: items.length };
      }
      if (message.snapshot) return null;
      const result = await cachedSearch(query);
      if (query.site_only) {
        const items = result.items.filter(item => !isItemAutofillExcluded(item.id, prefs.autofillExcludedItems));
        return { ...result, items, total: items.length };
      }
      return result;
    }
    case "favicon": return (await settings()).favicons ? favicon(message.origin) : null;
    case "folders": return native({ action: "folders", account, method: message.method, id: message.id || null, name: message.name || null });
    case "set_collections": return native({ action: "set_collections", account, item: message.item, collections: message.collections });
    case "send": return native({ action: "send", account, method: message.method, data: message.data || {} });
    case "copy_text": return native({ action: "copy_text", account, text: message.text });
    case "attachment_download": return native({ action: "attachment_download", account, item: message.item, attachment: message.attachment });
    case "attachment_delete": return native({ action: "attachment_delete", account, item: message.item, attachment: message.attachment });
    case "upload_begin": return native({ action: "upload_begin", account, item: message.item, name: message.name, size: message.size });
    case "upload_chunk": return native({ action: "upload_chunk", account, token: message.token, offset: message.offset, data: message.data });
    case "upload_finish": return native({ action: "upload_finish", account, token: message.token });
    case "upload_cancel": return native({ action: "upload_cancel", account, token: message.token });
    case "totp": return native({ action: "totp", account, item: message.item });
    case "detail": return native({ action: "detail", account, item: message.item });
    case "move": return native({ action: "move", account, item: message.item, to: message.to });
    case "save": return native({ action: "save", account, item: message.item || null, revision: message.revision || null, cipher: message.cipher });
    case "mutate": return native({ action: "mutate", account, item: message.item, mutation: message.mutation });
    case "copy": return native({ action: "copy", account, item: message.item, field: message.field });
    case "generate": return native({ action: "generate", account, length: message.length || null, passphrase: !!message.passphrase, mode: message.mode || null });
    case "fill": return fill(message, account);
    case "pending": return [...pending.values()].map(p => ({ id: p.id, tabId: p.tabId, method: p.method, origin: p.origin, user: p.options.user?.name, rp: p.options.rp?.id || p.options.rpId || new URL(p.origin).hostname, verification: (p.method === "create" ? p.options.authenticatorSelection?.userVerification : p.options.userVerification) || "preferred" }));
    case "passkey_choices": {
      const p = pending.get(message.request); if (!p) throw new Error("This request has expired.");
      await checkDocument(p);
      if (p.method === "get") return native({ action: "passkey_candidates", account, origin: p.origin, options: p.options });
      return native({ action: "search", account, query: "", url: p.url, site_only: true, kind: "login" });
    }
    case "passkey_approve": {
      const p = pending.get(message.request); if (!p) throw new Error("This request has expired.");
      await checkDocument(p);
      let result;
      if (p.method === "get") {
        await syncPasskeyStage(account, p.id, "before", "Could not sync the vault before signing in. Nothing was signed; sync the vault and try again.");
        if (!pending.has(p.id)) throw new Error("The request was cancelled.");
        await checkDocument(p);
        reportPasskeyProgress(p.id, "signing");
        result = await native({ action: "passkey_get", account, item: message.item || null, password: typeof message.password === "string" ? message.password : null, origin: p.origin, options: p.options });
        const counter = result?.counter;
        if (!Number.isSafeInteger(counter) || counter < 0) throw new Error("The passkey counter could not be confirmed.");
        // The counter is already written to the server before signing; the
        // follow-up sync only confirms it, so don't hold the login for it.
        // The next sign-in syncs first anyway.
        const verify = { action: "passkey_verify", account, item: message.item || null, origin: p.origin, options: p.options, counter };
        syncPasskeyStage(account, p.id, "after", "Could not sync the vault after passkey sign-in.")
          .then(() => native(verify))
          .then(() => setPasskeySyncFailure(null))
          .catch(error => {
            console.warn("rbw: passkey counter confirmation failed:", error);
            setPasskeySyncFailure({ origin: p.origin, time: Date.now() });
          });
        delete result.counter;
      } else {
        result = await native({ action: "passkey_create", account, item: message.item || null, password: typeof message.password === "string" ? message.password : null, origin: p.origin, options: p.options });
      }
      await checkDocument(p);
      if (!pending.has(p.id)) throw new Error("The request was cancelled.");
      finish(p.id, { result }); return true;
    }
    case "passkey_decline": finish(message.request, message.fallback ? { fallback: true } : { error: "Passkey request cancelled." }); return true;
    case "save_offers": return [...offers.entries()].map(([tabId, offer]) => ({ tabId, origin: offer.origin, username: offer.username }));
    case "save_offer_apply": {
      return applySaveOffer(message.tabId, message.item || null, account);
    }
    case "unsaved_logins": {
      // Drop entries the vault caught up with (saved elsewhere since), and
      // recheck which stored login each one would update.
      const entries = [];
      for (const entry of unsavedLogins) {
        const known = await classifySaveOffer(account, entry.url, entry.username, entry.password);
        if (known.saved) unsavedLogins = unsavedLogins.filter(other => other !== entry);
        else entries.push({ id: entry.id, host: new URL(entry.origin).host, username: entry.username, update: known.update, time: entry.time });
      }
      return entries;
    }
    case "unsaved_login_apply": {
      const entry = unsavedLogins.find(other => other.id === message.id); if (!entry) throw new Error("This unsaved login is no longer available.");
      await saveOfferLogin(entry, typeof message.item === "string" ? message.item : null, account); return true;
    }
    case "unsaved_login_dismiss": unsavedLogins = unsavedLogins.filter(entry => entry.id !== message.id); return true;
    case "save_offer_dismiss": {
      const offer = offers.get(message.tabId); if (offer) clearTimeout(offer.timer);
      offers.delete(message.tabId); badge(); return true;
    }
    default: throw new Error("Unknown action.");
  }
}
api.runtime.onMessage.addListener((message, sender, respond) => {
  const page = sender.url?.split(/[?#]/)[0];
  const trustedUI = sender.id === api.runtime.id && [api.runtime.getURL("popup.html"), api.runtime.getURL("options.html")].includes(page);
  // Options and pop-out pages may themselves live in a tab. Authenticate the
  // exact extension document before handling the narrower content-script API.
  if (trustedUI) {
    const independent = ["cancel_unlock", "preferences", "managed_preferences", "pending", "save_offers", "popup_notice", "favicon", "popup_state", "save_popup_state", "edit_draft", "save_edit_draft"].includes(message.action);
    const operation = independent ? handle(message) : queue.then(() => handle(message));
    if (!independent) queue = operation.catch(() => {});
    operation.then(result => {
      respond({ result });
      if (["unlock", "sync", "save", "mutate", "set_preferences", "import", "save_offer_apply", "unsaved_login_apply", "passkey_approve"].includes(message.action)) settings().then(() => refreshActiveBadge()).catch(() => {});
    }, error => respond({ error: error.message || "Operation failed.", diagnostic: error.diagnostic || null })); return true;
  }
  if (!sender.tab || !["passkey_request", "passkey_cancel", "passkey_available", "save_offer", "inline_open", "keyboard_fill_shortcut", "autofill_load", "undo_fill", "dismiss_fill", "open_settings"].includes(message?.action)) return false;
  pageMessage(message, sender, respond).catch(() => respond({ error: "Request failed." })); return true;
});

api.tabs.onRemoved.addListener(tabId => {
  suggestionCounts.delete(tabId); badgeRequests.delete(tabId);
  fillCycles.delete(tabId); popupNotices.delete(tabId);
  for (const [id, p] of pending) if (p.tabId === tabId) finish(id, { error: "Page closed." });
  closeTabInlineSessions(tabId);
  const offer = offers.get(tabId); if (offer) { rememberUnsaved(offer); offers.delete(tabId); badge(); }
  badgeTabs.delete(tabId);
});
api.tabs.onActivated.addListener(({ tabId }) => { updateSuggestionsBadge(tabId).catch(() => {}); });
api.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.url || change.status === "loading") {
    suggestionCounts.delete(tabId); badgeRequests.delete(tabId); badge(tabId);
    fillCycles.delete(tabId); popupNotices.delete(tabId);
    for (const [id, p] of pending) if (p.tabId === tabId) finish(id, { error: "Page navigated." });
    closeTabInlineSessions(tabId);
  }
  const offer = offers.get(tabId);
  if (change.status === "complete" && tab?.url && offer && new URL(tab.url).origin === offer.origin) {
    notifySaveOffer(tabId, offer).catch(() => {});
  }
  if (change.status === "complete" && tab?.active) updateSuggestionsBadge(tabId, tab).catch(() => {});
});
api.windows?.onFocusChanged?.addListener(windowId => {
  if (windowId >= 0) { refreshVaultLockState(); refreshActiveBadge().catch(() => {}); }
});
api.runtime.onInstalled.addListener(() => {
  api.contextMenus.removeAll().then(() => api.contextMenus.create({ id: "rbw-open", title: "Fill with rbw…", contexts: ["editable"] }));
  api.alarms.create("rbw-vault-lock-state", { periodInMinutes: 1 });
  refreshVaultLockState();
});
api.runtime.onStartup.addListener(() => refreshVaultLockState());
api.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "rbw-vault-lock-state") refreshVaultLockState();
});
api.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== "rbw-open" || !tab?.id) return;
  api.tabs.sendMessage(tab.id, { action: "open_inline_suggestions" }, { frameId: info.frameId || 0 }).catch(() => {});
});
async function fillShortcut(tabId) {
  let tab;
  try {
    tab = tabId === undefined ? await activeTab() : await api.tabs.get(tabId);
    if (!tab?.url || !/^https?:\/\//.test(tab.url)) throw new Error("Open an HTTP or HTTPS page first.");
    const prefs = await settings();
    if (!isSecureFillUrl(tab.url, prefs.allowHttpFill)) {
      await notifyFill(tab, { title: "Autofill blocked", error: true, message: "HTTP is unencrypted. Change this in rbw settings.", settingsAction: true }).catch(() => {});
      return;
    }
    const account = null;
    if (isAutofillBlocked(tab.url, prefs.autofillBlocklist)) throw new Error("Autofill is blocked for this site in rbw settings.");
    const status = await native({ action: "status", account });
    setVaultUnlocked(status.unlocked);
    if (!status.unlocked) {
      fillCycles.delete(tab.id);
      await notifyFill(tab, { title: "rbw is locked", error: true, message: "Unlock your vault to autofill this page." }).catch(() => {});
      return;
    }
    const result = await cachedSearch({ account, url: tab.url, site_only: true, kind: "login" });
    const eligible = result.items.filter(item => !isItemAutofillExcluded(item.id, prefs.autofillExcludedItems));
    if (!eligible.length) {
      fillCycles.delete(tab.id);
      await notifyFill(tab, { title: "No matching logins", error: true, message: "No matching logins found for this page." }).catch(() => {});
      return;
    }
    const previous = fillCycles.get(tab.id);
    const previousIndex = previous?.url === tab.url && previous.account === account ? eligible.findIndex(item => item.id === previous.item) : -1;
    const index = (previousIndex + 1) % eligible.length;
    await fill({ item: eligible[index].id, displayName: eligible[index].name, expectedTab: tab.id, expectedUrl: tab.url, cycleIndex: index + 1, cycleCount: eligible.length }, account);
    popupNotices.delete(tab.id);
  } catch (err) {
    if (tab) {
      fillCycles.delete(tab.id);
      await notifyFill(tab, { title: "Autofill failed", error: true, message: err?.message || "Could not autofill this page." }).catch(() => {});
    }
  }
}
api.commands.onCommand.addListener(command => {
  if (command === "open-vault") { api.action.openPopup().catch(() => {}); return; }
  if (command === "fill-login") {
    // Firefox may reserve this shortcut for a browser action. The content
    // fallback handles the page key event; delay the command path briefly to
    // avoid filling twice when both events are delivered.
    api.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
      if (!tab?.id) return;
      if (Date.now() - (contentShortcutTimes.get(tab.id) || 0) < 500) return;
      clearTimeout(shortcutTimers.get(tab.id));
      const timer = setTimeout(() => {
        shortcutTimers.delete(tab.id);
        if (Date.now() - (contentShortcutTimes.get(tab.id) || 0) >= 500) {
          const operation = queue.then(() => fillShortcut(tab.id));
          queue = operation.catch(() => {});
        }
      }, 100);
      shortcutTimers.set(tab.id, timer);
    }).catch(() => {});
  }
});

api.webNavigation.onCommitted.addListener(details => {
  for (const [id, p] of pending) if (p.tabId === details.tabId && p.frameId === details.frameId) finish(id, { error: "Document navigated." });
});

api.alarms.create("rbw-vault-lock-state", { periodInMinutes: 1 });
settings().then(async preferences => {
  await refreshVaultLockState(preferences);
  await refreshActiveBadge();
}).catch(() => {});
