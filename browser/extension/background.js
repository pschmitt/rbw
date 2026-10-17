/* Native operations are only exposed to our own UI, never directly to pages. */
if (typeof importScripts === "function") importScripts("fill.js");
const api = globalThis.browser || chrome;
let serial = 0;
let queue = Promise.resolve();
const pending = new Map();
const offers = new Map();
const fillCycles = new Map();
const popupNotices = new Map();
// Only list metadata lives here. No details, notes, passwords or persistent storage.
const listCache = new Map();
// Navigation only; never save forms or item details. Cleared when the vault locks.
const popupStates = new Map();
const faviconCache = new Map();
const faviconPending = new Map();
let metadataEpoch = 0;
function clearMetadata() {
  ++metadataEpoch;
  for (const map of [listCache, faviconCache]) { for (const entry of map.values()) clearTimeout(entry.timer); map.clear(); }
  faviconPending.clear();
}
function cacheFor(map, key, value, milliseconds, maximum) {
  if (map.size >= maximum) { const first = map.keys().next().value; clearTimeout(map.get(first).timer); map.delete(first); }
  clearTimeout(map.get(key)?.timer);
  const entry = { value, expires: Date.now() + milliseconds }; map.set(key, entry);
  entry.timer = setTimeout(() => { if (map.get(key) === entry) map.delete(key); }, milliseconds);
}
async function favicon(origin) {
  if (faviconPending.has(origin)) return faviconPending.get(origin);
  const operation = fetchFavicon(origin); faviconPending.set(origin, operation);
  try { return await operation; } finally { if (faviconPending.get(origin) === operation) faviconPending.delete(origin); }
}
async function fetchFavicon(origin) {
  const generation = metadataEpoch;
  const url = new URL(origin);
  if (url.origin !== origin || url.username || url.password || !(url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost"))) return null;
  const cached = faviconCache.get(origin); if (cached) return cached.value;
  let value = null;
  try {
    const response = await fetch(origin + "/favicon.ico", { credentials: "omit", referrerPolicy: "no-referrer", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(3000) });
    const type = response.headers.get("content-type")?.split(";")[0].trim();
    if (!response.ok || !["image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon", "image/vnd.microsoft.icon", "image/avif"].includes(type)) throw new Error("No icon");
    if (Number(response.headers.get("content-length")) > 128 * 1024) throw new Error("Icon too large");
    const reader = response.body.getReader(); let length = 0; const chunks = [];
    while (true) {
      const { done, value: chunk } = await reader.read(); if (done) break;
      length += chunk.length;
      if (length > 128 * 1024) { await reader.cancel(); throw new Error("Icon too large"); }
      chunks.push(chunk);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
    value = `data:${type};base64,${btoa(binary)}`;
  } catch (_) { /* Missing icons retain the local item-type icon. */ }
  if (generation === metadataEpoch) cacheFor(faviconCache, origin, value, 5 * 60 * 1000, 128); return value;
}
const defaults = { passkeys: true, savePrompts: true, inlineSuggestions: true, autoFill: false, theme: "dark", account: "", showGenerator: true, showSend: false, showHealth: false, favicons: true };
async function settings() { return { ...defaults, ...(await api.storage.local.get("preferences")).preferences }; }
let nativePort;
const nativeRequests = new Map();
function native(request) {
  if (!nativePort) {
    nativePort = api.runtime.connectNative("org.rbw.browser");
    nativePort.onMessage.addListener(response => {
      if (response.code === "browser_not_authorized") {
        clearMetadata(); popupStates.clear();
        for (const entry of nativeRequests.values()) entry.reject(new Error(response.error));
        nativeRequests.clear();
        return;
      }
      const entry = nativeRequests.get(response.id); if (!entry) return;
      nativeRequests.delete(response.id);
      if (response.error) entry.reject(new Error(response.error)); else entry.resolve(response.result);
    });
    nativePort.onDisconnect.addListener(() => {
      nativePort = null; clearMetadata(); popupStates.clear();
      for (const entry of nativeRequests.values()) entry.reject(new Error("Cannot connect to rbw. Check the native host installation and browser.clients allowlist, then retry."));
      nativeRequests.clear();
    });
  }
  return new Promise((resolve, reject) => {
    const id = ++serial; nativeRequests.set(id, { resolve, reject });
    try { nativePort.postMessage({ ...request, id }); } catch (error) { nativeRequests.delete(id); reject(error); }
  });
}

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:\/\//.test(tab.url)) throw new Error("Open an HTTP or HTTPS page first.");
  return tab;
}
function badge() {
  api.action.setBadgeBackgroundColor({ color: "#64abff" });
  api.action.setBadgeText({ text: pending.size + offers.size ? String(pending.size + offers.size) : "" });
  api.action.setTitle({ title: pending.size ? "rbw — Passkey approval waiting. Click to continue." : "rbw" });
}
function finish(id, response) {
  const operation = pending.get(id);
  if (!operation) return;
  clearTimeout(operation.timer); pending.delete(id); badge(); operation.respond(response);
}
async function checkDocument(operation) {
  const tab = await api.tabs.get(operation.tabId);
  if (tab.url !== operation.topUrl) throw new Error("The requesting page changed.");
  const frame = await api.webNavigation.getFrame({ tabId: operation.tabId, frameId: operation.frameId });
  if (!frame || frame.url !== operation.url || (operation.documentId && frame.documentId && frame.documentId !== operation.documentId)) throw new Error("The requesting document changed.");
  // Document identity is checked by the content script as well; navigation events
  // cancel the pending request even when the replacement has the same URL.
  return tab;
}
async function pageMessage(message, sender, respond) {
  if (sender.id !== api.runtime.id || !sender.tab || !sender.url) return respond({ error: "Invalid sender." });
  const url = new URL(sender.url);
  if (!sender.tab.url || new URL(sender.tab.url).origin !== url.origin) return respond({ fallback: true });
  if (url.protocol !== "https:" && !(url.protocol === "http:" && url.hostname === "localhost")) return respond({ fallback: true });
  if (message.action === "passkey_cancel") {
    for (const [id, p] of pending) if (p.tabId === sender.tab.id && p.pageRequest === message.request) finish(id, { error: "Cancelled." });
    return respond({ result: true });
  }
  const prefs = await settings();
  if (message.action === "passkey_available") return respond({ result: prefs.passkeys });
  if (message.action === "autofill_load") {
    if (!prefs.autoFill || sender.frameId !== 0 || !sender.tab.active) return respond({ result: false });
    const results = await native({ action: "search", account: prefs.account || null, query: "", url: sender.url, site_only: true, kind: "login" });
    if (results.items.length !== 1 || results.items[0].protected) return respond({ result: false });
    return respond({ result: await fill({ item: results.items[0].id }, prefs.account || null) });
  }
  if (message.action === "inline_choices") {
    if (!prefs.inlineSuggestions) return respond({ result: [] });
    try {
      const result = await native({ action: "search", account: prefs.account || null, query: "", url: sender.url, site_only: true, kind: "login" });
      return respond({ result: result.items.slice(0, 5).map(v => ({ id: v.id, name: v.name, username: v.username })) });
    } catch (_) { return respond({ result: [] }); }
  }
  if (message.action === "inline_fill") {
    const tab = await activeTab();
    if (tab.id !== sender.tab.id || new URL(tab.url).origin !== url.origin) return respond({ error: "Page changed." });
    return respond({ result: await fill({ item: message.item }, prefs.account || null) });
  }
  if (message.action === "save_offer") {
    if (!prefs.savePrompts || typeof message.username !== "string" || typeof message.password !== "string" || message.password.length > 4096 || message.username.length > 1024) return respond({ result: false });
    const tabId = sender.tab.id;
    const previous = offers.get(tabId); if (previous) clearTimeout(previous.timer);
    offers.set(tabId, { origin: url.origin, url: sender.url, username: message.username, password: message.password, timer: setTimeout(() => { offers.delete(tabId); badge(); }, 120000) });
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
async function fill(message, account) {
  const tab = await activeTab();
  if (message.expectedTab !== undefined && (tab.id !== message.expectedTab || tab.url !== message.expectedUrl)) throw new Error("The active page changed.");
  let credential, label;
  if (message.type && message.type !== "login") {
    const detail = await native({ action: "detail", account, item: message.item });
    credential = { ...detail.cipher.data, custom: detail.cipher.fields };
    label = detail.cipher.name;
    if (!["card", "identity"].includes(credential.type)) throw new Error("This item cannot fill a form.");
  } else {
    credential = { type: "login", ...await native({ action: "credential", account, item: message.item, url: tab.url }) };
  }
  const current = await activeTab();
  if (current.id !== tab.id || current.url !== tab.url) throw new Error("Page changed. Choose Fill again.");
  const frames = await api.webNavigation.getAllFrames({ tabId: tab.id });
  let count = 0;
  for (const frame of frames.filter(f => { try { return new URL(f.url).origin === new URL(tab.url).origin; } catch (_) { return false; } })) {
    try {
      const results = await api.scripting.executeScript({ target: { tabId: tab.id, frameIds: [frame.frameId] }, func: fillPage, args: [frame.url, credential] });
      count += results[0]?.result || 0;
    } catch (error) { if (frame.frameId === 0 && frames.length === 1) throw error; }
  }
  if (!count) throw new Error("No supported fields found on this page.");
  // Only public display metadata goes to the notice, never the credential.
  const notice = { name: label || credential.name || "Item", username: credential.type === "login" ? credential.username : null, position: message.cycleIndex, total: message.cycleCount };
  await api.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func: showFillNotice, args: [tab.url, notice] }).catch(() => {});
  return count;
}
async function handle(message) {
  const account = message.account || null;
  if (["lock", "sync", "save", "mutate", "set_collections", "folders", "import", "save_offer_apply", "passkey_approve"].includes(message.action)) clearMetadata();
  switch (message.action) {
    case "unlock": return native({ action: "unlock", account, password: typeof message.password === "string" ? message.password : null });
    case "status": {
      const state = await native({ action: "status", account });
      if (!state.unlocked) { clearMetadata(); popupStates.clear(); } return state;
    }
    case "sync": case "audit":
      return native({ action: message.action, account });
    case "lock":
      fillCycles.clear(); popupNotices.clear(); popupStates.clear();
      for (const id of [...pending.keys()]) finish(id, { error: "Vault locked." });
      for (const offer of offers.values()) clearTimeout(offer.timer); offers.clear(); badge();
      return native({ action: "lock", account });
    case "export": return native({ action: "export", account, format: message.format, password: message.password || null, attachments: !!message.attachments });
    case "import": return native({ action: "import", account, token: message.token, password: message.password || null, overwrite: !!message.overwrite });
    case "agent_settings": return native({ action: "agent_settings", account });
    case "popup_notice": {
      const [tab] = await api.tabs.query({ active: true, currentWindow: true });
      const notice = popupNotices.get(tab?.id); popupNotices.delete(tab?.id);
      return notice && notice.url === tab.url && notice.expires > Date.now() ? notice : null;
    }
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
    case "preferences": return settings();
    case "set_preferences": {
      const old = await settings();
      const next = { ...old, ...Object.fromEntries(Object.entries(message.preferences || {}).filter(([k, v]) => (k in defaults) && typeof v === typeof defaults[k])) };
      if (next.account !== old.account || !next.favicons) clearMetadata();
      await api.storage.local.set({ preferences: next }); return next;
    }
    case "search": {
      let tab; try { tab = await activeTab(); } catch (_) { /* Search also works on internal pages. */ }
      const query = { action: "search", account, query: String(message.query || ""), url: tab?.url || null, site_only: !!message.siteOnly, kind: message.kind || null, folder: message.folder || null, collection: message.collection || null, view: message.view || null };
      const key = JSON.stringify(query); const cached = listCache.get(key);
      if (cached && cached.expires > Date.now()) {
        const state = await native({ action: "status", account });
        if (!state.unlocked) { clearMetadata(); popupStates.clear(); throw new Error("Vault locked by rbw-agent."); }
        return cached.value;
      }
      const result = await native(query); cacheFor(listCache, key, result, 300000, 8); return result;
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
    case "detail": return native({ action: "detail", account, item: message.item });
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
      const result = await native({ action: p.method === "get" ? "passkey_get" : "passkey_create", account, item: message.item || null, password: typeof message.password === "string" ? message.password : null, origin: p.origin, options: p.options });
      await checkDocument(p);
      if (!pending.has(p.id)) throw new Error("The request was cancelled.");
      finish(p.id, { result }); return true;
    }
    case "passkey_decline": finish(message.request, message.fallback ? { fallback: true } : { error: "Passkey request cancelled." }); return true;
    case "save_offers": return [...offers.entries()].map(([tabId, offer]) => ({ tabId, origin: offer.origin, username: offer.username }));
    case "save_offer_apply": {
      const offer = offers.get(message.tabId); if (!offer) throw new Error("Save suggestion expired.");
      if (message.item) {
        const detail = await native({ action: "detail", account, item: message.item });
        // Recheck the originating site with the same native matcher used for fill.
        await native({ action: "credential", account, item: message.item, url: offer.url });
        detail.cipher.data.password = offer.password;
        if (offer.username) detail.cipher.data.username = offer.username;
        await native({ action: "save", account, item: message.item, revision: detail.revision, cipher: detail.cipher });
      } else {
        await native({ action: "save", account, item: null, revision: null, cipher: { name: new URL(offer.origin).hostname, data: { type: "login", username: offer.username, password: offer.password, uris: [{ uri: offer.origin }] }, fields: [] } });
      }
      clearTimeout(offer.timer); offers.delete(message.tabId); badge(); return true;
    }
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
    const independent = ["preferences", "pending", "save_offers", "popup_notice", "favicon", "popup_state", "save_popup_state"].includes(message.action);
    const operation = independent ? handle(message) : queue.then(() => handle(message));
    if (!independent) queue = operation.catch(() => {});
    operation.then(result => respond({ result }), error => respond({ error: error.message || "Operation failed." })); return true;
  }
  if (!sender.tab || !["passkey_request", "passkey_cancel", "passkey_available", "save_offer", "inline_choices", "inline_fill", "autofill_load"].includes(message?.action)) return false;
  pageMessage(message, sender, respond).catch(() => respond({ error: "Request failed." })); return true;
});

api.tabs.onRemoved.addListener(tabId => {
  fillCycles.delete(tabId); popupNotices.delete(tabId);
  for (const [id, p] of pending) if (p.tabId === tabId) finish(id, { error: "Page closed." });
  const offer = offers.get(tabId); if (offer) { clearTimeout(offer.timer); offers.delete(tabId); badge(); }
});
api.tabs.onUpdated.addListener((tabId, change) => {
  if (!change.url && change.status !== "loading") return;
  fillCycles.delete(tabId); popupNotices.delete(tabId);
  for (const [id, p] of pending) if (p.tabId === tabId) finish(id, { error: "Page navigated." });
});
api.runtime.onInstalled.addListener(() => {
  api.contextMenus.removeAll().then(() => api.contextMenus.create({ id: "rbw-open", title: "Fill with rbw…", contexts: ["editable"] }));
});
api.contextMenus.onClicked.addListener(() => api.action.openPopup().catch(() => api.windows.create({ url: api.runtime.getURL("popup.html?surface=window"), type: "popup", width: 460, height: 680 })));
async function fillShortcut() {
  let tab;
  try {
    tab = await activeTab();
    const prefs = await settings(); const account = prefs.account || null;
    const status = await native({ action: "status", account });
    if (!status.unlocked) {
      popupNotices.set(tab.id, { url: tab.url, text: "Unlock rbw to autofill this page, then press the fill shortcut again.", error: false, expires: Date.now() + 60000 });
      fillCycles.delete(tab.id);
      api.action.openPopup({ windowId: tab.windowId }).catch(() => {});
      return;
    }
    const result = await native({ action: "search", account, query: "", url: tab.url, site_only: true, kind: "login" });
    if (!result.items.length) {
      popupNotices.set(tab.id, { url: tab.url, text: "No matching logins for this page. Choose a login or add one to your vault.", error: false, expires: Date.now() + 60000 });
      fillCycles.delete(tab.id);
      api.action.openPopup({ windowId: tab.windowId }).catch(() => {});
      return;
    }
    const signature = JSON.stringify([account, result.items.map(item => item.id)]);
    const previous = fillCycles.get(tab.id);
    const index = previous?.url === tab.url && previous.signature === signature && Date.now() - previous.time < 30000 ? (previous.index + 1) % result.items.length : 0;
    await fill({ item: result.items[index].id, expectedTab: tab.id, expectedUrl: tab.url, cycleIndex: index + 1, cycleCount: result.items.length }, account);
    fillCycles.set(tab.id, { url: tab.url, signature, index, time: Date.now() });
    popupNotices.delete(tab.id);
  } catch (_) {
    if (tab) {
      fillCycles.delete(tab.id);
      popupNotices.set(tab.id, { url: tab.url, text: "Could not autofill this page. Unlock your vault if needed, check that it has a matching login and the page has login fields, then press the fill shortcut again.", error: true, expires: Date.now() + 60000 });
    }
    api.action.openPopup().catch(() => {});
  }
}
api.commands.onCommand.addListener(command => {
  if (command === "open-vault") { api.action.openPopup().catch(() => {}); return; }
  if (command === "fill-login") {
    // Serialize repeated presses so they advance through matches in order.
    const operation = queue.then(fillShortcut); queue = operation.catch(() => {});
  }
});

api.webNavigation.onCommitted.addListener(details => {
  for (const [id, p] of pending) if (p.tabId === details.tabId && p.frameId === details.frameId) finish(id, { error: "Document navigated." });
});
