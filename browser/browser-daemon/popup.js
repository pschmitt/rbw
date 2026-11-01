"use strict";
// The toolbar popover: the logins for the live view's page, in the rbw
// popup's look (its popup.css and markup). The secret agent holds the vault
// and the node fills the page, so this frame sees names, users and folders;
// a password or code only goes to the clipboard of the device viewing, when
// you copy it, and never through this frame. Which page and site that is the
// live view decides.
const vault = { site: "", list: null, at: 0, peeking: null, peekSite: "", off: 0, locked: false };
const FRESH = 120000;
let ctx = { site: "", ready: false };
let publicSession = false, shown = false, seq = 0, abort = null, timer = 0, rows = [], query = "";

// As in the extension's toolbar button: locked, the crab's eyes are red and
// the badge is a red L. The picture is drawn by the extension's own code
// (toolbar-icon.js), from the same sprite.
const SPRITE = "icons/toolbar-64.png";
// The bundle's page may not fetch (its CSP has connect-src 'none'), but it may
// load images, and the files carry CORS headers: a decoded sprite for the canvas.
const loadSprite = () => new Promise((resolve, reject) => {
  const image = new Image();
  image.crossOrigin = "anonymous";
  image.onload = () => createImageBitmap(image).then(resolve, reject);
  image.onerror = () => reject(new Error("sprite"));
  image.src = SPRITE;
});
let redEyes = null;
function redEyeIcon() {
  redEyes ||= loadSprite()
    .then((bitmap) => rbwToolbarIcon.dataUrl(rbwToolbarIcon.redEyeFrame(bitmap, bitmap.width))).catch(() => null);
  return redEyes;
}
// After a fill: the crab squashes and hops, as in the extension (toolbar-icon.js),
// then the icon goes back to its resting picture.
let hopping = false;
async function hop() {
  if (hopping || !motion()) return;
  hopping = true;
  try {
    const bitmap = await loadSprite();
    const size = bitmap.width;
    await rbwToolbarIcon.playHop(async (t) => bd.icon(await rbwToolbarIcon.dataUrl(rbwToolbarIcon.hopFrame(bitmap, size, t))));
  } catch (_) { /* Cosmetic only. */ } finally {
    hopping = false;
    badge();
  }
}
// While the vault is being asked (a lookup, an unlock, a fill): the sync ring
// round the crab and no badge, as in the extension.
const syncState = { active: 0, timer: null, frame: 0 };
let spriteBitmap = null;
const sprite = () => (spriteBitmap ||= loadSprite());
const sync = rbwToolbarIcon.spinner(syncState, async (angle) => {
  try {
    const bitmap = await sprite();
    if (!syncState.active || hopping || !motion()) return;
    const src = await rbwToolbarIcon.dataUrl(rbwToolbarIcon.syncFrame(bitmap, bitmap.width, angle));
    if (syncState.active) bd.icon(src); // not after the spinner ended: that frame would outlive it
  } catch (_) { /* Cosmetic only. */ }
}, () => badge());
const vaultRequest = (kind, args, opts) => {
  sync.begin();
  const call = bd.request(kind, args, opts);
  call.then(sync.end, sync.end);
  return call;
};
function badge() {
  if (hopping || syncState.active) { if (syncState.active) bd.badge(null); return; }
  const n = vault.site === ctx.site && Array.isArray(vault.list) ? vault.list.filter((e) => e.site !== false).length : 0;
  if (vault.locked) bd.badge("L", "danger"); else bd.badge(n ? (n > 9 ? "9+" : String(n)) : null);
  if (!vault.locked) { bd.icon(null); $("logo").src = "icons/rbw-64.png"; return; }
  redEyeIcon().then((src) => { if (!src || !vault.locked) return; bd.icon(src); $("logo").src = src; });
}
// After a page load: how many logins the vault has for the site (the button's badge).
// Never asks for an unlock; a node without a secret agent is left alone a while.
function peek() {
  const site = ctx.site;
  badge();
  if (!site || !ctx.ready || vault.peeking || Date.now() < vault.off) return;
  if (vault.site === site && Date.now() - vault.at < FRESH) return;
  vault.peekSite = site;
  vault.peeking = vaultRequest("logins").then((found) => {
    vault.site = site;
    vault.at = Date.now();
    vault.list = Array.isArray(found) ? found : null; // locked: not known
    vault.locked = !!found?.locked;
  }, (err) => {
    if (/secret agent/i.test(err.message)) vault.off = Date.now() + 300000;
  }).finally(() => { vault.peeking = null; badge(); });
}
bd.on("context", (m) => { ctx = { site: m.site || "", ready: !!m.ready }; peek(); });

bd.on("open", (m) => {
  shown = true;
  warning($("public"), m.warning);
  publicSession = !!m.warning;
  $("query").value = query = "";
  $("folder").value = "";
  // Desktop: type right away. Phones: the keyboard would cover the list.
  if (matchMedia("(hover: hover) and (pointer: fine)").matches) $("query").focus();
  load(ctx.site);
});
// Ctrl+Alt+L (the view catches it; the extension's own is Ctrl+Shift+L): fill the
// site's first login, and the next one at each press, as the extension's fill shortcut.
let cycle = { site: "", next: 0 };
bd.on("shortcut", async (m) => {
  if (m.action !== "fill") return;
  const site = ctx.site;
  if (!site || !ctx.ready) return bd.toast("This page is not on a website: there is nothing to fill.", 2500);
  let list;
  try { list = await vaultRequest("logins"); } catch (err) { return bd.toast(`Not filled: ${err.message}`, 4000); }
  if (list?.locked) { vault.locked = true; badge(); return bd.toast("Your vault is locked: open the vault button to unlock it.", 4000); }
  const own = (Array.isArray(list) ? list : []).filter((e) => e.site !== false);
  if (!own.length) return bd.toast("No login saved for this site.", 2500);
  if (cycle.site !== site) cycle = { site, next: 0 };
  const index = cycle.next % own.length, entry = own[index];
  cycle.next = index + 1;
  try {
    await vaultRequest("fill", { entry: entry.id, fields: ["username", "password", "totp"], any_site: false });
    hop();
    const where = own.length > 1 ? ` (${index + 1}/${own.length}, press again for the next)` : "";
    bd.toast(`Filled ${entry.name || "the login"}${entry.user ? ` · ${entry.user}` : ""}${where}`, 3500);
  } catch (err) { bd.toast(`Not filled: ${err.message}`, 5000); }
});
// As the extension says when its browser host is out of date: the bundle (rbw
// as built into this live view) and the rbw the node's secret agent uses should
// share major.minor, or the bundle may ask for things the node does not know.
let bundleVersion = "";
bd.on("init", (m) => { bundleVersion = String(m.version || "").replace(/^v/, ""); });
bd.on("rbw", (m) => {
  const node = String(m.rbw || ""), mine = bundleVersion, el = $("stale");
  const minor = (v) => v.split(".").slice(0, 2).join(".");
  if (!/^\d+\.\d+/.test(node) || !/^\d+\.\d+/.test(mine) || minor(node) === minor(mine)) { el.hidden = true; return; }
  const parts = (v) => v.split(".").map((n) => parseInt(n, 10) || 0);
  const [a, b] = [parts(node), parts(mine)];
  const older = (a.find((n, i) => n !== b[i]) ?? 0) < (b.find((n, i) => n !== a[i]) ?? 0);
  el.textContent = older
    ? `rbw on the node is ${node}, but this live view runs rbw ${mine}: update rbw on the node.`
    : `rbw on the node is ${node}, but this live view runs rbw ${mine}: update the live view's vault bundle.`;
  el.hidden = false;
});
bd.on("closed", () => {
  shown = false;
  seq++;
  abort?.abort();                            // no more polling for a popover nobody sees
  clearTimeout(timer);
  closeMenus();
});
$("close").onclick = () => bd.close("button");
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  e.preventDefault();
  if (document.querySelector("details.menu[open]")) closeMenus(); else bd.close("button");
});
document.addEventListener("click", (e) => { if (!e.target.closest("details.menu")) closeMenus(); });
const closeMenus = () => { for (const m of document.querySelectorAll("details.menu[open]")) m.open = false; };

$("query").oninput = () => {
  clearTimeout(timer);
  const q = $("query").value.trim(), site = ctx.site;
  query = q;
  // Right away: the site's logins that match; the vault's answer follows.
  if (q && Array.isArray(vault.list) && vault.site === site) render(filter(vault.list, q), site, q, true);
  timer = setTimeout(() => load(site, false, q), q ? 350 : 0);
};
$("query").onkeydown = (e) => {
  if (e.key === "Enter") { e.preventDefault(); $("items").querySelector(".item-main")?.click(); }
  if (e.key === "ArrowDown") { e.preventDefault(); $("items").querySelector(".item-main")?.focus(); }
};
$("filter-toggle").onclick = () => {
  const open = $("filters").hidden;
  $("filters").hidden = !open;
  $("filter-toggle").setAttribute("aria-expanded", String(open));
};
$("folder").onchange = () => render(rows, ctx.site, query);

const filter = (list, q) => list.filter((e) => `${e.name || ""} ${e.user || ""} ${e.folder || ""}`.toLowerCase().includes(q.toLowerCase()));
const empty = (text, cls = "") => `<p class="empty ${cls}">${text}</p>`;
// The locked card, as in the extension's popup: the master password (unless the
// session is shared publicly) or the phone.
function lockedCard(site, q, problem, body) {
  const field = publicSession ? "" : `<form id="unlock-form"><div class="unlock-password-row"><input id="unlock-password" type="password" aria-label="Master password" placeholder="Master password" maxlength="4096" autocomplete="off" spellcheck="false" required>` +
    `<button type="submit" class="primary">${ico("unlock")}<span>Unlock</span></button></div></form>`;
  body(`<section id="locked"><div class="lock-art">${ico("lock")}</div><h2>Vault locked</h2>` +
    (problem ? `<p class="empty bad">${esc(problem)}</p>` : "") + field +
    `<div class="actions"><button id="unlock">${ico("unlock")}<span>Unlock from your phone</span></button></div></section>`);
  if (!$("unlock")) return;                     // the view moved on: nothing was drawn
  $("unlock").onclick = () => load(site, true, q);
  const form = $("unlock-form");
  if (!form) return;
  $("unlock-password").focus();
  form.onsubmit = (e) => {
    e.preventDefault();
    const input = $("unlock-password"), password = input.value;
    input.value = "";                          // not kept in this page
    if (password) load(site, false, q, password);
  };
}
async function load(site, unlock = false, q = "", password = null) {
  const mine = ++seq;
  abort?.abort();                            // the previous question is not wanted any more
  const ac = abort = new AbortController();
  const body = (html) => { if (shown && mine === seq) $("items").innerHTML = html; };
  if (!site) return body(empty("This page is not on a website: there is nothing to fill."));
  if (!ctx.ready) return body(empty("Not connected to a session yet."));
  // The badge's lookup for this page is underway: wait for it rather than ask twice.
  if (!unlock && !q && vault.peeking && vault.peekSite === site) {
    body(empty("Looking in the vault…", "checking"));
    await vault.peeking;
  }
  if (!shown || mine !== seq) return;
  const fresh = !unlock && !q && vault.site === site && Array.isArray(vault.list) && Date.now() - vault.at < FRESH;
  if (fresh) return render(vault.list, site, "");
  if (!q || !$("items").querySelector("article")) {
    body(empty(unlock ? "Unlocking the vault…" : q ? "Searching the vault…" : "Looking in the vault…", "checking"));
  }
  let found;
  try {
    found = await vaultRequest("logins", { unlock, query: q || null, ...(password ? { password } : {}) },
      { onNote: (note) => body(empty(esc(note), "locked checking")), signal: ac.signal });
  } catch (err) {
    if (err.aborted) return;
    if (password) return lockedCard(site, q, err.message, body); // wrong password: try again
    return body(empty(esc(err.message), "bad"));
  }
  if (!shown || mine !== seq || ctx.site !== site) return;
  vault.locked = !!found?.locked;
  if (vault.locked) {
    badge();
    return lockedCard(site, q, "", body);
  }
  found = Array.isArray(found) ? found : [];
  if (vault.locked) { vault.locked = false; badge(); }
  if (!q) {
    vault.site = site;
    vault.at = Date.now();
    vault.list = found;
    badge();
  }
  render(found, site, q);
}

// The folder filter offers the folders of what is listed.
function folders(list) {
  const select = $("folder"), current = select.value;
  const names = [...new Set(list.map((e) => e.folder).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  select.replaceChildren(new Option("Folder", ""), ...names.map((n) => new Option(n, n)));
  select.value = names.includes(current) ? current : "";
}

// partial: the site's logins filtered here while the vault search runs.
function render(found, site, q, partial = false) {
  rows = found;
  folders(found);
  const folder = $("folder").value;
  const shownRows = folder ? found.filter((e) => e.folder === folder) : found;
  const list = $("items");
  if (!shownRows.length) {
    list.innerHTML = partial ? empty("Searching the vault…", "checking")
      : empty(q ? `Nothing in your vault matches “${esc(q)}”.` : folder ? `No logins in ${esc(folder)}.` : `No logins for ${esc(site)} in your vault: search for one above.`);
    return;
  }
  const mine = shownRows.filter((e) => e.site !== false), others = shownRows.filter((e) => e.site === false);
  list.replaceChildren();
  if (mine.length) list.append(heading(q ? "Matching this site" : "Autofill suggestions", mine.length), ...mine.map((e) => row(e, site)));
  if (others.length) list.append(heading(mine.length ? "Other logins" : `Not saved for ${site}`, others.length), ...others.map((e) => row(e, site)));
}
function heading(text, n) {
  const h = document.createElement("h3");
  h.textContent = `${text} · ${n}`;
  return h;
}

function button(label, iconName, onclick, cls = "") {
  const b = document.createElement("button");
  b.type = "button";
  if (cls) b.className = cls;
  b.title = label;
  b.setAttribute("aria-label", label);
  b.append(icon(iconName));
  b.onclick = (e) => { e.stopPropagation(); onclick(b); };
  return b;
}
function menuEntry(label, iconName, onclick) {
  const b = button(label, iconName, onclick);
  const span = document.createElement("span");
  span.textContent = label;
  b.append(span);
  return b;
}

// A login, as the popup's itemRow draws it: icon (the site's favicon), name
// and user, then fill, copy and a menu.
function row(e, site) {
  const other = e.site === false;
  const article = document.createElement("article");
  const lead = document.createElement("span");
  lead.className = "item-lead";
  const image = document.createElement("span");
  image.className = "item-icon";
  image.append(icon("key"));
  lead.append(image);
  favicon(image, e.uri);
  const main = document.createElement("button");
  main.type = "button";
  main.className = "item-main";
  main.title = other ? `Not saved for ${site}` : "Fill this login";
  const title = document.createElement("div");
  title.className = "item-title";
  const strong = document.createElement("strong");
  strong.textContent = e.name || "?";
  title.append(strong);
  const small = document.createElement("small");
  small.textContent = (e.user || "no username") + (e.folder ? ` · ${e.folder}` : "");
  main.append(title, small);
  const actions = document.createElement("div");
  actions.className = "item-actions";
  const fillBtn = button("Fill", "fill", (b) => pick(e, ["username", "password", "totp"], b, article, site), "item-fill");
  main.onclick = () => pick(e, ["username", "password", "totp"], fillBtn, article, site);
  const copyBtn = button("Copy", "copy", (b) => copy(e, ["password", "totp", "username"], b), "copy");
  copyBtn.setAttribute("aria-label", `Copy password of ${e.name || "the login"}`);
  const menu = document.createElement("details");
  menu.className = "menu";
  const summary = document.createElement("summary");
  summary.append(icon("more"));
  summary.setAttribute("aria-label", `Actions for ${e.name || "the login"}`);
  const entries = document.createElement("div");
  entries.append(menuEntry("Autofill", "fill", () => pick(e, ["username", "password", "totp"], fillBtn, article, site)));
  if (e.totp) entries.append(menuEntry("Fill one-time code", "generator", () => pick(e, ["totp"], fillBtn, article, site)));
  if (e.user) entries.append(menuEntry("Copy username", "identity", () => copy(e, ["username"], copyBtn)));
  if (e.password !== false) entries.append(menuEntry("Copy password", "key", () => copy(e, ["password"], copyBtn)));
  if (e.totp) entries.append(menuEntry("Copy TOTP", "generator", () => copy(e, ["totp"], copyBtn)));
  entries.addEventListener("click", (ev) => { if (ev.target.closest("button")) menu.open = false; });
  // The frame is as tall as its content, up to what the live view allows: an
  // open menu goes above its button when the frame ends too soon below it and
  // there is room above (as the extension's menus do), and otherwise makes room
  // below itself (the frame grows) rather than open over the search field.
  menu.addEventListener("toggle", () => {
    document.body.style.paddingBottom = "";
    menu.classList.remove("drop-up");
    if (!menu.open) return;
    for (const o of document.querySelectorAll("details.menu[open]")) if (o !== menu) o.open = false;
    const need = entries.offsetHeight + 10, button = summary.getBoundingClientRect();
    if (innerHeight - button.bottom < need && button.top > need) { menu.classList.add("drop-up"); return; }
    // Against the body, not the document: scrollHeight already counts the
    // menu overflowing it, and the frame is sized from the body.
    const below = entries.getBoundingClientRect().bottom + 10 - document.body.getBoundingClientRect().bottom;
    if (below > 0) document.body.style.paddingBottom = `${below}px`;
  });
  menu.append(summary, entries);
  // Like the popup: the fill button only for the site's own logins (another
  // site's shows once a click armed it, see pick).
  fillBtn.hidden = other;
  actions.append(fillBtn, copyBtn, menu);
  article.append(lead, main, actions);
  return article;
}

// A login saved for another site fills only after a second click (it may be a
// phishing page asking for it): the first one says so.
function pick(e, fields, stampOn, article, site) {
  if (e.site !== false) return fill(e, fields, false, stampOn, article);
  if (!article.classList.contains("armed")) {
    for (const a of document.querySelectorAll("article.armed")) {
      a.classList.remove("armed");
      a.querySelector(".item-main small").textContent = a.dataset.sub;
      a.querySelector(".item-fill").hidden = true;
    }
    const small = article.querySelector(".item-main small");
    article.dataset.sub = small.textContent;
    article.classList.add("armed");
    small.textContent = `Not saved for ${site}: click again to fill`;
    stampOn.hidden = false;
    return;
  }
  fill(e, fields, true, stampOn, article);
}

// Like the rbw popup's fill: the button confirms in place (feedback.js), a
// check and then the popover closes, or a red cross and the error. Notes on
// the way (a phone unlock) show at the bottom of the view.
async function fill(entry, fields, anySite, stampOn, article) {
  article.classList.add("busy");
  stampOn.classList.add("is-pending");
  let shownNote = "";
  try {
    const res = await vaultRequest("fill", { entry: entry.id, fields, any_site: anySite },
      { onNote: (note) => { if (note !== shownNote) { shownNote = note; bd.toast(note, 0); } } });
    stampOn.classList.remove("is-pending");
    stampResult(stampOn, { motion: motion() });
    hop();
    // A note is still up: replace it with the outcome.
    if (shownNote) {
      const names = (res?.filled || []).map((f) => (f === "totp" ? "one-time code" : f === "custom" ? "custom fields" : f));
      bd.toast(`Filled ${names.join(" and ") || "the login"}`, 2000);
    }
    setTimeout(() => { if (shown) bd.close("view"); }, motion() ? 650 : 250);
  } catch (err) {
    stampOn.classList.remove("is-pending");
    stampResult(stampOn, { kind: "error", motion: motion() });
    bd.toast(`Not filled: ${err.message}`, 5000);
  } finally {
    article.classList.remove("busy");
  }
}

// Copies the first of `fields` the login has to the clipboard of the device
// viewing. The live view puts it there; this frame only hears which it was.
async function copy(entry, fields, stampOn) {
  stampOn.classList.add("is-pending");
  let shownNote = "";
  try {
    const res = await vaultRequest("copy", { entry: entry.id, fields },
      { onNote: (note) => { if (note !== shownNote) { shownNote = note; bd.toast(note, 0); } } });
    stampOn.classList.remove("is-pending");
    stampResult(stampOn, { motion: motion() });
    const name = { username: "username", password: "password", totp: "one-time code" }[res?.copied] || "it";
    bd.toast(`Copied ${name}`, shownNote ? 2000 : 1500);
  } catch (err) {
    stampOn.classList.remove("is-pending");
    stampResult(stampOn, { kind: "error", motion: motion() });
    bd.toast(`Not copied: ${err.message}`, 5000);
  }
}

// The site's favicon instead of the key, when the live view has one (it asks
// its node; this frame cannot load anything from the web).
const favicons = new Map();
function favicon(target, uri) {
  if (!uri) return;
  let origin;
  try { origin = new URL(uri).origin; } catch { return; }
  if (!/^https?:/.test(origin)) return;
  if (!favicons.has(origin)) favicons.set(origin, bd.request("favicon", { url: origin }).catch(() => null));
  favicons.get(origin).then((src) => {
    if (!src || !target.isConnected) return;
    const image = document.createElement("img");
    image.alt = "";
    image.width = 24;
    image.height = 24;
    image.src = src;
    image.onerror = () => target.replaceChildren(icon("key"));
    target.replaceChildren(image);
  });
}
