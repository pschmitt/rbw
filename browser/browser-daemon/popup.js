"use strict";
// The toolbar popover: the logins for the live view's page, in the rbw
// popup's look (its popup.css and markup). The secret agent holds the vault
// and the node fills the page, so this frame sees names, users and folders;
// a password or code only goes to the clipboard of the device viewing, when
// you copy it, and never through this frame. Which page and site that is the
// live view decides.
const vault = { site: "", list: null, at: 0, peeking: null, peekSite: "", off: 0 };
const FRESH = 120000;
let ctx = { site: "", ready: false };
let shown = false, seq = 0, abort = null, timer = 0, rows = [], query = "";

function badge() {
  const n = vault.site === ctx.site && Array.isArray(vault.list) ? vault.list.filter((e) => e.site !== false).length : 0;
  bd.badge(n ? (n > 9 ? "9+" : String(n)) : null);
}
// After a page load: how many logins the vault has for the site (the button's badge).
// Never asks for an unlock; a node without a secret agent is left alone a while.
function peek() {
  const site = ctx.site;
  badge();
  if (!site || !ctx.ready || vault.peeking || Date.now() < vault.off) return;
  if (vault.site === site && Date.now() - vault.at < FRESH) return;
  vault.peekSite = site;
  vault.peeking = bd.request("logins").then((found) => {
    vault.site = site;
    vault.at = Date.now();
    vault.list = Array.isArray(found) ? found : null; // locked: not known
  }, (err) => {
    if (/secret agent/i.test(err.message)) vault.off = Date.now() + 300000;
  }).finally(() => { vault.peeking = null; badge(); });
}
bd.on("context", (m) => { ctx = { site: m.site || "", ready: !!m.ready }; peek(); });

bd.on("open", (m) => {
  shown = true;
  warning($("public"), m.warning);
  $("query").value = query = "";
  $("folder").value = "";
  // Desktop: type right away. Phones: the keyboard would cover the list.
  if (matchMedia("(hover: hover) and (pointer: fine)").matches) $("query").focus();
  load(ctx.site);
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
async function load(site, unlock = false, q = "") {
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
    found = await bd.request("logins", { unlock, query: q || null },
      { onNote: (note) => body(empty(esc(note), "locked checking")), signal: ac.signal });
  } catch (err) {
    if (err.aborted) return;
    return body(empty(esc(err.message), "bad"));
  }
  if (!shown || mine !== seq || ctx.site !== site) return;
  if (found?.locked) {
    body(empty("Your vault is locked.", "locked") + `<div class="actions"><button class="primary" id="unlock">${ico("unlock")}<span>Unlock from your phone</span></button></div>`);
    $("unlock").onclick = () => load(site, true, q);
    return;
  }
  found = Array.isArray(found) ? found : [];
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
  // The frame is as tall as its content: an open menu makes room below
  // itself (the frame grows) rather than open over the search field.
  menu.addEventListener("toggle", () => {
    document.body.style.paddingBottom = "";
    if (!menu.open) return;
    for (const o of document.querySelectorAll("details.menu[open]")) if (o !== menu) o.open = false;
    const below = entries.getBoundingClientRect().bottom + scrollY + 10 - document.documentElement.scrollHeight;
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
    const res = await bd.request("fill", { entry: entry.id, fields, any_site: anySite },
      { onNote: (note) => { if (note !== shownNote) { shownNote = note; bd.toast(note, 0); } } });
    stampOn.classList.remove("is-pending");
    stampResult(stampOn, { motion: motion() });
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
    const res = await bd.request("copy", { entry: entry.id, fields },
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
