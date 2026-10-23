"use strict";
// The toolbar popover: fills logins as the Bitwarden extension does. It lists
// the vault's entries for the page's site and fills the picked one into the
// page's login form. The secret agent holds the vault and the node fills the
// page, so this frame only ever sees entry names and users, never a password
// or code. Which page and site that is the live view decides, not this frame.
const vault = { site: "", list: null, at: 0, peeking: null, peekSite: "", off: 0 };
const FRESH = 120000;
let ctx = { site: "", ready: false };
let shown = false, seq = 0, abort = null, timer = 0;

$("searchWrap").insertAdjacentHTML("afterbegin", ico("search"));

function badge() {
  const n = vault.site === ctx.site && Array.isArray(vault.list) ? vault.list.length : 0;
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
  const site = ctx.site;
  $("head").innerHTML = header("Vault", site || "rbw", "Close vault");
  $("head").querySelector(".rbw-close").onclick = () => bd.close("button");
  warning($("public"), m.warning);
  const search = $("search");
  search.value = "";
  // Desktop: type right away. Phones: the keyboard would cover the list.
  if (matchMedia("(hover: hover) and (pointer: fine)").matches) search.focus();
  load(site);
});
bd.on("closed", () => {
  shown = false;
  seq++;
  abort?.abort();                            // no more polling for a popover nobody sees
  clearTimeout(timer);
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); bd.close("button"); } });

$("search").oninput = () => {
  clearTimeout(timer);
  const q = $("search").value.trim(), site = ctx.site;
  // Right away: the site's logins that match; the vault's answer follows.
  if (q && Array.isArray(vault.list) && vault.site === site) render(filter(vault.list, q), site, q, true);
  timer = setTimeout(() => load(site, false, q), q ? 350 : 0);
};
$("search").onkeydown = (e) => {
  if (e.key === "Enter") { e.preventDefault(); $("list").querySelector(".vp-entry")?.click(); }
  if (e.key === "ArrowDown") { e.preventDefault(); $("list").querySelector(".vp-entry")?.focus(); }
};

const filter = (list, q) => list.filter((e) => `${e.name || ""} ${e.user || ""} ${e.folder || ""}`.toLowerCase().includes(q.toLowerCase()));
async function load(site, unlock = false, query = "") {
  const mine = ++seq;
  abort?.abort();                            // the previous question is not wanted any more
  const ac = abort = new AbortController();
  const body = (html) => { if (shown && mine === seq) $("list").innerHTML = html; };
  if (!site) return body('<div class="sp-empty">This page is not on a website: there is nothing to fill.</div>');
  if (!ctx.ready) return body('<div class="sp-empty">Not connected to a session yet.</div>');
  // The badge's lookup for this page is underway: wait for it rather than ask twice.
  if (!unlock && !query && vault.peeking && vault.peekSite === site) {
    body('<div class="sp-empty checking">Looking in the vault…</div>');
    await vault.peeking;
  }
  if (!shown || mine !== seq) return;
  const fresh = !unlock && !query && vault.site === site && Array.isArray(vault.list) && Date.now() - vault.at < FRESH;
  if (fresh) return render(vault.list, site, "");
  if (!query || !$("list").querySelector(".vp-entry")) {
    body(`<div class="sp-empty checking">${unlock ? "Unlocking the vault…" : query ? "Searching the vault…" : "Looking in the vault…"}</div>`);
  }
  let found;
  try {
    found = await bd.request("logins", { unlock, query: query || null },
      { onNote: (note) => body(`<div class="sp-empty locked checking">${esc(note)}</div>`), signal: ac.signal });
  } catch (err) {
    if (err.aborted) return;
    return body(`<div class="sp-empty bad">${esc(err.message)}</div>`);
  }
  if (!shown || mine !== seq || ctx.site !== site) return;
  if (found?.locked) {
    body('<div class="sp-empty locked">Your vault is locked.</div><button class="vp-act" id="unlock">Unlock from your phone</button>');
    $("unlock").onclick = () => load(site, true, query);
    return;
  }
  found = Array.isArray(found) ? found : [];
  if (!query) {
    vault.site = site;
    vault.at = Date.now();
    vault.list = found;
    badge();
  }
  render(found, site, query);
}
// partial: the site's logins filtered here while the vault search runs.
function render(found, site, query, partial = false) {
  const list = $("list");
  if (!found.length) {
    list.innerHTML = partial ? '<div class="sp-empty checking">Searching the vault…</div>'
      : `<div class="sp-empty">${query ? `Nothing in your vault matches “${esc(query)}”.` : `No logins for ${esc(site)} in your vault: search for one above.`}</div>`;
    return;
  }
  const row = (e, i) => {
    const other = e.site === false;
    return `<div class="vp-row"><button class="vp-entry${other ? " other" : ""}" data-i="${i}" title="${other ? `Not saved for ${esc(site)}` : "Fill this login"}">`
      + `<span class="sp-eng">${ico("key")}</span>`
      + `<span class="sp-t"><b>${esc(e.name || "?")}</b><span>${esc(e.user || "no username")}${e.folder ? " · " + esc(e.folder) : ""}</span></span><span class="vp-tool vp-fill" aria-hidden="true">${ico("fill")}</span></button>`
      + (e.totp ? `<button class="vp-tool vp-totp" data-i="${i}" title="Fill only the one-time code" aria-label="Fill one-time code">${ico("generator")}</button>` : "") + "</div>";
  };
  const firstOther = found.findIndex((e) => e.site === false);
  const matches = firstOther < 0 ? found.length : firstOther;
  list.innerHTML = (matches ? `<h3 class="vp-sep">${query ? "Matching this site" : "Suggested for this site"} · ${matches}</h3>` : "")
    + found.map((e, i) => (i === firstOther ? `<h3 class="vp-sep">${firstOther ? "Other logins" : `Not saved for ${esc(site)}`} · ${found.length - firstOther}</h3>` : "") + row(e, i)).join("")
    + '<div class="vp-note">Select a login to fill this page</div>';
  // A login saved for another site fills only after a second click (it may be a
  // phishing page asking for it): the first one says so.
  const pick = (b, fields) => {
    const e = found[+b.dataset.i];
    if (e.site !== false) return fill(e, fields);
    const entryBtn = b.closest(".vp-row").querySelector(".vp-entry");
    if (!entryBtn.classList.contains("armed")) {
      list.querySelectorAll(".vp-entry.armed").forEach((x) => { x.classList.remove("armed"); x.querySelector(".sp-t span").textContent = x.dataset.sub; });
      entryBtn.classList.add("armed");
      const sub = entryBtn.querySelector(".sp-t span");
      entryBtn.dataset.sub = sub.textContent;
      sub.textContent = `Not saved for ${site}: click again to fill`;
      return;
    }
    fill(e, fields, true);
  };
  list.querySelectorAll(".vp-entry").forEach((b) => { b.onclick = () => pick(b, ["username", "password", "totp"]); });
  list.querySelectorAll(".vp-totp").forEach((b) => { b.onclick = () => pick(b, ["totp"]); });
}
async function fill(entry, fields, anySite = false) {
  bd.close("view");
  bd.toast(`Filling ${entry.name || "the login"}…`, 0);
  let shownNote = "";
  try {
    const res = await bd.request("fill", { entry: entry.id, fields, any_site: anySite },
      { onNote: (note) => { if (note !== shownNote) { shownNote = note; bd.toast(note, 0); } } });
    const names = (res?.filled || []).map((f) => (f === "totp" ? "one-time code" : f === "custom" ? "custom fields" : f));
    bd.toast(`Filled ${names.join(" and ") || "the login"}`, 2000);
  } catch (err) {
    bd.toast(`Not filled: ${err.message}`, 5000);
  }
}
