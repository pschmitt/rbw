"use strict";
// This frame's side of browser-daemon's live-view extension contract (its
// docs/extensions.md): messages to and from the live view that embeds it. The
// frame is sandboxed: it can reach nothing but the view, and the view answers
// only what it allows.
const bd = (() => {
  const handlers = {};
  const pending = new Map();
  let seq = 0;
  const post = (type, data = {}) => parent.postMessage({ bd: "ext", type, ...data }, "*");
  const failure = (message, aborted = false) => Object.assign(new Error(message), { aborted });
  // The view's theme ("light", "dark", or null: follow the system), in rbw's terms.
  const system = matchMedia("(prefers-color-scheme: light)");
  let theme = null;
  const applyTheme = () => { document.documentElement.dataset.theme = theme || (system.matches ? "light" : "dark"); };
  system.addEventListener("change", applyTheme);
  applyTheme();
  addEventListener("message", (e) => {
    const m = e.data;
    if (e.source !== parent || !m || m.bd !== "ext") return;
    if (m.type === "reply") {
      const p = pending.get(m.id);
      if (!p) return;
      pending.delete(m.id);
      if ("error" in m) p.reject(failure(m.error, !!m.aborted)); else p.resolve(m.result);
      return;
    }
    if (m.type === "note") { pending.get(m.id)?.onNote?.(m.note); return; }
    if (m.type === "init") {
      theme = m.theme || null;
      applyTheme();
      // The bundle's version (rbw's), where the popup shows its own.
      for (const el of document.querySelectorAll("[data-extension-version]")) el.textContent = m.version ? `v${m.version}` : "rbw";
    }
    handlers[m.type]?.(m);
  });
  // The view sizes the frame to the content (up to its limit; beyond, this scrolls).
  addEventListener("DOMContentLoaded", () => {
    // Icons as in the popup: <span data-icon="name">.
    for (const el of document.querySelectorAll("[data-icon]")) el.replaceChildren(icon(el.dataset.icon));
    new ResizeObserver(() => post("size", { height: Math.ceil(document.body.getBoundingClientRect().height) })).observe(document.body);
    post("ready");
  });
  return {
    on(type, fn) { handlers[type] = fn; },
    // A request for the view (see the contract): resolves with its answer,
    // onNote gets progress ("confirm the unlock on your phone").
    request(kind, args = {}, { onNote, signal } = {}) {
      const id = String(++seq);
      return new Promise((resolve, reject) => {
        if (signal?.aborted) return reject(failure("cancelled", true));
        pending.set(id, { resolve, reject, onNote });
        signal?.addEventListener("abort", () => {
          if (!pending.delete(id)) return;
          post("cancel", { id });
          reject(failure("cancelled", true));
        }, { once: true });
        post("request", { id, kind, ...args });
      });
    },
    badge: (text) => post("badge", { text: text || null }),
    close: (focus = "button") => post("close", { focus }),
    toast: (text, ms) => post("toast", { text, ms }),
    // use: sign in with the vault (entry: the account picked, or null to let
    // rbw pick or unlock first); device: let the browser ask its own way.
    answerPasskey: (id, use, entry = null, device = false) => post("passkey.answer", { id, use, entry, device }),
  };
})();

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
// rbw's icons (icons.js, the extension's), as markup.
const ico = (name) => icon(name).outerHTML;
// The view's note that the session is shared publicly ({text, watch}, or null).
function warning(el, w) {
  el.hidden = !w;
  if (!w) return;
  el.textContent = w.text;
  el.classList.toggle("watch", !!w.watch);
}
// Respect reduced motion, as the popup's animations setting does.
const motion = () => !matchMedia("(prefers-reduced-motion: reduce)").matches;
