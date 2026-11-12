/* ISOLATED world, shared by the content scripts and the injected fill notice.
 *
 * rbw's overlays (the inline chooser, the save-login prompt, the fill notice)
 * must be above everything the page draws. z-index cannot beat the browser's
 * top layer, where a modal <dialog> lives, and a modal dialog also makes the
 * rest of the document inert. So each overlay host
 *  - is a manual popover, which puts it in the top layer (last shown is on
 *    top), and is shown again whenever a dialog or another popover opens;
 *  - is mounted inside the top-most open modal dialog, if there is one, so it
 *    is not inert, and moved back to <html> when that dialog closes.
 * Without the Popover API the hosts keep their maximal z-index. The shadow
 * root of a host is untouched: the page still cannot reach into it. */
(() => {
  if (globalThis.rbwTopLayer) return;
  // The UA stylesheet gives [popover] inset:0, margin:auto, a border, padding,
  // a background and overflow:auto. Put this first in a host's cssText.
  const RESET = "inset:auto!important;margin:0!important;border:0!important;padding:0!important;background:transparent!important;color:inherit!important;overflow:visible!important;height:auto!important;max-height:none!important;max-width:none!important;";
  const hosts = new Set();
  const stamps = new WeakMap();
  let tick = 0, restacking = false;

  const modals = () => {
    try { return [...document.querySelectorAll("dialog:modal")]; } catch (_) { return [...document.querySelectorAll("dialog[open]")]; }
  };
  // The modal dialog opened last is the top one (stamped when its `open`
  // attribute appeared; document order for those seen only now).
  function topModal() {
    const open = modals();
    for (const dialog of document.querySelectorAll("dialog")) if (!open.includes(dialog)) stamps.delete(dialog);
    let best = null, bestStamp = -1;
    for (const dialog of open) {
      if (!stamps.has(dialog)) stamps.set(dialog, ++tick);
      if (stamps.get(dialog) >= bestStamp) { best = dialog; bestStamp = stamps.get(dialog); }
    }
    return best;
  }
  const parentFor = () => topModal() || document.documentElement;

  function show(host) {
    if (typeof host.showPopover !== "function") return;
    try {
      if (host.matches(":popover-open")) host.hidePopover();
      host.showPopover();
    } catch (_) { /* Not connected yet, or already shown. */ }
  }
  // Put one host under the right parent and on top of the top layer.
  function place(host) {
    const parent = parentFor();
    if (!parent) return;
    if (host.parentNode !== parent) parent.append(host);
    show(host);
  }
  // Watches the tree only while an overlay is up (a busy page mutates a lot).
  const tree = new MutationObserver(() => { if (hosts.size) refresh(); });
  const watch = () => { if (hosts.size) tree.observe(document, { childList: true, subtree: true }); else tree.disconnect(); };
  function refresh() {
    for (const host of hosts) {
      // Removed by its owner: forget it. A dialog that was removed from the
      // page takes the host along (parentNode is that dialog): put it back.
      if (!host.isConnected && !(host.parentNode && host.parentNode.localName === "dialog")) { if (!host.parentNode) hosts.delete(host); continue; }
      place(host);
    }
    watch();
  }
  function restack() {
    if (restacking) return;
    restacking = true;
    try { for (const host of hosts) if (host.isConnected) show(host); } finally { restacking = false; }
  }
  function mount(host) {
    for (const other of hosts) if (!other.isConnected && !other.parentNode) hosts.delete(other);
    hosts.add(host);
    if ("showPopover" in HTMLElement.prototype) host.setAttribute("popover", "manual");
    place(host);
    watch();
  }
  function release(host) {
    hosts.delete(host); watch();
    try { if (host.matches(":popover-open")) host.hidePopover(); } catch (_) { /* Not a popover. */ }
  }

  // Dialogs opening or closing, and anything else entering the top layer.
  new MutationObserver(records => {
    for (const record of records) {
      const target = record.target;
      if (target.localName === "dialog" && target.hasAttribute("open") && !stamps.has(target)) stamps.set(target, ++tick);
    }
    if (hosts.size) refresh();
  }).observe(document, { attributes: true, attributeFilter: ["open"], subtree: true });
  // A dialog removed together with a host fires no attribute change: `tree`.
  document.addEventListener("toggle", event => {
    if (event.newState === "open" && hosts.size && !hosts.has(event.target)) restack();
  }, true);
  // Escape in an rbw overlay must not close the page's dialog.
  document.addEventListener("cancel", event => {
    const focused = document.activeElement;
    if (focused && hosts.has(focused)) event.preventDefault();
  }, true);

  globalThis.rbwTopLayer = { mount, release, refresh, parentFor, RESET };
})();
