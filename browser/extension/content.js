/* ISOLATED world: the background obtains the site from MessageSender.url. */
// Inline UI renders in extension frames, so pages can neither read nor restyle
// it. Hosts pin their own styles; each action click is verified by
// rbwVerifyFrame while the background makes every page element hit-testable.
const rbwHardenCss = "display:block!important;opacity:1!important;filter:none!important;transform:none!important;translate:none!important;scale:none!important;rotate:none!important;clip-path:none!important;clip:auto!important;mask:none!important;mix-blend-mode:normal!important;overflow:visible!important;";
const rbwExtensionOrigin = (globalThis.browser || chrome).runtime.getURL("").replace(/\/$/, "");
function rbwVerifyFrame(state, x, y) {
  try {
    const { host, frame, shownAt } = state;
    if (!host?.isConnected || shownAt == null || performance.now() - shownAt < 500 || document.visibilityState !== "visible" || !document.hasFocus()) return false;
    if (host.checkVisibility && !host.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })) return false;
    let opacity = 1;
    for (let node = host; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      opacity *= Number(style.opacity);
      if (style.display === "none" || style.visibility !== "visible" || style.filter !== "none" || style.transform !== "none" || (style.clipPath || "none") !== "none" || (style.maskImage || style.webkitMaskImage || "none") !== "none" || style.mixBlendMode !== "normal") return false;
    }
    if (!(opacity >= 0.95)) return false;
    // Layout size equals rendered size unless something scales or zooms the frame.
    const rect = frame.getBoundingClientRect();
    if (Math.abs(rect.width - frame.offsetWidth) > 1 || Math.abs(rect.height - frame.offsetHeight) > 1 || rect.height < 16 || rect.left < -1 || rect.top < -1 || rect.right > innerWidth + 1 || rect.bottom > innerHeight + 1) return false;
    if (!(x >= 0 && y >= 0 && x <= rect.width && y <= rect.height)) return false;
    return document.elementsFromPoint(rect.left + x, rect.top + y)[0] === host;
  } catch (_) { return false; }
}
// The token reaches only this frame; the page cannot read messages addressed
// to the extension origin. Retry until shown in case a page posted a forged one first.
function rbwConnectFrame(state, onTimeout) {
  const handoff = () => { try { state.frame.contentWindow?.postMessage({ channel: "rbw-inline", token: state.token }, rbwExtensionOrigin); } catch (_) { /* Not loaded yet. */ } };
  state.frame.addEventListener("load", handoff);
  state.retry = setInterval(handoff, 250);
  state.readyTimer = setTimeout(() => { if (state.shownAt == null) onTimeout(); }, 4000);
}
function rbwReleaseFrame(state) { clearInterval(state.retry); clearTimeout(state.readyTimer); state.host.remove(); }
// Handles frame plumbing messages; returns true when handled.
function rbwFrameMessage(state, message, respond, { onSize, onClose, onRefocus }) {
  if (message.action === "rbw_inline_size") {
    state.frame.style.setProperty("height", `${Math.max(0, Math.min(Number(message.height) || 0, 600))}px`, "important");
    if (state.shownAt == null) { clearInterval(state.retry); clearTimeout(state.readyTimer); state.host.style.setProperty("visibility", "visible", "important"); state.shownAt = performance.now(); }
    onSize?.();
  } else if (message.action === "rbw_inline_close") onClose();
  else if (message.action === "rbw_inline_verify") respond({ ok: rbwVerifyFrame(state, message.x, message.y) });
  else if (message.action === "rbw_inline_refocus") { onRefocus?.(); respond({ result: true }); }
  else return false;
  return true;
}
(() => {
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const api = globalThis.browser || chrome;
  const requests = new Set();
  window.addEventListener("message", event => {
    const data = event.data;
    if (event.source !== window || event.origin !== location.origin || data?.channel !== "rbw-passkey" || typeof data.id !== "string" || data.id.length > 64) return;
    if (data.action === "cancel") {
      if (requests.delete(data.id)) api.runtime.sendMessage({ action: "passkey_cancel", request: data.id }).catch(() => {});
      return;
    }
    if (!["get", "create", "availability"].includes(data.action) || requests.has(data.id) || requests.size > 2) return;
    if (JSON.stringify(data).length > 65536) return;
    requests.add(data.id);
    api.runtime.sendMessage(data.action === "availability" ? { action: "passkey_available" } : { action: "passkey_request", request: data.id, method: data.action, options: data.options, conditional: !!data.conditional }).then(response => {
      if (!requests.delete(data.id)) return;
      window.postMessage({ channel: "rbw-passkey-response", id: data.id, ...response }, location.origin);
    }).catch(() => {
      if (requests.delete(data.id)) window.postMessage({ channel: "rbw-passkey-response", id: data.id, fallback: true }, location.origin);
    });
  });
  // Capture only user submitted forms. Nothing is written without approval.
  document.addEventListener("submit", event => {
    if (!event.isTrusted || !(event.target instanceof HTMLFormElement)) return;
    const form = event.target;
    const fields = [...form.querySelectorAll('input[type="password"]')].filter(el => el.value && !el.disabled);
    if (!fields.length || fields.length > 3 || !isSecureContext) return;
    const password = fields.find(el => el.autocomplete === "new-password")?.value || fields[0].value;
    const username = form.querySelector('input[autocomplete="username"],input[type="email"],input[type="text"]')?.value || "";
    if (password.length > 4096 || username.length > 1024) return;
    api.runtime.sendMessage({ action: "save_offer", username, password }).catch(() => {});
  }, true);
})();

// The inline chooser: a draggable header in a closed shadow root around an
// extension frame holding the choices. The page never receives vault data.
(() => {
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const api = globalThis.browser || chrome;
  const autofillGate = globalThis.__rbwAutofillGate || (globalThis.__rbwAutofillGate = { waiting: document.readyState === "loading", pending: false, completed: false });
  let ui = null, generation = 0, filled = false, dismissed = false, refocusing = false, movedPosition = null, contextMenuTarget = null, lastInteraction = { el: null, at: -Infinity };
  const fills = new Set();
  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== api.runtime.id) return;
    if (message?.action === "open_inline_suggestions") {
      let input = contextMenuTarget || document.activeElement;
      contextMenuTarget = null;
      while (input?.shadowRoot?.activeElement) input = input.shadowRoot.activeElement;
      showInlineSuggestions(input, true);
      return;
    }
    if (message?.action === "rbw_fill_state") {
      if (message.active) fills.add(message.token);
      else { fills.delete(message.token); if (message.filled) { filled = true; if (ui?.kind === "card") startCardCloseCountdown(); } }
      return;
    }
    if (!ui || message?.token !== ui.token) return;
    rbwFrameMessage(ui, message, respond, {
      onSize: place, onClose: close,
      onRefocus: () => { refocusing = true; try { ui.input.focus({ preventScroll: true }); } catch (_) { /* Removed input. */ } refocusing = false; },
    });
  });
  // Only deliberate interaction re-enables suggestions after filling; focus() is trusted too.
  const noteInteraction = event => { if (event.isTrusted) lastInteraction = { el: event.type === "keydown" && event.key === "Tab" ? null : event.composedPath()[0], at: performance.now() }; };
  document.addEventListener("pointerdown", noteInteraction, true); document.addEventListener("keydown", noteInteraction, true);
  document.addEventListener("pointerdown", event => { if (event.isTrusted && !fills.size) filled = false; }, true);
  document.addEventListener("keydown", event => { if (event.isTrusted && !fills.size && event.key !== "Escape") filled = false; }, true);
  function close() { if (ui) { clearTimeout(ui.closeTimer); rbwReleaseFrame(ui); } ui = null; ++generation; }
  function dismissSuggestions() { dismissed = true; close(); }
  function stopCardCloseCountdown() {
    if (!ui) return;
    clearTimeout(ui.closeTimer); ui.closeTimer = null; ui.closeStopped = true;
    ui.progress.hidden = true; ui.keepOpen.hidden = true;
  }
  function startCardCloseCountdown() {
    const current = ui;
    if (!current || current.closeStopped) return;
    clearTimeout(current.closeTimer);
    current.progress.hidden = false; current.keepOpen.hidden = false;
    const bar = current.progressFill;
    bar.style.transition = "none"; bar.style.transform = "scaleX(1)"; void bar.getBoundingClientRect();
    bar.style.transition = "transform 5s linear";
    requestAnimationFrame(() => { if (ui === current) bar.style.transform = "scaleX(0)"; });
    current.closeTimer = setTimeout(() => { if (ui === current) close(); }, 5000);
  }
  function place() {
    if (!ui) return null;
    const size = ui.box.getBoundingClientRect(), rect = ui.input.getBoundingClientRect();
    const anchor = movedPosition || { x: rect.left, y: rect.bottom + 4 };
    const point = { x: Math.max(8, Math.min(anchor.x, innerWidth - size.width - 8)), y: Math.max(8, Math.min(anchor.y, innerHeight - size.height - 8)) };
    ui.host.style.setProperty("left", `${point.x}px`, "important"); ui.host.style.setProperty("top", `${point.y}px`, "important");
    return point;
  }
  const moveTo = (x, y) => { movedPosition = { x, y }; movedPosition = place(); };
  document.addEventListener("contextmenu", event => {
    if (!event.isTrusted) return;
    const target = event.composedPath()[0];
    if (target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement || (target instanceof HTMLElement && target.isContentEditable)) contextMenuTarget = target;
  }, true);
  async function showInlineSuggestions(input, explicit = false) {
    if (refocusing || (ui && (input === ui.host || ui.host.contains(input)))) return;
    if ((!explicit && (dismissed || filled || autofillGate.waiting || autofillGate.pending || autofillGate.completed)) || fills.size) { close(); return; }
    const autocomplete = (input?.getAttribute?.("autocomplete") || "").toLowerCase().split(/\s+/);
    const cardField = ["cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type"].some(value => autocomplete.includes(value));
    const loginField = input instanceof HTMLInputElement && ["password", "email", "text"].includes(input.type) && (input.type !== "text" || autocomplete.includes("username"));
    const editableTarget = input instanceof HTMLInputElement || input instanceof HTMLSelectElement || (explicit && (input instanceof HTMLTextAreaElement || (input instanceof HTMLElement && input.isContentEditable)));
    if (!editableTarget || !isSecureContext || (!cardField && !loginField && !explicit)) { close(); return; }
    const defaultOption = input instanceof HTMLSelectElement ? [...input.options].find(option => option.defaultSelected) || input.options[0] : null;
    const alreadyFilled = input instanceof HTMLSelectElement ? input.value !== (defaultOption?.value || "") : String(input.value || "").trim() !== "";
    if (alreadyFilled && !explicit) { close(); return; }
    // Cards are not tied to a site: a script focusing a card field must not open them.
    if (cardField && !explicit && (performance.now() - lastInteraction.at > 1000 || (lastInteraction.el && lastInteraction.el !== input))) { close(); return; }
    const kind = cardField ? "card" : "login";
    close(); const current = generation;
    const response = await api.runtime.sendMessage({ action: "inline_open", kind }).catch(() => null);
    let focused = document.activeElement; while (focused?.shadowRoot?.activeElement) focused = focused.shadowRoot.activeElement;
    if (current !== generation || typeof response?.result !== "string" || focused !== input) return;
    open(input, kind, response.result, response.appIcon);
  }
  function open(input, kind, token, appIcon) {
    const host = document.createElement("div");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = ":host{all:initial}.box{box-sizing:border-box;font:13px/1.4 system-ui,sans-serif;color:#efefef;background:#282828;border:1px solid #555555;border-radius:10px;box-shadow:0 6px 20px #0006;overflow:hidden;max-width:380px}.header{position:relative;display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:#202020;border-bottom:1px solid #494949}.drag-handle{display:flex;align-items:center;gap:7px;flex:1;min-width:0;border:0;padding:0;background:transparent;text-align:left;cursor:grab;touch-action:none;user-select:none}.drag-handle:active{cursor:grabbing}.drag-handle:focus-visible{outline:1px solid #d0d0d0;outline-offset:3px;border-radius:3px}.grip{width:12px;height:16px;fill:#adadad;flex-shrink:0}.title{display:flex;align-items:center;gap:6px;color:#adadad;font-size:11px;font-weight:600;letter-spacing:0.3px;text-transform:uppercase}.app-icon{width:18px;height:18px;object-fit:contain;flex-shrink:0}.autoclose-progress{position:absolute;left:0;right:0;bottom:0;height:3px;overflow:hidden;background:#3b3b3b;pointer-events:none}.autoclose-progress-fill{display:block;width:100%;height:100%;background:#8ab4f8;transform:scaleX(1);transform-origin:left center}.timer-stop-btn{border:0;border-radius:4px;padding:3px 6px;background:transparent;color:#adadad;font:11px system-ui,sans-serif;cursor:pointer}.timer-stop-btn:hover,.timer-stop-btn:focus-visible{background:#383838;color:#efefef;outline:1px solid #777}.timer-stop-btn[hidden],.autoclose-progress[hidden]{display:none}.dismiss-btn{display:flex;align-items:center;justify-content:center;border:0;background:transparent;color:#adadad;padding:2px 4px;border-radius:4px;cursor:pointer;line-height:1}.dismiss-btn:hover,.dismiss-btn:focus-visible{color:#efefef;background:#383838}.dismiss-btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}iframe{display:block;width:100%;height:0;border:0;background:#282828;color-scheme:dark}";
    const box = document.createElement("div"); box.className = "box";
    const header = document.createElement("div"); header.className = "header";
    const title = document.createElement("span"); title.className = "title";
    if (appIcon) { const image = document.createElement("img"); image.className = "app-icon"; image.alt = ""; image.src = appIcon; title.append(image); }
    const titleText = document.createElement("span"); titleText.textContent = kind === "card" ? "rbw · Payment cards" : "rbw · Autofill"; title.append(titleText);
    const progress = document.createElement("div"); progress.className = "autoclose-progress"; progress.hidden = true; progress.setAttribute("role", "progressbar"); progress.setAttribute("aria-label", "Card autofill window closes in five seconds");
    const progressFill = document.createElement("span"); progressFill.className = "autoclose-progress-fill"; progress.append(progressFill);
    const keepOpen = document.createElement("button"); keepOpen.className = "timer-stop-btn"; keepOpen.type = "button"; keepOpen.textContent = "Keep open"; keepOpen.title = "Stop the auto-close timer"; keepOpen.setAttribute("aria-label", "Keep this window open"); keepOpen.hidden = true;
    keepOpen.addEventListener("click", event => { if (event.isTrusted) stopCardCloseCountdown(); });
    const dismiss = document.createElement("button"); dismiss.className = "dismiss-btn"; dismiss.type = "button"; dismiss.title = "Dismiss"; dismiss.setAttribute("aria-label", "Dismiss");
    const closeIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"); closeIcon.setAttribute("viewBox", "0 0 24 24"); closeIcon.setAttribute("aria-hidden", "true");
    const closePath = document.createElementNS(closeIcon.namespaceURI, "path"); closePath.setAttribute("d", "M18 6 6 18M6 6l12 12"); closeIcon.append(closePath); dismiss.append(closeIcon);
    dismiss.addEventListener("click", event => { if (event.isTrusted) dismissSuggestions(); });
    const handle = document.createElement("button"); handle.type = "button"; handle.className = "drag-handle";
    handle.setAttribute("aria-label", "Move autofill suggestions"); handle.title = "Drag to move · Arrow keys to adjust · Home to reset";
    const grip = document.createElementNS(closeIcon.namespaceURI, "svg"); grip.setAttribute("viewBox", "0 0 12 16"); grip.setAttribute("class", "grip"); grip.setAttribute("aria-hidden", "true");
    for (const x of [3, 9]) for (const y of [3, 8, 13]) { const dot = document.createElementNS(closeIcon.namespaceURI, "circle"); dot.setAttribute("cx", x); dot.setAttribute("cy", y); dot.setAttribute("r", "1"); grip.append(dot); }
    handle.append(grip, title); header.append(handle, keepOpen, dismiss, progress);
    const frame = document.createElement("iframe"); frame.title = "rbw suggestions"; frame.src = api.runtime.getURL("inline.html");
    box.append(header, frame); shadow.append(style, box);
    const rect = input.getBoundingClientRect();
    host.style.cssText = `position:fixed!important;z-index:2147483647!important;top:0!important;left:0!important;width:${Math.max(0, Math.min(380, Math.max(rect.width, 240), innerWidth - 16))}px!important;visibility:hidden!important;pointer-events:auto!important;${rbwHardenCss}`;
    document.documentElement.append(host);
    ui = { token, host, box, frame, input, kind, shownAt: null, progress, progressFill, keepOpen, closeTimer: null, closeStopped: false };
    const current = ui;
    rbwConnectFrame(ui, () => { if (ui === current) close(); });
    place();
    let drag;
    handle.addEventListener("pointerdown", event => {
      if (!event.isTrusted || event.button !== 0) return;
      event.preventDefault(); const bounds = box.getBoundingClientRect();
      drag = { id: event.pointerId, x: event.clientX, y: event.clientY, left: bounds.left, top: bounds.top };
      handle.setPointerCapture(event.pointerId);
    });
    handle.addEventListener("pointermove", event => {
      if (!event.isTrusted || !drag || drag.id !== event.pointerId || ui !== current) return;
      moveTo(drag.left + event.clientX - drag.x, drag.top + event.clientY - drag.y);
    });
    const endDrag = () => { drag = null; };
    handle.addEventListener("pointerup", endDrag); handle.addEventListener("pointercancel", endDrag); handle.addEventListener("lostpointercapture", endDrag);
    handle.addEventListener("keydown", event => {
      if (!event.isTrusted || ui !== current) return;
      if (event.key === "Home") { event.preventDefault(); movedPosition = null; place(); return; }
      const delta = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[event.key];
      if (!delta) return;
      event.preventDefault(); const bounds = box.getBoundingClientRect(); const step = event.shiftKey ? 40 : 10;
      moveTo(bounds.left + delta[0] * step, bounds.top + delta[1] * step);
    });
  }
  document.addEventListener("focusin", event => showInlineSuggestions(event.composedPath()[0]));
  document.addEventListener("keydown", event => { if (event.key === "Escape") close(); });
  window.addEventListener("scroll", close, true); window.addEventListener("resize", close);
})();

// Save offers stay in the extension background; the prompt is an extension
// frame that sends back only a selected item ID.
(() => {
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const api = globalThis.browser || chrome;
  let prompt = null;
  const close = () => { if (prompt) rbwReleaseFrame(prompt); prompt = null; };
  function show(token, origin) {
    close();
    if (origin !== location.origin || typeof token !== "string") return;
    const host = document.createElement("div");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = ":host{all:initial}iframe{display:block;width:380px;max-width:calc(100vw - 32px);height:0;border:0;border-radius:10px;box-shadow:0 6px 20px #0006;background:#282828;color-scheme:dark}";
    const frame = document.createElement("iframe"); frame.title = "Save login in rbw"; frame.src = api.runtime.getURL("inline.html");
    shadow.append(style, frame);
    host.style.cssText = `all:initial!important;position:fixed!important;inset:16px 16px auto auto!important;z-index:2147483647!important;max-width:calc(100vw - 32px)!important;visibility:hidden!important;pointer-events:auto!important;${rbwHardenCss}`;
    document.documentElement.append(host);
    prompt = { token, host, frame, shownAt: null };
    const current = prompt;
    rbwConnectFrame(prompt, () => { if (prompt === current) close(); });
  }
  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== api.runtime.id) return;
    if (message?.action === "rbw_save_offer") { show(message.token, message.origin); return; }
    if (message?.action === "rbw_save_offer_clear") { close(); return; }
    if (prompt && message?.token === prompt.token) rbwFrameMessage(prompt, message, respond, { onClose: close });
  });
})();

if (window === window.top) {
  const autofillGate = globalThis.__rbwAutofillGate || (globalThis.__rbwAutofillGate = { waiting: false, pending: false, completed: false });
  document.addEventListener("keydown", event => {
    const modifier = /Mac|iPhone|iPad/.test(navigator.platform) ? event.metaKey : event.ctrlKey;
    if (!event.isTrusted || event.repeat || !modifier || !event.shiftKey || event.altKey || event.key.toLowerCase() !== "l") return;
    event.preventDefault();
    (globalThis.browser || chrome).runtime.sendMessage({ action: "keyboard_fill_shortcut" }).catch(() => {});
  }, true);
  const loaded = () => {
    autofillGate.waiting = false;
    let observer, timer, expiry;
    const eligible = () => document.querySelector('input[type="password"]:not([autocomplete="new-password"]),input[autocomplete="username"]');
    const check = () => {
      if (!eligible()) return false;
      observer?.disconnect(); clearTimeout(timer); clearTimeout(expiry);
      autofillGate.pending = true;
      (globalThis.browser || chrome).runtime.sendMessage({ action: "autofill_load" }).then(response => {
        autofillGate.pending = false;
        autofillGate.completed = Number(response?.result) > 0;
      }).catch(() => { autofillGate.pending = false; });
      return true;
    };
    if (check()) return;
    // Briefly cover asynchronously rendered sign-in forms without keeping a
    // permanent observer or querying the vault on ordinary content/search pages.
    observer = new MutationObserver(() => {
      if (eligible()) { check(); return; }
      clearTimeout(timer); timer = setTimeout(check, 250);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    expiry = setTimeout(() => { observer.disconnect(); clearTimeout(timer); }, 10000);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loaded, { once: true }); else loaded();
}
