/* ISOLATED world: the background obtains the site from MessageSender.url. */
// Inline UI renders in extension frames, so pages can neither read nor restyle
// it. Hosts pin their own styles; each action click is verified by
// rbwVerifyFrame while the background makes every page element hit-testable.
const rbwHardenCss = "display:block!important;opacity:1!important;filter:none!important;transform:none!important;translate:none!important;scale:none!important;rotate:none!important;clip-path:none!important;clip:auto!important;mask:none!important;mix-blend-mode:normal!important;overflow:visible!important;";
// Overlay hosts go through top-layer.js (manifest order: before this file).
const rbwMount = host => { if (globalThis.rbwTopLayer) globalThis.rbwTopLayer.mount(host); else document.documentElement.append(host); };
const rbwTopReset = () => globalThis.rbwTopLayer?.RESET || "";
const rbwExtensionOrigin = (globalThis.browser || chrome).runtime.getURL("").replace(/\/$/, "");
// Prefer positions that leave interactive controls visible. The overlap cost
// is normalized per control so a wide input matters as much as a small button.
function rbwChooserPosition(anchor, size, viewport, obstacles) {
  const margin = 8, gap = 8;
  const maxX = Math.max(margin, viewport.width - size.width - margin);
  const maxY = Math.max(margin, viewport.height - size.height - margin);
  const clamp = (value, max) => Math.max(margin, Math.min(value, max));
  const xs = [anchor.left, anchor.right - size.width, anchor.right + gap, anchor.left - size.width - gap, margin, maxX];
  const ys = [anchor.bottom + gap, anchor.top - size.height - gap, margin, maxY];
  for (const rect of obstacles) {
    xs.push(rect.left - size.width - gap, rect.right + gap);
    ys.push(rect.top - size.height - gap, rect.bottom + gap);
  }
  const unique = (values, max) => [...new Set(values.map(value => Math.round(clamp(value, max))))];
  let best = null;
  for (const x of unique(xs, maxX)) for (const y of unique(ys, maxY)) {
    let overlap = 0;
    for (const rect of obstacles) {
      const width = Math.max(0, Math.min(x + size.width, rect.right) - Math.max(x, rect.left));
      const height = Math.max(0, Math.min(y + size.height, rect.bottom) - Math.max(y, rect.top));
      if (width && height) overlap += width * height / Math.max(1, (rect.right - rect.left) * (rect.bottom - rect.top)) * (rect.focused ? 8 : 1);
    }
    const distance = Math.hypot(x - anchor.left, y - (anchor.bottom + gap));
    const score = overlap * 100000 + distance;
    if (!best || score < best.score) best = { x, y, score };
  }
  return { x: best.x, y: best.y };
}
function rbwVerifyFrame(state, x, y) {
  try {
    const { host, frame, shownAt } = state;
    if (!host?.isConnected) return "closed";
    if (shownAt == null || performance.now() - shownAt < 500) return "settling";
    if (document.visibilityState !== "visible" || !document.hasFocus()) return "unfocused";
    if (host.checkVisibility && !host.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })) return "hidden";
    let opacity = 1;
    for (let node = host; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      opacity *= Number(style.opacity);
      if (style.display === "none" || style.visibility !== "visible") return "hidden";
      if (style.filter !== "none" || (style.clipPath || "none") !== "none" || (style.maskImage || style.webkitMaskImage || "none") !== "none" || style.mixBlendMode !== "normal") return "altered";
      // A computed identity matrix (e.g. translate(0)) changes no pixels.
      if (style.transform !== "none" && !new DOMMatrixReadOnly(style.transform).isIdentity) return "altered";
    }
    if (!(opacity >= 0.95)) return "translucent";
    // Layout size equals rendered size unless something scales or zooms the frame.
    const rect = frame.getBoundingClientRect();
    if (Math.abs(rect.width - frame.offsetWidth) > 1 || Math.abs(rect.height - frame.offsetHeight) > 1) return "altered";
    if (rect.height < 16 || rect.left < -1 || rect.top < -1 || rect.right > innerWidth + 1 || rect.bottom > innerHeight + 1) return "clipped";
    if (!(x >= 0 && y >= 0 && x <= rect.width && y <= rect.height)) return "coordinates";
    return document.elementsFromPoint(rect.left + x, rect.top + y)[0] === host ? null : "covered";
  } catch (_) { return "unavailable"; }
}
// The token reaches only this frame; the page cannot read messages addressed
// to the extension origin. Retry until shown in case a page posted a forged one first.
function rbwConnectFrame(state, onTimeout) {
  const handoff = () => { try { state.frame.contentWindow?.postMessage({ channel: "rbw-inline", token: state.token }, rbwExtensionOrigin); } catch (_) { /* Not loaded yet. */ } };
  state.frame.addEventListener("load", handoff);
  state.retry = setInterval(handoff, 250);
  state.readyTimer = setTimeout(() => { if (state.shownAt == null) onTimeout(); }, 4000);
}
// The window slides/fades in and out. The animated element is the box (or the
// iframe) inside the shadow root: the host's own styles stay pinned by
// rbwHardenCss, and clicks only count 500 ms after it was shown anyway.
const rbwMotion = () => !matchMedia("(prefers-reduced-motion: reduce)").matches;
function rbwAnimate(state, keyframes, options) {
  try { return (state.box || state.frame)?.animate(keyframes, options) || null; } catch (_) { return null; }
}
function rbwReleaseFrame(state) {
  clearInterval(state.retry); clearTimeout(state.readyTimer);
  const gone = () => { globalThis.rbwTopLayer?.release(state.host); state.host.remove(); };
  // Only what was visible animates out; it can't be clicked meanwhile.
  const out = state.shownAt != null && state.host.isConnected && rbwMotion()
    ? (state.host.style.setProperty("pointer-events", "none", "important"),
      rbwAnimate(state, [{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(-6px) scale(.98)" }], { duration: 140, easing: "ease-in", fill: "forwards" }))
    : null;
  if (!out) { gone(); return; }
  out.onfinish = gone; out.oncancel = gone; setTimeout(gone, 400);
}
// Handles frame plumbing messages; returns true when handled.
function rbwFrameMessage(state, message, respond, { onSize, onClose, onRefocus }) {
  if (message.action === "rbw_inline_size") {
    state.frame.style.setProperty("height", `${Math.max(0, Math.min(Number(message.height) || 0, 600))}px`, "important");
    if (state.shownAt == null) { clearInterval(state.retry); clearTimeout(state.readyTimer); state.host.style.setProperty("visibility", "visible", "important"); state.shownAt = performance.now(); if (rbwMotion()) rbwAnimate(state, [{ opacity: 0, transform: "translateY(-8px) scale(.98)" }, { opacity: 1, transform: "none" }], { duration: 190, easing: "cubic-bezier(.2,.8,.2,1)" }); }
    onSize?.();
  } else if (message.action === "rbw_inline_close") onClose();
  else if (message.action === "rbw_inline_verify") respond({ reason: rbwVerifyFrame(state, message.x, message.y) });
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
  // Capture only user submitted forms. Nothing is written without approval;
  // the background drops pages that are not secure for filling either.
  document.addEventListener("submit", event => {
    if (!event.isTrusted || !(event.target instanceof HTMLFormElement)) return;
    const form = event.target;
    const fields = [...form.querySelectorAll('input[type="password"]')].filter(el => el.value && !el.disabled);
    if (!fields.length || fields.length > 3) return;
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
  let passwordRequest = null;
  const usablePasswordField = input => input instanceof HTMLInputElement && input.type === "password" &&
    input.isConnected && !input.matches(":disabled, [readonly]") && input.getClientRects().length;
  const passwordFields = input => [input, globalThis.rbwFillTargets.confirmationField(input)].filter(Boolean);
  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (sender.id !== api.runtime.id) return;
    if (message?.action === "open_inline_suggestions") {
      let input = contextMenuTarget || document.activeElement;
      contextMenuTarget = null;
      while (input?.shadowRoot?.activeElement) input = input.shadowRoot.activeElement;
      showInlineSuggestions(input, true);
      return;
    }
    if (message?.action === "rbw_password_limits") {
      const input = contextMenuTarget;
      contextMenuTarget = null;
      passwordRequest = null;
      if (location.href !== message.url || !usablePasswordField(input)) { respond(null); return; }
      passwordRequest = { input, id: message.request };
      respond(globalThis.rbwFillTargets.passwordLengthBounds(...passwordFields(input)));
      return;
    }
    if (message?.action === "rbw_generated_password") {
      if (!passwordRequest || passwordRequest.id !== message.request) { respond(false); return; }
      const { input } = passwordRequest;
      passwordRequest = null;
      const password = message.password;
      if (location.href !== message.url || !usablePasswordField(input) || typeof password !== "string") {
        respond(false);
        return;
      }
      const targets = passwordFields(input);
      const { min, max } = globalThis.rbwFillTargets.passwordLengthBounds(...targets);
      if (password.length < min || (max !== null && password.length > max)) { respond(false); return; }
      close();
      const fillPassword = el => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, password);
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
      };
      fillPassword(input);
      if (targets.length > 1 && usablePasswordField(input)) {
        // The first input event can replace the confirmation field in a controlled form.
        const repeat = globalThis.rbwFillTargets.confirmationField(input);
        if (repeat) {
          const { min, max } = globalThis.rbwFillTargets.passwordLengthBounds(repeat);
          if (password.length >= min && (max === null || password.length <= max)) fillPassword(repeat);
        }
      }
      respond(true);
      return;
    }
    if (message?.action === "rbw_fill_state") {
      if (message.active) fills.add(message.token);
      else { fills.delete(message.token); if (message.filled) { filled = true; if (ui) { dockFilled(); startCardCloseCountdown(); } } }
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
    undim();
  }
  // The docked window fades back in once you touch it. The fade is on the box
  // inside the shadow root: the host's own opacity stays pinned at 1.
  function undim() {
    const current = ui;
    if (!current?.dimmed) return;
    current.dimmed = false;
    current.box.style.setProperty("opacity", "1");
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
    let anchor = movedPosition || (ui.docked ? { x: innerWidth - size.width - 16, y: innerHeight - size.height - 16 } : null);
    if (!anchor) {
      const selector = 'input:not([type="hidden"]),select,textarea,button,[role="button"],[contenteditable="true"]';
      const roots = [...new Set([document, ui.input.getRootNode()])];
      const controls = [...new Set(roots.flatMap(root => [...root.querySelectorAll(selector)]))];
      if (!controls.includes(ui.input)) controls.push(ui.input);
      const obstacles = controls.filter(element => element.isConnected && element.getClientRects().length && (typeof element.checkVisibility !== "function" || element.checkVisibility({ visibilityProperty: true, opacityProperty: true })))
        .map(element => ({ rect: element.getBoundingClientRect(), focused: element === ui.input }))
        .filter(({ rect: r }) => r.width > 0 && r.height > 0 && r.right > 0 && r.bottom > 0 && r.left < innerWidth && r.top < innerHeight)
        .sort((a, b) => (b.focused - a.focused) || Math.abs(a.rect.top - rect.top) - Math.abs(b.rect.top - rect.top))
        .slice(0, 40).map(({ rect: r, focused }) => ({ left: r.left, right: r.right, top: r.top, bottom: r.bottom, focused }));
      anchor = rbwChooserPosition(rect, size, { width: innerWidth, height: innerHeight }, obstacles);
    }
    const point = { x: Math.max(8, Math.min(anchor.x, innerWidth - size.width - 8)), y: Math.max(8, Math.min(anchor.y, innerHeight - size.height - 8)) };
    ui.host.style.setProperty("left", `${point.x}px`, "important"); ui.host.style.setProperty("top", `${point.y}px`, "important");
    return point;
  }
  // Once filled, the window slips to the bottom right, out of the form's way,
  // and counts down to closing. The slide is a transition on the pinned host
  // position, removed afterwards so dragging stays immediate.
  function dockFilled() {
    const current = ui;
    if (!current || current.docked) return;
    current.docked = true; movedPosition = null;
    current.dimmed = true;
    current.box.style.setProperty("transition", rbwMotion() ? "opacity .35s ease" : "none");
    current.box.style.setProperty("opacity", ".55");
    if (rbwMotion()) {
      current.host.style.setProperty("transition", "left .45s cubic-bezier(.2,.8,.2,1),top .45s cubic-bezier(.2,.8,.2,1)", "important");
      setTimeout(() => { if (ui === current) current.host.style.removeProperty("transition"); }, 500);
    }
    place();
  }
  const moveTo = (x, y) => { movedPosition = { x, y }; movedPosition = place(); };
  document.addEventListener("contextmenu", event => {
    if (!event.isTrusted) return;
    passwordRequest = null;
    const target = event.composedPath()[0];
    contextMenuTarget = target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement || (target instanceof HTMLElement && target.isContentEditable) ? target : null;
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
    // A set-password step (only new-password fields in the form) can get a
    // freshly generated password for the chosen login.
    const setPassword = kind === "login" && input.type === "password" && autocomplete.includes("new-password") && ![...(input.form || document).querySelectorAll('input[type="password"]')].some(el => !el.autocomplete.split(/\s+/).includes("new-password"));
    const response = await api.runtime.sendMessage({ action: "inline_open", kind, explicit, setPassword }).catch(() => null);
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
    for (const type of ["pointerenter", "pointerdown", "focusin", "keydown"]) box.addEventListener(type, event => { if (event.isTrusted) undim(); });
    const rect = input.getBoundingClientRect();
    host.style.cssText = `${rbwTopReset()}position:fixed!important;z-index:2147483647!important;top:0!important;left:0!important;width:${Math.max(0, Math.min(380, Math.max(rect.width, 240), innerWidth - 16))}px!important;visibility:hidden!important;pointer-events:auto!important;${rbwHardenCss}`;
    rbwMount(host);
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
  // A page restored from the back-forward cache can contain an old, already
  // resolved prompt. The background will issue a fresh one if an offer remains.
  window.addEventListener("pageshow", event => { if (event.persisted) close(); });
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
    rbwMount(host);
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
    let timer;
    let pageUrl = location.href;
    let attempted = new WeakSet();
    const visible = el => el.getClientRects().length && (typeof el.checkVisibility === "function" ? el.checkVisibility({ opacityProperty: true, visibilityProperty: true }) : getComputedStyle(el).visibility !== "hidden");
    const check = () => {
      if (location.href !== pageUrl) {
        pageUrl = location.href;
        attempted = new WeakSet();
        autofillGate.completed = false;
      }
      if (autofillGate.pending || document.visibilityState === "hidden") return;
      const fields = [...document.querySelectorAll('input[type="password"]:not([autocomplete="new-password"]),input[autocomplete="username"]')];
      // Authenticator-code fields too (the background fills them only when
      // "Autofill TOTP codes" is on). The detection of fill-targets.js.
      const otpFields = [...document.querySelectorAll("input")].filter(rbwFillTargets.isOtpField);
      fields.push(...otpFields.filter(el => !fields.includes(el)));
      const field = fields.find(el => !attempted.has(el) && !el.value && !el.disabled && !el.readOnly && visible(el));
      if (!field) return;
      // Mark only visible candidates: a hidden password step may become visible
      // after passkey login without a document navigation.
      for (const el of fields.filter(el => visible(el))) attempted.add(el);
      autofillGate.pending = true;
      (globalThis.browser || chrome).runtime.sendMessage({ action: "autofill_load", otp: otpFields.includes(field) && !fields.some(el => !otpFields.includes(el) && visible(el)) }).then(response => {
        autofillGate.completed = Number(response?.result) > 0;
      }).catch(() => {}).finally(() => {
        autofillGate.pending = false;
        schedule();
      });
    };
    const schedule = () => { clearTimeout(timer); timer = setTimeout(check, 250); };
    const observer = new MutationObserver(schedule);
    observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "class", "style", "hidden", "disabled", "readonly", "autocomplete"] });
    // History API navigation does not dispatch popstate. Poll only the URL;
    // ordinary mutations never cause another lookup for the same form.
    setInterval(() => { if (location.href !== pageUrl) schedule(); }, 1000);
    addEventListener("popstate", schedule);
    addEventListener("hashchange", schedule);
    document.addEventListener("visibilitychange", schedule);
    schedule();
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loaded, { once: true }); else loaded();
}
