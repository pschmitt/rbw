/* ISOLATED world: the background obtains the site from MessageSender.url. */
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

// Inline UI lives in a closed shadow root in the isolated world. A page never
// receives the vault result set or a native messaging capability.
(() => {
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const api = globalThis.browser || chrome;
  let host, generation = 0, filled = false, movedPosition = null;
  const fills = new Set();
  api.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== api.runtime.id || message?.action !== "rbw_fill_state") return;
    close();
    if (message.active) fills.add(message.token);
    else { fills.delete(message.token); filled ||= message.filled === true; }
  });
  // Only deliberate interaction re-enables suggestions after filling; focus() is trusted too.
  document.addEventListener("pointerdown", event => { if (event.isTrusted && !fills.size) filled = false; }, true);
  document.addEventListener("keydown", event => { if (event.isTrusted && !fills.size && event.key !== "Escape") filled = false; }, true);
  function close() { ++generation; host?.remove(); host = null; }
  document.addEventListener("focusin", async event => {
    const input = event.composedPath()[0];
    if (filled || fills.size) { close(); return; }
    if (!(input instanceof HTMLInputElement) || !event.isTrusted || !isSecureContext || !["password", "email", "text"].includes(input.type) || (input.type === "text" && input.autocomplete !== "username")) { if (!host?.contains(input)) close(); return; }
    close(); const current = generation;
    const result = await api.runtime.sendMessage({ action: "inline_choices" }).catch(() => null);
    let focused = document.activeElement; while (focused?.shadowRoot?.activeElement) focused = focused.shadowRoot.activeElement;
    if (current !== generation || !result?.result?.length || focused !== input) return;
    host = document.createElement("div");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = ":host{all:initial}.box{box-sizing:border-box;font:13px/1.4 system-ui,sans-serif;color:#efefef;background:#282828;border:1px solid #555555;border-radius:10px;box-shadow:0 6px 20px #0006;overflow:hidden;max-width:380px}.header{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:#202020;border-bottom:1px solid #494949}.drag-handle{display:flex;align-items:center;gap:7px;flex:1;min-width:0;border:0;padding:0;background:transparent;text-align:left;cursor:grab;touch-action:none;user-select:none}.drag-handle:active{cursor:grabbing}.drag-handle:focus-visible{outline:1px solid #d0d0d0;outline-offset:3px;border-radius:3px}.grip{width:12px;height:16px;fill:#adadad;flex-shrink:0}.title{display:flex;align-items:center;gap:6px;color:#adadad;font-size:11px;font-weight:600;letter-spacing:0.3px;text-transform:uppercase}.app-icon{width:14px;height:14px;object-fit:contain;flex-shrink:0;border-radius:2px}.dismiss-btn{display:flex;align-items:center;justify-content:center;border:0;background:transparent;color:#adadad;padding:2px 4px;border-radius:4px;cursor:pointer;line-height:1}.dismiss-btn:hover,.dismiss-btn:focus-visible{color:#efefef;background:#383838}.dismiss-btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}.item-btn{display:flex;align-items:center;gap:10px;width:100%;text-align:left;border:0;border-top:1px solid #383838;padding:8px 12px;background:#282828;color:#efefef;font:13px system-ui,sans-serif;cursor:pointer}.item-btn:first-of-type{border-top:0}.item-btn:hover,.item-btn:focus-visible{background:#383838;outline:none}.icon-col{width:20px;height:20px;display:flex;align-items:center;justify-content:center;flex-shrink:0;border-radius:3px}.icon-col img{width:18px;height:18px;border-radius:3px;object-fit:contain}.icon-col svg{width:18px;height:18px;stroke:#d0d0d0;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.text-col{min-width:0;flex:1}strong,small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}strong{font-weight:500;font-size:13px}small{color:#adadad;font-size:11px;margin-top:1px}";
    shadow.append(style);
    const box = document.createElement("div"); box.className = "box";
    const header = document.createElement("div"); header.className = "header";
    const title = document.createElement("span"); title.className = "title";
    if (result?.appIcon) {
      const appIcon = document.createElement("img"); appIcon.className = "app-icon"; appIcon.alt = ""; appIcon.src = result.appIcon;
      title.append(appIcon);
    }
    const titleText = document.createElement("span"); titleText.textContent = "rbw · Autofill";
    title.append(titleText);
    const dismiss = document.createElement("button"); dismiss.className = "dismiss-btn"; dismiss.type = "button"; dismiss.title = "Dismiss"; dismiss.setAttribute("aria-label", "Dismiss");
    const closeIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"); closeIcon.setAttribute("viewBox", "0 0 24 24"); closeIcon.setAttribute("aria-hidden", "true");
    const closePath = document.createElementNS(closeIcon.namespaceURI, "path"); closePath.setAttribute("d", "M18 6 6 18M6 6l12 12"); closeIcon.append(closePath); dismiss.append(closeIcon);
    dismiss.addEventListener("click", event => { if (event.isTrusted) close(); });
    const handle = document.createElement("button"); handle.type = "button"; handle.className = "drag-handle";
    handle.setAttribute("aria-label", "Move autofill suggestions"); handle.title = "Drag to move · Arrow keys to adjust · Home to reset";
    const grip = document.createElementNS(closeIcon.namespaceURI, "svg"); grip.setAttribute("viewBox", "0 0 12 16"); grip.setAttribute("class", "grip"); grip.setAttribute("aria-hidden", "true");
    for (const x of [3, 9]) for (const y of [3, 8, 13]) { const dot = document.createElementNS(closeIcon.namespaceURI, "circle"); dot.setAttribute("cx", x); dot.setAttribute("cy", y); dot.setAttribute("r", "1"); grip.append(dot); }
    handle.append(grip, title); header.append(handle, dismiss); box.append(header);

    const iconTargets = new Map();
    for (const item of result.result) {
      const button = document.createElement("button"); button.type = "button"; button.className = "item-btn";
      const iconCol = document.createElement("span"); iconCol.className = "icon-col";
      if (item.favicon) {
        const img = document.createElement("img"); img.src = item.favicon; img.alt = "";
        iconCol.append(img);
      } else {
        const keyIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"); keyIcon.setAttribute("viewBox", "0 0 24 24"); keyIcon.setAttribute("aria-hidden", "true");
        const keyPath = document.createElementNS(keyIcon.namespaceURI, "path"); keyPath.setAttribute("d", "M13 15a5 5 0 1 1-1.5-3.5l8-8L22 6l-2 2-2-2-2 2 2 2-3 3"); keyIcon.append(keyPath); iconCol.append(keyIcon);
      }
      iconTargets.set(item.id, iconCol);
      const textCol = document.createElement("div"); textCol.className = "text-col";
      const name = document.createElement("strong"); name.textContent = item.name;
      textCol.append(name);
      if (item.username) {
        const subtitle = document.createElement("small"); subtitle.textContent = item.username;
        textCol.append(subtitle);
      }
      button.append(iconCol, textCol);
      button.addEventListener("pointerdown", event => { if (event.isTrusted) event.preventDefault(); });
      button.addEventListener("click", async event => { if (!event.isTrusted) return; close(); await api.runtime.sendMessage({ action: "inline_fill", item: item.id }).catch(() => {}); });
      box.append(button);
    }
    shadow.append(box);
    const rect = input.getBoundingClientRect();
    host.style.cssText = `position:fixed!important;z-index:2147483647!important;top:0!important;left:0!important;width:${Math.max(0, Math.min(380, Math.max(rect.width, 240), innerWidth - 16))}px!important;visibility:hidden!important`;
    document.documentElement.append(host);
    const position = (x, y) => {
      const size = box.getBoundingClientRect();
      const point = { x: Math.max(8, Math.min(x, innerWidth - size.width - 8)), y: Math.max(8, Math.min(y, innerHeight - size.height - 8)) };
      host.style.setProperty("left", `${point.x}px`, "important"); host.style.setProperty("top", `${point.y}px`, "important");
      return point;
    };
    position(movedPosition?.x ?? rect.left, movedPosition?.y ?? rect.bottom + 4); host.style.setProperty("visibility", "visible", "important");
    let drag;
    handle.addEventListener("pointerdown", event => {
      if (!event.isTrusted || event.button !== 0) return;
      event.preventDefault(); const bounds = box.getBoundingClientRect();
      drag = { id: event.pointerId, x: event.clientX, y: event.clientY, left: bounds.left, top: bounds.top };
      handle.setPointerCapture(event.pointerId);
    });
    handle.addEventListener("pointermove", event => {
      if (!event.isTrusted || !drag || drag.id !== event.pointerId || !host) return;
      movedPosition = position(drag.left + event.clientX - drag.x, drag.top + event.clientY - drag.y);
    });
    const endDrag = () => { drag = null; };
    handle.addEventListener("pointerup", endDrag); handle.addEventListener("pointercancel", endDrag); handle.addEventListener("lostpointercapture", endDrag);
    handle.addEventListener("keydown", event => {
      if (!event.isTrusted || !host) return;
      if (event.key === "Home") { event.preventDefault(); movedPosition = null; const anchor = input.getBoundingClientRect(); position(anchor.left, anchor.bottom + 4); return; }
      const delta = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[event.key];
      if (!delta) return;
      event.preventDefault(); const bounds = box.getBoundingClientRect(); const step = event.shiftKey ? 40 : 10;
      movedPosition = position(bounds.left + delta[0] * step, bounds.top + delta[1] * step);
    });
    api.runtime.sendMessage({ action: "inline_icons" }).then(response => {
      if (generation !== current || !host) return;
      for (const item of response?.result || []) {
        const target = iconTargets.get(item.id);
        if (!target || !item.favicon) continue;
        const image = document.createElement("img"); image.alt = ""; image.src = item.favicon;
        image.onload = () => { if (generation === current && host) target.replaceChildren(image); };
      }
    }).catch(() => {});
  });
  document.addEventListener("keydown", event => { if (event.key === "Escape") close(); });
  window.addEventListener("scroll", close, true); window.addEventListener("resize", close);
})();

if (window === window.top) {
  const loaded = () => {
    let observer, timer, expiry;
    const eligible = () => document.querySelector('input[type="password"]:not([autocomplete="new-password"]),input[autocomplete="username"]');
    const check = () => {
      if (!eligible()) return false;
      observer?.disconnect(); clearTimeout(timer); clearTimeout(expiry);
      (globalThis.browser || chrome).runtime.sendMessage({ action: "autofill_load" }).catch(() => {});
      return true;
    };
    if (check()) return;
    // Briefly cover asynchronously rendered sign-in forms without keeping a
    // permanent observer or querying the vault on ordinary content/search pages.
    observer = new MutationObserver(() => { clearTimeout(timer); timer = setTimeout(check, 250); });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    expiry = setTimeout(() => { observer.disconnect(); clearTimeout(timer); }, 10000);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loaded, { once: true }); else loaded();
}
