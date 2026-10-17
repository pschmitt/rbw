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
  let host, generation = 0;
  function close() { ++generation; host?.remove(); host = null; }
  document.addEventListener("focusin", async event => {
    const input = event.composedPath()[0];
    if (!(input instanceof HTMLInputElement) || !event.isTrusted || !isSecureContext || !["password", "email", "text"].includes(input.type) || (input.type === "text" && input.autocomplete !== "username")) { if (!host?.contains(input)) close(); return; }
    close(); const current = generation;
    const result = await api.runtime.sendMessage({ action: "inline_choices" }).catch(() => null);
    let focused = document.activeElement; while (focused?.shadowRoot?.activeElement) focused = focused.shadowRoot.activeElement;
    if (current !== generation || !result?.result?.length || focused !== input) return;
    host = document.createElement("div");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = ":host{all:initial}.box{box-sizing:border-box;font:13px/1.4 system-ui,sans-serif;color:#f1f4fc;background:#1b263d;border:1px solid #a7bfea;border-radius:10px;box-shadow:0 6px 20px #0006;overflow:hidden;max-width:380px}.header{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:#151b2d;border-bottom:1px solid #384d70}.title{color:#a0b4d6;font-size:11px;font-weight:600;letter-spacing:0.3px;text-transform:uppercase}.dismiss-btn{display:flex;align-items:center;justify-content:center;border:0;background:transparent;color:#a0b4d6;padding:2px 4px;border-radius:4px;cursor:pointer;line-height:1}.dismiss-btn:hover,.dismiss-btn:focus-visible{color:#f1f4fc;background:#253653}.dismiss-btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}.item-btn{display:flex;align-items:center;gap:10px;width:100%;text-align:left;border:0;border-top:1px solid #253653;padding:8px 12px;background:#1b263d;color:#f1f4fc;font:13px system-ui,sans-serif;cursor:pointer}.item-btn:first-of-type{border-top:0}.item-btn:hover,.item-btn:focus-visible{background:#253653;outline:none}.icon-col{width:20px;height:20px;display:flex;align-items:center;justify-content:center;flex-shrink:0;border-radius:3px}.icon-col img{width:18px;height:18px;border-radius:3px;object-fit:contain}.icon-col svg{width:18px;height:18px;stroke:#a7bfea;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.text-col{min-width:0;flex:1}strong,small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}strong{font-weight:500;font-size:13px}small{color:#a0b4d6;font-size:11px;margin-top:1px}";
    shadow.append(style);
    const box = document.createElement("div"); box.className = "box";
    const header = document.createElement("div"); header.className = "header";
    const title = document.createElement("span"); title.className = "title"; title.textContent = "rbw · Fill a login";
    const dismiss = document.createElement("button"); dismiss.className = "dismiss-btn"; dismiss.type = "button"; dismiss.title = "Dismiss"; dismiss.setAttribute("aria-label", "Dismiss");
    const closeIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"); closeIcon.setAttribute("viewBox", "0 0 24 24"); closeIcon.setAttribute("aria-hidden", "true");
    const closePath = document.createElementNS(closeIcon.namespaceURI, "path"); closePath.setAttribute("d", "M18 6 6 18M6 6l12 12"); closeIcon.append(closePath); dismiss.append(closeIcon);
    dismiss.addEventListener("click", event => { if (event.isTrusted) close(); });
    header.append(title, dismiss); box.append(header);

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
    const rect = input.getBoundingClientRect(); host.style.cssText = `position:fixed!important;z-index:2147483647!important;top:${Math.min(rect.bottom + 4, innerHeight - 230)}px!important;left:${Math.max(0, Math.min(rect.left, innerWidth - 300))}px!important;width:${Math.max(rect.width, 240)}px!important`;
    document.documentElement.append(host);
  });
  document.addEventListener("keydown", event => { if (event.key === "Escape") close(); });
  window.addEventListener("scroll", close, true); window.addEventListener("resize", close);
})();

if (window === window.top) {
  const loaded = () => (globalThis.browser || chrome).runtime.sendMessage({ action: "autofill_load" }).catch(() => {});
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loaded, { once: true }); else loaded();
}
