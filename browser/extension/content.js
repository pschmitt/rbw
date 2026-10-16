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
    const style = document.createElement("style"); style.textContent = ":host{all:initial}div{font:13px system-ui;color:#e6e9f1;background:#10182b;border:1px solid #67adff;border-radius:8px;box-shadow:0 4px 15px #0005;overflow:hidden;max-width:360px}p{margin:0;padding:7px 10px;color:#91a4c3;font-size:11px}button{display:block;width:100%;text-align:left;border:0;border-top:1px solid #2b3c55;padding:9px 12px;background:#10182b;color:#e6e9f1;font:13px system-ui;cursor:pointer}button:hover,button:focus{background:#1e293e}small{display:block;color:#91a4c3}"; shadow.append(style);
    const box = document.createElement("div"); const title = document.createElement("p"); title.textContent = "rbw · Fill a login"; box.append(title);
    for (const item of result.result) {
      const button = document.createElement("button"); button.type = "button"; button.textContent = item.name;
      const subtitle = document.createElement("small"); subtitle.textContent = item.username || ""; button.append(subtitle);
      button.addEventListener("pointerdown", event => { if (event.isTrusted) event.preventDefault(); });
      button.addEventListener("click", async event => { if (!event.isTrusted) return; close(); await api.runtime.sendMessage({ action: "inline_fill", item: item.id }).catch(() => {}); }); box.append(button);
    }
    const dismiss = document.createElement("button"); dismiss.textContent = "Dismiss"; dismiss.addEventListener("click", event => { if (event.isTrusted) close(); }); box.append(dismiss); shadow.append(box);
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
