/* MAIN world: only WebAuthn public options and responses cross this boundary. */
(() => {
  const shim = globalThis.rbwPasskeyShim;
  delete globalThis.rbwPasskeyShim;
  const { credential } = shim;
  if (!globalThis.isSecureContext || !navigator.credentials) return;
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const credentials = navigator.credentials;
  const encode = value => {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      let text = ""; for (const byte of bytes) text += String.fromCharCode(byte);
      return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    if (Array.isArray(value)) return value.map(encode);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).filter(([key]) => key !== "signal").map(([key, v]) => [key, encode(v)]));
    return value;
  };
  function available() {
    const id = crypto.randomUUID();
    return new Promise(resolve => {
      const listener = event => {
        if (event.source !== window || event.origin !== location.origin || event.data?.channel !== "rbw-passkey-response" || event.data.id !== id) return;
        clearTimeout(timer); window.removeEventListener("message", listener); resolve(event.data.result === true);
      };
      const timer = setTimeout(() => { window.removeEventListener("message", listener); resolve(false); }, 1000);
      window.addEventListener("message", listener);
      window.postMessage({ channel: "rbw-passkey", action: "availability", id }, location.origin);
    });
  }
  shim.patchPlatformAuthenticator(available);
  const methods = ["get", "create"].map(method => ({ method, handler: null, outer: null, repair: null, retries: 0, warned: false }));
  function install(state) {
    const { method } = state;
    const fallback = credentials[method].bind(credentials);
    const handler = async options => {
      // A provider may have captured an older rbw wrapper. Only the newest one
      // handles requests; falling through older wrappers must not prompt twice.
      if (handler !== state.handler || !options?.publicKey) return fallback(options);
      if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
      const id = crypto.randomUUID();
      const result = await new Promise((resolve, reject) => {
        let timeout;
        const clean = () => { clearTimeout(timeout); window.removeEventListener("message", receive); options.signal?.removeEventListener("abort", abort); };
        const abort = () => { clean(); window.postMessage({ channel: "rbw-passkey", action: "cancel", id }, location.origin); reject(new DOMException("Aborted", "AbortError")); };
        const receive = event => {
          if (event.source !== window || event.origin !== location.origin || event.data?.channel !== "rbw-passkey-response" || event.data.id !== id) return;
          clean(); resolve(event.data);
        };
        window.addEventListener("message", receive);
        options.signal?.addEventListener("abort", abort, { once: true });
        timeout = setTimeout(() => { clean(); window.postMessage({ channel: "rbw-passkey", action: "cancel", id }, location.origin); reject(new DOMException("Passkey request timed out", "NotAllowedError")); }, Math.min(Math.max(options.publicKey.timeout || 120000, 15000), 300000));
        window.postMessage({ channel: "rbw-passkey", action: method, id, options: encode(options.publicKey), conditional: options.mediation === "conditional" }, location.origin);
      });
      if (result.fallback) return fallback(options);
      if (result.error) throw new DOMException(result.error, "NotAllowedError");
      return credential(result.result, method);
    };
    Object.defineProperty(credentials, method, { configurable: true, writable: true, value: handler });
    state.handler = handler;
    state.outer = state.repair = null;
    if (method === "get" && typeof globalThis.__bdPasskeyRepair === "function") {
      // Ask browser-daemon to wrap this exact handler, then remember the wrapper
      // it installed. Merely seeing the global is not enough to skip recovery.
      const repair = globalThis.__bdPasskeyRepair;
      try {
        repair();
        if (typeof credentials.get === "function" && credentials.get !== handler) {
          state.outer = credentials.get;
          state.repair = repair;
        }
      } catch (_) { /* A broken or unavailable proxy must not disable rbw. */ }
    }
  }
  const owns = state => state.handler !== null && (credentials[state.method] === state.handler ||
    (state.outer && credentials[state.method] === state.outer && state.repair === globalThis.__bdPasskeyRepair));
  const warn = state => {
    if (state.warned) return;
    state.warned = true;
    console.warn(`rbw: WebAuthn ${state.method} recovery stopped after repeated handler replacement or installation failure.`);
  };
  for (const state of methods) {
    try { install(state); } catch (_) { /* Retry briefly if the page is not ready. */ }
  }
  // Recover from late provider injection, without starting an endless ownership
  // contest. Each method gets five reinstalls within ten seconds of page load.
  const deadline = performance.now() + 10000;
  let timer;
  const recover = () => {
    if (performance.now() >= deadline) return;
    for (const state of methods) {
      if (owns(state)) continue;
      if (state.retries >= 5) { warn(state); continue; }
      state.retries++;
      try { install(state); } catch (_) { if (state.retries >= 5) warn(state); }
    }
    timer = setTimeout(recover, 500);
  };
  timer = setTimeout(recover, 500);
  window.addEventListener("pagehide", () => clearTimeout(timer), { once: true });
})();
