/* MAIN world: only WebAuthn public options and responses cross this boundary. */
(() => {
  if (!globalThis.isSecureContext || !navigator.credentials) return;
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const original = { get: navigator.credentials.get.bind(navigator.credentials), create: navigator.credentials.create.bind(navigator.credentials) };
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
  const decode = value => {
    const text = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(text, c => c.charCodeAt(0)).buffer;
  };
  function credential(value, method) {
    const data = value.response;
    const response = Object.create(method === "create" ? AuthenticatorAttestationResponse.prototype : AuthenticatorAssertionResponse.prototype);
    for (const field of ["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]) {
      if (field in data) Object.defineProperty(response, field, { value: data[field] == null ? null : decode(data[field]), enumerable: true });
    }
    if (method === "create") {
      Object.defineProperties(response, {
        getTransports: { value: () => data.transports || ["internal"] },
        getPublicKey: { value: () => data.publicKey ? decode(data.publicKey) : null },
        getPublicKeyAlgorithm: { value: () => data.publicKeyAlgorithm || -7 },
        getAuthenticatorData: { value: () => decode(data.authenticatorData) },
      });
    }
    const result = Object.create(PublicKeyCredential.prototype);
    Object.defineProperties(result, {
      id: { value: value.id, enumerable: true }, rawId: { value: decode(value.rawId), enumerable: true },
      type: { value: "public-key", enumerable: true }, response: { value: response, enumerable: true },
      authenticatorAttachment: { value: "platform", enumerable: true },
      getClientExtensionResults: { value: () => value.clientExtensionResults || {} },
      toJSON: { value: () => value },
    });
    return result;
  }
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
  for (const name of ["isUserVerifyingPlatformAuthenticatorAvailable", "isConditionalMediationAvailable"]) {
    const fallback = PublicKeyCredential[name]?.bind(PublicKeyCredential);
    if (fallback) Object.defineProperty(PublicKeyCredential, name, { configurable: true, value: async () => await available() || await fallback() });
  }
  const capabilities = PublicKeyCredential.getClientCapabilities?.bind(PublicKeyCredential);
  if (capabilities) Object.defineProperty(PublicKeyCredential, "getClientCapabilities", { configurable: true, value: async () => {
    const result = await capabilities();
    return await available() ? { ...result, userVerifyingPlatformAuthenticator: true, passkeyPlatformAuthenticator: true, conditionalGet: true } : result;
  } });
  for (const method of ["get", "create"]) {
    Object.defineProperty(navigator.credentials, method, { configurable: true, value: async options => {
      if (!options?.publicKey) return original[method](options);
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
      if (result.fallback) return original[method](options);
      if (result.error) throw new DOMException(result.error, "NotAllowedError");
      return credential(result.result, method);
    } });
  }
})();
