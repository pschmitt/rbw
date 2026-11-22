/* Direct connections use an extension-owned, non-exportable signing key. */
const remoteAgent = (() => {
  const extension = globalThis.browser || chrome;
  const encoder = new TextEncoder();
  const domain = encoder.encode("rbw browser api v1\0");
  const instances = new Map();
  const base64url = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");

  function originOf(text) {
    const address = new URL(text);
    if (address.protocol !== "https:" || address.username || address.password ||
        address.pathname !== "/" || address.search || address.hash) {
      throw new Error("Enter an HTTPS origin, such as https://rbw.example.net.");
    }
    return address.origin;
  }

  async function connection() {
    return (await extension.storage.local.get("remoteAgent")).remoteAgent || { mode: "native", origin: "" };
  }

  function database() {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open("rbw-remote-agent", 1);
      open.onupgradeneeded = () => open.result.createObjectStore("identity");
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
  }

  async function identity(origin) {
    const db = await database();
    try {
      const read = db.transaction("identity").objectStore("identity").get(origin);
      const existing = await new Promise((resolve, reject) => {
        read.onsuccess = () => resolve(read.result);
        read.onerror = () => reject(read.error);
      });
      if (existing) return existing;
      const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
      const raw = await crypto.subtle.exportKey("raw", key.publicKey);
      const id = base64url(await crypto.subtle.digest("SHA-256", raw));
      const record = { privateKey: key.privateKey, publicKey: base64url(raw), id };
      await new Promise((resolve, reject) => {
        const transaction = db.transaction("identity", "readwrite");
        transaction.oncomplete = resolve;
        transaction.onabort = () => reject(transaction.error);
        transaction.objectStore("identity").add(record, origin);
      });
      return record;
    } finally {
      db.close();
    }
  }

  function keyFor(origin) {
    if (!instances.has(origin)) {
      instances.set(origin, identity(origin).catch(error => {
        instances.delete(origin);
        throw error;
      }));
    }
    return instances.get(origin);
  }

  async function post(origin, endpoint, payload) {
    const result = await fetch(`${origin}/v1/browser/${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(30000),
    });
    let response;
    try { response = await result.json(); }
    catch (cause) { throw new Error(`Agent returned HTTP ${result.status} without a valid response.`, { cause }); }
    if (!result.ok) throw new Error(response.message || `Agent returned HTTP ${result.status}.`);
    return response;
  }

  async function send(origin, operation, payload = null) {
    const { privateKey, publicKey } = await keyFor(origin);
    const { challenge } = await post(origin, "challenge", { publicKey });
    if (typeof challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
      throw new Error("Agent returned an invalid signing challenge.");
    }
    const request = JSON.stringify({ origin, challenge, operation, payload });
    const data = encoder.encode(request);
    const message = new Uint8Array(domain.length + data.length);
    message.set(domain);
    message.set(data, domain.length);
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, message);
    return post(origin, "request", { publicKey, request, signature: base64url(signature) });
  }

  async function configure(mode, text) {
    if (!["native", "remote"].includes(mode)) throw new Error("Invalid connection mode.");
    const { origin: previous } = await connection();
    const origin = mode === "remote" ? originOf(text) : previous;
    const config = { mode, origin };
    await extension.storage.local.set({ remoteAgent: config });
    return config;
  }

  async function pair(origin, name) {
    const { id } = await keyFor(origin);
    await send(origin, "pair", { name });
    return { code: id.slice(0, 12), id };
  }

  function read(origin, item, field) {
    return send(origin, "read", { itemId: item, field }).then(result => result.value);
  }

  async function call(origin, request) {
    switch (request.action) {
      case "status": {
        const result = await send(origin, "status");
        const unlocked = result.state === "unlocked";
        return {
          unlocked, primary: result.account, accounts: [result.account],
          accountStates: [{ name: result.account, primary: true, unlocked, fingerprint: false }],
          remote: true, fingerprint: false, canUnlock: result.capabilities?.includes("unlock"),
        };
      }
      case "unlock":
        if (typeof request.password !== "string" || !request.password) {
          throw new Error("Enter the vault master password to unlock remotely.");
        }
        await send(origin, "unlock", { account: request.account, password: request.password });
        return call(origin, { action: "status" });
      case "search": {
        const url = /^https?:/i.test(request.url || "") ? request.url : null;
        const empty = { items: [], total: 0, limit: 50, folders: [], collections: [] };
        if (request.kind && request.kind !== "login") return empty;
        if (!url && request.site_only) return empty;
        if (["trash", "archive", "favorites"].includes(request.view)) return empty;
        const result = await send(origin, "search", { url, query: request.query || "", siteOnly: !!request.site_only });
        const items = result.items.filter(item => !request.folder || item.folder === request.folder)
          .map(item => ({
            ...item, type: "login", remote: true, matched: item.site,
            iconOrigin: item.faviconHost ? `https://${item.faviconHost}` : null,
          }));
        return { ...empty, items, total: items.length, folders: [...new Set(items.map(item => item.folder).filter(Boolean))].sort() };
      }
      case "credential": {
        if (!request.manual) {
          const { items } = await send(origin, "search", { url: request.url, query: "", siteOnly: true });
          if (!items.some(item => item.id === request.item)) throw new Error("Item does not match this site.");
        }
        const [name, username, password, fields] = await Promise.all(["name", "username", "password", "custom_all"]
          .map(field => read(origin, request.item, field)));
        const { items } = await send(origin, "search", { url: request.url, query: name || "", siteOnly: false });
        return { name, username, password, custom: fields ? JSON.parse(fields) : [], hasTotp: items.find(item => item.id === request.item)?.hasTotp === true, matched: !request.manual };
      }
      case "detail": {
        const [name, username, password, notes, uris, fields] = await Promise.all(
          ["name", "username", "password", "notes", "uri_all", "custom_all"].map(field => read(origin, request.item, field)));
        return {
          remote: true,
          cipher: { name, notes, data: { type: "login", username, password, uris: uris ? JSON.parse(uris) : [] }, fields: fields ? JSON.parse(fields) : [] },
          passkeys: [], history: [],
        };
      }
      case "copy_value": {
        const value = await read(origin, request.item, request.field);
        if (value == null || value === "") throw new Error("This item has no value for that field.");
        return value;
      }
      case "totp": return { code: await read(origin, request.item, "totp") };
      case "passkey_candidates": {
        const rp = request.options?.rpId || new URL(request.origin).hostname;
        return { rp, ...await send(origin, "passkeys", rp) };
      }
      case "passkey_get": {
        const options = request.options || {};
        if (options.userVerification === "required") {
          throw new Error("This passkey requires user verification. Use the native bridge.");
        }
        return send(origin, "assert", {
          itemId: request.item,
          rpId: options.rpId || new URL(request.origin).hostname,
          origin: request.origin,
          challenge: options.challenge,
          allowCredentials: (options.allowCredentials || []).map(credential => credential.id),
          userVerified: false,
        });
      }
      default: throw new Error("This action is unavailable over the remote connection.");
    }
  }

  return { call, configure, connection, pair, send };
})();
