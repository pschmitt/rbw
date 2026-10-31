import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {randomUUID} from "node:crypto";
import {test} from "node:test";
import vm from "node:vm";

const shim = readFileSync(new URL("../extension/passkey-shim.js", import.meta.url), "utf8");
const source = readFileSync(new URL("../extension/webauthn.js", import.meta.url), "utf8");

function page({before, respond = () => ({fallback: true})} = {}) {
  let now = 100000, nextTimer = 0;
  const timers = new Map(), listeners = new Map(), messages = [], warnings = [];
  const calls = {get: 0, create: 0};
  const credentials = Object.fromEntries(["get", "create"].map(method => [method, async function () {
    assert.equal(this, credentials);
    calls[method]++;
    return `native-${method}`;
  }]));
  const location = {origin: "https://example.org", hostname: "example.org"};
  const window = {
    location, top: {location},
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(listener);
    },
    removeEventListener(type, listener) { listeners.get(type)?.delete(listener); },
    postMessage(message, target) {
      assert.equal(target, location.origin);
      messages.push(message);
      const result = respond(message);
      if (result != null) queueMicrotask(() => reply(message, result));
    },
  };
  function reply(message, result) {
    for (const listener of [...listeners.get("message") || []]) {
      listener({source: window, origin: location.origin, data: {channel: "rbw-passkey-response", id: message.id, ...result}});
    }
  }
  const context = vm.createContext({window, location, navigator: {credentials}, isSecureContext: true,
    Date: class extends Date { static now() { return now; } },
    performance: {now: () => now},
    crypto: {randomUUID}, ArrayBuffer, Uint8Array, AbortController, DOMException,
    PublicKeyCredential: class {}, AuthenticatorAssertionResponse: class {}, AuthenticatorAttestationResponse: class {},
    btoa: value => Buffer.from(value, "binary").toString("base64"),
    atob: value => Buffer.from(value, "base64").toString("binary"),
    console: {warn: message => warnings.push(message)},
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, {callback, time: now + delay}); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  const result = {context, credentials, calls, messages, warnings, timers, reply,
    run: () => { vm.runInContext(shim, context); vm.runInContext(source, context); },
    hide() { for (const listener of listeners.get("pagehide") || []) listener(); },
    advance(ms) {
      const end = now + ms;
      for (;;) {
        const next = [...timers].filter(([, timer]) => timer.time <= end).sort((a, b) => a[1].time - b[1].time)[0];
        if (!next) break;
        now = Math.max(now, next[1].time);
        timers.delete(next[0]);
        next[1].callback();
      }
      now = end;
    },
    jump(ms) { now += ms; },
  };
  before?.(result);
  result.run();
  return result;
}
const options = extra => ({publicKey: {challenge: new Uint8Array([1, 2, 3])}, ...extra});
const requests = p => p.messages.filter(message => ["get", "create"].includes(message.action));
const replace = (p, method, value) => Object.defineProperty(p.credentials, method, {configurable: true, writable: true, value});

// Model browser-daemon's existing repair API: it captures the current handler,
// wraps it for a live view and bypasses its older wrappers on fallback.
function daemon(p) {
  let current;
  const state = {viewed: false, offers: 0, repairs: 0};
  p.context.__bdPasskeyRepair = () => {
    if (p.credentials.get === current) return;
    const fallback = p.credentials.get.bind(p.credentials);
    const hook = options => {
      if (hook !== current || !state.viewed) return fallback(options);
      state.offers++;
      return Promise.resolve("proxy");
    };
    replace(p, "get", hook);
    current = hook;
    state.repairs++;
  };
  p.context.__bdPasskeyRepair();
  return state;
}

test("get and create recover from a later provider, preserving its fallback and receiver", async () => {
  const p = page();
  for (const method of ["get", "create"]) {
    let providerCalls = 0;
    const provider = async function () { assert.equal(this, p.credentials); providerCalls++; return "provider"; };
    replace(p, method, provider);
    p.advance(500);
    assert.notEqual(p.credentials[method], provider);
    assert.equal(await p.credentials[method](options()), "provider");
    assert.equal(providerCalls, 1);
  }
  assert.deepEqual(requests(p).map(request => request.action), ["get", "create"]);
});

test("captured older rbw wrappers never prompt again on fallback", async () => {
  const p = page();
  let providerCalls = 0;
  for (let generation = 0; generation < 4; generation++) {
    const captured = p.credentials.get.bind(p.credentials);
    replace(p, "get", opts => { providerCalls++; return captured(opts); });
    p.advance(500);
  }
  assert.equal(await p.credentials.get(options()), "native-get");
  assert.equal(requests(p).length, 1);
  assert.equal(providerCalls, 4);
  assert.equal(p.calls.get, 1);
});

test("browser-daemon installed first keeps the outer wrapper and rbw as fallback", async () => {
  let proxy;
  const p = page({before: p => { proxy = daemon(p); }});
  const outer = p.credentials.get;
  p.advance(9000);
  assert.equal(p.credentials.get, outer);
  assert.equal(proxy.repairs, 2, "rbw must ask the daemon to wrap its newly installed handler only once");
  proxy.viewed = true;
  assert.equal(await p.credentials.get(options()), "proxy");
  assert.equal(proxy.offers, 1);
  assert.equal(requests(p).length, 0);
  proxy.viewed = false;
  assert.equal(await p.credentials.get(options()), "native-get");
  assert.equal(requests(p).length, 1);
});

test("browser-daemon installed later cooperates once, then recovery leaves it alone", async () => {
  const p = page(), proxy = daemon(p);
  p.advance(500);
  const outer = p.credentials.get;
  p.advance(9000);
  assert.equal(p.credentials.get, outer);
  assert.equal(proxy.repairs, 2);
  assert.equal(p.warnings.length, 0);
  proxy.viewed = true;
  assert.equal(await p.credentials.get(options()), "proxy");
  assert.equal(requests(p).length, 0);
});

test("a daemon global alone does not make an unrelated replacement compatible", async () => {
  const p = page({before: p => { p.context.__bdPasskeyRepair = () => {}; }});
  const unrelated = () => Promise.resolve("other");
  replace(p, "get", unrelated);
  p.advance(500);
  assert.notEqual(p.credentials.get, unrelated);
  assert.equal(await p.credentials.get(options()), "other");
  assert.equal(requests(p).length, 1);
});

test("a failing daemon repair does not break rbw", async () => {
  const p = page({before: p => { p.context.__bdPasskeyRepair = () => { throw new Error("unavailable"); }; }});
  assert.equal(await p.credentials.get(options()), "native-get");
  assert.equal(requests(p).length, 1);
});

test("each method gives up after five replacements without repeated warnings", () => {
  const p = page();
  for (let attempt = 0; attempt < 5; attempt++) {
    const provider = () => {};
    replace(p, "get", provider);
    p.advance(500);
    assert.notEqual(p.credentials.get, provider);
  }
  const winner = () => {};
  replace(p, "get", winner);
  p.advance(500);
  assert.equal(p.credentials.get, winner);
  assert.equal(p.warnings.length, 1);
  const createProvider = () => {};
  replace(p, "create", createProvider);
  p.advance(500);
  assert.notEqual(p.credentials.create, createProvider, "get must not spend create's recovery budget");
  p.advance(20000);
  assert.equal(p.credentials.get, winner);
  assert.equal(p.warnings.length, 1);
  assert.equal(p.timers.size, 0);
});

test("recovery ends after ten seconds, including when the browser throttles timers", () => {
  for (const throttled of [false, true]) {
    const p = page();
    if (throttled) p.jump(15000);
    else p.advance(10000);
    const provider = () => {};
    replace(p, "get", provider);
    p.advance(20000);
    assert.equal(p.credentials.get, provider);
    assert.equal(p.timers.size, 0);
  }
});

test("leaving the page stops recovery immediately", () => {
  const p = page();
  p.hide();
  const provider = () => {};
  replace(p, "get", provider);
  p.advance(10000);
  assert.equal(p.credentials.get, provider);
  assert.equal(p.timers.size, 0);
});

test("non-configurable handlers fail safely and recovery still stops", async () => {
  const p = page({before: p => Object.defineProperty(p.credentials, "get", {configurable: false, writable: false, value: p.credentials.get})});
  p.advance(20000);
  assert.equal(p.warnings.length, 1);
  assert.equal(p.timers.size, 0);
  assert.equal(await p.credentials.get(options()), "native-get");
  assert.equal(requests(p).length, 0);
});

test("non-WebAuthn requests bypass the extension", async () => {
  const p = page();
  assert.equal(await p.credentials.get(), "native-get");
  assert.equal(await p.credentials.create({password: true}), "native-create");
  assert.equal(requests(p).length, 0);
});

test("abort, conditional mediation and request timeout keep their behavior", async () => {
  const p = page({respond: () => null});
  const controller = new AbortController();
  const pending = p.credentials.get(options({mediation: "conditional", signal: controller.signal}));
  assert.equal(requests(p)[0].conditional, true);
  controller.abort();
  await assert.rejects(pending, {name: "AbortError"});
  assert.equal(p.messages.filter(message => message.action === "cancel").length, 1);
  const timed = p.credentials.get({publicKey: {challenge: new Uint8Array([1]), timeout: 15000}});
  const rejected = assert.rejects(timed, {name: "NotAllowedError"});
  p.advance(15000);
  await rejected;
  assert.equal(p.timers.size, 0);
});

test("a pending request survives handler recovery", async () => {
  const p = page({respond: () => null});
  const pending = p.credentials.get(options());
  const request = requests(p)[0];
  replace(p, "get", () => Promise.resolve("provider"));
  p.advance(500);
  p.reply(request, {fallback: true});
  assert.equal(await pending, "native-get");
  assert.equal(requests(p).length, 1);
});
