import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";

const background = readFileSync(new URL("../extension/background.js", import.meta.url), "utf8");
const copySource = background.slice(background.indexOf("async function copyToClipboard("), background.indexOf("async function fill("));

function harness({url = "https://login.example/", token = "fill-token", documentId} = {}) {
  const writes = [], targets = [];
  const page = vm.createContext({location: {href: url}, __rbwClipboardFillToken: token,
    navigator: {clipboard: {writeText: async value => { writes.push(value); }}}});
  const api = {scripting: {executeScript: async ({target, args, func}) => {
    targets.push(target);
    if (target.documentIds && target.documentIds[0] !== documentId) throw new Error("Document no longer exists");
    const injected = vm.runInContext(`(${func.toString()})`, page);
    return [{result: await injected(...args)}];
  }}};
  const context = vm.createContext({api});
  vm.runInContext(copySource, context);
  return {writes, targets, copy: () => context.copyToClipboard({id: 1, url: "https://login.example/"}, "fill-token", documentId, "test-code")};
}

test("TOTP copy succeeds only once in the original document", async () => {
  const h = harness();
  await h.copy();
  assert.deepEqual(h.writes, ["test-code"]);
  await assert.rejects(h.copy(), /Could not write/);
  assert.deepEqual(h.writes, ["test-code"]);
  assert.deepEqual(Array.from(h.targets[0].frameIds), [0]);
});

test("a redirect cannot receive the TOTP clipboard operation", async () => {
  const h = harness({url: "https://other.example/"});
  await assert.rejects(h.copy(), /Could not write/);
  assert.deepEqual(h.writes, []);
});

test("a replacement document at the same URL cannot receive the code", async () => {
  const h = harness({token: null});
  await assert.rejects(h.copy(), /Could not write/);
  assert.deepEqual(h.writes, []);
});

test("document IDs pin Chromium injection without a frame-ID fallback", async () => {
  const h = harness({documentId: "original-document"});
  await h.copy();
  assert.deepEqual(Array.from(h.targets[0].documentIds), ["original-document"]);
  assert.equal(h.targets[0].frameIds, undefined);
});

test("filling the top document establishes a token even when only a subframe has fields", async () => {
  const timers = [];
  const context = vm.createContext({location: {href: "https://login.example/"},
    document: {querySelectorAll: () => []},
    setTimeout: fn => { timers.push(fn); },
  });
  vm.runInContext(readFileSync(new URL("../extension/fill.js", import.meta.url), "utf8"), context);
  const result = await context.fillPage("https://login.example/", {type: "login"}, "fill-token", {animations: "off"});
  assert.equal(result.count, 0);
  assert.equal(context.__rbwClipboardFillToken, "fill-token");
  timers.at(-1)();
  assert.equal(context.__rbwClipboardFillToken, undefined);
});
