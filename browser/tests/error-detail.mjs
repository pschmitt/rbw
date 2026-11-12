import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";

const popup = readFileSync(new URL("../extension/popup.js", import.meta.url), "utf8");
const background = readFileSync(new URL("../extension/background.js", import.meta.url), "utf8");
const messageSource = popup.slice(popup.indexOf("function message("), popup.indexOf("// Notices are banners"));
const attemptSource = popup.slice(popup.indexOf("async function attempt("), popup.indexOf("function showDiagnostic("));

function element() {
  return {hidden: true, open: false, textContent: "", dataset: {}, classList: {toggle() {}, remove() {}, add() {}}, setAttribute() {}, replaceChildren() {}, get offsetWidth() { return 0; }};
}

function harness() {
  const elements = {};
  const context = vm.createContext({
    $: id => elements[id] ??= element(), icon: () => ({}), bannerAnimated: () => false,
    hideNotification() {}, setTimeout, clearTimeout, notificationTimer: 0, notificationLeaving: 0,
    show() {}, clearVault() {}, unlocked: true, showDiagnostic() {},
  });
  vm.runInContext(`${messageSource}\n${attemptSource}`, context);
  return {elements, context};
}

test("an error with a detail shows the message and an expandable detail", () => {
  const {elements, context} = harness();
  context.message("The master password is incorrect.", true, null, "verifying\ncaused by: Password is incorrect");
  assert.equal(elements["message-text"].textContent, "The master password is incorrect.");
  assert.equal(elements["message-details"].hidden, false);
  assert.equal(elements["message-details"].open, false);
  assert.match(elements["message-detail"].textContent, /Password is incorrect/);
});

test("no detail, or a detail equal to the message, shows no disclosure", () => {
  const {elements, context} = harness();
  context.message("Vault synced.");
  assert.equal(elements["message-details"].hidden, true);
  context.message("Same text.", true, null, "Same text.");
  assert.equal(elements["message-details"].hidden, true);
  context.message("Other.", true, null, "   ");
  assert.equal(elements["message-details"].hidden, true);
});

test("attempt passes the detail of a rejected request to the banner", async () => {
  const {elements, context} = harness();
  await context.attempt(async () => { const error = new Error("Server said no."); error.detail = "HTTP 400"; throw error; });
  assert.equal(elements["message-text"].textContent, "Server said no.");
  assert.equal(elements["message-detail"].textContent, "HTTP 400");
});

test("the background keeps the host's detail on rejected native requests and relays it", () => {
  assert.match(background, /error\.detail = response\.detail/);
  assert.match(background, /detail: error\.detail \|\| null/);
});
