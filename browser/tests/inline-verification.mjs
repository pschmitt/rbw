import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../extension/content.js", import.meta.url), "utf8");
const verify = source.slice(source.indexOf("function rbwVerifyFrame"), source.indexOf("// The token reaches"));
const background = readFileSync(new URL("../extension/background.js", import.meta.url), "utf8");
const errors = background.slice(background.indexOf("const inlineVerificationErrors ="), background.indexOf("async function verifyInlineClick"));
const style = {opacity: "1", display: "block", visibility: "visible", filter: "none", transform: "none", clipPath: "none", maskImage: "none", mixBlendMode: "normal"};
const host = {isConnected: true, parentElement: null, checkVisibility: () => true};
const rect = {width: 380, height: 150, left: 10, top: 10, right: 390, bottom: 160};
const frame = {offsetWidth: 380, offsetHeight: 150, getBoundingClientRect: () => rect};
const document = {visibilityState: "visible", hasFocus: () => true, elementsFromPoint: () => [host]};
class DOMMatrixReadOnly { constructor(value) { this.isIdentity = value === "matrix(1, 0, 0, 1, 0, 0)"; } }
const context = vm.createContext({document, performance: {now: () => 1000}, getComputedStyle: () => style, innerWidth: 800, innerHeight: 600, DOMMatrixReadOnly});
vm.runInContext(verify, context);
vm.runInContext(`${errors}\nglobalThis.verificationErrors = inlineVerificationErrors;`, context);
const check = () => context.rbwVerifyFrame({host, frame, shownAt: 0}, 20, 20);

test("unchanged transforms are accepted and real transforms are rejected", () => {
  assert.equal(check(), null);
  style.transform = "matrix(1, 0, 0, 1, 0, 0)";
  assert.equal(check(), null);
  style.transform = "matrix(0.6, 0, 0, 0.6, 0, 0)";
  assert.equal(check(), "altered");
  style.transform = "none";
});
test("verification reports why a click was rejected", () => {
  document.hasFocus = () => false; assert.equal(check(), "unfocused"); document.hasFocus = () => true;
  style.opacity = "0.5"; assert.equal(check(), "translucent"); style.opacity = "1";
  document.elementsFromPoint = () => [{}]; assert.equal(check(), "covered"); document.elementsFromPoint = () => [host];
  rect.bottom = 700; assert.equal(check(), "clipped"); rect.bottom = 160;
  assert.equal(context.rbwVerifyFrame({host, frame, shownAt: 0}, -1, 20), "coordinates");
});
test("rejection messages distinguish covering, clipping and focus", () => {
  assert.match(context.verificationErrors.covered, /covering/i);
  assert.match(context.verificationErrors.clipped, /outside the window/i);
  assert.match(context.verificationErrors.unfocused, /foreground/i);
  assert.match(context.verificationErrors.unavailable, /could not check/i);
});
