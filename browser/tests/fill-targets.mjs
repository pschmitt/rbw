import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../extension/fill-targets.js", import.meta.url), "utf8");
const context = vm.createContext({document: {getElementById: () => null}, Node: {DOCUMENT_POSITION_FOLLOWING: 4}});
vm.runInContext(source, context);
const {isOtpField, loginTargets} = context.rbwFillTargets;

// Just enough of an input for the heuristics: attributes, a form, document order.
let order = 0;
function input(attrs = {}, form = null) {
  const el = {
    type: attrs.type ?? "text", id: attrs.id ?? "", name: attrs.name ?? "", placeholder: attrs.placeholder ?? "",
    autocomplete: attrs.autocomplete ?? "", labels: [], form, pos: order++,
    getAttribute(name) { return name === "aria-label" ? attrs.label ?? null : name === "aria-labelledby" ? null : null; },
    closest: () => attrs.inSearch ? {} : null,
    compareDocumentPosition(other) { return other.pos > el.pos ? 4 : 2; },
  };
  return el;
}
const form = {id: "login"};

test("the username before the password in the same form is the user", () => {
  const user = input({name: "login"}, form), password = input({type: "password"}, form);
  const found = loginTargets([input({name: "q"}), user, password]);
  assert.equal(found.user, user);
  assert.equal(found.password, password);
});

test("search boxes are never the username", () => {
  const search = input({type: "search"}, form), user = input({autocomplete: "username"}, form);
  assert.equal(loginTargets([search, user, input({type: "password"}, form)]).user, user);
});

test("API-key fields are not login passwords", () => {
  const key = input({type: "password", name: "api_key"}, form), password = input({type: "password"}, form);
  assert.equal(loginTargets([key, password]).password, password);
});

test("several passwords leave no choice", () => {
  assert.throws(() => loginTargets([input({type: "password"}, form), input({type: "password"}, form)]), /Several password fields/);
});

test("one-time-code fields are recognized by autocomplete or name", () => {
  assert.equal(isOtpField(input({autocomplete: "one-time-code"})), true);
  assert.equal(isOtpField(input({name: "totp"})), true);
  assert.equal(isOtpField(input({name: "email"})), false);
  assert.equal(isOtpField(input({autocomplete: "username", name: "otp"})), false);
  const otp = input({name: "signInMFA"}, form);
  assert.equal(loginTargets([input({type: "password"}, form), otp]).otp, otp);
});
