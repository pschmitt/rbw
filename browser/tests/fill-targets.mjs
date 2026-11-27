import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../extension/fill-targets.js", import.meta.url), "utf8");
class HTMLInputElement {}
const context = vm.createContext({document: {getElementById: () => null}, Node: {DOCUMENT_POSITION_FOLLOWING: 4}, HTMLInputElement});
vm.runInContext(source, context);
const {isOtpField, loginTargets, confirmationField, passwordLengthBounds} = context.rbwFillTargets;

function passwordField({minLength = -1, maxLength = -1, rules, hint, nearby} = {}) {
  const description = textContent => ({textContent, querySelector: () => null});
  return {
    minLength, maxLength,
    getAttribute: name => ({"aria-describedby": hint && "hint", passwordrules: rules})[name],
    getRootNode: () => ({getElementById: () => description(hint)}),
    parentElement: nearby && {nextElementSibling: description(nearby)},
  };
}

test("length bounds recognize the nearby 8–16 character hint", () => {
  const {min, max} = passwordLengthBounds(passwordField({nearby: "Contains 8 - 16 characters"}));
  assert.equal(min, 8);
  assert.equal(max, 16);
});

test("length bounds combine field attributes, passwordrules and descriptions across both fields", () => {
  const {min, max} = passwordLengthBounds(
    passwordField({minLength: 9, maxLength: 24, rules: "minlength: 10; maxlength: 20; required: upper;"}),
    passwordField({maxLength: 18, hint: "Maximum 16 characters"}),
  );
  assert.equal(min, 10);
  assert.equal(max, 16);
});

test("length bounds ignore unrelated text and malformed ranges", () => {
  const {min, max} = passwordLengthBounds(passwordField({
    hint: "Use 2 special characters and 3 digits.", nearby: "Contains 16 - 8 characters",
  }));
  assert.equal(min, 1);
  assert.equal(max, null);
});

test("length bounds recognize a minimum from the field's linked hint", () => {
  const {min, max} = passwordLengthBounds(passwordField({hint: "At least 10 characters."}));
  assert.equal(min, 10);
  assert.equal(max, null);
});

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

test("an email placeholder identifies a username-only step", () => {
  const email = input({placeholder: "Enter your email"});
  assert.equal(loginTargets([email]).user, email);
});

test("search boxes are never the username", () => {
  const search = input({type: "search"}, form), user = input({autocomplete: "username"}, form);
  assert.equal(loginTargets([search, user, input({type: "password"}, form)]).user, user);
});

test("API-key fields are not login passwords", () => {
  const key = input({type: "password", name: "api_key"}, form), password = input({type: "password"}, form);
  assert.equal(loginTargets([key, password]).password, password);
});

test("an explicitly selected access token receives the password only", () => {
  const token = input({type: "text", label: "Operator access token"}, form);
  assert.equal(loginTargets([token]).password, undefined);
  const found = loginTargets([token], token);
  assert.equal(found.password, token);
  assert.equal(found.user, undefined);
  assert.equal(found.otp, undefined);
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

test("a set-password step fills its new-password fields", () => {
  const fresh = input({type: "password", name: "password-new", autocomplete: "new-password"}, form);
  const confirm = input({type: "password", name: "password-confirm", autocomplete: "new-password"}, form);
  const found = loginTargets([fresh, confirm, input({type: "checkbox", name: "logout-sessions"}, form)]);
  assert.equal(found.password, undefined);
  assert.deepEqual([...found.newPasswords], [fresh, confirm]);
});

test("a change-password form fills only the current password", () => {
  const current = input({type: "password", autocomplete: "current-password"}, form);
  const found = loginTargets([current, input({type: "password", autocomplete: "new-password"}, form), input({type: "password", autocomplete: "new-password"}, form)]);
  assert.equal(found.password, current);
  assert.equal(found.newPasswords.length, 0);
});

// A visible, editable password input as confirmationField sees it.
function passwordInput(attrs = {}, form = null) {
  return Object.assign(Object.create(HTMLInputElement.prototype), input({type: "password", ...attrs}, form),
    {value: attrs.value ?? "", isConnected: true, matches: () => false, getClientRects: () => [{}]});
}
function formOf(...build) {
  const f = {elements: []};
  f.elements = build.map(make => make(f));
  return f;
}

test("a generated password also goes into the repeat field after it", () => {
  const f = formOf(form => passwordInput({name: "password"}, form), form => passwordInput({placeholder: "Passwort bestätigen"}, form));
  assert.equal(confirmationField(f.elements[0]), f.elements[1]);
});

test("paired new-password fields work without a form element", () => {
  const first = passwordInput({autocomplete: "new-password"});
  const repeat = passwordInput({autocomplete: "new-password"});
  first.getRootNode = () => ({querySelectorAll: () => [first, repeat]});
  assert.equal(confirmationField(first), repeat);
});

test("a form of just two password fields pairs them without hints", () => {
  const f = formOf(form => passwordInput({name: "a"}, form), form => passwordInput({name: "b"}, form));
  assert.equal(confirmationField(f.elements[0]), f.elements[1]);
});

test("a filled, a current or an unrelated next password field is left alone", () => {
  const filled = formOf(form => passwordInput({}, form), form => passwordInput({name: "confirm", value: "x"}, form));
  assert.equal(confirmationField(filled.elements[0]), null);
  const current = formOf(form => passwordInput({autocomplete: "current-password"}, form), form => passwordInput({name: "confirm"}, form));
  assert.equal(confirmationField(current.elements[0]), null);
  const three = formOf(form => passwordInput({}, form), form => passwordInput({name: "pin"}, form), form => passwordInput({}, form));
  assert.equal(confirmationField(three.elements[0]), null);
  const last = formOf(form => passwordInput({}, form), form => passwordInput({name: "confirm"}, form));
  assert.equal(confirmationField(last.elements[1]), null);
});
