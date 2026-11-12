import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../extension/top-layer.js", import.meta.url), "utf8");

// A tiny DOM: enough tree, <dialog open>, popover state and observers for the
// placement logic. `observers` lets a test deliver the mutations a browser would.
class Node {
  constructor(name) { this.localName = name; this.parentNode = null; this.children = []; this.attrs = new Map(); this.popoverOpen = false; this.calls = []; }
  get isConnected() { let n = this; while (n.parentNode) n = n.parentNode; return n === this.doc.documentElement; }
  append(child) { child.parentNode?.children.splice(child.parentNode.children.indexOf(child), 1); child.parentNode = this; this.children.push(child); if (!child.isConnected) child.popoverOpen = false; else if (child.popoverOpen && child.moved !== false) child.popoverOpen = false; }
  remove() { this.parentNode?.children.splice(this.parentNode.children.indexOf(this), 1); this.parentNode = null; this.popoverOpen = false; }
  setAttribute(k, v) { this.attrs.set(k, v); }
  hasAttribute(k) { return this.attrs.has(k); }
  matches(sel) { if (sel === ":popover-open") return this.popoverOpen; throw new Error(sel); }
  showPopover() { if (!this.isConnected) throw new Error("not connected"); if (this.popoverOpen) throw new Error("already open"); this.popoverOpen = true; this.calls.push("show"); }
  hidePopover() { this.popoverOpen = false; this.calls.push("hide"); }
}

function setup({popover = true} = {}) {
  const documentElement = new Node("html");
  const listeners = {}, observers = [];
  const doc = {
    documentElement, activeElement: null,
    all: () => { const out = []; const walk = n => { for (const c of n.children) { out.push(c); walk(c); } }; walk(documentElement); return out; },
    querySelectorAll(sel) {
      const dialogs = this.all().filter(n => n.localName === "dialog" && n.isConnected);
      if (sel === "dialog:modal") return dialogs.filter(d => d.hasAttribute("open") && d.modal);
      if (sel === "dialog") return dialogs;
      throw new Error(sel);
    },
    addEventListener(type, fn) { (listeners[type] ||= []).push(fn); },
  };
  Node.prototype.doc = doc;
  const HTMLElement = function () {};
  if (popover) { HTMLElement.prototype.showPopover = () => {}; }
  class MutationObserver { constructor(cb) { this.cb = cb; this.active = false; observers.push(this); } observe() { this.active = true; } disconnect() { this.active = false; } }
  const context = vm.createContext({document: doc, HTMLElement, MutationObserver, globalThis: null});
  context.globalThis = context;
  vm.runInContext(source, context);
  const dialog = (open = true, modal = true) => { const d = new Node("dialog"); d.modal = modal; documentElement.append(d); if (open) d.setAttribute("open", ""); return d; };
  const host = () => new Node("div");
  const notify = (target, type = "open") => observers[1].cb([{target, type: "attributes", attributeName: type}]);
  const tree = () => observers[0].cb([]);
  return {doc, rbw: context.rbwTopLayer, dialog, host, notify, tree, listeners, observers};
}

test("without a dialog the host goes under <html> as a manual popover", () => {
  const t = setup(), h = t.host();
  t.rbw.mount(h);
  assert.equal(h.parentNode, t.doc.documentElement);
  assert.equal(h.attrs.get("popover"), "manual");
  assert.equal(h.popoverOpen, true);
});

test("with one modal dialog the host is mounted inside it, and moves back when it closes", () => {
  const t = setup(), d = t.dialog(), h = t.host();
  t.rbw.mount(h);
  assert.equal(h.parentNode, d);
  assert.equal(h.popoverOpen, true);
  d.attrs.delete("open"); t.notify(d);
  assert.equal(h.parentNode, t.doc.documentElement);
  assert.equal(h.popoverOpen, true);
});

test("a dialog opened after the host pulls it inside (not inert)", () => {
  const t = setup(), h = t.host();
  t.rbw.mount(h);
  const d = t.dialog(false); d.setAttribute("open", ""); t.notify(d);
  assert.equal(h.parentNode, d);
  assert.equal(h.popoverOpen, true);
});

test("nested modal dialogs: the one opened last wins, and closing it falls back", () => {
  const t = setup(), outer = t.dialog(false), inner = t.dialog(false), h = t.host();
  outer.setAttribute("open", ""); t.notify(outer);
  t.rbw.mount(h);
  assert.equal(h.parentNode, outer);
  inner.setAttribute("open", ""); t.notify(inner);
  assert.equal(h.parentNode, inner);
  inner.attrs.delete("open"); t.notify(inner);
  assert.equal(h.parentNode, outer);
  outer.attrs.delete("open"); t.notify(outer);
  assert.equal(h.parentNode, t.doc.documentElement);
});

test("non-modal open dialogs are ignored", () => {
  const t = setup(); t.dialog(true, false);
  const h = t.host(); t.rbw.mount(h);
  assert.equal(h.parentNode, t.doc.documentElement);
});

test("a dialog removed with the host inside brings the host back", () => {
  const t = setup(), d = t.dialog(), h = t.host();
  t.rbw.mount(h);
  d.remove();
  assert.equal(h.isConnected, false);
  t.tree();
  assert.equal(h.parentNode, t.doc.documentElement);
  assert.equal(h.isConnected, true);
});

test("a host removed by its owner is forgotten, not resurrected", () => {
  const t = setup(), h = t.host();
  t.rbw.mount(h); h.remove(); t.tree();
  assert.equal(h.parentNode, null);
  assert.equal(t.observers[0].active, false);
});

test("another popover opening re-stacks rbw above it; its own toggle does not loop", () => {
  const t = setup(), h = t.host();
  t.rbw.mount(h);
  const before = h.calls.length;
  t.listeners.toggle[0]({newState: "open", target: new Node("div")});
  assert.deepEqual(h.calls.slice(before), ["hide", "show"]);
  const mid = h.calls.length;
  t.listeners.toggle[0]({newState: "open", target: h});
  assert.equal(h.calls.length, mid);
});

test("Escape (cancel) on the focused rbw host does not close the page's dialog", () => {
  const t = setup(), h = t.host();
  t.rbw.mount(h);
  let prevented = 0; const event = {preventDefault: () => prevented++};
  t.doc.activeElement = h; t.listeners.cancel[0](event);
  assert.equal(prevented, 1);
  t.doc.activeElement = new Node("input"); t.listeners.cancel[0](event);
  assert.equal(prevented, 1);
});

test("without the Popover API hosts are still placed (inside the dialog) and keep their z-index", () => {
  const t = setup({popover: false}), d = t.dialog(), h = t.host();
  t.rbw.mount(h);
  assert.equal(h.parentNode, d);
  assert.equal(h.attrs.has("popover"), false);
  assert.match(t.rbw.RESET, /inset:auto!important/);
});
