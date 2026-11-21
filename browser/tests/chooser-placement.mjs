import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../extension/content.js", import.meta.url), "utf8");
const placement = source.slice(source.indexOf("function rbwChooserPosition"), source.indexOf("function rbwVerifyFrame"));
const context = vm.createContext({}); vm.runInContext(placement, context);
const rect = (left, top, right, bottom, focused = false) => ({left, top, right, bottom, focused});
const intersects = (point, size, r) => point.x < r.right && point.x + size.width > r.left && point.y < r.bottom && point.y + size.height > r.top;

test("registration chooser avoids fields and the submit button", () => {
  const controls = [rect(70, 100, 870, 134), rect(70, 177, 870, 211), rect(70, 253, 870, 288, true), rect(70, 320, 210, 360)];
  const size = {width: 380, height: 250};
  const point = context.rbwChooserPosition(controls[2], size, {width: 940, height: 597}, controls);
  assert.ok(controls.every(control => !intersects(point, size, control)), JSON.stringify(point));
});
test("a narrow screen keeps the active input clear when space is limited", () => {
  const controls = [rect(16, 50, 344, 90), rect(16, 130, 344, 170, true), rect(16, 205, 160, 245)];
  const size = {width: 344, height: 180};
  const point = context.rbwChooserPosition(controls[1], size, {width: 360, height: 500}, controls);
  assert.ok(!intersects(point, size, controls[1]));
  assert.ok(!intersects(point, size, controls[2]));
  assert.ok(point.x >= 8 && point.y >= 8 && point.x + size.width <= 352 && point.y + size.height <= 492);
});
test("when no clear position exists, avoids the focused field first", () => {
  const controls = [rect(8, 80, 312, 120, true), rect(8, 135, 312, 240)];
  const size = {width: 304, height: 130};
  const point = context.rbwChooserPosition(controls[0], size, {width: 320, height: 260}, controls);
  assert.ok(!intersects(point, size, controls[0]));
});
