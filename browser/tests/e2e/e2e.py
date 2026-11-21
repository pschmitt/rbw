#!/usr/bin/env python3
"""End-to-end checks for the inline autofill UI with real, trusted input.

Loads the unpacked extension (python3 browser/build.py) into Chromium via
Playwright or Firefox via Selenium, talks to stub_host.py instead of a real
vault, and exercises fills, saves and clickjacking attempts. Run it through
run.sh, which isolates HOME and registers the stub native host.
"""
import argparse
import os
import sys
import struct
import time
import zlib

# Extension frames are not exposed to the drivers, so tests find the visible rbw
# host in the page and click at fixed offsets inside it. The save prompt is the
# host pinned to a corner (`inset: 16px ...`); every host's style also starts
# with top-layer.js's reset (`inset: auto`), so a bare "inset" cannot tell them
# apart. The browser re-serializes the style attribute ("inset: 16px"), hence \s*.
HOST_JS = """(save) => { const el = [...document.documentElement.children].filter(e => e.tagName === 'DIV' && (e.getAttribute('style') || '').includes('2147483647') && /inset:\\s*16px/.test(e.getAttribute('style') || '') === !!save).pop();
  if (!el || getComputedStyle(el).visibility !== 'visible') return null; const r = el.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; }"""
# A set-password chooser has a hint line above its rows; "New" sits at their right end.
OFFSETS = {"setpw": (60, 140), "setpw-new": (-30, 140), "login": (60, 102), "card": (60, 102), "search": (60, 40), "result": (60, 130), "save": (70, 102)}
# Page-controlled top-layer decoys, shown after rbw's chooser: a magenta sheet
# over the whole viewport that lets clicks through to whatever is below it.
TOP_DECOY_CSS = "position:fixed;inset:0;width:100vw;height:100vh;max-width:none;max-height:none;margin:0;padding:0;border:0;background:#f0f;pointer-events:none"
TOP_DECOYS = [
    ("page popover decoy", "() => { const d = document.createElement('div'); d.setAttribute('popover', 'manual'); d.style.cssText = '%s'; document.body.append(d); d.showPopover(); }" % TOP_DECOY_CSS),
    ("closed-shadow popover decoy", "() => { const h = document.createElement('span'); document.body.append(h); const r = h.attachShadow({ mode: 'closed' }); const d = document.createElement('div'); d.setAttribute('popover', 'manual'); d.style.cssText = '%s'; r.append(d); d.showPopover(); }" % TOP_DECOY_CSS),
    ("closed-shadow modal dialog decoy", "() => { const h = document.createElement('span'); document.body.append(h); const r = h.attachShadow({ mode: 'closed' }); const d = document.createElement('dialog'); d.style.cssText = '%s'; r.append(d); d.showModal(); }" % TOP_DECOY_CSS),
]
HAS_POPOVER_JS = "() => 'showPopover' in HTMLElement.prototype"
# Whether the chooser is topmost at its click point with every page element made
# hit-testable, as the background does before it accepts a click.
TOPMOST_JS = """() => { const st = document.createElement('style'); st.textContent = '*,*::before,*::after{pointer-events:auto!important}'; document.head.append(st);
  try { const host = [...document.documentElement.children].find(e => e.matches(':popover-open')); if (!host) return false; const r = host.getBoundingClientRect(); return document.elementsFromPoint(r.left + 60, r.top + 102)[0] === host; } finally { st.remove(); } }"""
SHADOW_DECOY = "() => { const h = document.createElement('span'); document.documentElement.append(h); const r = h.attachShadow({ mode: 'closed' }); const d = document.createElement('div'); d.style.cssText = 'position:fixed;inset:0;z-index:2147483647;pointer-events:none;background:#fff'; r.append(d); }"


def png_pixel(png, x, y):
    """The (r, g, b) of pixel x, y of an 8-bit, non-interlaced RGB(A) PNG."""
    pos, idat, width = 8, b"", 0
    while pos < len(png):
        length, kind = struct.unpack(">I4s", png[pos:pos + 8])
        data = png[pos + 8:pos + 8 + length]
        if kind == b"IHDR": width, height, depth, color = struct.unpack(">IIBB", data[:10])
        elif kind == b"IDAT": idat += data
        pos += 12 + length
    channels = {2: 3, 6: 4}[color]
    stride = width * channels
    raw, rows, prev = zlib.decompress(idat), [], bytearray(stride)
    for row in range(y + 1):
        line = raw[row * (stride + 1):(row + 1) * (stride + 1)]
        kind, cur = line[0], bytearray(line[1:])
        for i in range(stride):
            a = cur[i - channels] if i >= channels else 0
            b, c = prev[i], prev[i - channels] if i >= channels else 0
            if kind == 1: cur[i] = (cur[i] + a) & 255
            elif kind == 2: cur[i] = (cur[i] + b) & 255
            elif kind == 3: cur[i] = (cur[i] + (a + b) // 2) & 255
            elif kind == 4:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                cur[i] = (cur[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        prev = cur
    return tuple(prev[x * channels:x * channels + 3])


class ChromiumPage:
    def __init__(self, extension, profile):
        from playwright.sync_api import sync_playwright
        self.playwright = sync_playwright().start()
        self.context = self.playwright.chromium.launch_persistent_context(profile, channel="chromium", headless=True, args=[f"--disable-extensions-except={extension}", f"--load-extension={extension}"])
        self.page = self.context.new_page()

    def goto(self, url): self.page.goto(url); self.page.wait_for_load_state("load")
    def evaluate(self, js, arg=None): return self.page.evaluate(js, arg)
    def click_point(self, x, y): self.page.mouse.click(x, y)
    def png(self): return self.page.screenshot()
    def click(self, selector): self.page.click(selector)
    def fill(self, selector, value): self.page.fill(selector, value)
    def key(self, key, selector=None): (self.page.press(selector, key) if selector else self.page.keyboard.press(key))
    def type_text(self, text): self.page.keyboard.type(text, delay=20)
    def screenshot(self, path, rect): self.page.screenshot(path=path, clip={"x": rect["x"] - 8, "y": rect["y"] - 8, "width": rect["w"] + 16, "height": rect["h"] + 16})
    def close(self): self.context.close(); self.playwright.stop()
    def editor_opened(self):
        end = time.time() + 8
        while time.time() < end:
            for tab in self.context.pages:
                if tab != self.page and "edit=login-new" in tab.url:
                    tab.wait_for_selector("#editor:not([hidden])", timeout=10000)
                    tab.close(); return True
            self.page.wait_for_timeout(200)
        return None
    def multi_select(self):
        worker = self.context.service_workers[0] if self.context.service_workers else self.context.wait_for_event("serviceworker")
        extension_id = worker.url.split("/")[2]
        popup = self.context.new_page()
        try:
            popup.set_viewport_size({"width": 460, "height": 680})
            popup.goto(f"chrome-extension://{extension_id}/popup.html?surface=window&search=logins")
            rows = popup.locator("#items article[data-selection-key]")
            rows.nth(2).wait_for(timeout=15000)
            rows.nth(0).locator(".item-main").click(modifiers=["Shift"])
            rows.nth(2).locator(".item-main").click(modifiers=["Shift"])
            assert popup.locator("#selection-count").inner_text() == "3 selected"
            assert popup.locator("#items article.is-selected").count() == 3
            popup.keyboard.press("Escape")
            assert popup.locator("#selection-bar").is_hidden()
            rows.nth(0).locator(".item-main").click(modifiers=["Shift"])
            rows.nth(2).locator(".item-main").click(modifiers=["Shift"])
            rows.nth(1).locator(".item-main").click()
            assert popup.locator("#selection-count").inner_text() == "2 selected"
            popup.locator("#selection-menu summary").click()
            if os.environ.get("RBW_E2E_SCREENSHOTS"): popup.screenshot(path=os.path.join(os.environ["RBW_E2E_SCREENSHOTS"], "chromium-multi-select.png"))
            popup.locator("#selection-trash").click()
            assert "2 items" in popup.locator("#confirm-dialog-title").inner_text()
            popup.locator(".confirm-dialog button[value=cancel]").click()
            assert popup.locator("#selection-count").inner_text() == "2 selected"
            popup.locator("#selection-menu summary").click()
            popup.locator("#selection-trash").click()
            popup.locator(".confirm-dialog button[value=ok]").click()
            popup.locator("#selection-bar.is-working").wait_for(state="visible", timeout=5000)
            assert "of 2 to trash" in popup.locator("#selection-count").inner_text()
            assert popup.locator("#selection-progress-icon").is_visible()
            assert popup.locator("#selection-bar").bounding_box()["y"] >= popup.locator(".search-row").bounding_box()["y"] + popup.locator(".search-row").bounding_box()["height"] - 1
            if os.environ.get("RBW_E2E_SCREENSHOTS"): popup.screenshot(path=os.path.join(os.environ["RBW_E2E_SCREENSHOTS"], "chromium-trash-progress.png"))
            popup.locator("#selection-bar").wait_for(state="hidden", timeout=15000)
            popup.locator("#message-action").wait_for(state="visible", timeout=5000)
            failed = os.environ.get("RBW_E2E_FAIL_ITEM") == "login-3"
            assert ("Moved 1 of 2 items" if failed else "Moved 2 items to trash") in popup.locator("#message-text").inner_text()
            if failed: assert "Other Login 3" in popup.locator("#message-text").inner_text()
            assert popup.locator("#message-action").inner_text() == "Undo"
            if os.environ.get("RBW_E2E_SCREENSHOTS"): popup.screenshot(path=os.path.join(os.environ["RBW_E2E_SCREENSHOTS"], "chromium-trash-result.png"))
            with open(os.environ["RBW_E2E_LOG"]) as log:
                operations = log.read().split()
            assert "mutate:login-1" in operations and "mutate:login-3" in operations
            assert "mutate:login-2" not in operations
            popup.locator("#message-action").click()
            popup.get_by_text("Restored 1 item from trash." if failed else "Restored 2 items from trash.").wait_for(timeout=15000)
            with open(os.environ["RBW_E2E_LOG"]) as log:
                operations = log.read().split()
            assert "mutation:restore:login-1" in operations
            assert ("mutation:restore:login-3" in operations) != failed
            assert "mutation:restore:login-2" not in operations
            return True
        finally:
            popup.close()


class FirefoxPage:
    def __init__(self, extension, _profile):
        from selenium import webdriver
        options = webdriver.FirefoxOptions(); options.add_argument("-headless")
        options.set_preference("extensions.originControls.grantByDefault", True)
        self.driver = webdriver.Firefox(options=options); self.driver.set_window_size(1280, 900)
        self.driver.install_addon(extension, temporary=True); time.sleep(2)

    def goto(self, url): self.driver.get(url)
    def evaluate(self, js, arg=None):
        return self.driver.execute_script(f"return ({js})(arguments[0]);" if "=>" in js else f"return {js};", arg)
    def click_point(self, x, y):
        from selenium.webdriver.common.actions.action_builder import ActionBuilder
        action = ActionBuilder(self.driver); action.pointer_action.move_to_location(int(x), int(y)).click(); action.perform()
    def click(self, selector): self.driver.find_element("css selector", selector).click()
    def fill(self, selector, value): element = self.driver.find_element("css selector", selector); element.clear(); element.send_keys(value)
    def key(self, key, selector=None):
        from selenium.webdriver.common.action_chains import ActionChains
        from selenium.webdriver.common.keys import Keys
        value = {"Enter": Keys.ENTER, "Escape": Keys.ESCAPE, "ArrowDown": Keys.ARROW_DOWN, "ArrowUp": Keys.ARROW_UP}[key]
        if selector: self.driver.find_element("css selector", selector).send_keys(value)
        else: ActionChains(self.driver).send_keys(value).perform()
    def screenshot(self, path, _rect): self.driver.save_screenshot(path)
    def png(self): return self.driver.get_screenshot_as_png()
    def type_text(self, text):
        from selenium.webdriver.common.action_chains import ActionChains
        ActionChains(self.driver).send_keys(text).perform()
    def close(self): self.driver.quit()
    def editor_opened(self):
        original = self.driver.current_window_handle
        for handle in self.driver.window_handles:
            if handle == original: continue
            self.driver.switch_to.window(handle)
            if "edit=login-new" in self.driver.current_url:
                self.driver.close(); self.driver.switch_to.window(original); return True
        self.driver.switch_to.window(original); return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("browser", choices=["chromium", "firefox"])
    parser.add_argument("extension"); parser.add_argument("url"); parser.add_argument("profile")
    args = parser.parse_args()
    page = (ChromiumPage if args.browser == "chromium" else FirefoxPage)(args.extension, args.profile)
    results = []

    def check(name, ok, detail=""):
        results.append(bool(ok)); print(f"{'PASS' if ok else 'FAIL'} {name} {detail}", flush=True)

    def host(kind="login", timeout=4.0):
        end = time.time() + timeout
        while time.time() < end:
            rect = page.evaluate(HOST_JS, kind == "save")
            if rect and rect["h"] > 40: return rect
            time.sleep(0.1)
        return None

    def click_in(kind, settle=0.8):
        time.sleep(settle)
        rect = page.evaluate(HOST_JS, kind == "save")
        dx, dy = OFFSETS[kind]
        page.click_point(rect["x"] + (dx if dx >= 0 else rect["w"] + dx), rect["y"] + dy); time.sleep(1.5)

    def fresh(attack=""):
        page.goto(args.url); time.sleep(0.5)
        if attack: page.evaluate(f"setAttack({attack!r})")

    def values(): return page.evaluate("values()")

    def shoot(name, rect):
        if os.environ.get("RBW_E2E_SCREENSHOTS"): time.sleep(0.6); page.screenshot(os.path.join(os.environ["RBW_E2E_SCREENSHOTS"], f"{args.browser}-{name}.png"), rect)

    try:
        if os.environ.get("RBW_E2E_ONLY_SELECTION") and args.browser == "chromium":
            try: check("select a range and move selected items to trash", page.multi_select())
            except Exception as error: check("select a range and move selected items to trash", False, str(error))
            sys.exit(0 if all(results) else 1)
        fresh(); page.click("#pass"); opened = host()
        if opened is None:
            # The first page load can beat the extension's service worker
            # start in Chromium; try once more now that it is up.
            fresh(); page.click("#pass"); opened = host(timeout=8.0)
        check("login chooser opens in extension frame", opened is not None)
        if opened: shoot("chooser", opened)
        if opened:
            click_in("login"); v = values()
            check("login fill via frame", v["pass"] == "pw-from-rbw" and v["user"] == "alice", str(v))

        for field, offset in [("username", -80), ("password", -48), ("totp", -16)]:
            fresh(); page.click("#pass"); opened = host()
            if opened:
                time.sleep(0.8)
                page.click_point(opened["x"] + opened["w"] + offset, opened["y"] + 102); time.sleep(1)
                with open(os.environ["RBW_E2E_LOG"]) as log:
                    check(f"copy {field} reaches native host", f"copy-field:{field}" in log.read().split())
            else: check(f"copy {field} chooser opens", False)

        fresh(); page.click("#pass"); opened = host()
        if opened:
            click_in("search"); page.type_text("Test Login"); time.sleep(1.2)
            shoot("login-search", page.evaluate(HOST_JS, False))
            click_in("result"); v = values()
            check("login search finds and fills a site login", v["pass"] == "pw-from-rbw" and v["user"] == "alice", str(v))

        fresh(); page.click("#pass")
        if host():
            click_in("search"); page.type_text("Other Login 3"); time.sleep(1.2)
            page.key("ArrowDown"); page.key("Enter"); time.sleep(1.5)
            check("arrow keys and Enter fill the highlighted login", values()["pass"] == "pw-from-rbw")

        fresh(); page.click("#pass")
        if host():
            click_in("login", settle=0)
            check("click within 500 ms is ignored", values()["pass"] == "")
            click_in("login", settle=0.3)
            check("second, settled click fills", values()["pass"] == "pw-from-rbw")

        for name, css in [("html opacity", "html{opacity:.3}"), ("html scale", "html{transform:scale(.6);transform-origin:0 0}"), ("html filter", "html{filter:opacity(.2)}"), ("html opacity .9", "html{opacity:.9}")]:
            fresh(css); page.click("#pass")
            if host(): click_in("login"); check(f"{name}: clickjack rejected", values()["pass"] == "")
            else: check(f"{name}: chooser not shown", True)

        fresh("html{transform:translate(0,0)}"); page.click("#pass")
        if host():
            click_in("login"); check("identity transform permits filling", values()["pass"] == "pw-from-rbw")
        else: check("identity transform permits filling", False, "chooser not shown")

        for name, decoy in [("pointer-events:none decoy", "() => { document.documentElement.append(decoy); decoy.style.display = 'block'; }"), ("closed-shadow pointer-events:none decoy", SHADOW_DECOY)]:
            fresh(); page.click("#pass")
            if host():
                time.sleep(0.8); page.evaluate(decoy)
                if page.evaluate(HAS_POPOVER_JS):
                    # The chooser is a popover in the top layer: no page element,
                    # however late or high its z-index, can be painted over it.
                    check(f"{name} cannot cover the chooser", page.evaluate(TOPMOST_JS))
                else:
                    click_in("login", settle=0.3)
                    check(f"{name} rejected", values()["pass"] == "")

        # A page can put its own elements into the top layer too. A click may
        # only fill when the user could see the chooser at the click point:
        # sample the screenshot there right before clicking.
        if page.evaluate(HAS_POPOVER_JS):
            for name, decoy in TOP_DECOYS:
                fresh(); page.click("#pass")
                rect = host()
                if not rect:
                    check(f"{name}: chooser opens", False); continue
                # Where the user would click: the login row, as placed before the decoy.
                dx, dy = OFFSETS["login"]
                time.sleep(0.8); page.evaluate(decoy); time.sleep(0.6)
                pixel = png_pixel(page.png(), int(rect["x"] + dx), int(rect["y"] + dy))
                covered = pixel[0] > 200 and pixel[1] < 60 and pixel[2] > 200
                page.click_point(rect["x"] + dx, rect["y"] + dy); time.sleep(1.5)
                filled = values()["pass"] != ""
                check(f"{name}: no fill through a covered chooser", not (covered and filled), f"covered={covered} filled={filled} pixel={pixel}")

        fresh("html>div:last-of-type{opacity:0!important;visibility:hidden!important}"); page.click("#pass")
        check("page !important restyle cannot hide the host", host() is not None)

        fresh(); page.evaluate("() => ccnum.focus()")
        check("card chooser not opened by script focus", host(timeout=1.5) is None)

        fresh(); page.click("#ccnum"); opened = host()
        check("card chooser opens on click", opened is not None)
        if opened:
            click_in("card"); v = values()
            check("card fill via frame", v["ccnum"] == "4111111111111111" and v["ccname"] == "Alice Test", str(v))

        fresh(); page.click("#ccnum")
        if host():
            click_in("search"); page.type_text("Visa"); time.sleep(1.2)
            page.key("ArrowDown"); page.key("Enter"); time.sleep(1.5)
            check("arrow keys and Enter fill the highlighted card", values()["ccnum"] == "4111111111111111")

        def submit(user, password):
            fresh(); page.fill("#user", user); page.fill("#pass", password); page.key("Escape"); page.key("Enter", "#pass")

        def logged(entry):
            with open(os.environ["RBW_E2E_LOG"]) as log: return entry in log.read().split()

        submit("bob", "hunter2"); opened = host("save")
        if opened:
            page.evaluate(TOP_DECOYS[2][1])
            click_in("save")
            check("covered save prompt does not write to the vault", not logged("save:"))
        else: check("covered save prompt does not write to the vault", False, "prompt not shown")

        submit("bob", "hunter2"); opened = host("save")
        if opened: shoot("save-new", opened)
        check("save prompt opens for a new login", opened is not None)
        if opened:
            page.goto(args.url + "?redirected"); opened = host("save")
            check("save prompt follows redirect", opened is not None)
            # Click near the bottom of the original button, below the height
            # of the smaller saving state. Verification must use the layout
            # the user actually clicked, not the later progress layout.
            time.sleep(0.8)
            page.click_point(opened["x"] + 70, opened["y"] + opened["h"] - 20); time.sleep(1.5)
            saving = page.evaluate(HOST_JS, True)
            check("save click remains valid after the prompt shrinks", saving is not None and opened["h"] - 20 > saving["h"], str(saving))
            check("saving state replaces the form", saving is not None and saving["h"] < opened["h"] - 10, str(saving))
            time.sleep(2)
            check("save prompt saves a new login", logged("save:"))
            saved = page.evaluate(HOST_JS, True)
            check("save confirmation replaces the form", saved is not None and saved["h"] < opened["h"] - 10, str(saved))
            if saved:
                pixel = png_pixel(page.png(), int(saved["x"] + 27), int(saved["y"] + 66))
                check("save confirmation has a compact green icon", saved["h"] < 140 and pixel[1] > pixel[0] + 15 and pixel[1] > pixel[2] + 5, str(pixel))
                shoot("save-success", saved)
                time.sleep(0.8)
                page.click_point(saved["x"] + saved["w"] - 43, saved["y"] + 68); time.sleep(2)
                editor_opened = page.editor_opened()
                check("Edit opens the saved login", editor_opened and logged("detail:login-new"), str(editor_opened))
            page.evaluate("() => history.back()"); time.sleep(2)
            check("back navigation does not restore a resolved save prompt", page.evaluate(HOST_JS, True) is None)

        submit("alice", "pw-from-rbw")
        check("no save prompt for an already stored login", host("save", timeout=3.0) is None)

        submit("Alice", "changed-password"); opened = host("save")
        if opened: shoot("save-update", opened)
        check("update prompt for a stored username with a new password", opened is not None)
        if opened:
            click_in("save"); check("update prompt updates the stored login", logged("save:login-1"))

        # The first host was left over from an "upgrade" (older than the
        # extension): the extension started a fresh one and used that.
        with open(os.environ["RBW_E2E_LOG"]) as log:
            spawns = [line.split(":", 1)[1] for line in log.read().split() if line.startswith("spawn:")]
        check("an outdated native host is replaced by a fresh one", spawns[:2] == ["0.0.1", "999.0.0"], str(spawns))

        # A set-password step (Keycloak's UPDATE_PASSWORD): only new-password fields.
        fresh(); page.click("#newpw"); opened = host()
        check("set-password chooser opens", opened is not None)
        if opened:
            shoot("set-password", opened)
            click_in("setpw"); v = values()
            check("set-password fill puts the stored password in both fields", v["newpw"] == v["confirmpw"] == "pw-from-rbw" and v["pass"] == "", str(v))
        fresh(); page.click("#newpw")
        if host():
            click_in("setpw-new"); time.sleep(1.0); v = values()
            check("New generates, saves, then fills both fields", v["newpw"] == v["confirmpw"] == "generated-pw" and logged("generate:") and logged("save:login-1"), str(v))
        if args.browser == "chromium":
            try: check("select a range and move selected items to trash", page.multi_select() and logged("mutate:login-1") and logged("mutate:login-3"))
            except Exception as error: check("select a range and move selected items to trash", False, str(error))
    finally:
        page.close()
    print(f"{sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
