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
import time

# Extension frames are not exposed to the drivers, so tests find the visible rbw
# host in the page and click at fixed offsets inside it.
HOST_JS = """(save) => { const el = [...document.documentElement.children].filter(e => e.tagName === 'DIV' && (e.getAttribute('style') || '').includes('2147483647') && (e.getAttribute('style') || '').includes('inset') === !!save).pop();
  if (!el || getComputedStyle(el).visibility !== 'visible') return null; const r = el.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; }"""
OFFSETS = {"login": (60, 102), "card": (60, 102), "search": (60, 40), "result": (60, 130), "save": (70, 102)}
SHADOW_DECOY = "() => { const h = document.createElement('span'); document.documentElement.append(h); const r = h.attachShadow({ mode: 'closed' }); const d = document.createElement('div'); d.style.cssText = 'position:fixed;inset:0;z-index:2147483647;pointer-events:none;background:#fff'; r.append(d); }"


class ChromiumPage:
    def __init__(self, extension, profile):
        from playwright.sync_api import sync_playwright
        self.playwright = sync_playwright().start()
        self.context = self.playwright.chromium.launch_persistent_context(profile, channel="chromium", headless=True, args=[f"--disable-extensions-except={extension}", f"--load-extension={extension}"])
        self.page = self.context.new_page()

    def goto(self, url): self.page.goto(url); self.page.wait_for_load_state("load")
    def evaluate(self, js, arg=None): return self.page.evaluate(js, arg)
    def click_point(self, x, y): self.page.mouse.click(x, y)
    def click(self, selector): self.page.click(selector)
    def fill(self, selector, value): self.page.fill(selector, value)
    def key(self, key, selector=None): (self.page.press(selector, key) if selector else self.page.keyboard.press(key))
    def type_text(self, text): self.page.keyboard.type(text, delay=20)
    def screenshot(self, path, rect): self.page.screenshot(path=path, clip={"x": rect["x"] - 8, "y": rect["y"] - 8, "width": rect["w"] + 16, "height": rect["h"] + 16})
    def close(self): self.context.close(); self.playwright.stop()


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
    def type_text(self, text):
        from selenium.webdriver.common.action_chains import ActionChains
        ActionChains(self.driver).send_keys(text).perform()
    def close(self): self.driver.quit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("browser", choices=["chromium", "firefox"])
    parser.add_argument("extension"); parser.add_argument("url"); parser.add_argument("profile")
    args = parser.parse_args()
    page = (ChromiumPage if args.browser == "chromium" else FirefoxPage)(args.extension, args.profile)
    results = []

    def check(name, ok, detail=""):
        results.append(ok); print(f"{'PASS' if ok else 'FAIL'} {name} {detail}", flush=True)

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
        page.click_point(rect["x"] + dx, rect["y"] + dy); time.sleep(1.5)

    def fresh(attack=""):
        page.goto(args.url); time.sleep(0.5)
        if attack: page.evaluate(f"setAttack({attack!r})")

    def values(): return page.evaluate("values()")

    def shoot(name, rect):
        if os.environ.get("RBW_E2E_SCREENSHOTS"): time.sleep(0.6); page.screenshot(os.path.join(os.environ["RBW_E2E_SCREENSHOTS"], f"{args.browser}-{name}.png"), rect)

    try:
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

        for name, decoy in [("pointer-events:none decoy", "() => { document.documentElement.append(decoy); decoy.style.display = 'block'; }"), ("closed-shadow pointer-events:none decoy", SHADOW_DECOY)]:
            fresh(); page.click("#pass")
            if host():
                time.sleep(0.8); page.evaluate(decoy); click_in("login", settle=0.3)
                check(f"{name} rejected", values()["pass"] == "")

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
        if opened: shoot("save-new", opened)
        check("save prompt opens for a new login", opened is not None)
        if opened:
            click_in("save"); check("save prompt saves a new login", logged("save:"))

        submit("alice", "pw-from-rbw")
        check("no save prompt for an already stored login", host("save", timeout=3.0) is None)

        submit("Alice", "changed-password"); opened = host("save")
        if opened: shoot("save-update", opened)
        check("update prompt for a stored username with a new password", opened is not None)
        if opened:
            click_in("save"); check("update prompt updates the stored login", logged("save:login-1"))
    finally:
        page.close()
    print(f"{sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
