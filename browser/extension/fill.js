/* This function is serialized into an isolated world by scripting.executeScript. */
function fillPage(expectedUrl, data, fillToken) {
  if (location.href !== expectedUrl) throw new Error("Page changed. Choose Fill again.");
  const all = root => [...root.querySelectorAll("input,textarea,select"), ...[...root.querySelectorAll("*")].filter(el => el.shadowRoot).flatMap(el => all(el.shadowRoot))];
  const fields = all(document).filter(el => !el.disabled && !el.readOnly && el.getClientRects().length && getComputedStyle(el).visibility !== "hidden" && el.type !== "hidden");
  const previous = new Map();
  const read = el => ({ value: el.value, checked: el.checked });
  const setter = (el, value) => {
    if (value == null || !el) return;
    if (!previous.has(el)) previous.set(el, { before: read(el) });
    const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    if (el instanceof HTMLInputElement && el.type === "checkbox") Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "checked").set.call(el, value === true || value === "true");
    else if (el instanceof HTMLSelectElement) {
      const option = [...el.options].find(o => o.value.toLowerCase() === String(value).toLowerCase() || o.textContent.trim().toLowerCase() === String(value).toLowerCase());
      if (option) Object.getOwnPropertyDescriptor(proto, "value").set.call(el, option.value);
    } else Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  let count = 0;
  const put = (el, value) => { if (el && value != null) { setter(el, value); count++; } };
  if (data.type === "login") {
    const passwords = fields.filter(el => el.type === "password" && el.autocomplete !== "new-password");
    if (passwords.length > 1) throw new Error("Several password fields found. Select a login form.");
    const password = passwords[0];
    const isSearch = el => el.type === "search" || el.closest('[role="search"],form[action*="search"]') || /search|(^|[\s_-])q($|[\s_-])/i.test([el.id, el.name, el.autocomplete, el.getAttribute("aria-label"), el.placeholder].filter(Boolean).join(" "));
    const users = fields.filter(el => (!password?.form || el.form === password.form) && ["text", "email", "tel"].includes(el.type) && !isSearch(el));
    const recognizable = el => el.autocomplete?.split(/\s+/).includes("username") || el.type === "email" || /(^|[\s_-])(user(name)?|email|login|identifier|account)([\s_-]|$)/i.test([el.id, el.name, el.getAttribute("aria-label")].filter(Boolean).join(" "));
    // Generic text fields are only eligible inside the same real login form.
    // Username-only flows require explicit login semantics; never guess a search box.
    const usernameOnly = el => el.autocomplete?.split(/\s+/).includes("username") || /username|identifier|login/i.test([el.id, el.name].join(" ")) || (recognizable(el) && /login|sign.?in|auth/i.test([el.form?.id, el.form?.name, el.form?.getAttribute("action"), el.form?.getAttribute("aria-label")].filter(Boolean).join(" ")));
    const user = password ? users.find(recognizable) || (password.form ? users.filter(el => el.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING).at(-1) : null) : users.find(usernameOnly);
    put(user, data.username); put(password, data.password);
    if (password) password.focus(); else user?.focus();
  } else {
    const names = data.type === "card" ? { "cc-name": "cardholder_name", "cc-number": "number", "cc-exp-month": "exp_month", "cc-exp-year": "exp_year", "cc-csc": "code", "cc-type": "brand" } : { "given-name": "first_name", "additional-name": "middle_name", "family-name": "last_name", "address-line1": "address1", "address-line2": "address2", "address-line3": "address3", "address-level2": "city", "address-level1": "state", "postal-code": "postal_code", "country": "country", "country-name": "country", "tel": "phone", "email": "email", "username": "username", "honorific-prefix": "title" };
    for (const el of fields) {
      const name = el.autocomplete?.split(/\s+/).at(-1);
      if (names[name]) put(el, data[names[name]]);
      if (name === "cc-exp" && data.exp_month && data.exp_year) put(el, `${data.exp_month.padStart(2, "0")}/${data.exp_year.slice(-2)}`);
      if (name === "name") put(el, [data.first_name, data.middle_name, data.last_name].filter(Boolean).join(" "));
    }
  }
  for (const field of data.custom || []) {
    const el = fields.find(el => el.id === field.name || el.name === field.name);
    if (el) {
      const linked = { 100: "username", 101: "password", 300: "cardholder_name", 301: "exp_month", 302: "exp_year", 303: "code", 304: "brand", 305: "number", 400: "title", 401: "first_name", 402: "middle_name", 403: "last_name", 404: "address1", 405: "address2", 406: "address3", 407: "city", 408: "state", 409: "postal_code", 410: "country", 412: "email", 413: "phone", 414: "ssn", 415: "username", 416: "passport_number", 417: "license_number" };
      const value = field.type === "linked" ? field.value === "418" ? [data.first_name, data.middle_name, data.last_name].filter(Boolean).join(" ") : data[linked[field.value]] : field.value;
      put(el, value);
    }
  }
  if (count) {
    const token = fillToken || crypto.randomUUID();
    for (const [el, state] of previous) state.filled = read(el);
    const undo = { token, restore: () => {
      let restored = 0;
      for (const [el, state] of previous) {
        const current = read(el);
        if (!el.isConnected || current.value !== state.filled.value || current.checked !== state.filled.checked) continue;
        const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        if (el.type === "checkbox") Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "checked").set.call(el, state.before.checked);
        else Object.getOwnPropertyDescriptor(proto, "value").set.call(el, state.before.value);
        el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); restored++;
      }
      previous.clear(); return restored;
    }, clear: () => previous.clear() };
    globalThis.__rbwUndoFill?.clear(); globalThis.__rbwUndoFill = undo;
    setTimeout(() => { undo.clear(); if (globalThis.__rbwUndoFill === undo) delete globalThis.__rbwUndoFill; }, 10000);
  }
  return count;
}


/* Same isolated world as fillPage; no form values cross the messaging boundary. */
function undoPageFill(expectedUrl, token, restore) {
  if (location.href !== expectedUrl || globalThis.__rbwUndoFill?.token !== token) return 0;
  const undo = globalThis.__rbwUndoFill; delete globalThis.__rbwUndoFill;
  if (restore) return undo.restore();
  undo.clear(); return 0;
}

/* Render a transient notice without publishing vault metadata in the page DOM. */
function showFillNotice(expectedUrl, notice) {
  if (location.href !== expectedUrl || window !== window.top) return;
  document.getElementById("rbw-fill-notice")?.remove();
  const host = document.createElement("div"); host.id = "rbw-fill-notice";
  host.style.cssText = "all:initial!important;position:fixed!important;inset:16px 16px auto auto!important;z-index:2147483647!important;pointer-events:none!important;max-width:calc(100vw - 32px)!important;";
  const shadow = host.attachShadow({ mode: "closed" });
  const sheet = new CSSStyleSheet();
  const border = notice.error ? "#efa9b9" : "#555555";
  const bg = notice.error ? "#302528" : "#282828";
  sheet.replaceSync(`:host{all:initial}.notice{box-sizing:border-box;display:flex;align-items:center;gap:10px;width:360px;max-width:calc(100vw - 32px);padding:10px 12px;border:1px solid ${border};border-radius:12px;background:${bg};color:#efefef;box-shadow:0 6px 24px #0006;font:14px/1.4 system-ui,sans-serif;pointer-events:none}.brand{width:30px;height:30px;object-fit:contain;flex-shrink:0}.text{min-width:0;flex:1}strong,small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}small{color:#adadad;font-size:12px;margin-top:2px}button{flex-shrink:0;pointer-events:auto;cursor:pointer;border:0;border-radius:6px;background:transparent;color:#adadad;width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;padding:0;line-height:1}button svg{width:18px;height:18px;display:block;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}button:hover,button:focus-visible{background:#383838;color:#efefef;outline:1px solid #d0d0d0}.notice{animation:rbw-in 160ms ease-out both}.notice.closing{animation:rbw-out 120ms ease-in both}@keyframes rbw-in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}@keyframes rbw-out{to{opacity:0;transform:translateY(-4px)}}@media(prefers-reduced-motion:reduce){.notice,.notice.closing{animation:none}}`);
  shadow.adoptedStyleSheets = [sheet];
  const box = document.createElement("div"); box.className = "notice"; box.setAttribute("role", "status"); box.setAttribute("aria-live", "polite");
  const text = document.createElement("div"); text.className = "text";
  const title = document.createElement("strong");
  if (notice.title) {
    title.textContent = notice.title;
  } else {
    const cycle = Number.isInteger(notice.position) && Number.isInteger(notice.total) && notice.total > 1 ? ` · (${notice.position}/${notice.total})` : "";
    title.textContent = `rbw · Autofilled${cycle}`;
  }
  const account = document.createElement("small");
  if (notice.message) {
    account.textContent = notice.message;
  } else {
    account.textContent = [String(notice.name || "Item").slice(0, 256), notice.username ? String(notice.username).slice(0, 256) : ""].filter(Boolean).join(" · ");
  }
  account.title = account.textContent;
  text.append(title, account);
  const close = document.createElement("button"); close.type = "button"; const closeIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"); closeIcon.setAttribute("viewBox", "0 0 24 24"); closeIcon.setAttribute("width", "16"); closeIcon.setAttribute("height", "16"); closeIcon.setAttribute("aria-hidden", "true");
  const closePath = document.createElementNS(closeIcon.namespaceURI, "path"); closePath.setAttribute("d", "M18 6 6 18M6 6l12 12"); closePath.setAttribute("stroke", "currentColor"); closePath.setAttribute("stroke-width", "1.8"); closeIcon.append(closePath); close.append(closeIcon); close.setAttribute("aria-label", "Dismiss autofill notification");
  let timer;
  const undo = !notice.error && !notice.title ? notice.undoToken : null;
  const api = globalThis.browser || chrome;
  const clearUndo = () => { if (undo) api.runtime.sendMessage({ action: "dismiss_fill", token: undo }).catch(() => {}); };
  let closing = false;
  const dismiss = () => {
    if (closing) return; closing = true;
    clearTimeout(timer); clearUndo(); document.removeEventListener("keydown", onKey);
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) host.remove();
    else { box.classList.add("closing"); setTimeout(() => host.remove(), 140); }
  };
  const onKey = event => { if (event.key === "Escape") dismiss(); };
  close.addEventListener("click", dismiss); document.addEventListener("keydown", onKey);
  if (notice.icon) { const image = document.createElement("img"); image.className = "brand"; image.alt = "rbw"; image.src = notice.icon; box.append(image); }
  box.append(text);
  if (undo) {
    const undoButton = document.createElement("button"); undoButton.type = "button"; undoButton.setAttribute("aria-label", "Undo autofill"); undoButton.title = "Undo autofill";
    const undoIcon = document.createElementNS(closeIcon.namespaceURI, "svg"); undoIcon.setAttribute("viewBox", "0 0 24 24"); undoIcon.setAttribute("aria-hidden", "true");
    const undoPath = document.createElementNS(closeIcon.namespaceURI, "path"); undoPath.setAttribute("d", "M9 14 4 9l5-5 M4 9h10.5a5.5 5.5 0 0 1 5.5 5.5a5.5 5.5 0 0 1-5.5 5.5H11"); undoIcon.append(undoPath); undoButton.append(undoIcon);
    undoButton.addEventListener("click", async () => {
      undoButton.disabled = true;
      try {
        const response = await api.runtime.sendMessage({ action: "undo_fill", token: undo });
        const restored = response?.result || 0; undoButton.remove();
        title.textContent = restored ? "Autofill undone" : "Fields kept";
        account.textContent = restored ? "Previous field values restored. Later edits were preserved." : "The fields changed or undo expired; your edits were preserved.";
      } catch (_) { title.textContent = "Undo unavailable"; undoButton.remove(); }
      clearTimeout(timer); timer = setTimeout(dismiss, 3000);
    }); box.append(undoButton);
  }
  box.append(close); shadow.append(box); document.documentElement.append(host);
  timer = setTimeout(dismiss, undo ? 8000 : 4500);
}
