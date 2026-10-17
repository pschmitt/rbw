/* This function is serialized into an isolated world by scripting.executeScript. */
function fillPage(expectedUrl, data) {
  if (location.href !== expectedUrl) throw new Error("Page changed. Choose Fill again.");
  const all = root => [...root.querySelectorAll("input,textarea,select"), ...[...root.querySelectorAll("*")].filter(el => el.shadowRoot).flatMap(el => all(el.shadowRoot))];
  const fields = all(document).filter(el => !el.disabled && !el.readOnly && el.getClientRects().length && getComputedStyle(el).visibility !== "hidden" && el.type !== "hidden");
  const setter = (el, value) => {
    if (value == null || !el) return;
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
    const users = fields.filter(el => (!password?.form || el.form === password.form) && ["text", "email", "tel"].includes(el.type));
    const user = users.find(el => el.autocomplete === "username") || users.find(el => el.type === "email") || users.at(-1);
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
  return count;
}


/* Render a transient notice without publishing vault metadata in the page DOM. */
function showFillNotice(expectedUrl, notice) {
  if (location.href !== expectedUrl || window !== window.top) return;
  document.getElementById("rbw-fill-notice")?.remove();
  const host = document.createElement("div"); host.id = "rbw-fill-notice";
  host.style.cssText = "all:initial!important;position:fixed!important;inset:16px 16px auto auto!important;z-index:2147483647!important;pointer-events:none!important;max-width:calc(100vw - 32px)!important;";
  const shadow = host.attachShadow({ mode: "closed" });
  const sheet = new CSSStyleSheet();
  const border = notice.error ? "#efa9b9" : "#a7bfea";
  const bg = notice.error ? "#251821" : "#1b263d";
  sheet.replaceSync(`:host{all:initial}.notice{box-sizing:border-box;display:flex;align-items:start;gap:12px;width:340px;max-width:calc(100vw - 32px);padding:12px 14px;border:1px solid ${border};border-radius:12px;background:${bg};color:#f1f4fc;box-shadow:0 6px 24px #0006;font:14px/1.4 system-ui,sans-serif;pointer-events:none}.text{min-width:0;flex:1}strong,small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}small{color:#a0b4d6;font-size:12px;margin-top:2px}button{flex-shrink:0;pointer-events:auto;cursor:pointer;border:0;border-radius:6px;background:transparent;color:#a0b4d6;font:20px/1 system-ui;padding:4px}button:hover,button:focus-visible{background:#253653;color:#f1f4fc;outline:1px solid #a7bfea}`);
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
  const closePath = document.createElementNS(closeIcon.namespaceURI, "path"); closePath.setAttribute("d", "M18 6 6 18M6 6l12 12"); closePath.setAttribute("stroke", "currentColor"); closePath.setAttribute("stroke-width", "2"); closeIcon.append(closePath); close.append(closeIcon); close.setAttribute("aria-label", "Dismiss autofill notification");
  let timer;
  const dismiss = () => { clearTimeout(timer); host.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = event => { if (event.key === "Escape") dismiss(); };
  close.addEventListener("click", dismiss); document.addEventListener("keydown", onKey);
  box.append(text, close); shadow.append(box); document.documentElement.append(host);
  timer = setTimeout(dismiss, 4500);
}
