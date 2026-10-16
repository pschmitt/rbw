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
