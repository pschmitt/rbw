/* This function is serialized into an isolated world by scripting.executeScript. */
async function fillPage(expectedUrl, data, fillToken, options = {}) {
  if (location.href !== expectedUrl) throw new Error("Page changed. Choose Fill again.");
  const speedFactor = options.animationSpeed === "slow" ? 0.65 : options.animationSpeed === "fast" ? 1.5 : 1;
  const all = root => [...root.querySelectorAll("input,textarea,select"), ...[...root.querySelectorAll("*")].filter(el => el.shadowRoot).flatMap(el => all(el.shadowRoot))];
  const parentOf = n => n.parentElement || n.getRootNode().host;
  const isFillable = el => {
    if (el.disabled || el.readOnly || el.type === "hidden") return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 8 || rect.height < 8) return false;
    const doc = document.documentElement;
    if (rect.right + scrollX <= 0 || rect.bottom + scrollY <= 0 || rect.left + scrollX >= Math.max(doc.scrollWidth, innerWidth) || rect.top + scrollY >= Math.max(doc.scrollHeight, innerHeight)) return false;
    if (typeof el.checkVisibility === "function" ? !el.checkVisibility({ opacityProperty: true, visibilityProperty: true }) : getComputedStyle(el).visibility === "hidden") return false;
    let opacity = 1;
    for (let n = el; n; n = parentOf(n)) {
      const style = getComputedStyle(n);
      opacity *= Number(style.opacity || 1);
      if (!(opacity >= 0.1) || style.display === "none" || /inset\(\s*(50|100)%|circle\(\s*0(px|%)?\s*[a-z)]/i.test(style.clipPath)) return false;
    }
    return true;
  };
  const fields = all(document).filter(isFillable);
  const previous = new Map();
  const read = el => ({ value: el.value, checked: el.checked });
  const brandNames = {
    visa: ["visa"],
    mastercard: ["mastercard", "master card", "mc"],
    mc: ["mastercard", "master card", "mc"],
    amex: ["amex", "american express", "americanexpress"],
    americanexpress: ["amex", "american express", "americanexpress"],
    discover: ["discover"]
  };
  const optionNames = value => {
    const normalized = String(value).trim().toLowerCase();
    return brandNames[normalized.replace(/[^a-z]/g, "")] || [normalized];
  };
  // Intermediate animation frames only fire "input"; "change" marks the final
  // value, as with real typing. Some pages (HR WORKS) post to the server on
  // every change and reject overlapping requests.
  const setter = (el, value, field = null, commit = true) => {
    if (value == null || !el) return;
    if (!previous.has(el)) previous.set(el, { before: read(el) });
    const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    if (el instanceof HTMLInputElement && el.type === "checkbox") Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "checked").set.call(el, value === true || value === "true");
    else if (el instanceof HTMLSelectElement) {
      const values = optionNames(value);
      const options = [...el.options];
      let option = options.find(o => values.includes(o.value.trim().toLowerCase()) || values.includes(o.textContent.trim().toLowerCase()));
      if (!option && field === "cc-exp-month") {
        const month = Number.parseInt(String(value), 10);
        if (month >= 1 && month <= 12) {
          const names = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
          option = options.find(o => [o.value, o.textContent].some(label => {
            const normalized = label.trim().toLowerCase();
            return Number.parseInt(normalized, 10) === month || normalized === names[month - 1] || normalized === names[month - 1].slice(0, 3);
          }));
        }
      }
      if (!option && field === "cc-exp-year") {
        const year = String(value).trim();
        option = options.find(o => [o.value, o.textContent].some(label => {
          const candidate = label.trim().match(/(?:19|20|21)\d{2}|\d{2}/)?.[0];
          return candidate === year || (year.length === 2 && candidate?.slice(-2) === year);
        }));
      }
      if (option) Object.getOwnPropertyDescriptor(proto, "value").set.call(el, option.value);
    } else Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    if (commit) el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  // Authenticator-code fields: autocomplete=one-time-code, or a name that says so
  // (signInMFA, ci-otpCode-0, totp, 2fa, ...).
  const isOtpField = el => ["text", "tel", "number", ""].includes(el.type) && !el.autocomplete.split(/\s+/).includes("username") && (el.autocomplete.split(/\s+/).includes("one-time-code") || /(^|[^a-z])(otp|totp|mfa|2fa|tfa|authenticator|one[\s_-]*time|verification[\s_-]*code|auth(entication)?[\s_-]*code)([^a-z]|$)/i.test([el.id, el.name, el.getAttribute("aria-label"), el.placeholder].filter(Boolean).join(" ").replace(/([a-z])([A-Z])/g, "$1 $2")));
  let count = 0;
  let securityCodeFieldPresent = false;
  const assignments = [];
  let scoped = fields;
  const put = (el, value, field = null) => {
    if (el && value != null && (!options.automatic || !el.value)) {
      assignments.push({ el, value, field });
      count++;
    }
  };
  if (data.type === "login" && data.totpOnly) {
    // A 2FA step: only the authenticator code, never the password.
    const otp = fields.find(isOtpField);
    put(otp, data.totpCode); otp?.focus();
  } else if (data.type === "login") {
    // Masked integration credentials are not login passwords, even on a
    // matching site. Include associated labels (Rails often labels API keys).
    const isIntegrationSecret = el => {
      const text = [el.id, el.name, el.placeholder, el.getAttribute("aria-label"),
        ...Array.from(el.labels || [], label => label.textContent),
        ...(el.getAttribute("aria-labelledby") || "").split(/\s+/).filter(Boolean).map(id => document.getElementById(id)?.textContent)]
        .filter(Boolean).join(" ").replace(/([a-z])([A-Z])/g, "$1 $2");
      return /api[\s_-]*key|access[\s_-]*key|token|client[\s_-]*secret|private[\s_-]*key|secret[\s_-]*key/i.test(text);
    };
    const passwords = fields.filter(el => el.type === "password" && !el.autocomplete.split(/\s+/).includes("new-password") && !isIntegrationSecret(el));
    if (passwords.length > 1) throw new Error("Several password fields found. Select a login form.");
    const password = passwords[0];
    const isSearch = el => el.type === "search" || el.closest('[role="search"],form[action*="search"]') || /search|(^|[\s_-])q($|[\s_-])/i.test([el.id, el.name, el.autocomplete, el.getAttribute("aria-label"), el.placeholder].filter(Boolean).join(" "));
    const users = fields.filter(el => (!password?.form || el.form === password.form) && ["text", "email", "tel"].includes(el.type) && !isSearch(el) && !isOtpField(el));
    const recognizable = el => el.autocomplete?.split(/\s+/).includes("username") || el.type === "email" || /(^|[\s_-])(user(name)?|email|login|identifier|account)([\s_-]|$)/i.test([el.id, el.name, el.getAttribute("aria-label")].filter(Boolean).join(" "));
    // Generic text fields are only eligible inside the same real login form.
    // Username-only flows require explicit login semantics; never guess a search box.
    const usernameOnly = el => el.autocomplete?.split(/\s+/).includes("username") || /username|identifier|login/i.test([el.id, el.name].join(" ")) || (recognizable(el) && /login|sign.?in|auth/i.test([el.form?.id, el.form?.name, el.form?.getAttribute("action"), el.form?.getAttribute("aria-label")].filter(Boolean).join(" ")));
    const user = password ? users.find(recognizable) || (password.form ? users.filter(el => el.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING).at(-1) : null) : users.find(usernameOnly);
    scoped = password?.form ? fields.filter(el => el.form === password.form) : fields;
    put(user, data.username); put(password, data.password);
    if (data.totpCode) put(fields.find(isOtpField), data.totpCode);
    if (password) password.focus(); else user?.focus();
  } else {
    const names = data.type === "card" ? { "cc-name": "cardholder_name", "cc-number": "number", "cc-exp-month": "exp_month", "cc-exp-year": "exp_year", "cc-type": "brand" } : { "given-name": "first_name", "additional-name": "middle_name", "family-name": "last_name", "address-line1": "address1", "address-line2": "address2", "address-line3": "address3", "address-level2": "city", "address-level1": "state", "postal-code": "postal_code", "country": "country", "country-name": "country", "tel": "phone", "email": "email", "username": "username", "honorific-prefix": "title" };
    if (data.type === "card" && options.cardSecurityCode === "fill") names["cc-csc"] = "code";
    let focused = document.activeElement;
    while (focused?.shadowRoot?.activeElement) focused = focused.shadowRoot.activeElement;
    if (!fields.includes(focused)) throw new Error("Focus a field in the form you want to fill.");
    const within = (box, n) => { for (; n; n = parentOf(n)) if (n === box) return true; return false; };
    if (focused.form) scoped = fields.filter(el => el.form === focused.form);
    else {
      let box = null;
      for (let n = parentOf(focused); n && n !== document.body && n !== document.documentElement; n = parentOf(n)) {
        if (n.matches?.('fieldset,form,[role="form"]') || fields.filter(el => within(n, el)).length >= 3) { box = n; break; }
      }
      scoped = box ? fields.filter(el => within(box, el)) : [focused];
    }
    const targets = scoped;
    for (const el of targets) {
      const name = (el.getAttribute("autocomplete") || el.autocomplete || "").toLowerCase().split(/\s+/).at(-1);
      const fieldLabel = [el.id, el.name, el.getAttribute("aria-label"), el.getAttribute("placeholder")].filter(Boolean).join(" ");
      const securityCodeField = data.type === "card" && (name === "cc-csc" || /(^|[^a-z])(cvv2?|cvc2?|csc|security[ _-]?code)([^a-z]|$)/i.test(fieldLabel));
      if (securityCodeField) {
        securityCodeFieldPresent = true;
        if (options.cardSecurityCode === "fill") put(el, data.code);
        continue;
      }
      if (names[name]) put(el, data[names[name]], name);
      if (name === "cc-exp" && data.exp_month && data.exp_year) put(el, `${data.exp_month.padStart(2, "0")}/${data.exp_year.slice(-2)}`);
      if (name === "name") put(el, [data.first_name, data.middle_name, data.last_name].filter(Boolean).join(" "));
    }
  }
  const normalize = text => String(text || "").toLowerCase().replace(/[^\p{L}\p{N}]/gu, "");
  const labelText = el => {
    const ids = el.getAttribute("aria-labelledby");
    if (ids) return ids.split(/\s+/).map(id => el.getRootNode().getElementById?.(id)?.textContent).filter(Boolean).join(" ");
    if (el.labels?.length) return [...el.labels].map(label => label.textContent).join(" ");
    // Floating-label widgets often put an unbound <label> next to the input.
    for (let n = parentOf(el); n && n !== document.body; n = parentOf(n)) {
      if (n.querySelectorAll("input,textarea,select").length > 1) break;
      const label = n.querySelector("label");
      if (label) return label.textContent;
    }
    return "";
  };
  const fieldKeys = el => [el.id, el.name, el.getAttribute("autocomplete"), el.getAttribute("aria-label"), el.getAttribute("placeholder"), labelText(el)].map(normalize).filter(Boolean);
  for (const field of data.custom || []) {
    if (field.type === "hidden") continue;
    if (data.type === "card" && field.type === "linked" && field.value === "303" && options.cardSecurityCode !== "fill") continue;
    if (data.type !== "login" && field.type === "linked" && ["414", "416", "417"].includes(String(field.value))) continue;
    const el = scoped.find(el => el.id === field.name || el.name === field.name) || scoped.find(el => !assignments.some(item => item.el === el) && fieldKeys(el).includes(normalize(field.name)));
    if (el) {
      const linked = { 100: "username", 101: "password", 300: "cardholder_name", 301: "exp_month", 302: "exp_year", 303: "code", 304: "brand", 305: "number", 400: "title", 401: "first_name", 402: "middle_name", 403: "last_name", 404: "address1", 405: "address2", 406: "address3", 407: "city", 408: "state", 409: "postal_code", 410: "country", 412: "email", 413: "phone", 414: "ssn", 415: "username", 416: "passport_number", 417: "license_number" };
      const value = field.type === "linked" ? field.value === "418" ? [data.first_name, data.middle_name, data.last_name].filter(Boolean).join(" ") : data[linked[field.value]] : field.value;
      put(el, value);
    }
  }

  const runCrab = (el, finalVal, iconUrl, field) => new Promise(resolve => {
    const rect = el.getBoundingClientRect();
    const isTextControl = el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement && !["checkbox", "radio", "button", "submit", "reset", "hidden", "file"].includes(el.type);
    if (!rect.width || !rect.height || !isTextControl || typeof finalVal !== "string") {
      setter(el, finalVal, field); resolve(); return;
    }
    const crab = document.createElement("div");
    crab.setAttribute("aria-hidden", "true");
    const crabSize = Math.max(18, Math.min(26, rect.height - 4));
    const top = rect.top + (rect.height - crabSize) / 2;
    const startX = rect.left + 4;
    crab.style.cssText = `position:fixed!important;z-index:2147483647!important;pointer-events:none!important;width:${crabSize}px!important;height:${crabSize}px!important;left:${startX}px!important;top:${top}px!important;background:url('${iconUrl}') no-repeat center/contain!important;filter:drop-shadow(0 2px 4px rgba(0,0,0,0.4))!important;transform-origin:center center!important;will-change:transform,opacity!important;`;
    document.documentElement.appendChild(crab);

    const travel = Math.max(28, Math.min(rect.width - crabSize - 8, Math.max(50, finalVal.length * 8)));
    const duration = Math.round(Math.min(260, Math.max(150, finalVal.length * 13)) / speedFactor);
    const startTime = performance.now();

    function frame(now) {
      const elapsed = now - startTime;
      const p = Math.min(1, elapsed / duration);
      const curX = p * travel;
      const angle = Math.sin(p * Math.PI * 10) * 16;
      const bob = Math.abs(Math.sin(p * Math.PI * 10)) * -3;
      crab.style.transform = `translate(${curX}px, ${bob}px) rotate(${angle}deg)`;

      const curLen = Math.min(finalVal.length, Math.max(1, Math.floor(p * finalVal.length)));
      setter(el, finalVal.slice(0, curLen), field, false);

      if (p < 1) {
        requestAnimationFrame(frame);
      } else {
        setter(el, finalVal, field);
        crab.style.transition = `transform ${120 / speedFactor}ms ease-out, opacity ${120 / speedFactor}ms ease-out`;
        crab.style.transform = `translate(${travel}px, -10px) scale(1.25) rotate(0deg)`;
        crab.style.opacity = "0";
        if (typeof el.animate === "function") {
          try {
            el.animate([
              { boxShadow: "0 0 0 3px rgba(96, 165, 250, 0.75), 0 0 12px rgba(96, 165, 250, 0.35)", backgroundColor: "rgba(96, 165, 250, 0.1)" },
              { boxShadow: "0 0 0 0 rgba(96, 165, 250, 0)", backgroundColor: "transparent" }
          ], { duration: 400 / speedFactor, easing: "ease-out" });
          } catch (_) {}
        }
        setTimeout(() => { crab.remove(); resolve(); }, 130 / speedFactor);
      }
    }
    requestAnimationFrame(frame);
  });

  const runType = (el, finalVal, field) => new Promise(resolve => {
    const isText = el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement && !["checkbox", "radio", "button", "submit", "reset", "hidden", "file"].includes(el.type);
    if (!isText || typeof finalVal !== "string" || finalVal.length < 2) {
      setter(el, finalVal, field); resolve(); return;
    }
    const delay = Math.max(1, Math.min(8, 240 / finalVal.length) / speedFactor);
    let length = 0;
    const typeNext = () => {
      length++;
      setter(el, finalVal.slice(0, length), field, length === finalVal.length);
      if (length < finalVal.length) setTimeout(typeNext, delay);
      else resolve();
    };
    typeNext();
  });

  if (count) {
    const reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const animate = !reducedMotion && options.animations !== "off";
    const typeable = el => el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement && !["checkbox", "radio", "button", "submit", "reset", "hidden", "file"].includes(el.type);
    let animationTask;
    if (animate && (options.animations === "plaid" && options.icon || options.animations === "on")) {
      for (const item of assignments) {
        if (!previous.has(item.el)) previous.set(item.el, { before: read(item.el) });
        const state = previous.get(item.el);
        if (typeable(item.el) && typeof item.value === "string") state.filled = { value: item.value, checked: state.before.checked };
        else {
          setter(item.el, item.value, item.field);
          state.filled = read(item.el);
        }
      }
      animationTask = (async () => {
        if (options.animations === "plaid" && options.icon) {
          for (const item of assignments) await runCrab(item.el, item.value, options.icon, item.field);
        } else {
          for (const item of assignments) await runType(item.el, item.value, item.field);
          assignments.forEach((item, index) => {
            if (typeof item.el.animate !== "function") return;
            try {
              item.el.animate([
                { boxShadow: "0 0 0 2px rgba(96, 165, 250, 0.55)", backgroundColor: "rgba(96, 165, 250, 0.08)" },
                { boxShadow: "0 0 0 0 rgba(96, 165, 250, 0)", backgroundColor: "transparent" }
              ], { duration: 300 / speedFactor, delay: index * 40 / speedFactor, easing: "ease-out" });
            } catch (_) {}
          });
        }
      })();
      animationTask.catch(() => { for (const item of assignments) setter(item.el, item.value, item.field); });
    } else {
      for (const item of assignments) {
        setter(item.el, item.value, item.field);
      }
      if (animate) {
        assignments.forEach((item, index) => {
          const el = item.el;
          if (typeof el.animate !== "function") return;
          try {
            el.animate([
              {
                boxShadow: "0 0 0 3px rgba(96, 165, 250, 0.75), 0 0 14px rgba(96, 165, 250, 0.35)",
                backgroundColor: "rgba(96, 165, 250, 0.12)",
                transform: "scale(1.012)"
              },
              {
                boxShadow: "0 0 0 1px rgba(96, 165, 250, 0.35), 0 0 6px rgba(96, 165, 250, 0.15)",
                backgroundColor: "rgba(96, 165, 250, 0.05)",
                transform: "scale(1.004)",
                offset: 0.55
              },
              {
                boxShadow: "0 0 0 0 rgba(96, 165, 250, 0)",
                backgroundColor: "transparent",
                transform: "scale(1)"
              }
            ], {
              duration: 600 / speedFactor,
              delay: index * 75 / speedFactor,
              easing: "cubic-bezier(0.16, 1, 0.3, 1)"
            });
          } catch (_) {}
        });
      }
    }
    const token = fillToken || crypto.randomUUID();
    for (const [el, state] of previous) if (!state.filled) state.filled = read(el);
    const undo = { token, restore: () => {
      let restored = 0;
      for (const [el, state] of previous) {
        const current = read(el);
        if (!el.isConnected || current.value !== state.filled.value || current.checked !== state.filled.checked) continue;
        const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        if (el.type === "checkbox") Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "checked").set.call(el, state.before.checked);
        else Object.getOwnPropertyDescriptor(proto, "value").set.call(el, state.before.value);
        el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); restored++;
        if (options.animations !== "off" && typeof el.animate === "function" && (!window.matchMedia || !window.matchMedia("(prefers-reduced-motion: reduce)").matches)) {
          try {
            el.animate([
              { boxShadow: "0 0 0 2px rgba(239, 169, 185, 0.7)", backgroundColor: "rgba(239, 169, 185, 0.12)" },
              { boxShadow: "0 0 0 0 rgba(239, 169, 185, 0)", backgroundColor: "transparent" }
            ], { duration: 400 / speedFactor, easing: "ease-out" });
          } catch (_) {}
        }
      }
      previous.clear(); return restored;
    }, clear: () => previous.clear() };
    globalThis.__rbwUndoFill?.clear(); globalThis.__rbwUndoFill = undo;
    setTimeout(() => { undo.clear(); if (globalThis.__rbwUndoFill === undo) delete globalThis.__rbwUndoFill; }, 10000);
  }
  // A separate document-local capability also covers forms in same-origin
  // subframes. A replacement document at the same URL cannot inherit it.
  globalThis.__rbwClipboardFillToken = fillToken;
  setTimeout(() => { if (globalThis.__rbwClipboardFillToken === fillToken) delete globalThis.__rbwClipboardFillToken; }, 120000);
  return { count, securityCodeFieldPresent };
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
  const speedFor = value => value === "slow" ? 0.65 : value === "fast" ? 1.5 : 1;
  const speedFactor = speedFor(notice.animationSpeed);
  const enterDuration = Math.round(360 / speedFactor);
  const exitDuration = Math.round(120 / speedFactor);
  const previousHost = document.getElementById("rbw-fill-notice");
  if (previousHost) {
    previousHost.__rbwDispose?.();
    previousHost.removeAttribute("id");
    if (previousHost.dataset.animations !== "off" && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      const previousSpeed = speedFor(previousHost.dataset.animationSpeed);
      const outgoingDuration = Math.round(180 / previousSpeed);
      previousHost.style.setProperty("transition", `opacity ${outgoingDuration}ms ease-in, transform ${outgoingDuration}ms ease-in`, "important");
      previousHost.style.setProperty("pointer-events", "none", "important");
      previousHost.getBoundingClientRect();
      previousHost.style.setProperty("opacity", "0", "important");
      previousHost.style.setProperty("transform", "translateX(-28px)", "important");
      setTimeout(() => previousHost.remove(), outgoingDuration + 20);
    } else previousHost.remove();
  }
  const host = document.createElement("div"); host.id = "rbw-fill-notice";
  host.dataset.animations = notice.animations === "off" ? "off" : notice.animations === "plaid" ? "plaid" : "on";
  host.dataset.animationSpeed = notice.animationSpeed;
  host.style.cssText = "all:initial!important;position:fixed!important;inset:16px 16px auto auto!important;z-index:2147483647!important;pointer-events:none!important;max-width:calc(100vw - 32px)!important;";
  const shadow = host.attachShadow({ mode: "closed" });
  const sheet = new CSSStyleSheet();
  const border = notice.error ? "#efa9b9" : "#555555";
  const bg = notice.error ? "#302528" : "#282828";
  const motionRules = notice.animations === "off" ? "" : `@media(prefers-reduced-motion:no-preference){.notice{opacity:0;transform:translateX(40px)}.notice.entering{animation:rbw-in ${enterDuration}ms cubic-bezier(.16,1,.3,1) both}.notice.closing{animation:rbw-out ${exitDuration}ms ease-in both}@keyframes rbw-in{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}@keyframes rbw-out{to{opacity:0;transform:translateX(16px)}}}`;
  sheet.replaceSync(`:host{all:initial}.notice{box-sizing:border-box;position:relative;overflow:hidden;display:flex;align-items:center;gap:14px;width:450px;max-width:calc(100vw - 32px);padding:14px 16px;border:1px solid ${border};border-radius:14px;background:${bg};color:#efefef;box-shadow:0 6px 24px #0006;font:17px/1.4 system-ui,sans-serif;pointer-events:auto}.brand{width:38px;height:38px;object-fit:contain;flex-shrink:0}.text{min-width:0;flex:1}.progress{position:absolute;left:0;right:0;bottom:0;height:3px;background:rgba(255,255,255,.12);pointer-events:none}.progress span{display:block;width:100%;height:100%;background:#8ab4f8;transform-origin:left center}strong,small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}small{color:#adadad;font-size:14.5px;margin-top:3px}button{flex-shrink:0;pointer-events:auto;cursor:pointer;border:0;border-radius:6px;background:transparent;color:#adadad;width:34px;height:34px;display:inline-flex;align-items:center;justify-content:center;padding:0;line-height:1}button.settings{width:auto;padding:0 8px;font:600 14px system-ui,sans-serif}button svg{width:22px;height:22px;display:block;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}button:hover,button:focus-visible{background:#383838;color:#efefef;outline:1px solid #d0d0d0}${motionRules}`);
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
  const onKey = event => { if (event.key === "Escape") dismiss(); };
  const cleanup = () => { clearTimeout(timer); document.removeEventListener("keydown", onKey); delete host.__rbwDispose; };
  const dismiss = () => {
    if (closing) return; closing = true;
    cleanup(); clearUndo();
    if (host.dataset.animations === "off" || matchMedia("(prefers-reduced-motion: reduce)").matches) host.remove();
    else { box.classList.add("closing"); setTimeout(() => host.remove(), exitDuration + 20); }
  };
  host.__rbwDispose = cleanup;
  close.addEventListener("click", dismiss); document.addEventListener("keydown", onKey);
  if (notice.icon) { const image = document.createElement("img"); image.className = "brand"; image.alt = "rbw"; image.src = notice.icon; box.append(image); }
  box.append(text);
  if (typeof notice.clipboard === "string") {
    // Something was put on the clipboard: a clipboard icon says so.
    const clip = document.createElementNS(closeIcon.namespaceURI, "svg"); clip.setAttribute("viewBox", "0 0 24 24"); clip.setAttribute("role", "img");
    // Small, tinted and inline with the item's name, so it reads as a status
    // marker and not as one of the buttons.
    clip.setAttribute("aria-label", notice.clipboard.slice(0, 64)); clip.style.cssText = "display:inline-block;width:14px;height:14px;margin-right:6px;vertical-align:-2px;color:#8ab4f8;pointer-events:auto";
    const clipTitle = document.createElementNS(closeIcon.namespaceURI, "title"); clipTitle.textContent = notice.clipboard.slice(0, 64); clip.append(clipTitle);
    for (const [tag, attributes] of [["rect", { x: 8, y: 3, width: 8, height: 4, rx: 1 }], ["path", { d: "M16 5h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2" }]]) {
      const part = document.createElementNS(closeIcon.namespaceURI, tag);
      for (const [name, value] of Object.entries({ fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", ...attributes })) part.setAttribute(name, value);
      clip.append(part);
    }
    account.prepend(clip);
    // A little wiggle once the notice has landed, to catch the eye.
    if (!matchMedia("(prefers-reduced-motion: reduce)").matches && notice.animations !== "off") {
      clip.style.transformOrigin = "50% 75%";
      clip.animate([{ transform: "rotate(0)" }, { transform: "rotate(-16deg) scale(1.15)", offset: .2 }, { transform: "rotate(13deg) scale(1.15)", offset: .4 }, { transform: "rotate(-9deg)", offset: .6 }, { transform: "rotate(5deg)", offset: .8 }, { transform: "rotate(0)" }], { duration: 650, delay: 350, easing: "ease-in-out" });
    }
  }
  if (notice.settingsAction) {
    const settings = document.createElement("button"); settings.type = "button"; settings.className = "settings"; settings.textContent = "Settings";
    settings.addEventListener("click", () => { api.runtime.sendMessage({ action: "open_settings" }).catch(() => {}); dismiss(); });
    box.append(settings);
  }
  if (notice.generatorAction) {
    const generator = document.createElement("button"); generator.type = "button"; generator.className = "settings"; generator.textContent = "Open generator";
    generator.addEventListener("click", event => { if (!event.isTrusted) return; api.runtime.sendMessage({ action: "open_generator" }).catch(() => {}); dismiss(); });
    box.append(generator);
  }
  // With several matching logins: a button for the next one (what the fill
  // shortcut does); the next notice replaces this one.
  if (Number.isInteger(notice.position) && Number.isInteger(notice.total) && notice.total > 1 && !notice.error && !notice.title) {
    const nextButton = document.createElement("button"); nextButton.type = "button"; nextButton.setAttribute("aria-label", "Fill the next matching login"); nextButton.title = "Fill the next matching login";
    const nextIcon = document.createElementNS(closeIcon.namespaceURI, "svg"); nextIcon.setAttribute("viewBox", "0 0 24 24"); nextIcon.setAttribute("aria-hidden", "true");
    const nextPath = document.createElementNS(closeIcon.namespaceURI, "path"); nextPath.setAttribute("d", "M5 12h14M13 6l6 6-6 6"); nextIcon.append(nextPath); nextButton.append(nextIcon);
    nextButton.addEventListener("click", event => {
      if (!event.isTrusted) return;
      nextButton.disabled = true;
      api.runtime.sendMessage({ action: "keyboard_fill_shortcut" }).catch(() => {});
      dismiss();
    }); box.append(nextButton);
  }
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
      if (typeof arm === "function") arm(3000); else { clearTimeout(timer); timer = setTimeout(dismiss, 3000); }
    }); box.append(undoButton);
  }
  // The notice takes clicks itself (they no longer fall through to the page
  // underneath): a click on it dismisses it, and hovering keeps it around.
  box.addEventListener("click", event => { if (event.isTrusted && !event.target.closest?.("button")) dismiss(); });
  // A countdown bar along the bottom edge, like the suggestion window's.
  const progress = document.createElement("div"); progress.className = "progress"; progress.setAttribute("aria-hidden", "true");
  const progressFill = document.createElement("span"); progress.append(progressFill);
  const motion = !matchMedia("(prefers-reduced-motion: reduce)").matches;
  progress.hidden = !motion;
  let barAnimation = null, armedFor = 0, armedAt = 0, armedFrom = 1, held = 1;
  const remaining = () => Math.max(0, 1 - (performance.now() - armedAt) / armedFor) * armedFrom;
  const arm = (ms, from = 1) => {
    clearTimeout(timer); timer = setTimeout(dismiss, ms);
    armedFor = ms; armedAt = performance.now(); armedFrom = from;
    if (!motion) return;
    barAnimation?.cancel();
    barAnimation = progressFill.animate([{ transform: `scaleX(${from})` }, { transform: "scaleX(0)" }], { duration: ms, easing: "linear", fill: "forwards" });
  };
  box.addEventListener("mouseenter", () => { clearTimeout(timer); held = remaining(); barAnimation?.pause(); });
  box.addEventListener("mouseleave", () => { if (!closing) arm(2000, held); });
  box.append(close, progress); shadow.append(box); document.documentElement.append(host);
  requestAnimationFrame(() => { if (host.isConnected) box.classList.add("entering"); });
  arm(undo ? 8000 : 4500);
}
