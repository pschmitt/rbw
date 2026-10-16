/* The background is the only extension context allowed to reach the host. */
const api = globalThis.browser || chrome;
let serial = 0;
let queue = Promise.resolve();

function native(request) {
  return api.runtime.sendNativeMessage("org.rbw.browser", { ...request, id: ++serial }).then(response => {
    if (response.error) throw new Error(response.error);
    return response.result;
  });
}

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:\/\//.test(tab.url)) throw new Error("Open an HTTP or HTTPS page first.");
  return tab;
}

async function handle(message) {
  const account = message.account || null;
  switch (message.action) {
    case "status": case "unlock": case "lock": case "sync":
      return native({ action: message.action, account });
    case "search": {
      let tab;
      try { tab = await activeTab(); } catch (_) { /* Vault search works on internal pages. */ }
      return native({ action: "search", account, query: String(message.query || ""), url: tab?.url || null, site_only: !!message.siteOnly });
    }
    case "copy":
      return native({ action: "copy", account, item: message.item, field: message.field });
    case "generate":
      return native({ action: "generate", account, length: message.length || null, passphrase: !!message.passphrase });
    case "fill": {
      const tab = await activeTab();
      const credential = await native({ action: "credential", account, item: message.item, url: tab.url });
      // Navigation or tab selection may have changed while pinentry was open.
      const current = await activeTab();
      if (current.id !== tab.id || current.url !== tab.url) throw new Error("Page changed. Choose Fill again.");
      const results = await api.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [0] },
        func: (expectedUrl, username, password) => {
          if (location.href !== expectedUrl) throw new Error("Page changed.");
          const visible = el => !el.disabled && !el.readOnly && el.getClientRects().length > 0;
          const passwords = [...document.querySelectorAll('input[type="password"]')].filter(visible);
          // Multiple password fields can indicate signup or password changes.
          if (passwords.length !== 1) throw new Error("Choose a login form with exactly one password field.");
          const passwordInput = passwords[0];
          const scope = passwordInput.form || document;
          const users = [...scope.querySelectorAll('input[autocomplete="username"],input[type="email"],input[type="text"],input:not([type])')].filter(visible);
          const user = users.find(el => el.autocomplete === "username") || users.find(el => el.type === "email") || users.at(-1);
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
          for (const [el, value] of [[user, username], [passwordInput, password]]) {
            if (!el || value == null) continue;
            setter.call(el, value);
            el.dispatchEvent(new Event("input", { bubbles: true }));
            el.dispatchEvent(new Event("change", { bubbles: true }));
          }
          passwordInput.focus();
          return true;
        },
        args: [tab.url, credential.username, credential.password],
      });
      if (!results[0]?.result) throw new Error("Could not fill this page.");
      return true;
    }
    default: throw new Error("Unknown action.");
  }
}

api.runtime.onMessage.addListener((message, sender, respond) => {
  // Content scripts and other extension pages have no access to this API.
  if (sender.id !== api.runtime.id || sender.tab || sender.url !== api.runtime.getURL("popup.html")) return false;
  const operation = queue.then(() => handle(message));
  queue = operation.catch(() => {});
  operation.then(result => respond({ result }), error => respond({ error: error.message || "Operation failed." }));
  return true;
});
