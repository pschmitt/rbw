/* ISOLATED world: the background obtains the site from MessageSender.url. */
// Anti-clickjacking: action clicks need a trusted, settled, unobscured, fully opaque, focused UI.
const rbwHardenCss = "display:block!important;opacity:1!important;filter:none!important;transform:none!important;translate:none!important;scale:none!important;rotate:none!important;clip-path:none!important;clip:auto!important;mask:none!important;mix-blend-mode:normal!important;overflow:visible!important;";
const rbwGuard = () => {
  const state = { at: performance.now(), io: null, seen: !("IntersectionObserver" in globalThis && "isVisible" in IntersectionObserverEntry.prototype), visible: true };
  state.watch = host => {
    if (state.seen) return;
    try { state.visible = false; state.io = new IntersectionObserver(entries => { state.seen = true; state.visible = entries[entries.length - 1].isVisible === true; }, { trackVisibility: true, delay: 100 }); state.io.observe(host); } catch (_) { state.seen = true; state.visible = true; }
  };
  state.reset = () => { state.at = performance.now(); };
  state.stop = () => { state.io?.disconnect(); state.io = null; };
  state.allow = (event, host) => {
    try {
      if (!event.isTrusted || !host?.isConnected || performance.now() - state.at < 500 || !state.seen || !state.visible) return false;
      if (document.visibilityState !== "visible" || !document.hasFocus()) return false;
      if (host.checkVisibility && !host.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })) return false;
      let opacity = 1;
      for (let node = host; node; node = node.parentElement) {
        const style = getComputedStyle(node);
        opacity *= Number(style.opacity);
        if (style.display === "none" || style.visibility !== "visible" || style.filter !== "none" || (style.clipPath || "none") !== "none" || (style.maskImage || style.webkitMaskImage || "none") !== "none" || style.mixBlendMode !== "normal" || (node === host && style.transform !== "none")) return false;
      }
      if (!(opacity >= 0.95)) return false;
      let x = event.clientX, y = event.clientY;
      if (!event.detail) { const rect = event.currentTarget?.getBoundingClientRect?.(); if (!rect) return false; x = rect.left + rect.width / 2; y = rect.top + rect.height / 2; }
      return document.elementsFromPoint(x, y)[0] === host;
    } catch (_) { return false; }
  };
  return state;
};
(() => {
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const api = globalThis.browser || chrome;
  const requests = new Set();
  window.addEventListener("message", event => {
    const data = event.data;
    if (event.source !== window || event.origin !== location.origin || data?.channel !== "rbw-passkey" || typeof data.id !== "string" || data.id.length > 64) return;
    if (data.action === "cancel") {
      if (requests.delete(data.id)) api.runtime.sendMessage({ action: "passkey_cancel", request: data.id }).catch(() => {});
      return;
    }
    if (!["get", "create", "availability"].includes(data.action) || requests.has(data.id) || requests.size > 2) return;
    if (JSON.stringify(data).length > 65536) return;
    requests.add(data.id);
    api.runtime.sendMessage(data.action === "availability" ? { action: "passkey_available" } : { action: "passkey_request", request: data.id, method: data.action, options: data.options, conditional: !!data.conditional }).then(response => {
      if (!requests.delete(data.id)) return;
      window.postMessage({ channel: "rbw-passkey-response", id: data.id, ...response }, location.origin);
    }).catch(() => {
      if (requests.delete(data.id)) window.postMessage({ channel: "rbw-passkey-response", id: data.id, fallback: true }, location.origin);
    });
  });
  // Capture only user submitted forms. Nothing is written without approval.
  document.addEventListener("submit", event => {
    if (!event.isTrusted || !(event.target instanceof HTMLFormElement)) return;
    const form = event.target;
    const fields = [...form.querySelectorAll('input[type="password"]')].filter(el => el.value && !el.disabled);
    if (!fields.length || fields.length > 3 || !isSecureContext) return;
    const password = fields.find(el => el.autocomplete === "new-password")?.value || fields[0].value;
    const username = form.querySelector('input[autocomplete="username"],input[type="email"],input[type="text"]')?.value || "";
    if (password.length > 4096 || username.length > 1024) return;
    api.runtime.sendMessage({ action: "save_offer", username, password }).catch(() => {});
  }, true);
})();

// Inline UI lives in a closed shadow root in the isolated world. A page never
// receives the vault result set or a native messaging capability.
(() => {
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const api = globalThis.browser || chrome;
  const autofillGate = globalThis.__rbwAutofillGate || (globalThis.__rbwAutofillGate = { waiting: document.readyState === "loading", pending: false, completed: false });
  let host, generation = 0, filled = false, dismissed = false, activeFillItem = null, activeFillName = null, lastFilledItem = null, lastFilledName = null, fillBanner = null, movedPosition = null, closeTimer = null, closeCountdownTimer = null, closeProgressFrame = null, closeProgress = null, closeProgressFill = null, closeStopButton = null, cardCloseStopped = false, contextMenuTarget = null;
  const fills = new Set();
  const itemRows = new Map();
  const cardBrandIcon = brand => {
    const value = String(brand || "").toLowerCase().replace(/[^a-z]/g, "");
    if (value.includes("visa")) return "visa";
    if (value.includes("mastercard") || value === "mc") return "mastercard";
    if (value.includes("amex") || value.includes("americanexpress")) return "amex";
    if (value.includes("discover")) return "discover";
    return "card";
  };
  api.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== api.runtime.id) return;
    if (message?.action === "open_inline_suggestions") {
      let input = contextMenuTarget || document.activeElement;
      contextMenuTarget = null;
      while (input?.shadowRoot?.activeElement) input = input.shadowRoot.activeElement;
      showInlineSuggestions(input, true);
      return;
    }
    if (message?.action !== "rbw_fill_state") return;
    if (message.active) {
      fills.add(message.token);
      activeFillItem = message.item || null;
      activeFillName = message.name || activeFillName;
      lastFilledItem = null;
      lastFilledName = null;
    } else {
      fills.delete(message.token);
      if (message.filled) { lastFilledItem = message.item || null; lastFilledName = activeFillName; filled = true; }
      if (!fills.size) { activeFillItem = null; activeFillName = null; }
    }
    updateFillHighlight();
  });
  // Only deliberate interaction re-enables suggestions after filling; focus() is trusted too.
  let ui = null, lastInteraction = { el: null, at: -Infinity };
  const noteInteraction = event => { if (event.isTrusted) lastInteraction = { el: event.type === "keydown" && event.key === "Tab" ? null : event.composedPath()[0], at: performance.now() }; };
  document.addEventListener("pointerdown", noteInteraction, true); document.addEventListener("keydown", noteInteraction, true);
  document.addEventListener("pointerdown", event => { if (event.isTrusted && !fills.size) filled = false; }, true);
  document.addEventListener("keydown", event => { if (event.isTrusted && !fills.size && event.key !== "Escape") filled = false; }, true);
  function close() { clearTimeout(closeTimer); clearInterval(closeCountdownTimer); if (closeProgressFrame !== null) cancelAnimationFrame(closeProgressFrame); closeTimer = null; closeCountdownTimer = null; closeProgressFrame = null; closeProgress = null; closeProgressFill = null; closeStopButton = null; cardCloseStopped = false; ++generation; ui?.stop(); ui = null; host?.remove(); host = null; fillBanner = null; itemRows.clear(); }
  function dismissSuggestions() { dismissed = true; close(); }
  function stopCardCloseCountdown(selectedHost) {
    if (host !== selectedHost || !closeProgress || !closeProgressFill) return;
    clearTimeout(closeTimer); clearInterval(closeCountdownTimer);
    closeTimer = null; closeCountdownTimer = null;
    if (closeProgressFrame !== null) cancelAnimationFrame(closeProgressFrame);
    closeProgressFrame = null;
    cardCloseStopped = true;
    closeProgress.hidden = true;
    if (closeStopButton) closeStopButton.hidden = true;
  }
  function startCardCloseCountdown(selectedHost) {
    clearTimeout(closeTimer); clearInterval(closeCountdownTimer);
    if (cardCloseStopped || !closeProgress || !closeProgressFill) return;
    let remaining = 5;
    closeProgress.hidden = false;
    if (closeStopButton) closeStopButton.hidden = false;
    closeProgress.setAttribute("aria-label", "Card autofill window closes in five seconds");
    closeProgress.setAttribute("aria-valuenow", String(remaining));
    if (closeProgressFrame !== null) cancelAnimationFrame(closeProgressFrame);
    closeProgressFill.style.transition = "none";
    closeProgressFill.style.transform = "scaleX(1)";
    void closeProgressFill.getBoundingClientRect();
    closeProgressFill.style.transition = "transform 5s linear";
    closeProgressFrame = requestAnimationFrame(() => {
      closeProgressFrame = null;
      if (host === selectedHost) closeProgressFill.style.transform = "scaleX(0)";
    });
    closeCountdownTimer = setInterval(() => {
      remaining--;
      if (remaining > 0) closeProgress.setAttribute("aria-valuenow", String(remaining));
    }, 1000);
    closeTimer = setTimeout(() => { if (host === selectedHost) close(); }, 5000);
  }
  async function fillItem(item, name, kind) {
    const selectedHost = host;
    const response = await api.runtime.sendMessage({ action: "inline_fill", item, name, kind }).catch(() => null);
    if (kind === "card" && selectedHost && host === selectedHost && !response?.error && Number(response?.result) > 0) {
      startCardCloseCountdown(selectedHost);
    }
  }
  function updateFillHighlight() {
    for (const [id, button] of itemRows) {
      const active = activeFillItem === id;
      const complete = !active && lastFilledItem === id;
      button.classList.toggle("is-filling", active);
      button.classList.toggle("is-filled", complete);
      let status = button.querySelector(".fill-state");
      if (active || complete) {
        if (!status) { status = document.createElement("small"); status.className = "fill-state"; button.querySelector(".text-col")?.append(status); }
        status.textContent = active ? "Filling…" : "Filled";
      } else status?.remove();
    }
    if (fillBanner) {
      const name = activeFillName || lastFilledName;
      fillBanner.hidden = !name;
      fillBanner.textContent = activeFillName ? `Filling ${name}…` : name ? `Filled ${name}` : "";
      fillBanner.classList.toggle("is-filling", !!activeFillName);
    }
  }
  document.addEventListener("contextmenu", event => {
    if (!event.isTrusted) return;
    const target = event.composedPath()[0];
    if (target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement || (target instanceof HTMLElement && target.isContentEditable)) contextMenuTarget = target;
  }, true);
  async function openCardSearch(box, titleText, searchInput) {
    titleText.textContent = "rbw · Search all cards"; ui?.reset();
    itemRows.clear();
    for (const child of [...box.children].slice(1)) child.remove();
    const controls = document.createElement("div"); controls.className = "card-search";
    const query = searchInput || document.createElement("input"); query.type = "search"; query.placeholder = "Search all cards"; query.setAttribute("aria-label", "Search all cards");
    const count = document.createElement("small"); count.className = "card-search-count"; count.textContent = "Loading cards…";
    const results = document.createElement("div"); results.className = "card-search-results";
    fillBanner = document.createElement("div"); fillBanner.className = "fill-banner"; fillBanner.hidden = true;
    controls.append(query); box.append(controls, fillBanner, count, results);
    let sequence = 0, timer;
    const search = async () => {
      const current = ++sequence;
      count.textContent = "Searching…";
      const response = await api.runtime.sendMessage({ action: "inline_search_cards", query: query.value }).catch(() => null);
      if (current !== sequence || !results.isConnected) return;
      const items = response?.result || [];
      results.replaceChildren(); ui?.reset();
      count.textContent = response?.total > items.length ? `Showing ${items.length} of ${response.total} cards` : `${items.length} ${items.length === 1 ? "card" : "cards"}`;
      if (!items.length) { const empty = document.createElement("p"); empty.className = "inline-empty"; empty.textContent = "No matching cards."; results.append(empty); return; }
      for (const item of items) {
        const button = document.createElement("button"); button.type = "button"; button.className = "item-btn"; itemRows.set(item.id, button);
        const iconCol = document.createElement("span"); iconCol.className = "icon-col"; iconCol.append(icon(cardBrandIcon(item.brand)));
        const textCol = document.createElement("div"); textCol.className = "text-col";
        const name = document.createElement("strong"); name.textContent = item.name; textCol.append(name);
        if (item.brand) { const brand = document.createElement("small"); brand.textContent = item.brand; textCol.append(brand); }
        button.append(iconCol, textCol);
        button.addEventListener("pointerdown", event => { if (event.isTrusted) event.preventDefault(); });
        button.addEventListener("click", event => { if (ui?.allow(event, host)) fillItem(item.id, item.name, "card"); });
        results.append(button);
      }
      updateFillHighlight();
    };
    query.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 180); });
    await search();
  }
  async function showInlineSuggestions(input, explicit = false) {
    if (host && (input === host || host.contains(input))) return;
    if ((!explicit && (dismissed || filled || autofillGate.waiting || autofillGate.pending || autofillGate.completed)) || fills.size) { close(); return; }
    const autocomplete = (input?.getAttribute?.("autocomplete") || "").toLowerCase().split(/\s+/);
    const cardField = ["cc-name", "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type"].some(value => autocomplete.includes(value));
    const loginField = input instanceof HTMLInputElement && ["password", "email", "text"].includes(input.type) && (input.type !== "text" || autocomplete.includes("username"));
    const editableTarget = input instanceof HTMLInputElement || input instanceof HTMLSelectElement || (explicit && (input instanceof HTMLTextAreaElement || (input instanceof HTMLElement && input.isContentEditable)));
    if (!editableTarget || !isSecureContext || (!cardField && !loginField && !explicit)) { if (!host?.contains(input)) close(); return; }
    const defaultOption = input instanceof HTMLSelectElement ? [...input.options].find(option => option.defaultSelected) || input.options[0] : null;
    const alreadyFilled = input instanceof HTMLSelectElement ? input.value !== (defaultOption?.value || "") : String(input.value || "").trim() !== "";
    if (alreadyFilled && !explicit) { close(); return; }
    if (cardField && !explicit && (performance.now() - lastInteraction.at > 1000 || (lastInteraction.el && lastInteraction.el !== input))) { close(); return; }
    const kind = cardField ? "card" : "login";
    close(); const current = generation;
    const result = await api.runtime.sendMessage({ action: "inline_choices", kind }).catch(() => null);
    let focused = document.activeElement; while (focused?.shadowRoot?.activeElement) focused = focused.shadowRoot.activeElement;
    if (current !== generation || !result?.result?.length || focused !== input) return;
    host = document.createElement("div");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = ":host{all:initial}.box{box-sizing:border-box;font:13px/1.4 system-ui,sans-serif;color:#efefef;background:#282828;border:1px solid #555555;border-radius:10px;box-shadow:0 6px 20px #0006;overflow:hidden;max-width:380px}.header{position:relative;display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:#202020;border-bottom:1px solid #494949}.drag-handle{display:flex;align-items:center;gap:7px;flex:1;min-width:0;border:0;padding:0;background:transparent;text-align:left;cursor:grab;touch-action:none;user-select:none}.drag-handle:active{cursor:grabbing}.drag-handle:focus-visible{outline:1px solid #d0d0d0;outline-offset:3px;border-radius:3px}.grip{width:12px;height:16px;fill:#adadad;flex-shrink:0}.title{display:flex;align-items:center;gap:6px;color:#adadad;font-size:11px;font-weight:600;letter-spacing:0.3px;text-transform:uppercase}.app-icon{width:14px;height:14px;object-fit:contain;flex-shrink:0;border-radius:2px}.autoclose-progress{position:absolute;left:0;right:0;bottom:0;height:3px;overflow:hidden;background:#3b3b3b;pointer-events:none}.autoclose-progress-fill{display:block;width:100%;height:100%;background:#8ab4f8;transform:scaleX(1);transform-origin:left center}.timer-stop-btn{border:0;border-radius:4px;padding:3px 6px;background:transparent;color:#adadad;font:11px system-ui,sans-serif;cursor:pointer}.timer-stop-btn:hover,.timer-stop-btn:focus-visible{background:#383838;color:#efefef;outline:1px solid #777}.timer-stop-btn[hidden],.autoclose-progress[hidden]{display:none}.dismiss-btn{display:flex;align-items:center;justify-content:center;border:0;background:transparent;color:#adadad;padding:2px 4px;border-radius:4px;cursor:pointer;line-height:1}.dismiss-btn:hover,.dismiss-btn:focus-visible{color:#efefef;background:#383838}.dismiss-btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}.item-btn{display:flex;align-items:center;gap:10px;width:100%;text-align:left;border:0;border-top:1px solid #383838;padding:8px 12px;background:#282828;color:#efefef;font:13px system-ui,sans-serif;cursor:pointer}.item-btn:first-of-type{border-top:0}.item-btn:hover,.item-btn:focus-visible{background:#383838;outline:none}.icon-col{width:20px;height:20px;display:flex;align-items:center;justify-content:center;flex-shrink:0;border-radius:3px}.icon-col img{width:18px;height:18px;border-radius:3px;object-fit:contain}.icon-col svg{width:18px;height:18px;stroke:#d0d0d0;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.text-col{min-width:0;flex:1}strong,small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}strong{font-weight:500;font-size:13px}small{color:#adadad;font-size:11px;margin-top:1px}";
    style.textContent += ".icon-col svg.brand-icon{width:24px;height:24px;stroke:none}.item-btn.is-filling{background:#383838;box-shadow:inset 3px 0 #8ab4f8,inset 0 0 0 1px #8ab4f8}.item-btn.is-filled{background:#303a32;box-shadow:inset 3px 0 #81c995}.fill-state{color:#a8c7fa!important;font-weight:600}.item-btn.is-filled .fill-state{color:#81c995!important}.fill-banner{padding:7px 12px;border-bottom:1px solid #494949;background:#26344a;color:#d3e3fd;font-size:12px;font-weight:600}.fill-banner.is-filling:before{content:'';display:inline-block;width:9px;height:9px;margin-right:7px;border:2px solid #7895bd;border-top-color:#d3e3fd;border-radius:50%;vertical-align:-2px;animation:rbw-spin .8s linear infinite}@keyframes rbw-spin{to{transform:rotate(360deg)}}";
    style.textContent += ".more{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 10px;border-top:1px solid #494949;color:#adadad;font:11px system-ui,sans-serif}.more button{display:flex;align-items:center;gap:5px;border:1px solid #555;border-radius:6px;padding:5px 7px;background:#303030;color:#efefef;font:11px system-ui,sans-serif;cursor:pointer}.more button:hover,.more button:focus-visible{background:#383838;outline:1px solid #d0d0d0}.more button .svg-icon{width:14px;height:14px;stroke:currentColor;fill:none}.card-search{padding:8px 10px}.card-search input{box-sizing:border-box;width:100%;border:1px solid #555;border-radius:6px;padding:8px 10px;background:#202020;color:#efefef;font:13px system-ui,sans-serif;outline:none}.card-search input:focus{border-color:#8ab4f8;box-shadow:0 0 0 1px #8ab4f8}.card-search-count{padding:0 12px 6px;color:#adadad}.card-search-results{max-height:45vh;overflow:auto}.inline-empty{margin:0;padding:14px 12px;color:#adadad}";
    shadow.append(style);
    const box = document.createElement("div"); box.className = "box";
    const header = document.createElement("div"); header.className = "header";
    const title = document.createElement("span"); title.className = "title";
    if (result?.appIcon) {
      const appIcon = document.createElement("img"); appIcon.className = "app-icon"; appIcon.alt = ""; appIcon.src = result.appIcon;
      title.append(appIcon);
    }
    const titleText = document.createElement("span"); titleText.textContent = kind === "card" ? "rbw · Payment cards" : "rbw · Autofill";
    title.append(titleText);
    const progress = document.createElement("div"); progress.className = "autoclose-progress"; progress.hidden = true; progress.setAttribute("role", "progressbar"); progress.setAttribute("aria-label", "Card autofill window closes in five seconds"); progress.setAttribute("aria-valuemin", "0"); progress.setAttribute("aria-valuemax", "5"); progress.setAttribute("aria-valuenow", "5");
    const progressFill = document.createElement("span"); progressFill.className = "autoclose-progress-fill"; progress.append(progressFill);
    if (kind === "card") { closeProgress = progress; closeProgressFill = progressFill; }
    const keepOpen = document.createElement("button"); keepOpen.className = "timer-stop-btn"; keepOpen.type = "button"; keepOpen.textContent = "Keep open"; keepOpen.title = "Stop the auto-close timer"; keepOpen.setAttribute("aria-label", "Keep this window open"); keepOpen.hidden = true;
    keepOpen.addEventListener("click", event => { if (event.isTrusted) stopCardCloseCountdown(host); });
    if (kind === "card") closeStopButton = keepOpen;
    const dismiss = document.createElement("button"); dismiss.className = "dismiss-btn"; dismiss.type = "button"; dismiss.title = "Dismiss"; dismiss.setAttribute("aria-label", "Dismiss");
    const closeIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"); closeIcon.setAttribute("viewBox", "0 0 24 24"); closeIcon.setAttribute("aria-hidden", "true");
    const closePath = document.createElementNS(closeIcon.namespaceURI, "path"); closePath.setAttribute("d", "M18 6 6 18M6 6l12 12"); closeIcon.append(closePath); dismiss.append(closeIcon);
    dismiss.addEventListener("click", event => { if (event.isTrusted) dismissSuggestions(); });
    const handle = document.createElement("button"); handle.type = "button"; handle.className = "drag-handle";
    handle.setAttribute("aria-label", "Move autofill suggestions"); handle.title = "Drag to move · Arrow keys to adjust · Home to reset";
    const grip = document.createElementNS(closeIcon.namespaceURI, "svg"); grip.setAttribute("viewBox", "0 0 12 16"); grip.setAttribute("class", "grip"); grip.setAttribute("aria-hidden", "true");
    for (const x of [3, 9]) for (const y of [3, 8, 13]) { const dot = document.createElementNS(closeIcon.namespaceURI, "circle"); dot.setAttribute("cx", x); dot.setAttribute("cy", y); dot.setAttribute("r", "1"); grip.append(dot); }
    handle.append(grip, title); header.append(handle, keepOpen, dismiss, progress); box.append(header);
    fillBanner = document.createElement("div"); fillBanner.className = "fill-banner"; fillBanner.hidden = true; box.append(fillBanner);

    const iconTargets = new Map();
    const suggestions = document.createElement("div");
    let cardSearchInput = null, searchMode = false;
    if (kind === "card") {
      const controls = document.createElement("div"); controls.className = "card-search";
      cardSearchInput = document.createElement("input"); cardSearchInput.type = "search"; cardSearchInput.placeholder = "Search all cards"; cardSearchInput.setAttribute("aria-label", "Search all cards");
      cardSearchInput.addEventListener("input", () => {
        if (searchMode || !cardSearchInput.value.trim()) return;
        searchMode = true;
        openCardSearch(box, titleText, cardSearchInput);
      });
      controls.append(cardSearchInput); box.append(controls);
    }
    for (const item of result.result) {
      const button = document.createElement("button"); button.type = "button"; button.className = "item-btn";
      itemRows.set(item.id, button);
      const iconCol = document.createElement("span"); iconCol.className = "icon-col";
      if (item.favicon) {
        const img = document.createElement("img"); img.src = item.favicon; img.alt = "";
        iconCol.append(img);
      } else if (kind === "card") {
        iconCol.append(icon(cardBrandIcon(item.brand)));
      } else {
        const itemIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"); itemIcon.setAttribute("viewBox", "0 0 24 24"); itemIcon.setAttribute("aria-hidden", "true");
        const itemPath = document.createElementNS(itemIcon.namespaceURI, "path");
        itemPath.setAttribute("d", "M13 15a5 5 0 1 1-1.5-3.5l8-8L22 6l-2 2-2-2-2 2 2 2-3 3"); itemIcon.append(itemPath); iconCol.append(itemIcon);
      }
      iconTargets.set(item.id, iconCol);
      const textCol = document.createElement("div"); textCol.className = "text-col";
      const name = document.createElement("strong"); name.textContent = item.name;
      textCol.append(name);
      if (item.username) {
        const subtitle = document.createElement("small"); subtitle.textContent = item.username;
        textCol.append(subtitle);
      }
      button.append(iconCol, textCol);
      button.addEventListener("pointerdown", event => { if (event.isTrusted) event.preventDefault(); });
      button.addEventListener("click", event => { if (ui?.allow(event, host)) fillItem(item.id, item.name, kind); });
      suggestions.append(button);
    }
    box.append(suggestions);
    updateFillHighlight();
    if (kind === "card" && Number(result.total) > result.result.length) {
      const more = document.createElement("div"); more.className = "more";
      const count = document.createElement("span"); count.textContent = `Showing ${result.result.length} of ${result.total} cards · Search to find another`;
      more.append(count); box.append(more);
    }
    shadow.append(box);
    const rect = input.getBoundingClientRect();
    host.style.cssText = `position:fixed!important;z-index:2147483647!important;top:0!important;left:0!important;width:${Math.max(0, Math.min(380, Math.max(rect.width, 240), innerWidth - 16))}px!important;visibility:hidden!important;pointer-events:auto!important;${rbwHardenCss}`;
    document.documentElement.append(host);
    const position = (x, y) => {
      const size = box.getBoundingClientRect();
      const point = { x: Math.max(8, Math.min(x, innerWidth - size.width - 8)), y: Math.max(8, Math.min(y, innerHeight - size.height - 8)) };
      host.style.setProperty("left", `${point.x}px`, "important"); host.style.setProperty("top", `${point.y}px`, "important");
      return point;
    };
    position(movedPosition?.x ?? rect.left, movedPosition?.y ?? rect.bottom + 4); host.style.setProperty("visibility", "visible", "important");
    ui = rbwGuard(); ui.watch(host);
    let drag;
    handle.addEventListener("pointerdown", event => {
      if (!event.isTrusted || event.button !== 0) return;
      event.preventDefault(); const bounds = box.getBoundingClientRect();
      drag = { id: event.pointerId, x: event.clientX, y: event.clientY, left: bounds.left, top: bounds.top };
      handle.setPointerCapture(event.pointerId);
    });
    handle.addEventListener("pointermove", event => {
      if (!event.isTrusted || !drag || drag.id !== event.pointerId || !host) return;
      movedPosition = position(drag.left + event.clientX - drag.x, drag.top + event.clientY - drag.y);
    });
    const endDrag = () => { drag = null; };
    handle.addEventListener("pointerup", endDrag); handle.addEventListener("pointercancel", endDrag); handle.addEventListener("lostpointercapture", endDrag);
    handle.addEventListener("keydown", event => {
      if (!event.isTrusted || !host) return;
      if (event.key === "Home") { event.preventDefault(); movedPosition = null; const anchor = input.getBoundingClientRect(); position(anchor.left, anchor.bottom + 4); return; }
      const delta = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[event.key];
      if (!delta) return;
      event.preventDefault(); const bounds = box.getBoundingClientRect(); const step = event.shiftKey ? 40 : 10;
      movedPosition = position(bounds.left + delta[0] * step, bounds.top + delta[1] * step);
    });
    if (kind === "login") api.runtime.sendMessage({ action: "inline_icons" }).then(response => {
      if (generation !== current || !host) return;
      for (const item of response?.result || []) {
        const target = iconTargets.get(item.id);
        if (!target || !item.favicon) continue;
        const image = document.createElement("img"); image.alt = ""; image.src = item.favicon;
        image.onload = () => { if (generation === current && host) target.replaceChildren(image); };
      }
    }).catch(() => {});
  }
  document.addEventListener("focusin", event => showInlineSuggestions(event.composedPath()[0]));
  document.addEventListener("keydown", event => { if (event.key === "Escape") close(); });
  window.addEventListener("scroll", close, true); window.addEventListener("resize", close);
})();

// Save offers stay in the extension background; the page UI only receives the
// site and username and sends back a selected item ID.
(() => {
  try { if (window.top.location.origin !== location.origin) return; } catch (_) { return; }
  const api = globalThis.browser || chrome;
  let host, shadow, offer;
  let ui = null;
  const close = () => { ui?.stop(); ui = null; host?.remove(); host = null; shadow = null; offer = null; };
  const send = (action, values = {}) => api.runtime.sendMessage({ action, ...values });
  const text = (tag, value, className) => {
    const node = document.createElement(tag); node.textContent = value;
    if (className) node.className = className;
    return node;
  };
  function show(value) {
    close();
    if (value?.origin !== location.origin) return;
    offer = value;
    host = document.createElement("div");
    host.style.cssText = "all:initial!important;position:fixed!important;inset:16px 16px auto auto!important;z-index:2147483647!important;pointer-events:none!important;max-width:calc(100vw - 32px)!important;" + rbwHardenCss;
    shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = ":host{all:initial}.card{box-sizing:border-box;width:380px;max-width:calc(100vw - 32px);padding:16px;border:1px solid #555;border-radius:14px;background:#242424;color:#f2f2f2;box-shadow:0 12px 36px #0008;font:14px/1.45 system-ui,sans-serif;pointer-events:auto}.head{display:flex;align-items:flex-start;gap:12px}.logo{width:34px;height:34px;object-fit:contain;flex:none;border-radius:8px}.copy{min-width:0;flex:1}strong,small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}strong{font-size:15px;font-weight:650}small{margin-top:3px;color:#b9b9b9;font-size:12px}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}button,select{box-sizing:border-box;font:inherit;color:inherit;border:1px solid #555;border-radius:8px;background:#303030;padding:8px 11px}button{cursor:pointer}button:hover,button:focus-visible{border-color:#aaa;background:#383838;outline:2px solid #aaa;outline-offset:1px}button.primary{background:#e1e1e1;color:#202020;border-color:#e1e1e1;font-weight:650}button.primary:hover{background:#fff}.dismiss{margin-left:auto;padding:5px 9px;color:#c3c3c3}.picker{display:grid;grid-template-columns:1fr auto;gap:8px;margin-top:12px;padding-top:12px;border-top:1px solid #494949}.picker[hidden]{display:none}.picker select{min-width:0;width:100%;background:#303030}.status{grid-column:1/-1;min-height:18px;margin:0;color:#f0b4c0;font-size:12px}.status:empty{display:none}@media(prefers-reduced-motion:no-preference){.card{animation:enter 180ms ease-out both}@keyframes enter{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}}";
    const card = document.createElement("section"); card.className = "card"; card.setAttribute("role", "dialog"); card.setAttribute("aria-label", "Save login in rbw");
    const head = document.createElement("div"); head.className = "head";
    const logo = document.createElement("img"); logo.className = "logo"; logo.alt = ""; logo.src = api.runtime.getURL("icons/rbw-48.png");
    const copy = document.createElement("div"); copy.className = "copy";
    copy.append(text("strong", "Save this login?"), text("small", `${new URL(value.origin).host}${value.username ? ` · ${value.username}` : ""}`));
    const dismiss = document.createElement("button"); dismiss.className = "dismiss"; dismiss.type = "button"; dismiss.textContent = "Dismiss";
    dismiss.addEventListener("click", async event => { if (!event.isTrusted) return; await send("save_offer_dismiss").catch(() => {}); close(); });
    head.append(logo, copy, dismiss);
    const actions = document.createElement("div"); actions.className = "actions";
    const save = document.createElement("button"); save.className = "primary"; save.type = "button"; save.textContent = "Save new login";
    save.addEventListener("click", async event => {
      if (!ui?.allow(event, host)) return;
      save.disabled = true; choose.disabled = true; dismiss.disabled = true; status.textContent = "Saving and syncing…";
      const result = await send("save_offer_apply").catch(error => ({ error: error.message || "Could not save login." }));
      if (result?.error) { status.textContent = result.error; save.disabled = false; choose.disabled = false; dismiss.disabled = false; }
      else close();
    });
    const choose = document.createElement("button"); choose.type = "button"; choose.textContent = "Update existing";
    const picker = document.createElement("div"); picker.className = "picker"; picker.hidden = true;
    const select = document.createElement("select"); select.setAttribute("aria-label", "Choose an existing login");
    select.append(new Option("Choose a login…", ""));
    const update = document.createElement("button"); update.className = "primary"; update.type = "button"; update.textContent = "Update login"; update.disabled = true;
    const status = text("p", "", "status");
    choose.addEventListener("click", async event => {
      if (!event.isTrusted) return;
      picker.hidden = false; choose.disabled = true; status.textContent = "Loading matching logins…";
      const result = await send("save_offer_choices").catch(() => null);
      if (!host) return;
      select.replaceChildren(new Option("Choose a login…", ""));
      for (const item of result?.result || []) {
        const label = item.username ? `${item.name} · ${item.username}` : item.name;
        select.append(new Option(label, item.id));
      }
      status.textContent = result?.error || (select.options.length > 1 ? "" : "No matching logins found.");
      choose.disabled = false;
    });
    select.addEventListener("change", () => { update.disabled = !select.value; });
    update.addEventListener("click", async event => {
      if (!ui?.allow(event, host) || !select.value) return;
      save.disabled = true; choose.disabled = true; update.disabled = true; dismiss.disabled = true; status.textContent = "Updating and syncing…";
      const result = await send("save_offer_apply", { item: select.value }).catch(error => ({ error: error.message || "Could not update login." }));
      if (result?.error) { status.textContent = result.error; save.disabled = false; choose.disabled = false; update.disabled = false; dismiss.disabled = false; }
      else close();
    });
    picker.append(select, update, status); actions.append(save, choose); card.append(head, actions, picker); shadow.append(style, card);
    document.documentElement.append(host);
    ui = rbwGuard(); ui.watch(host);
    status.textContent = "";
  }
  api.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== api.runtime.id) return;
    if (message?.action === "rbw_save_offer") show(message.offer);
    if (message?.action === "rbw_save_offer_clear") close();
  });
})();

if (window === window.top) {
  const autofillGate = globalThis.__rbwAutofillGate || (globalThis.__rbwAutofillGate = { waiting: false, pending: false, completed: false });
  document.addEventListener("keydown", event => {
    const modifier = /Mac|iPhone|iPad/.test(navigator.platform) ? event.metaKey : event.ctrlKey;
    if (!event.isTrusted || event.repeat || !modifier || !event.shiftKey || event.altKey || event.key.toLowerCase() !== "l") return;
    event.preventDefault();
    (globalThis.browser || chrome).runtime.sendMessage({ action: "keyboard_fill_shortcut" }).catch(() => {});
  }, true);
  const loaded = () => {
    autofillGate.waiting = false;
    let observer, timer, expiry;
    const eligible = () => document.querySelector('input[type="password"]:not([autocomplete="new-password"]),input[autocomplete="username"]');
    const check = () => {
      if (!eligible()) return false;
      observer?.disconnect(); clearTimeout(timer); clearTimeout(expiry);
      autofillGate.pending = true;
      (globalThis.browser || chrome).runtime.sendMessage({ action: "autofill_load" }).then(response => {
        autofillGate.pending = false;
        autofillGate.completed = Number(response?.result) > 0;
      }).catch(() => { autofillGate.pending = false; });
      return true;
    };
    if (check()) return;
    // Briefly cover asynchronously rendered sign-in forms without keeping a
    // permanent observer or querying the vault on ordinary content/search pages.
    observer = new MutationObserver(() => {
      if (eligible()) { check(); return; }
      clearTimeout(timer); timer = setTimeout(check, 250);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    expiry = setTimeout(() => { observer.disconnect(); clearTimeout(timer); }, 10000);
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loaded, { once: true }); else loaded();
}
