/* Extension-origin frame for inline suggestions and save prompts. Pages can
   neither script nor restyle it; the session token arrives only by a
   postMessage the content script addresses to this frame. */
const api = globalThis.browser || chrome;
const root = document.getElementById("root");
// IntersectionObserver v2 reports occlusion, opacity, filters and transforms
// across frames (Chromium). Elsewhere the background verifies each click.
const trackVisibility = "IntersectionObserver" in globalThis && "isVisible" in IntersectionObserverEntry.prototype;
let port = null, token = null, shownAt = Infinity, visible = !trackVisibility, notice = null, banner = null, session = null;
const rows = new Map();
const element = (tag, text, className) => { const node = document.createElement(tag); if (text != null) node.textContent = text; if (className) node.className = className; return node; };
const cardBrandIcon = brand => {
  const value = String(brand || "").toLowerCase().replace(/[^a-z]/g, "");
  if (value.includes("visa")) return "visa";
  if (value.includes("mastercard") || value === "mc") return "mastercard";
  if (value.includes("amex") || value.includes("americanexpress")) return "amex";
  if (value.includes("discover")) return "discover";
  return "card";
};
const settle = () => { shownAt = performance.now(); };
const send = message => { try { port?.postMessage(message); } catch (_) { /* The session closed. */ } };
// Clicks only count once the UI has been visible and still for 500 ms.
// `target` is what the user activated; keyboard activations are verified at
// its centre, like a click there.
function act(event, message, target = event.currentTarget) {
  if (!event.isTrusted || performance.now() - shownAt < 500 || !visible || document.visibilityState !== "visible" || !document.hasFocus()) {
    if (notice) notice.textContent = "rbw is checking that this window is visible. Click again.";
    return false;
  }
  let x = event.clientX, y = event.clientY;
  if (!event.detail) { const rect = target.getBoundingClientRect(); x = rect.left + rect.width / 2; y = rect.top + rect.height / 2; }
  if (notice) notice.textContent = "";
  send({ ...message, x, y });
  return true;
}
new ResizeObserver(() => { if (!root.hidden) send({ type: "size", height: Math.ceil(root.getBoundingClientRect().height) }); }).observe(root);
if (trackVisibility) {
  new IntersectionObserver(entries => { visible = entries[entries.length - 1].isVisible === true; }, { trackVisibility: true, delay: 100 }).observe(root);
}
document.addEventListener("keydown", event => { if (event.key === "Escape") send({ type: "close" }); });

function itemButton(item, kind) {
  const button = element("button", null, "item-btn"); button.type = "button"; button.dataset.item = item.id; rows.set(item.id, button);
  const iconCol = element("span", null, "icon-col");
  if (item.favicon) { const img = element("img"); img.src = item.favicon; img.alt = ""; iconCol.append(img); }
  else iconCol.append(icon(kind === "card" ? cardBrandIcon(item.brand) : "key"));
  const textCol = element("div", null, "text-col"); textCol.append(element("strong", item.name));
  const subtitle = kind === "card" ? item.brand : item.username;
  if (subtitle) textCol.append(element("small", subtitle));
  button.append(iconCol, textCol);
  button.addEventListener("click", event => act(event, { type: "fill", item: item.id }));
  return button;
}
function updateState(state) {
  for (const [id, button] of rows) {
    const active = state.active && state.item === id, complete = !state.active && state.filled && state.item === id;
    button.classList.toggle("is-filling", active); button.classList.toggle("is-filled", complete);
    let status = button.querySelector(".fill-state");
    if (active || complete) {
      if (!status) { status = element("small", null, "fill-state"); button.querySelector(".text-col")?.append(status); }
      status.textContent = active ? "Filling…" : "Filled";
    } else status?.remove();
  }
  if (!banner) return;
  banner.hidden = !state.name && !state.error;
  banner.classList.toggle("is-filling", !!state.active); banner.classList.toggle("is-error", !!state.error);
  banner.textContent = state.error || (state.active ? `Filling ${state.name}…` : state.filled ? `Filled ${state.name}` : "");
}
// Logins search only this site's matches (rbw never fills another site's
// login); cards are not tied to a site, so their search covers all cards.
function renderChoices(data) {
  root.className = "choices"; rows.clear();
  const card = data.kind === "card";
  const noun = (count = 2) => card ? (count === 1 ? "card" : "cards") : (count === 1 ? "login" : "logins");
  banner = element("div", null, "fill-banner"); banner.hidden = true;
  notice = element("div", null, "notice");
  const list = element("div");
  for (const item of data.items) list.append(itemButton(item, data.kind));
  const controls = element("div", null, "card-search");
  const label = card ? "Search all cards" : "Search this site's logins";
  const query = element("input"); query.type = "search"; query.placeholder = label; query.setAttribute("aria-label", label);
  const count = element("small", null, "card-search-count"); count.hidden = true;
  let timer, sequence = 0;
  query.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => send({ type: "search", query: query.value, sequence: ++sequence }), 180); });
  // Arrow keys move a highlight through the rows; Enter fills it (or the first row).
  let active = -1;
  const buttons = () => [...list.querySelectorAll(".item-btn")];
  const highlight = index => {
    const all = buttons(); active = all.length ? (index + all.length) % all.length : -1;
    all.forEach((button, i) => button.classList.toggle("is-active", i === active));
    all[active]?.scrollIntoView({ block: "nearest" });
  };
  query.addEventListener("keydown", event => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); highlight(active + (event.key === "ArrowDown" ? 1 : -1)); }
    else if (event.key === "Enter") {
      event.preventDefault();
      const target = buttons()[active >= 0 ? active : 0];
      if (target) act(event, { type: "fill", item: target.dataset.item }, target);
    }
  });
  new MutationObserver(() => { active = -1; }).observe(list, { childList: true });
  controls.append(query);
  root.replaceChildren(banner, controls, count, list, notice);
  if (Number(data.total) > data.items.length) {
    const more = element("div", null, "more"); more.append(element("span", `Showing ${data.items.length} of ${data.total} ${noun()} · Search to find another`)); list.after(more);
  }
  session.results = (results) => {
    if (results.sequence !== sequence) return;
    root.querySelector(".more")?.remove(); rows.clear();
    count.hidden = false; list.className = "card-search-results";
    count.textContent = results.total > results.items.length ? `Showing ${results.items.length} of ${results.total} ${noun()}` : `${results.items.length} ${noun(results.items.length)}`;
    list.replaceChildren(...(results.items.length ? results.items.map(item => itemButton(item, data.kind)) : [element("p", `No matching ${noun()}.`, "inline-empty")]));
    settle();
    if (!card && results.items.length) send({ type: "icons" });
  };
  if (!card) send({ type: "icons" });
}
const SAVE_TIMEOUT = 20000;
// Header shared in look with the inline chooser: title, Keep open, close and
// an auto-close progress bar.
function header(titleText, onClose) {
  const head = element("div", null, "header");
  const title = element("span", null, "title");
  const appIcon = element("img", null, "app-icon"); appIcon.alt = ""; appIcon.src = "icons/toolbar-48.png";
  title.append(appIcon, element("span", titleText));
  const keepOpen = element("button", "Keep open", "timer-stop-btn"); keepOpen.type = "button"; keepOpen.title = "Stop the auto-close timer"; keepOpen.hidden = true;
  const close = element("button", null, "dismiss-btn"); close.type = "button"; close.title = "Dismiss"; close.setAttribute("aria-label", "Dismiss"); close.append(icon("close"));
  close.addEventListener("click", event => { if (event.isTrusted) onClose(); });
  const progress = element("div", null, "autoclose-progress"); progress.hidden = true; progress.setAttribute("role", "progressbar");
  const bar = element("span", null, "autoclose-progress-fill"); progress.append(bar);
  head.append(title, keepOpen, close, progress);
  let timer = null;
  const stop = () => { clearTimeout(timer); timer = null; progress.hidden = true; keepOpen.hidden = true; };
  const start = (ms, onTimeout) => {
    stop(); progress.hidden = false; keepOpen.hidden = false;
    progress.setAttribute("aria-label", `Closes in ${Math.round(ms / 1000)} seconds`);
    bar.style.transition = "none"; bar.style.transform = "scaleX(1)"; void bar.getBoundingClientRect();
    bar.style.transition = `transform ${ms}ms linear`;
    requestAnimationFrame(() => { bar.style.transform = "scaleX(0)"; });
    timer = setTimeout(onTimeout, ms);
  };
  keepOpen.addEventListener("click", event => { if (event.isTrusted) stop(); });
  return { head, start, stop };
}
const labelled = (button, iconName, text) => { button.append(icon(iconName), element("span", text)); return button; };
function renderSave(data) {
  root.className = "save";
  const update = data.update;
  const top = header("rbw · Save login", () => send({ type: "dismiss" }));
  const body = element("div", null, "body");
  const head = element("div", null, "head");
  // The site's own icon; rbw's logo is already in the header.
  const logo = element("span", null, "logo");
  if (data.favicon) { const image = element("img"); image.alt = ""; image.src = data.favicon; image.onerror = () => image.replaceWith(icon("key")); logo.append(image); }
  else logo.append(icon("key"));
  const copy = element("div", null, "copy");
  copy.append(element("strong", update ? `Update password for ${update.name}?` : "Save this login?"),
    element("small", `${data.host}${(update?.username || data.username) ? ` · ${update?.username || data.username}` : ""}`));
  head.append(logo, copy);
  const actions = element("div", null, "actions");
  const primary = labelled(element("button", null, "primary"), update ? "check" : "plus", update ? "Update password" : "Save new login"); primary.type = "button";
  const secondary = update ? labelled(element("button"), "plus", "Save as new") : labelled(element("button"), "edit", "Update existing"); secondary.type = "button";
  const picker = element("div", null, "picker"); picker.hidden = true;
  const select = element("select"); select.setAttribute("aria-label", "Choose an existing login"); select.append(new Option("Choose a login…", ""));
  const apply = labelled(element("button", null, "primary"), "check", "Update login"); apply.type = "button"; apply.disabled = true;
  const status = element("p", "", "status");
  notice = status;
  const buttons = [primary, secondary, apply];
  const busy = (value, text = "") => { for (const button of buttons) button.disabled = value; if (!value) apply.disabled = !select.value; status.textContent = text; };
  const engaged = () => top.stop();
  primary.addEventListener("click", event => { engaged(); if (act(event, { type: "save", item: update ? update.id : null })) busy(true, update ? "Updating and syncing…" : "Saving and syncing…"); });
  if (update) secondary.addEventListener("click", event => { engaged(); if (act(event, { type: "save", item: null })) busy(true, "Saving and syncing…"); });
  else secondary.addEventListener("click", event => { if (!event.isTrusted) return; engaged(); picker.hidden = false; secondary.disabled = true; status.textContent = "Loading this site's logins…"; send({ type: "save_choices" }); });
  select.addEventListener("change", () => { engaged(); apply.disabled = !select.value; });
  apply.addEventListener("click", event => { engaged(); if (select.value && act(event, { type: "save", item: select.value })) busy(true, "Updating and syncing…"); });
  session.saveChoices = items => {
    select.replaceChildren(new Option("Choose a login…", ""));
    for (const item of items) select.append(new Option(item.username ? `${item.name} · ${item.username}` : item.name, item.id));
    status.textContent = select.options.length > 1 ? "" : "No logins for this site."; secondary.disabled = false;
  };
  session.saveResult = error => busy(false, error || "");
  picker.append(select, apply);
  actions.append(primary, secondary);
  body.append(head, actions, picker, status);
  root.replaceChildren(top.head, body);
  // Hide after a while; the offer stays available from the toolbar badge.
  top.start(SAVE_TIMEOUT, () => send({ type: "close" }));
}
function connect(value) {
  port = api.runtime.connect({ name: "rbw-inline" });
  port.onMessage.addListener(message => {
    if (message.type === "init") {
      session = {}; root.hidden = false;
      if (message.mode === "save") renderSave(message); else renderChoices(message);
      settle(); send({ type: "size", height: Math.ceil(root.getBoundingClientRect().height) });
    } else if (message.type === "state") updateState(message);
    else if (message.type === "results") session?.results?.(message);
    else if (message.type === "icons") {
      for (const item of message.items) {
        const target = rows.get(item.id)?.querySelector(".icon-col");
        if (!target || !item.favicon) continue;
        const image = element("img"); image.alt = ""; image.src = item.favicon; image.onload = () => target.replaceChildren(image);
      }
    } else if (message.type === "save_choices") session?.saveChoices?.(message.items || []);
    else if (message.type === "save_result") session?.saveResult?.(message.error);
    else if (message.type === "rejected" && notice) notice.textContent = message.error;
  });
  // A rejected (forged) token frees the frame for the content script's real one.
  port.onDisconnect.addListener(() => { port = null; if (!session) token = null; root.hidden = true; });
  port.postMessage({ type: "init", token: value });
}
// The page shares the parent window, so it can post here too; only the
// content script knows a valid token, and the background accepts each once.
window.addEventListener("message", event => {
  if (token || event.source !== parent || event.data?.channel !== "rbw-inline" || typeof event.data.token !== "string" || event.data.token.length > 64) return;
  token = event.data.token; connect(token);
});
