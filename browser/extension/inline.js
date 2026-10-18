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
function act(event, message) {
  if (!event.isTrusted || performance.now() - shownAt < 500 || !visible || document.visibilityState !== "visible" || !document.hasFocus()) {
    if (notice) notice.textContent = "rbw is checking that this window is visible. Click again.";
    return false;
  }
  let x = event.clientX, y = event.clientY;
  if (!event.detail) { const rect = event.currentTarget.getBoundingClientRect(); x = rect.left + rect.width / 2; y = rect.top + rect.height / 2; }
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
  const button = element("button", null, "item-btn"); button.type = "button"; rows.set(item.id, button);
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
function renderChoices(data) {
  root.className = "choices"; rows.clear();
  banner = element("div", null, "fill-banner"); banner.hidden = true;
  notice = element("div", null, "notice");
  const list = element("div");
  for (const item of data.items) list.append(itemButton(item, data.kind));
  if (data.kind === "card") {
    const controls = element("div", null, "card-search");
    const query = element("input"); query.type = "search"; query.placeholder = "Search all cards"; query.setAttribute("aria-label", "Search all cards");
    const count = element("small", null, "card-search-count"); count.hidden = true;
    let timer, sequence = 0;
    query.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => send({ type: "search", query: query.value, sequence: ++sequence }), 180); });
    controls.append(query);
    root.replaceChildren(banner, controls, count, list, notice);
    if (Number(data.total) > data.items.length) {
      const more = element("div", null, "more"); more.append(element("span", `Showing ${data.items.length} of ${data.total} cards · Search to find another`)); list.after(more);
    }
    session.results = (results) => {
      if (results.sequence !== sequence) return;
      root.querySelector(".more")?.remove(); rows.clear();
      count.hidden = false; list.className = "card-search-results";
      count.textContent = results.total > results.items.length ? `Showing ${results.items.length} of ${results.total} cards` : `${results.items.length} ${results.items.length === 1 ? "card" : "cards"}`;
      list.replaceChildren(...(results.items.length ? results.items.map(item => itemButton(item, "card")) : [element("p", "No matching cards.", "inline-empty")]));
      settle();
    };
  } else {
    root.replaceChildren(banner, list, notice);
    send({ type: "icons" });
  }
}
function renderSave(data) {
  root.className = "save";
  const head = element("div", null, "head");
  const logo = element("img", null, "logo"); logo.alt = ""; logo.src = "icons/rbw-48.png";
  const copy = element("div", null, "copy"); copy.append(element("strong", "Save this login?"), element("small", `${data.host}${data.username ? ` · ${data.username}` : ""}`));
  const dismiss = element("button", "Dismiss", "dismiss"); dismiss.type = "button";
  dismiss.addEventListener("click", event => { if (event.isTrusted) send({ type: "dismiss" }); });
  head.append(logo, copy, dismiss);
  const actions = element("div", null, "actions");
  const save = element("button", "Save new login", "primary"); save.type = "button";
  const choose = element("button", "Update existing"); choose.type = "button";
  const picker = element("div", null, "picker"); picker.hidden = true;
  const select = element("select"); select.setAttribute("aria-label", "Choose an existing login"); select.append(new Option("Choose a login…", ""));
  const update = element("button", "Update login", "primary"); update.type = "button"; update.disabled = true;
  const status = element("p", "", "status");
  notice = status;
  const busy = (value, text = "") => { for (const button of [save, choose, update, dismiss]) button.disabled = value; if (!value) update.disabled = !select.value; status.textContent = text; };
  save.addEventListener("click", event => { if (act(event, { type: "save", item: null })) busy(true, "Saving and syncing…"); });
  choose.addEventListener("click", event => { if (!event.isTrusted) return; picker.hidden = false; choose.disabled = true; status.textContent = "Loading matching logins…"; send({ type: "save_choices" }); });
  select.addEventListener("change", () => { update.disabled = !select.value; });
  update.addEventListener("click", event => { if (select.value && act(event, { type: "save", item: select.value })) busy(true, "Updating and syncing…"); });
  session.saveChoices = items => {
    select.replaceChildren(new Option("Choose a login…", ""));
    for (const item of items) select.append(new Option(item.username ? `${item.name} · ${item.username}` : item.name, item.id));
    status.textContent = select.options.length > 1 ? "" : "No matching logins found."; choose.disabled = false;
  };
  session.saveResult = error => busy(false, error || "");
  picker.append(select, update, status); actions.append(save, choose);
  root.replaceChildren(head, actions, picker);
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
