const api = globalThis.browser || chrome;
const $ = id => document.getElementById(id);
let epoch = 0;
let timer;
async function request(action, values = {}) {
  const response = await api.runtime.sendMessage({ action, account: $("account").value, ...values });
  if (response.error) throw new Error(response.error);
  return response.result;
}
function message(text) { $("message").textContent = text; }
async function attempt(fn) {
  try { await fn(); } catch (error) { message(error.message); }
}
function clearVault() { ++epoch; $("items").replaceChildren(); $("generated").value = ""; }
async function refresh() {
  clearVault();
  const status = await request("status");
  const selected = $("account").value;
  $("account").replaceChildren(new Option("Primary account", ""), ...status.accounts.map(name => new Option(name, name)));
  $("account").value = selected;
  $("state").textContent = status.unlocked ? "Unlocked" : "Locked";
  $("vault").hidden = !status.unlocked;
  $("unlock").disabled = status.unlocked;
  $("lock").disabled = !status.unlocked;
  if (status.unlocked) await search();
}
async function search() {
  const current = ++epoch;
  const result = await request("search", { query: $("query").value, siteOnly: $("site").checked });
  if (current !== epoch) return;
  $("items").replaceChildren();
  for (const item of result.items) {
    const row = document.createElement("article");
    const title = document.createElement("strong"); title.textContent = item.name;
    const user = document.createElement("small"); user.textContent = item.username || "No username";
    const actions = document.createElement("div"); actions.className = "item-actions";
    for (const [label, action, field] of [["Fill", "fill"], ["Username", "copy", "username"], ["Password", "copy", "password"], ["TOTP", "copy", "totp"]]) {
      const button = document.createElement("button"); button.textContent = label;
      if (action === "fill") button.disabled = !item.matched;
      button.onclick = () => attempt(async () => {
        button.disabled = true;
        try { await request(action, { item: item.id, ...(field ? { field } : {}) }); message(action === "fill" ? "Filled. Submit the form when ready." : "Copied using rbw clipboard settings."); }
        finally { button.disabled = false; }
      });
      actions.append(button);
    }
    row.append(title, user, actions); $("items").append(row);
  }
  message(result.items.length ? `${result.items.length} logins${result.items.length === result.limit ? " (limit reached; narrow your search)" : ""}` : "No matching logins.");
}
for (const action of ["unlock", "lock", "sync"]) {
  $(action).onclick = () => attempt(async () => {
    clearVault(); $("vault").hidden = true; message("Working…");
    await request(action); await refresh();
  });
}
$("account").onchange = () => attempt(refresh);
$("query").oninput = () => { clearTimeout(timer); ++epoch; timer = setTimeout(() => attempt(search), 200); };
$("site").onchange = () => attempt(search);
$("generate").onclick = () => attempt(async () => {
  const value = $("length").value;
  $("generated").value = await request("generate", { length: value ? Number(value) : null, passphrase: $("passphrase").checked });
  $("generated").select();
});
// Clear displayed metadata and generated values promptly if the CLI locks.
setInterval(() => attempt(async () => {
  const status = await request("status");
  if (!status.unlocked) { clearVault(); $("vault").hidden = true; $("state").textContent = "Locked"; $("unlock").disabled = false; }
}), 3000);
attempt(refresh);
