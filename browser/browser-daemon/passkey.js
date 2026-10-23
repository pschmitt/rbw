"use strict";
// The passkey prompt: a page started from the live view wants a passkey. It
// shows the site and which vault entry would sign in; the view does the
// signing once this frame answers "use" (with the entry picked).
$("head").innerHTML = header("Vault", "rbw", "Cancel passkey request");
$("emblem").innerHTML = ico("key");
let current = null;   // {id, abort}

function answer(use) {
  if (!current) return;
  const { id, abort } = current;
  current = null;
  abort.abort();
  bd.answerPasskey(id, use, use ? document.querySelector('input[name="entry"]:checked')?.value || null : null);
}
$("use").onclick = () => answer(true);
$("cancel").onclick = () => answer(false);
$("head").querySelector(".rbw-close").onclick = () => answer(false);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); answer(false); } });

bd.on("passkey.end", (m) => { if (current?.id === m.id) { current.abort.abort(); current = null; } });
bd.on("passkey", async (m) => {
  current?.abort.abort();
  const abort = new AbortController();
  current = { id: m.id, abort };
  const rpId = m.site;
  const info = $("info"), pick = $("entries"), use = $("use"), cancel = $("cancel");
  const set = (text, cls = "") => { if (current?.id === m.id) { info.textContent = text; info.className = "pk-info " + cls; } };
  $("rp").textContent = rpId;
  warning($("public"), m.warning);
  cancel.textContent = "Cancel request";
  use.textContent = "Use passkey";
  use.hidden = false;
  set("Checking the vault…", "checking");
  pick.innerHTML = "";
  // Not before the lookup: rbw would have to guess the entry (and fails with several).
  use.disabled = true;
  cancel.focus();
  try {
    // The lookup stops with the prompt (closed, or answered).
    const found = await bd.request("passkey.find", {}, { signal: abort.signal });
    if (current?.id !== m.id) return;
    if (found?.locked) {
      set("Your vault is locked. Continue to unlock it from your phone.", "locked");
      use.textContent = "Unlock and continue";
      use.disabled = false;
      use.focus();
    } else if (!Array.isArray(found) || !found.length) {
      // Nothing to approve: say so and get out of the way. The site hears "cancelled"
      // and usually offers another way to sign in (password, code, ...).
      set(`No passkey for ${rpId} in your vault: sign in another way.`, "bad");
      use.hidden = true;
      cancel.textContent = "OK";
      cancel.focus();
      setTimeout(() => { if (current?.id === m.id) answer(false); }, 6000);
    } else {
      set(found.length === 1 ? "Use this account to continue." : "Choose an account to continue.");
      pick.innerHTML = found.map((e, i) => `<label class="pk-choice"><input type="radio" name="entry" value="${esc(e.id)}"${i === 0 ? " checked" : ""}>`
        + `${ico("key")}<span class="pk-account"><strong>${esc(e.name || "Passkey")}</strong><small>${esc(e.user || e.passkey_user || rpId)}</small></span>`
        + `<span class="pk-tick" aria-hidden="true">${ico("check")}</span></label>`).join("");
      use.disabled = false;
      pick.querySelector("input:checked")?.focus();
    }
  } catch (err) {
    if (err.aborted || current?.id !== m.id) return;
    set(err.message, "bad");
    // The lookup itself failed: rbw may still find the entry.
    use.disabled = /no passkey|no matching|no entry|No secret agent/i.test(err.message);
  }
});
