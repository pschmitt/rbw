"use strict";
// The passkey prompt: a page started from the live view wants a passkey. As
// the rbw popup's approval page: the site, the vault's accounts for it (one
// click signs in with that one), another authenticator, or cancel. The live
// view does the signing once this frame has answered.
let current = null;   // {id, abort}

function answer(use, entry = null, device = false) {
  if (!current) return;
  const { id, abort } = current;
  current = null;
  abort.abort();
  bd.answerPasskey(id, use, use ? entry : null, device);
}
$("close").onclick = () => answer(false);
$("cancel-passkey").onclick = () => answer(false);
// The browser's own way (a security key, the phone): the page goes on without rbw.
$("use-device").onclick = () => answer(false, null, true);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); answer(false); } });

// The site's favicon instead of the key (the live view asks its node), as on
// the popup's approval page.
let siteIcon = Promise.resolve(null);
function withFavicon(target) {
  siteIcon.then((src) => {
    if (!src || !target.isConnected) return;
    const image = document.createElement("img");
    image.alt = "";
    image.src = src;
    image.onerror = () => target.replaceChildren(icon("key"));
    target.replaceChildren(image);
  });
}

function choice(e, rpId) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "passkey-choice";
  const iconBox = document.createElement("span");
  iconBox.className = "passkey-choice-icon";
  iconBox.append(icon("key"));
  const text = document.createElement("span");
  text.className = "passkey-choice-text";
  const strong = document.createElement("strong");
  strong.textContent = e.name || "Passkey";
  const small = document.createElement("small");
  small.textContent = e.user || e.passkey_user || rpId;
  text.append(strong, small);
  b.append(iconBox, text);
  withFavicon(iconBox);
  b.onclick = () => {
    b.classList.add("is-selected");
    $("approval-items").classList.add("is-busy");
    answer(true, e.id);
  };
  return b;
}

bd.on("passkey.end", (m) => { if (current?.id === m.id) { current.abort.abort(); current = null; } });
bd.on("passkey", async (m) => {
  current?.abort.abort();
  const abort = new AbortController();
  current = { id: m.id, abort };
  const rpId = m.site;
  const info = $("approval-description"), items = $("approval-items"), cancel = $("cancel-passkey");
  const set = (text, cls = "") => { if (current?.id === m.id) { info.textContent = text; info.className = "hint " + cls; } };
  $("approval-origin").textContent = rpId;
  siteIcon = bd.request("favicon", { url: `https://${rpId}` }).catch(() => null);
  const emblem = document.querySelector(".passkey-emblem");
  emblem.replaceChildren(icon("key"));
  withFavicon(emblem);
  warning($("public"), m.warning);
  cancel.lastChild.textContent = "Cancel";
  items.classList.remove("is-busy");
  items.replaceChildren();
  set("Checking the vault…", "checking");
  cancel.focus();
  try {
    // The lookup stops with the prompt (closed, or answered).
    const found = await bd.request("passkey.find", {}, { signal: abort.signal });
    if (current?.id !== m.id) return;
    if (found?.locked) {
      set("Your vault is locked. Continue to unlock it from your phone.", "locked");
      const unlock = document.createElement("button");
      unlock.type = "button";
      unlock.className = "primary passkey-locked";
      unlock.append(icon("unlock"), "Unlock and continue");
      unlock.onclick = () => answer(true, null);
      items.replaceChildren(unlock);
      unlock.focus();
    } else if (!Array.isArray(found) || !found.length) {
      // Nothing to approve: say so and get out of the way. The site hears "cancelled"
      // and usually offers another way to sign in (password, code, ...).
      set(`No passkey for ${rpId} in your vault: sign in another way.`, "bad");
      cancel.lastChild.textContent = "OK";
      cancel.focus();
      setTimeout(() => { if (current?.id === m.id) answer(false); }, 6000);
    } else {
      set("Choose an account to continue.");
      items.replaceChildren(...found.map((e) => choice(e, rpId)));
    }
  } catch (err) {
    if (err.aborted || current?.id !== m.id) return;
    set(err.message, "bad");
    // The lookup itself failed: rbw may still find the entry.
    if (!/no passkey|no matching|no entry|No secret agent/i.test(err.message)) {
      const anyway = document.createElement("button");
      anyway.type = "button";
      anyway.className = "primary passkey-locked";
      anyway.append(icon("key"), "Try the vault anyway");
      anyway.onclick = () => answer(true, null);
      items.replaceChildren(anyway);
    }
  }
});
