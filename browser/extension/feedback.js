/* A button confirms what it did in place: the result (a check, or a cross for
   kind "error") is stamped onto it from large to small, then it shakes and a
   pressure ring goes off (feedback.css). With motion off the result simply
   replaces the icon. Shared with browser-daemon's live view. Returns false
   when there is no button to change. */
function stampResult(trigger, { kind = "ok", motion = true, speed = 1 } = {}) {
  const original = trigger?.isConnected && (trigger._copyOriginal || trigger.querySelector(".svg-icon"));
  if (!original) return false;
  clearTimeout(trigger._copiedTimer);
  trigger._copyOriginal = original;
  // Every result replays the animation, even while the last one still runs.
  trigger.classList.remove("is-copied"); trigger.querySelector(".copy-check")?.remove();
  const check = icon(kind === "error" ? "close" : "check"); check.classList.add("copy-check");
  const box = original.getBoundingClientRect();
  if (box.width) { check.style.width = `${box.width}px`; check.style.height = `${box.height}px`; }
  original.after(check);
  trigger.classList.add("copy-btn");
  trigger.dataset.motion = motion ? "on" : "off";
  trigger.style.setProperty("--copy-speed", speed);
  if (kind === "error") trigger.dataset.flash = "error"; else delete trigger.dataset.flash;
  void trigger.offsetWidth; trigger.classList.add("is-copied");
  trigger._copiedTimer = setTimeout(() => {
    trigger.querySelector(".copy-check")?.remove();
    trigger.classList.remove("is-copied"); delete trigger._copyOriginal; delete trigger.dataset.flash;
  }, 1500);
  return true;
}
