/* The toolbar crab's pictures: the locked one (red eyes), the sync spinner and
   the fill hop. Drawn on canvases, so the extension's background and the
   live view of browser-daemon (browser-daemon/popup.js) share one drawing:
   change it here only. Each takes a decoded toolbar sprite (ImageBitmap) and
   its size and returns ImageData. */
globalThis.rbwToolbarIcon = (() => {
// Locked: the crab's eyes turn red. The eye band of the toolbar sprite is
// recoloured pixel by pixel (white to red), keeping the anti-aliasing.
function redEyeFrame(bitmap, size) {
  const canvas = new OffscreenCanvas(size, size); const ctx = canvas.getContext("2d");
  ctx.drawImage(bitmap, 0, 0, size, size);
  const image = ctx.getImageData(0, 0, size, size), data = image.data;
  for (let y = Math.floor(size * 0.55); y < Math.ceil(size * 0.72); y++) {
    for (let x = Math.floor(size * 0.28); x < Math.ceil(size * 0.72); x++) {
      const i = (y * size + x) * 4, low = Math.min(data[i], data[i + 1], data[i + 2]);
      if (low < 150) continue;
      const k = (low - 150) / 105;
      data[i] = 255; data[i + 1] = Math.round(255 - k * 196); data[i + 2] = Math.round(255 - k * 177);
    }
  }
  return image;
}
// A spinner ring around the (slightly smaller) crab: a comet-tail arc with a round head.
function syncFrame(bitmap, size, angle) {
  const canvas = new OffscreenCanvas(size, size); const ctx = canvas.getContext("2d");
  const c = size / 2, lw = Math.max(1.6, size / 10), r = c - lw / 2 - size * 0.02;
  const inner = size * 0.76;
  ctx.drawImage(bitmap, (size - inner) / 2, (size - inner) / 2, inner, inner);
  const accent = "255,176,32";
  ctx.lineWidth = lw; ctx.lineCap = "round";
  ctx.strokeStyle = "rgba(128,128,128,.35)";
  ctx.beginPath(); ctx.arc(c, c, r, 0, Math.PI * 2); ctx.stroke();
  const tail = Math.PI * 1.35, steps = 14;
  for (let i = 0; i < steps; i++) {
    const a0 = angle - tail + (tail * i) / steps, a1 = angle - tail + (tail * (i + 1)) / steps + 0.04;
    ctx.strokeStyle = `rgba(${accent},${(0.08 + 0.92 * ((i + 1) / steps) ** 1.6).toFixed(3)})`;
    ctx.beginPath(); ctx.arc(c, c, r, a0, a1); ctx.stroke();
  }
  return ctx.getImageData(0, 0, size, size);
}
// Toolbar feedback after a successful fill: the crab squashes, hops twice and
// a sparkle pops. Skipped while a sync spinner owns the icon.
function hopFrame(bitmap, size, t) {
  const canvas = new OffscreenCanvas(size, size); const ctx = canvas.getContext("2d");
  const body = size * 0.8, hops = 2;
  const wave = Math.abs(Math.sin(t * Math.PI * hops)), air = Math.sin(t * Math.PI * hops) ** 2 * (1 - t * 0.35);
  // Stretch in the air, squash on touching down.
  const stretch = 1 + (wave > 0.6 ? 0.08 : 0) - (wave < 0.15 ? 0.1 : 0);
  const w = body / stretch, h = body * stretch;
  const x = (size - w) / 2, y = size - h - size * 0.04 - air * size * 0.2;
  ctx.drawImage(bitmap, x, y, w, h);
  // Sparkle: a four-point star pops in the top-right and fades out.
  const pop = Math.max(0, (t - 0.35) / 0.65);
  if (pop > 0) {
    const r = size * 0.2 * Math.sin(Math.min(1, pop) * Math.PI) ** 0.7, cx = size * 0.82, cy = size * 0.2;
    ctx.fillStyle = "rgba(120,255,160,.95)"; ctx.beginPath();
    for (let i = 0; i < 8; i++) { const a = i * Math.PI / 4, d = i % 2 ? r * 0.3 : r; ctx[i ? "lineTo" : "moveTo"](cx + Math.cos(a - Math.PI / 2) * d, cy + Math.sin(a - Math.PI / 2) * d); }
    ctx.closePath(); ctx.fill();
  }
  return ctx.getImageData(0, 0, size, size);
}
// A frame as a PNG data URL, for a picture that has to travel in a message.
async function dataUrl(image) {
  const canvas = new OffscreenCanvas(image.width, image.height);
  canvas.getContext("2d").putImageData(image, 0, 0);
  const blob = await canvas.convertToBlob({ type: "image/png" });
  return new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.onerror = reject; reader.readAsDataURL(blob); });
}
return { redEyeFrame, syncFrame, hopFrame, dataUrl };
})();
