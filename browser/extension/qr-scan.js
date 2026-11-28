/* Read a 2FA QR code shown on the current page, as Bitwarden's "Scan
 * authenticator QR code": capture the visible part of the active tab and
 * decode it with the bundled jsQR (vendor/jsQR.js). Nothing leaves the
 * browser. */
const otpUriPattern = /^(otpauth:\/\/totp\/|steam:\/\/)/i;

// The tab to read: the active web page of the current window, or of the last
// focused one when the vault runs in its own window or the sidebar.
async function qrScanTab(api) {
  for (const query of [{ active: true, currentWindow: true }, { active: true, lastFocusedWindow: true }]) {
    let tab;
    try { [tab] = await api.tabs.query(query); } catch (_) { continue; }
    if (/^https?:\/\//.test(tab?.url || "")) return tab;
  }
  throw new Error("Open the page that shows the QR code first.");
}

function qrDecode(image, scale) {
  const width = Math.max(1, Math.round(image.naturalWidth * scale)), height = Math.max(1, Math.round(image.naturalHeight * scale));
  const canvas = document.createElement("canvas"); canvas.width = width; canvas.height = height;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.imageSmoothingEnabled = scale !== 1;
  context.drawImage(image, 0, 0, width, height);
  // Dark-mode pages may draw the code light on dark: try both.
  return jsQR(context.getImageData(0, 0, width, height).data, width, height, { inversionAttempts: "attemptBoth" })?.data || null;
}

// Returns the QR code's text. Rejects when the page shows none, or one that is
// not a TOTP key.
async function scanPageQr(api) {
  const tab = await qrScanTab(api);
  let url;
  try { url = await api.tabs.captureVisibleTab(tab.windowId, { format: "png" }); } catch (error) {
    throw new Error("Could not capture the page to look for a QR code.", { cause: error });
  }
  const image = new Image(); image.src = url; await image.decode();
  // Full size first; a high-DPI capture can be too fine for the locator, so
  // retry at half size.
  let text = null;
  for (const scale of [1, 0.5]) if ((text = qrDecode(image, scale))) break;
  if (!text) throw new Error("No QR code found on the visible part of the page. Scroll it into view and try again.");
  text = text.trim();
  if (!otpUriPattern.test(text)) throw new Error("The QR code on this page is not a TOTP key (otpauth://totp/…).");
  return text;
}
