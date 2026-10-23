// Account colors, shared by the popup and the settings page: the user's pick
// in the extension (preference `accountColors`), else the one set in the rbw
// config (`rbw account set --color`, reported by the native host), else a
// default from a fixed palette, assigned by the account's place in the sorted
// list of all configured accounts, so it doesn't shift when the selection
// changes.
const ACCOUNT_PALETTE = ["#6d9cff", "#f2a971", "#4cc38a", "#ff7ab6", "#e6c07b", "#5fd3e0", "#c58bff", "#ff7a6b"];
function accountColor(name, allNames, colors, cliColors) {
  for (const chosen of [colors?.[name], cliColors?.[name]]) if (typeof chosen === "string" && /^#[0-9a-f]{6}$/i.test(chosen)) return chosen;
  const index = Math.max(0, [...allNames || []].sort().indexOf(name));
  return ACCOUNT_PALETTE[index % ACCOUNT_PALETTE.length];
}
// Black or white, whichever reads better on `hex`.
function accountTextColor(hex) {
  const [r, g, b] = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16));
  return (0.299 * r + 0.587 * g + 0.114 * b) > 150 ? "#111" : "#fff";
}
