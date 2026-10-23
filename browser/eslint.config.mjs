import js from "@eslint/js";
import globals from "globals";

// The extension is plain classic scripts (no bundler); vendored libraries
// are not ours to lint.
// Top-level functions shared between the scripts one page loads together
// (see the <script> tags in the .html files and background.scripts).
const shared = Object.fromEntries(
  ["icon", "accountColor", "accountTextColor", "confirmDialog", "confirmLock", "lockManagedControls",
   "fillPage", "undoPageFill", "showFillNotice", "marked", "DOMPurify", "importScripts"].map(name => [name, "readonly"]),
);

export default [
  { ignores: ["dist/**", "packages/**", "extension/vendor/**"] },
  js.configs.recommended,
  {
    files: ["extension/**/*.js"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "script",
      globals: { ...globals.browser, ...globals.webextensions, ...shared, browser: "readonly", chrome: "readonly" },
    },
    rules: {
      // Top-level declarations are the other scripts' API, so only locals
      // count; ignored catch bindings and arguments are deliberate.
      "no-unused-vars": ["error", { vars: "local", args: "none", caughtErrors: "none" }],
      "no-empty": ["error", { allowEmptyCatch: true }],
      "no-redeclare": ["error", { builtinGlobals: false }],
    },
  },
  {
    files: ["tests/**/*.mjs"],
    languageOptions: { ecmaVersion: 2023, sourceType: "module", globals: globals.node },
  },
];
