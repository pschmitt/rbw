# Nix

The flake builds rbw, its browser extension and the native messaging host, and
ships a Home Manager module that renders rbw's `config.yaml`.

```nix
inputs.rbw.url = "github:pschmitt/rbw";
```

`main` carries unreleased changes; its pinned browser packages (release assets,
fetched by hash) are those of the last release, which may lag behind its
extension source. Pin a tag (`github:pschmitt/rbw/vX.Y.Z`) for a release.

## Flake outputs

| Output | Contents |
|---|---|
| `packages.<system>.default` (`rbw`) | `rbw`, `rbw-agent`, `rbw-browser`, `rbw-unlockd`, `git-credential-rbw` and shell completions |
| `packages.<system>.firefox-addon` | The AMO-signed Firefox add-on (`passthru.addonId`) |
| `packages.<system>.chromium-addon` | The signed Chromium CRX (`passthru.extensionId`, `passthru.version`) |
| `packages.<system>.browser-native-host` | Native messaging manifests for Firefox and Chromium, pointing at `rbw-browser` |
| `packages.<system>.rbw-termux` | A native Android (Termux) build |
| `overlays.default` | Sets `pkgs.rbw` to this flake's package |
| `homeManagerModules.default` | `programs.rbw.declarative` |
| `nixosModules.default` | `services.rbw-unlockd`, the fingerprint-enforcing unlock broker (see [desktop-unlock.md](desktop-unlock.md)) |

The package builds with [crane](https://github.com/ipetkov/crane): rbw's
dependencies are a separate derivation that only changes with `Cargo.lock` or
the toolchain, not with rbw's own sources or version, so updating rbw reuses
them. The build still runs the full test suite.

To replace nixpkgs' rbw everywhere, add the overlay:

```nix
nixpkgs.overlays = [ inputs.rbw.overlays.default ];
```

## Home Manager

The module exposes `config.yaml` as Nix options (mirroring `Config` and
`Account` in `src/config.rs`) and installs rbw itself:

```nix
{
  imports = [ inputs.rbw.homeManagerModules.default ];

  programs.rbw.declarative = {
    enable = true;
    settings = {
      pinentry.command = "pinentry-gnome3";
      agent.lockTimeout = 3600;
      defaultUriMatch = "domain";
      primaryAccount = "personal";
      accounts.personal = {
        email = "me@example.com";
        baseUrl = "https://vault.bitwarden.com";
      };
    };
  };
}
```

This writes `~/.config/rbw/config.yaml` (or `$XDG_CONFIG_HOME/rbw/config.yaml`);
unset options are left out instead of being written as `null`. See the
module's option documentation (`home-manager option programs.rbw.declarative`
or your editor's Nix LSP) for every setting, including
`accounts.<name>.unlock`, `accounts.<name>.excludeFrom`, `accounts.<name>.color`, `tui.keys` and
`browser.clients`. `programs.rbw.declarative.package` selects the rbw package.

The options live under `programs.rbw.declarative` because Home Manager's own
minimal `programs.rbw` module already declares `programs.rbw.enable`,
`package` and `settings`. Use one or the other: only this module renders the
full configuration file.

rbw reads both `config.yaml` and the legacy `config.json`; `config.yaml` wins
when both exist, and `rbw config set`/`rbw config edit` write `config.yaml`.

## Browser extension

The extension needs three things: the add-on, the native messaging host, and
an entry in rbw's `browser.clients` allowlist (access is denied without one).
Install `rbw`, `rbw-agent` and `rbw-browser` from the same flake revision.

```nix
let
  rbwPkgs = inputs.rbw.packages.${pkgs.stdenv.hostPlatform.system};
in
```

### Firefox

On NixOS, install the add-on through a policy and register the host:

```nix
programs.firefox = {
  enable = true;
  nativeMessagingHosts.packages = [ rbwPkgs.browser-native-host ];
  policies.ExtensionSettings."rbw-browser@pschmitt.dev" = {
    installation_mode = "normal_installed";
    # A new store path on every update triggers Firefox's managed update.
    install_url = "file://${rbwPkgs.firefox-addon}/rbw-browser@pschmitt.dev.xpi";
    updates_disabled = true;
  };
};
```

With Home Manager's Firefox module, add `rbwPkgs.firefox-addon` to a profile's
`extensions.packages` and `rbwPkgs.browser-native-host` to
`programs.firefox.nativeMessagingHosts` instead.

### Chromium

With Home Manager (NixOS's `programs.chromium` only takes extension IDs from
the Chrome Web Store):

```nix
programs.chromium = {
  enable = true;
  nativeMessagingHosts = [ rbwPkgs.browser-native-host ];
  extensions = [
    {
      id = rbwPkgs.chromium-addon.extensionId;
      crxPath = "${rbwPkgs.chromium-addon}/rbw.crx";
      inherit (rbwPkgs.chromium-addon) version;
    }
  ];
};
```

### Allowing the browser

The native host only answers browsers whose executable lives under an allowed
root and whose extension ID is listed. Browser updates change the store path,
so declare it with the browser packages themselves:

```nix
programs.rbw.declarative.settings.browser.clients = {
  firefox = {
    browser = "firefox";
    extensions = [ "rbw-browser@pschmitt.dev" ];
    # Native messaging wraps Firefox again: allow the final package and the
    # system one.
    executableRoots = [
      "${pkgs.firefox}"
      "${config.programs.firefox.finalPackage}"
    ];
  };
  chromium = {
    browser = "chromium";
    extensions = [ rbwPkgs.chromium-addon.extensionId ];
    executableRoots = [ "${pkgs.chromium.browser}" ];
  };
};
```

Restart the browser after the first install; Firefox may also ask you to accept
newly requested permissions after an update. See the
[browser reference](browser.md) for how the allowlist and permissions work.
