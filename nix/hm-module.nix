# Home Manager module exposing rbw's `config.yaml` as declarative Nix
# options. Kept in sync with `src/config.rs` — every field of `Config` and
# `Account` there should have a corresponding option here.
#
# Parameterized over the flake's `self` so `package` can default to this
# flake's own build, mirroring `overlays.default` in `flake.nix`.
#
# NOTE on the option path: home-manager itself now ships a built-in (and
# unconditionally-imported) `programs.rbw` module -- a thin, freeform-typed
# installer (see upstream `modules/programs/rbw.nix`). Its `enable`,
# `package`, and `settings` options are therefore already declared before
# this module ever loads, and the module system forbids re-declaring an
# option's `type`/`default` a second time ("... is already declared in
# ..."). To avoid that collision (and to avoid two different, confusingly
# similar `settings` options coexisting under the same `programs.rbw.*`
# prefix -- one freeform and effectively unused, one fully typed), this
# module lives under the sibling path `programs.rbw.declarative.*` instead
# of `programs.rbw.*` directly. It is fully independent of upstream's
# `programs.rbw.enable`/`.settings`: enabling this module does not touch
# those, and vice versa. Don't set both `programs.rbw.settings` (upstream)
# and `programs.rbw.declarative.enable` (this module) at once -- only this
# module actually renders rbw's configuration file.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    types
    ;

  # Provides `genJqSecretsReplacementSnippet`: given a Nix value containing
  # `{ _secret = "/path/to/file"; }` markers anywhere inside it (including
  # nested inside lists), generates a shell snippet that renders the value to
  # JSON with each marker replaced by that file's contents, read at
  # activation time rather than baked into the Nix store. Used below so
  # account fields like `email`/`baseUrl` can point at a sops-nix secret
  # instead of embedding the value in `config.yaml` -- mirrors the same
  # `_secret` convention used for `glab`'s config in this repo (see
  # modules/home-manager/glab.nix).
  utils = import "${pkgs.path}/nixos/lib/utils.nix" {
    inherit lib config pkgs;
  };

  cfg = config.programs.rbw.declarative;

  # Recursively drop `null` values from attrsets (including those nested
  # inside lists), so unset `Option<T>` fields are omitted from the
  # generated YAML instead of being written out as explicit `null` --
  # matching the `#[serde(skip_serializing_if = "Option::is_none")]"`
  # behavior of the corresponding fields in `src/config.rs`.
  filterNulls =
    v:
    if builtins.isAttrs v then
      let
        filtered = lib.filterAttrs (_: x: x != null) (lib.mapAttrs (_: filterNulls) v);
      in
      if filtered == { } then null else filtered
    else if builtins.isList v then
      if v == [ ] then null else map filterNulls v
    else
      v;

  isDefaultPasswordGen =
    pg: pg.length == null && !pg.noSymbols && !pg.onlyNumbers && !pg.nonconfusables && !pg.diceware;

  mkNullOrStr =
    description:
    mkOption {
      type = types.nullOr types.str;
      default = null;
      inherit description;
    };

  # A `{ _secret = "/path/to/file"; }` marker, resolved at activation time by
  # `utils.genJqSecretsReplacementSnippet` (see `utils` above) into that
  # file's contents -- e.g. a sops-nix secret's `config.sops.secrets.<name>.path`.
  secretRef = types.submodule {
    options._secret = mkOption {
      type = types.either types.str types.path;
      description = ''
        Path to a file whose contents become this value, resolved at
        activation time instead of being embedded in the Nix store (e.g. a
        sops-nix secret's `.path`).
      '';
    };
  };

  # Like `mkNullOrStr`, but also accepts a `secretRef` so the value can be
  # sourced from a file (e.g. a sops-nix secret) instead of being written
  # literally into the Nix store copy of rbw's configuration.
  mkNullOrStrOrSecret =
    description:
    mkOption {
      type = types.nullOr (types.either types.str secretRef);
      default = null;
      inherit description;
    };

  mkNullOrPath =
    description:
    mkOption {
      type = types.nullOr types.path;
      default = null;
      inherit description;
    };

  mkNullOrInt =
    description:
    mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      inherit description;
    };

  # A single Bitwarden/Vaultwarden account. Mirrors `Account` in
  # `src/config.rs`. Keyed by attribute name in `settings.accounts`, which
  # doubles as the account's `name` field unless overridden.
  accountModule = types.submodule (
    { name, ... }:
    {
      options = {
        name = mkOption {
          type = types.str;
          default = name;
          description = ''
            Stable local identifier used by `--account` and the agent;
            unrelated to the email/server. Defaults to the attribute name.
          '';
        };
        email = mkNullOrStrOrSecret "The email address to log into this account with.";
        ssoId = mkNullOrStrOrSecret "The SSO organization ID for this account. Defaults to the regular login process if unset.";
        baseUrl = mkNullOrStrOrSecret "The URL of the Bitwarden/Vaultwarden server for this account. Defaults to the official Bitwarden server if unset.";
        identityUrl = mkNullOrStrOrSecret "The identity server URL for this account. Defaults to the `/identity` path on `baseUrl`, or the official server, if unset.";
        uiUrl = mkNullOrStrOrSecret "The vault UI URL for this account. Defaults to the official Bitwarden vault UI if unset.";
        notificationsUrl = mkNullOrStrOrSecret "The notifications server URL for this account. Defaults to the `/notifications` path on `baseUrl`, or the official server, if unset.";
        clientCertPath = mkNullOrPath "Path to a client certificate to present to the server for this account, if required.";
        # See `UnlockConfig` in `src/config.rs`.
        unlock = mkOption {
          type = types.submodule {
            options = {
              policy = mkOption {
                type = types.enum [
                  "always"
                  "never"
                  "on-demand"
                ];
                default = "on-demand";
                description = ''
                  Whether `list`/`search`/`get` should proactively unlock
                  this account (prompting as needed) when merging entries
                  across every configured account:

                  - `always`: always unlock this account for a merge, even
                    on a plain `rbw list` with no `--all`.
                  - `never`: never proactively unlock this account for a
                    merge, not even with `--all`; only included if already
                    unlocked.
                  - `on-demand` (default): included in a merge only if
                    already unlocked; `--all` unlocks it too.
                '';
              };
              # See `CredentialSource`.
              credentials = mkOption {
                type = types.nullOr (
                  types.submodule {
                    options = {
                      account = mkOption {
                        type = types.str;
                        description = ''
                          Name of the *other* configured account whose vault
                          holds this account's master password. Must not be
                          this account's own name, and must not form a cycle
                          with other accounts' `unlock.credentials`.
                        '';
                      };
                      item = mkOption {
                        type = types.nullOr types.str;
                        default = null;
                        description = ''
                          Optional name of the Login item in that account's
                          vault holding this account's master password
                          (matched the same way as an `rbw get NAME` lookup).
                          When unset, rbw tries to find a unique Login item
                          whose URI matches this account's server URL
                          instead.
                        '';
                      };
                    };
                  }
                );
                default = null;
                description = ''
                  Points at a Login item, in another configured account's
                  vault, that holds this account's master password. Used by
                  the agent's unlock flow to skip the pinentry prompt: the
                  source account is unlocked (recursively, if it itself has
                  `unlock.credentials` set), the named item is looked up in
                  its vault and its `password` field is used as this
                  account's master password. If `item` is unset, rbw tries
                  to find a unique URI match for this account's server URL
                  instead. Mirrors `Option<CredentialSource>` in
                  `src/config.rs`. Unset (`null`, the default) means this
                  account is unlocked normally via pinentry. See `rbw
                  account set
                  --credential-source-account/--credential-source-item`, or
                  the equivalent TUI accounts-panel action.
                '';
              };
              termux = mkOption {
                type = types.nullOr (
                  types.submodule {
                    options = {
                      file = mkOption {
                        type = types.path;
                        description = ''
                          Path to the encrypted master-password bundle
                          produced by `rbw termux enroll`.
                        '';
                      };
                      keyAlias = mkOption {
                        type = types.str;
                        description = ''
                          Android Keystore alias of the authentication-gated
                          signing key used to unlock this account.
                        '';
                      };
                      algorithm = mkOption {
                        type = types.str;
                        default = "SHA256withRSA";
                        description = ''
                          Termux Keystore signature algorithm, matching the
                          configured RSA or EC key.
                        '';
                      };
                    };
                  }
                );
                default = null;
                description = ''
                  Unlock this account using an authentication-gated Android
                  Keystore signing key through Termux. Mirrors
                  `TermuxKeystoreUnlock` in `src/config.rs`.
                '';
              };
            };
          };
          default = { };
          description = ''
            This account's unlock policy and (optionally) where its master
            password comes from. Mirrors `UnlockConfig` in `src/config.rs`.
          '';
        };
        # See `ExcludeContext` in `src/config.rs`.
        excludeFrom = mkOption {
          type = types.listOf (
            types.enum [
              "list"
              "search"
              "get"
              "show"
              "code"
              "sync"
              "unlock"
              "tui"
              "all"
            ]
          );
          default = [ ];
          description = ''
            Hard opt-out: skip this account for the listed commands (even if
            unlocked, even with that command's own `--all`). `"all"` is a
            magic value equivalent to listing every other one. Still
            reachable via `--account <name>` directly (or, for `"tui"`, via
            `rbw tui --account <name>`) regardless of what it's excluded
            from.
          '';
        };
      };
    }
  );

  # Top-level `Config` fields from `src/config.rs`.
  settingsModule = types.submodule {
    options = {
      # ---- accounts --------------------------------------------------------
      accounts = mkOption {
        type = types.attrsOf accountModule;
        default = { };
        description = ''
          Configured Bitwarden/Vaultwarden accounts, keyed by account name
          (used as the account's `name` field unless overridden). Rendered
          to the YAML `accounts` array; note that array order in the
          rendered config follows attribute-name (alphabetical) order, so
          if `primaryAccount` is unset, the alphabetically-first account
          name becomes primary rather than any particular insertion order --
          set `primaryAccount` explicitly when configuring more than one
          account to avoid relying on this.
        '';
      };
      primaryAccount = mkNullOrStr ''
        Name of the primary account; defaults to the first account (see the
        `accounts` ordering caveat above) when unset.
      '';

      # ---- grouped global preferences ---------------------------------
      agent = mkOption {
        type = types.submodule {
          options = {
            syncInterval = mkOption {
              type = types.ints.unsigned;
              default = 3600;
              description = ''
                `rbw` automatically syncs the database at this many seconds
                while the agent is running. `0` disables this behavior.
              '';
            };
            lockTimeout = mkOption {
              type = types.ints.unsigned;
              default = 3600;
              description = ''
                Seconds to keep master keys in memory before requiring the
                password again.
              '';
            };
          };
        };
        default = { };
        description = "Agent synchronization and key-retention settings.";
      };
      pinentry = mkOption {
        type = types.submodule {
          options = {
            command = mkOption {
              type = types.str;
              default = "pinentry";
              description = "The pinentry executable to use.";
            };
            timeout = mkOption {
              type = types.ints.unsigned;
              default = 300;
              description = ''
                Seconds pinentry waits before giving up. `0` disables the
                timeout and makes pinentry wait forever.
              '';
            };
          };
        };
        default = { };
        description = "Pinentry command and timeout settings.";
      };
      termux = mkOption {
        type = types.submodule {
          options.keyAlias = mkNullOrStr ''
            Default Android Keystore alias for `rbw termux enroll` and other
            native Termux unlock operations. `RBW_TERMUX_KEY_ALIAS` overrides
            this value at runtime.
          '';
        };
        default = { };
        description = "Global Termux Keystore settings.";
      };
      tui = mkOption {
        type = types.submodule {
          options = {
            keys = mkOption {
              type = types.attrsOf (types.listOf types.str);
              default = { };
              description = ''
                TUI keybinding overrides, keyed by camelCase action names
                such as `forceQuit` and `copyPassword`.
              '';
            };
            lockTimeout = mkOption {
              type = types.ints.unsigned;
              default = 0;
              description = ''
                Seconds of inactivity before the TUI locks. Zero disables
                the timeout; `rbw tui --screen-lock-timeout` overrides it.
              '';
            };
          };
        };
        default = { };
        description = "TUI keybindings and inactivity-lock settings.";
      };
      hide = mkOption {
        type = types.submodule {
          options = {
            archived = mkOption {
              type = types.bool;
              default = true;
              description = "Hide archived entries by default.";
            };
            trashed = mkOption {
              type = types.bool;
              default = true;
              description = "Hide trashed entries by default.";
            };
          };
        };
        default = { };
        description = "Default visibility settings for archived and trashed entries.";
      };
      clipboard = mkOption {
        type = types.enum [
          "auto"
          "system"
          "osc52"
        ];
        default = "auto";
        description = ''
          Which mechanism `-c`/`--clipboard` and the TUI's copy actions use
          to copy text: `system` copies via the system clipboard (X11/
          Wayland/macOS, through the `rbw-agent`); `osc52` writes an OSC 52
          terminal escape sequence to the client's own stdout instead,
          which works over SSH and in terminals without display-server
          access, provided the terminal (or multiplexer) supports it;
          `auto` tries both and succeeds if either one does.
        '';
      };
      # Mirrors `PasswordGenPolicy` in `src/config.rs`.
      passwordGen = mkOption {
        type = types.submodule {
          options = {
            length = mkNullOrInt ''
              Default password length for `rbw gen`/`rbw create --generate`
              when not overridden on the command line. Unset (`null`)
              leaves the built-in default length in place.
            '';
            noSymbols = mkOption {
              type = types.bool;
              default = false;
              description = ''
                Default `--no-symbols` behavior for `rbw gen`/`rbw create
                --generate` when not overridden on the command line.
              '';
            };
            onlyNumbers = mkOption {
              type = types.bool;
              default = false;
              description = ''
                Default `--only-numbers` behavior for `rbw gen`/`rbw create
                --generate` when not overridden on the command line.
              '';
            };
            nonconfusables = mkOption {
              type = types.bool;
              default = false;
              description = ''
                Default `--nonconfusables` behavior for `rbw gen`/`rbw
                create --generate` when not overridden on the command line.
              '';
            };
            diceware = mkOption {
              type = types.bool;
              default = false;
              description = ''
                Default `--diceware` behavior for `rbw gen`/`rbw create
                --generate` when not overridden on the command line.
              '';
            };
          };
        };
        default = { };
        description = ''
          Default password-generation policy for `rbw gen` and `rbw create
          --generate`, used whenever a given flag isn't passed explicitly
          on the command line. Mirrors `PasswordGenPolicy` in
          `src/config.rs`. Also editable from the TUI's settings view.
        '';
      };
    };
  };
in
{
  options.programs.rbw.declarative = {
    enable = mkEnableOption "rbw, the unofficial Bitwarden CLI, with a fully declarative config.yaml";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "The rbw package to install.";
    };

    settings = mkOption {
      type = settingsModule;
      default = { };
      description = ''
        Contents of rbw's `config.yaml`, mirroring `Config` in
        `src/config.rs`. Written to
        `$XDG_CONFIG_HOME/rbw/config.yaml` (typically
        `~/.config/rbw/config.yaml`); unset (`null`) options are omitted
        from the generated file rather than written as explicit `null`.
      '';
    };
  };

  config = mkIf cfg.enable (
    let
      rendered = filterNulls (
        cfg.settings
        // {
          accounts = lib.attrValues cfg.settings.accounts;
          passwordGen =
            if isDefaultPasswordGen cfg.settings.passwordGen then null else cfg.settings.passwordGen;
        }
      );
      configFile = "${config.xdg.configHome}/rbw/config.yaml";
      configJson = "${config.xdg.configHome}/rbw/config.json.tmp";
    in
    {
      home.packages = [ cfg.package ];

      # Rendered via an activation script (rather than `xdg.configFile`,
      # which would symlink into the world-readable Nix store) so that any
      # `_secret` markers in `rendered` -- see `secretRef` above -- get
      # resolved from their source file at activation time instead of
      # having their value embedded in the store. Mirrors the `_secret`
      # convention used for `glab`'s config in this repo (see
      # modules/home-manager/glab.nix).
      home.activation.rbw-config = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
        $DRY_RUN_CMD mkdir -p "$(dirname '${configFile}')"
        $DRY_RUN_CMD rm -f '${configFile}' '${configJson}'
        if [[ -z "''${DRY_RUN_CMD:-}" ]]
        then
          umask 077
          ${utils.genJqSecretsReplacementSnippet rendered configJson}
          ${pkgs.yq-go}/bin/yq -P '.' '${configJson}' > '${configFile}'
          rm -f '${configJson}'
          chmod 600 '${configFile}'
        fi
      '';
    }
  );
}
