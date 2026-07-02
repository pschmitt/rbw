# Home Manager module exposing rbw's `config.json` as declarative Nix
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
# module actually renders `config.json`.
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

  cfg = config.programs.rbw.declarative;

  # Recursively drop `null` values from attrsets (including those nested
  # inside lists), so unset `Option<T>` fields are omitted from the
  # generated JSON instead of being written out as explicit `null` --
  # matching the `#[serde(skip_serializing_if = "Option::is_none")]"`
  # behavior of the corresponding fields in `src/config.rs`.
  filterNulls =
    v:
    if builtins.isAttrs v then
      lib.mapAttrs (_: filterNulls) (lib.filterAttrs (_: x: x != null) v)
    else if builtins.isList v then
      map filterNulls v
    else
      v;

  mkNullOrStr =
    description:
    mkOption {
      type = types.nullOr types.str;
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
        email = mkNullOrStr "The email address to log into this account with.";
        sso_id = mkNullOrStr "The SSO organization ID for this account. Defaults to the regular login process if unset.";
        base_url = mkNullOrStr "The URL of the Bitwarden/Vaultwarden server for this account. Defaults to the official Bitwarden server if unset.";
        identity_url = mkNullOrStr "The identity server URL for this account. Defaults to the `/identity` path on `base_url`, or the official server, if unset.";
        ui_url = mkNullOrStr "The vault UI URL for this account. Defaults to the official Bitwarden vault UI if unset.";
        notifications_url = mkNullOrStr "The notifications server URL for this account. Defaults to the `/notifications` path on `base_url`, or the official server, if unset.";
        client_cert_path = mkNullOrPath "Path to a client certificate to present to the server for this account, if required.";
        unlock = mkOption {
          type = types.enum [
            "always"
            "never"
            "on-demand"
          ];
          default = "on-demand";
          description = ''
            Whether `list`/`search`/`get` should proactively unlock this
            account (prompting as needed) when merging entries across every
            configured account:

            - `always`: always unlock this account for a merge, even on a
              plain `rbw list` with no `--all`.
            - `never`: never proactively unlock this account for a merge,
              not even with `--all`; only included if already unlocked.
            - `on-demand` (default): included in a merge only if already
              unlocked; `--all` unlocks it too.
          '';
        };
        exclude_from_list = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Hard opt-out: never include this account's entries in a
            `list`/`search`/`get` merge across accounts (even if unlocked,
            even with `--all`). Still reachable via `--account <name>`
            directly.
          '';
        };
      };
    }
  );

  # Top-level `Config` fields from `src/config.rs`.
  settingsModule = types.submodule {
    options = {
      # ---- legacy single-account fields, retained for backward
      # compatibility; prefer `accounts` for new configs -------------------
      email = mkNullOrStr ''
        Legacy top-level email address. Retained for backward compatibility
        with configs predating multi-account support; prefer `accounts`.
      '';
      sso_id = mkNullOrStr "Legacy top-level SSO organization ID; prefer `accounts`.";
      base_url = mkNullOrStr "Legacy top-level server URL; prefer `accounts`.";
      identity_url = mkNullOrStr "Legacy top-level identity server URL; prefer `accounts`.";
      ui_url = mkNullOrStr "Legacy top-level vault UI URL; prefer `accounts`.";
      notifications_url = mkNullOrStr "Legacy top-level notifications server URL; prefer `accounts`.";
      client_cert_path = mkNullOrPath "Legacy top-level client certificate path; prefer `accounts`.";

      # ---- accounts --------------------------------------------------------
      accounts = mkOption {
        type = types.attrsOf accountModule;
        default = { };
        description = ''
          Configured Bitwarden/Vaultwarden accounts, keyed by account name
          (used as the account's `name` field unless overridden). Rendered
          to the JSON `accounts` array; note that array order in the
          rendered config follows attribute-name (alphabetical) order, so
          if `primary_account` is unset, the alphabetically-first account
          name becomes primary rather than any particular insertion order --
          set `primary_account` explicitly when configuring more than one
          account to avoid relying on this.
        '';
      };
      primary_account = mkNullOrStr ''
        Name of the primary account; defaults to the first account (see the
        `accounts` ordering caveat above) when unset.
      '';

      # ---- global preferences ------------------------------------------
      lock_timeout = mkOption {
        type = types.ints.unsigned;
        default = 3600;
        description = ''
          The number of seconds to keep the master keys in memory for
          before requiring the password to be entered again.
        '';
      };
      sync_interval = mkOption {
        type = types.ints.unsigned;
        default = 3600;
        description = ''
          `rbw` will automatically sync the database from the server at an
          interval of this many seconds, while the agent is running.
          Setting this to `0` disables this behavior.
        '';
      };
      pinentry = mkOption {
        type = types.str;
        default = "pinentry";
        description = "The pinentry executable to use.";
      };
      tui_keybindings = mkOption {
        type = types.attrsOf (types.listOf types.str);
        default = { };
        description = ''
          TUI keybinding overrides: action name (e.g. `copy_password`,
          `move_down`) to a list of key chord strings (e.g. `ctrl-y`,
          `alt-p`, `g`, `pagedown`) that fully replace that action's
          built-in default chords. Actions not listed here keep their
          defaults. See `src/bin/rbw/tui/keymap.rs` in the rbw source for
          the full action list and defaults.
        '';
      };
    };
  };
in
{
  options.programs.rbw.declarative = {
    enable = mkEnableOption "rbw, the unofficial Bitwarden CLI, with a fully declarative config.json";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "The rbw package to install.";
    };

    settings = mkOption {
      type = settingsModule;
      default = { };
      description = ''
        Contents of rbw's `config.json`, mirroring `Config` in
        `src/config.rs`. Written to
        `$XDG_CONFIG_HOME/rbw/config.json` (typically
        `~/.config/rbw/config.json`); unset (`null`) options are omitted
        from the generated file rather than written as explicit `null`.
      '';
    };
  };

  config = mkIf cfg.enable {
    home.packages = [ cfg.package ];

    xdg.configFile."rbw/config.json".text =
      let
        rendered = cfg.settings // {
          accounts = lib.attrValues cfg.settings.accounts;
        };
      in
      builtins.toJSON (filterNulls rendered) + "\n";
  };
}
