{
  description = "Unofficial Bitwarden CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      home-manager,
    }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        rec {
          rbw = pkgs.rustPlatform.buildRustPackage {
            pname = "rbw";
            inherit (cargoToml.package) version;

            src = self;
            cargoLock.lockFile = ./Cargo.lock;

            postInstall = ''
              install -Dm755 bin/git-credential-rbw -t "$out/bin"
              mkdir -p \
                "$out/share/bash-completion/completions" \
                "$out/share/fish/vendor_completions.d" \
                "$out/share/zsh/site-functions"
              "$out/bin/rbw" completions bash \
                > "$out/share/bash-completion/completions/rbw"
              "$out/bin/rbw" completions fish \
                > "$out/share/fish/vendor_completions.d/rbw.fish"
              "$out/bin/rbw" completions zsh \
                > "$out/share/zsh/site-functions/_rbw"
            '';
          };

          default = rbw;
        }
      );

      overlays.default = final: _prev: {
        rbw = self.packages.${final.stdenv.hostPlatform.system}.default;
      };

      homeManagerModules.default = import ./nix/hm-module.nix { inherit self; };

      # Smoke test: build a minimal home-manager configuration exercising
      # `programs.rbw.declarative`, and assert the rendered `config.json` matches what
      # we expect (field naming, kebab-case `unlock` enum, `accounts`
      # attrsOf->list conversion, null-stripping). Config rendering happens
      # in a `home.activation` script (not `xdg.configFile`, since it needs
      # to resolve `_secret` markers from disk at activation time -- see
      # `nix/hm-module.nix`), so the check actually runs that script rather
      # than reading a Nix-store-rendered file.
      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          hm = home-manager.lib.homeManagerConfiguration {
            inherit pkgs;
            modules = [
              self.homeManagerModules.default
              {
                home = {
                  username = "rbw-test";
                  homeDirectory = "/build/rbw-test";
                  stateVersion = "24.05";
                };
                programs.rbw.declarative = {
                  enable = true;
                  settings = {
                    pinentry = "pinentry-gtk2";
                    lock_timeout = 120;
                    primary_account = "personal";
                    accounts.personal = {
                      email = "me@example.com";
                      base_url = "https://vault.example.com";
                    };
                  };
                };
              }
            ];
          };
          activationScript = hm.config.home.activation.rbw-config.data;
          configFile = "${hm.config.xdg.configHome}/rbw/config.json";
          expected =
            builtins.toJSON {
              pinentry = "pinentry-gtk2";
              pinentry_timeout = 300;
              lock_timeout = 120;
              sync_interval = 3600;
              primary_account = "personal";
              accounts = [
                {
                  name = "personal";
                  email = "me@example.com";
                  base_url = "https://vault.example.com";
                  unlock = {
                    policy = "on-demand";
                  };
                  exclude_from = [ ];
                }
              ];
              hide_archived = true;
              hide_trashed = true;
              clipboard = "auto";
              tui_keybindings = { };
              tui_lock_timeout = 0;
            }
            + "\n";
        in
        {
          hm-module-config-json =
            pkgs.runCommand "rbw-hm-module-check" { nativeBuildInputs = [ pkgs.jq ]; }
              ''
                ${activationScript}
                jq . > expected.json <<'EXPECTED_EOF'
                ${expected}
                EXPECTED_EOF
                diff -u expected.json '${configFile}'
                touch "$out"
              '';
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              just
              cargo
              rustc
              clippy
              rustfmt
              cargo-deny
              nixfmt-rfc-style
            ];
          };
        }
      );
    };
}
