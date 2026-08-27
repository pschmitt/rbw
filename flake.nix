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
      # `programs.rbw.declarative`, and assert the rendered `config.yaml`
      # matches what we expect (field naming, kebab-case `unlock` enum,
      # `accounts` attrsOf->list conversion, null-stripping, and a `file`
      # secretRef staying an unresolved `{file: ...}` reference rather than
      # being read). The module renders this purely from `cfg.settings` at
      # eval time (`renderedConfigFile`, exposed as an internal option for
      # exactly this reason) -- unlike the old `_secret`-marker convention
      # this replaced, nothing here needs a `home.activation` script or a
      # secret to actually exist on disk, so the check just reads the
      # rendered store path directly.
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
                    pinentry.command = "pinentry-gtk2";
                    agent.lockTimeout = 120;
                    primaryAccount = "personal";
                    accounts.personal = {
                      email = "me@example.com";
                      baseUrl.file = "/run/secrets/rbw-base-url";
                    };
                  };
                };
              }
            ];
          };
          renderedConfigFile = hm.config.programs.rbw.declarative.renderedConfigFile;
          expected =
            builtins.toJSON {
              agent = {
                syncInterval = 3600;
                lockTimeout = 120;
              };
              pinentry = {
                command = "pinentry-gtk2";
                timeout = 300;
              };
              primaryAccount = "personal";
              accounts = [
                {
                  name = "personal";
                  email = "me@example.com";
                  baseUrl.file = "/run/secrets/rbw-base-url";
                  unlock = {
                    policy = "on-demand";
                  };
                }
              ];
              tui = {
                lockTimeout = 0;
              };
              hide = {
                archived = true;
                trashed = true;
              };
              clipboard = "auto";
            }
            + "\n";
        in
        {
          hm-module-config-yaml =
            pkgs.runCommand "rbw-hm-module-check"
              {
                nativeBuildInputs = [ pkgs.jq ];
              }
              ''
                jq . '${renderedConfigFile}' > actual.json
                jq . > expected.json <<'EXPECTED_EOF'
                ${expected}
                EXPECTED_EOF
                diff -u expected.json actual.json
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
