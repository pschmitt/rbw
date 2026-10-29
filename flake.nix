{
  description = "Unofficial Bitwarden CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Builds dependencies in their own derivation, so CI caches and hosts
    # reuse them instead of recompiling every crate on each rbw change.
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      home-manager,
      crane,
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
      # Signing or changing a browser package must not rebuild the shared agent.
      rbwSource = nixpkgs.lib.fileset.toSource {
        root = ./.;
        fileset = nixpkgs.lib.fileset.unions [
          ./Cargo.toml
          ./Cargo.lock
          ./src
          ./bin
          ./assets/rbw.png
          ./LICENSE
          ./README.md
          ./CHANGELOG.md
        ];
      };
    in
    {
      # Linux package builds and checks run on the self-hosted nixbot.
      hydraJobs = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system: {
        # The Android NDK used by rbw-termux only runs on x86_64 Linux.
        packages = builtins.removeAttrs self.packages.${system} (
          nixpkgs.lib.optional (system != "x86_64-linux") "rbw-termux"
        );
        checks = self.checks.${system} or { };
      });

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          craneLib = crane.mkLib pkgs;
          # rbw's own version, normalized out of everything the dependency build
          # sees, so a release bump keeps that derivation (and its caches).
          inherit (cargoToml.package) version;
          depsLock = builtins.toFile "Cargo.lock" (
            builtins.replaceStrings
              [ "name = \"rbw\"\nversion = \"${version}\"" ]
              [ "name = \"rbw\"\nversion = \"0.0.0\"" ]
              (builtins.readFile ./Cargo.lock)
          );
          craneArgs = {
            pname = "rbw";
            inherit version;
            src = rbwSource;
            strictDeps = true;
            # Shared by both builds: vendored crates don't depend on rbw's version.
            cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = depsLock; };
            # WebAuthn/FIDO2 2FA login; links libudev on Linux.
            cargoExtraArgs = "--locked --features fido2";
            nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.pkg-config ];
            buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.udev ];
          };
          depsToml = builtins.toFile "Cargo.toml" (
            builtins.replaceStrings
              [ "name = \"rbw\"\nversion = \"${version}\"" ]
              [ "name = \"rbw\"\nversion = \"0.0.0\"" ]
              (builtins.readFile ./Cargo.toml)
          );
          # Built only from the normalized manifests (eval-time files) and stub
          # targets, unlike crane's mkDummySrc, which also copies the raw ones.
          depsSrc = pkgs.runCommand "rbw-deps-src" { } ''
            mkdir -p $out/src/bin/rbw $out/src/bin/rbw-agent $out/src/bin/rbw-browser $out/src/bin/rbw-unlockd
            cp ${depsToml} $out/Cargo.toml
            cp ${depsLock} $out/Cargo.lock
            for bin in rbw rbw-agent rbw-browser rbw-unlockd; do
              echo 'fn main() {}' > $out/src/bin/$bin/main.rs
            done
            touch $out/src/lib.rs
          '';
          rbwDeps = craneLib.buildDepsOnly (
            # dummySrc replaces src; passing both makes crane warn.
            builtins.removeAttrs craneArgs [ "src" ]
            // {
              pname = "rbw-deps";
              version = "0";
              dummySrc = depsSrc;
            }
          );
          rbw = craneLib.buildPackage (
            craneArgs
            // {
              cargoArtifacts = rbwDeps;
              # The test suite still runs here, reusing the cached dependencies.
              doCheck = true;

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
            }
          );

          rbwTermux =
            let
              androidPkgs =
                (import nixpkgs {
                  inherit system;
                  config = {
                    allowUnfree = true;
                    android_sdk.accept_license = true;
                  };
                }).pkgsCross.aarch64-android-prebuilt;
              androidRbw = androidPkgs.rustPlatform.buildRustPackage {
                pname = "rbw";
                inherit (cargoToml.package) version;

                src = rbwSource;
                cargoLock.lockFile = ./Cargo.lock;
                cargoBuildFlags = [ "--no-default-features" ];
                RUSTFLAGS = nixpkgs.lib.concatStringsSep " " [
                  "-C link-arg=-Wl,-z,max-page-size=16384"
                  "-C link-arg=-Wl,-z,common-page-size=16384"
                ];
                doCheck = false;
              };
            in
            pkgs.runCommand "rbw-termux-${cargoToml.package.version}"
              {
                passthru.termuxNative = {
                  abi = "android-bionic";
                  files = [
                    "bin/rbw"
                    "bin/rbw-agent"
                    "bin/git-credential-rbw"
                    "share/bash-completion/completions/rbw"
                    "share/fish/vendor_completions.d/rbw.fish"
                    "share/zsh/site-functions/_rbw"
                    "share/licenses/rbw/LICENSE"
                  ];
                  binaries = [
                    "bin/rbw"
                    "bin/rbw-agent"
                  ];
                  scripts = [ "bin/git-credential-rbw" ];
                  trees = [ ];
                };
                meta = {
                  description = "Termux-native Android/Bionic build of the pschmitt rbw fork";
                  mainProgram = "rbw";
                  # The derivation executes on the Linux builder; its declared
                  # payload is Android/Bionic and is described by termuxNative.
                  platforms = pkgs.lib.platforms.linux;
                };
              }
              ''
                mkdir -p \
                  "$out/bin" \
                  "$out/share/bash-completion/completions" \
                  "$out/share/fish/vendor_completions.d" \
                  "$out/share/zsh/site-functions" \
                  "$out/share/licenses/rbw"
                install -m755 ${androidRbw}/bin/rbw "$out/bin/rbw"
                install -m755 ${androidRbw}/bin/rbw-agent "$out/bin/rbw-agent"
                sed '1c#!/data/data/com.termux/files/usr/bin/sh' \
                  ${rbw}/bin/git-credential-rbw > "$out/bin/git-credential-rbw"
                chmod 755 "$out/bin/git-credential-rbw"
                install -m644 ${rbw}/share/bash-completion/completions/rbw \
                  "$out/share/bash-completion/completions/rbw"
                install -m644 ${rbw}/share/fish/vendor_completions.d/rbw.fish \
                  "$out/share/fish/vendor_completions.d/rbw.fish"
                install -m644 ${rbw}/share/zsh/site-functions/_rbw \
                  "$out/share/zsh/site-functions/_rbw"
                install -m644 ${self}/LICENSE \
                  "$out/share/licenses/rbw/LICENSE"
              '';
        in
        {
          inherit rbw;

          # This output is built on Linux by Nix's Android cross set. Its
          # metadata describes files for the Termux bundle exporter, which
          # strips store paths and installs the files under the Termux prefix.
          default = rbw;
        }
        // (import ./nix/browser.nix { inherit pkgs rbw; })
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          rbw-gtk = craneLib.buildPackage (
            craneArgs
            // {
              pname = "rbw-gtk";
              cargoExtraArgs = "--locked --features fido2,gtk-ui";
              nativeBuildInputs = craneArgs.nativeBuildInputs ++ [ pkgs.wrapGAppsHook4 ];
              buildInputs = craneArgs.buildInputs ++ [ pkgs.gtk4 ];
              doCheck = true;
              postInstall = rbw.postInstall + ''
                install -Dm644 assets/rbw.png "$out/share/icons/hicolor/128x128/apps/rbw.png"
                install -Dm644 ${
                  pkgs.makeDesktopItem {
                    name = "org.rbw.Unlock";
                    desktopName = "Unlock rbw";
                    exec = "rbw unlock --ui gtk";
                    icon = "rbw";
                    categories = [
                      "Utility"
                      "Security"
                    ];
                    terminal = false;
                  }
                }/share/applications/org.rbw.Unlock.desktop "$out/share/applications/org.rbw.Unlock.desktop"
              '';
            }
          );
          rbw-termux = rbwTermux;
        }
      );

      overlays.default = final: _prev: {
        rbw = self.packages.${final.stdenv.hostPlatform.system}.default;
      };

      homeManagerModules.default = import ./nix/hm-module.nix { inherit self; };

      nixosModules.default = import ./nix/nixos-module.nix { inherit self; };

      # Smoke test: build a minimal home-manager configuration exercising
      # `programs.rbw`, and assert the rendered `config.yaml`
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
          mkHm =
            rbw:
            home-manager.lib.homeManagerConfiguration {
              inherit pkgs;
              modules = [
                self.homeManagerModules.default
                {
                  home = {
                    username = "rbw-test";
                    homeDirectory = "/build/rbw-test";
                    stateVersion = "24.05";
                  };
                  programs.rbw = rbw;
                }
              ];
            };
          rbwConfig = {
            enable = true;
            mcp = {
              enable = true;
              readOnly = true;
            };
            settings = {
              pinentry.command = "pinentry-gtk2";
              agent.lockTimeout = 120;
              unlockUi = "auto";
              unlockNoEcho = false;
              primaryAccount = "personal";
              accounts.personal = {
                email = "me@example.com";
                baseUrl.file = "/run/secrets/rbw-base-url";
              };
            };
          };
          hm = mkHm rbwConfig;
          # The old `programs.rbw.declarative` path, renamed to `programs.rbw`.
          hmLegacy = mkHm { declarative = rbwConfig; };
          renderedConfigFile = hm.config.programs.rbw.renderedConfigFile;
          mcpArgs = hm.config.programs.mcp.servers.rbw.args;
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
              unlockUi = "auto";
              unlockNoEcho = false;
              unlockFingerprint = "auto";
              unlockHideFingerprintNotice = false;
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
              passkeyCounter = false;
              clipboard = "auto";
              redact = false;
              defaultUriMatch = "domain";
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
          hm-module-mcp =
            assert
              mcpArgs == [
                "mcp"
                "--timeout"
                "120"
                "--read-only"
              ];
            pkgs.runCommand "rbw-hm-module-mcp-check" { } "touch $out";
          hm-module-legacy-path =
            assert hmLegacy.config.programs.rbw.renderedConfigFile == renderedConfigFile;
            assert hmLegacy.config.programs.mcp.servers.rbw.args == mcpArgs;
            pkgs.runCommand "rbw-hm-module-legacy-path-check" { } "touch $out";
        }
        // {
          inherit (self.packages.${system}) browser-daemon-extension;
        }
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # Evaluates (without building rbw) a NixOS system enabling
          # `services.rbw-unlockd` and checks the units it renders.
          nixos-module-unlockd =
            let
              nixos = nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [
                  self.nixosModules.default
                  {
                    services.rbw-unlockd.enable = true;
                    boot.loader.grub.enable = false;
                    fileSystems."/" = {
                      device = "none";
                      fsType = "tmpfs";
                    };
                    system.stateVersion = "24.05";
                  }
                ];
              };
              inherit (nixos.config.systemd) services sockets;
              execStart = builtins.unsafeDiscardStringContext services.rbw-unlockd.serviceConfig.ExecStart;
              listen = builtins.concatStringsSep " " sockets.rbw-unlockd.listenStreams;
            in
            pkgs.runCommand "rbw-nixos-module-check" { } ''
              [[ ${nixpkgs.lib.escapeShellArg execStart} == */bin/rbw-unlockd ]]
              [[ ${nixpkgs.lib.escapeShellArg listen} == /run/rbw-unlockd.sock ]]
              [[ ${nixpkgs.lib.boolToString nixos.config.services.fprintd.enable} == true ]]
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
            packages = [
              pkgs.just
              pkgs.cargo
              pkgs.rustc
              pkgs.clippy
              pkgs.rustfmt
              pkgs.cargo-deny
              pkgs.nixfmt
              pkgs.statix
              pkgs.deadnix
            ];
          };
          gtk = pkgs.mkShell {
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [
              pkgs.gtk4
              pkgs.openssl
              pkgs.udev
            ];
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.clippy
              pkgs.rustfmt
              pkgs.binutils
            ];
          };
        }
      );
    };
}
