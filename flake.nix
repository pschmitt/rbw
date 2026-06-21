{
  description = "Unofficial Bitwarden CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
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

            nativeBuildInputs = [ pkgs.installShellFiles ];

            postInstall = ''
              install -Dm755 bin/git-credential-rbw -t "$out/bin"
              installShellCompletion --cmd rbw \
                --bash <("$out/bin/rbw" gen-completions bash) \
                --zsh <("$out/bin/rbw" gen-completions zsh) \
                --fish <("$out/bin/rbw" gen-completions fish)
            '';
          };

          default = rbw;
        }
      );

      overlays.default = final: _prev: {
        rbw = self.packages.${final.stdenv.hostPlatform.system}.default;
      };
    };
}
