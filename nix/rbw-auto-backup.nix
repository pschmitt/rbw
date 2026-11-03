# SPDX-License-Identifier: GPL-3.0-only
# Part of rbw-auto (auto/), licensed GPL-3.0 unlike the rest of rbw; see auto/LICENSE.
{
  lib,
  stdenvNoCC,
  makeWrapper,
  bash,
  coreutils,
  curl,
  findutils,
  gnupg,
  oath-toolkit,
  rbw,
}:

stdenvNoCC.mkDerivation {
  pname = "rbw-auto-backup";
  inherit (rbw) version;
  # Only what the package installs, so docs or Docker changes don't rebuild it.
  src = lib.fileset.toSource {
    root = ../auto;
    fileset = lib.fileset.unions [
      ../auto/rbw-auto-backup.sh
      ../auto/lib.sh
    ];
  };

  nativeBuildInputs = [ makeWrapper ];
  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall

    install -Dm755 "$src/rbw-auto-backup.sh" "$out/bin/rbw-auto-backup"
    install -Dm644 "$src/lib.sh" "$out/bin/lib.sh"

    runHook postInstall
  '';

  postInstall = ''
    patchShebangs "$out/bin"
    wrapProgram "$out/bin/rbw-auto-backup" \
      --prefix PATH : ${
        lib.makeBinPath [
          bash
          coreutils
          curl
          findutils
          gnupg
          oath-toolkit
          rbw
        ]
      }
  '';

  meta = {
    description = "Bitwarden/Vaultwarden backup helper, built on rbw";
    homepage = "https://github.com/pschmitt/rbw/blob/main/docs/auto.md";
    license = lib.licenses.gpl3Only;
    mainProgram = "rbw-auto-backup";
    platforms = lib.platforms.unix;
  };
}
