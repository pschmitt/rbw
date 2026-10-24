# Browser packages share the same rbw derivation as the CLI and agent.
{ pkgs, rbw }:
let
  # The extension shares rbw's version (see browser/build.py).
  inherit (rbw) version;
  metadata = builtins.fromJSON (builtins.readFile ../browser/packages/metadata.json);
  # The signed packages are release assets, pinned by hash in metadata.json
  # (the release workflow updates it after signing).
  releaseAsset =
    file: sha256:
    pkgs.fetchurl {
      url = "https://github.com/pschmitt/rbw/releases/download/v${metadata.version}/${file}";
      inherit sha256;
    };
  firefoxXpi = releaseAsset "rbw-browser-${metadata.version}-firefox.xpi" metadata.firefoxSha256;
  chromiumCrx = releaseAsset "rbw-browser-${metadata.version}-chromium.crx" metadata.chromiumSha256;
  firefoxId = "rbw-browser@pschmitt.dev";
  firefoxAppId = "{ec8030f7-c20a-464f-9b0e-13a3a9e97384}";
  hostName = "org.rbw.browser";
  json = pkgs.formats.json { };
  common = {
    name = hostName;
    description = "rbw-agent browser bridge";
    path = "${rbw}/bin/rbw-browser";
    type = "stdio";
  };
  firefoxManifest = json.generate "${hostName}-firefox.json" (
    common // { allowed_extensions = [ firefoxId ]; }
  );
  chromiumManifest = json.generate "${hostName}-chromium.json" (
    common // { allowed_origins = [ "chrome-extension://${metadata.chromiumId}/" ]; }
  );
in
{
  browser-native-host = pkgs.runCommand "rbw-browser-native-host-${version}" { } ''
    mkdir -p "$out/lib/mozilla/native-messaging-hosts" "$out/etc/chromium/native-messaging-hosts" "$out/lib/chromium/NativeMessagingHosts"
    ln -s ${firefoxManifest} "$out/lib/mozilla/native-messaging-hosts/${hostName}.json"
    ln -s ${chromiumManifest} "$out/etc/chromium/native-messaging-hosts/${hostName}.json"
    ln -s ${chromiumManifest} "$out/lib/chromium/NativeMessagingHosts/${hostName}.json"
  '';

  firefox-addon =
    pkgs.runCommand "rbw-firefox-addon-${metadata.version}"
      {
        passthru = {
          addonId = firefoxId;
          extid = firefoxId;
        };
      }
      ''
        mkdir -p "$out/share/mozilla/extensions/${firefoxAppId}"
        cp ${firefoxXpi} "$out/${firefoxId}.xpi"
        ln -s "$out/${firefoxId}.xpi" "$out/share/mozilla/extensions/${firefoxAppId}/${firefoxId}.xpi"
      '';

  # browser-daemon's live-view extension (browser/browser-daemon): the vault
  # popover and passkey prompt of its live view, in this extension's look.
  browser-daemon-extension =
    pkgs.runCommand "rbw-browser-daemon-extension-${version}"
      {
        nativeBuildInputs = [ pkgs.python3 ];
        src = pkgs.lib.fileset.toSource {
          root = ../.;
          fileset = pkgs.lib.fileset.unions [
            ../Cargo.toml
            ../browser/build.py
            ../browser/browser-daemon
            ../browser/extension/theme.css
            ../browser/extension/icons.js
            ../browser/extension/feedback.css
            ../browser/extension/feedback.js
            ../browser/extension/popup.css
            ../browser/extension/icons/rbw-64.png
            ../browser/extension/icons/rbw-48.png
          ];
        };
      }
      ''
        python3 "$src/browser/build.py" --browser-daemon "$out"
      '';

  chromium-addon =
    pkgs.runCommand "rbw-chromium-addon-${metadata.version}"
      {
        passthru = {
          extensionId = metadata.chromiumId;
          inherit (metadata) version;
        };
      }
      ''
        mkdir -p "$out"
        cp ${chromiumCrx} "$out/rbw.crx"
      '';
}
