# Browser packages share the same rbw derivation as the CLI and agent.
{ pkgs, rbw }:
let
  version = "0.2.23";
  metadata = builtins.fromJSON (builtins.readFile ../browser/packages/metadata.json);
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
    pkgs.runCommand "rbw-firefox-addon-${version}"
      {
        passthru = {
          addonId = firefoxId;
          extid = firefoxId;
        };
      }
      ''
        mkdir -p "$out/share/mozilla/extensions/${firefoxAppId}"
        cp ${../browser/packages/rbw-firefox.xpi} "$out/${firefoxId}.xpi"
        ln -s "$out/${firefoxId}.xpi" "$out/share/mozilla/extensions/${firefoxAppId}/${firefoxId}.xpi"
      '';

  chromium-addon =
    pkgs.runCommand "rbw-chromium-addon-${version}"
      {
        passthru = {
          extensionId = metadata.chromiumId;
          inherit version;
        };
      }
      ''
        mkdir -p "$out"
        cp ${../browser/packages/rbw-chromium.crx} "$out/rbw.crx"
      '';
}
