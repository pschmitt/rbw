# NixOS module for rbw-unlockd, the system service that holds native unlock
# credentials for `rbw security unlock enroll --broker` and releases them
# only after fprintd verifies a finger of the user asking (see
# `src/unlockd.rs`). It runs as root so the credentials are out of reach
# of the users it serves; it is socket-activated on /run/rbw-unlockd.sock.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkDefault
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  cfg = config.services.rbw-unlockd;
in
{
  options.services.rbw-unlockd = {
    enable = mkEnableOption "rbw-unlockd, the fingerprint-enforcing rbw unlock broker";
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "rbw.packages.\${system}.default";
      description = "The rbw package providing `rbw-unlockd`.";
    };
  };

  config = mkIf cfg.enable {
    # Fingerprint verification, and the TPM for the default `tpm2` store.
    services.fprintd.enable = mkDefault true;
    security.tpm2.enable = mkDefault true;

    systemd.sockets.rbw-unlockd = {
      description = "rbw unlock broker socket";
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/rbw-unlockd.sock" ];
      # Any local user may ask; the service tells them apart by their
      # socket peer credentials.
      socketConfig.SocketMode = "0666";
    };

    systemd.services.rbw-unlockd = {
      description = "rbw unlock broker";
      requires = [ "rbw-unlockd.socket" ];
      after = [ "rbw-unlockd.socket" ];
      # systemd-creds seals and unseals `tpm2` credentials.
      path = [ config.systemd.package ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/rbw-unlockd";
        StateDirectory = "rbw-unlockd";
        StateDirectoryMode = "0700";
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "full";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateNetwork = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
