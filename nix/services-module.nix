# SPDX-License-Identifier: GPL-3.0-only
# Successor of the rbw-auto module (auto/), licensed GPL-3.0 like it; see auto/LICENSE.
# NixOS module for unattended rbw jobs: rotated vault backups
# (`rbw backup`) and a one-way mirror into another account
# (`rbw mirror --config`). The units run rbw directly. Accounts unlock
# without prompting from systemd credentials (`unlock.files` in rbw's
# config.json): the master password, an optional TOTP secret and, for a
# first login to bitwarden.com, the personal API key. Secrets never enter
# the Nix store or the environment.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib) mkOption types;

  cfg = config.services.rbw;

  secretPath = types.strMatching "/.+" // {
    description = "absolute path to a file outside the Nix store";
  };

  accountModule = types.submodule (
    { name, ... }:
    {
      options = {
        email = mkOption {
          type = types.str;
          description = "Email address of the account.";
        };

        baseUrl = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Server URL. Omit for the official bitwarden.com.";
          example = "https://vault.example.com";
        };

        ssoId = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "SSO organization ID, if the account uses SSO.";
        };

        passwordFile = mkOption {
          type = secretPath;
          description = "File holding the master password of account `${name}`.";
        };

        totpSecretFile = mkOption {
          type = types.nullOr secretPath;
          default = null;
          description = ''
            File holding the base32 TOTP secret of the account's two-step
            login, if it has one. A fresh code is generated for every login.
          '';
        };

        apiKey = {
          clientIdFile = mkOption {
            type = types.nullOr secretPath;
            default = null;
            description = ''
              File holding the client_id of the account's personal API key.
              bitwarden.com wants a new device registered with it before
              the first login; rbw does that by itself when it is set.
            '';
          };

          clientSecretFile = mkOption {
            type = types.nullOr secretPath;
            default = null;
            description = "File holding the client_secret of the personal API key.";
          };
        };
      };
    }
  );

  monitOptions = what: {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = "Add a Monit check that alerts when the last successful ${what} is too old.";
    };

    thresholdSeconds = mkOption {
      type = types.ints.positive;
      default = 86400;
      description = "Maximum age of the last successful ${what} before Monit alerts.";
    };
  };

  scheduleOptions = default: {
    schedule = mkOption {
      type = types.str;
      inherit default;
      description = "systemd OnCalendar expression for the job.";
      example = "0/6:00:00";
    };

    randomizedDelaySec = mkOption {
      type = types.str;
      default = "5m";
      description = ''
        systemd RandomizedDelaySec of the job's timer. Jobs that log into
        the same account should run far enough apart: bitwarden.com
        rejects a TOTP code that was already used.
      '';
    };
  };

  healthcheckOption = mkOption {
    type = types.nullOr secretPath;
    default = null;
    description = ''
      File holding a healthchecks.io-style ping URL. The job pings
      `URL/start` when it starts, `URL` when it succeeds and `URL/fail`
      when it fails.
    '';
  };

  backupModule = types.submodule (
    { name, ... }:
    {
      options = {
        account = mkOption {
          type = types.str;
          description = "Name of the account (in `services.rbw.accounts`) to back up.";
        };

        path = mkOption {
          type = types.str;
          default = "/var/lib/rbw-backup/${name}";
          description = "Directory the backups are written to.";
        };

        retentionDays = mkOption {
          type = types.ints.unsigned;
          default = 30;
          description = "Delete backups older than this many days (0 keeps all). The newest is always kept.";
        };

        attachments = mkOption {
          type = types.bool;
          default = true;
          description = "Include attachment contents in the backups.";
        };

        passphraseFile = mkOption {
          type = types.nullOr secretPath;
          default = null;
          description = "File holding the gpg passphrase the backups are encrypted with. Unset: unencrypted.";
        };

        healthcheckUrlFile = healthcheckOption;
        monit = monitOptions "backup";
      }
      // scheduleOptions "daily";
    }
  );

  enabledBackups = cfg.backups;
  inherit (cfg) mirror;

  backupAccounts = lib.unique (lib.mapAttrsToList (_: b: b.account) enabledBackups);
  mirrorAccounts = lib.optionals mirror.enable (
    lib.unique [
      mirror.from
      mirror.to
    ]
  );
  allUsedAccounts = lib.unique (backupAccounts ++ mirrorAccounts);

  rbw = lib.getExe' cfg.package "rbw";

  # Credential names under $CREDENTIALS_DIRECTORY for one account.
  credential = account: kind: "rbw-${account}-${kind}";

  accountCredentials =
    account:
    let
      a = cfg.accounts.${account};
    in
    [ "${credential account "password"}:${a.passwordFile}" ]
    ++ lib.optional (a.totpSecretFile != null) "${credential account "totp"}:${a.totpSecretFile}"
    ++ lib.optional (
      a.apiKey.clientIdFile != null
    ) "${credential account "client-id"}:${a.apiKey.clientIdFile}"
    ++ lib.optional (
      a.apiKey.clientSecretFile != null
    ) "${credential account "client-secret"}:${a.apiKey.clientSecretFile}";

  renderAccount =
    account:
    let
      a = cfg.accounts.${account};
      file = kind: "$CREDENTIALS_DIRECTORY/${credential account kind}";
    in
    {
      name = account;
      inherit (a) email;
      unlock.files = {
        passwordFile = file "password";
      }
      // lib.optionalAttrs (a.totpSecretFile != null) { totpSecretFile = file "totp"; }
      // lib.optionalAttrs (a.apiKey.clientIdFile != null) { clientIdFile = file "client-id"; }
      // lib.optionalAttrs (a.apiKey.clientSecretFile != null) {
        clientSecretFile = file "client-secret";
      };
    }
    // lib.optionalAttrs (a.baseUrl != null) { inherit (a) baseUrl; }
    // lib.optionalAttrs (a.ssoId != null) { inherit (a) ssoId; };

  rbwConfigFile =
    accounts:
    pkgs.writeText "rbw-config.json" (
      builtins.toJSON {
        accounts = map renderAccount accounts;
        primaryAccount = lib.head accounts;
      }
    );

  mirrorConfigFile = pkgs.writeText "rbw-mirrors.json" (
    builtins.toJSON {
      mirrors =
        let
          common = {
            inherit (mirror) from to attachments;
            overwrite = true;
          };
        in
        if mirror.mode == "personal" then
          [ (common // { purgeDest = mirror.purgeDestination; }) ]
        else
          map (
            collection:
            common
            // {
              inherit collection;
              destCollection = collection;
              destOrg = mirror.collections.org;
              inherit (mirror) prune;
              purgeDest = mirror.purgeDestination;
              fallbackToWholeVault = mirror.collections.fallback == "whole-vault";
              fallbackToPersonalVault = mirror.collections.fallback == "personal-vault";
            }
          ) mirror.collections.names;
    }
  );

  healthcheckScript = pkgs.writeShellScript "rbw-healthcheck" ''
    set -u
    url=$(${pkgs.coreutils}/bin/cat "$CREDENTIALS_DIRECTORY/rbw-healthcheck-url")
    case "$1" in
      start) suffix=/start ;;
      stop) if [ "''${SERVICE_RESULT:-}" = success ]; then suffix=; else suffix=/fail; fi ;;
      *) exit 0 ;;
    esac
    ${lib.getExe pkgs.curl} -fsS -m 10 --retry 3 -o /dev/null "$url$suffix" || true
  '';

  stopAgents =
    accounts:
    map (account: "-${rbw} --account ${lib.escapeShellArg account} stop-agent --kill") accounts;

  lastRunCheck =
    {
      name,
      label,
      file,
      thresholdSeconds,
    }:
    pkgs.writeShellScript name ''
      set -euo pipefail
      threshold=''${1:-${toString thresholdSeconds}}
      now=$(${pkgs.coreutils}/bin/date '+%s')
      if [[ ! -s "${file}" ]]
      then
        echo "🚨 No ${label} timestamp found"
        exit 1
      fi
      last=$(${pkgs.coreutils}/bin/cat "${file}")
      when=$(${pkgs.coreutils}/bin/date -d "@$last")
      if (( now - last > threshold ))
      then
        echo "🚨 Last ${label} was more than $threshold seconds ago ($when)"
        exit 1
      fi
      echo "✅ Last ${label}: $when"
    '';

  # Sandbox shared by all jobs. rbw only needs its home (config, cache,
  # device id), the job's own directory, a runtime directory for the agent
  # socket, and outgoing HTTPS.
  commonServiceConfig = user: runtimeDirectory: {
    Type = "oneshot";
    User = user;
    Group = user;
    UMask = "0077";
    Environment = [
      "HOME=${userHome user}"
      "XDG_RUNTIME_DIR=/run/${runtimeDirectory}"
      "RBW_AGENT=${lib.getExe' cfg.package "rbw-agent"}"
    ];
    RuntimeDirectory = runtimeDirectory;
    RuntimeDirectoryMode = "0700";

    NoNewPrivileges = true;
    CapabilityBoundingSet = "";
    AmbientCapabilities = "";
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_INET"
      "AF_INET6"
    ];
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    RemoveIPC = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
    ];
  };

  userHome = user: config.users.users.${user}.home;

  mirrorStateDir = "/var/lib/${cfg.mirrorUser}";
in
{
  imports = [
    (lib.mkRemovedOptionModule [ "services" "rbw-auto" ] ''
      rbw-auto was folded into rbw: declare accounts with their credential
      files in `services.rbw.accounts`, backups in `services.rbw.backups`
      and the mirror in `services.rbw.mirror`. The environment files are
      replaced by one file per credential (passwordFile, totpSecretFile,
      apiKey.*, passphraseFile, healthcheckUrlFile).
    '')
  ];

  options.services.rbw = {
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "rbw.packages.\${system}.default";
      description = "The rbw package the jobs run.";
    };

    accounts = mkOption {
      type = types.attrsOf accountModule;
      default = { };
      description = "Accounts the jobs below use, by rbw account name.";
      example = lib.literalExpression ''
        {
          personal = {
            email = "me@example.com";
            passwordFile = config.sops.secrets."rbw/personal/password".path;
            totpSecretFile = config.sops.secrets."rbw/personal/totp".path;
          };
        }
      '';
    };

    backupUser = mkOption {
      type = types.str;
      default = "rbw-backup";
      description = "System user (and group) that runs the backup jobs.";
    };

    mirrorUser = mkOption {
      type = types.str;
      default = "rbw-mirror";
      description = "System user (and group) that runs the mirror.";
    };

    backups = mkOption {
      type = types.attrsOf backupModule;
      default = { };
      description = "Backup jobs, each with its own `rbw-backup-<name>` service and timer.";
    };

    mirror = {
      enable = lib.mkEnableOption "a one-way mirror from one account into another";

      from = mkOption {
        type = types.str;
        description = "Name of the account to mirror from. It is only read.";
      };

      to = mkOption {
        type = types.str;
        description = "Name of the account to mirror into.";
      };

      mode = mkOption {
        type = types.enum [
          "personal"
          "collections"
        ];
        default = "collections";
        description = ''
          "collections": mirror into organization collections of `to`,
          reconciled by source id (see `collections`).
          "personal": copy the whole source vault into the personal vault
          of `to`.
        '';
      };

      collections = {
        org = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Destination organization, created if missing.";
        };

        names = mkOption {
          type = types.listOf types.nonEmptyStr;
          default = [ ];
          description = ''
            Destination collections, created if missing. A name that
            matches a source collection receives a copy of it; any other
            name receives the `fallback`.
          '';
        };

        fallback = mkOption {
          type = types.enum [
            "whole-vault"
            "personal-vault"
          ];
          default = "personal-vault";
          description = ''
            What a collection without an equally-named source collection
            receives: the source's personal vault (entries outside any
            organization), or the whole source vault.
          '';
        };
      };

      attachments = mkOption {
        type = types.bool;
        default = true;
        description = "Mirror attachments too.";
      };

      prune = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Move copies whose source entry no longer exists to the trash, so
          every collection is an exact copy of its source.
        '';
      };

      purgeDestination = mkOption {
        type = types.bool;
        default = false;
        description = "Wipe the destination before copying (rarely wanted; see `rbw mirror --purge-dest`).";
      };

      healthcheckUrlFile = healthcheckOption;
      monit = monitOptions "mirror run";
    }
    // scheduleOptions "daily";
  };

  config = lib.mkIf (enabledBackups != { } || mirror.enable) {
    assertions = [
      {
        assertion = lib.all (account: cfg.accounts ? ${account}) allUsedAccounts;
        message = "services.rbw: every account used by a backup or the mirror must be declared in services.rbw.accounts (missing: ${
          lib.concatStringsSep ", " (lib.filter (account: !(cfg.accounts ? ${account})) allUsedAccounts)
        })";
      }
      {
        # ProtectHome hides these from the sandboxed units.
        assertion = lib.all (job: !(lib.hasPrefix "/home/" job.path || lib.hasPrefix "/root" job.path)) (
          lib.attrValues enabledBackups
        );
        message = "services.rbw.backups.<name>.path must not be under /home or /root (the units run with ProtectHome)";
      }
      {
        assertion = !mirror.enable || mirror.from != mirror.to;
        message = "services.rbw.mirror: `from` and `to` must be different accounts";
      }
      {
        assertion =
          !mirror.enable
          || mirror.mode != "collections"
          || (mirror.collections.org != null && mirror.collections.names != [ ]);
        message = "services.rbw.mirror: mode = \"collections\" needs collections.org and collections.names";
      }
    ];

    users.groups = lib.mkMerge [
      (lib.mkIf (enabledBackups != { }) { ${cfg.backupUser} = { }; })
      (lib.mkIf mirror.enable { ${cfg.mirrorUser} = { }; })
    ];

    users.users = lib.mkMerge [
      (lib.mkIf (enabledBackups != { }) {
        ${cfg.backupUser} = {
          isSystemUser = true;
          group = cfg.backupUser;
          home = "/var/lib/${cfg.backupUser}";
          createHome = true;
        };
      })
      (lib.mkIf mirror.enable {
        ${cfg.mirrorUser} = {
          isSystemUser = true;
          group = cfg.mirrorUser;
          home = mirrorStateDir;
          createHome = true;
        };
      })
    ];

    systemd = {
      tmpfiles.rules =
        lib.optionals (enabledBackups != { }) (
          [
            "d ${userHome cfg.backupUser}/.config/rbw 0700 ${cfg.backupUser} ${cfg.backupUser} -"
            "L+ ${userHome cfg.backupUser}/.config/rbw/config.json - - - - ${rbwConfigFile backupAccounts}"
          ]
          # `Z` hands existing backups to the backup user, e.g. after the
          # user was renamed.
          ++ lib.concatLists (
            lib.mapAttrsToList (_: job: [
              "d ${job.path} 0700 ${cfg.backupUser} ${cfg.backupUser} -"
              "Z ${job.path} - ${cfg.backupUser} ${cfg.backupUser} -"
            ]) enabledBackups
          )
        )
        ++ lib.optionals mirror.enable [
          "d ${mirrorStateDir}/.config/rbw 0700 ${cfg.mirrorUser} ${cfg.mirrorUser} -"
          "L+ ${mirrorStateDir}/.config/rbw/config.json - - - - ${rbwConfigFile mirrorAccounts}"
        ];

      services =
        lib.mapAttrs' (
          name: job:
          lib.nameValuePair "rbw-backup-${name}" {
            description = "rbw backup (${name})";
            after = [ "network-online.target" ];
            wants = [ "network-online.target" ];
            serviceConfig = commonServiceConfig cfg.backupUser "rbw-backup-${name}" // {
              ReadWritePaths = [
                job.path
                (userHome cfg.backupUser)
              ];
              LoadCredential =
                accountCredentials job.account
                ++ lib.optional (job.passphraseFile != null) "rbw-backup-passphrase:${job.passphraseFile}"
                ++ lib.optional (job.healthcheckUrlFile != null) "rbw-healthcheck-url:${job.healthcheckUrlFile}";
              ExecStartPre = lib.optional (job.healthcheckUrlFile != null) "${healthcheckScript} start";
              ExecStart = lib.concatStringsSep " " (
                [
                  rbw
                  "--account"
                  (lib.escapeShellArg job.account)
                  "backup"
                  (lib.escapeShellArg job.path)
                  "--retention-days"
                  (toString job.retentionDays)
                ]
                ++ lib.optional (!job.attachments) "--no-attachments"
                ++ lib.optionals (job.passphraseFile != null) [
                  "--passphrase-file"
                  "%d/rbw-backup-passphrase"
                ]
              );
              ExecStopPost =
                stopAgents [ job.account ]
                ++ lib.optional (job.healthcheckUrlFile != null) "${healthcheckScript} stop";
            };
          }
        ) enabledBackups
        // lib.optionalAttrs mirror.enable {
          rbw-mirror = {
            description = "rbw one-way mirror (${mirror.from} -> ${mirror.to})";
            after = [ "network-online.target" ];
            wants = [ "network-online.target" ];
            serviceConfig = commonServiceConfig cfg.mirrorUser "rbw-mirror" // {
              ReadWritePaths = [ mirrorStateDir ];
              LoadCredential =
                lib.concatMap accountCredentials mirrorAccounts
                ++ lib.optional (
                  mirror.healthcheckUrlFile != null
                ) "rbw-healthcheck-url:${mirror.healthcheckUrlFile}";
              ExecStartPre = lib.optional (mirror.healthcheckUrlFile != null) "${healthcheckScript} start";
              ExecStart = "${rbw} mirror --config ${mirrorConfigFile} --yes";
              ExecStartPost = "${pkgs.runtimeShell} -c '${pkgs.coreutils}/bin/date +%%s > ${mirrorStateDir}/LAST_MIRROR'";
              ExecStopPost =
                stopAgents mirrorAccounts
                ++ lib.optional (mirror.healthcheckUrlFile != null) "${healthcheckScript} stop";
              # A mirror that rewrites every entry (the first run, or after the
              # state is lost) takes a while; never let it run into the next one.
              TimeoutStartSec = "2h";
            };
          };
        };

      timers =
        lib.mapAttrs' (
          name: job:
          lib.nameValuePair "rbw-backup-${name}" {
            description = "Run the rbw backup (${name})";
            wantedBy = [ "timers.target" ];
            timerConfig = {
              OnCalendar = job.schedule;
              RandomizedDelaySec = job.randomizedDelaySec;
              Persistent = true;
            };
          }
        ) enabledBackups
        // lib.optionalAttrs mirror.enable {
          rbw-mirror = {
            description = "Run the rbw mirror";
            wantedBy = [ "timers.target" ];
            timerConfig = {
              OnCalendar = mirror.schedule;
              RandomizedDelaySec = mirror.randomizedDelaySec;
              Persistent = true;
            };
          };
        };

    };

    services.monit.config = lib.mkMerge (
      lib.mapAttrsToList (
        name: job:
        lib.mkIf job.monit.enable (
          lib.mkAfter ''
            check program "rbw-backup-${name}" with path "${
              lastRunCheck {
                name = "rbw-backup-${name}-last-run";
                label = "backup (${name})";
                file = "${job.path}/LAST_BACKUP";
                inherit (job.monit) thresholdSeconds;
              }
            }"
              group backup
              every 2 cycles
              if status > 0 then alert
          ''
        )
      ) enabledBackups
      ++ lib.optional (mirror.enable && mirror.monit.enable) (
        lib.mkAfter ''
          check program "rbw-mirror" with path "${
            lastRunCheck {
              name = "rbw-mirror-last-run";
              label = "mirror run";
              file = "${mirrorStateDir}/LAST_MIRROR";
              inherit (mirror.monit) thresholdSeconds;
            }
          }"
            group sync
            every 2 cycles
            if status > 0 then alert
        ''
      )
    );
  };
}
