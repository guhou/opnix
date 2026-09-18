{
  pkgs,
  nixpkgs,
  system,
  src,
  vendorHash,
}:
{
  # Run tests
  go-tests = pkgs.buildGoModule {
    pname = "opnix-go-tests";
    version = "0.11.0";
    inherit src;
    inherit vendorHash;

    checkPhase = ''
      go test ./...
    '';

    installPhase = "touch $out";
  };

  # Run golangci-lint
  go-lint = pkgs.buildGoModule {
    pname = "opnix-go-lint";
    version = "0.11.0";
    inherit src;
    inherit vendorHash;

    nativeBuildInputs = [pkgs.golangci-lint];

    buildPhase = ''
      export GOLANGCI_LINT_CACHE=$TMPDIR/golangci-lint
      export XDG_CACHE_HOME=$TMPDIR/cache

      mkdir -p $GOLANGCI_LINT_CACHE
      mkdir -p $XDG_CACHE_HOME

      ${
        let
          cfg = ''
            version: "2"
            linters:
              default: standard
              settings:
                errcheck:
                  exclude-functions:
                    - fmt.Fprintf
              exclusions:
                rules:
                  - path: ".*_test\\.go$"
                    linters:
                      - errcheck
          '';
        in "echo -n '${cfg}' >> .golangci.yaml"
      }

      golangci-lint run --allow-parallel-runners \
        --timeout=5m \
        --max-same-issues=20 \
        ./...
    '';

    installPhase = "touch $out";
  };

  # Check nix formatting
  nix-fmt-check =
    pkgs.runCommand "opnix-nix-fmt-check"
    {
      nativeBuildInputs = [pkgs.alejandra];
      inherit src;
    } ''
      cp -r $src/* .
      alejandra --check .
      touch $out
    '';
}
// (let
  lib = pkgs.lib;
  hmLib = lib.extend (_: _: {
    hm.dag = {
      entryBefore = _: value: value;
      entryAfter = _: value: value;
    };
  });
  hmConfig =
    (hmLib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        ./hm-module.nix
        {
          options = {
            home.homeDirectory = lib.mkOption {type = lib.types.str;};
            home.username = lib.mkOption {type = lib.types.str;};
            home.packages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [];
            };
            home.activation = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
          };
          config = {
            home.homeDirectory = "/home/opnix-test";
            home.username = "opnix-test";
            programs.onepassword-secrets = {
              enable = true;
              secrets = {
                defaultSecret.reference = "op://Example/Service/password";
                fileSecret = {
                  reference = "op://Example/Document/archive.bin";
                  kind = "file";
                };
              };
            };
          };
        }
      ];
    }).config;
  darwinConfigWith = extra:
    (lib.evalModules {
      specialArgs = {inherit pkgs;};
      modules = [
        ./darwin-module.nix
        {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
            users.knownGroups = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
            };
            users.groups = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
            users.users = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
            launchd.daemons = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
            system.activationScripts.extraActivation.text = lib.mkOption {
              type = lib.types.str;
              default = "";
            };
          };
          config.services.onepassword-secrets =
            {
              enable = true;
              secrets = {
                defaultSecret.reference = "op://Example/Service/password";
                fileSecret = {
                  reference = "op://Example/Document/archive.bin";
                  kind = "file";
                };
              };
            }
            // extra;
        }
      ];
    }).config;
  darwinConfig = darwinConfigWith {};
  darwinScriptOf = config: builtins.elemAt config.launchd.daemons.opnix-secrets.serviceConfig.ProgramArguments 2;
  darwinScript = darwinScriptOf darwinConfig;
  # A path needing quotes is rejected by the module's own assertion, but
  # assertions are not forced by reading the script, so this still shows what
  # the generated shell would look like.
  darwinAwkwardScript = darwinScriptOf (darwinConfigWith {outputDir = "/usr/local/var/my secrets";});
in {
  hm-module-evaluation = assert hmConfig.programs.onepassword-secrets.secrets.defaultSecret.kind == "field";
  assert hmConfig.programs.onepassword-secrets.secrets.fileSecret.kind == "file";
    pkgs.runCommand "opnix-hm-module-evaluation" {
      moduleScript = hmConfig.home.activation.retrieveOpnixSecrets;
    } ''
      config_file=$(printf '%s\n' "$moduleScript" | grep -o '/nix/store/[^ ]*-hm-opnix-declarative-secrets.json' | head -n1)
      grep -Fq '"kind":"field"' "$config_file"
      grep -Fq '"kind":"file"' "$config_file"
      touch $out
    '';

  darwin-module-evaluation = assert darwinConfig.services.onepassword-secrets.secrets.defaultSecret.kind == "field";
  assert darwinConfig.services.onepassword-secrets.secrets.fileSecret.kind == "file";
  # The daemon runs as root with no GroupName, so without an explicit chown the
  # output directory lands on root:wheel and members of the opnix group cannot
  # traverse into it at all.
  assert lib.hasInfix "chown root:onepassword-secrets /usr/local/var/opnix/secrets" darwinScript;
  assert lib.hasInfix "chmod 750 /usr/local/var/opnix/secrets" darwinScript;
  # An outputDir containing a space must reach opnix as one argument.
  # launchd's default respawn floor is 10s with no backoff, and it has no
  # equivalent of RestartPreventExitStatus, so terminal exits are mapped here.
  assert darwinConfig.launchd.daemons.opnix-secrets.serviceConfig.ThrottleInterval == 900;
  assert lib.hasInfix "65)" darwinScript;
  assert lib.hasInfix "75)" darwinScript;
  assert lib.hasInfix "-output '/usr/local/var/my secrets'" darwinAwkwardScript;
  assert lib.hasInfix "mkdir -p '/usr/local/var/my secrets'" darwinAwkwardScript;
    pkgs.runCommand "opnix-darwin-module-evaluation" {
      moduleScript = darwinScript;
    } ''
      config_file=$(printf '%s\n' "$moduleScript" | grep -o '/nix/store/[^ ]*-opnix-declarative-secrets.json' | head -n1)
      grep -Fq '"kind":"field"' "$config_file"
      grep -Fq '"kind":"file"' "$config_file"
      touch $out
    '';
})
// pkgs.lib.optionalAttrs pkgs.stdenv.isLinux (let
  nixosConfig = polling: extra:
    (nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        ./module.nix
        {
          system.stateVersion = "26.05";
          services.onepassword-secrets =
            extra
            // {
              enable = true;
              secrets.testSecret.reference = "op://Example/Service/password";
              secrets.testFile = {
                reference = "op://Example/Document/archive.bin";
                kind = "file";
              };
              secrets.testOrdering = {
                reference = "op://Example/Service/ordering";
                services.opnixTestApp = {
                  restart = true;
                  after = ["postgresql.service" "redis.service"];
                };
              };
              systemdIntegration.polling = polling;
            };
        }
      ];
    }).config;

  defaultPollingConfig = nixosConfig {} {};
  nixosScript = defaultPollingConfig.systemd.services.opnix-secrets.script;
  # A path needing quotes is rejected by the module's own assertion, but
  # assertions are not forced by reading the script, so this still shows what
  # the generated shell would look like.
  awkwardScript = (nixosConfig {} {outputDir = "/var/lib/my secrets";}).systemd.services.opnix-secrets.script;
  enabledPollingConfig = nixosConfig {
    enable = true;
    interval = "45min";
  } {};
in {
  module-evaluation = assert defaultPollingConfig.systemd.services.opnix-secrets.serviceConfig.TimeoutStartSec == "5min";
  # Paths reaching the generated shell must be quoted, and the output directory
  # must be owned by the opnix group rather than relying on a world-execute bit.
  assert nixpkgs.lib.hasInfix "chown root:onepassword-secrets /var/lib/opnix/secrets" nixosScript;
  assert nixpkgs.lib.hasInfix "chmod 750 /var/lib/opnix/secrets" nixosScript;
  assert !(nixpkgs.lib.hasInfix "chmod 751" nixosScript);
  # An outputDir containing a space must reach opnix as one argument rather
  # than splitting into "-output /var/lib/my" plus a stray positional.
  assert nixpkgs.lib.hasInfix "-output '/var/lib/my secrets'" awkwardScript;
  assert nixpkgs.lib.hasInfix "mkdir -p '/var/lib/my secrets'" awkwardScript;
  # Every run touches the watched directory, so the guard has to be on the units
  # that run opnix — not only on the polling path.
  assert nixpkgs.lib.hasInfix "systemctl stop opnix-secrets-watcher.path" nixosScript;
  assert nixpkgs.lib.hasInfix "trap restore_watcher EXIT" nixosScript;
  assert nixpkgs.lib.hasInfix "systemctl stop opnix-secrets-watcher.path" defaultPollingConfig.systemd.services.opnix-secrets-restart.script;
  # A host whose network arrived late must recover without a human.
  assert defaultPollingConfig.systemd.timers.opnix-secrets-recover.timerConfig.OnUnitActiveSec == "1h";
  assert nixpkgs.lib.hasInfix "reset-failed opnix-secrets.service" defaultPollingConfig.systemd.services.opnix-secrets-recover.script;
  assert defaultPollingConfig.systemd.services.opnix-secrets.unitConfig.StartLimitBurst == 5;
  assert defaultPollingConfig.systemd.services.opnix-secrets.serviceConfig.RestartSec == "1min";
  # The wasm runtime the 1Password SDK embeds needs writable-executable mappings.
  assert !(defaultPollingConfig.systemd.services.opnix-secrets.serviceConfig ? MemoryDenyWriteExecute);
  assert defaultPollingConfig.systemd.services.opnix-secrets.serviceConfig.ProtectSystem == "strict";
  assert defaultPollingConfig.systemd.services.opnix-secrets.serviceConfig.NoNewPrivileges;
  # Per-secret `after` entries must reach the generated unit ordering rather
  # than being serialised to JSON and discarded.
  assert nixpkgs.lib.elem "postgresql.service" defaultPollingConfig.systemd.services.opnixTestApp.after;
  assert nixpkgs.lib.elem "redis.service" defaultPollingConfig.systemd.services.opnixTestApp.after;
  assert nixpkgs.lib.elem "opnix-secrets.service" defaultPollingConfig.systemd.services.opnixTestApp.after;
  assert !(defaultPollingConfig.systemd.services ? opnix-secrets-poll);
  assert !(defaultPollingConfig.systemd.timers ? opnix-secrets-poll);
  assert defaultPollingConfig.services.onepassword-secrets.secrets.testSecret.kind == "field";
  assert defaultPollingConfig.services.onepassword-secrets.secrets.testFile.kind == "file";
  assert enabledPollingConfig.systemd.services.opnix-secrets-poll.serviceConfig.Type == "oneshot";
  assert !(enabledPollingConfig.systemd.services.opnix-secrets-poll.serviceConfig ? RemainAfterExit);
  assert nixpkgs.lib.hasInfix "systemctl stop opnix-secrets-watcher.path" enabledPollingConfig.systemd.services.opnix-secrets-poll.script;
  assert nixpkgs.lib.hasInfix "trap restore_watcher EXIT" enabledPollingConfig.systemd.services.opnix-secrets-poll.script;
  assert enabledPollingConfig.systemd.timers.opnix-secrets-poll.timerConfig.OnActiveSec == "45min";
  assert enabledPollingConfig.systemd.timers.opnix-secrets-poll.timerConfig.OnUnitActiveSec == "45min";
  assert enabledPollingConfig.systemd.timers.opnix-secrets-poll.timerConfig.Unit == "opnix-secrets-poll.service";
    pkgs.runCommand "opnix-module-evaluation" {
      moduleScript = nixosScript;
    } ''
      config_file=$(printf '%s\n' "$moduleScript" | grep -o '/nix/store/[^ ]*-opnix-declarative-secrets.json' | head -n1)
      grep -Fq '"kind":"field"' "$config_file"
      grep -Fq '"kind":"file"' "$config_file"
      touch $out
    '';
})
