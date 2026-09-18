{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.onepassword-secrets;

  # Validate that secret keys use proper Nix variable naming (camelCase)
  # Valid: databasePassword, sslCert, myApiKey
  # Invalid: "database/password", "ssl-cert", "my_api_key"
  isValidNixVariableName = key:
    builtins.match "^[a-z][a-zA-Z0-9]*$" key != null;

  # Validate all secret keys
  validateSecretKeys = secrets: let
    invalidKeys = lib.filter (key: !isValidNixVariableName key) (lib.attrNames secrets);
  in
    if invalidKeys != []
    then throw "Invalid secret key names. OpNix requires camelCase variable names like 'databasePassword', not path-like strings. Invalid keys: ${lib.concatStringsSep ", " invalidKeys}"
    else secrets;

  # Paths reach the generated shell scripts by interpolation. They are quoted
  # with escapeShellArg, so a space no longer splits a command — but a path that
  # needs quoting is almost always a mistake, and catching it at evaluation time
  # beats discovering it in a service log.
  isPlainAbsolutePath = path:
    builtins.match "/[^[:space:]$`\"'\\\\]*" (toString path) != null;

  # Create a system group for opnix token access
  opnixGroup = "onepassword-secrets";

  # RestartSteps and RestartMaxDelaySec are systemd 254 and later. Without them
  # every retry waits retry.initialDelay, which is still an improvement on a
  # flat 15 minutes.
  supportsRestartBackoff = lib.versionAtLeast config.systemd.package.version "254";

  # Every destination this configuration is known to write to.
  secretDestinations = lib.flatten (lib.mapAttrsToList (
      name: secret:
        [
          (
            if secret.path != null
            then secret.path
            else "${cfg.outputDir}/${name}"
          )
        ]
        ++ secret.symlinks
    )
    cfg.secrets);

  # ProtectSystem=strict is the one sandboxing directive here with real
  # containment value, but it can only be turned on by default where it is
  # certain not to break secret delivery.
  #
  # Two things have to hold. Every destination must be knowable at evaluation
  # time — paths inside configFiles are opaque JSON, and a path template is
  # resolved at runtime. And every destination must live under outputDir, which
  # this module creates itself, because ReadWritePaths= cannot make a directory
  # that does not exist writable. A secret written to, say, /etc/ssl/certs is
  # fine in practice, but only because that directory happens to exist; the
  # module cannot know that, so it does not assume it.
  #
  # Anything else is opt-in via hardening.protectSystem plus
  # hardening.extraReadWritePaths.
  destinationsSelfContained =
    cfg.configFiles
    == []
    && cfg.pathTemplate == null
    && lib.all (
      path:
        lib.hasPrefix "${cfg.outputDir}/" path
        && !(lib.hasInfix "{" path)
    )
    secretDestinations;

  # Directories the service legitimately writes to.
  #
  # Every entry carries the "-" prefix so that a path which does not exist is
  # skipped rather than failing the unit's mount namespace setup outright.
  readWritePaths = map (path: "-${path}") (
    lib.unique (
      [cfg.outputDir]
      ++ map builtins.dirOf secretDestinations
      ++ lib.optional cfg.systemdIntegration.changeDetection.enable
      (builtins.dirOf cfg.systemdIntegration.changeDetection.hashFile)
      ++ [(toString cfg.tokenFile)]
      ++ cfg.hardening.extraReadWritePaths
    )
  );

  # Sandboxing for the units that run opnix.
  #
  # The service is root by design and writes root-owned files by design, so most
  # of the usual directives buy little on their own: NoNewPrivileges on an
  # already-root process, for instance, changes nothing an attacker cares about.
  # They are cheap and they raise effort, so they are here — but ProtectSystem
  # is what actually confines a compromised wasm runtime, and it is the reason
  # this block exists.
  #
  # MemoryDenyWriteExecute is deliberately absent and must stay absent: the
  # 1Password SDK embeds wazero, which needs writable-executable mappings. With
  # it set, secret retrieval dies in wazevo.mmapExecutable with
  # "operation not permitted".
  #
  # ProtectHome is also deliberately absent. Writing a secret to a path under
  # /home is a legitimate thing to ask this service to do.
  hardeningConfig = lib.optionalAttrs cfg.hardening.enable ({
      NoNewPrivileges = true;
      CapabilityBoundingSet = [
        "CAP_CHOWN"
        "CAP_FOWNER"
        "CAP_DAC_OVERRIDE"
        "CAP_DAC_READ_SEARCH"
      ];
      PrivateTmp = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6"];
    }
    // lib.optionalAttrs (cfg.hardening.protectSystem != "off") {
      ProtectSystem = cfg.hardening.protectSystem;
      ReadWritePaths = readWritePaths;
    });
in {
  options.services.onepassword-secrets = {
    enable = lib.mkEnableOption "1Password secrets integration";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.opnix or (import ./package.nix {inherit pkgs;});
      defaultText = lib.literalExpression "pkgs.opnix";
      description = ''
        The opnix package to use.

        Defaults to `pkgs.opnix` when the flake's overlay is in scope, and
        otherwise builds it against the ambient `pkgs`. Set this to substitute a
        patched build without touching the module.
      '';
    };

    tokenFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/opnix-token";
      description = ''
        Path to file containing the 1Password service account token.
        The file should contain only the token and should have appropriate permissions (640).
        Will be readable by members of the ${opnixGroup} group.

        You can set up the token using the opnix CLI:
          opnix token set
          # or with a custom path:
          opnix token set -path /path/to/token
      '';
    };

    configFiles = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [];
      description = "List of secrets configuration files (GitHub #3)";
      example = [./database-secrets.json ./api-secrets.json];
    };

    outputDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/opnix/secrets";
      description = "Directory to store retrieved secrets";
    };

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Users to add to the ${opnixGroup} group, which grants read access to
        `tokenFile`.

        ::: {.warning}
        This delegates the raw 1Password service account token, not access to
        individual secrets. Anyone listed here can read every item in every
        vault the service account can reach, from any machine, and nothing opnix
        produces records that they did.

        Revoking it requires rotating the token. Removing the group membership
        stops future reads of the file; it does nothing about a copy already
        taken.
        :::

        Prefer leaving this empty and scoping the service account to the minimum
        set of vaults this host needs.
      '';
      example = ["alice" "bob"];
    };

    secrets = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          reference = lib.mkOption {
            type = lib.types.str;
            description = "1Password reference in the format op://Vault/Item/field or op://Vault/Item/filename";
            example = "op://Homelab/Database/password";
          };

          kind = lib.mkOption {
            type = lib.types.enum ["field" "file"];
            default = "field";
            description = "Whether to resolve a text field or download a Document/attachment as raw bytes";
          };

          path = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "Custom path for the secret file. If null, uses pathTemplate or outputDir + secret name";
            example = "/etc/ssl/certs/app.pem";
          };

          symlinks = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
            description = "List of symlink paths that should point to this secret";
            example = ["/etc/ssl/certs/legacy.pem" "/opt/service/ssl/cert.pem"];
          };

          variables = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
            description = "Variables for path template substitution";
            example = {
              service = "postgresql";
              environment = "prod";
            };
          };

          owner = lib.mkOption {
            type = lib.types.str;
            default = "root";
            description = "User who owns the secret file";
            example = "caddy";
          };

          group = lib.mkOption {
            type = lib.types.str;
            default = "root";
            description = "Group that owns the secret file";
            example = "caddy";
          };

          mode = lib.mkOption {
            type = lib.types.str;
            default = "0600";
            description = "File permissions in octal notation";
            example = "0644";
          };

          services = lib.mkOption {
            type =
              lib.types.either
              (lib.types.listOf lib.types.str)
              (lib.types.attrsOf (lib.types.submodule {
                options = {
                  restart = lib.mkOption {
                    type = lib.types.bool;
                    default = true;
                    description = "Whether to restart the service when this secret changes";
                  };

                  signal = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = "Custom signal to send instead of restart (e.g., SIGHUP for reload)";
                    example = "SIGHUP";
                  };

                  after = lib.mkOption {
                    type = lib.types.listOf lib.types.str;
                    default = ["opnix-secrets.service"];
                    description = ''
                      Additional systemd units this service should be ordered
                      after. These are merged into the generated
                      `systemd.services.<name>.after` list alongside
                      opnix-secrets.service.
                    '';
                    example = ["postgresql.service" "redis.service"];
                  };
                };
              }));
            default = [];
            description = ''
              Services to manage when this secret changes.
              Can be a simple list of service names or an attribute set with advanced options.
            '';
            example = [
              "caddy"
              "postgresql"
            ];
          };
        };
      });
      default = {};
      description = ''
        Declarative secrets configuration (GitHub #11).
        Keys are secret names, values are secret configurations.
      '';
      example = {
        databasePassword = {
          reference = "op://Vault/Database/password";
          services = ["postgresql"];
        };
        sslCert = {
          reference = "op://Vault/SSL/certificate";
          path = "/etc/ssl/certs/app.pem";
          owner = "caddy";
          group = "caddy";
          mode = "0644";
          symlinks = ["/etc/ssl/certs/legacy.pem"];
          services = {
            caddy = {
              restart = true;
              after = ["opnix-secrets.service"];
            };
          };
        };
        serviceConfig = {
          reference = "op://Vault/Service/config";
          variables = {
            DATABASE_URL = "postgresql://user:password@localhost/myapp";
            API_KEY = "secret-api-key";
          };
        };
      };
    };

    pathTemplate = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Path template for secrets when no explicit path is specified.
        Variables can be substituted using {variable} syntax.
      '';
      example = "/etc/secrets/{service}/{name}";
    };

    defaults = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      description = "Default variables for path template substitution";
      example = {
        environment = "production";
        service = "default";
      };
    };

    systemdIntegration = lib.mkOption {
      type = lib.types.submodule {
        options = {
          enable = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Enable systemd service integration and dependency management";
          };

          services = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
            description = "Global list of services that should depend on opnix-secrets.service";
            example = ["caddy" "postgresql" "grafana"];
          };

          restartOnChange = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Whether to restart services when their secrets change";
          };

          changeDetection = lib.mkOption {
            type = lib.types.submodule {
              options = {
                enable = lib.mkOption {
                  type = lib.types.bool;
                  default = true;
                  description = "Enable content-based change detection to avoid unnecessary service restarts";
                };

                hashFile = lib.mkOption {
                  type = lib.types.str;
                  default = "/var/lib/opnix/secret-hashes.json";
                  description = "File to store secret content hashes for change detection";
                };
              };
            };
            default = {};
            description = "Change detection configuration";
          };

          polling = lib.mkOption {
            type = lib.types.submodule {
              options = {
                enable = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = "Periodically retrieve secrets from 1Password";
                };

                interval = lib.mkOption {
                  type = lib.types.str;
                  default = "6h";
                  description = "Systemd time span between automatic secret retrievals";
                  example = "30min";
                };
              };
            };
            default = {};
            description = "Automatic 1Password polling configuration";
          };

          errorHandling = lib.mkOption {
            type = lib.types.submodule {
              options = {
                rollbackOnFailure = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = ''
                    Reserved for future secret-file rollback handling. This option does not
                    roll back NixOS generations or preserve 1Password references used by
                    older generations.
                  '';
                };

                continueOnError = lib.mkOption {
                  type = lib.types.bool;
                  default = true;
                  description = "Continue processing other secrets if one fails";
                };

                maxRetries = lib.mkOption {
                  type = lib.types.ints.unsigned;
                  default = 3;
                  description = ''
                    Number of retries beyond the first attempt for a failed
                    service action. 0 means try once and do not retry.
                  '';
                };
              };
            };
            default = {};
            description = "Error handling and recovery configuration";
          };
        };
      };
      default = {};
      description = "Systemd service integration configuration";
    };

    hardening = lib.mkOption {
      type = lib.types.submodule {
        options = {
          enable = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = ''
              Apply systemd sandboxing directives to the units that run opnix.
            '';
          };

          protectSystem = lib.mkOption {
            type = lib.types.enum ["off" "yes" "full" "strict"];
            default =
              if destinationsSelfContained
              then "strict"
              else "off";
            defaultText = lib.literalMD ''
              `"strict"` when every declared secret lands under `outputDir`,
              which this module creates itself; `"off"` otherwise — that is,
              whenever `configFiles` or `pathTemplate` is in use, or a secret
              declares a `path` or `symlinks` entry outside `outputDir`.
            '';
            description = ''
              systemd ProtectSystem= setting for the opnix units.

              `"strict"` mounts the whole filesystem hierarchy read-only except
              for the destinations this configuration declares. It is the only
              directive here that would contain a compromised 1Password SDK wasm
              runtime, so it is on by default wherever it is safe.

              It is not enabled automatically for destinations outside
              `outputDir`, because ReadWritePaths= cannot make a directory that
              does not yet exist writable, and the module has no way to know
              whether a given path already exists on the target host. To opt in,
              set this to `"strict"` and make sure every parent directory
              involved exists and is listed — the ones this module can work out
              are added for you; use `extraReadWritePaths` for the rest.

              MemoryDenyWriteExecute is deliberately never set, at any level: the
              1Password SDK embeds a wasm runtime that needs
              writable-executable mappings.
            '';
          };

          extraReadWritePaths = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
            description = ''
              Additional paths to add to ReadWritePaths= when `protectSystem` is
              not `"off"`. Needed for destinations opnix only learns about at
              runtime, such as those declared in `configFiles`.
            '';
            example = ["/etc/ssl/certs" "/var/lib/myservice"];
          };
        };
      };
      default = {};
      description = "systemd sandboxing for the opnix units";
    };

    retry = lib.mkOption {
      type = lib.types.submodule {
        options = {
          initialDelay = lib.mkOption {
            type = lib.types.str;
            default = "1min";
            description = ''
              How long to wait before the first retry after a failed run. Kept
              short because the most likely boot-time failure is a network that
              becomes available a few seconds late.
            '';
          };

          maxDelay = lib.mkOption {
            type = lib.types.str;
            default = "15min";
            description = ''
              Upper bound on the backoff between retries, so a genuinely broken
              configuration stops hammering the 1Password API. Requires systemd
              254 or later; on older versions every retry uses `initialDelay`.
            '';
          };

          maxAttempts = lib.mkOption {
            type = lib.types.ints.positive;
            default = 5;
            description = ''
              How many times the unit may start within `window` before systemd
              refuses further starts.
            '';
          };

          window = lib.mkOption {
            type = lib.types.str;
            default = "1h";
            description = "Period over which `maxAttempts` is counted.";
          };

          recoveryInterval = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = "1h";
            description = ''
              How often to check whether opnix-secrets.service has exhausted its
              start limit, and if so clear it and try again.

              Without this the unit stays `failed` indefinitely once the limit
              is hit: the window rolling over only makes a future explicit
              request succeed, and nothing issues one. A host whose network
              arrived late would never get its secrets until a human
              intervened. Set to null to disable.
            '';
          };
        };
      };
      default = {};
      description = "Retry and recovery policy for opnix-secrets.service";
    };

    secretPaths = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      description = ''
        Computed paths for declarative secrets (GitHub #11).
        This is automatically populated and provides declarative references
        to secret file paths for use in other configuration sections.
      '';
    };
  };

  config = lib.mkMerge [
    # Always define secretPaths to prevent evaluation errors (fixes MMI-88, MMI-92)
    (lib.mkIf (cfg.enable && cfg.secrets != {}) {
      services.onepassword-secrets.secretPaths =
        lib.mapAttrs (
          name: secret:
            if secret.path != null
            then secret.path
            else "${cfg.outputDir}/${name}"
        )
        (validateSecretKeys cfg.secrets);
    })

    # Main configuration only when enabled
    (lib.mkIf cfg.enable (let
      # Validate configuration
      hasMultipleConfigs = cfg.configFiles != [];
      hasDeclarativeSecrets = cfg.secrets != {};

      # At least one configuration method must be specified
      configCount = lib.length (lib.filter (x: x) [hasMultipleConfigs hasDeclarativeSecrets]);

      # Generate a temporary config file from declarative secrets
      declarativeConfigFile =
        if hasDeclarativeSecrets
        then
          pkgs.writeText "opnix-declarative-secrets.json" (builtins.toJSON {
            secrets =
              lib.mapAttrsToList (name: secret: {
                path =
                  if secret.path != null
                  then secret.path
                  else name;
                reference = secret.reference;
                kind = secret.kind;
                owner = secret.owner;
                group = secret.group;
                mode = secret.mode;
                symlinks = secret.symlinks;
                variables = secret.variables;
                services = secret.services;
              })
              (validateSecretKeys cfg.secrets);
            pathTemplate = cfg.pathTemplate;
            defaults = cfg.defaults;
            systemdIntegration = cfg.systemdIntegration;
          })
        else null;

      # Collect all config files
      allConfigFiles = lib.filter (f: f != null) (
        cfg.configFiles
        ++ (lib.optional hasDeclarativeSecrets declarativeConfigFile)
      );

      # Stop the path watcher for the duration of a run, and put it back
      # afterwards.
      #
      # Every run touches the directory the watcher monitors — the chmod at the
      # top of processSecretsScript is enough — so without this,
      # opnix-secrets.service triggers opnix-secrets-restart.service, which
      # starts a second, fully concurrent opnix against the same output
      # directory on every deployment: two processes writing the same paths and
      # double the 1Password API calls. The polling path already did this; the
      # guard just was not applied anywhere else.
      watcherGuard = lib.optionalString (cfg.systemdIntegration.enable && cfg.systemdIntegration.changeDetection.enable) ''
        watcher_was_active=false
        if ${pkgs.systemd}/bin/systemctl is-active --quiet opnix-secrets-watcher.path; then
          ${pkgs.systemd}/bin/systemctl stop opnix-secrets-watcher.path
          watcher_was_active=true
        fi

        restore_watcher() {
          run_status=$?
          if [ "$watcher_was_active" = true ]; then
            if ! ${pkgs.systemd}/bin/systemctl start opnix-secrets-watcher.path; then
              echo "ERROR: Failed to restore opnix-secrets-watcher.path" >&2
              if [ "$run_status" -eq 0 ]; then
                run_status=1
              fi
            fi
          fi
          exit "$run_status"
        }
        trap restore_watcher EXIT
      '';

      processSecretsScript = ''
        ${watcherGuard}

        # Ensure output directory exists with correct permissions.
        #
        # 0750 root:${opnixGroup}, not 0751 root:root. The world-execute bit is
        # not what grants group members access — the unit runs with
        # Group=${opnixGroup}, so they traverse via the group bit — it only lets
        # every other local user confirm which secrets exist and read any secret
        # whose own mode is permissive. The explicit chown matters for a
        # directory that already exists, which mkdir -p will not re-own.
        mkdir -p ${lib.escapeShellArg cfg.outputDir}
        chown root:${opnixGroup} ${lib.escapeShellArg cfg.outputDir}
        chmod 750 ${lib.escapeShellArg cfg.outputDir}

        # Create systemd integration directories if needed
        ${lib.optionalString cfg.systemdIntegration.enable (
          lib.optionalString cfg.systemdIntegration.changeDetection.enable ''
            hash_dir="$(dirname ${lib.escapeShellArg cfg.systemdIntegration.changeDetection.hashFile})"
            mkdir -p "$hash_dir"
            # 0700: the hash store names every secret path on the host, and the
            # key beside it is what keeps the stored digests meaningless to
            # anyone who obtains them.
            chmod 700 "$hash_dir"
          ''
        )}

        # Set up token file with correct group permissions if it exists
        if [ -f ${lib.escapeShellArg cfg.tokenFile} ]; then
          # Ensure token file has correct ownership and permissions
          chown root:${opnixGroup} ${lib.escapeShellArg cfg.tokenFile}
          chmod 640 ${lib.escapeShellArg cfg.tokenFile}
        fi

        # Handle missing token file gracefully - don't fail system boot
        if [ ! -f ${lib.escapeShellArg cfg.tokenFile} ]; then
          echo "WARNING: Token file ${cfg.tokenFile} does not exist!" >&2
          echo "INFO: Using existing secrets, skipping updates" >&2
          echo "INFO: Run 'opnix token set' to configure the token" >&2
          exit 0
        fi

        # Validate token file permissions
        if [ ! -r ${lib.escapeShellArg cfg.tokenFile} ]; then
          echo "ERROR: Token file ${cfg.tokenFile} is not readable!" >&2
          echo "INFO: Check file permissions or group membership" >&2
          exit 1
        fi

        # Validate token is not empty
        if [ ! -s ${lib.escapeShellArg cfg.tokenFile} ]; then
          echo "ERROR: Token file is empty!" >&2
          echo "INFO: Run 'opnix token set' to configure the token" >&2
          exit 1
        fi

        # Run the secrets retrieval tool once, over every config file. A single
        # invocation is what lets opnix detect two files writing to the same
        # destination; separate runs each saw only their own secrets and the
        # last one silently won. It also means one 1Password client rather than
        # one per file.
        echo "Processing config files: ${lib.concatStringsSep " " allConfigFiles}"
        ${cfg.package}/bin/opnix secret \
          -token-file ${lib.escapeShellArg cfg.tokenFile} \
          ${lib.concatMapStringsSep " " (configFile: "-config ${lib.escapeShellArg (toString configFile)}") allConfigFiles} \
          -output ${lib.escapeShellArg cfg.outputDir}

        ${lib.optionalString cfg.systemdIntegration.enable ''
          echo "INFO: Systemd integration enabled - services will be managed automatically"
        ''}
      '';

      # The watcher guard now lives inside processSecretsScript, so polling gets
      # it for free.
      pollSecretsScript = processSecretsScript;
    in
      lib.mkMerge [
        # Validation assertions
        {
          assertions =
            [
              {
                assertion = configCount > 0;
                message = "OpNix: At least one of configFiles or secrets must be specified";
              }
              {
                assertion = isPlainAbsolutePath cfg.outputDir;
                message = "OpNix: outputDir must be an absolute path without whitespace or shell metacharacters (got '${cfg.outputDir}')";
              }
              {
                assertion = isPlainAbsolutePath (toString cfg.tokenFile);
                message = "OpNix: tokenFile must be an absolute path without whitespace or shell metacharacters (got '${toString cfg.tokenFile}')";
              }
              {
                assertion = isPlainAbsolutePath cfg.systemdIntegration.changeDetection.hashFile;
                message = "OpNix: changeDetection.hashFile must be an absolute path without whitespace or shell metacharacters (got '${cfg.systemdIntegration.changeDetection.hashFile}')";
              }
            ]
            ++ (lib.flatten (lib.mapAttrsToList (name: secret: [
                {
                  assertion = builtins.match "^[0-7]{3,4}$" secret.mode != null;
                  message = "OpNix secret '${name}': mode '${secret.mode}' is not a valid octal permission (e.g., 0644, 0600)";
                }
              ])
              cfg.secrets));
        }

        # Main configuration
        {
          # Create the opnix group
          users.groups.${opnixGroup} = {};

          # Add specified users to the opnix group.
          #
          # The warning is here rather than only in the documentation because
          # this is the one place an administrator makes this trade-off, and it
          # is the place least likely to prompt them to think about it.
          users.users =
            lib.warnIf (cfg.users != []) ''
              services.onepassword-secrets.users grants ${lib.concatStringsSep ", " cfg.users} read access to the raw 1Password service account token in ${toString cfg.tokenFile}.
              That token reads every item in every vault the service account can reach, from any machine. Revoking it requires rotating the token, not just removing the group membership.
            '' (lib.mkMerge (map (user: {
                ${user}.extraGroups = [opnixGroup];
              })
              cfg.users));

          # Make the CLI available on PATH without requiring a manual overlay.
          # lib.lowPrio avoids a buildEnv collision if the user already added
          # opnix to systemPackages manually — their copy silently wins.
          environment.systemPackages = [(lib.lowPrio cfg.package)];

          # Create systemd service instead of activation script
          systemd.services.opnix-secrets = {
            description = "OpNix Secret Management";
            wantedBy = ["multi-user.target"];
            after = ["network-online.target" "nss-lookup.target"];
            wants = ["network-online.target" "nss-lookup.target"];

            unitConfig = {
              StartLimitIntervalSec = cfg.retry.window;
              StartLimitBurst = cfg.retry.maxAttempts;
            };

            serviceConfig =
              {
                Type = "oneshot";
                RemainAfterExit = true;
                Restart = "on-failure";
                # Short first retry, backing off to retry.maxDelay. The most
                # likely boot-time failure is a network that arrives a few
                # seconds late, and a flat 15-minute wait spent one of only two
                # permitted starts on it — two transient failures then left the
                # host without secrets, permanently.
                RestartSec = cfg.retry.initialDelay;
                RestartPreventExitStatus = "65 75";
                # Type=oneshot defaults TimeoutStartUSec to infinity, so without
                # this a hung run blocks multi-user.target and every unit ordered
                # after it, indefinitely. Bound it so any hang degrades to a
                # failed unit that Restart=on-failure can retry.
                TimeoutStartSec = "5min";
                User = "root";
                Group = opnixGroup;
              }
              // lib.optionalAttrs supportsRestartBackoff {
                RestartSteps = cfg.retry.maxAttempts - 1;
                RestartMaxDelaySec = cfg.retry.maxDelay;
              }
              // hardeningConfig;

            script = processSecretsScript;
          };

          # Clear the start limit and try again once the underlying problem has
          # had time to resolve itself.
          #
          # start-limit-hit is not self-healing: the unit stays failed, and the
          # window rolling over only means a future explicit request would be
          # accepted — nothing issues one. Without this, a host whose network
          # came up late has no secrets until a human intervenes or a rebuild
          # happens.
          systemd.services.opnix-secrets-recover = lib.mkIf (cfg.retry.recoveryInterval != null) {
            description = "Retry OpNix secret retrieval after its start limit was exhausted";
            serviceConfig = {
              Type = "oneshot";
              User = "root";
            };
            script = ''
              if ${pkgs.systemd}/bin/systemctl is-failed --quiet opnix-secrets.service; then
                echo "INFO: opnix-secrets.service is failed; clearing the start limit and retrying"
                ${pkgs.systemd}/bin/systemctl reset-failed opnix-secrets.service
                ${pkgs.systemd}/bin/systemctl start --no-block opnix-secrets.service
              fi
            '';
          };

          systemd.timers.opnix-secrets-recover = lib.mkIf (cfg.retry.recoveryInterval != null) {
            description = "Periodically retry OpNix secret retrieval after a failure";
            wantedBy = ["timers.target"];
            timerConfig = {
              OnBootSec = cfg.retry.recoveryInterval;
              OnUnitActiveSec = cfg.retry.recoveryInterval;
              Unit = "opnix-secrets-recover.service";
            };
          };
        }

        # Systemd service integration
        (lib.mkIf cfg.systemdIntegration.enable {
          # Collect all services that need dependency management
          systemd.services = let
            # Extract services from individual secrets
            servicesFromSecrets = lib.flatten (lib.mapAttrsToList (
                name: secret:
                  if lib.isList secret.services
                  then secret.services
                  else lib.attrNames secret.services
              )
              cfg.secrets);

            # Combine with global services list
            allServices = lib.unique (cfg.systemdIntegration.services ++ servicesFromSecrets);

            # Collect the per-secret `after` entries declared for a service.
            # Ordering is a build-time concern, so it is applied here rather
            # than being serialised to JSON for the CLI to discard.
            afterForService = serviceName:
              lib.flatten (lib.mapAttrsToList (
                  _: secret:
                    if lib.isList secret.services
                    then []
                    else lib.optionals (secret.services ? ${serviceName}) secret.services.${serviceName}.after
                )
                cfg.secrets);

            # Generate service configurations
            serviceConfigs = lib.listToAttrs (map (serviceName: {
                name = serviceName;
                value = {
                  after = lib.unique (["opnix-secrets.service"] ++ afterForService serviceName);
                  wants = ["opnix-secrets.service"];
                };
              })
              allServices);

            # Add restart service if change detection is enabled
            restartService = lib.optionalAttrs cfg.systemdIntegration.changeDetection.enable {
              opnix-secrets-restart = {
                description = "Restart services when OpNix secrets change";
                serviceConfig =
                  {
                    Type = "oneshot";
                    TimeoutStartSec = "5min";
                    User = "root";
                    Group = opnixGroup;
                  }
                  // hardeningConfig;

                script = ''
                  ${watcherGuard}

                  echo "OpNix secrets changed, triggering service restart evaluation..."

                  # Re-run opnix to process changes and handle service restarts
                  # The change detection logic is handled in the Go code
                  echo "Re-processing config files for service changes: ${lib.concatStringsSep " " allConfigFiles}"
                  ${cfg.package}/bin/opnix secret \
                    -token-file ${lib.escapeShellArg cfg.tokenFile} \
                    ${lib.concatMapStringsSep " " (configFile: "-config ${lib.escapeShellArg (toString configFile)}") allConfigFiles} \
                    -output ${lib.escapeShellArg cfg.outputDir} || true

                  echo "OpNix service restart evaluation completed"
                '';
              };
            };

            pollingService = lib.optionalAttrs cfg.systemdIntegration.polling.enable {
              opnix-secrets-poll = {
                description = "Poll 1Password for OpNix secret changes";
                after = ["network-online.target" "nss-lookup.target"];
                wants = ["network-online.target" "nss-lookup.target"];
                serviceConfig =
                  {
                    Type = "oneshot";
                    TimeoutStartSec = "5min";
                    User = "root";
                    Group = opnixGroup;
                  }
                  // hardeningConfig;
                script = pollSecretsScript;
              };
            };
          in
            serviceConfigs // restartService // pollingService;

          systemd.timers = lib.mkIf cfg.systemdIntegration.polling.enable {
            opnix-secrets-poll = {
              description = "Periodically poll 1Password for OpNix secret changes";
              wantedBy = ["timers.target"];
              timerConfig = {
                OnActiveSec = cfg.systemdIntegration.polling.interval;
                OnUnitActiveSec = cfg.systemdIntegration.polling.interval;
                Unit = "opnix-secrets-poll.service";
              };
            };
          };

          # Create a systemd path unit for change detection if enabled
          systemd.paths = lib.mkIf cfg.systemdIntegration.changeDetection.enable {
            opnix-secrets-watcher = {
              description = "Watch for OpNix secret changes";
              wantedBy = ["multi-user.target"];
              pathConfig = {
                PathModified = cfg.outputDir;
                Unit = "opnix-secrets-restart.service";
              };
            };
          };
        })
      ]))
  ];
}
