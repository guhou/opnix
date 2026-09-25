package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/brizzbuzz/opnix/internal/config"
	"github.com/brizzbuzz/opnix/internal/errors"
	"github.com/brizzbuzz/opnix/internal/onepass"
	"github.com/brizzbuzz/opnix/internal/secrets"
	"github.com/brizzbuzz/opnix/internal/systemd"
	"github.com/brizzbuzz/opnix/internal/validation"
)

const (
	defaultTokenPath  = "/etc/opnix-token"
	defaultConfigPath = "secrets.json"

	// secretDirMode matches the mode the processor uses for directories it
	// creates; see secrets.DirMode for why it is 0751 rather than 0755.
	secretDirMode = secrets.DirMode
)

// repeatedString collects a flag that may be supplied more than once.
type repeatedString []string

func (r *repeatedString) String() string { return strings.Join(*r, ", ") }

func (r *repeatedString) Set(value string) error {
	*r = append(*r, value)
	return nil
}

type secretProcessor interface {
	Process(*config.Config) (*secrets.ProcessResult, error)
}

type systemdManager interface {
	ProcessSecretChanges([]config.Secret, map[string]string) error
}

type secretCommand struct {
	fs          *flag.FlagSet
	configFiles repeatedString
	outputDir   string
	tokenFile   string

	loadConfig       func([]string) (*config.Config, error)
	newClient        func(onepass.TokenSource) (secrets.SecretClient, error)
	processorFactory func(secrets.SecretClient, string) secretProcessor
	systemdFactory   func(config.SystemdIntegration) (systemdManager, error)
}

func newSecretCommand() *secretCommand {
	sc := &secretCommand{
		fs: flag.NewFlagSet("secret", flag.ExitOnError),
	}

	sc.fs.Var(&sc.configFiles, "config",
		"Path to a secrets configuration file. Repeat to merge several; "+
			"destinations are then checked for conflicts across all of them.")
	sc.fs.StringVar(&sc.outputDir, "output", "secrets", "Directory to store retrieved secrets")
	sc.fs.StringVar(&sc.tokenFile, "token-file", defaultTokenPath,
		"Path to file containing 1Password service account token "+
			"(OP_SERVICE_ACCOUNT_TOKEN is used instead when this is left at its default)")

	sc.fs.Usage = func() {
		fmt.Fprintf(sc.fs.Output(), "Usage: opnix secret [options]\n\n")
		fmt.Fprintf(sc.fs.Output(), "Retrieve and manage secrets from 1Password\n\n")
		fmt.Fprintf(sc.fs.Output(), "Options:\n")
		sc.fs.PrintDefaults()
	}

	sc.loadConfig = config.LoadMultiple
	sc.newClient = func(source onepass.TokenSource) (secrets.SecretClient, error) {
		return onepass.NewClient(source)
	}
	sc.processorFactory = func(client secrets.SecretClient, outputDir string) secretProcessor {
		return secrets.NewProcessor(client, outputDir)
	}
	sc.systemdFactory = func(cfg config.SystemdIntegration) (systemdManager, error) {
		return systemd.NewManager(cfg)
	}

	return sc
}

func (s *secretCommand) Name() string { return s.fs.Name() }

func (s *secretCommand) Init(args []string) error {
	if err := s.fs.Parse(args); err != nil {
		return err
	}

	// Stray positional arguments were silently discarded, which is how an
	// unquoted path in a generated script — "-output /var/lib/my secrets" —
	// managed to write secrets to /var/lib/my and still exit 0.
	if s.fs.NArg() > 0 {
		s.fs.Usage()
		return fmt.Errorf("unexpected argument %q; every value must be attached to a flag", s.fs.Arg(0))
	}

	return nil
}

func (s *secretCommand) Run() error {
	// Pre-flight checks
	if err := s.validatePrerequisites(); err != nil {
		return err
	}

	// Load configuration with improved error handling
	cfg, err := s.loadConfig(s.configPaths())
	if err != nil {
		// Error already has context from config.LoadMultiple
		return err
	}

	log.Printf("Loaded configuration with %d secrets from %d file(s)", len(cfg.Secrets), len(s.configPaths()))

	// Initialize 1Password client with validation
	client, err := s.newClient(s.tokenSource())
	if err != nil {
		// Error already has context from onepass.NewClient
		return err
	}

	log.Printf("Initialized 1Password client successfully")

	// Process secrets with detailed progress
	processor := s.processorFactory(client, s.outputDir)
	result, err := processor.Process(cfg)
	if err != nil {
		// Error already has context from processor.Process
		return err
	}

	log.Printf("Successfully processed %d secrets to %s", result.ProcessedCount, s.outputDir)

	// Process systemd integration if enabled
	if cfg.SystemdIntegration.Enable {
		log.Printf("Processing systemd integration for %d services", len(cfg.SystemdIntegration.Services))

		systemdManager, err := s.systemdFactory(cfg.SystemdIntegration)
		if err != nil {
			return errors.WrapWithSuggestions(
				err,
				"Initializing systemd integration",
				"systemd integration",
				[]string{
					"Ensure systemctl is available in PATH",
					"Check if running on a systemd-enabled system",
					"Consider disabling systemd integration if not needed",
				},
			)
		}

		if err := systemdManager.ProcessSecretChanges(cfg.Secrets, result.SecretPaths); err != nil {
			return errors.WrapWithSuggestions(
				err,
				"Processing systemd service changes",
				"systemd integration",
				[]string{
					"Check if specified services exist and are accessible",
					"Verify systemctl permissions",
					"Review systemd integration configuration",
					"Check systemd service logs: journalctl -u <service-name>",
				},
			)
		}

		log.Printf("Successfully processed systemd integration")
	}

	return nil
}

// tokenSource reports where the token should come from, and whether the user
// asked for that file by name. A flag the user typed outranks
// OP_SERVICE_ACCOUNT_TOKEN; the built-in default does not.
func (s *secretCommand) tokenSource() onepass.TokenSource {
	explicit := false
	s.fs.Visit(func(f *flag.Flag) {
		if f.Name == "token-file" {
			explicit = true
		}
	})
	if explicit {
		return onepass.ExplicitTokenFile(s.tokenFile)
	}
	return onepass.DefaultTokenFile(s.tokenFile)
}

// configPaths returns the configuration files to merge, falling back to the
// historical single default when none were given.
func (s *secretCommand) configPaths() []string {
	if len(s.configFiles) == 0 {
		return []string{defaultConfigPath}
	}
	return s.configFiles
}

// validatePrerequisites performs pre-flight checks before processing
func (s *secretCommand) validatePrerequisites() error {
	// Check if config files exist
	for _, path := range s.configPaths() {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return errors.FileOperationError(
				"Checking configuration file",
				path,
				"Configuration file does not exist",
				err,
			)
		}
	}

	// Check if output directory is writable
	if err := s.checkOutputDirectory(); err != nil {
		return err
	}

	// Validate the token file. This stays non-fatal on purpose: a missing token
	// must not break boot, and refusing to run because a token is exposed would
	// leave the host without updated secrets while doing nothing about the
	// exposure. The message has to be unmistakable instead.
	validator := validation.NewValidator()
	if err := validator.ValidateTokenFile(s.tokenFile); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
		fmt.Fprintf(os.Stderr, "INFO: Continuing with existing secrets if available\n")
	}

	return nil
}

// checkOutputDirectory ensures the output directory exists.
//
// Writability is deliberately not probed here. The previous implementation
// created and deleted a fixed-name sentinel file, which was both a root
// file-clobber primitive when a symlink was planted at that name and a source
// of spurious inotify events for the module's path watcher. A directory that
// cannot be written to surfaces at the first real write, wrapped with the same
// suggestions.
func (s *secretCommand) checkOutputDirectory() error {
	if err := os.MkdirAll(s.outputDir, secretDirMode); err != nil {
		return errors.FileOperationError(
			"Creating output directory",
			s.outputDir,
			"Cannot create or access output directory",
			err,
		)
	}

	return nil
}
