package config

import (
	"encoding/json"
	"os"

	"github.com/brizzbuzz/opnix/internal/errors"
	"github.com/brizzbuzz/opnix/internal/validation"
)

type SecretKind string

const (
	SecretKindField SecretKind = "field"
	SecretKindFile  SecretKind = "file"
)

type Secret struct {
	Path      string            `json:"path"`
	Reference string            `json:"reference"`
	Kind      SecretKind        `json:"kind,omitempty"`
	Owner     string            `json:"owner,omitempty"`
	Group     string            `json:"group,omitempty"`
	Mode      string            `json:"mode,omitempty"`
	Symlinks  []string          `json:"symlinks,omitempty"`
	Variables map[string]string `json:"variables,omitempty"`
	Services  interface{}       `json:"services,omitempty"`
}

type ChangeDetection struct {
	Enable   bool   `json:"enable"`
	HashFile string `json:"hashFile"`
}

type ErrorHandling struct {
	RollbackOnFailure bool `json:"rollbackOnFailure"`
	ContinueOnError   bool `json:"continueOnError"`
	MaxRetries        int  `json:"maxRetries"`
}

type SystemdIntegration struct {
	Enable          bool            `json:"enable"`
	Services        []string        `json:"services"`
	RestartOnChange bool            `json:"restartOnChange"`
	ChangeDetection ChangeDetection `json:"changeDetection"`
	ErrorHandling   ErrorHandling   `json:"errorHandling"`
}

type Config struct {
	Secrets            []Secret           `json:"secrets"`
	PathTemplate       string             `json:"pathTemplate,omitempty"`
	Defaults           map[string]string  `json:"defaults,omitempty"`
	SystemdIntegration SystemdIntegration `json:"systemdIntegration,omitempty"`

	// systemdIntegrationSet records that the file actually carried a
	// systemdIntegration block, as opposed to SystemdIntegration holding its
	// zero value. LoadMultiple needs the distinction to decide which file's
	// settings win.
	systemdIntegrationSet bool
}

// convertToValidationSecrets converts config secrets to validation format
func (c *Config) convertToValidationSecrets() []validation.SecretData {
	secrets := make([]validation.SecretData, len(c.Secrets))
	for i, s := range c.Secrets {
		secrets[i] = validation.SecretData{
			Path:         s.Path,
			Reference:    s.Reference,
			Kind:         string(s.Kind),
			Owner:        s.Owner,
			Group:        s.Group,
			Mode:         s.Mode,
			Symlinks:     s.Symlinks,
			Variables:    s.Variables,
			Services:     s.Services,
			PathTemplate: c.PathTemplate,
			Defaults:     c.Defaults,
		}
	}
	return secrets
}

// Load loads a single config file
func Load(path string) (*Config, error) {
	// G304: reading a caller-supplied path is the entire purpose of this
	// function. The path comes from -config or from a module-generated store
	// path, both administrator-controlled.
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, errors.FileOperationError(
			"Loading configuration file",
			path,
			"Failed to read config file",
			err,
		)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, errors.ConfigError(
			"Parsing configuration file",
			"Invalid JSON format in config file",
			err,
		)
	}

	// Decode again to learn whether systemdIntegration was present at all; the
	// value alone cannot distinguish "absent" from "every field at its zero".
	var probe struct {
		SystemdIntegration *json.RawMessage `json:"systemdIntegration"`
	}
	if err := json.Unmarshal(data, &probe); err == nil {
		config.systemdIntegrationSet = probe.SystemdIntegration != nil
	}

	for i := range config.Secrets {
		if config.Secrets[i].Kind == "" {
			config.Secrets[i].Kind = SecretKindField
		}
	}

	// Validate the loaded configuration
	validator := validation.NewValidator()
	if err := validator.ValidateConfigStruct(config.convertToValidationSecrets()); err != nil {
		return nil, err
	}

	return &config, nil
}

// LoadMultiple loads and merges multiple config files (GitHub #3).
//
// The merge is what makes cross-file conflicts detectable: ValidateConfigStruct
// threads one seenPaths map across every secret, so two files writing to the
// same destination are an error rather than a silent last-writer-wins race.
// Running opnix once per file, as the modules used to, gave each invocation its
// own map and no way to see the conflict.
//
// pathTemplate, defaults and systemdIntegration are taken from the last file
// that specifies them.
func LoadMultiple(paths []string) (*Config, error) {
	if len(paths) == 0 {
		return nil, errors.ConfigError(
			"Loading multiple config files",
			"No config file paths provided",
			nil,
		)
	}

	merged := &Config{}

	// One pass. The previous implementation loaded every file twice and
	// discarded the error on the second read with the comment "we know this
	// works from above" — a file deleted or truncated between the two reads
	// returned a nil *Config that was then dereferenced.
	for _, path := range paths {
		config, err := Load(path)
		if err != nil {
			return nil, errors.WrapWithSuggestions(
				err,
				"Loading multiple config files",
				"configuration",
				[]string{
					"Check that all config file paths are correct",
					"Ensure all config files have valid JSON format",
					"Verify file permissions allow reading",
				},
			)
		}

		merged.Secrets = append(merged.Secrets, config.Secrets...)

		if config.PathTemplate != "" {
			merged.PathTemplate = config.PathTemplate
		}
		if len(config.Defaults) > 0 {
			merged.Defaults = make(map[string]string, len(config.Defaults))
			for k, v := range config.Defaults {
				merged.Defaults[k] = v
			}
		}
		if config.systemdIntegrationSet {
			merged.SystemdIntegration = config.SystemdIntegration
			merged.systemdIntegrationSet = true
		}
	}

	// Validate the merged configuration for cross-file conflicts
	validator := validation.NewValidator()
	if err := validator.ValidateConfigStruct(merged.convertToValidationSecrets()); err != nil {
		return nil, err
	}

	return merged, nil
}

// Validate checks for duplicate secret paths across all configs
// Deprecated: Use validation.Validator.ValidateConfigStruct() for comprehensive validation
func (c *Config) Validate() error {
	validator := validation.NewValidator()
	return validator.ValidateConfigStruct(c.convertToValidationSecrets())
}
