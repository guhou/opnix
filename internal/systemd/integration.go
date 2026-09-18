package systemd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/brizzbuzz/opnix/internal/config"
	"github.com/brizzbuzz/opnix/internal/errors"
)

// hashStoreVersion identifies the digest scheme in the hash store.
//
// Version 1 held a bare, unsalted SHA-256 of each secret's plaintext, which is
// a confirmation oracle for anyone who obtains the file. Version 2 holds an
// HMAC keyed by a root-only value generated on first run. A store written by
// the older scheme is discarded rather than compared against, so the first run
// after an upgrade treats every secret as changed.
const hashStoreVersion = 2

// hashKeySize is the length of the HMAC key, in bytes.
const hashKeySize = 32

// ServiceAction defines how to handle a service when secrets change.
//
// There is deliberately no ordering field here. Per-service `after` values are
// a build-time concern: nix/module.nix threads them into the generated unit's
// After= directive. Carrying them through to runtime only produced a struct
// field nothing ever read.
type ServiceAction struct {
	Name    string
	Start   bool
	Restart bool
	Signal  string
}

type serviceStatus struct {
	ActiveState string
	SubState    string
	Result      string
}

// SecretHash represents a stored hash of a secret's content
type SecretHash struct {
	Path         string    `json:"path"`
	Hash         string    `json:"hash"`
	LastModified time.Time `json:"lastModified"`
}

// HashStore manages secret content hashes for change detection
type HashStore struct {
	Version int                   `json:"version"`
	Hashes  map[string]SecretHash `json:"hashes"`

	filePath string
	key      []byte
}

// Manager handles systemd service integration and change detection
type Manager struct {
	config    config.SystemdIntegration
	hashStore *HashStore
	dryRun    bool
	systemctl string
}

// NewManager creates a new systemd integration manager
func NewManager(cfg config.SystemdIntegration) (*Manager, error) {
	// Find systemctl binary
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, errors.FileOperationError(
			"Finding systemctl binary",
			"systemctl",
			"systemctl not found in PATH - systemd integration requires systemd",
			err,
		)
	}

	// Initialize hash store if change detection is enabled
	var hashStore *HashStore
	if cfg.ChangeDetection.Enable {
		hashStore, err = NewHashStore(cfg.ChangeDetection.HashFile)
		if err != nil {
			return nil, err
		}
	}

	return &Manager{
		config:    cfg,
		hashStore: hashStore,
		systemctl: systemctl,
	}, nil
}

// NewHashStore creates or loads a hash store from disk
func NewHashStore(filePath string) (*HashStore, error) {
	store := &HashStore{
		Version:  hashStoreVersion,
		Hashes:   make(map[string]SecretHash),
		filePath: filePath,
	}

	// Create parent directory if it doesn't exist. 0700: the store names every
	// secret path on the host and holds a digest of each one's content.
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.FileOperationError(
			"Creating hash store directory",
			dir,
			"Failed to create directory for hash store",
			err,
		)
	}

	key, err := loadOrCreateHashKey(hashKeyPath(filePath))
	if err != nil {
		return nil, err
	}
	store.key = key

	// Load existing hashes if file exists
	if _, err := os.Stat(filePath); err == nil {
		if err := store.load(); err != nil {
			return nil, err
		}
	}

	return store, nil
}

// hashKeyPath is where the HMAC key lives, alongside the hash store itself.
func hashKeyPath(hashFile string) string {
	return filepath.Join(filepath.Dir(hashFile), ".opnix-hash-key")
}

// loadOrCreateHashKey returns the store's HMAC key, generating one on first
// run. It is written 0600 and never leaves the host: without it the stored
// digests are useless for confirming a guessed secret value.
func loadOrCreateHashKey(path string) ([]byte, error) {
	// G304: the key lives beside the administrator-configured hash store.
	if key, err := os.ReadFile(path); err == nil && len(key) == hashKeySize { //nolint:gosec
		// Narrow an existing key that a previous run or an operator left open.
		if err := os.Chmod(path, 0600); err != nil {
			return nil, errors.FileOperationError(
				"Securing hash store key",
				path,
				"Failed to restrict permissions on the change-detection key",
				err,
			)
		}
		return key, nil
	}

	key := make([]byte, hashKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.ConfigError(
			"Generating hash store key",
			"Failed to generate a key for change detection",
			err,
		)
	}

	if err := writeRestricted(path, key); err != nil {
		return nil, errors.FileOperationError(
			"Writing hash store key",
			path,
			"Failed to write the change-detection key",
			err,
		)
	}

	return key, nil
}

// writeRestricted writes data to path with mode 0600, tightening the mode of an
// existing file. os.WriteFile applies its perm argument only when it creates
// the file, so a file left at 0644 by an earlier release stays 0644 without the
// explicit Chmod.
func writeRestricted(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// load reads the hash store from disk
func (hs *HashStore) load() error {
	// G304: the hash store path is administrator-configured.
	data, err := os.ReadFile(hs.filePath) //nolint:gosec
	if err != nil {
		return errors.FileOperationError(
			"Loading hash store",
			hs.filePath,
			"Failed to read hash store file",
			err,
		)
	}

	// Decode into a fresh value: unmarshalling over hs would leave the version
	// this process already set in place when the file has no version field,
	// which is exactly the case that needs detecting.
	var loaded struct {
		Version int                   `json:"version"`
		Hashes  map[string]SecretHash `json:"hashes"`
	}
	if err := json.Unmarshal(data, &loaded); err != nil {
		return errors.ConfigError(
			"Parsing hash store",
			"Invalid JSON format in hash store file",
			err,
		)
	}

	hs.Version = hashStoreVersion
	if loaded.Version != hashStoreVersion {
		// Digests from an older scheme are not comparable with the current one.
		// Start over rather than reporting spurious differences forever; the
		// cost is that this run sees every secret as changed.
		fmt.Fprintf(os.Stderr, "INFO: Hash store %s uses an older digest scheme; rebuilding it\n", hs.filePath)
		hs.Hashes = make(map[string]SecretHash)
		return nil
	}

	hs.Hashes = loaded.Hashes
	if hs.Hashes == nil {
		hs.Hashes = make(map[string]SecretHash)
	}

	return nil
}

// save writes the hash store to disk
func (hs *HashStore) save() error {
	data, err := json.MarshalIndent(hs, "", "  ")
	if err != nil {
		return errors.ConfigError(
			"Serializing hash store",
			"Failed to marshal hash store data",
			err,
		)
	}

	if err := writeRestricted(hs.filePath, data); err != nil {
		return errors.FileOperationError(
			"Saving hash store",
			hs.filePath,
			"Failed to write hash store file",
			err,
		)
	}

	return nil
}

// calculateHash returns a keyed digest of a file's content.
//
// The digest is an HMAC rather than a bare hash. Change detection only needs to
// know whether the value differs from last time; it does not need a digest that
// means anything to whoever obtains the store. A bare SHA-256 of a secret lets
// anyone holding it confirm a guessed plaintext instantly and without touching
// the service, and brute-force a low-entropy one outright.
func (hs *HashStore) calculateHash(filePath string) (string, error) {
	// G304: hashing a secret opnix just wrote requires opening it by path.
	file, err := os.Open(filePath) //nolint:gosec
	if err != nil {
		return "", errors.FileOperationError(
			"Opening file for hashing",
			filePath,
			"Failed to open file for hash calculation",
			err,
		)
	}
	defer func() { _ = file.Close() }() // Ignore error - defer cleanup is best effort

	hasher := hmac.New(sha256.New, hs.key)
	if _, err := io.Copy(hasher, file); err != nil {
		return "", errors.FileOperationError(
			"Reading file for hashing",
			filePath,
			"Failed to read file content for hash calculation",
			err,
		)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// HasChanged checks if a secret has changed since last deployment
func (hs *HashStore) hasChanged(filePath string) (bool, error) {
	// Calculate current hash
	currentHash, err := hs.calculateHash(filePath)
	if err != nil {
		return false, err
	}

	// Get file info for modification time
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false, errors.FileOperationError(
			"Getting file info",
			filePath,
			"Failed to get file information",
			err,
		)
	}

	// Check if we have a previous hash
	previousHash, exists := hs.Hashes[filePath]
	if !exists {
		// First time seeing this file - it's "changed"
		hs.Hashes[filePath] = SecretHash{
			Path:         filePath,
			Hash:         currentHash,
			LastModified: fileInfo.ModTime(),
		}
		return true, nil
	}

	// Compare hashes
	if previousHash.Hash != currentHash {
		// Content changed - update stored hash
		hs.Hashes[filePath] = SecretHash{
			Path:         filePath,
			Hash:         currentHash,
			LastModified: fileInfo.ModTime(),
		}
		return true, nil
	}

	// No change detected
	return false, nil
}

// ExtractServiceActions extracts service actions from secret configuration
func (m *Manager) ExtractServiceActions(secret config.Secret, secretName string) ([]ServiceAction, error) {
	if secret.Services == nil {
		return nil, nil
	}

	var actions []ServiceAction

	switch services := secret.Services.(type) {
	case []interface{}:
		// Simple list of service names
		for _, svc := range services {
			if serviceName, ok := svc.(string); ok {
				actions = append(actions, ServiceAction{
					Name:    serviceName,
					Restart: m.config.RestartOnChange,
				})
			}
		}

	case map[string]interface{}:
		// Advanced service configuration
		for serviceName, svcConfig := range services {
			action := ServiceAction{
				Name:    serviceName,
				Restart: m.config.RestartOnChange,
			}

			// Parse service configuration. "after" is intentionally not read:
			// unit ordering is generated by the Nix module, not applied here.
			if configMap, ok := svcConfig.(map[string]interface{}); ok {
				if restart, ok := configMap["restart"].(bool); ok {
					action.Restart = restart
				}
				if signal, ok := configMap["signal"].(string); ok {
					if err := validateSignal(signal, serviceName, secretName); err != nil {
						return nil, err
					}
					action.Signal = signal
				}
			}

			actions = append(actions, action)
		}

	default:
		return nil, errors.ConfigError(
			fmt.Sprintf("Parsing services for secret %s", secretName),
			"Services field must be an array of strings or object with service configurations",
			nil,
		)
	}

	return actions, nil
}

// ProcessSecretChanges processes secrets and determines which services need restart
func (m *Manager) ProcessSecretChanges(secrets []config.Secret, secretPaths map[string]string) error {
	if !m.config.Enable {
		return nil
	}

	var changedSecrets []string
	var changedServiceActions []ServiceAction
	var configuredServiceActions []ServiceAction

	// Check each secret for changes
	for i, secret := range secrets {
		secretName := fmt.Sprintf("secret[%d]:%s", i, secret.Path)

		actions, err := m.ExtractServiceActions(secret, secretName)
		if err != nil {
			if m.config.ErrorHandling.ContinueOnError {
				fmt.Fprintf(os.Stderr, "WARNING: Failed to extract service actions for %s: %v\n", secretName, err)
				continue
			}
			return err
		}
		configuredServiceActions = append(configuredServiceActions, actions...)

		// Use the destination the processor actually wrote to. Re-deriving it
		// from secret.Path was wrong in two of its three branches: an absolute
		// path was taken verbatim, so a templated path such as
		// "/etc/secrets/{service}/cert.pem" was hashed with the braces still in
		// it, and a secret relying on pathTemplate had no path at all.
		secretPath, recorded := secretPaths[secretName]

		// Default to "changed" whenever the answer is not knowable. Suppressing
		// a restart is the dangerous direction: the service keeps running on a
		// credential that has already been rotated on disk.
		hasChanged := true
		switch {
		case !recorded:
			fmt.Fprintf(os.Stderr, "WARNING: No resolved path recorded for %s; treating it as changed\n", secretName)
		case m.config.ChangeDetection.Enable && m.hashStore != nil:
			changed, err := m.hashStore.hasChanged(secretPath)
			if err != nil {
				if !m.config.ErrorHandling.ContinueOnError {
					return err
				}
				fmt.Fprintf(os.Stderr, "WARNING: Failed to check changes for %s; treating it as changed: %v\n", secretName, err)
				break
			}
			hasChanged = changed
		}

		if hasChanged {
			changedSecrets = append(changedSecrets, secretName)
			changedServiceActions = append(changedServiceActions, actions...)
		}
	}

	// Save hash store if we have changes and change detection is enabled
	if len(changedSecrets) > 0 && m.config.ChangeDetection.Enable && m.hashStore != nil {
		if err := m.hashStore.save(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Failed to save hash store: %v\n", err)
		}
	}

	if len(changedServiceActions) > 0 {
		fmt.Printf("INFO: Processing %d changed secrets: %v\n", len(changedSecrets), changedSecrets)
	}

	recoveryActions, err := m.collectRecoveryActions(configuredServiceActions, changedServiceActions)
	if err != nil {
		return err
	}

	allServiceActions := append(changedServiceActions, recoveryActions...)
	if len(allServiceActions) > 0 {
		return m.processServiceActions(allServiceActions)
	}

	fmt.Printf("INFO: No secret changes detected, skipping service restarts\n")
	return nil
}

func (m *Manager) collectRecoveryActions(configuredActions, _ []ServiceAction) ([]ServiceAction, error) {
	var recoveryActions []ServiceAction
	for _, action := range configuredActions {
		recoverService, err := m.shouldRecoverService(action.Name)
		if err != nil {
			if m.config.ErrorHandling.ContinueOnError {
				fmt.Fprintf(os.Stderr, "WARNING: Failed to determine recovery state for %s: %v\n", action.Name, err)
				continue
			}
			return nil, err
		}
		if !recoverService {
			continue
		}

		recoveryAction := action
		recoveryAction.Start = true
		recoveryAction.Restart = false
		recoveryAction.Signal = ""
		recoveryActions = append(recoveryActions, recoveryAction)
	}

	if len(recoveryActions) > 0 {
		var serviceNames []string
		for _, action := range recoveryActions {
			serviceNames = append(serviceNames, action.Name)
		}
		fmt.Printf("INFO: Recovering %d services after successful secret processing: %v\n", len(recoveryActions), serviceNames)
	}

	return recoveryActions, nil
}

// processServiceActions executes the required service actions
func (m *Manager) processServiceActions(actions []ServiceAction) error {
	// Group actions by service to avoid duplicate operations
	serviceActions := make(map[string]ServiceAction)
	for _, action := range actions {
		// Start wins over restart/reload because try-restart is a no-op for inactive units.
		if existing, exists := serviceActions[action.Name]; exists {
			if existing.Start {
				continue
			}

			if action.Start {
				serviceActions[action.Name] = action
			} else if action.Restart && !existing.Restart {
				serviceActions[action.Name] = action
			}
		} else {
			serviceActions[action.Name] = action
		}
	}

	// Execute actions with retry logic
	var failures []string
	for serviceName, action := range serviceActions {
		if err := m.executeServiceAction(action); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", serviceName, err))

			if !m.config.ErrorHandling.ContinueOnError {
				return errors.ServiceError(
					fmt.Sprintf("Executing service action for %s", serviceName),
					serviceName,
					"start/restart/reload",
					err,
				)
			}
		}
	}

	if len(failures) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: Some service actions failed: %v\n", failures)
	}

	return nil
}

// buildCommand returns the argument vector for a service action, along with a
// description of what it is about to do.
//
// This is split out from executeServiceAction so the shape of each command can
// be asserted without a systemd host. The signal case in particular was wrong
// for the lifetime of the feature and there was no seam to catch it.
func (m *Manager) buildCommand(action ServiceAction) (string, []string, string) {
	switch {
	case action.Start:
		return m.systemctl, []string{"--no-block", "start", action.Name},
			fmt.Sprintf("Starting service %s", action.Name)
	case action.Signal != "":
		// systemctl resolves the unit's main process itself. The previous
		// implementation shelled out to kill(1) with the literal string
		// "$(systemctl show -p MainPID --value <unit>)" as its PID operand;
		// exec.Command does not invoke a shell, so nothing ever performed that
		// substitution and the signal was never delivered.
		return m.systemctl, []string{"kill", "--signal=" + action.Signal, action.Name},
			fmt.Sprintf("Sending %s signal to service %s", action.Signal, action.Name)
	case action.Restart:
		return m.systemctl, []string{"--no-block", "try-restart", action.Name},
			fmt.Sprintf("Restarting service %s", action.Name)
	default:
		return m.systemctl, []string{"--no-block", "reload", action.Name},
			fmt.Sprintf("Reloading service %s", action.Name)
	}
}

// attemptLimit returns how many times a service action may be tried.
//
// MaxRetries counts retries beyond the first attempt, which is what its name
// says and what a user setting it to 0 expects. The previous loop treated it as
// a total attempt count and then used it as an exclusive bound, so the absent
// or zero value ran the body zero times: systemctl was never invoked, lastErr
// stayed nil, and the caller recorded a success.
func (m *Manager) attemptLimit() int {
	attempts := m.config.ErrorHandling.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	return attempts
}

// executeServiceAction executes a single service action with retry logic
func (m *Manager) executeServiceAction(action ServiceAction) error {
	cmd, args, intent := m.buildCommand(action)
	attempts := m.attemptLimit()

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			fmt.Printf("INFO: Retrying service action for %s (attempt %d/%d)\n",
				action.Name, attempt, attempts)
			retrySleep(time.Duration(attempt-1) * time.Second)
		}

		if m.dryRun {
			fmt.Printf("DRY-RUN: Would execute: %s %s\n", cmd, strings.Join(args, " "))
			return nil
		}

		// G204: cmd is the systemctl resolved once at startup, and every
		// argument is either a literal or a unit name from administrator
		// configuration. No shell is involved, so nothing is word-split or
		// expanded; signal names are checked against a known set at parse time.
		execCmd := exec.Command(cmd, args...) //nolint:gosec
		output, err := execCmd.CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("command failed: %v, output: %s", err, string(output))
			continue
		}

		// Report what happened, not what was intended: the log line used to be
		// printed before the command ran, so it claimed a restart even when the
		// command was never executed.
		fmt.Printf("INFO: %s succeeded\n", intent)
		return nil
	}

	if lastErr == nil {
		// Defensive: never report success for a command that was not run.
		return fmt.Errorf("service action for %s was never attempted", action.Name)
	}
	return lastErr
}

// retrySleep is a variable so tests can run the retry loop without waiting.
var retrySleep = time.Sleep

// knownSignals are the signals a service may be asked to reload on. Restricting
// the set gives a clear error at configuration time rather than a systemctl
// failure at deploy time, and keeps a user-supplied string from being
// concatenated into a command line unchecked.
var knownSignals = map[string]struct{}{
	"SIGHUP": {}, "SIGINT": {}, "SIGQUIT": {}, "SIGTERM": {},
	"SIGUSR1": {}, "SIGUSR2": {}, "SIGWINCH": {},
	"HUP": {}, "INT": {}, "QUIT": {}, "TERM": {},
	"USR1": {}, "USR2": {}, "WINCH": {},
}

func validateSignal(signal, serviceName, secretName string) error {
	if _, ok := knownSignals[signal]; ok {
		return nil
	}
	return errors.ConfigError(
		fmt.Sprintf("Parsing services for secret %s", secretName),
		fmt.Sprintf("Service %q requests unsupported signal %q; use one of SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2 or SIGWINCH", serviceName, signal),
		nil,
	)
}

// SetDryRun enables dry-run mode for testing
func (m *Manager) SetDryRun(dryRun bool) {
	m.dryRun = dryRun
}

// IsServiceRunning checks if a systemd service is currently running
func (m *Manager) IsServiceRunning(serviceName string) (bool, error) {
	status, err := m.getServiceStatus(serviceName)
	if err != nil {
		return false, err
	}

	return status.ActiveState == "active", nil
}

func (m *Manager) shouldRecoverService(serviceName string) (bool, error) {
	status, err := m.getServiceStatus(serviceName)
	if err != nil {
		return false, err
	}

	if status.ActiveState == "active" {
		return false, nil
	}

	if status.ActiveState == "failed" {
		return true, nil
	}

	return status.ActiveState == "inactive" && status.Result == "dependency", nil
}

func (m *Manager) getServiceStatus(serviceName string) (serviceStatus, error) {
	// G204: see executeServiceAction — resolved binary, no shell.
	cmd := exec.Command(m.systemctl, "show", serviceName, "--property=ActiveState", "--property=SubState", "--property=Result") //nolint:gosec
	output, err := cmd.Output()
	if err != nil {
		return serviceStatus{}, errors.ServiceError(
			"Checking service status",
			serviceName,
			"show",
			err,
		)
	}

	status := serviceStatus{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		switch parts[0] {
		case "ActiveState":
			status.ActiveState = parts[1]
		case "SubState":
			status.SubState = parts[1]
		case "Result":
			status.Result = parts[1]
		}
	}

	if status.ActiveState == "" {
		return serviceStatus{}, errors.ServiceError(
			"Checking service status",
			serviceName,
			"show",
			fmt.Errorf("missing ActiveState in systemctl output"),
		)
	}

	return status, nil
}

// ValidateServices checks that all configured services exist and are valid
func (m *Manager) ValidateServices(services []string) error {
	for _, serviceName := range services {
		// Check if service unit exists
		// G204: see executeServiceAction — resolved binary, no shell.
		cmd := exec.Command(m.systemctl, "cat", serviceName) //nolint:gosec
		if err := cmd.Run(); err != nil {
			return errors.ServiceError(
				"Validating service configuration",
				serviceName,
				"cat",
				fmt.Errorf("service unit not found or not accessible"),
			)
		}
	}

	return nil
}
