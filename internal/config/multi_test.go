package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("Failed to write %s: %v", name, err)
	}
	return path
}

// Two files writing to the same destination used to be a silent
// last-writer-wins race, because each file was processed by its own opnix run
// with its own seenPaths map. Merging first is what makes the conflict visible.
func TestLoadMultipleDetectsCrossFileDuplicatePaths(t *testing.T) {
	dir := t.TempDir()
	a := writeConfig(t, dir, "a.json", `{"secrets":[{"path":"shared","reference":"op://Vault/ItemA/field","mode":"0600"}]}`)
	b := writeConfig(t, dir, "b.json", `{"secrets":[{"path":"shared","reference":"op://Vault/ItemB/field","mode":"0644"}]}`)

	_, err := LoadMultiple([]string{a, b})
	if err == nil {
		t.Fatal("Expected the duplicate destination to be rejected")
	}
	if !strings.Contains(err.Error(), "Duplicate path") {
		t.Fatalf("Expected a duplicate-path error, got: %v", err)
	}
}

func TestLoadMultipleDetectsCrossFileSymlinkConflicts(t *testing.T) {
	dir := t.TempDir()
	a := writeConfig(t, dir, "a.json",
		`{"secrets":[{"path":"a","reference":"op://Vault/ItemA/field","symlinks":["/etc/ssl/legacy.pem"]}]}`)
	b := writeConfig(t, dir, "b.json",
		`{"secrets":[{"path":"b","reference":"op://Vault/ItemB/field","symlinks":["/etc/ssl/legacy.pem"]}]}`)

	if _, err := LoadMultiple([]string{a, b}); err == nil {
		t.Fatal("Expected the duplicate symlink destination to be rejected")
	}
}

// The merged config used to set only Secrets, PathTemplate and Defaults, so
// systemdIntegration was dropped on the floor.
func TestLoadMultiplePreservesSystemdIntegration(t *testing.T) {
	dir := t.TempDir()
	a := writeConfig(t, dir, "a.json", `{"secrets":[{"path":"a","reference":"op://Vault/ItemA/field"}]}`)
	b := writeConfig(t, dir, "b.json", `{
	  "secrets":[{"path":"b","reference":"op://Vault/ItemB/field"}],
	  "systemdIntegration":{"enable":true,"restartOnChange":true,"errorHandling":{"maxRetries":5}}
	}`)

	cfg, err := LoadMultiple([]string{a, b})
	if err != nil {
		t.Fatalf("Failed to load configs: %v", err)
	}
	if !cfg.SystemdIntegration.Enable {
		t.Error("Expected systemdIntegration to survive the merge")
	}
	if cfg.SystemdIntegration.ErrorHandling.MaxRetries != 5 {
		t.Errorf("Expected maxRetries 5, got %d", cfg.SystemdIntegration.ErrorHandling.MaxRetries)
	}
}

// A later file that says nothing about systemdIntegration must not silently
// reset an earlier file's settings to the zero value.
func TestLoadMultipleKeepsSystemdIntegrationFromTheFileThatSetIt(t *testing.T) {
	dir := t.TempDir()
	a := writeConfig(t, dir, "a.json", `{
	  "secrets":[{"path":"a","reference":"op://Vault/ItemA/field"}],
	  "systemdIntegration":{"enable":true,"restartOnChange":true,"errorHandling":{"maxRetries":2}}
	}`)
	b := writeConfig(t, dir, "b.json", `{"secrets":[{"path":"b","reference":"op://Vault/ItemB/field"}]}`)

	cfg, err := LoadMultiple([]string{a, b})
	if err != nil {
		t.Fatalf("Failed to load configs: %v", err)
	}
	if !cfg.SystemdIntegration.Enable {
		t.Fatal("Expected the earlier file's systemdIntegration to be kept")
	}
	if cfg.SystemdIntegration.ErrorHandling.MaxRetries != 2 {
		t.Errorf("Expected maxRetries 2, got %d", cfg.SystemdIntegration.ErrorHandling.MaxRetries)
	}
}

func TestLoadMultipleMergesSecretsInOrder(t *testing.T) {
	dir := t.TempDir()
	a := writeConfig(t, dir, "a.json", `{"secrets":[{"path":"a","reference":"op://Vault/ItemA/field"}]}`)
	b := writeConfig(t, dir, "b.json", `{"secrets":[{"path":"b","reference":"op://Vault/ItemB/field"}]}`)

	cfg, err := LoadMultiple([]string{a, b})
	if err != nil {
		t.Fatalf("Failed to load configs: %v", err)
	}
	if len(cfg.Secrets) != 2 {
		t.Fatalf("Expected 2 secrets, got %d", len(cfg.Secrets))
	}
	if cfg.Secrets[0].Path != "a" || cfg.Secrets[1].Path != "b" {
		t.Fatalf("Expected secrets in file order, got %q and %q", cfg.Secrets[0].Path, cfg.Secrets[1].Path)
	}
}
