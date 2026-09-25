package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/brizzbuzz/opnix/internal/config"
)

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Failed to stat %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("Unexpected FileInfo.Sys type for %s", path)
	}
	return uint64(stat.Ino)
}

// A secret destination is a directory entry to be replaced, never a path to be
// followed: an unprivileged user who plants a symlink there must not be able to
// redirect the write, the mode change, or the ownership change onto its target.
func TestProcessorReplacesSymlinkAtDestination(t *testing.T) {
	tmpDir := t.TempDir()
	canary := filepath.Join(tmpDir, "canary")
	if err := os.WriteFile(canary, []byte("do-not-touch"), 0644); err != nil {
		t.Fatalf("Failed to create canary file: %v", err)
	}

	outputDir := filepath.Join(tmpDir, "out")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}
	outputPath := filepath.Join(outputDir, "apiToken")
	if err := os.Symlink(canary, outputPath); err != nil {
		t.Fatalf("Failed to plant symlink: %v", err)
	}

	processor := NewProcessor(&mockClient{secrets: map[string]string{
		"op://vault/item/field": "secret-value",
	}}, outputDir)
	if _, err := processor.Process(&config.Config{Secrets: []config.Secret{{
		Path:      "apiToken",
		Reference: "op://vault/item/field",
		Mode:      "0600",
	}}}); err != nil {
		t.Fatalf("Failed to process secret: %v", err)
	}

	canaryContent, err := os.ReadFile(canary)
	if err != nil {
		t.Fatalf("Failed to read canary file: %v", err)
	}
	if string(canaryContent) != "do-not-touch" {
		t.Fatalf("Secret was written through the symlink; canary now holds %q", canaryContent)
	}
	canaryInfo, err := os.Stat(canary)
	if err != nil {
		t.Fatalf("Failed to stat canary file: %v", err)
	}
	if canaryInfo.Mode().Perm() != 0644 {
		t.Fatalf("Symlink target was chmoded to %04o, expected it to stay 0644", canaryInfo.Mode().Perm())
	}

	info, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatalf("Failed to stat secret file: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("Destination is still a symlink; expected it to be replaced by a regular file")
	}
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read secret file: %v", err)
	}
	if string(content) != "secret-value" {
		t.Fatalf("Expected secret content %q, got %q", "secret-value", content)
	}
}

// The secret must never be visible at its final path under the previous file's
// permissions, so a pre-existing world-readable file is replaced rather than
// truncated and rewritten in place.
func TestProcessorReplacesFileRatherThanRewritingInPlace(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "apiToken")
	if err := os.WriteFile(outputPath, []byte("stale-value"), 0644); err != nil {
		t.Fatalf("Failed to create existing secret: %v", err)
	}
	if err := os.Chmod(outputPath, 0644); err != nil {
		t.Fatalf("Failed to set existing secret mode: %v", err)
	}
	before := inodeOf(t, outputPath)

	processor := NewProcessor(&mockClient{secrets: map[string]string{
		"op://vault/item/field": "fresh-value",
	}}, tmpDir)
	if _, err := processor.Process(&config.Config{Secrets: []config.Secret{{
		Path:      "apiToken",
		Reference: "op://vault/item/field",
		Mode:      "0600",
	}}}); err != nil {
		t.Fatalf("Failed to process secret: %v", err)
	}

	if after := inodeOf(t, outputPath); after == before {
		t.Fatal("Secret was rewritten in place; expected a new file renamed over the old one")
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Failed to stat secret file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("Expected permissions 0600, got %04o", info.Mode().Perm())
	}
}

// An unchanged secret must not be rewritten: the module watches the output
// directory and turns every modification into a service restart.
func TestProcessorSkipsRewriteWhenContentUnchanged(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "apiToken")

	processor := NewProcessor(&mockClient{secrets: map[string]string{
		"op://vault/item/field": "stable-value",
	}}, tmpDir)
	cfg := &config.Config{Secrets: []config.Secret{{
		Path:      "apiToken",
		Reference: "op://vault/item/field",
		Mode:      "0600",
	}}}

	if _, err := processor.Process(cfg); err != nil {
		t.Fatalf("Failed to process secret: %v", err)
	}
	before := inodeOf(t, outputPath)

	if _, err := processor.Process(cfg); err != nil {
		t.Fatalf("Failed to reprocess secret: %v", err)
	}
	if after := inodeOf(t, outputPath); after != before {
		t.Fatal("Unchanged secret was rewritten; expected the existing file to be left alone")
	}
}

// The staging file must never be left behind, and the writability probes that
// used to churn the watched directory must be gone.
func TestProcessorLeavesNoScratchFiles(t *testing.T) {
	tmpDir := t.TempDir()
	processor := NewProcessor(&mockClient{secrets: map[string]string{
		"op://vault/item/field": "secret-value",
	}}, tmpDir)
	if _, err := processor.Process(&config.Config{Secrets: []config.Secret{{
		Path:      "apiToken",
		Reference: "op://vault/item/field",
		Symlinks:  []string{filepath.Join(tmpDir, "legacy-token")},
	}}}); err != nil {
		t.Fatalf("Failed to process secret: %v", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to list output directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".opnix") {
			t.Errorf("Unexpected scratch file left in the output directory: %s", entry.Name())
		}
	}
}

func TestProcessorReplacesExistingSymlinkTarget(t *testing.T) {
	tmpDir := t.TempDir()
	symlinkPath := filepath.Join(tmpDir, "legacy-token")
	if err := os.WriteFile(symlinkPath, []byte("previous-file"), 0600); err != nil {
		t.Fatalf("Failed to create the file the symlink must replace: %v", err)
	}

	processor := NewProcessor(&mockClient{secrets: map[string]string{
		"op://vault/item/field": "secret-value",
	}}, tmpDir)
	if _, err := processor.Process(&config.Config{Secrets: []config.Secret{{
		Path:      "apiToken",
		Reference: "op://vault/item/field",
		Symlinks:  []string{symlinkPath},
	}}}); err != nil {
		t.Fatalf("Failed to process secret: %v", err)
	}

	target, err := os.Readlink(symlinkPath)
	if err != nil {
		t.Fatalf("Expected %s to be a symlink: %v", symlinkPath, err)
	}
	if want := filepath.Join(tmpDir, "apiToken"); target != want {
		t.Fatalf("Expected symlink to point at %s, got %s", want, target)
	}
}

// Normalisation must happen before the guarded-location check, or "/etc//shadow"
// walks straight past it.
func TestProcessorRejectsGuardedPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "shadow file", path: "/etc/shadow"},
		{name: "doubled separator", path: "/etc//shadow"},
		{name: "dot component", path: "/etc/./shadow"},
		{name: "sudoers drop-in", path: "/etc/sudoers.d/opnix"},
		{name: "root ssh keys", path: "/root/.ssh/authorized_keys"},
		{name: "systemd unit", path: "/etc/systemd/system/opnix-evil.service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewProcessor(&mockClient{}, t.TempDir())
			err := processor.validateSecretPath(tt.path, "secret[0]")
			if err == nil {
				t.Fatalf("Expected %s to be rejected", tt.path)
			}
			if !strings.Contains(err.Error(), "dangerous system location") {
				t.Fatalf("Expected a guarded-location error, got: %v", err)
			}
		})
	}
}

func TestProcessorAllowsPathsThatMerelyShareAPrefix(t *testing.T) {
	for _, path := range []string{
		"/etc/group-secrets/app.key",
		"/etc/passwd-sync/token",
		"/binaries/svc/cert.pem",
		"/var/lib/app..backup/secret",
	} {
		t.Run(path, func(t *testing.T) {
			processor := NewProcessor(&mockClient{}, t.TempDir())
			if err := processor.validateSecretPath(path, "secret[0]"); err != nil {
				t.Fatalf("Expected %s to be allowed, got: %v", path, err)
			}
		})
	}
}
