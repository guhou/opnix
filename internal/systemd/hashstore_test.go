package systemd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/brizzbuzz/opnix/internal/config"
)

func newTestHashStore(t *testing.T, hashFile string) *HashStore {
	t.Helper()
	store, err := NewHashStore(hashFile)
	if err != nil {
		t.Fatalf("Failed to create hash store: %v", err)
	}
	return store
}

// The store names every secret path on the host and holds a digest of each
// one's content, so neither it nor its key may be readable by other users.
func TestHashStoreIsNotWorldReadable(t *testing.T) {
	tempDir := t.TempDir()
	hashFile := filepath.Join(tempDir, "secret-hashes.json")

	store := newTestHashStore(t, hashFile)
	store.Hashes["/var/lib/opnix/secrets/apiToken"] = SecretHash{Path: "/var/lib/opnix/secrets/apiToken", Hash: "abc"}
	if err := store.save(); err != nil {
		t.Fatalf("Failed to save hash store: %v", err)
	}

	for _, path := range []string{hashFile, hashKeyPath(hashFile)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Failed to stat %s: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			t.Errorf("Expected %s to be inaccessible to group and others, got %04o", path, perm)
		}
	}
}

// os.WriteFile applies its perm argument only when it creates the file, so a
// store left at 0644 by an earlier release needs an explicit chmod.
func TestHashStoreTightensExistingFileMode(t *testing.T) {
	tempDir := t.TempDir()
	hashFile := filepath.Join(tempDir, "secret-hashes.json")
	if err := os.WriteFile(hashFile, []byte(`{"version":2,"hashes":{}}`), 0644); err != nil {
		t.Fatalf("Failed to seed an open hash store: %v", err)
	}
	if err := os.Chmod(hashFile, 0644); err != nil {
		t.Fatalf("Failed to set the seeded mode: %v", err)
	}

	store := newTestHashStore(t, hashFile)
	if err := store.save(); err != nil {
		t.Fatalf("Failed to save hash store: %v", err)
	}

	info, err := os.Stat(hashFile)
	if err != nil {
		t.Fatalf("Failed to stat hash store: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("Expected an existing hash store to be narrowed to 0600, got %04o", perm)
	}
}

// A bare SHA-256 of a secret lets anyone holding the store confirm a guessed
// plaintext instantly. The stored digest must not be reproducible without the
// store's key.
func TestHashStoreDigestIsKeyed(t *testing.T) {
	tempDir := t.TempDir()
	hashFile := filepath.Join(tempDir, "secret-hashes.json")
	secretFile := filepath.Join(tempDir, "apiToken")
	const secretValue = "s3cr3t-value-123"
	if err := os.WriteFile(secretFile, []byte(secretValue), 0600); err != nil {
		t.Fatalf("Failed to create secret file: %v", err)
	}

	store := newTestHashStore(t, hashFile)
	digest, err := store.calculateHash(secretFile)
	if err != nil {
		t.Fatalf("Failed to calculate digest: %v", err)
	}

	bare := sha256.Sum256([]byte(secretValue))
	if digest == hex.EncodeToString(bare[:]) {
		t.Fatal("Stored digest is a plain SHA-256 of the secret; anyone with the store can confirm a guess")
	}
}

func TestHashStoreDigestIsStableAcrossRuns(t *testing.T) {
	tempDir := t.TempDir()
	hashFile := filepath.Join(tempDir, "secret-hashes.json")
	secretFile := filepath.Join(tempDir, "apiToken")
	if err := os.WriteFile(secretFile, []byte("stable-value"), 0600); err != nil {
		t.Fatalf("Failed to create secret file: %v", err)
	}

	first := newTestHashStore(t, hashFile)
	changed, err := first.hasChanged(secretFile)
	if err != nil {
		t.Fatalf("Failed to check for changes: %v", err)
	}
	if !changed {
		t.Fatal("Expected a first sighting to count as changed")
	}
	if err := first.save(); err != nil {
		t.Fatalf("Failed to save hash store: %v", err)
	}

	// A second process must reuse the persisted key, or every run would look
	// like a change and restart every dependent service.
	second := newTestHashStore(t, hashFile)
	changed, err = second.hasChanged(secretFile)
	if err != nil {
		t.Fatalf("Failed to check for changes: %v", err)
	}
	if changed {
		t.Fatal("Expected an unchanged secret to be recognised across runs")
	}
}

// Version 1 digests were bare SHA-256 and are not comparable with the keyed
// ones, so they are discarded rather than reported as differences forever.
func TestHashStoreDiscardsLegacyDigests(t *testing.T) {
	tempDir := t.TempDir()
	hashFile := filepath.Join(tempDir, "secret-hashes.json")
	legacy := map[string]interface{}{
		"hashes": map[string]interface{}{
			"/var/lib/opnix/secrets/apiToken": map[string]interface{}{
				"path": "/var/lib/opnix/secrets/apiToken",
				"hash": "bd567158a44ada8e8e7454cd93471b888854c42945f34e27e94e4f0211178489",
			},
		},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("Failed to build a legacy hash store: %v", err)
	}
	if err := os.WriteFile(hashFile, data, 0600); err != nil {
		t.Fatalf("Failed to write a legacy hash store: %v", err)
	}

	store := newTestHashStore(t, hashFile)
	if len(store.Hashes) != 0 {
		t.Fatalf("Expected legacy digests to be discarded, got %d entries", len(store.Hashes))
	}
	if store.Version != hashStoreVersion {
		t.Fatalf("Expected the store to be upgraded to version %d, got %d", hashStoreVersion, store.Version)
	}
}

// Change detection must hash the path the processor wrote, not the raw
// configured path: a templated destination still has its braces in it, and a
// pathTemplate-only secret has no configured path at all.
func TestProcessSecretChangesUsesResolvedPaths(t *testing.T) {
	tempDir := t.TempDir()
	resolved := filepath.Join(tempDir, "cert.pem")
	if err := os.WriteFile(resolved, []byte("cert-content"), 0600); err != nil {
		t.Fatalf("Failed to create resolved secret: %v", err)
	}

	m := &Manager{
		config: config.SystemdIntegration{
			Enable:          true,
			RestartOnChange: true,
			ChangeDetection: config.ChangeDetection{Enable: true, HashFile: filepath.Join(tempDir, "h.json")},
			ErrorHandling:   config.ErrorHandling{ContinueOnError: false, MaxRetries: 1},
		},
		hashStore: newTestHashStore(t, filepath.Join(tempDir, "h.json")),
		systemctl: "/bin/true",
	}
	m.SetDryRun(true)

	secrets := []config.Secret{{Path: "/etc/secrets/{service}/cert.pem", Reference: "op://V/I/f"}}
	paths := map[string]string{"secret[0]:/etc/secrets/{service}/cert.pem": resolved}

	if err := m.ProcessSecretChanges(secrets, paths); err != nil {
		t.Fatalf("Change detection failed on a templated path: %v", err)
	}
	if _, recorded := m.hashStore.Hashes[resolved]; !recorded {
		t.Fatalf("Expected the resolved path to be hashed, store holds %v", m.hashStore.Hashes)
	}
}

// A secret whose destination could not be determined must be treated as
// changed. Skipping it means the service keeps running on a credential that
// has already been rotated on disk, with nothing in the output to say so.
func TestProcessSecretChangesFailsOpenOnUnknownPath(t *testing.T) {
	tempDir := t.TempDir()
	m := &Manager{
		config: config.SystemdIntegration{
			Enable:          true,
			RestartOnChange: true,
			ChangeDetection: config.ChangeDetection{Enable: true, HashFile: filepath.Join(tempDir, "h.json")},
			ErrorHandling:   config.ErrorHandling{ContinueOnError: true, MaxRetries: 1},
		},
		hashStore: newTestHashStore(t, filepath.Join(tempDir, "h.json")),
		systemctl: "/bin/true",
	}
	m.SetDryRun(true)

	secrets := []config.Secret{{
		Path:      "missing",
		Reference: "op://V/I/f",
		Services:  []interface{}{"caddy"},
	}}

	// No entry in secretPaths for this secret.
	if err := m.ProcessSecretChanges(secrets, map[string]string{}); err != nil {
		t.Fatalf("Expected the run to continue, got: %v", err)
	}
}
