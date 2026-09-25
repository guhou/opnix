package onepass

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/1password/onepassword-sdk-go"
	"github.com/brizzbuzz/opnix/internal/errors"
)

func writeToken(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}
	return path
}

// Naming a token file is a stronger statement of intent than an ambient
// environment variable. The previous precedence meant a developer with a
// staging token exported could point opnix at a production token file and
// silently resolve staging values, exiting 0.
func TestGetTokenPrefersExplicitFileOverEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := writeToken(t, dir, "prod-token", "ops_from_file")
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_from_env")

	got, err := GetToken(ExplicitTokenFile(path))
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if got != "ops_from_file" {
		t.Fatalf("Expected the explicitly named file to win, got %q", got)
	}
}

// A defaulted path keeps the SDK's usual convention, so CI that exports the
// variable continues to work.
func TestGetTokenPrefersEnvironmentOverDefaultedFile(t *testing.T) {
	dir := t.TempDir()
	path := writeToken(t, dir, "token", "ops_from_file")
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_from_env")

	got, err := GetToken(DefaultTokenFile(path))
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if got != "ops_from_env" {
		t.Fatalf("Expected the environment to win for a defaulted path, got %q", got)
	}
}

func TestGetTokenFallsBackToEnvironmentWhenExplicitFileIsMissing(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_from_env")

	got, err := GetToken(ExplicitTokenFile(filepath.Join(t.TempDir(), "absent")))
	if err != nil {
		t.Fatalf("Expected a fallback to the environment, got: %v", err)
	}
	if got != "ops_from_env" {
		t.Fatalf("Expected the environment token, got %q", got)
	}
}

func TestGetTokenFailsWhenExplicitFileIsMissingAndNoEnvironment(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "")

	if _, err := GetToken(ExplicitTokenFile(filepath.Join(t.TempDir(), "absent"))); err == nil {
		t.Fatal("Expected an error when neither source yields a token")
	}
}

// Rate limits are terminal until the provider's reset window: retrying is
// exactly the wrong response, and every resolution call already declines to.
func TestNewClientDoesNotRetryRateLimits(t *testing.T) {
	originalNewSDKClient := newSDKClient
	originalRetrySleep := retrySleep
	t.Cleanup(func() {
		newSDKClient = originalNewSDKClient
		retrySleep = originalRetrySleep
	})
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_test_token")
	retrySleep = func(time.Duration) {}

	attempts := 0
	newSDKClient = func(context.Context, string) (sdkAPIs, error) {
		attempts++
		return sdkAPIs{}, &onepassword.RateLimitExceededError{}
	}

	_, err := NewClient(DefaultTokenFile(""))
	if err == nil {
		t.Fatal("Expected client initialisation to fail")
	}
	if attempts != 1 {
		t.Fatalf("Expected a rate limit to end initialisation after 1 attempt, got %d", attempts)
	}

	// Exit code 75 is what RestartPreventExitStatus in the NixOS module keys
	// off. Before this, a rate-limited initialisation exited 1 and systemd
	// retried it 15 minutes later.
	if code := errors.ExitCode(err); code != errors.ExitCodeRateLimited {
		t.Fatalf("Expected exit code %d for a rate-limited initialisation, got %d", errors.ExitCodeRateLimited, code)
	}
}

// Network and DNS failures at initialisation are exactly the class the retry
// loop should cover, so they must keep retrying.
func TestNewClientStillRetriesTransientFailures(t *testing.T) {
	originalNewSDKClient := newSDKClient
	originalRetrySleep := retrySleep
	t.Cleanup(func() {
		newSDKClient = originalNewSDKClient
		retrySleep = originalRetrySleep
	})
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_test_token")
	retrySleep = func(time.Duration) {}

	attempts := 0
	newSDKClient = func(context.Context, string) (sdkAPIs, error) {
		attempts++
		return sdkAPIs{}, stderrors.New("dial tcp: lookup my.1password.com: no such host")
	}

	if _, err := NewClient(DefaultTokenFile("")); err == nil {
		t.Fatal("Expected client initialisation to fail")
	}
	if attempts != defaultInitAttempts {
		t.Fatalf("Expected %d attempts for a transient failure, got %d", defaultInitAttempts, attempts)
	}
}
