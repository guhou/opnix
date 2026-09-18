package systemd

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/brizzbuzz/opnix/internal/config"
)

// noRetrySleep removes the backoff for the duration of a test.
func noRetrySleep(t *testing.T) {
	t.Helper()
	original := retrySleep
	retrySleep = func(time.Duration) {}
	t.Cleanup(func() { retrySleep = original })
}

func testManager(maxRetries int) *Manager {
	return &Manager{
		config: config.SystemdIntegration{
			Enable:        true,
			ErrorHandling: config.ErrorHandling{MaxRetries: maxRetries},
		},
		// Anything that actually runs against this path fails, so a nil error
		// proves no command was executed.
		systemctl: "/definitely/not/a/real/systemctl",
	}
}

// MaxRetries counts retries beyond the first attempt, so 0 — the value an
// absent JSON field parses to — must still run the command once.
func TestExecuteServiceActionAlwaysAttemptsOnce(t *testing.T) {
	noRetrySleep(t)

	for _, maxRetries := range []int{0, 1, 3} {
		m := testManager(maxRetries)
		err := m.executeServiceAction(ServiceAction{Name: "caddy.service", Restart: true})
		if err == nil {
			t.Fatalf("MaxRetries=%d: executeServiceAction reported success without invoking systemctl", maxRetries)
		}
		if strings.Contains(err.Error(), "never attempted") {
			t.Fatalf("MaxRetries=%d: the command was not run at all: %v", maxRetries, err)
		}
	}
}

func TestAttemptLimit(t *testing.T) {
	tests := []struct {
		maxRetries int
		want       int
	}{
		{maxRetries: -5, want: 1},
		{maxRetries: 0, want: 1},
		{maxRetries: 1, want: 2},
		{maxRetries: 3, want: 4},
	}

	for _, tt := range tests {
		if got := testManager(tt.maxRetries).attemptLimit(); got != tt.want {
			t.Errorf("MaxRetries=%d: attemptLimit() = %d, want %d", tt.maxRetries, got, tt.want)
		}
	}
}

// exec.Command does not invoke a shell, so the command has to name the unit
// directly rather than embedding a command substitution for its PID.
func TestBuildCommand(t *testing.T) {
	m := &Manager{systemctl: "/run/current-system/sw/bin/systemctl"}

	tests := []struct {
		name   string
		action ServiceAction
		want   []string
	}{
		{
			name:   "start",
			action: ServiceAction{Name: "caddy.service", Start: true},
			want:   []string{"--no-block", "start", "caddy.service"},
		},
		{
			name:   "signal",
			action: ServiceAction{Name: "nginx.service", Signal: "SIGHUP"},
			want:   []string{"kill", "--signal=SIGHUP", "nginx.service"},
		},
		{
			name:   "restart",
			action: ServiceAction{Name: "caddy.service", Restart: true},
			want:   []string{"--no-block", "try-restart", "caddy.service"},
		},
		{
			name:   "reload",
			action: ServiceAction{Name: "caddy.service"},
			want:   []string{"--no-block", "reload", "caddy.service"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args, _ := m.buildCommand(tt.action)
			if cmd != m.systemctl {
				t.Errorf("Expected the command to be the systemctl resolved at startup, got %q", cmd)
			}
			if !reflect.DeepEqual(args, tt.want) {
				t.Errorf("Expected args %v, got %v", tt.want, args)
			}
			for _, arg := range args {
				if strings.Contains(arg, "$(") {
					t.Errorf("Argument %q contains a command substitution; exec.Command does not run a shell", arg)
				}
			}
		})
	}
}

func TestExtractServiceActionsRejectsUnknownSignal(t *testing.T) {
	m := &Manager{config: config.SystemdIntegration{Enable: true, RestartOnChange: true}}

	_, err := m.ExtractServiceActions(config.Secret{
		Services: map[string]interface{}{
			"nginx": map[string]interface{}{"restart": false, "signal": "SIGNOTASIGNAL"},
		},
	}, "secret[0]")
	if err == nil {
		t.Fatal("Expected an unsupported signal to be rejected")
	}
	if !strings.Contains(err.Error(), "SIGNOTASIGNAL") {
		t.Fatalf("Expected the error to name the offending signal, got: %v", err)
	}
}

func TestExtractServiceActionsAcceptsKnownSignals(t *testing.T) {
	m := &Manager{config: config.SystemdIntegration{Enable: true, RestartOnChange: true}}

	for _, signal := range []string{"SIGHUP", "HUP", "SIGUSR1", "SIGTERM"} {
		actions, err := m.ExtractServiceActions(config.Secret{
			Services: map[string]interface{}{
				"nginx": map[string]interface{}{"restart": false, "signal": signal},
			},
		}, "secret[0]")
		if err != nil {
			t.Fatalf("Expected %s to be accepted, got: %v", signal, err)
		}
		if len(actions) != 1 || actions[0].Signal != signal {
			t.Fatalf("Expected a single action carrying %s, got %#v", signal, actions)
		}
	}
}

// A null signal is what the Nix module emits for a service that does not set
// one, and it must not be mistaken for a request to signal.
func TestExtractServiceActionsIgnoresNullSignal(t *testing.T) {
	m := &Manager{config: config.SystemdIntegration{Enable: true, RestartOnChange: true}}

	actions, err := m.ExtractServiceActions(config.Secret{
		Services: map[string]interface{}{
			"caddy": map[string]interface{}{"restart": true, "signal": nil},
		},
	}, "secret[0]")
	if err != nil {
		t.Fatalf("Failed to extract service actions: %v", err)
	}
	if len(actions) != 1 || actions[0].Signal != "" || !actions[0].Restart {
		t.Fatalf("Expected a plain restart action, got %#v", actions)
	}
}
