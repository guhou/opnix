package secrets

import (
	"strings"
	"testing"
	"time"
)

// Mutually referential variable values used to feed the processor's own output
// back into its substitution loop, which never terminated. Run under a timeout
// so a regression fails the suite instead of hanging it.
func TestProcessorSubstituteVariablesTerminates(t *testing.T) {
	tests := []struct {
		name      string
		template  string
		defaults  map[string]string
		variables map[string]string
	}{
		{
			name:     "mutually referential defaults",
			template: "/etc/secrets/{a}",
			defaults: map[string]string{"a": "{b}", "b": "{a}"},
		},
		{
			name:     "self-referential default",
			template: "/etc/secrets/{a}",
			defaults: map[string]string{"a": "{a}"},
		},
		{
			name:      "self-referential secret variable",
			template:  "{service}/password",
			variables: map[string]string{"service": "{service}"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewProcessorWithConfig(&mockClient{}, "/tmp/out", "", tt.defaults)

			type outcome struct {
				path string
				err  error
			}
			done := make(chan outcome, 1)
			go func() {
				path, err := processor.substituteVariables(tt.template, tt.variables, "secret[0]")
				done <- outcome{path: path, err: err}
			}()

			select {
			case got := <-done:
				if got.err == nil {
					t.Fatalf("Expected a brace-valued variable to be rejected, got path %q", got.path)
				}
				if !strings.Contains(got.err.Error(), "brace") {
					t.Fatalf("Expected an error naming the offending brace, got: %v", got.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("substituteVariables did not return; the substitution loop is unbounded again")
			}
		})
	}
}

func TestProcessorSubstituteVariablesExpandsOnce(t *testing.T) {
	processor := NewProcessorWithConfig(&mockClient{}, "/tmp/out", "", map[string]string{
		"environment": "prod",
	})

	got, err := processor.substituteVariables(
		"/etc/secrets/{environment}/{service}/{service}.pem",
		map[string]string{"service": "caddy"},
		"secret[0]",
	)
	if err != nil {
		t.Fatalf("Failed to substitute variables: %v", err)
	}
	if want := "/etc/secrets/prod/caddy/caddy.pem"; got != want {
		t.Fatalf("Expected %q, got %q", want, got)
	}
}

func TestProcessorSubstituteVariablesRejectsUnknownVariable(t *testing.T) {
	processor := NewProcessorWithConfig(&mockClient{}, "/tmp/out", "", nil)

	if _, err := processor.substituteVariables("/etc/secrets/{missing}", nil, "secret[0]"); err == nil {
		t.Fatal("Expected an unknown template variable to be rejected")
	}
}
