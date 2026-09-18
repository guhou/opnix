package validation

import "testing"

func TestGuardedPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		wantGuarded string
	}{
		// Locations that must stay out of reach.
		{name: "shadow file", path: "/etc/shadow", wantGuarded: "/etc/shadow"},
		{name: "doubled separator", path: "/etc//shadow", wantGuarded: "/etc/shadow"},
		{name: "dot component", path: "/etc/./shadow", wantGuarded: "/etc/shadow"},
		{name: "leading double slash", path: "//etc/shadow", wantGuarded: "/etc/shadow"},
		{name: "sudoers drop-in", path: "/etc/sudoers.d/opnix", wantGuarded: "/etc/sudoers.d"},
		{name: "root ssh keys", path: "/root/.ssh/authorized_keys", wantGuarded: "/root/.ssh"},
		{name: "systemd unit", path: "/etc/systemd/system/evil.service", wantGuarded: "/etc/systemd/system"},
		{name: "cron drop-in", path: "/etc/cron.d/opnix", wantGuarded: "/etc/cron.d"},
		{name: "profile drop-in", path: "/etc/profile.d/opnix.sh", wantGuarded: "/etc/profile.d"},
		{name: "loader config", path: "/etc/ld.so.conf.d/opnix.conf", wantGuarded: "/etc/ld.so.conf.d"},
		{name: "pam config", path: "/etc/pam.d/sshd", wantGuarded: "/etc/pam.d"},
		{name: "shared library", path: "/lib/x.so", wantGuarded: "/lib"},
		{name: "usr shared library", path: "/usr/lib/x.so", wantGuarded: "/usr/lib"},
		{name: "nix store", path: "/nix/store/zzz-file", wantGuarded: "/nix/store"},
		{name: "system binary", path: "/usr/bin/opnix", wantGuarded: "/usr/bin"},

		// Legitimate destinations that a textual prefix test used to reject.
		{name: "group secrets dir", path: "/etc/group-secrets/app.key"},
		{name: "passwd sync dir", path: "/etc/passwd-sync/token"},
		{name: "boot config dir", path: "/boot-config/secrets/key"},
		{name: "binaries dir", path: "/binaries/svc/cert.pem"},
		{name: "devops dir", path: "/devops/secrets/api.key"},
		{name: "system secrets dir", path: "/system-secrets/k"},
		{name: "procurement dir", path: "/procurement/secrets/k"},
		{name: "usr local", path: "/usr/local/var/opnix/secrets/token"},
		{name: "default output dir", path: "/var/lib/opnix/secrets/databasePassword"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guarded, ok := GuardedPath(tt.path)
			if tt.wantGuarded == "" {
				if ok {
					t.Fatalf("GuardedPath(%q) rejected the path as %q, expected it to be allowed", tt.path, guarded)
				}
				return
			}
			if !ok {
				t.Fatalf("GuardedPath(%q) allowed the path, expected it to be guarded by %q", tt.path, tt.wantGuarded)
			}
			if guarded != tt.wantGuarded {
				t.Fatalf("GuardedPath(%q) = %q, want %q", tt.path, guarded, tt.wantGuarded)
			}
		})
	}
}

func TestHasPathTraversal(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "../../../etc/passwd", want: true},
		{path: "/var/lib/opnix/../../etc/shadow", want: true},
		{path: "..", want: true},
		{path: "secrets/../token", want: true},
		{path: "config..old", want: false},
		{path: "/var/lib/app..backup/secret", want: false},
		{path: "/var/lib/opnix/secrets/token", want: false},
		{path: "database/password", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := HasPathTraversal(tt.path); got != tt.want {
				t.Fatalf("HasPathTraversal(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestSubstituteVariablesRejectsBraceValues(t *testing.T) {
	// A value containing braces used to be spliced back into the template and
	// rescanned, which never terminated for mutually referential values.
	_, err := SubstituteVariables(
		"/etc/secrets/{a}",
		nil,
		map[string]string{"a": "{b}", "b": "{a}"},
		"secret[0]",
	)
	if err == nil {
		t.Fatal("Expected a brace-valued variable to be rejected")
	}
	if !containsString(err.Error(), "brace") {
		t.Fatalf("Expected an error naming the offending brace, got: %v", err)
	}
}

func TestSubstituteVariablesLayersVariablesOverDefaults(t *testing.T) {
	got, err := SubstituteVariables(
		"/etc/secrets/{environment}/{service}",
		map[string]string{"service": "caddy"},
		map[string]string{"environment": "prod", "service": "default"},
		"secret[0]",
	)
	if err != nil {
		t.Fatalf("Failed to substitute variables: %v", err)
	}
	if want := "/etc/secrets/prod/caddy"; got != want {
		t.Fatalf("Expected %q, got %q", want, got)
	}
}
