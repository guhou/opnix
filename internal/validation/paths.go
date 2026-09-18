package validation

import (
	"path/filepath"
	"strings"
)

// guardedPaths lists locations where a root-written file is equivalent to code
// execution or to privilege escalation.
//
// This is a guardrail against configuration mistakes, not a security boundary:
// the configuration is administrator-authored, and the check runs on the
// configured path rather than on what the kernel will ultimately resolve. The
// boundary against writing to an unintended location is the O_NOFOLLOW
// temp-file-plus-rename write in internal/secrets.
var guardedPaths = []string{
	"/bin",
	"/sbin",
	"/lib",
	"/usr/bin",
	"/usr/sbin",
	"/usr/lib",
	"/boot",
	"/dev",
	"/proc",
	"/sys",
	"/nix/store",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers.d",
	"/etc/systemd/system",
	"/etc/cron.d",
	"/etc/profile.d",
	"/etc/ld.so.conf.d",
	"/etc/pam.d",
	"/root/.ssh",
}

// GuardedPath reports the guarded location a path resolves into, if any.
//
// The path is normalised with filepath.Clean before matching, so "/etc//shadow"
// and "/etc/./shadow" are caught alongside "/etc/shadow". Matching is on whole
// path components, so a legitimate destination such as "/etc/group-secrets" is
// not mistaken for "/etc/group".
func GuardedPath(path string) (string, bool) {
	clean := filepath.Clean(path)
	for _, guarded := range guardedPaths {
		if clean == guarded || strings.HasPrefix(clean, guarded+string(filepath.Separator)) {
			return guarded, true
		}
	}
	return "", false
}

// HasPathTraversal reports whether a path contains a ".." component.
//
// A substring test would reject names that merely contain two dots, such as
// "config..old" or "/var/lib/app..backup/secret", which are not traversal.
func HasPathTraversal(path string) bool {
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component == ".." {
			return true
		}
	}
	return false
}

// GuardedPathSuggestions returns the remediation advice shown when a path lands
// in a guarded location.
func GuardedPathSuggestions() []string {
	return []string{
		"Avoid placing secrets in system directories",
		"Use /etc/secrets/, /var/lib/opnix/secrets/, or /run/secrets/ instead",
		"Consider using relative paths under the configured output directory",
	}
}
