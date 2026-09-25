package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/brizzbuzz/opnix/internal/config"
	"github.com/brizzbuzz/opnix/internal/errors"
	"github.com/brizzbuzz/opnix/internal/validation"
)

// tempFileAttempts bounds the retries when a randomly named staging file
// collides with an existing entry.
const tempFileAttempts = 10

// DirMode is the mode for directories opnix creates to hold secrets.
//
// 0751, not 0755: execute-without-read grants the traversal a service user
// needs to open its own secret, while withholding the directory listing. A
// nested secret path such as "nested/deep/key" used to produce world-readable
// intermediate directories, so anyone could enumerate the secrets inside them
// regardless of how the top-level directory was locked down.
//
// The NixOS and nix-darwin modules tighten the top-level output directory
// further, to 0750 owned by the opnix group. MkdirAll does not alter a
// directory that already exists, so this value only applies to ones opnix
// creates itself.
const DirMode = 0751

type SecretClient interface {
	ResolveSecrets(references []string) (map[string]string, error)
	ResolveFiles(references []string) (map[string][]byte, error)
}

type ProcessResult struct {
	SecretPaths    map[string]string // Maps secret names to their file paths
	ProcessedCount int
}

type Processor struct {
	client       SecretClient
	outputDir    string
	pathTemplate string
	defaults     map[string]string
}

func NewProcessor(client SecretClient, outputDir string) *Processor {
	return &Processor{
		client:    client,
		outputDir: outputDir,
	}
}

func NewProcessorWithConfig(client SecretClient, outputDir, pathTemplate string, defaults map[string]string) *Processor {
	return &Processor{
		client:       client,
		outputDir:    outputDir,
		pathTemplate: pathTemplate,
		defaults:     defaults,
	}
}

func (p *Processor) Process(cfg *config.Config) (*ProcessResult, error) {
	// Update processor with config-level settings
	if cfg.PathTemplate != "" {
		p.pathTemplate = cfg.PathTemplate
	}
	if len(cfg.Defaults) > 0 {
		p.defaults = cfg.Defaults
	}

	result := &ProcessResult{
		SecretPaths:    make(map[string]string),
		ProcessedCount: 0,
	}

	fieldReferences, fileReferences := uniqueReferencesByKind(cfg.Secrets)
	resolvedSecrets := make(map[string]string, len(fieldReferences))
	if len(fieldReferences) > 0 {
		var err error
		resolvedSecrets, err = p.client.ResolveSecrets(fieldReferences)
		if err != nil {
			return nil, wrapResolutionError(err)
		}
	}
	resolvedFiles := make(map[string][]byte, len(fileReferences))
	if len(fileReferences) > 0 {
		var err error
		resolvedFiles, err = p.client.ResolveFiles(fileReferences)
		if err != nil {
			return nil, wrapResolutionError(err)
		}
	}
	if err := os.MkdirAll(p.outputDir, DirMode); err != nil {
		return nil, errors.FileOperationError(
			"Creating output directory",
			p.outputDir,
			"Failed to create output directory",
			err,
		)
	}

	for i, secret := range cfg.Secrets {
		secretName := fmt.Sprintf("secret[%d]:%s", i, secret.Path)
		var value []byte
		var ok bool
		if secret.Kind == config.SecretKindFile {
			value, ok = resolvedFiles[secret.Reference]
		} else {
			var fieldValue string
			fieldValue, ok = resolvedSecrets[secret.Reference]
			value = []byte(fieldValue)
		}
		if !ok {
			return nil, errors.OnePasswordError(
				fmt.Sprintf("Resolving secret %s", secretName),
				fmt.Sprintf("Failed to resolve 1Password reference: %s", secret.Reference),
				nil,
			)
		}

		outputPath, err := p.processSecret(secret, secretName, value)
		if err != nil {
			return nil, errors.WrapWithSuggestions(
				err,
				fmt.Sprintf("Processing %s", secretName),
				"secret processing",
				[]string{
					"Check the secret configuration for errors",
					"Verify 1Password reference is correct",
					"Ensure target directory permissions are correct",
				},
			)
		}

		result.SecretPaths[secretName] = outputPath
		result.ProcessedCount++
	}

	return result, nil
}

func (p *Processor) processSecret(secret config.Secret, secretName string, value []byte) (string, error) {
	// Determine output path with enhanced path management
	outputPath, err := p.resolveSecretPathWithTemplate(secret, secretName)
	if err != nil {
		return "", err
	}

	// Validate the resolved path for security
	if err := p.validateSecretPath(outputPath, secretName); err != nil {
		return "", err
	}

	// Create parent directory if needed (validation already ensured it's writable)
	parentDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(parentDir, DirMode); err != nil {
		return "", errors.FileOperationError(
			fmt.Sprintf("Creating parent directory for %s", secretName),
			parentDir,
			"Failed to create parent directory",
			err,
		)
	}

	// Parse file permissions
	mode := secret.Mode
	if mode == "" {
		mode = "0600" // Default secure permissions
	}
	fileMode, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return "", errors.ValidationError(
			fmt.Sprintf("Parsing file mode for %s", secretName),
			"mode",
			mode,
			"3-4 digit octal number (e.g., 0600, 0644)",
		)
	}

	// Resolve the declared owner and group to numeric ids up front, so the
	// write path only ever applies them to a file descriptor it owns.
	uid, gid, err := p.resolveOwnership(secret.Owner, secret.Group, secretName)
	if err != nil {
		return "", err
	}

	if err := p.writeSecret(outputPath, value, uid, gid, os.FileMode(fileMode), mode, secretName); err != nil {
		return "", err
	}

	// Create symlinks if specified
	if err := p.createSymlinks(outputPath, secret.Symlinks, secretName); err != nil {
		return "", err
	}

	return outputPath, nil
}

func uniqueReferencesByKind(secrets []config.Secret) ([]string, []string) {
	seenFields := make(map[string]struct{}, len(secrets))
	seenFiles := make(map[string]struct{}, len(secrets))
	var fields, files []string
	for _, secret := range secrets {
		if secret.Kind == config.SecretKindFile {
			if _, ok := seenFiles[secret.Reference]; ok {
				continue
			}
			seenFiles[secret.Reference] = struct{}{}
			files = append(files, secret.Reference)
			continue
		}
		if _, ok := seenFields[secret.Reference]; ok {
			continue
		}
		seenFields[secret.Reference] = struct{}{}
		fields = append(fields, secret.Reference)
	}
	return fields, files
}

func wrapResolutionError(err error) error {
	suggestions := []string{
		"Check the failed 1Password references listed above",
		"Create any missing vaults, items, fields, or files before restarting opnix-secrets.service",
		"If rate-limited, wait for the 1Password reset window before retrying",
	}
	var resolutionErr *errors.ProviderResolutionError
	if stderrors.As(err, &resolutionErr) {
		for _, failure := range resolutionErr.Failures {
			if failure.Kind == errors.ProviderErrorMissingReference {
				suggestions = append(suggestions,
					"If this service belongs to an older NixOS generation, restore any retired 1Password references until its rollback window closes",
				)
				break
			}
		}
	}
	return errors.WrapWithSuggestions(
		err,
		"Resolving 1Password references",
		"secret processing",
		suggestions,
	)
}

// resolveOwnership resolves owner and group names to numeric ids, returning -1
// for either when it was not configured. Resolution is separated from applying
// the change so that ownership is only ever set on a file descriptor, never on
// a path that could be redirected by a symlink.
func (p *Processor) resolveOwnership(owner, group, secretName string) (int, int, error) {
	var uid, gid = -1, -1

	// Resolve owner to UID
	if owner != "" {
		if owner == "root" {
			uid = 0
		} else {
			u, err := user.Lookup(owner)
			if err != nil {
				// Get available users for suggestions
				availableUsers := p.getAvailableUsers()
				return -1, -1, errors.UserGroupError(
					fmt.Sprintf("Setting ownership for %s", secretName),
					owner,
					"user",
					availableUsers,
				)
			}
			parsedUID, err := strconv.Atoi(u.Uid)
			if err != nil {
				return -1, -1, errors.ConfigError(
					fmt.Sprintf("Parsing UID for user %s", owner),
					fmt.Sprintf("Invalid UID format: %s", u.Uid),
					err,
				)
			}
			uid = parsedUID
		}
	}

	// Resolve group to GID
	if group != "" {
		if group == "root" {
			gid = 0
		} else {
			g, err := user.LookupGroup(group)
			if err != nil {
				// Get available groups for suggestions
				availableGroups := p.getAvailableGroups()
				return -1, -1, errors.UserGroupError(
					fmt.Sprintf("Setting ownership for %s", secretName),
					group,
					"group",
					availableGroups,
				)
			}
			parsedGID, err := strconv.Atoi(g.Gid)
			if err != nil {
				return -1, -1, errors.ConfigError(
					fmt.Sprintf("Parsing GID for group %s", group),
					fmt.Sprintf("Invalid GID format: %s", g.Gid),
					err,
				)
			}
			gid = parsedGID
		}
	}

	return uid, gid, nil
}

// writeSecret places value at outputPath with the requested ownership and mode.
//
// The content is staged in a freshly created temporary file in the destination
// directory, opened with O_EXCL|O_NOFOLLOW so it cannot be redirected, and its
// ownership and mode are applied to the file descriptor with fchown(2) and
// fchmod(2). Only then is it renamed into place. rename(2) replaces the
// directory entry itself, so a symlink planted at outputPath is overwritten
// rather than followed, and a concurrent reader sees either the complete old
// file or the complete new one — never a truncated secret and never the new
// content under the old file's permissions.
//
// When the destination already holds exactly this value, the content is left
// alone and only the metadata is reconciled. That keeps unchanged secrets from
// generating spurious filesystem events for the module's path watcher.
func (p *Processor) writeSecret(outputPath string, value []byte, uid, gid int, fileMode os.FileMode, mode, secretName string) error {
	unchanged, err := reuseExistingSecret(outputPath, value, uid, gid, fileMode)
	if err != nil {
		return errors.FileOperationError(
			fmt.Sprintf("Reconciling existing secret file for %s", secretName),
			outputPath,
			fmt.Sprintf("Failed to apply ownership %s and permissions %s", ownershipDescription(uid, gid), mode),
			err,
		)
	}
	if unchanged {
		return nil
	}

	dir := filepath.Dir(outputPath)
	tmpPath, f, err := createTempSecretFile(dir)
	if err != nil {
		return errors.FileOperationError(
			fmt.Sprintf("Creating temporary secret file for %s", secretName),
			dir,
			"Failed to create a temporary file in the destination directory",
			err,
		)
	}

	if err := finalizeSecretFile(f, value, uid, gid, fileMode); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return errors.FileOperationError(
			fmt.Sprintf("Writing secret file for %s", secretName),
			outputPath,
			"Failed to write secret to file",
			err,
		)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return errors.FileOperationError(
			fmt.Sprintf("Writing secret file for %s", secretName),
			outputPath,
			"Failed to close secret file",
			err,
		)
	}

	if err := os.Rename(tmpPath, outputPath); err != nil {
		_ = os.Remove(tmpPath)
		return errors.FileOperationError(
			fmt.Sprintf("Writing secret file for %s", secretName),
			outputPath,
			"Failed to move the secret into place",
			err,
		)
	}

	return nil
}

// finalizeSecretFile writes the content and applies ownership and mode to the
// open descriptor, before the file is reachable under its final name.
func finalizeSecretFile(f *os.File, value []byte, uid, gid int, fileMode os.FileMode) error {
	if _, err := f.Write(value); err != nil {
		return err
	}
	if uid != -1 || gid != -1 {
		// fchown(2): operates on the descriptor, so it cannot be redirected.
		if err := f.Chown(uid, gid); err != nil {
			return err
		}
	}
	// fchmod(2). Set explicitly rather than relying on the open mode, which is
	// subject to the umask.
	if err := f.Chmod(fileMode); err != nil {
		return err
	}
	return f.Sync()
}

// createTempSecretFile creates a uniquely named file in dir that cannot be a
// pre-planted symlink: O_CREATE|O_EXCL fails outright if the name already
// exists, and O_NOFOLLOW refuses to traverse one.
func createTempSecretFile(dir string) (string, *os.File, error) {
	var lastErr error
	for attempt := 0; attempt < tempFileAttempts; attempt++ {
		suffix := make([]byte, 8)
		if _, err := rand.Read(suffix); err != nil {
			return "", nil, err
		}
		path := filepath.Join(dir, ".opnix-tmp-"+hex.EncodeToString(suffix))

		// G304: the destination directory is administrator-configured, and
		// O_EXCL|O_NOFOLLOW is precisely what makes opening it by path safe.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600) //nolint:gosec
		if err == nil {
			return path, f, nil
		}
		if !os.IsExist(err) {
			return "", nil, err
		}
		lastErr = err
	}
	return "", nil, lastErr
}

// reuseExistingSecret reports whether outputPath already holds value, and if so
// reconciles its ownership and mode in place.
//
// The file is opened with O_NOFOLLOW, so a symlink at the destination is never
// inspected or modified through this path: the open fails and the caller falls
// through to a fresh atomic write, which replaces the link. Any other failure to
// examine the existing file is likewise treated as "write a fresh one".
func reuseExistingSecret(outputPath string, value []byte, uid, gid int, fileMode os.FileMode) (bool, error) {
	// G304: O_NOFOLLOW is the point — see the doc comment above.
	f, err := os.OpenFile(outputPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec
	if err != nil {
		return false, nil
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(value)) {
		return false, nil
	}

	existing, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(existing, value) {
		return false, nil
	}

	if ownershipDiffers(info, uid, gid) {
		if err := f.Chown(uid, gid); err != nil {
			return false, err
		}
	}
	if info.Mode().Perm() != fileMode.Perm() {
		if err := f.Chmod(fileMode); err != nil {
			return false, err
		}
	}

	return true, nil
}

// ownershipDiffers reports whether the file needs a chown to reach the
// requested ownership. An id of -1 means "leave this one alone".
func ownershipDiffers(info os.FileInfo, uid, gid int) bool {
	if uid == -1 && gid == -1 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	if uid != -1 && int(stat.Uid) != uid {
		return true
	}
	return gid != -1 && int(stat.Gid) != gid
}

func ownershipDescription(uid, gid int) string {
	owner, group := "unchanged", "unchanged"
	if uid != -1 {
		owner = strconv.Itoa(uid)
	}
	if gid != -1 {
		group = strconv.Itoa(gid)
	}
	return owner + ":" + group
}

// getAvailableUsers returns a list of common system users for error suggestions
func (p *Processor) getAvailableUsers() []string {
	users := []string{"root"}

	// Try to get some common service users
	commonUsers := []string{"nginx", "apache", "www-data", "caddy", "postgres", "mysql", "redis", "docker"}

	for _, username := range commonUsers {
		if _, err := user.Lookup(username); err == nil {
			users = append(users, username)
		}
	}

	return users
}

// getAvailableGroups returns a list of common system groups for error suggestions
func (p *Processor) getAvailableGroups() []string {
	groups := []string{"root"}

	// Try to get some common service groups
	commonGroups := []string{"nginx", "apache", "www-data", "caddy", "postgres", "mysql", "redis", "docker", "ssl-cert"}

	for _, groupname := range commonGroups {
		if _, err := user.LookupGroup(groupname); err == nil {
			groups = append(groups, groupname)
		}
	}

	return groups
}

// resolveSecretPath resolves the final path for a secret based on custom path logic (legacy)
func (p *Processor) resolveSecretPath(secretPath, secretName string) string {
	// If path is absolute, use it directly (custom path management)
	if filepath.IsAbs(secretPath) {
		return secretPath
	}

	// For relative paths, combine with outputDir (backward compatibility)
	return filepath.Join(p.outputDir, secretPath)
}

// resolveSecretPathWithTemplate resolves the final path for a secret with template support
func (p *Processor) resolveSecretPathWithTemplate(secret config.Secret, secretName string) (string, error) {
	// If path is explicitly set, use it with variable substitution
	if secret.Path != "" {
		resolvedPath, err := p.substituteVariables(secret.Path, secret.Variables, secretName)
		if err != nil {
			return "", err
		}
		return p.resolveSecretPath(resolvedPath, secretName), nil
	}

	// If no path template is configured, return error
	if p.pathTemplate == "" {
		return "", errors.ConfigError(
			fmt.Sprintf("Resolving path for %s", secretName),
			"No path specified and no pathTemplate configured",
			nil,
		)
	}

	// Use template with variable substitution
	resolvedPath, err := p.substituteVariables(p.pathTemplate, secret.Variables, secretName)
	if err != nil {
		return "", err
	}

	return p.resolveSecretPath(resolvedPath, secretName), nil
}

// validateSecretPath rejects resolved paths that point somewhere a secret has
// no business being.
//
// This is a guardrail against configuration mistakes and shares its
// implementation with the validator, so the two cannot drift. It is explicitly
// not the boundary that keeps a secret inside its intended destination — that
// is writeSecret's O_NOFOLLOW-and-rename, which does not follow a symlink
// planted at the destination.
func (p *Processor) validateSecretPath(resolvedPath, secretName string) error {
	if validation.HasPathTraversal(resolvedPath) {
		return errors.FileOperationError(
			fmt.Sprintf("Validating path for %s", secretName),
			resolvedPath,
			"Path contains a path traversal component (..)",
			nil,
		)
	}

	if guarded, ok := validation.GuardedPath(resolvedPath); ok {
		return errors.FileOperationError(
			fmt.Sprintf("Validating path for %s", secretName),
			resolvedPath,
			fmt.Sprintf("Path resolves into potentially dangerous system location: %s", guarded),
			nil,
		)
	}

	return nil
}

// createSymlinks creates symlinks for a secret file
func (p *Processor) createSymlinks(targetPath string, symlinks []string, secretName string) error {
	for i, symlinkPath := range symlinks {
		symlinkName := fmt.Sprintf("%s.symlinks[%d]", secretName, i)

		// Validate symlink path
		if err := p.validateSecretPath(symlinkPath, symlinkName); err != nil {
			return err
		}

		// Create parent directory for symlink if needed
		parentDir := filepath.Dir(symlinkPath)
		if err := os.MkdirAll(parentDir, DirMode); err != nil {
			return errors.FileOperationError(
				fmt.Sprintf("Creating parent directory for symlink %s", symlinkName),
				parentDir,
				"Failed to create parent directory for symlink",
				err,
			)
		}

		// Create the link under a temporary name and rename it over the target.
		// Unlike remove-then-symlink, this leaves no window in which another
		// process can claim the path, and it replaces whatever is already there
		// in a single step.
		if err := replaceSymlink(targetPath, symlinkPath, parentDir); err != nil {
			return errors.FileOperationError(
				fmt.Sprintf("Creating symlink %s", symlinkName),
				symlinkPath,
				fmt.Sprintf("Failed to create symlink to %s", targetPath),
				err,
			)
		}
	}

	return nil
}

// replaceSymlink atomically points symlinkPath at targetPath.
func replaceSymlink(targetPath, symlinkPath, parentDir string) error {
	var lastErr error
	for attempt := 0; attempt < tempFileAttempts; attempt++ {
		suffix := make([]byte, 8)
		if _, err := rand.Read(suffix); err != nil {
			return err
		}
		tmpPath := filepath.Join(parentDir, ".opnix-link-"+hex.EncodeToString(suffix))

		if err := os.Symlink(targetPath, tmpPath); err != nil {
			if !os.IsExist(err) {
				return err
			}
			lastErr = err
			continue
		}

		if err := os.Rename(tmpPath, symlinkPath); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
		return nil
	}
	return lastErr
}

// substituteVariables expands {varname} placeholders in a path template.
//
// This delegates to the validator's implementation rather than carrying a
// second copy. The two had drifted: this one re-scanned its own output on every
// iteration, so a variable whose value contained braces fed itself back in and
// the loop never terminated. Because the validator accepted such a
// configuration during config.Load, the result was a root-run oneshot unit
// spinning at 100% CPU during boot.
func (p *Processor) substituteVariables(template string, variables map[string]string, secretName string) (string, error) {
	return validation.SubstituteVariables(template, variables, p.defaults, secretName)
}
