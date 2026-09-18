package onepass

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/1password/onepassword-sdk-go"
	"github.com/brizzbuzz/opnix/internal/errors"
)

const (
	defaultInitAttempts    = 3
	defaultResolveAttempts = 3
)

type sdkSecretsAPI interface {
	Resolve(context.Context, string) (string, error)
	ResolveAll(context.Context, []string) (onepassword.ResolveAllResponse, error)
}

type sdkVaultsAPI interface {
	List(context.Context, ...onepassword.VaultListParams) ([]onepassword.VaultOverview, error)
}

type sdkItemsAPI interface {
	Get(context.Context, string, string) (onepassword.Item, error)
	List(context.Context, string, ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error)
}

type sdkFilesAPI interface {
	Read(context.Context, string, string, onepassword.FileAttributes) ([]byte, error)
}

type sdkAPIs struct {
	secrets sdkSecretsAPI
	vaults  sdkVaultsAPI
	items   sdkItemsAPI
	files   sdkFilesAPI
}

type Client struct {
	secrets sdkSecretsAPI
	vaults  sdkVaultsAPI
	items   sdkItemsAPI
	files   sdkFilesAPI
}

var (
	newSDKClient = func(ctx context.Context, token string) (sdkAPIs, error) {
		client, err := onepassword.NewClient(
			ctx,
			onepassword.WithServiceAccountToken(token),
			onepassword.WithIntegrationInfo("NixOS Secrets Integration", "v1.0.0"),
		)
		if err != nil {
			return sdkAPIs{}, err
		}
		items := client.Items()
		return sdkAPIs{
			secrets: client.Secrets(),
			vaults:  client.Vaults(),
			items:   items,
			files:   items.Files(),
		}, nil
	}
	retrySleep = time.Sleep
)

// TokenSource describes where the service account token should be read from.
type TokenSource struct {
	// File is the path to the token file.
	File string
	// FileExplicit records that the user named this file, rather than it being
	// the built-in default. An explicitly named file takes precedence over
	// OP_SERVICE_ACCOUNT_TOKEN.
	FileExplicit bool
}

// DefaultTokenFile returns a source for a path the user did not ask for.
func DefaultTokenFile(path string) TokenSource {
	return TokenSource{File: path}
}

// ExplicitTokenFile returns a source for a path the user named themselves.
func ExplicitTokenFile(path string) TokenSource {
	return TokenSource{File: path, FileExplicit: true}
}

// GetToken resolves the service account token from a file or the environment.
//
// A file the user named explicitly wins over OP_SERVICE_ACCOUNT_TOKEN, because
// naming a file is a stronger statement of intent than an ambient variable.
// Previously the environment always won, silently: a developer with a staging
// token exported could point opnix at a production token file and resolve
// staging values into production paths, with a successful exit and nothing in
// the output to explain it.
//
// For a defaulted path the environment still wins, which keeps the SDK's usual
// convention working for CI — but it now says so.
func GetToken(source TokenSource) (string, error) {
	envToken := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")

	if source.File != "" && (source.FileExplicit || envToken == "") {
		data, err := os.ReadFile(source.File)
		if err != nil {
			if envToken != "" {
				fmt.Fprintf(os.Stderr,
					"WARNING: Cannot read the token file %s (%v); falling back to OP_SERVICE_ACCOUNT_TOKEN\n",
					source.File, err)
				return envToken, nil
			}
			return "", errors.TokenError(
				fmt.Sprintf("Failed to read token file: %s", err.Error()),
				source.File,
				err,
			)
		}
		token := strings.TrimSpace(string(data))
		if len(token) == 0 {
			return "", errors.TokenError(
				"Token file is empty",
				source.File,
				nil,
			)
		}
		if envToken != "" {
			fmt.Fprintf(os.Stderr,
				"INFO: Using the token file %s; OP_SERVICE_ACCOUNT_TOKEN is set but was not requested\n",
				source.File)
		}
		return token, nil
	}

	if envToken != "" {
		if source.File != "" {
			if _, err := os.Stat(source.File); err == nil {
				fmt.Fprintf(os.Stderr,
					"WARNING: Using OP_SERVICE_ACCOUNT_TOKEN from the environment; ignoring the token file %s\n",
					source.File)
			}
		}
		return envToken, nil
	}

	return "", errors.TokenError(
		"No token provided - neither OP_SERVICE_ACCOUNT_TOKEN environment variable nor token file specified",
		source.File,
		nil,
	)
}

func NewClient(source TokenSource) (*Client, error) {
	token, err := GetToken(source)
	if err != nil {
		return nil, err
	}

	apis, err := retryOperation(defaultInitAttempts, "Initializing 1Password client", func() (sdkAPIs, error) {
		return newSDKClient(context.Background(), token)
	}, shouldRetryProviderError)
	if err != nil {
		return nil, errors.OnePasswordError(
			"Initializing 1Password client",
			"Failed to create 1Password SDK client - check token validity",
			// Classify as the resolution paths do, so a rate-limited
			// initialisation exits 75 and RestartPreventExitStatus applies to
			// it. Without this it exited 1 and systemd retried immediately.
			classifyTopLevelProviderError(err),
		)
	}

	return &Client{secrets: apis.secrets, vaults: apis.vaults, items: apis.items, files: apis.files}, nil
}

func (c *Client) ResolveSecret(reference string) (string, error) {
	secrets, err := c.ResolveSecrets([]string{reference})
	if err != nil {
		return "", err
	}
	return secrets[reference], nil
}

func (c *Client) ResolveSecrets(references []string) (map[string]string, error) {
	response, err := retryOperation(defaultResolveAttempts, "Resolving 1Password references", func() (onepassword.ResolveAllResponse, error) {
		return c.secrets.ResolveAll(context.Background(), references)
	}, shouldRetryProviderError)
	if err != nil {
		return nil, errors.OnePasswordError(
			"Resolving 1Password secrets",
			"Failed to resolve 1Password references",
			classifyTopLevelProviderError(err),
		)
	}

	resolved := make(map[string]string, len(references))
	var failures []*errors.ProviderError
	for _, reference := range references {
		individual, ok := response.IndividualResponses[reference]
		if !ok {
			failures = append(failures, &errors.ProviderError{
				Kind:      errors.ProviderErrorOther,
				Reference: reference,
				Issue:     "1Password did not return a result for this reference",
			})
			continue
		}

		if individual.Error != nil {
			failures = append(failures, classifyResolveReferenceError(reference, *individual.Error))
			continue
		}
		if individual.Content == nil {
			failures = append(failures, &errors.ProviderError{
				Kind:      errors.ProviderErrorOther,
				Reference: reference,
				Issue:     "1Password returned an empty result for this reference",
			})
			continue
		}

		resolved[reference] = individual.Content.Secret
	}

	if len(failures) > 0 {
		return nil, &errors.ProviderResolutionError{Failures: failures}
	}

	return resolved, nil
}

func (c *Client) ResolveFiles(references []string) (map[string][]byte, error) {
	ctx := context.Background()
	vaults, err := retryOperation(defaultResolveAttempts, "Listing 1Password vaults", func() ([]onepassword.VaultOverview, error) {
		return c.vaults.List(ctx)
	}, shouldRetryProviderError)
	if err != nil {
		return nil, errors.OnePasswordError(
			"Resolving 1Password files",
			"Failed to list 1Password vaults",
			classifyTopLevelProviderError(err),
		)
	}

	resolved := make(map[string][]byte, len(references))
	itemsByVault := make(map[string][]onepassword.ItemOverview)
	itemCache := make(map[string]onepassword.Item)
	var failures []*errors.ProviderError

	for _, reference := range references {
		vaultSelector, itemSelector, fileSelector, parseErr := parseFileReference(reference)
		if parseErr != nil {
			failures = append(failures, &errors.ProviderError{
				Kind: errors.ProviderErrorInvalidReference, Reference: reference, Issue: parseErr.Error(),
			})
			continue
		}

		vault, failure := matchVault(reference, vaultSelector, vaults)
		if failure != nil {
			failures = append(failures, failure)
			continue
		}

		itemOverviews, ok := itemsByVault[vault.ID]
		if !ok {
			itemOverviews, err = retryOperation(defaultResolveAttempts, "Listing 1Password items", func() ([]onepassword.ItemOverview, error) {
				return c.items.List(ctx, vault.ID)
			}, shouldRetryProviderError)
			if err != nil {
				failures = append(failures, classifyFileProviderError(reference, "failed to list items", err))
				continue
			}
			itemsByVault[vault.ID] = itemOverviews
		}

		itemOverview, failure := matchItem(reference, itemSelector, itemOverviews)
		if failure != nil {
			failures = append(failures, failure)
			continue
		}

		cacheKey := vault.ID + "/" + itemOverview.ID
		item, ok := itemCache[cacheKey]
		if !ok {
			item, err = retryOperation(defaultResolveAttempts, "Reading 1Password item", func() (onepassword.Item, error) {
				return c.items.Get(ctx, vault.ID, itemOverview.ID)
			}, shouldRetryProviderError)
			if err != nil {
				failures = append(failures, classifyFileProviderError(reference, "failed to read item", err))
				continue
			}
			itemCache[cacheKey] = item
		}

		attributes, failure := matchFile(reference, fileSelector, item)
		if failure != nil {
			failures = append(failures, failure)
			continue
		}

		content, readErr := retryOperation(defaultResolveAttempts, "Reading 1Password file", func() ([]byte, error) {
			return c.files.Read(ctx, vault.ID, itemOverview.ID, attributes)
		}, shouldRetryProviderError)
		if readErr != nil {
			failures = append(failures, classifyFileProviderError(reference, "failed to read file", readErr))
			continue
		}
		resolved[reference] = content
	}

	if len(failures) > 0 {
		return nil, &errors.ProviderResolutionError{Failures: failures}
	}
	return resolved, nil
}

func parseFileReference(reference string) (string, string, string, error) {
	if !strings.HasPrefix(reference, "op://") {
		return "", "", "", fmt.Errorf("file reference must use op://Vault/Item/filename")
	}
	parts := strings.Split(strings.TrimPrefix(reference, "op://"), "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("file reference must contain exactly vault, item, and filename")
	}
	decoded := make([]string, len(parts))
	for i, part := range parts {
		value, err := url.PathUnescape(part)
		if err != nil || value == "" {
			return "", "", "", fmt.Errorf("file reference contains an invalid or empty component")
		}
		decoded[i] = value
	}
	return decoded[0], decoded[1], decoded[2], nil
}

func matchVault(reference, selector string, vaults []onepassword.VaultOverview) (onepassword.VaultOverview, *errors.ProviderError) {
	var matches []onepassword.VaultOverview
	for _, vault := range vaults {
		if vault.ID == selector || vault.Title == selector {
			matches = append(matches, vault)
		}
	}
	if len(matches) == 0 {
		return onepassword.VaultOverview{}, &errors.ProviderError{Kind: errors.ProviderErrorMissingReference, Reference: reference, Issue: "vault not found"}
	}
	if len(matches) > 1 {
		return onepassword.VaultOverview{}, &errors.ProviderError{Kind: errors.ProviderErrorAmbiguousReference, Reference: reference, Issue: "multiple vaults match exactly"}
	}
	return matches[0], nil
}

func matchItem(reference, selector string, items []onepassword.ItemOverview) (onepassword.ItemOverview, *errors.ProviderError) {
	var matches []onepassword.ItemOverview
	for _, item := range items {
		if item.ID == selector || item.Title == selector {
			matches = append(matches, item)
		}
	}
	if len(matches) == 0 {
		return onepassword.ItemOverview{}, &errors.ProviderError{Kind: errors.ProviderErrorMissingReference, Reference: reference, Issue: "item not found"}
	}
	if len(matches) > 1 {
		return onepassword.ItemOverview{}, &errors.ProviderError{Kind: errors.ProviderErrorAmbiguousReference, Reference: reference, Issue: "multiple items match exactly"}
	}
	return matches[0], nil
}

func matchFile(reference, selector string, item onepassword.Item) (onepassword.FileAttributes, *errors.ProviderError) {
	matches := make(map[string]onepassword.FileAttributes)
	if item.Document != nil && item.Document.Name == selector {
		matches[item.Document.ID] = *item.Document
	}
	for _, file := range item.Files {
		if file.Attributes.Name == selector {
			matches[file.Attributes.ID] = file.Attributes
		}
	}
	if len(matches) == 0 {
		return onepassword.FileAttributes{}, &errors.ProviderError{Kind: errors.ProviderErrorMissingReference, Reference: reference, Issue: "file not found"}
	}
	if len(matches) > 1 {
		return onepassword.FileAttributes{}, &errors.ProviderError{Kind: errors.ProviderErrorAmbiguousReference, Reference: reference, Issue: "multiple files have this filename"}
	}
	for _, attributes := range matches {
		return attributes, nil
	}
	panic("unreachable")
}

func classifyFileProviderError(reference, operation string, err error) *errors.ProviderError {
	var rateLimited *onepassword.RateLimitExceededError
	if stderrors.As(err, &rateLimited) {
		return &errors.ProviderError{Kind: errors.ProviderErrorRateLimited, Reference: reference, Issue: "1Password rate limit exceeded", Cause: err}
	}
	return &errors.ProviderError{Kind: errors.ProviderErrorTransient, Reference: reference, Issue: operation, Cause: err}
}

func retryOperation[T any](attempts int, operation string, fn func() (T, error), shouldRetry ...func(error) bool) (T, error) {
	var zero T
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		value, err := fn()
		if err == nil {
			return value, nil
		}

		lastErr = err
		if len(shouldRetry) > 0 && !shouldRetry[0](err) {
			break
		}
		if attempt == attempts {
			break
		}

		fmt.Fprintf(os.Stderr, "WARNING: %s attempt %d/%d failed: %v\n", operation, attempt, attempts, err)
		retrySleep(time.Duration(attempt) * time.Second)
	}

	return zero, fmt.Errorf("%s failed after %d attempts: %w", operation, attempts, lastErr)
}

func shouldRetryProviderError(err error) bool {
	var rateLimited *onepassword.RateLimitExceededError
	return !stderrors.As(err, &rateLimited)
}

func classifyTopLevelProviderError(err error) error {
	var rateLimited *onepassword.RateLimitExceededError
	if stderrors.As(err, &rateLimited) {
		return &errors.ProviderResolutionError{Failures: []*errors.ProviderError{{
			Kind:  errors.ProviderErrorRateLimited,
			Issue: "1Password rate limit exceeded; wait for the provider reset window before retrying",
			Cause: err,
		}}}
	}
	return &errors.ProviderResolutionError{Failures: []*errors.ProviderError{{
		Kind:  errors.ProviderErrorTransient,
		Issue: err.Error(),
		Cause: err,
	}}}
}

func classifyResolveReferenceError(reference string, err onepassword.ResolveReferenceError) *errors.ProviderError {
	switch err.Type {
	case onepassword.ResolveReferenceErrorTypeVariantVaultNotFound,
		onepassword.ResolveReferenceErrorTypeVariantItemNotFound,
		onepassword.ResolveReferenceErrorTypeVariantFieldNotFound,
		onepassword.ResolveReferenceErrorTypeVariantNoMatchingSections:
		return &errors.ProviderError{Kind: errors.ProviderErrorMissingReference, Reference: reference, Issue: string(err.Type)}
	case onepassword.ResolveReferenceErrorTypeVariantParsing:
		return &errors.ProviderError{Kind: errors.ProviderErrorInvalidReference, Reference: reference, Issue: string(err.Parsing())}
	case onepassword.ResolveReferenceErrorTypeVariantTooManyVaults,
		onepassword.ResolveReferenceErrorTypeVariantTooManyItems,
		onepassword.ResolveReferenceErrorTypeVariantTooManyMatchingFields:
		return &errors.ProviderError{Kind: errors.ProviderErrorAmbiguousReference, Reference: reference, Issue: string(err.Type)}
	case onepassword.ResolveReferenceErrorTypeVariantUnsupportedFileFormat:
		return &errors.ProviderError{Kind: errors.ProviderErrorOther, Reference: reference, Issue: `unsupported file format; configure this secret with kind = "file"`}
	default:
		return &errors.ProviderError{Kind: errors.ProviderErrorOther, Reference: reference, Issue: string(err.Type)}
	}
}
