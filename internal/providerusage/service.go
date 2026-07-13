package providerusage

import (
	"context"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// Adapter normalizes upstream usage for a specific provider family.
type Adapter interface {
	// Supports reports whether the adapter can fetch usage for this credential.
	Supports(auth *coreauth.Auth) bool
	// Fetch performs the upstream call and normalizes the result. A non-nil
	// fetchError means the fetch failed in a structured way; the returned
	// UsageResponse is nil in that case.
	Fetch(ctx context.Context, cfg *config.Config, auth *coreauth.Auth, now time.Time) (*UsageResponse, *fetchError)
}

// Service is the entry point for provider listing and usage resolution. It is
// safe for concurrent use.
type Service struct {
	cache    *usageCache
	now      func() time.Time
	sf       singleflight.Group
	adapters map[string]Adapter
}

// NewService builds a Service with the built-in adapters registered.
func NewService() *Service {
	s := &Service{
		cache:    newUsageCache(),
		now:      time.Now,
		adapters: map[string]Adapter{},
	}
	s.RegisterAdapter("codex", codexAdapter{})
	return s
}

// FlushCache drops all cached results. Intended for tests and forced resets.
func (s *Service) FlushCache() {
	if s != nil && s.cache != nil {
		s.cache.flush()
	}
}

// RegisterAdapter registers (or replaces) the adapter for a provider type.
func (s *Service) RegisterAdapter(providerType string, adapter Adapter) {
	providerType = strings.ToLower(strings.TrimSpace(providerType))
	if providerType == "" || adapter == nil {
		return
	}
	s.adapters[providerType] = adapter
}

// List returns every credential exposed as a usage provider. Providers are
// de-duplicated by stable ID. Multiple credentials of the same provider type
// (e.g. several ChatGPT accounts) each appear as separate entries.
func (s *Service) List(manager *coreauth.Manager) ListResponse {
	out := ListResponse{Providers: []Provider{}}
	if manager == nil {
		return out
	}
	now := s.now()
	seen := make(map[string]bool)
	for _, auth := range manager.List() {
		if auth == nil {
			continue
		}
		auth.EnsureIndex()
		id := StableID(auth)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out.Providers = append(out.Providers, Provider{
			ID:             id,
			Type:           ProviderType(auth),
			DisplayName:    DisplayName(auth),
			UsageSupported: UsageSupported(auth),
			Status:         ProviderStatus(auth, now),
		})
	}
	return out
}

// Usage resolves a provider by stable ID and returns its normalized usage. It
// applies a short TTL cache with singleflight deduplication. When forceRefresh
// is true the cache is bypassed (a concurrent in-flight fetch is still shared).
func (s *Service) Usage(ctx context.Context, cfg *config.Config, manager *coreauth.Manager, providerID string, forceRefresh bool) *Result {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return errorResult(httpStatusNotFound, CodeProviderNotFound, "provider not found", providerID)
	}

	auth, ok := resolveByProviderID(manager, providerID)
	if !ok {
		return errorResult(httpStatusNotFound, CodeProviderNotFound, "provider not found", providerID)
	}

	if !UsageSupported(auth) {
		return errorResult(httpStatusUnprocessable, CodeUsageUnsupported, "usage is not supported for this provider", providerID)
	}
	adapter, ok := s.adapters[ProviderType(auth)]
	if !ok || adapter == nil {
		return errorResult(httpStatusUnprocessable, CodeUsageUnsupported, "usage is not supported for this provider", providerID)
	}

	if !forceRefresh {
		if cached, hit := s.cache.get(providerID, s.now()); hit {
			return cached
		}
	}

	// Deduplicate concurrent fetches for the same provider. Use a context that
	// is not cancelled by a single caller dropping the request, mirroring the
	// pattern used by the codex OAuth refresh singleflight.
	fetchCtx := ctx
	if fetchCtx == nil {
		fetchCtx = context.Background()
	} else {
		fetchCtx = context.WithoutCancel(fetchCtx)
	}

	v, _, _ := s.sf.Do(providerID, func() (any, error) {
		return s.fetchOnce(fetchCtx, cfg, auth, adapter), nil
	})
	res, _ := v.(*Result)
	if res == nil {
		return errorResult(httpStatusServiceUnavailable, CodeInternal, "usage fetch returned no result", providerID)
	}
	s.cache.set(providerID, res, s.now())
	return res
}

func (s *Service) fetchOnce(ctx context.Context, cfg *config.Config, auth *coreauth.Auth, adapter Adapter) *Result {
	now := s.now()
	usage, ferr := adapter.Fetch(ctx, cfg, auth, now)
	if ferr == nil && usage != nil {
		return &Result{HTTPStatus: httpStatusOK, Usage: usage}
	}
	if ferr == nil {
		ferr = &fetchError{code: CodeUpstreamFailed, status: httpStatusBadGateway, message: "usage fetch returned no data"}
	}
	status := ferr.status
	if status == 0 {
		status = httpStatusBadGateway
	}
	log.WithFields(log.Fields{
		"provider": StableID(auth),
		"code":     ferr.code,
	}).Debug("providerusage: fetch failed")
	return errorResult(status, ferr.code, ferr.message, StableID(auth))
}

// resolveByProviderID finds the credential whose StableID matches providerID.
func resolveByProviderID(manager *coreauth.Manager, providerID string) (*coreauth.Auth, bool) {
	if manager == nil || providerID == "" {
		return nil, false
	}
	for _, auth := range manager.List() {
		if auth == nil {
			continue
		}
		auth.EnsureIndex()
		if StableID(auth) == providerID {
			return auth, true
		}
	}
	return nil, false
}

func errorResult(status int, code, message, providerID string) *Result {
	return &Result{
		HTTPStatus: status,
		Error: &ErrorResponse{
			Status:     "error",
			Code:       code,
			Message:    message,
			ProviderID: providerID,
		},
	}
}
