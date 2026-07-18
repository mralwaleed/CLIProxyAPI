package providerusage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// fixedNow keeps fetchedAt / reset comparisons deterministic.
var fixedNow = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)

func newManager(t *testing.T, auths ...*coreauth.Auth) *coreauth.Manager {
	t.Helper()
	m := coreauth.NewManager(nil, nil, nil)
	for _, a := range auths {
		if _, err := m.Register(context.Background(), a); err != nil {
			t.Fatalf("register auth: %v", err)
		}
	}
	return m
}

func newService() *Service {
	s := NewService()
	s.now = func() time.Time { return fixedNow }
	return s
}

func codexOAuthAuth(serverURL, accountID string) *coreauth.Auth {
	return &coreauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{"base_url": serverURL},
		Metadata: map[string]any{
			"access_token": "test-token-value",
			"account_id":   accountID,
			"email":        "alice@example.com",
			"plan_type":    "plus",
			"expired":      fixedNow.Add(24 * time.Hour).Format(time.RFC3339),
		},
	}
}

const sampleUsageBody = `{
  "plan_type": "plus",
  "rate_limit": {
    "limit_reached": false,
    "primary_window": {"used_percent": 22, "reset_at": 1753100000},
    "secondary_window": {"used_percent": 40, "reset_at": 1753700000}
  },
  "rate_limit_reset_credits": {"available_count": 3}
}`

// usageServer returns a mock wham/usage server. If token is non-empty it asserts
// the request carried the expected bearer token + account id headers.
func usageServer(t *testing.T, status int, body string, hits *int32, requireHeaders bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		if requireHeaders {
			if got := r.Header.Get("Authorization"); got != "Bearer test-token-value" {
				t.Errorf("Authorization header = %q, want Bearer test-token-value", got)
			}
			if got := r.Header.Get("Chatgpt-Account-Id"); got == "" {
				t.Errorf("Chatgpt-Account-Id header missing")
			}
			if got := r.Header.Get("User-Agent"); !strings.Contains(got, "codex_cli_rs") {
				t.Errorf("User-Agent = %q, want codex_cli_rs", got)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
}

// ---- identity ----

func TestStableID_DeterministicAndNamespaced(t *testing.T) {
	a := codexOAuthAuth("", "00000000-0000-0000-0000-000000000001")
	id1 := StableID(a)
	id2 := StableID(a)
	if id1 != id2 {
		t.Fatalf("StableID not deterministic: %q vs %q", id1, id2)
	}
	if !strings.HasPrefix(id1, "codex:account_") {
		t.Fatalf("StableID %q must be namespaced codex:account_", id1)
	}
}

func TestStableID_DiffersAcrossAccounts(t *testing.T) {
	a := codexOAuthAuth("", "00000000-0000-0000-0000-000000000001")
	b := codexOAuthAuth("", "11111111-2222-3333-4444-555555555555")
	if StableID(a) == StableID(b) {
		t.Fatalf("distinct accounts must have distinct stable IDs")
	}
}

func TestStableID_APIKeyUsesKeyShape(t *testing.T) {
	a := &coreauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{"api_key": "sk-test", "base_url": "https://x"},
	}
	id := StableID(a)
	if !strings.HasPrefix(id, "codex:key_") {
		t.Fatalf("api-key credential ID %q must use codex:key_ shape", id)
	}
}

// ---- listing ----

func TestList_MultipleProvidersAndDedup(t *testing.T) {
	a := codexOAuthAuth("", "00000000-0000-0000-0000-000000000001")
	a2 := codexOAuthAuth("", "11111111-2222-3333-4444-555555555555")
	a2.Metadata["email"] = "bob@example.com"
	apiKey := &coreauth.Auth{Provider: "codex", Attributes: map[string]string{"api_key": "sk-x", "base_url": "https://x"}}
	m := newManager(t, a, a2, a, apiKey) // a registered twice -> dedup

	svc := newService()
	list := svc.List(m)
	if len(list.Providers) != 3 {
		t.Fatalf("expected 3 providers (2 oauth + 1 api key), got %d", len(list.Providers))
	}
	supported := 0
	for _, p := range list.Providers {
		if p.UsageSupported {
			supported++
		}
		if !strings.HasPrefix(p.ID, "codex:") {
			t.Fatalf("provider id %q not namespaced", p.ID)
		}
		if p.DisplayName == "" {
			t.Fatalf("provider %q has empty displayName", p.ID)
		}
	}
	if supported != 2 {
		t.Fatalf("expected 2 usageSupported providers (oauth only), got %d", supported)
	}
}

// ---- normalization ----

func TestUsage_SuccessNormalization(t *testing.T) {
	var hits int32
	srv := usageServer(t, 200, sampleUsageBody, &hits, true)
	defer srv.Close()

	auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
	m := newManager(t, auth)
	id := StableID(auth)

	svc := newService()
	res := svc.Usage(context.Background(), nil, m, id, false)
	if res.HTTPStatus != 200 || res.Error != nil {
		t.Fatalf("status=%d err=%+v", res.HTTPStatus, res.Error)
	}
	u := res.Usage
	if u.Provider.ID != id {
		t.Fatalf("provider id = %q want %q", u.Provider.ID, id)
	}
	if u.RawProviderType != "codex" {
		t.Fatalf("rawProviderType = %q", u.RawProviderType)
	}
	if len(u.Meters) < 2 {
		t.Fatalf("expected >=2 meters, got %d", len(u.Meters))
	}
	primary := u.Meters[0]
	if primary.ID != "primary" || primary.Kind != "rate_limit" || primary.Unit != "%" {
		t.Fatalf("primary meter wrong: %+v", primary)
	}
	if primary.Used == nil || *primary.Used != 22 {
		t.Fatalf("primary used = %v", primary.Used)
	}
	if primary.Remaining == nil || *primary.Remaining != 78 {
		t.Fatalf("primary remaining = %v want 78", primary.Remaining)
	}
	if primary.Limit == nil || *primary.Limit != 100 {
		t.Fatalf("primary limit = %v want 100", primary.Limit)
	}
	if primary.Window != "5h" {
		t.Fatalf("primary window = %q", primary.Window)
	}
	if primary.ResetAt == nil || primary.UnknownReset {
		t.Fatalf("primary resetAt missing or marked unknown")
	}
	if primary.ResetAt.Equal(time.Unix(1753100000, 0).UTC()) == false {
		t.Fatalf("primary resetAt = %v", primary.ResetAt)
	}
	// Convenience fields map balance<-primary, subscription<-secondary.
	if u.Balance == nil || *u.Balance.Remaining != 78 || *u.Balance.Total != 100 {
		t.Fatalf("balance wrong: %+v", u.Balance)
	}
	if u.Subscription == nil || u.Subscription.ResetAt == nil {
		t.Fatalf("subscription missing")
	}
	if !strings.Contains(u.Message, "5h:") || !strings.Contains(u.Message, "weekly:") {
		t.Fatalf("message = %q", u.Message)
	}
	if !u.FetchedAt.Equal(fixedNow) {
		t.Fatalf("fetchedAt = %v want %v", u.FetchedAt, fixedNow)
	}
}

func TestUsage_NoTokenLeakage(t *testing.T) {
	var hits int32
	srv := usageServer(t, 200, sampleUsageBody, &hits, false)
	defer srv.Close()

	auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.Usage == nil {
		t.Fatalf("expected usage")
	}
	b, _ := json.Marshal(res.Usage)
	out := string(b)
	if strings.Contains(out, "test-token-value") {
		t.Fatalf("response leaks access token: %s", out)
	}
	if strings.Contains(out, "00000000-0000-0000-0000-000000000001") {
		t.Fatalf("response leaks account id: %s", out)
	}
	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("response leaks full email: %s", out)
	}
	if !strings.Contains(out, "a***@example.com") {
		t.Fatalf("expected masked email in displayName: %s", out)
	}
}

// ---- error / edge cases ----

func TestUsage_ProviderNotFound(t *testing.T) {
	m := newManager(t, codexOAuthAuth("", "00000000-0000-0000-0000-000000000001"))
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, "codex:account_nope", false)
	if res.HTTPStatus != 404 || res.Error == nil || res.Error.Code != CodeProviderNotFound {
		t.Fatalf("want 404/not-found, got %+v", res)
	}
}

func TestUsage_UnsupportedAPIKey(t *testing.T) {
	apiKey := &coreauth.Auth{Provider: "codex", Attributes: map[string]string{"api_key": "sk-x", "base_url": "https://x"}}
	m := newManager(t, apiKey)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(apiKey), false)
	if res.HTTPStatus != 422 || res.Error.Code != CodeUsageUnsupported {
		t.Fatalf("want 422/unsupported for api-key, got %+v", res)
	}
}

func TestUsage_UnsupportedProviderType(t *testing.T) {
	// gemini OAuth is a supported OAuth shape but has no usage adapter -> 422.
	// (Claude is now a supported usage provider, so it no longer hits this path.)
	auth := &coreauth.Auth{Provider: "gemini", Metadata: map[string]any{"access_token": "t", "email": "c@x.com"}}
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.HTTPStatus != 422 || res.Error.Code != CodeUsageUnsupported {
		t.Fatalf("want 422/unsupported for gemini, got %+v", res)
	}
}

func TestUsage_NoTokenAttached(t *testing.T) {
	auth := codexOAuthAuth("", "00000000-0000-0000-0000-000000000001")
	delete(auth.Metadata, "access_token") // oauth but no token
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.HTTPStatus != 409 || res.Error.Code != CodeCredentialMissing {
		t.Fatalf("want 409/credential-missing, got %+v", res)
	}
}

func TestUsage_ExpiredToken(t *testing.T) {
	auth := codexOAuthAuth("", "00000000-0000-0000-0000-000000000001")
	auth.Metadata["expired"] = fixedNow.Add(-time.Hour).Format(time.RFC3339)
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.HTTPStatus != 403 || res.Error.Code != CodeCredentialExpired {
		t.Fatalf("want 403/expired, got %+v", res)
	}
}

func TestUsage_MissingAccountID(t *testing.T) {
	var hits int32
	srv := usageServer(t, 200, sampleUsageBody, &hits, false)
	defer srv.Close()
	auth := codexOAuthAuth(srv.URL, "")
	delete(auth.Metadata, "account_id")
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.HTTPStatus != 503 || res.Error.Code != CodeCredentialIncomplete {
		t.Fatalf("want 503/incomplete, got %+v", res)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("upstream must not be called when account id missing, hits=%d", hits)
	}
}

func TestUsage_UpstreamErrors(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		wantCode string
		wantHTTP int
	}{
		{"upstream401", 401, CodeCredentialUnauthorized, 403},
		{"upstream403", 403, CodeCredentialUnauthorized, 403},
		{"upstream429", 429, CodeUpstreamRateLimited, 429},
		{"upstream500", 500, CodeUpstreamFailed, 502},
		{"upstream503", 503, CodeUpstreamFailed, 502},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := usageServer(t, tc.status, `{"error":"x"}`, nil, false)
			defer srv.Close()
			auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
			m := newManager(t, auth)
			svc := newService()
			res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
			if res.HTTPStatus != tc.wantHTTP {
				t.Fatalf("http = %d want %d", res.HTTPStatus, tc.wantHTTP)
			}
			if res.Error == nil || res.Error.Code != tc.wantCode {
				t.Fatalf("code = %+v want %s", res.Error, tc.wantCode)
			}
		})
	}
}

func TestUsage_MalformedJSON(t *testing.T) {
	srv := usageServer(t, 200, `{not json`, nil, false)
	defer srv.Close()
	auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.HTTPStatus != 502 || res.Error.Code != CodeUpstreamMalformed {
		t.Fatalf("want 502/malformed, got %+v", res)
	}
}

func TestUsage_NestedStringifiedJSON(t *testing.T) {
	// rate_limit delivered as a JSON string; whole structure must still parse.
	body := `{
	  "plan_type": "plus",
	  "rate_limit": "{\"limit_reached\":false,\"primary_window\":{\"used_percent\":10,\"reset_at\":1753100000},\"secondary_window\":{\"used_percent\":20,\"reset_at\":1753700000}}",
	  "rate_limit_reset_credits": "{\"available_count\":1}"
	}`
	srv := usageServer(t, 200, body, nil, false)
	defer srv.Close()
	auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.HTTPStatus != 200 || res.Usage == nil {
		t.Fatalf("expected 200 success for stringified JSON, got %+v", res)
	}
	if res.Usage.Meters[0].Used == nil || *res.Usage.Meters[0].Used != 10 {
		t.Fatalf("primary used = %v want 10", res.Usage.Meters[0].Used)
	}
}

func TestUsage_MissingQuotaFields(t *testing.T) {
	// No rate_limit at all: normalization should still produce meters with
	// unknowns and not panic.
	srv := usageServer(t, 200, `{"plan_type":"plus"}`, nil, false)
	defer srv.Close()
	auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.HTTPStatus != 200 || res.Usage == nil {
		t.Fatalf("expected 200 with unknowns, got %+v", res)
	}
	for _, mm := range res.Usage.Meters {
		if mm.Limit == nil {
			t.Fatalf("percent meter %q missing limit", mm.ID)
		}
		if !mm.UnknownReset {
			t.Fatalf("meter %q should have unknown reset when reset_at absent", mm.ID)
		}
	}
}

// ---- cache + concurrency ----

func TestUsage_CacheHitAvoidsUpstream(t *testing.T) {
	var hits int32
	srv := usageServer(t, 200, sampleUsageBody, &hits, false)
	defer srv.Close()
	auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
	m := newManager(t, auth)
	svc := newService()
	id := StableID(auth)

	_ = svc.Usage(context.Background(), nil, m, id, false)
	_ = svc.Usage(context.Background(), nil, m, id, false)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 upstream hit with caching, got %d", got)
	}
	// Force refresh bypasses the cache.
	_ = svc.Usage(context.Background(), nil, m, id, true)
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 upstream hits after force refresh, got %d", got)
	}
}

func TestUsage_FailureCachedBriefly(t *testing.T) {
	var hits int32
	srv := usageServer(t, 500, `{"e":"x"}`, &hits, false)
	defer srv.Close()
	auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
	m := newManager(t, auth)
	svc := newService()
	id := StableID(auth)
	r1 := svc.Usage(context.Background(), nil, m, id, false)
	r2 := svc.Usage(context.Background(), nil, m, id, false)
	if r1.HTTPStatus != 502 || r2.HTTPStatus != 502 {
		t.Fatalf("want 502 both, got %d/%d", r1.HTTPStatus, r2.HTTPStatus)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("failure should be cached briefly (1 hit), got %d", got)
	}
}

func TestUsage_ConcurrentSingleflight(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(80 * time.Millisecond) // slow so callers overlap
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, sampleUsageBody)
	}))
	defer srv.Close()

	auth := codexOAuthAuth(srv.URL, "00000000-0000-0000-0000-000000000001")
	m := newManager(t, auth)
	svc := newService()
	id := StableID(auth)

	const n = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]*Result, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = svc.Usage(context.Background(), nil, m, id, false)
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("singleflight should collapse to 1 upstream hit, got %d", got)
	}
	for i, r := range results {
		if r == nil || r.HTTPStatus != 200 {
			t.Fatalf("result %d not 200: %+v", i, r)
		}
	}
}

func TestUsage_MultipleAccountsResolveIndependently(t *testing.T) {
	var hitsA, hitsB int32
	srvA := usageServer(t, 200, sampleUsageBody, &hitsA, false)
	srvB := usageServer(t, 200, sampleUsageBody, &hitsB, false)
	defer srvA.Close()
	defer srvB.Close()

	a := codexOAuthAuth(srvA.URL, "00000000-0000-0000-0000-000000000001")
	a.Metadata["email"] = "alice@example.com"
	b := codexOAuthAuth(srvB.URL, "11111111-2222-3333-4444-555555555555")
	b.Metadata["email"] = "bob@example.com"
	m := newManager(t, a, b)
	svc := newService()

	ra := svc.Usage(context.Background(), nil, m, StableID(a), false)
	rb := svc.Usage(context.Background(), nil, m, StableID(b), false)
	if ra.HTTPStatus != 200 || rb.HTTPStatus != 200 {
		t.Fatalf("both accounts must fetch, got %d/%d", ra.HTTPStatus, rb.HTTPStatus)
	}
	if ra.Usage.Provider.ID == rb.Usage.Provider.ID {
		t.Fatalf("two accounts must resolve to different provider ids")
	}
	if hitsA != 1 || hitsB != 1 {
		t.Fatalf("each account must hit its own upstream once, got %d/%d", hitsA, hitsB)
	}
}

// ---- Claude (Anthropic) adapter ----

// claudeOAuthAuth builds a Claude OAuth credential pointing at an upstream mock
// via the base_url attribute. No account_id is persisted (Claude falls back to
// the email-derived stable id, which is the existing contract).
func claudeOAuthAuth(serverURL string) *coreauth.Auth {
	return &coreauth.Auth{
		Provider:   "claude",
		Attributes: map[string]string{"base_url": serverURL},
		Metadata: map[string]any{
			"access_token": "claude-test-token",
			"email":        "claude@example.com",
			"expired":      fixedNow.Add(24 * time.Hour).Format(time.RFC3339),
		},
	}
}

const sampleClaudeUsageBody = `{
  "five_hour": {"utilization": 0.25, "resets_at": "2026-07-13T05:00:00Z"},
  "seven_day": {"utilization": 0.0, "resets_at": "2026-07-20T00:00:00Z"},
  "seven_day_opus": {"utilization": 0.5, "resets_at": "2026-07-20T00:00:00Z"},
  "iguana_necktie": {"utilization": 0.1, "resets_at": "2026-07-20T00:00:00Z"},
  "extra_usage": {"is_enabled": true, "monthly_limit": 100, "used_credits": 25, "utilization": 0.25}
}`

const sampleClaudeProfileBody = `{
  "account": {"uuid": "acc-1", "display_name": "Claude User", "email": "claude@example.com", "has_claude_max": true, "has_claude_pro": false},
  "organization": {"uuid": "org-1", "name": "Personal", "rate_limit_tier": "tier_5"}
}`

// claudeUpstreamServer returns a mock that serves /api/oauth/usage and
// /api/oauth/profile. When requireHeaders is set it asserts the bearer token and
// anthropic-beta header are present on every request.
func claudeUpstreamServer(t *testing.T, usageBody, profileBody string, hits *int32, requireHeaders bool, usageStatus int) *httptest.Server {
	t.Helper()
	if usageStatus == 0 {
		usageStatus = 200
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		if requireHeaders {
			if got := r.Header.Get("Authorization"); got != "Bearer claude-test-token" {
				t.Errorf("Authorization = %q, want Bearer claude-test-token", got)
			}
			if got := r.Header.Get("anthropic-beta"); got != "oauth-2025-04-20" {
				t.Errorf("anthropic-beta = %q, want oauth-2025-04-20", got)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/oauth/usage"):
			w.WriteHeader(usageStatus)
			_, _ = io.WriteString(w, usageBody)
		case strings.HasSuffix(r.URL.Path, "/api/oauth/profile"):
			w.WriteHeader(200)
			_, _ = io.WriteString(w, profileBody)
		default:
			w.WriteHeader(404)
		}
	}))
}

func meterByID(meters []Meter, id string) (Meter, bool) {
	for _, m := range meters {
		if m.ID == id {
			return m, true
		}
	}
	return Meter{}, false
}

func TestList_ClaudeUsageSupported(t *testing.T) {
	auth := claudeOAuthAuth("")
	m := newManager(t, auth)
	svc := newService()
	list := svc.List(m)

	var claude *Provider
	for i := range list.Providers {
		if list.Providers[i].Type == "claude" {
			claude = &list.Providers[i]
		}
	}
	if claude == nil {
		t.Fatalf("claude provider not listed: %+v", list.Providers)
	}
	if !claude.UsageSupported {
		t.Fatalf("claude oauth must be usageSupported")
	}
	if !strings.HasPrefix(claude.ID, "claude:account_") {
		t.Fatalf("claude id = %q, want claude:account_ prefix", claude.ID)
	}
}

func TestClaudeUsage_Normalization(t *testing.T) {
	var hits int32
	srv := claudeUpstreamServer(t, sampleClaudeUsageBody, sampleClaudeProfileBody, &hits, true, 200)
	defer srv.Close()

	auth := claudeOAuthAuth(srv.URL)
	m := newManager(t, auth)
	id := StableID(auth)

	svc := newService()
	res := svc.Usage(context.Background(), nil, m, id, false)
	if res.HTTPStatus != 200 || res.Error != nil {
		t.Fatalf("status=%d err=%+v", res.HTTPStatus, res.Error)
	}
	u := res.Usage
	if u.Provider.ID != id || u.RawProviderType != "claude" {
		t.Fatalf("provider = %+v", u.Provider)
	}

	// five_hour utilization 0.25 -> used 25, remaining 75.
	five, ok := meterByID(u.Meters, "five_hour")
	if !ok {
		t.Fatalf("missing five_hour meter: %+v", u.Meters)
	}
	if five.Used == nil || *five.Used != 25 {
		t.Fatalf("five_hour used = %v want 25", five.Used)
	}
	if five.Remaining == nil || *five.Remaining != 75 {
		t.Fatalf("five_hour remaining = %v want 75", five.Remaining)
	}
	if five.Limit == nil || *five.Limit != 100 || five.Window != "5h" || five.Unit != "%" {
		t.Fatalf("five_hour meta wrong: %+v", five)
	}
	if five.ResetAt == nil || five.UnknownReset {
		t.Fatalf("five_hour resetAt missing")
	}

	// seven_day utilization 0.0 -> used 0, remaining 100.
	seven, ok := meterByID(u.Meters, "seven_day")
	if !ok {
		t.Fatalf("missing seven_day meter")
	}
	if seven.Used == nil || *seven.Used != 0 {
		t.Fatalf("seven_day used = %v want 0", seven.Used)
	}
	if seven.Remaining == nil || *seven.Remaining != 100 {
		t.Fatalf("seven_day remaining = %v want 100", seven.Remaining)
	}

	// A scoped weekly window is preserved.
	opus, ok := meterByID(u.Meters, "seven_day_opus")
	if !ok || opus.Used == nil || *opus.Used != 50 {
		t.Fatalf("seven_day_opus scoped meter wrong: %+v", opus)
	}

	// Plan derived from profile, extra-usage credits meter preserved.
	if !strings.Contains(u.Message, "plan: max") {
		t.Fatalf("message = %q", u.Message)
	}
	extra, ok := meterByID(u.Meters, "extra_usage")
	if !ok || extra.Used == nil || *extra.Used != 25 || extra.Limit == nil || *extra.Limit != 100 {
		t.Fatalf("extra_usage meter wrong: %+v", extra)
	}

	// Convenience fields: balance <- five-hour, subscription <- seven-day.
	if u.Balance == nil || *u.Balance.Remaining != 75 {
		t.Fatalf("balance wrong: %+v", u.Balance)
	}
	if u.Subscription == nil || *u.Subscription.Remaining != 100 {
		t.Fatalf("subscription wrong: %+v", u.Subscription)
	}
	if !u.FetchedAt.Equal(fixedNow) {
		t.Fatalf("fetchedAt = %v want %v", u.FetchedAt, fixedNow)
	}
}

func TestClaudeUsage_ZeroUtilizationFullRemaining(t *testing.T) {
	body := `{
	  "five_hour": {"utilization": 0.0, "resets_at": "2026-07-13T05:00:00Z"},
	  "seven_day": {"utilization": 0.0, "resets_at": "2026-07-20T00:00:00Z"}
	}`
	srv := claudeUpstreamServer(t, body, sampleClaudeProfileBody, nil, false, 200)
	defer srv.Close()

	auth := claudeOAuthAuth(srv.URL)
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.HTTPStatus != 200 || res.Usage == nil {
		t.Fatalf("expected 200, got %+v", res)
	}
	for _, id := range []string{"five_hour", "seven_day"} {
		meter, ok := meterByID(res.Usage.Meters, id)
		if !ok {
			t.Fatalf("missing %s meter", id)
		}
		if meter.Used == nil || *meter.Used != 0 {
			t.Fatalf("%s used = %v want 0", id, meter.Used)
		}
		if meter.Remaining == nil || *meter.Remaining != 100 {
			t.Fatalf("%s remaining = %v want 100 at zero utilization", id, meter.Remaining)
		}
	}
}

func TestClaudeUsage_FableScopedLimit(t *testing.T) {
	// A "limits" array with a scoped weekly limit per model (Fable). The percent
	// is already on a 0-100 scale and must NOT be multiplied. The identity rides
	// in the "type" field (Claude limit objects are not documented to use "name")
	// and the reset uses the "resets_at" spelling like the rolling windows. The
	// second limit echoes the seven_day window (same value + reset) and must be
	// dropped as a redundant duplicate.
	body := `{
	  "five_hour": {"utilization": 0.0, "resets_at": "2026-07-13T05:00:00Z"},
	  "seven_day": {"utilization": 0.0, "resets_at": "2026-07-20T00:00:00Z"},
	  "limits": [
	    {"type": "weekly_scoped", "model": "claude-fable-5", "percent": 30, "resets_at": "2026-07-20T00:00:00Z"},
	    {"type": "weekly", "percent": 0, "resets_at": "2026-07-20T00:00:00Z"}
	  ]
	}`
	srv := claudeUpstreamServer(t, body, sampleClaudeProfileBody, nil, false, 200)
	defer srv.Close()

	auth := claudeOAuthAuth(srv.URL)
	mm := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, mm, StableID(auth), false)
	if res.HTTPStatus != 200 || res.Usage == nil {
		t.Fatalf("expected 200, got %+v", res)
	}

	// five_hour + seven_day + the Fable scoped limit; the redundant weekly echo
	// is dropped.
	if len(res.Usage.Meters) != 3 {
		t.Fatalf("expected 3 meters after dedup, got %d: %+v", len(res.Usage.Meters), res.Usage.Meters)
	}
	var fable *Meter
	for i := range res.Usage.Meters {
		if strings.Contains(strings.ToLower(res.Usage.Meters[i].Label), "fable") {
			fable = &res.Usage.Meters[i]
		}
	}
	if fable == nil {
		t.Fatalf("expected a fable scoped meter, got %+v", res.Usage.Meters)
	}
	// percent 30 -> used 30, remaining 70 (NOT 3000 / 70).
	if fable.Used == nil || *fable.Used != 30 {
		t.Fatalf("fable used = %v want 30", fable.Used)
	}
	if fable.Remaining == nil || *fable.Remaining != 70 {
		t.Fatalf("fable remaining = %v want 70", fable.Remaining)
	}
	if fable.Limit == nil || *fable.Limit != 100 || fable.Window != "weekly" {
		t.Fatalf("fable meta wrong: %+v", fable)
	}
	if fable.ResetAt == nil || fable.UnknownReset {
		t.Fatalf("fable resets_at not parsed: %+v", fable)
	}
}

func TestClaudeUsage_UpstreamAuthFailure(t *testing.T) {
	srv := claudeUpstreamServer(t, `{"error":"unauthorized"}`, sampleClaudeProfileBody, nil, false, 401)
	defer srv.Close()

	auth := claudeOAuthAuth(srv.URL)
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	// 401 upstream -> 403 USAGE_UNAUTHORIZED (NOT usageSupported false / 422).
	if res.HTTPStatus != 403 || res.Error == nil || res.Error.Code != CodeCredentialUnauthorized {
		t.Fatalf("want 403/USAGE_UNAUTHORIZED for upstream 401, got %+v", res)
	}
}

func TestClaudeUsage_NoTokenLeakage(t *testing.T) {
	srv := claudeUpstreamServer(t, sampleClaudeUsageBody, sampleClaudeProfileBody, nil, false, 200)
	defer srv.Close()

	auth := claudeOAuthAuth(srv.URL)
	m := newManager(t, auth)
	svc := newService()
	res := svc.Usage(context.Background(), nil, m, StableID(auth), false)
	if res.Usage == nil {
		t.Fatalf("expected usage")
	}
	out := string(jsonMustMarshal(t, res.Usage))
	if strings.Contains(out, "claude-test-token") {
		t.Fatalf("response leaks access token: %s", out)
	}
	// Profile is fetched but only the plan label is extracted; the full email /
	// display name from the profile must not be echoed.
	if strings.Contains(out, "claude@example.com") {
		t.Fatalf("response leaks full email: %s", out)
	}
	if !strings.Contains(out, "c***@example.com") {
		t.Fatalf("expected masked email in displayName: %s", out)
	}
}

func jsonMustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
