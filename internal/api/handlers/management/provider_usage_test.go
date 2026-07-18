package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/providerusage"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func codexTestAuth() *coreauth.Auth {
	return &coreauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{"base_url": "http://example.invalid"},
		Metadata: map[string]any{
			"access_token": "test-token",
			"account_id":   "00000000-0000-0000-0000-000000000001",
			"email":        "alice@example.com",
			"plan_type":    "plus",
		},
	}
}

func TestGetProviders_HandlerListsProviders(t *testing.T) {
	usageServiceInstance().FlushCache()

	manager := coreauth.NewManager(nil, nil, nil)
	if _, err := manager.Register(context.Background(), codexTestAuth()); err != nil {
		t.Fatalf("register: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(nil, manager)

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/providers", nil)
	h.GetProviders(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Providers []struct {
			ID, Type, DisplayName, Status string
			UsageSupported                bool
		} `json:"providers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(resp.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(resp.Providers))
	}
	p := resp.Providers[0]
	if !strings.HasPrefix(p.ID, "codex:account_") {
		t.Fatalf("provider id = %q", p.ID)
	}
	if !p.UsageSupported {
		t.Fatalf("codex oauth must be usageSupported")
	}
	if strings.Contains(rec.Body.String(), "test-token") {
		t.Fatalf("response must not leak tokens: %s", rec.Body.String())
	}
}

func TestGetProviderUsage_HandlerNotFound(t *testing.T) {
	usageServiceInstance().FlushCache()

	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(nil, manager)

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/providers/codex:account_nope/usage", nil)
	ginCtx.Params = gin.Params{{Key: "providerId", Value: "codex:account_nope"}}
	h.GetProviderUsage(ginCtx)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Status, Code, Message, ProviderID string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBody.Code != "USAGE_PROVIDER_NOT_FOUND" {
		t.Fatalf("error code = %q", errBody.Code)
	}
	if errBody.Status != "error" {
		t.Fatalf("error status = %q", errBody.Status)
	}
}

func TestProviderUsage_ManagementAuthEnforced(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	usageServiceInstance().FlushCache()

	manager := coreauth.NewManager(nil, nil, nil)
	if _, err := manager.Register(context.Background(), codexTestAuth()); err != nil {
		t.Fatalf("register: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(nil, manager)

	engine := gin.New()
	grp := engine.Group("/v0/management")
	grp.Use(h.Middleware())
	grp.GET("/providers", h.GetProviders)

	// No key -> 401.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v0/management/providers", nil)
	engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no key: status = %d, want 401", rr.Code)
	}

	// Valid key -> 200.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/v0/management/providers", nil)
	req2.Header.Set("Authorization", "Bearer test-management-key")
	engine.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("with key: status = %d, want 200, body=%s", rr2.Code, rr2.Body.String())
	}
}

// ---- Claude provider support (handler / routing) ----

func claudeHandlerAuth(serverURL string) *coreauth.Auth {
	return &coreauth.Auth{
		Provider:   "claude",
		Attributes: map[string]string{"base_url": serverURL},
		Metadata: map[string]any{
			"access_token": "claude-test-token",
			"email":        "claude@example.com",
		},
	}
}

// claudeMockUpstream serves the Claude OAuth usage + profile payloads.
func claudeMockUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/oauth/usage"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"five_hour":{"utilization":0.25,"resets_at":"2026-07-13T05:00:00Z"},"seven_day":{"utilization":0.0,"resets_at":"2026-07-20T00:00:00Z"}}`))
		case strings.HasSuffix(r.URL.Path, "/api/oauth/profile"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"account":{"has_claude_max":true}}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestGetProviders_HandlerListsClaudeSupported(t *testing.T) {
	usageServiceInstance().FlushCache()

	manager := coreauth.NewManager(nil, nil, nil)
	if _, err := manager.Register(context.Background(), claudeHandlerAuth("")); err != nil {
		t.Fatalf("register: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(nil, manager)

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/providers", nil)
	h.GetProviders(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Providers []struct {
			ID, Type       string
			UsageSupported bool `json:"usageSupported"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(resp.Providers) != 1 || resp.Providers[0].Type != "claude" {
		t.Fatalf("expected one claude provider, got %+v", resp.Providers)
	}
	if !resp.Providers[0].UsageSupported {
		t.Fatalf("claude must be usageSupported=true")
	}
	if !strings.HasPrefix(resp.Providers[0].ID, "claude:account_") {
		t.Fatalf("claude id = %q", resp.Providers[0].ID)
	}
}

func TestGetProviderUsage_ColonInProviderID(t *testing.T) {
	upstream := claudeMockUpstream(t)
	defer upstream.Close()

	manager := coreauth.NewManager(nil, nil, nil)
	auth := claudeHandlerAuth(upstream.URL)
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(nil, manager)

	engine := gin.New()
	grp := engine.Group("/v0/management")
	grp.GET("/providers/:providerId/usage", h.GetProviderUsage)

	id := providerusage.StableID(auth)
	if !strings.HasPrefix(id, "claude:account_") {
		t.Fatalf("stable id = %q", id)
	}

	// Literal colon in the path segment resolves and returns 200.
	usageServiceInstance().FlushCache()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v0/management/providers/"+id+"/usage", nil)
	engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("literal colon: status = %d want 200, body=%s", rr.Code, rr.Body.String())
	}

	// Percent-encoded colon (what CCR sends via encodeURIComponent) resolves to
	// the same provider and returns 200.
	usageServiceInstance().FlushCache()
	encoded := strings.ReplaceAll(id, ":", "%3A")
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/v0/management/providers/"+encoded+"/usage", nil)
	engine.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("encoded colon: status = %d want 200, body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestProviderUsage_UsageRouteRequiresManagementKey(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	usageServiceInstance().FlushCache()

	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(nil, manager)

	engine := gin.New()
	grp := engine.Group("/v0/management")
	grp.Use(h.Middleware())
	grp.GET("/providers/:providerId/usage", h.GetProviderUsage)

	// The colon-bearing provider id routes through the auth middleware too.
	id := "claude:account_deadbeefdead"

	// No key -> 401 before the handler runs.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v0/management/providers/"+id+"/usage", nil)
	engine.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no key: status = %d want 401, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if !strings.Contains(body.Error, "management key") {
		t.Fatalf("401 body = %s", rr.Body.String())
	}

	// Invalid key -> 401.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/v0/management/providers/"+id+"/usage", nil)
	req2.Header.Set("Authorization", "Bearer wrong-key")
	engine.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: status = %d want 401", rr2.Code)
	}
}
