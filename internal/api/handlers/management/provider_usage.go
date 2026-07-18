package management

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/providerusage"
)

// A single providerusage.Service is shared process-wide. It is stateless apart
// from its in-memory cache, which is keyed by stable provider ID and
// concurrency-safe.
var (
	usageServiceOnce sync.Once
	usageServiceInst *providerusage.Service
)

func usageServiceInstance() *providerusage.Service {
	usageServiceOnce.Do(func() {
		usageServiceInst = providerusage.NewService()
	})
	return usageServiceInst
}

// GetProviders lists every credential exposed as a usage provider, keyed by a
// stable, provider-namespaced identifier.
//
// Endpoint: GET /v0/management/providers
// Auth: same as all management endpoints (Authorization: Bearer <key> or
// X-Management-Key).
func (h *Handler) GetProviders(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	h.mu.Lock()
	manager := h.authManager
	h.mu.Unlock()
	if manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	c.JSON(http.StatusOK, usageServiceInstance().List(manager))
}

// GetProviderUsage returns normalized, provider-scoped usage for a single
// credential identified by its stable provider ID.
//
// Endpoint: GET /v0/management/providers/:providerId/usage
// Query:    refresh=1 (optional) bypass the short cache and force a fresh fetch.
// Auth:     same as all management endpoints.
func (h *Handler) GetProviderUsage(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	h.mu.Lock()
	manager := h.authManager
	cfg := h.cfg
	h.mu.Unlock()
	if manager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	providerID := c.Param("providerId")
	forceRefresh := c.Query("refresh") == "1" || c.Query("force") == "1"

	result := usageServiceInstance().Usage(c.Request.Context(), cfg, manager, providerID, forceRefresh)
	if result == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "usage unavailable"})
		return
	}
	if result.Error != nil {
		c.JSON(result.HTTPStatus, result.Error)
		return
	}
	c.JSON(result.HTTPStatus, result.Usage)
}
