// Package providerusage implements the provider-scoped usage API for the
// management layer.
//
// It exposes a stable, provider-namespaced identity for each stored credential
// (e.g. "codex:account_a1b2c3d4e5f6"), lists the credentials that support
// upstream usage, and normalizes upstream quota responses into a single
// canonical "meters" schema. The canonical schema is provider-agnostic and
// supports percentage quotas, token quotas, currency balances, request limits
// and multiple time windows (daily / weekly / monthly / rolling).
//
// The package is intentionally backend-only: the HTTP handlers live in
// internal/api/handlers/management and are thin wrappers around Service.
package providerusage

import "time"

// HTTP status codes returned by the usage endpoints.
const (
	httpStatusOK                 = 200
	httpStatusUnauthorized       = 401
	httpStatusForbidden          = 403
	httpStatusNotFound           = 404
	httpStatusConflict           = 409
	httpStatusUnprocessable      = 422
	httpStatusTooManyRequests    = 429
	httpStatusBadGateway         = 502
	httpStatusServiceUnavailable = 503
)

// Stable error codes used in ErrorResponse.Code.
const (
	CodeProviderNotFound       = "USAGE_PROVIDER_NOT_FOUND"
	CodeUsageUnsupported       = "USAGE_UNSUPPORTED"
	CodeCredentialMissing      = "USAGE_CREDENTIAL_MISSING"
	CodeCredentialIncomplete   = "USAGE_CREDENTIAL_INCOMPLETE"
	CodeCredentialUnauthorized = "USAGE_UNAUTHORIZED"
	CodeCredentialExpired      = "USAGE_CREDENTIAL_EXPIRED"
	CodeCredentialUnavailable  = "USAGE_CREDENTIAL_UNAVAILABLE"
	CodeUpstreamFailed         = "USAGE_UPSTREAM_FAILED"
	CodeUpstreamRateLimited    = "USAGE_UPSTREAM_RATE_LIMITED"
	CodeUpstreamMalformed      = "USAGE_UPSTREAM_MALFORMED"
	CodeInternal               = "USAGE_INTERNAL"
)

// Provider is a single entry in the provider listing response.
type Provider struct {
	// ID is the stable, provider-namespaced public identifier.
	ID string `json:"id"`
	// Type is the canonical provider type (codex, claude, gemini, ...).
	Type string `json:"type"`
	// DisplayName is a non-sensitive, human-readable label.
	DisplayName string `json:"displayName"`
	// UsageSupported reports whether upstream usage can be fetched for this credential.
	UsageSupported bool `json:"usageSupported"`
	// Status is the credential lifecycle status (active, disabled, unavailable, expired, error).
	Status string `json:"status"`
}

// ListResponse is returned by GET /v0/management/providers.
type ListResponse struct {
	Providers []Provider `json:"providers"`
}

// Meter is the canonical, extensible usage measurement.
//
// Pointer-typed numeric fields allow the schema to distinguish "zero" from
// "unknown" — a meter with a nil Limit represents an unknown cap.
type Meter struct {
	ID           string     `json:"id"`
	Kind         string     `json:"kind"`
	Label        string     `json:"label"`
	Used         *float64   `json:"used,omitempty"`
	Remaining    *float64   `json:"remaining,omitempty"`
	Limit        *float64   `json:"limit,omitempty"`
	Unit         string     `json:"unit,omitempty"`
	ResetAt      *time.Time `json:"resetAt,omitempty"`
	Window       string     `json:"window,omitempty"`
	UnknownLimit bool       `json:"unknownLimit,omitempty"`
	UnknownReset bool       `json:"unknownReset,omitempty"`
}

// ProviderInfo describes the provider inside a usage response.
type ProviderInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"displayName"`
}

// ConvenienceBalance is an optional backwards-compatible summary derived from
// the canonical meters. It is provided for legacy clients; "meters" remains
// the canonical representation.
type ConvenienceBalance struct {
	Remaining *float64 `json:"remaining,omitempty"`
	Used      *float64 `json:"used,omitempty"`
	Total     *float64 `json:"total,omitempty"`
}

// ConvenienceSubscription is an optional backwards-compatible subscription
// view derived from the canonical meters.
type ConvenienceSubscription struct {
	Remaining *float64   `json:"remaining,omitempty"`
	Limit     *float64   `json:"limit,omitempty"`
	ResetAt   *time.Time `json:"resetAt,omitempty"`
}

// UsageResponse is the canonical normalized provider usage response returned
// by GET /v0/management/providers/{providerId}/usage.
type UsageResponse struct {
	Provider        ProviderInfo             `json:"provider"`
	Status          string                   `json:"status"`
	Message         string                   `json:"message,omitempty"`
	FetchedAt       time.Time                `json:"fetchedAt"`
	Meters          []Meter                  `json:"meters"`
	RawProviderType string                   `json:"rawProviderType,omitempty"`
	Balance         *ConvenienceBalance      `json:"balance,omitempty"`
	Subscription    *ConvenienceSubscription `json:"subscription,omitempty"`
}

// ErrorResponse is the canonical error body returned for non-200 usage responses.
type ErrorResponse struct {
	Status     string `json:"status"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	ProviderID string `json:"providerId,omitempty"`
}

// Result is what Service.Usage returns. Exactly one of Usage or Error is non-nil
// for a resolved provider; HTTPStatus is always set.
type Result struct {
	HTTPStatus int
	Usage      *UsageResponse
	Error      *ErrorResponse
}

// fetchError carries the structured failure produced by an Adapter so the
// service can map it to a Result (HTTP status + error code) consistently.
type fetchError struct {
	code    string
	status  int
	message string
}

func (e *fetchError) Error() string { return e.message }
