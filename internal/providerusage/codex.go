package providerusage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// usageFetchTimeout bounds a single upstream quota fetch.
//
// This is an intentional, documented exception to the project rule that
// timeouts are only allowed during credential acquisition (see AGENTS.md). It
// mirrors the management api-call timeout: a usage fetch is a short, optional
// management query that must not hang indefinitely. It only bounds the overall
// request (connection + read).
const usageFetchTimeout = 20 * time.Second

// defaultCodexUsageURL is the upstream ChatGPT quota endpoint also used by the
// Codex CLI. It returns primary (5-hour) and secondary (weekly) usage windows.
const defaultCodexUsageURL = "https://chatgpt.com/backend-api/wham/usage"

// codexUserAgent matches the User-Agent the Codex CLI sends; some upstream
// endpoints gate on it.
const codexUserAgent = "codex_cli_rs/0.76.0"

// codexAdapter fetches and normalizes ChatGPT/Codex quota usage.
type codexAdapter struct{}

func (codexAdapter) Supports(auth *coreauth.Auth) bool {
	return UsageSupported(auth)
}

func (codexAdapter) Fetch(ctx context.Context, cfg *config.Config, auth *coreauth.Auth, now time.Time) (*UsageResponse, *fetchError) {
	token := strings.TrimSpace(accessToken(auth))
	if token == "" {
		// Provider resolves and supports usage, but no usable token is attached.
		return nil, &fetchError{code: CodeCredentialMissing, status: httpStatusConflict, message: "no access token attached to credential"}
	}

	if t, ok := auth.ExpirationTime(); ok && !t.IsZero() && now.After(t) {
		return nil, &fetchError{code: CodeCredentialExpired, status: httpStatusForbidden, message: "credential access token has expired"}
	}

	accountID := strings.TrimSpace(metadataString(auth, "account_id"))
	if accountID == "" {
		// Without the ChatGPT account id the upstream endpoint rejects the call.
		return nil, &fetchError{code: CodeCredentialIncomplete, status: httpStatusServiceUnavailable, message: "ChatGPT account id is not available for this credential"}
	}

	url := codexUsageURL(auth)

	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if errReq != nil {
		return nil, &fetchError{code: CodeInternal, status: httpStatusServiceUnavailable, message: "failed to build usage request"}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", codexUserAgent)
	req.Header.Set("Chatgpt-Account-Id", accountID)

	// chatgpt.com is a uTLS-protected host (Cloudflare). Reuse the same Chrome
	// TLS fingerprint the Codex executor uses for normal proxy traffic.
	client := helps.NewUtlsHTTPClient(ctx, cfg, auth, usageFetchTimeout)

	resp, errDo := client.Do(req)
	if errDo != nil {
		log.WithError(errDo).Debug("providerusage: codex usage request failed")
		return nil, &fetchError{code: CodeUpstreamFailed, status: httpStatusBadGateway, message: "Unable to retrieve provider usage"}
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("response body close error: %v", errClose)
		}
	}()

	body, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if errRead != nil {
		return nil, &fetchError{code: CodeUpstreamFailed, status: httpStatusBadGateway, message: "Unable to read provider usage response"}
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, &fetchError{code: CodeCredentialUnauthorized, status: httpStatusForbidden, message: "credential is not authorized upstream"}
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, &fetchError{code: CodeUpstreamRateLimited, status: httpStatusTooManyRequests, message: "upstream rate limit reached"}
	case resp.StatusCode == http.StatusForbidden:
		return nil, &fetchError{code: CodeCredentialUnauthorized, status: httpStatusForbidden, message: "credential is not permitted to read usage"}
	case resp.StatusCode >= 500:
		return nil, &fetchError{code: CodeUpstreamFailed, status: httpStatusBadGateway, message: "upstream quota endpoint failed"}
	case resp.StatusCode != http.StatusOK:
		return nil, &fetchError{code: CodeUpstreamFailed, status: httpStatusBadGateway, message: fmt.Sprintf("upstream quota endpoint returned status %d", resp.StatusCode)}
	}

	parsed, errParse := parseCodexUsageBody(body)
	if errParse != nil {
		log.WithError(errParse).Debug("providerusage: failed to parse codex usage body")
		return nil, &fetchError{code: CodeUpstreamMalformed, status: httpStatusBadGateway, message: "upstream usage response was malformed"}
	}

	return normalizeCodexUsage(auth, parsed, now), nil
}

// codexUsageURL derives the upstream endpoint from the credential's configured
// base_url when present (used by tests and custom deployments), stripping a
// trailing "/codex" segment so "/wham/usage" lands on the right path.
func codexUsageURL(auth *coreauth.Auth) string {
	base := ""
	if auth != nil && auth.Attributes != nil {
		base = strings.TrimSpace(auth.Attributes["base_url"])
	}
	if base == "" {
		return defaultCodexUsageURL
	}
	base = strings.TrimRight(base, "/")
	base = strings.TrimSuffix(base, "/codex")
	return base + "/wham/usage"
}

// accessToken reads the OAuth access token from credential metadata. It mirrors
// the resolution order used by the management api-call "$TOKEN$" substitution
// without depending on the management package.
func accessToken(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	for _, key := range []string{"access_token", "accessToken"} {
		if v, ok := auth.Metadata[key].(string); ok {
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		}
	}
	if tokenRaw, ok := auth.Metadata["token"]; ok {
		switch typed := tokenRaw.(type) {
		case string:
			return strings.TrimSpace(typed)
		case map[string]any:
			for _, key := range []string{"access_token", "accessToken"} {
				if v, ok := typed[key].(string); ok {
					if s := strings.TrimSpace(v); s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

// ---- response parsing (tolerant of stringified nested JSON) ----

// parseCodexUsageBody decodes the wham/usage payload. It tolerates:
//   - the whole body being a JSON string containing the real object,
//   - nested objects (rate_limit, rate_limit_reset_credits) being stringified.
func parseCodexUsageBody(body []byte) (map[string]any, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	// Whole-body string literal: unwrap once.
	if body[0] == '"' {
		var s string
		if err := json.Unmarshal(body, &s); err != nil {
			return nil, err
		}
		body = []byte(s)
	}

	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}

	// Unwrap stringified nested objects in place.
	for _, key := range []string{"rate_limit", "rate_limit_reset_credits", "primary_window", "secondary_window"} {
		raw = unwrapStringified(raw, key)
	}
	if rl, ok := raw["rate_limit"].(map[string]any); ok {
		rl = unwrapStringified(rl, "primary_window")
		rl = unwrapStringified(rl, "secondary_window")
		raw["rate_limit"] = rl
	}
	return raw, nil
}

func unwrapStringified(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return m
	}
	s, ok := v.(string)
	if !ok {
		return m
	}
	s = strings.TrimSpace(s)
	if s == "" || (s[0] != '{' && s[0] != '[') {
		return m
	}
	var inner map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&inner); err == nil {
		m[key] = inner
	}
	return m
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func numberValue(v any) (float64, bool) {
	switch typed := v.(type) {
	case json.Number:
		if f, err := typed.Float64(); err == nil {
			return f, true
		}
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(typed), 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

// timeFromUnixish parses a reset timestamp that may be a unix-seconds number or
// an RFC3339 string. Returns ok=false when unknown/unparseable.
func timeFromUnixish(v any) (time.Time, bool) {
	if n, ok := numberValue(v); ok {
		sec := int64(n)
		// Guard against millis being supplied instead of seconds.
		if sec > 1e12 {
			sec = sec / 1000
		}
		if sec <= 0 {
			return time.Time{}, false
		}
		return time.Unix(sec, 0).UTC(), true
	}
	if s, ok := v.(string); ok {
		s = strings.TrimSpace(s)
		if s == "" {
			return time.Time{}, false
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC(), true
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			if n > 1e12 {
				n = n / 1000
			}
			return time.Unix(n, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

// ---- normalization into the canonical meters schema ----

func normalizeCodexUsage(auth *coreauth.Auth, parsed map[string]any, now time.Time) *UsageResponse {
	planType, _ := parsed["plan_type"].(string)
	rateLimit := asMap(parsed["rate_limit"])
	limitReached := boolValue(rateLimit["limit_reached"])
	primary := asMap(rateLimit["primary_window"])
	secondary := asMap(rateLimit["secondary_window"])
	resetCredits := asMap(parsed["rate_limit_reset_credits"])

	meters := make([]Meter, 0, 3)

	primaryMeter := percentMeter("primary", "5-hour usage window", "5h", primary, limitReached)
	secondaryMeter := percentMeter("secondary", "Weekly usage window", "weekly", secondary, false)
	meters = append(meters, primaryMeter, secondaryMeter)

	if avail, ok := numberValue(resetCredits["available_count"]); ok {
		availF := avail
		meters = append(meters, Meter{
			ID:           "reset_credits",
			Kind:         "request_limit",
			Label:        "Rate-limit reset credits",
			Remaining:    &availF,
			Unit:         "credits",
			UnknownLimit: true,
		})
	}

	resp := &UsageResponse{
		Provider: ProviderInfo{
			ID:          StableID(auth),
			Type:        ProviderType(auth),
			DisplayName: DisplayName(auth),
		},
		Status:          "ok",
		FetchedAt:       now.UTC(),
		Meters:          meters,
		RawProviderType: ProviderType(auth),
		Message:         summarize(primaryMeter, secondaryMeter, planType),
	}

	// Backwards-compatible convenience fields, mapped exactly like the legacy
	// bridge so existing http-json consumers keep working: balance <- primary,
	// subscription <- secondary.
	resp.Balance = convenienceBalance(&primaryMeter)
	resp.Subscription = convenienceSubscription(&secondaryMeter)

	return resp
}

// percentMeter builds a percentage meter from a wham window object. limit is
// always 100 (percent); used/remaining derive from used_percent. When the
// upstream reports the limit as reached and used_percent is absent, the meter
// is reported as fully consumed.
func percentMeter(id, label, window string, windowObj map[string]any, limitReached bool) Meter {
	m := Meter{
		ID:     id,
		Kind:   "rate_limit",
		Label:  label,
		Unit:   "%",
		Window: window,
	}
	limit := 100.0
	m.Limit = &limit
	if used, ok := numberValue(windowObj["used_percent"]); ok {
		u := used
		m.Used = &u
		remaining := limit - used
		if remaining < 0 {
			remaining = 0
		}
		m.Remaining = &remaining
	} else if limitReached {
		u := limit
		m.Used = &u
		zero := 0.0
		m.Remaining = &zero
	} else {
		m.UnknownLimit = false
	}
	if t, ok := timeFromUnixish(windowObj["reset_at"]); ok {
		tt := t
		m.ResetAt = &tt
	} else {
		m.UnknownReset = true
	}
	return m
}

func convenienceBalance(m *Meter) *ConvenienceBalance {
	if m == nil {
		return nil
	}
	b := &ConvenienceBalance{}
	if m.Limit != nil {
		t := *m.Limit
		b.Total = &t
	}
	b.Remaining = m.Remaining
	b.Used = m.Used
	return b
}

func convenienceSubscription(m *Meter) *ConvenienceSubscription {
	if m == nil {
		return nil
	}
	s := &ConvenienceSubscription{
		Remaining: m.Remaining,
		Limit:     m.Limit,
		ResetAt:   m.ResetAt,
	}
	return s
}

func summarize(primary, secondary Meter, planType string) string {
	var parts []string
	if primary.Remaining != nil {
		parts = append(parts, fmt.Sprintf("5h: %.0f%% remaining", *primary.Remaining))
	}
	if secondary.Remaining != nil {
		parts = append(parts, fmt.Sprintf("weekly: %.0f%% remaining", *secondary.Remaining))
	}
	if planType != "" {
		parts = append(parts, "plan: "+strings.TrimSpace(planType))
	}
	return strings.Join(parts, " | ")
}
