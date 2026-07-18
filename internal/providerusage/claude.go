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

// Upstream Claude (Anthropic) OAuth quota endpoints. These are the same URLs the
// Claude Code CLI and the management quota UI call. Both take the access token
// as a bearer and require the "anthropic-beta: oauth-2025-04-20" header.
const (
	defaultClaudeUsageURL   = "https://api.anthropic.com/api/oauth/usage"
	defaultClaudeProfileURL = "https://api.anthropic.com/api/oauth/profile"
	claudeAnthropicBeta     = "oauth-2025-04-20"
)

// claudeWindowMeta describes a known Claude usage window field. Claude reports
// usage as a set of rolling windows, each carrying a utilization fraction
// (0.0-1.0) and a resets_at timestamp.
type claudeWindowMeta struct {
	key    string
	id     string
	label  string
	window string
}

// claudeUsageWindows lists the documented Claude window keys in display order.
// Unknown/extra keys are still normalized generically by the limits[] fallback.
var claudeUsageWindows = []claudeWindowMeta{
	{key: "five_hour", id: "five_hour", label: "5-hour usage window", window: "5h"},
	{key: "seven_day", id: "seven_day", label: "7-day usage window", window: "weekly"},
	{key: "seven_day_oauth_apps", id: "seven_day_oauth_apps", label: "7-day OAuth apps", window: "weekly"},
	{key: "seven_day_opus", id: "seven_day_opus", label: "7-day Opus", window: "weekly"},
	{key: "seven_day_sonnet", id: "seven_day_sonnet", label: "7-day Sonnet", window: "weekly"},
	{key: "seven_day_cowork", id: "seven_day_cowork", label: "7-day Cowork", window: "weekly"},
	{key: "iguana_necktie", id: "iguana_necktie", label: "Weekly scoped (iguana_necktie)", window: "weekly"},
}

// claudeAdapter fetches and normalizes Claude (Anthropic) OAuth quota usage.
type claudeAdapter struct{}

func (claudeAdapter) Supports(auth *coreauth.Auth) bool { return UsageSupported(auth) }

func (claudeAdapter) Fetch(ctx context.Context, cfg *config.Config, auth *coreauth.Auth, now time.Time) (*UsageResponse, *fetchError) {
	token := strings.TrimSpace(accessToken(auth))
	if token == "" {
		// Provider resolves and supports usage, but no usable token is attached.
		return nil, &fetchError{code: CodeCredentialMissing, status: httpStatusConflict, message: "no access token attached to credential"}
	}

	if t, ok := auth.ExpirationTime(); ok && !t.IsZero() && now.After(t) {
		return nil, &fetchError{code: CodeCredentialExpired, status: httpStatusForbidden, message: "credential access token has expired"}
	}

	// api.anthropic.com is a uTLS-protected host (Cloudflare) and uses the same
	// Chrome TLS fingerprint the Claude auth package uses for token refresh, so
	// reuse the project's shared uTLS client (it honors the per-credential proxy).
	client := helps.NewUtlsHTTPClient(ctx, cfg, auth, usageFetchTimeout)

	usageBody, ferr := claudeFetch(ctx, client, token, claudeUsageURL(auth))
	if ferr != nil {
		return nil, ferr
	}
	parsedUsage, errParse := parseClaudeBody(usageBody)
	if errParse != nil {
		log.WithError(errParse).Debug("providerusage: failed to parse claude usage body")
		return nil, &fetchError{code: CodeUpstreamMalformed, status: httpStatusBadGateway, message: "upstream usage response was malformed"}
	}

	// The profile call enriches the response with display name + plan (Pro/Max).
	// It is best-effort: a failure leaves the usage result intact.
	var profile map[string]any
	if body, perr := claudeFetch(ctx, client, token, claudeProfileURL(auth)); perr == nil {
		if pp, err := parseClaudeBody(body); err == nil {
			profile = pp
		}
	}

	return normalizeClaudeUsage(auth, parsedUsage, profile, now), nil
}

// claudeFetch performs a single authenticated GET against a Claude OAuth
// endpoint and maps upstream status codes to structured fetch errors.
func claudeFetch(ctx context.Context, client *http.Client, token, url string) ([]byte, *fetchError) {
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if errReq != nil {
		return nil, &fetchError{code: CodeInternal, status: httpStatusServiceUnavailable, message: "failed to build usage request"}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-beta", claudeAnthropicBeta)

	resp, errDo := client.Do(req)
	if errDo != nil {
		log.WithError(errDo).Debug("providerusage: claude usage request failed")
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
	case resp.StatusCode == http.StatusForbidden:
		return nil, &fetchError{code: CodeCredentialUnauthorized, status: httpStatusForbidden, message: "credential is not permitted to read usage"}
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, &fetchError{code: CodeUpstreamRateLimited, status: httpStatusTooManyRequests, message: "upstream rate limit reached"}
	case resp.StatusCode >= 500:
		return nil, &fetchError{code: CodeUpstreamFailed, status: httpStatusBadGateway, message: "upstream quota endpoint failed"}
	case resp.StatusCode != http.StatusOK:
		return nil, &fetchError{code: CodeUpstreamFailed, status: httpStatusBadGateway, message: fmt.Sprintf("upstream quota endpoint returned status %d", resp.StatusCode)}
	}
	return body, nil
}

// claudeUsageURL / claudeProfileURL derive the upstream endpoint from the
// credential's configured base_url when present (tests/custom deployments),
// otherwise the public api.anthropic.com defaults.
func claudeUsageURL(auth *coreauth.Auth) string {
	if base := claudeBaseURL(auth); base != "" {
		return base + "/api/oauth/usage"
	}
	return defaultClaudeUsageURL
}

func claudeProfileURL(auth *coreauth.Auth) string {
	if base := claudeBaseURL(auth); base != "" {
		return base + "/api/oauth/profile"
	}
	return defaultClaudeProfileURL
}

func claudeBaseURL(auth *coreauth.Auth) string {
	if auth == nil || auth.Attributes == nil {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(auth.Attributes["base_url"]), "/")
}

// parseClaudeBody decodes a Claude OAuth payload, tolerating a whole-body JSON
// string literal (mirrors the codex parser's tolerance).
func parseClaudeBody(body []byte) (map[string]any, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
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
	return raw, nil
}

// ---- normalization into the canonical meters schema ----

func normalizeClaudeUsage(auth *coreauth.Auth, usage, profile map[string]any, now time.Time) *UsageResponse {
	meters := make([]Meter, 0, len(claudeUsageWindows)+2)

	var fiveHourMeter, sevenDayMeter Meter
	hasFiveHour, hasSevenDay := false, false
	for _, w := range claudeUsageWindows {
		win := asMap(usage[w.key])
		if len(win) == 0 {
			continue
		}
		m := claudeUtilizationMeter(w.id, w.label, w.window, win)
		meters = append(meters, m)
		if w.key == "five_hour" {
			fiveHourMeter = m
			hasFiveHour = true
		}
		if w.key == "seven_day" {
			sevenDayMeter = m
			hasSevenDay = true
		}
	}

	// Defensive: some Claude responses carry a "limits" array (e.g. scoped
	// weekly limits per model such as Fable). Unlike the rolling windows above,
	// each limit exposes a "percent" that is ALREADY expressed on a 0-100 scale,
	// so it must NOT be multiplied. The upstream also tends to echo the named
	// rolling windows in this array with sub-second timestamp jitter, so each
	// limit is deduplicated against the windows by (reset second, used,
	// remaining); a genuinely distinct scoped limit (different value) survives.
	// This branch is a no-op when "limits" is absent.
	seen := make(map[string]bool, len(meters))
	for _, m := range meters {
		seen[meterDedupKey(m)] = true
	}
	if limits, ok := usage["limits"].([]any); ok {
		for i, lim := range limits {
			m, ok := claudeLimitMeter(i, asMap(lim))
			if !ok {
				continue
			}
			key := meterDedupKey(m)
			if seen[key] {
				continue
			}
			seen[key] = true
			meters = append(meters, m)
		}
	}

	if extra := asMap(usage["extra_usage"]); len(extra) > 0 {
		if m, ok := claudeExtraUsageMeter(extra); ok {
			meters = append(meters, m)
		}
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
		Message:         summarizeClaude(hasFiveHour, &fiveHourMeter, hasSevenDay, &sevenDayMeter, profile),
	}

	// Backwards-compatible convenience fields, mapped like the codex adapter:
	// balance <- five-hour, subscription <- seven-day.
	if hasFiveHour {
		resp.Balance = convenienceBalance(&fiveHourMeter)
	}
	if hasSevenDay {
		resp.Subscription = convenienceSubscription(&sevenDayMeter)
	}
	return resp
}

// claudeUtilizationMeter builds a percentage meter from a Claude rolling window.
// utilization is a fraction in [0.0, 1.0]; the meter reports it as 0-100 used
// against a 100 limit. At utilization 0 the meter reports 0% used / 100%
// remaining.
func claudeUtilizationMeter(id, label, window string, win map[string]any) Meter {
	m := Meter{
		ID:     id,
		Kind:   "rate_limit",
		Label:  label,
		Unit:   "%",
		Window: window,
	}
	limit := 100.0
	m.Limit = &limit
	if util, ok := numberValue(win["utilization"]); ok {
		used := clampPercent(util * 100.0)
		m.Used = &used
		remaining := clampPercent(limit - used)
		m.Remaining = &remaining
	}
	if t, ok := timeFromUnixish(win["resets_at"]); ok {
		tt := t
		m.ResetAt = &tt
	} else {
		m.UnknownReset = true
	}
	return m
}

// claudeLimitMeter normalizes a single element of a Claude "limits" array. It
// prefers an explicit "percent" (already 0-100, NOT multiplied) and falls back
// to "utilization" (a 0-1 fraction). Returns ok=false when there is no usable
// usage signal.
func claudeLimitMeter(index int, lim map[string]any) (Meter, bool) {
	if len(lim) == 0 {
		return Meter{}, false
	}
	percent, hasPercent := numberValue(lim["percent"])
	util, hasUtil := numberValue(lim["utilization"])
	if !hasPercent && !hasUtil {
		return Meter{}, false
	}

	// Claude limit objects are not documented to use a stable field name for the
	// limit identity, so probe a range of common keys (name/type/key/window/...)
	// and the model. Windows use "resets_at" (with an 's'); honor both spellings.
	name := stringFromMap(lim, "name", "title", "scope", "type", "key", "window", "bucket", "dimension", "label")
	model := strings.TrimSpace(stringFromMap(lim, "model", "model_name"))
	id := name
	if id == "" {
		id = fmt.Sprintf("limit-%d", index)
	}
	if model != "" {
		id = id + "-" + model
	}

	m := Meter{
		ID:     stableMeterID(id),
		Kind:   "rate_limit",
		Label:  claudeLimitLabel(name, model, index),
		Unit:   "%",
		Window: claudeLimitWindow(name, model),
	}
	limit := 100.0
	m.Limit = &limit
	var used float64
	if hasPercent {
		used = percent // already 0-100: do NOT multiply
	} else {
		used = util * 100.0
	}
	used = clampPercent(used)
	m.Used = &used
	remaining := clampPercent(limit - used)
	m.Remaining = &remaining

	resetRaw, ok := lim["reset_at"]
	if !ok || resetRaw == nil {
		resetRaw = lim["resets_at"]
	}
	if t, ok := timeFromUnixish(resetRaw); ok {
		tt := t
		m.ResetAt = &tt
	} else {
		m.UnknownReset = true
	}
	return m, true
}

// claudeExtraUsageMeter models the optional monthly "extra usage" allowance as a
// credits meter. Only emitted when extra usage is enabled.
func claudeExtraUsageMeter(extra map[string]any) (Meter, bool) {
	if len(extra) == 0 || !boolValue(extra["is_enabled"]) {
		return Meter{}, false
	}
	m := Meter{
		ID:     "extra_usage",
		Kind:   "request_limit",
		Label:  "Extra usage (monthly)",
		Unit:   "credits",
		Window: "monthly",
	}
	if used, ok := numberValue(extra["used_credits"]); ok {
		u := used
		m.Used = &u
	}
	if lim, ok := numberValue(extra["monthly_limit"]); ok && lim > 0 {
		l := lim
		m.Limit = &l
		if m.Used != nil {
			remaining := lim - *m.Used
			if remaining < 0 {
				remaining = 0
			}
			m.Remaining = &remaining
		}
	} else {
		m.UnknownLimit = true
	}
	return m, true
}

func summarizeClaude(hasFive bool, five *Meter, hasSeven bool, seven *Meter, profile map[string]any) string {
	var parts []string
	if hasFive && five != nil && five.Remaining != nil {
		parts = append(parts, fmt.Sprintf("5h: %.0f%% remaining", *five.Remaining))
	}
	if hasSeven && seven != nil && seven.Remaining != nil {
		parts = append(parts, fmt.Sprintf("7d: %.0f%% remaining", *seven.Remaining))
	}
	if plan := claudePlan(profile); plan != "" {
		parts = append(parts, "plan: "+plan)
	}
	return strings.Join(parts, " | ")
}

// claudePlan derives a human plan label (max/pro or the org rate-limit tier)
// from the optional profile payload.
func claudePlan(profile map[string]any) string {
	account := asMap(profile["account"])
	if boolValue(account["has_claude_max"]) {
		return "max"
	}
	if boolValue(account["has_claude_pro"]) {
		return "pro"
	}
	org := asMap(profile["organization"])
	if tier := strings.TrimSpace(stringFromMap(org, "rate_limit_tier")); tier != "" {
		return strings.ToLower(tier)
	}
	return ""
}

// ---- small shared helpers (claude-specific) ----

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// meterDedupKey is a coarse identity for a percentage meter used to drop
// redundant "limits" echoes of the rolling windows. It collapses to the
// second (ignoring sub-second jitter) and the integer used/remaining.
func meterDedupKey(m Meter) string {
	reset := "none"
	if m.ResetAt != nil {
		reset = m.ResetAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	used := "none"
	if m.Used != nil {
		used = strconv.FormatFloat(*m.Used, 'f', 0, 64)
	}
	remaining := "none"
	if m.Remaining != nil {
		remaining = strconv.FormatFloat(*m.Remaining, 'f', 0, 64)
	}
	return reset + "|" + used + "|" + remaining
}

func stringFromMap(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			if v := strings.TrimSpace(s); v != "" {
				return v
			}
		}
	}
	return ""
}

func claudeLimitLabel(name, model string, index int) string {
	var parts []string
	if human := humanizeClaudeLimitName(name); human != "" {
		parts = append(parts, human)
	}
	if model != "" {
		parts = append(parts, model)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Weekly limit %d", index+1)
	}
	return strings.Join(parts, " · ")
}

func humanizeClaudeLimitName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "":
		return ""
	case "session":
		return "Session limit"
	case "weekly_all", "weekly":
		return "Weekly usage limit"
	case "weekly_scoped":
		return "Weekly scoped limit"
	default:
		return titleCase(strings.ReplaceAll(name, "_", " "))
	}
}

func claudeLimitWindow(name, model string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "session":
		return "5h"
	case "weekly_all", "weekly", "weekly_scoped":
		return "weekly"
	}
	if model != "" {
		return "weekly"
	}
	return ""
}

// stableMeterID collapses a free-form id into a stable lowercase slug.
func stableMeterID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "limit"
	}
	return out
}
