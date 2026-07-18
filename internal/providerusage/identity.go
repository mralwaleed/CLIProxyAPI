package providerusage

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// idHashLen is the number of bytes (hex = 2x characters) used for the stable
// identifier suffix. 6 bytes => 12 hex chars, which is collision-resistant for
// the small number of credentials on a single instance.
const idHashLen = 6

// ProviderType returns the canonical lowercase provider type for a credential.
// It prefers the explicit compat_name attribute (used by openai-compatibility
// providers) and falls back to Auth.Provider.
func ProviderType(auth *coreauth.Auth) string {
	if auth == nil {
		return "unknown"
	}
	p := strings.ToLower(strings.TrimSpace(auth.Provider))
	if auth.Attributes != nil {
		if c := strings.ToLower(strings.TrimSpace(auth.Attributes["compat_name"])); c != "" {
			p = c
		}
	}
	if p == "" {
		p = "unknown"
	}
	return p
}

// StableID returns a stable, provider-namespaced public identifier for a
// credential. The format is:
//
//	"<type>:account_<12hex>"  for OAuth accounts (e.g. codex:account_a1b2...)
//	"<type>:key_<12hex>"      for API-key accounts
//
// It is a pure function of already-persisted, non-secret fields:
//   - OAuth: provider type + upstream account id (codex stores the ChatGPT
//     account id), falling back to email, then to Auth.ID.
//   - API key: provider type + api key + configured base url.
//
// Because it depends only on durable data, the identifier is identical across
// restarts and credential reloads within an installation. It deliberately does
// NOT use the internal authIndex (which is an install-specific path hash), the
// raw credential filename, the email as the sole identifier, or any token.
func StableID(auth *coreauth.Auth) string {
	if auth == nil {
		return "unknown:account_000000000000"
	}
	ptype := ProviderType(auth)
	kind, account := auth.AccountInfo()
	account = strings.TrimSpace(account)

	var seed string
	switch {
	case strings.EqualFold(kind, "oauth"):
		// Prefer the durable upstream account id; codex persists this from the
		// ID-token JWT. Fall back to email, then Auth.ID.
		if aid := strings.TrimSpace(metadataString(auth, "account_id")); aid != "" {
			seed = ptype + "|account|" + aid
		} else if account != "" {
			seed = ptype + "|account|" + account
		} else {
			seed = ptype + "|account|" + auth.ID
		}
	case strings.EqualFold(kind, "api_key"):
		base := ""
		if auth.Attributes != nil {
			base = strings.TrimSpace(auth.Attributes["base_url"])
		}
		seed = ptype + "|key|" + account + "|" + base
	default:
		seed = ptype + "|account|" + auth.ID
	}

	suffix := hashSeed(seed)
	if strings.EqualFold(kind, "api_key") {
		return ptype + ":key_" + suffix
	}
	return ptype + ":account_" + suffix
}

func hashSeed(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:idHashLen])
}

// DisplayName returns a non-sensitive, human-readable label. Email addresses
// are masked so the listing does not leak full account identities, while still
// disambiguating multiple accounts of the same type.
func DisplayName(auth *coreauth.Auth) string {
	if auth == nil {
		return "Unknown"
	}
	ptype := ProviderType(auth)
	kind, account := auth.AccountInfo()
	account = strings.TrimSpace(account)
	label := strings.TrimSpace(auth.Label)

	switch strings.ToLower(kind) {
	case "oauth":
		base := humanProviderName(ptype)
		if label != "" {
			base = label
		} else if plan := strings.TrimSpace(metadataString(auth, "plan_type")); plan != "" {
			base = base + " " + titleCase(plan)
		}
		if email := strings.TrimSpace(metadataString(auth, "email")); email != "" {
			if masked := maskEmail(email); masked != "" {
				base = base + " · " + masked
			}
		}
		if base == "" {
			base = humanProviderName(ptype)
		}
		return base
	case "api_key":
		base := humanProviderName(ptype) + " (API key)"
		if label != "" {
			base = label
		}
		return base
	default:
		if label != "" {
			return label
		}
		return humanProviderName(ptype)
	}
}

// UsageSupported reports whether upstream usage can be fetched for this
// credential. Today OAuth Codex/ChatGPT and Claude/Anthropic accounts are
// supported (each has a known quota endpoint). API-key accounts and other OAuth
// providers report unsupported; their usage endpoint returns 422. An expired or
// revoked token is NOT reported as unsupported here — the static listing keeps
// usageSupported true and the per-request fetch surfaces the auth failure.
func UsageSupported(auth *coreauth.Auth) bool {
	if auth == nil {
		return false
	}
	kind, _ := auth.AccountInfo()
	if !strings.EqualFold(kind, "oauth") {
		return false
	}
	switch ProviderType(auth) {
	case "codex", "claude":
		return true
	}
	return false
}

// ProviderStatus derives a lifecycle status for the listing. It does not fetch
// upstream; it inspects in-memory credential state.
func ProviderStatus(auth *coreauth.Auth, now time.Time) string {
	if auth == nil {
		return "unknown"
	}
	if auth.Disabled {
		return "disabled"
	}
	if auth.Unavailable {
		return "unavailable"
	}
	if t, ok := auth.ExpirationTime(); ok && !t.IsZero() && now.After(t) {
		return "expired"
	}
	if auth.LastError != nil {
		return "error"
	}
	return "active"
}

func metadataString(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil || key == "" {
		return ""
	}
	v, ok := auth.Metadata[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func humanProviderName(ptype string) string {
	switch ptype {
	case "codex":
		return "ChatGPT"
	case "claude":
		return "Claude"
	case "gemini":
		return "Gemini"
	case "gemini-interactions":
		return "Gemini Interactions"
	case "xai":
		return "xAI"
	case "kimi":
		return "Kimi"
	case "antigravity":
		return "Antigravity"
	case "vertex":
		return "Vertex"
	case "openai-compatibility":
		return "OpenAI Compatible"
	default:
		return ptype
	}
}

func titleCase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// maskEmail reduces an email to its first character + "***@" + domain so the
// listing can disambiguate accounts without exposing the full address.
func maskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.IndexByte(email, '@')
	if at <= 0 || at >= len(email)-1 {
		return ""
	}
	local := email[:at]
	domain := email[at+1:]
	if local == "" {
		return ""
	}
	return string(local[0]) + "***@" + domain
}
