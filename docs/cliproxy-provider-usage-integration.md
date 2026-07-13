# Provider-Scoped Usage API — Integration Contract

This document specifies the provider-scoped usage API that CLIProxyAPI exposes so
that clients (notably **Claude Code Router**) can display upstream quota for the
matching provider/account, instead of relying on an external bridge.

> Scope of this document (CLIProxyAPI side): identity model, endpoints, request/
> response schema, authentication, error codes, caching, security, build/test.
> The consumer side (Claude Code Router native connector + migration) is
> described in the same file in the CCR repository.

## 1. Goals

- Remove the external Python usage bridge (port 8321).
- CLIProxyAPI exposes **provider-scoped** usage keyed by a **stable** identifier.
- Multiple providers and multiple accounts are first-class (no hardcoded account).
- Usage is resolved per selected provider, never via a global endpoint that
  guesses an account.

Architecture:

```
Claude Code Router provider
  → CLIProxyAPI GET /v0/management/providers/{providerId}/usage
    → matching OAuth credential (resolved by stable ID)
      → upstream quota endpoint (chatgpt.com/backend-api/wham/usage)
        → normalized "meters" response
          → CCR account/usage widget
```

## 2. Stable provider identity

Each credential is identified by a **stable, provider-namespaced public ID**:

```
<providerType>:account_<12hex>   # OAuth accounts, e.g. codex:account_a1b2c3d4e5f6
<providerType>:key_<12hex>       # API-key accounts
```

The ID is a pure function of already-persisted, non-secret fields, so it is
identical across restarts and credential reloads within an installation:

| Credential kind | Identity seed |
| --- | --- |
| OAuth (codex) | `provider` + persisted upstream `account_id` (fallback: email, then Auth.ID) |
| Other OAuth | `provider` + email (fallback Auth.ID) |
| API key | `provider` + `api_key` + `base_url` |

It deliberately does **not** use:

- the internal `authIndex` (an install-specific path hash, opaque, not portable),
- the raw credential filename,
- the email as the sole identifier,
- any token or account token,
- mutable array position.

Implementation: `internal/providerusage/identity.go` (`StableID`, `ProviderType`,
`DisplayName`, `UsageSupported`, `ProviderStatus`).

## 3. Endpoints

Both endpoints are mounted under the existing management route group and inherit
its authentication middleware — there is **no** second auth system.

```
GET /v0/management/providers
GET /v0/management/providers/:providerId/usage
```

Query for usage: `?refresh=1` (or `?force=1`) bypasses the short cache.

Path parameter `providerId` should be URL-encoded by clients (the colon is
technically path-safe, but encoding is recommended); the server decodes it.

### 3.1 Provider listing

`GET /v0/management/providers` → `200`

```json
{
  "providers": [
    {
      "id": "codex:account_a1b2c3d4e5f6",
      "type": "codex",
      "displayName": "ChatGPT Plus · a***@example.com",
      "usageSupported": true,
      "status": "active"
    },
    {
      "id": "gemini:key_0123456789ab",
      "type": "gemini",
      "displayName": "Gemini (API key)",
      "usageSupported": false,
      "status": "active"
    }
  ]
}
```

`displayName` masks email addresses (`a***@domain`) so multiple accounts of the
same type remain distinguishable without leaking full identities. `status` is one
of `active`, `disabled`, `unavailable`, `expired`, `error`, `unknown` and is
derived from in-memory credential state (no upstream call).

### 3.2 Provider usage

`GET /v0/management/providers/:providerId/usage` → `200`

```json
{
  "provider": {
    "id": "codex:account_a1b2c3d4e5f6",
    "type": "codex",
    "displayName": "ChatGPT Plus · a***@example.com"
  },
  "status": "ok",
  "message": "5h: 78% remaining | weekly: 60% remaining | plan: plus",
  "fetchedAt": "2026-07-13T00:00:00Z",
  "meters": [
    {
      "id": "primary",
      "kind": "rate_limit",
      "label": "5-hour usage window",
      "used": 22,
      "remaining": 78,
      "limit": 100,
      "unit": "%",
      "window": "5h",
      "resetAt": "2026-07-21T00:00:00Z"
    },
    {
      "id": "secondary",
      "kind": "rate_limit",
      "label": "Weekly usage window",
      "used": 40,
      "remaining": 60,
      "limit": 100,
      "unit": "%",
      "window": "weekly",
      "resetAt": "2026-07-21T00:00:00Z"
    }
  ],
  "rawProviderType": "codex",
  "balance": { "remaining": 78, "used": 22, "total": 100 },
  "subscription": { "remaining": 60, "limit": 100, "resetAt": "2026-07-21T00:00:00Z" }
}
```

`meters` is the canonical, extensible representation. Numeric fields are
pointers so the schema can distinguish "zero" from "unknown": a meter with
`limit: null` (omitted) and `unknownLimit: true` means the cap is unknown; a
meter with `resetAt: null` (omitted) and `unknownReset: true` means the reset
date is unknown. Supported meter shapes include percentage quotas, token quotas,
currency balances, request limits, and multiple time windows
(`window`: `5h`, `daily`, `weekly`, `monthly`, `rolling`).

The optional `balance` / `subscription` convenience fields are derived from the
meters for backwards compatibility with clients that consumed the legacy bridge
shape. New clients should read `meters`.

## 4. Authentication

The endpoints reuse CLIProxyAPI's existing management authentication, identical
to every other `/v0/management/*` endpoint. Provide the management key via:

```
Authorization: Bearer <management-key>
# or
X-Management-Key: <management-key>
```

The key is resolved (in order): a localhost-only local password, the
`MANAGEMENT_PASSWORD` environment variable (constant-time compared), or the
bcrypt `remote-management.secret-key` config value. Remote (non-localhost)
access additionally requires `remote-management.allow-remote` or an env secret.

Clients (CCR) **never** send OAuth tokens to these endpoints and **never** need
to know which underlying account is used — they only send the management key and
the stable provider ID.

## 5. Error responses

Non-200 responses use a single canonical error object:

```json
{
  "status": "error",
  "code": "USAGE_UPSTREAM_FAILED",
  "message": "Unable to retrieve provider usage",
  "providerId": "codex:account_a1b2c3d4e5f6"
}
```

| HTTP | Code | Meaning |
| --- | --- | --- |
| 200 | — | Usage retrieved |
| 401 | (middleware) | Management authentication failed |
| 403 | `USAGE_UNAUTHORIZED` / `USAGE_CREDENTIAL_EXPIRED` | Credential unauthorized/revoked, or token expired |
| 404 | `USAGE_PROVIDER_NOT_FOUND` | Provider ID does not match a credential |
| 409 | `USAGE_CREDENTIAL_MISSING` | Provider resolved but no usable access token is attached |
| 422 | `USAGE_UNSUPPORTED` | Usage is unsupported for this provider type (e.g. API-key, or non-codex OAuth) |
| 429 | `USAGE_UPSTREAM_RATE_LIMITED` | Upstream rate limit |
| 502 | `USAGE_UPSTREAM_FAILED` / `USAGE_UPSTREAM_MALFORMED` | Upstream quota call failed or response was malformed |
| 503 | `USAGE_CREDENTIAL_INCOMPLETE` / `USAGE_CREDENTIAL_UNAVAILABLE` / `USAGE_INTERNAL` | Required credential metadata missing or fetch failed internally |

## 6. Caching

A small in-process cache (no external cache) protects the upstream quota
endpoint:

- Success TTL: 45 s. Failure TTL: 10 s (errors are cached only briefly so a
  transient problem self-corrects quickly).
- Concurrent fetches for the same provider ID are deduplicated via
  `golang.org/x/sync/singleflight` (mirrors the existing OAuth-refresh pattern).
- `?refresh=1` bypasses the cache; an in-flight fetch is still shared.
- Every success response carries `fetchedAt`.

Implementation: `internal/providerusage/cache.go`, `service.go`.

## 7. ChatGPT / Codex adapter

`internal/providerusage/codex.go`:

- Resolves the OAuth `access_token` from credential metadata (same resolution
  order as the management `$TOKEN$` substitution) — it does **not** read token
  files directly or hardcode accounts.
- Reads the persisted `account_id` (the `Chatgpt-Account-Id`, captured from the
  ID-token JWT at login) from credential metadata.
- Calls the upstream quota endpoint, deriving the URL from the credential's
  `base_url` attribute when present (stripping a trailing `/codex`), otherwise
  `https://chatgpt.com/backend-api/wham/usage`.
- Uses the project's uTLS Chrome-fingerprint HTTP client
  (`internal/runtime/executor/helps.NewUtlsHTTPClient`) — required for
  `chatgpt.com` (Cloudflare). The fetch timeout (20 s) is a documented
  intentional exception to the project timeout rule (see `AGENTS.md`).
- Sends headers: `Authorization: Bearer <token>`, `User-Agent: codex_cli_rs/0.76.0`,
  `Chatgpt-Account-Id: <id>`, `Accept: application/json`.
- Tolerates stringified nested JSON (`rate_limit` delivered as a string, etc.).
- Normalizes `rate_limit.primary_window` / `secondary_window` (`used_percent`,
  `reset_at`), `plan_type`, `limit_reached`, and `rate_limit_reset_credits` into
  the canonical meters.
- Never logs tokens or response bodies; logs only the provider ID and error code.

## 8. Security

- No OAuth tokens, refresh tokens, account tokens, API keys, cookies, or full
  emails appear in any response. Emails are masked (`a***@domain`).
- Usage endpoints require the management key; they are not public.
- The access token is held in memory and sent only to the legitimate upstream
  host. It is never logged.
- Response bodies are capped at 1 MiB to bound memory.
- Management auth rate-limits repeated failures and bans offending IPs, exactly
  like the rest of the management API.

## 9. Local development

```bash
gofmt -w .                         # format (required after Go changes)
go build -o cli-proxy-api ./cmd/server   # build
go run ./cmd/server                # run dev server
go test ./...                      # all tests
go test ./internal/providerusage/...    # usage package tests only
go test -v -run TestUsage ./internal/providerusage/...
```

The usage tests use `httptest.NewServer` mocks; **no test contacts real
ChatGPT services.** Tests redirect the upstream URL via the credential's
`base_url` attribute.

## 10. Troubleshooting

- **401 on every call**: no management key configured. Set `MANAGEMENT_PASSWORD`
  env (or `remote-management.secret-key`) and send it as `Authorization: Bearer`.
- **404 for a known account**: the provider ID is derived from the persisted
  `account_id`; if a Codex credential has no `account_id` (e.g. API-key style),
  it is listed with `key_` shape, not `account_`.
- **422 unsupported**: only OAuth Codex/ChatGPT accounts currently support
  upstream usage. API-key accounts and other OAuth providers return 422.
- **502 malformed**: the upstream `wham/usage` shape changed; the parser in
  `codex.go` needs updating.
- **503 incomplete**: the Codex credential exists but has no `account_id`
  metadata (re-login to repopulate from the JWT).

## 11. Migration from the Python bridge (port 8321)

This API replaces `~/.local/share/ccr-quota-adapter/server.py`, which proxied a
single hardcoded ChatGPT account through `/v0/management/api-call`. The native
API generalizes that to any number of accounts, resolved by stable ID, with a
normalized schema. The legacy `api-call` endpoint remains available for other
uses; the Python bridge should be retired once the CCR native connector is
verified (archive it rather than deleting it immediately).
