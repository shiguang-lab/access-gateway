# Shiguang Access Gateway

Organization-level HTTP access gateway for `*.shiguanglab.com`.

The service owns the public reverse-proxy boundary. It resolves an exact host
to a registered product origin, asks `auth-service` for protected-route
decisions, removes browser-provided identity headers, strips the shared session
cookie before proxying, and injects a short-lived product-scoped identity
assertion.

It is intentionally separate from every product BFF.

Huiguang, Yingguang, Lingguang, and Points remain independent repositories,
services, data boundaries, and workbenches. The main website is only an
introduction and centralized-login entry; authenticated users return to the
originating system through `return_to`. Cross-system integrations use gateway,
private API/service names, event queues, or versioned SDK contracts. Browser
code never receives machine client credentials.

## Current scope

- Exact host plus longest path-prefix routing from a JSON configuration file
- Public and protected path policies
- Fail-closed authorization through `auth-service`
- Removal of external `X-SG-*` and `X-User-*` identity headers
- Request and response isolation for `__Secure-sg_session`
- Reverse proxy support based on Go's standard `httputil.ReverseProxy`
- Liveness and readiness endpoints

Before production, place the service behind the selected L4/WAF entry, add
mTLS to `auth-service` and product origins, and complete rate limiting and
OpenTelemetry integration.

## Configuration

```bash
export AUTH_SERVICE_TOKEN="$(openssl rand -hex 32)"
export AUTH_SERVICE_URL="http://127.0.0.1:8081"
export IDENTITY_HEADER_SIGNING_SECRET_FILE="/run/secrets/huiguang_identity_header_secret"
export ROUTES_FILE="$PWD/config/routes.example.json"
go run ./cmd/access-gateway
```

The service refuses to start without an auth URL, shared service token, and at
least one valid route. The service does not implicitly load `.env`; deployment
configuration must be injected by the process supervisor or container runtime.

## Route configuration

Routes use exact host matching and then select the longest matching
`path_prefix`. This allows `shiguanglab.com/_auth/login/*` to reach Auth
Service while normal website paths reach the static website origin. Use
`public_paths` for exact anonymous paths and `public_prefixes` for anonymous
subtrees. Prefixes ending in `/` match a subtree; other prefixes match one
exact path for backwards compatibility.
Set `strip_prefix` when an externally namespaced API should reach an upstream
that serves from `/`; it must be a parent of the route's `path_prefix`.

```json
{
  "routes": [
    {
      "host": "opc.shiguanglab.com",
      "path_prefix": "/",
      "product_id": "superagents",
      "audience": "superagents-bff",
      "upstream": "http://opc-web:8080",
      "public_prefixes": ["/health", "/assets/"],
      "required_entitlements": ["superagents:access"],
      "forward_authorization": false
    }
  ]
}
```

For example, the dedicated Points routes map only `/api/v1/me/`,
`/api/v1/admin/points/`, and `/api/v1/integration-admin/points/` to Points
Service using `"strip_prefix": "/api"`. Exact `/api/auth/session` and
`/api/auth/logout` routes go to Auth Service and accept only GET and POST,
respectively. The gateway injects its internal credential only on those auth
routes and forwards the shared session cookie in both directions only on those
auth routes. Machine paths such as `/api/v1/integration/token` and
`/api/v1/points/*` therefore cannot reach Points Service through the browser
host. Keep equivalent narrow `/api/platform/v1/...` routes during the
compatibility release until callers migrate.
The points administration and personal points views are served from this
dedicated points-system entry. The main website does not own the points system
UI; it may host only introduction, display content, and a centralized login
entry that returns to the dedicated points workbench.
Huiguang remains a standalone product at `huiguang.shiguanglab.com`. Its exact
root path `/` and static assets are public so the product introduction can be
viewed anonymously. `/app` and all creation routes require `huiguang:access`;
unauthenticated requests are redirected to the shared login page and return to
the requested Huiguang route after login.
Huiguang may proxy only the lightweight `/api/points/v1/me/` browser endpoints
for balance, check-in, and personal ledger. Client-credential exchange and all
machine mutation APIs stay on the private service network or a separately
controlled machine gateway; the browser never receives a client secret.
Its `/api/huiguang/` route targets `huiguang-bff:8080` without rewriting the
path, matching the BFF's public API contract. The BFF receives a short-lived
`huiguang-bff` identity assertion from Auth Service; it does not receive the
browser's Authorization header.

The Huiguang BFF route sets `sign_identity_headers: true`. Access Gateway first
removes all browser-provided `X-SG-*` headers, then injects `X-SG-Identity`, an
RFC 3339 UTC `X-SG-Identity-Timestamp`, and an HMAC-SHA256
`X-SG-Identity-Signature` over `${timestamp}.${identityPayload}`. Mount the same
secret file into Access Gateway as `IDENTITY_HEADER_SIGNING_SECRET_FILE` and
Huiguang BFF as `HUIGUANG_IDENTITY_HEADER_SECRET_FILE`; never mount it into the
web container. The signing secret must contain at least 32 characters.

## Commands

```bash
make test
make build
```

Every push to `main` publishes multi-architecture images to GHCR. `latest` is
only a discovery tag; staging and production deployment records must pin
`ghcr.io/shiguang-lab/access-gateway@sha256:<digest>`. Immutable `sha-*` tags
help locate a build but do not replace digest pinning for deployment or rollback.

The module path assumes the future GitHub repository will be
`github.com/shiguanglab/access-gateway`.
