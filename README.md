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
- Explicit route priority, method and request-header matching
- Public and protected path policies
- Fail-closed authorization through `auth-service`
- Removal of external `X-SG-*` and `X-User-*` identity headers
- Request and response isolation for `__Secure-sg_session`
- Reverse proxy support based on Go's standard `httputil.ReverseProxy`
- Static responses, path rewriting, and request/response header policies
- Liveness and readiness endpoints

## Configuration

```bash
export AUTH_SERVICE_TOKEN_FILE="/run/secrets/auth_service_token"
export AUTH_SERVICE_URL="http://127.0.0.1:8081"
export IDENTITY_HEADER_SIGNING_SECRET_FILE="/run/secrets/huiguang_identity_header_secret"
export ROUTES_FILE="$PWD/config/routes.example.json"
go run ./cmd/access-gateway
```

The service refuses to start without an auth URL, shared service token, and at
least one valid route. The service does not implicitly load `.env`; deployment
configuration must be injected by the process supervisor or container runtime.
Set either `AUTH_SERVICE_TOKEN` for local development or
`AUTH_SERVICE_TOKEN_FILE` for deployed environments, never both. The file form
is required by the Shanghai production candidate.

When TLS terminates at a loopback reverse proxy, set
`TRUSTED_PROXY_CIDRS=127.0.0.0/8,::1/128`. Forwarded scheme, port, and client IP
are honored only when the direct peer belongs to one of those networks;
untrusted browser-provided forwarding headers are discarded. The ingress must
overwrite forwarding headers instead of appending arbitrary client values.

Access Gateway uses the canonical internal decision protocol
`POST /v1/authorize` with a bounded JSON request. The shared credential is sent
only as `X-SG-Gateway-Token`; `Authorization: Bearer` is not used for this
protocol. Auth Service returns a structured decision for allow, deny, login
redirect, identity assertion, and session-cookie updates. Any transport,
authentication, or JSON decoding error fails closed.

## Route configuration

Routes use exact host matching and then select the longest matching
`path_prefix`. A larger optional `priority` is evaluated first when a
header- or method-constrained route must override a longer general route.
This allows `shiguanglab.com/_auth/login/*` to reach Auth
Service while normal website paths reach the static website origin. Use
`public_paths` for exact anonymous paths and `public_prefixes` for anonymous
subtrees. Prefixes ending in `/` match a subtree; other prefixes match one
exact path for backwards compatibility.
Set `strip_prefix` when an externally namespaced API should reach an upstream
that serves from `/`; it must be a parent of the route's `path_prefix`.
Use `rewrite_path` for an exact replacement or `add_path_prefix` to prepend an
upstream namespace. Route files are decoded strictly, so unknown fields stop
the service during validation.

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
respectively. The protected `/api/auth/iam/points-role-assignments/` prefix also
goes to Auth Service, accepts only POST/PUT, and requires `platform:access`;
Auth Service then enforces `opc:system-admin` from the refreshed session. The
gateway injects its internal credential only on these exact auth routes and
forwards the shared session cookie in both directions only on those auth
routes. Browser `Authorization` is stripped. Machine paths such as
`/api/v1/integration/token` and
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

## Shanghai production candidate

The isolated candidate for `point.shiguanglab.com` and
`skills.shiguanglab.com` is documented in
[`deploy/shanghai/README.md`](deploy/shanghai/README.md). It binds the Gateway
only to `127.0.0.1:19480`, requires a digest-pinned image and a read-only Auth
credential file, and keeps product services in their independent repositories
and Compose projects. The official Website, Portal, and Auth Service are not
deployed by this stack.

## NAS production

The complete NAS route policy and candidate Compose stack are documented in
[`deploy/nas/README.md`](deploy/nas/README.md). The Go gateway owns HTTP host,
path, authentication, header, and upstream routing. TLS remains at the existing
external ingress.

## Local Points identity acceptance

The repository owns a local-only, no-secret integration stack for the Points
workbench. It builds the sibling Auth, Points Service, and Points Web
repositories and runs them behind the real Access Gateway at one browser
origin:

```bash
make local-e2e
```

That command starts fresh PostgreSQL and Redis containers, applies the Points
migrations to the new local volume, seeds identity state through the Auth
fixture, exercises the real browser session/JWT/membership boundaries, and
then removes the temporary containers, network, and database volume. It checks
anonymous login redirects, session and logout, platform role refresh,
application isolation, 401/403/404 behavior, durable IAM idempotency,
reconciliation, and controlled retry.

For manual browser acceptance:

```bash
make local-up
# open http://127.0.0.1:18080/
make local-smoke
make local-down
```

The isolated Redis and PostgreSQL integration suites can be repeated with:

```bash
make local-persistence-test
```

The helper creates uniquely named containers and a network and removes them on
success, failure, or interruption. It never connects to a host or shared
database.

The checked-in values in `local/compose.yaml` are conspicuous fixture values,
accepted only when Auth runs with `LOCAL_IDENTITY_FIXTURE=1` in development.
The fixture is rejected in production and never calls ZITADEL. It models the
real cookie, return-to, audience, Gateway authorization, Auth-signed identity,
and Points membership contracts; it is not a production identity provider.

Pushing a version tag matching `v*` publishes multi-architecture images to
GHCR. A `v0.1.0` release publishes `0.1.0`, `v0.1.0`, `sha-*`, and `latest`
tags. `latest` is only a discovery tag; staging and production deployment
records must pin `ghcr.io/shiguang-lab/access-gateway@sha256:<digest>`.
Immutable `sha-*` tags help locate a build but do not replace digest pinning
for deployment or rollback.

The module path assumes the future GitHub repository will be
`github.com/shiguanglab/access-gateway`.
