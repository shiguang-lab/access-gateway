# Shiguang Access Gateway

Organization-level HTTP access gateway for `*.shiguanglab.com`.

The service owns the public reverse-proxy boundary. It resolves an exact host
to a registered product origin, asks `auth-service` for protected-route
decisions, removes browser-provided identity headers, strips the shared session
cookie before proxying, and injects a short-lived product-scoped identity
assertion.

It is intentionally separate from every product BFF.

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
export ROUTES_FILE="$PWD/config/routes.example.json"
go run ./cmd/access-gateway
```

The service refuses to start without an auth URL, shared service token, and at
least one valid route. The service does not implicitly load `.env`; deployment
configuration must be injected by the process supervisor or container runtime.

## Route configuration

Routes use exact host matching and then select the longest matching
`path_prefix`. This allows `shiguanglab.com/_auth/login/*` to reach Auth
Service while normal website paths reach the static website origin. Public
prefixes ending in `/` match a subtree; other values match one exact path.

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

## Commands

```bash
make test
make build
```

The module path assumes the future GitHub repository will be
`github.com/shiguanglab/access-gateway`.
