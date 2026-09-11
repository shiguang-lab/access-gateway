# NAS Access Gateway

This directory is the production definition for the Go Access Gateway on the
NAS. It replaces the Caddy business-routing layer. TLS continues to terminate
at the existing external ingress, which forwards HTTP to the gateway's NAS
port.

`routes.json` contains every registered production host and its routing,
authorization, cookie, header, and path-rewrite policy. It also routes
`GET /oauth/device` to Website while the OAuth protocol endpoints remain on
Auth Service. The configuration rejects unknown fields at startup.

`compose.yaml` starts a candidate on port `13600` by default. Production must
pin `GATEWAY_IMAGE` by digest after the multi-architecture tag workflow has
finished. `GATEWAY_ENV_FILE` points to the existing protected environment file
that contains `GATEWAY_SHARED_TOKEN`; the token is passed to Auth Service only
through the internal gateway credential header.

Validate a candidate before changing the external ingress target:

```bash
docker compose --env-file /volume1/docker/shiguang-gateway/source/deploy/gateway.env \
  -f /volume1/docker/shiguang-deploy/access-gateway-go/compose.yaml config --quiet
docker compose --env-file /volume1/docker/shiguang-gateway/source/deploy/gateway.env \
  -f /volume1/docker/shiguang-deploy/access-gateway-go/compose.yaml up -d
curl -fsS http://100.87.115.78:13600/health/ready
```

Compare anonymous, protected, OAuth, CORS, static-media, and unknown-host
responses with the current gateway on port `3600`. After those checks pass,
recreate this stack on port `3600`, verify all public hosts through TLS, and
remove the old Caddy container and Caddyfile. Keep the last Caddy deployment
files only as an operational rollback artifact outside the active Compose
directory.
