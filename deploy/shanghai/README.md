# Shanghai Access Gateway candidate

This candidate serves only `point.shiguanglab.com` and
`skills.shiguanglab.com`. It does not host the official website, Portal, or
Auth Service.

Japan `8.216.91.60` is only the public Nginx/TLS forwarder for these two hosts.
It must not run this Gateway, Points, Lingguang, Auth, a database, a queue, a
worker, or another new business service. Existing Japan vhosts and services,
including `ai.jspin.cn`, Sub2API, and Huiguang, are immutable boundaries for
this deployment. Shanghai `101.132.41.39` owns the candidate services below;
Website/Portal/Auth remain owned by the independent Website team.

## Fixed local ports

| Component | Address |
| --- | --- |
| Access Gateway | `127.0.0.1:19480` |
| Auth private relay | `127.0.0.1:19481` |
| Points Web | `127.0.0.1:19280` |
| Points Service | `127.0.0.1:19283` |
| Lingguang Web | `127.0.0.1:19378` |
| Lingguang API | `127.0.0.1:19380` |

The Auth private relay is a mandatory external dependency. The Website/Auth
deployment owner must expose Auth Service session/logout routes and
`POST /v1/authorize` to Shanghai through a private tunnel or authenticated
mTLS connection. Do not publish `/v1/authorize` as an unauthenticated public
endpoint. The relay must preserve the Gateway credential and session-cookie
contract without logging either value.

The frozen WireGuard plus mTLS relay contract lives in
[`auth-relay/`](auth-relay/). `127.0.0.1:19481` is Gateway-only: bridge-network
product containers cannot use the host loopback address for Auth Directory or
JWKS calls and require a separately approved private Auth endpoint. The
Japan-Shanghai product-ingress tunnel is not the Auth relay upstream.

## Required inputs

- `GATEWAY_IMAGE`: GHCR image pinned by digest, never `latest` or a mutable tag.
- `GATEWAY_AUTH_TOKEN_FILE`: root-owned `0600` file issued by Auth Service and
  delivered through the approved secret store.
- Healthy production candidates on the four fixed product loopback ports.
- Healthy Auth private relay on `127.0.0.1:19481`.

Do not store secret values in this directory or in Compose environment fields.

## Preflight

```bash
test "${GATEWAY_IMAGE#*@sha256:}" != "$GATEWAY_IMAGE"
test -r "$GATEWAY_AUTH_TOKEN_FILE"
docker compose -f deploy/shanghai/compose.yaml config --quiet
curl -fsS http://127.0.0.1:19481/health/ready
curl -fsS http://127.0.0.1:19283/health/ready
curl -fsS http://127.0.0.1:19380/health/ready
```

Start only the Gateway candidate:

```bash
docker compose -f deploy/shanghai/compose.yaml up -d
curl -fsS http://127.0.0.1:19480/health/ready
```

Use Host-header smoke tests from Shanghai before adding any origin vhost:

```bash
curl -fsS -H 'Host: skills.shiguanglab.com' http://127.0.0.1:19480/
curl -i -H 'Host: point.shiguanglab.com' http://127.0.0.1:19480/
curl -i -H 'Host: unknown.shiguanglab.com' http://127.0.0.1:19480/
```

The anonymous Points request must redirect to the official Website login with
an HTTPS `return_to`. The unknown host must return `421`. Machine Points paths
such as `/api/v1/integration/token` and `/api/v1/points/reservations` must not
reach Points Service.

Only `/assets/` and `/health` bypass authorization on the Points UI route. The
SPA root and all workbench paths require an Auth decision.

The Shanghai Nginx vhost must block `/health/live`, `/health/ready`, and
`/__origin_health` from public clients. It must overwrite, not append,
`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Port`, and all `X-SG-*`
identity headers before forwarding to the loopback Gateway.

Executable Nginx templates live in [`nginx/`](nginx/):

- `shanghai-origin-wireguard.conf.example` binds only `10.77.0.2:19443`,
  allows only the Japan peer `10.77.0.1`, and forwards both product hosts to
  the loopback Gateway.
- `japan-ingress.conf.example` terminates public TLS, overwrites forwarding and
  identity headers, blocks all health paths publicly, and connects directly to
  `10.77.0.2:19443` without resolving the public product domains.

Before installation, verify certificate paths and that `10.77.0.0/30` and UDP
`51820` do not conflict with either host, Docker, cloud security groups, or
host firewall policy. Back up the active Nginx tree, copy each template to the
server's native include directory, run the native `nginx -t`, and reload only
after a successful check. Never overwrite an existing default vhost.

## Rollback

Remove the Japan vhost from service first, then remove the Shanghai private
origin vhost. Stop this Compose project without deleting unrelated containers,
networks, images, or volumes:

```bash
docker compose -f deploy/shanghai/compose.yaml down
```

Rollback is image/config based. Do not run database down migrations as part of
Gateway rollback.
