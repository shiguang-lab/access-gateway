# Shanghai Access Gateway candidate

This candidate serves only `point.shiguanglab.com` and
`skills.shiguanglab.com`. It does not host the official website, Portal, or
Auth Service.

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

The Shanghai Nginx vhost must block `/health/live`, `/health/ready`, and
`/__origin_health` from public clients. It must overwrite, not append,
`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Port`, and all `X-SG-*`
identity headers before forwarding to the loopback Gateway.

## Rollback

Remove the Japan vhost from service first, then remove the Shanghai private
origin vhost. Stop this Compose project without deleting unrelated containers,
networks, images, or volumes:

```bash
docker compose -f deploy/shanghai/compose.yaml down
```

Rollback is image/config based. Do not run database down migrations as part of
Gateway rollback.
