# Shanghai Auth private relay

This relay is the narrow handoff between the Shanghai Access Gateway and the
independently owned Website/Auth deployment. It listens only on
`127.0.0.1:19481` and connects to the Auth owner endpoint at
`auth-origin.shiguanglab.internal:18481` over a separately approved private
tunnel and mutually authenticated TLS.

It is not a Website or Auth Service deployment. It does not create IAM roles,
credentials, certificates, or public routes.

## Auth handoff baseline

The reviewed Auth Service source baseline is
`92b5ede5a3ebd23ed5cf09050c1a26879af32d36`. Its production return-origin
allowlist includes `https://point.shiguanglab.com` and
`https://skills.shiguanglab.com`; the Points IAM administrator origin is
`https://point.shiguanglab.com`. Auth unit tests and vet passed for that source
baseline.

This is source evidence only. The Shanghai relay, Gateway/Auth token, signing
and verification keys, private certificates, and real deployment remain
unprovisioned No-Go items.

## Deployment hard gate

- Japan `8.216.91.60` may terminate public Nginx/TLS only for
  `point.shiguanglab.com` and `skills.shiguanglab.com` and forward those hosts
  to Shanghai. It must not run Points, Lingguang, Gateway, Auth, databases,
  queues, workers, or any new business service.
- Existing Japan services including `ai.jspin.cn`, Sub2API, Huiguang, their
  Nginx vhosts, containers, ports, networks, and data are out of scope and must
  not be modified or migrated.
- Shanghai `101.132.41.39` owns the Points, Lingguang, and Access Gateway
  candidates. Website, Portal, and Auth remain independently deployed and
  operated by the Website/Auth team.
- The Japan-Shanghai `10.77.0.0/30` tunnel is product-ingress transport only.
  It is not an Auth origin and must not route Website/Auth traffic.
- The Website/Auth owner must provide a separate private origin IP, route,
  mTLS identity, health contract, and rollback owner before the relay can be
  enabled. The Shanghai host firewall must restrict relay egress to that one
  approved IP and port.

Any server action requires a C-class approval naming the target server, exact
services and ports, expected interruption, evidence capture, and rollback.

## Trust boundary

- The Shanghai Gateway is the only intended local caller.
- The relay passes through the existing `X-SG-Gateway-Token`; it never creates
  or persists that credential.
- The Auth origin accepts only the approved Shanghai relay private address and
  a certificate issued by the dedicated relay-client CA.
- Both proxy layers disable access logs and must never log cookies, gateway
  tokens, authorization bodies, or identity assertions.
- Unknown paths fail closed with `404`. Unsupported methods are denied.
- Login, registration, federated login, OIDC callbacks, organization APIs,
  Portal-wide product-role administration, and identity-directory APIs are not
  exposed by this relay.

The frozen relay paths are:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health/ready` | Verify the complete mTLS/Auth path |
| `GET` | `/.well-known/jwks.json` | Auth identity verification keys |
| `POST` | `/v1/authorize` | Gateway authorization decision |
| `GET` | `/api/auth/session` | Product-domain session projection |
| `POST` | `/api/auth/logout` | Shared-session logout |
| `POST` | `/api/auth/iam/points-role-assignments/search` | Points IAM search |
| `POST` | `/api/auth/iam/points-role-assignments/resolve` | Exact IAM resolve |
| `PUT` | `/api/auth/iam/points-role-assignments/{userId}` | Points role update |

`127.0.0.1:19481` is reachable by the host-network Gateway only. A Points
Service container on a bridge network must not use this loopback address for
`POINTS_IDENTITY_JWKS_URL` or `POINTS_IDENTITY_SERVICE_BASE_URL`; the Auth owner
must provide a separately approved private endpoint for those server-to-server
calls.

## Immutable inputs

- `AUTH_RELAY_IMAGE` is an approved image reference pinned by digest.
- `AUTH_PRIVATE_ORIGIN_IP` is the private IP handed off by the Website/Auth
  owner; it must not be a public product hostname or the Japan ingress peer.
- `AUTH_ORIGIN_CA_FILE` contains the CA bundle used to verify
  `auth-origin.shiguanglab.internal`.
- `AUTH_RELAY_CLIENT_CERT_FILE` and `AUTH_RELAY_CLIENT_KEY_FILE` identify this
  relay to the Auth origin.
- `AUTH_RELAY_UID_GID` is a non-root account that can read only the mounted
  relay material.

Secret files live outside Git and the image. Do not place values in an env
file, command line, ticket, or Compose YAML.

The Auth owner renders `auth-origin-nginx.conf.example` with its private bind
IP and the Shanghai relay's private source IP, then runs it as an isolated
private ingress. It must not be included in the Japan ingress or the existing
public Website vhost. The template assumes Auth Service is bound privately at
`127.0.0.1:8081`; its owner must validate that handoff without exposing that
port publicly.

## Preflight and smoke

Render and inspect Compose before any server action:

```bash
test "${AUTH_RELAY_IMAGE#*@sha256:}" != "$AUTH_RELAY_IMAGE"
docker compose -f deploy/shanghai/auth-relay/compose.yaml config --quiet
```

After the Website/Auth owner has independently validated the private origin,
the approved Shanghai smoke sequence is:

```bash
curl -fsS http://127.0.0.1:19481/health/live
curl -fsS http://127.0.0.1:19481/health/ready
curl -i http://127.0.0.1:19481/api/auth/login/context
curl -i -X POST http://127.0.0.1:19481/v1/authorize
```

The unlisted login path must return `404`. The authorization request without a
Gateway token must fail. From the Auth host, a TLS request without the relay
client certificate and a request from an address other than the approved
Shanghai relay address must both fail before reaching Auth Service.

## Certificate rotation

Rotate CA and leaf material with an overlap window:

1. Add the new issuing CA to the relay and Auth-origin trust bundles while the
   old CA remains trusted.
2. Install the new Auth-origin leaf and reload only its isolated ingress.
3. Verify hostname, chain, expiry, mTLS rejection, and `/health/ready` from the
   relay.
4. Install the new relay client certificate and reload only the relay.
5. Verify authorization, session, logout, `Set-Cookie`, and role-management
   responses through the Gateway.
6. Remove the old CA only after the overlap and rollback windows close.

Alert on either leaf certificate at 30 days remaining, page at 14 days, and
stop release work at 7 days. Public certificates for `point.shiguanglab.com`
and `skills.shiguanglab.com` remain owned by the Japan ingress and have a
separate renewal and reload procedure.

## Backup and rollback

Back up the rendered relay/origin configuration, immutable image digest,
certificate metadata and trust-bundle checksums. Private keys remain under the
secret-store backup policy and must not be copied into a generic configuration
archive.

Rollback the Japan product vhost first, then restore the previous relay config
and image digest. Validate the candidate config before reload. Keep the
loopback listener or an explicit fail-closed hold service in place so traffic
cannot fall through to an unrelated host service. Relay rollback never runs a
database migration and never changes Website/Auth public routing.
