package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthRelayTemplatesArePrivateAndAllowlisted(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "shanghai", "auth-relay")
	relayBody, err := os.ReadFile(filepath.Join(root, "nginx.conf.example"))
	if err != nil {
		t.Fatal(err)
	}
	relay := string(relayBody)
	for _, required := range []string{
		"listen 127.0.0.1:19481;",
		"server auth-origin.shiguanglab.internal:18481;",
		"proxy_ssl_verify on;",
		"proxy_ssl_certificate /run/secrets/auth_relay_client_cert;",
		"proxy_ssl_certificate_key /run/secrets/auth_relay_client_key;",
		"location / {\n            return 404;",
	} {
		if !strings.Contains(relay, required) {
			t.Fatalf("relay template missing %q", required)
		}
	}
	for _, path := range []string{
		"/health/ready",
		"/.well-known/jwks.json",
		"/v1/authorize",
		"/api/auth/session",
		"/api/auth/logout",
		"/api/auth/iam/points-role-assignments/search",
		"/api/auth/iam/points-role-assignments/resolve",
	} {
		if !strings.Contains(relay, "location = "+path) {
			t.Fatalf("relay template missing allowlisted path %s", path)
		}
	}
	for _, forbidden := range []string{
		"/api/auth/login/",
		"/api/auth/register",
		"/api/auth/oidc/callback",
		"/v1/identity/",
	} {
		if strings.Contains(relay, forbidden) {
			t.Fatalf("relay template exposes forbidden path %s", forbidden)
		}
	}

	originBody, err := os.ReadFile(filepath.Join(root, "auth-origin-nginx.conf.example"))
	if err != nil {
		t.Fatal(err)
	}
	origin := string(originBody)
	for _, required := range []string{
		"listen <AUTH_PRIVATE_BIND_IP>:18481 ssl;",
		"allow <SHANGHAI_RELAY_PRIVATE_IP>;",
		"deny all;",
		"ssl_verify_client on;",
		"proxy_pass http://127.0.0.1:8081;",
		"location / {\n            return 404;",
	} {
		if !strings.Contains(origin, required) {
			t.Fatalf("Auth origin template missing %q", required)
		}
	}

	composeBody, err := os.ReadFile(filepath.Join(root, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(composeBody)
	for _, required := range []string{
		"image: ${AUTH_RELAY_IMAGE:?set an immutable relay image ending in @sha256:digest}",
		"network_mode: host",
		"AUTH_PRIVATE_ORIGIN_IP",
		"user: ${AUTH_RELAY_UID_GID:-101:101}",
		"read_only: true",
		"no-new-privileges:true",
		"AUTH_RELAY_CLIENT_KEY_FILE",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("relay Compose missing %q", required)
		}
	}
	if strings.Contains(relay, "10.77.0.1") || strings.Contains(compose, "10.77.0.1") {
		t.Fatal("Auth relay must not use the Japan product-ingress peer as its Auth origin")
	}
}
