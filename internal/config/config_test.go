package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testIdentityHeaderSigningSecret = "test-identity-header-signing-secret-32"

func TestExampleRoutesValidate(t *testing.T) {
	routes, err := filepath.Abs(filepath.Join("..", "..", "config", "routes.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_SERVICE_URL", "http://auth-service:8081")
	t.Setenv("AUTH_SERVICE_TOKEN", "gateway-secret")
	t.Setenv("IDENTITY_HEADER_SIGNING_SECRET_FILE", "")
	t.Setenv("IDENTITY_HEADER_SIGNING_SECRET", testIdentityHeaderSigningSecret)
	t.Setenv("ROUTES_FILE", routes)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("example routes are invalid: %v", err)
	}
	required := map[string]bool{
		"shiguanglab.com\x00/api/auth/":            false,
		"point.shiguanglab.com\x00/api/v2/":        false,
		"skills.shiguanglab.com\x00/api/v1/skills": false,
		"skills.shiguanglab.com\x00/api/v1/":       false,
		"skills.shiguanglab.com\x00/":              false,
	}
	for _, route := range cfg.Routes {
		if route.Host == "points.shiguanglab.com" || route.Host == "lingguang.shiguanglab.com" {
			t.Fatalf("example routes retain retired host %q", route.Host)
		}
		key := route.Host + "\x00" + route.PathPrefix
		if _, ok := required[key]; ok {
			required[key] = true
		}
	}
	for route, found := range required {
		if !found {
			t.Fatalf("example routes missing deployed route %q", route)
		}
	}
}

func TestShanghaiRoutesValidateAndKeepMachineAPIsClosed(t *testing.T) {
	routes, err := filepath.Abs(filepath.Join("..", "..", "deploy", "shanghai", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_SERVICE_URL", "http://127.0.0.1:19481")
	t.Setenv("AUTH_SERVICE_TOKEN", "gateway-secret")
	t.Setenv("AUTH_SERVICE_TOKEN_FILE", "")
	t.Setenv("IDENTITY_HEADER_SIGNING_SECRET", "")
	t.Setenv("ROUTES_FILE", routes)
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Shanghai routes are invalid: %v", err)
	}
	required := map[string]bool{
		"point.shiguanglab.com\x00/api/v2/tenant/points/": false,
		"point.shiguanglab.com\x00/api/v2/admin/points/":  false,
		"skills.shiguanglab.com\x00/api/v1/session":       false,
		"skills.shiguanglab.com\x00/api/v1/":              false,
	}
	for _, route := range cfg.Routes {
		if route.Host != "point.shiguanglab.com" && route.Host != "skills.shiguanglab.com" {
			t.Fatalf("unexpected Shanghai host %q", route.Host)
		}
		if route.Host == "point.shiguanglab.com" {
			switch route.PathPrefix {
			case "/api/v1/", "/api/platform/v1/", "/api/v2/":
				t.Fatalf("broad Points browser API route exposes future machine endpoints: %q", route.PathPrefix)
			}
			if route.PathPrefix == "/" {
				if slices.Contains(route.PublicPrefixes, "/") {
					t.Fatal("Points UI root must not bypass Gateway authorization")
				}
				if !slices.Contains(route.PublicPrefixes, "/assets/") || !slices.Contains(route.PublicPaths, "/health") {
					t.Fatal("Points UI must keep only assets and health public")
				}
			}
		}
		key := route.Host + "\x00" + route.PathPrefix
		if _, ok := required[key]; ok {
			required[key] = true
		}
	}
	for route, found := range required {
		if !found {
			t.Fatalf("Shanghai routes missing %q", route)
		}
	}
}

func TestLoadRejectsUnknownRouteFields(t *testing.T) {
	routes := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(routes, []byte(`{"routes":[{"host":"example.com","path_prefix":"/","product_id":"x","audience":"x","upstream":"http://upstream:8080","publik":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_SERVICE_URL", "http://auth-service:8081")
	t.Setenv("AUTH_SERVICE_TOKEN", "gateway-secret")
	t.Setenv("ROUTES_FILE", routes)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown route field error = %v", err)
	}
}

func TestShanghaiNginxTemplatesBlockPublicHealth(t *testing.T) {
	root := filepath.Join("..", "..", "deploy", "shanghai", "nginx")
	for _, name := range []string{"shanghai-origin-wireguard.conf.example", "japan-ingress.conf.example"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, host := range []string{"point.shiguanglab.com", "skills.shiguanglab.com"} {
			if !strings.Contains(text, "server_name "+host+";") {
				t.Fatalf("%s missing host %s", name, host)
			}
		}
		for _, location := range []string{"location = /health/live { return 404; }", "location = /health/ready { return 404; }"} {
			if strings.Count(text, location) != 2 {
				t.Fatalf("%s must block %q in both product vhosts", name, location)
			}
		}
	}

	japanBody, err := os.ReadFile(filepath.Join(root, "japan-ingress.conf.example"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(japanBody), "location = /__origin_health { return 404; }") != 2 {
		t.Fatal("Japan ingress must block the private origin health path in both public vhosts")
	}
}

func TestValidateRejectsWildcardAndDuplicateHosts(t *testing.T) {
	base := Config{
		AuthServiceURL:    "http://auth-service:8081",
		AuthServiceToken:  "secret",
		SessionCookieName: "__Secure-sg_session",
	}

	base.Routes = []Route{{
		Host:      "*.shiguanglab.com",
		ProductID: "website",
		Audience:  "website",
		Upstream:  "http://website:8080",
	}}
	if err := base.Validate(); err == nil {
		t.Fatal("expected wildcard host to be rejected")
	}

	base.Routes = []Route{
		{Host: "opc.shiguanglab.com", PathPrefix: "/", ProductID: "opc", Audience: "opc", Upstream: "http://opc:8080"},
		{Host: "OPC.shiguanglab.com", PathPrefix: "/", ProductID: "opc2", Audience: "opc2", Upstream: "http://opc2:8080"},
	}
	if err := base.Validate(); err == nil {
		t.Fatal("expected duplicate normalized host and path prefix to be rejected")
	}

	base.Routes = []Route{
		{Host: "shiguanglab.com", PathPrefix: "/", ProductID: "website", Audience: "website", Upstream: "http://website:8080"},
		{Host: "shiguanglab.com", PathPrefix: "/_auth/login/", ProductID: "login", Audience: "auth-service", Upstream: "http://auth:8081"},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("same host with different path prefixes should be valid: %v", err)
	}
}

func TestValidateRequiresIdentityHeaderSigningSecret(t *testing.T) {
	base := Config{
		AuthServiceURL:    "http://auth-service:8081",
		AuthServiceToken:  "secret",
		SessionCookieName: "__Secure-sg_session",
		Routes: []Route{{
			Host:                "huiguang.shiguanglab.com",
			ProductID:           "huiguang",
			Audience:            "huiguang-bff",
			Upstream:            "http://huiguang-bff:8080",
			SignIdentityHeaders: true,
		}},
	}
	if err := base.Validate(); err == nil {
		t.Fatal("signed identity route accepted without a signing secret")
	}
	base.IdentityHeaderSigningSecret = testIdentityHeaderSigningSecret
	if err := base.Validate(); err != nil {
		t.Fatalf("signed identity route rejected with a signing secret: %v", err)
	}
}

func TestValidateRestrictsForwardedGatewayTokenToAuthService(t *testing.T) {
	base := Config{
		AuthServiceURL:    "http://auth-service:8081",
		AuthServiceToken:  "secret",
		SessionCookieName: "__Secure-sg_session",
		Routes: []Route{{
			Host:                "point.shiguanglab.com",
			PathPrefix:          "/api/v1/me/",
			ProductID:           "points",
			Audience:            "points-service",
			Upstream:            "http://points-service:8082",
			ForwardGatewayToken: true,
		}},
	}
	if err := base.Validate(); err == nil {
		t.Fatal("non-auth route accepted with forwarded gateway token")
	}
}

func TestValidateAllowsExplicitSessionForwardingToSelfAuthorizingUpstream(t *testing.T) {
	base := Config{
		AuthServiceURL:    "http://auth-service:8081",
		AuthServiceToken:  "secret",
		SessionCookieName: "__Secure-sg_session",
		Routes: []Route{{
			Host:                 "point.shiguanglab.com",
			PathPrefix:           "/api/v1/me/",
			ProductID:            "points",
			Audience:             "points-service",
			Upstream:             "http://points-service:8082",
			ForwardSessionCookie: true,
		}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("explicit session forwarding was rejected: %v", err)
	}
}

func TestValidateStripPrefix(t *testing.T) {
	base := Config{
		AuthServiceURL:    "http://auth-service:8081",
		AuthServiceToken:  "secret",
		SessionCookieName: "__Secure-sg_session",
		Routes: []Route{{
			Host:        "huiguang.shiguanglab.com",
			PathPrefix:  "/api/platform/",
			StripPrefix: "/api/platform/",
			ProductID:   "platform",
			Audience:    "platform-service",
			Upstream:    "http://platform-service:8082",
		}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid strip prefix rejected: %v", err)
	}
	if got := base.Routes[0].StripPrefix; got != "/api/platform" {
		t.Fatalf("normalized strip prefix = %q", got)
	}

	base.Routes[0].StripPrefix = "/api/other"
	if err := base.Validate(); err == nil {
		t.Fatal("strip prefix outside path prefix was accepted")
	}
}

func TestValidatePublicPaths(t *testing.T) {
	base := Config{
		AuthServiceURL:    "http://auth-service:8081",
		AuthServiceToken:  "secret",
		SessionCookieName: "__Secure-sg_session",
		Routes: []Route{{
			Host:        "huiguang.shiguanglab.com",
			ProductID:   "huiguang",
			Audience:    "huiguang-web",
			Upstream:    "http://huiguang-web:3000",
			PublicPaths: []string{"/"},
		}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid exact public path rejected: %v", err)
	}

	base.Routes[0].PublicPaths = []string{"app"}
	if err := base.Validate(); err == nil {
		t.Fatal("relative public path was accepted")
	}
}

func TestLoadReadsAuthServiceTokenFromFile(t *testing.T) {
	routes, err := filepath.Abs(filepath.Join("..", "..", "config", "routes.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "gateway-token")
	if err := os.WriteFile(tokenFile, []byte("file-gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_SERVICE_URL", "http://auth-service:8081")
	t.Setenv("AUTH_SERVICE_TOKEN", "")
	t.Setenv("AUTH_SERVICE_TOKEN_FILE", tokenFile)
	t.Setenv("IDENTITY_HEADER_SIGNING_SECRET", testIdentityHeaderSigningSecret)
	t.Setenv("ROUTES_FILE", routes)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthServiceToken != "file-gateway-secret" {
		t.Fatalf("auth service token = %q", cfg.AuthServiceToken)
	}
}

func TestLoadRejectsAmbiguousAuthServiceToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "gateway-token")
	if err := os.WriteFile(tokenFile, []byte("file-gateway-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_SERVICE_TOKEN", "environment-secret")
	t.Setenv("AUTH_SERVICE_TOKEN_FILE", tokenFile)

	if _, err := Load(); err == nil {
		t.Fatal("expected ambiguous auth service token configuration to fail")
	}
}

func TestLoadParsesTrustedProxyCIDRs(t *testing.T) {
	routes, err := filepath.Abs(filepath.Join("..", "..", "config", "routes.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_SERVICE_URL", "http://auth-service:8081")
	t.Setenv("AUTH_SERVICE_TOKEN", "gateway-secret")
	t.Setenv("AUTH_SERVICE_TOKEN_FILE", "")
	t.Setenv("IDENTITY_HEADER_SIGNING_SECRET", testIdentityHeaderSigningSecret)
	t.Setenv("ROUTES_FILE", routes)
	t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.0/8, ::1/128")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("trusted proxy CIDRs = %d", len(cfg.TrustedProxyCIDRs))
	}
}

func TestLoadRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	t.Setenv("AUTH_SERVICE_TOKEN", "gateway-secret")
	t.Setenv("TRUSTED_PROXY_CIDRS", "not-a-cidr")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid trusted proxy CIDR to fail")
	}
}
