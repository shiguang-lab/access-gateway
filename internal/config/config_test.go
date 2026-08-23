package config

import (
	"path/filepath"
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
		"shiguanglab.com\x00/api/auth/": false,
		"point.shiguanglab.com\x00/api/v2/": false,
		"skills.shiguanglab.com\x00/api/v1/skills": false,
		"skills.shiguanglab.com\x00/api/v1/": false,
		"skills.shiguanglab.com\x00/": false,
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

func TestValidateRestrictsForwardedSessionCookieToAuthService(t *testing.T) {
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
	if err := base.Validate(); err == nil {
		t.Fatal("non-auth route accepted with forwarded session cookie")
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
