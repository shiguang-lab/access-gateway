package config

import "testing"

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
