package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shiguanglab/access-gateway/internal/authz"
	"github.com/shiguanglab/access-gateway/internal/config"
)

const testIdentityHeaderSecret = "test-identity-header-signing-secret-32"

type fakeAuthorizer struct {
	decision authz.DecisionResponse
	err      error
	request  authz.DecisionRequest
}

func (f *fakeAuthorizer) Authorize(_ context.Context, request authz.DecisionRequest) (authz.DecisionResponse, error) {
	f.request = request
	return f.decision, f.err
}

func TestHandlerStripsUntrustedIdentityAndSessionCookie(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("X-SG-Identity"); got != "trusted.jwt" {
			t.Errorf("identity = %q", got)
		}
		if got := request.Header.Get("X-User-ID"); got != "" {
			t.Errorf("untrusted user header reached upstream: %q", got)
		}
		if got := request.Header.Get("Cookie"); got != "product_cookie=ok" {
			t.Errorf("cookie = %q", got)
		}
		if got := request.Header.Get("Authorization"); got != "" {
			t.Errorf("authorization reached upstream: %q", got)
		}
		response.Header().Add("Set-Cookie", "__Secure-sg_session=overwrite")
		response.Header().Add("Set-Cookie", "product_cookie=new")
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	authorizer := &fakeAuthorizer{decision: authz.DecisionResponse{
		Allow:         true,
		Status:        http.StatusOK,
		IdentityToken: "trusted.jwt",
	}}
	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{{
			Host:      "opc.shiguanglab.com",
			ProductID: "superagents",
			Audience:  "superagents-bff",
			Upstream:  upstream.URL,
		}},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://opc.shiguanglab.com/api/me", nil)
	request.Header.Set("Cookie", "__Secure-sg_session=secret; product_cookie=ok")
	request.Header.Set("Authorization", "Bearer browser-token")
	request.Header.Set("X-SG-Identity", "forged")
	request.Header.Set("X-User-ID", "forged-user")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	if cookies := recorder.Result().Header.Values("Set-Cookie"); len(cookies) != 1 || !strings.HasPrefix(cookies[0], "product_cookie=") {
		t.Fatalf("set-cookie = %#v", cookies)
	}
	if authorizer.request.Cookie == "" {
		t.Fatal("auth service did not receive browser cookie")
	}
}

func TestHandlerReplacesForgedExpiredAndReplayedIdentityHeaders(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.URL.Path; got != "/api/huiguang/tasks/task-1" {
			t.Errorf("Huiguang BFF path was rewritten: %q", got)
		}
		timestamp := request.Header.Get("X-SG-Identity-Timestamp")
		if timestamp != fixedNow.Format(time.RFC3339Nano) {
			t.Errorf("timestamp = %q", timestamp)
		}
		if got := request.Header.Get("X-SG-Identity"); got != "trusted.jwt" {
			t.Errorf("identity = %q", got)
		}
		expected := hmac.New(sha256.New, []byte(testIdentityHeaderSecret))
		expected.Write([]byte(timestamp + ".trusted.jwt"))
		if got := request.Header.Get("X-SG-Identity-Signature"); !hmac.Equal(mustDecodeHex(t, got), expected.Sum(nil)) {
			t.Errorf("signature was not replaced with a trusted value")
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, err := NewHandler(config.Config{
		IdentityHeaderSigningSecret: testIdentityHeaderSecret,
		SessionCookieName:           "__Secure-sg_session",
		Routes: []config.Route{{
			Host:                "huiguang.shiguanglab.com",
			PathPrefix:          "/api/huiguang/",
			ProductID:           "huiguang",
			Audience:            "huiguang-bff",
			Upstream:            upstream.URL,
			SignIdentityHeaders: true,
		}},
	}, &fakeAuthorizer{decision: authz.DecisionResponse{Allow: true, Status: http.StatusOK, IdentityToken: "trusted.jwt"}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return fixedNow }

	request := httptest.NewRequest(http.MethodGet, "https://huiguang.shiguanglab.com/api/huiguang/tasks/task-1", nil)
	request.Header.Set("X-SG-Identity", "replayed.jwt")
	request.Header.Set("X-SG-Identity-Timestamp", fixedNow.Add(-time.Hour).Format(time.RFC3339Nano))
	request.Header.Set("X-SG-Identity-Signature", "forged")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	return decoded
}

func TestHandlerFailsClosedWhenAuthorizationFails(t *testing.T) {
	authorizer := &fakeAuthorizer{err: context.DeadlineExceeded}
	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{{
			Host:      "opc.shiguanglab.com",
			ProductID: "superagents",
			Audience:  "superagents-bff",
			Upstream:  "http://127.0.0.1:1",
		}},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://opc.shiguanglab.com/api/me", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestPublicPathBypassesAuthService(t *testing.T) {
	authorizer := &fakeAuthorizer{decision: authz.DecisionResponse{Allow: true, Status: http.StatusOK}}
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{{
			Host:           "shiguanglab.com",
			ProductID:      "website",
			Audience:       "website",
			Upstream:       upstream.URL,
			PublicPrefixes: []string{"/assets/"},
		}},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://shiguanglab.com/assets/app.js", nil))
	if authorizer.request.RequestID != "" {
		t.Fatal("public route unexpectedly called auth service")
	}
}

func TestExactPublicRootDoesNotExposeProtectedApp(t *testing.T) {
	authorizer := &fakeAuthorizer{decision: authz.DecisionResponse{
		Allow:    false,
		Status:   http.StatusFound,
		Location: "https://shiguanglab.com/login?return_to=https%3A%2F%2Fhuiguang.shiguanglab.com%2Fapp",
	}}
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{{
			Host:        "huiguang.shiguanglab.com",
			ProductID:   "huiguang",
			Audience:    "huiguang-web",
			Upstream:    upstream.URL,
			PublicPaths: []string{"/"},
		}},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	rootRecorder := httptest.NewRecorder()
	handler.ServeHTTP(rootRecorder, httptest.NewRequest(http.MethodGet, "https://huiguang.shiguanglab.com/", nil))
	if rootRecorder.Code != http.StatusOK {
		t.Fatalf("root status = %d", rootRecorder.Code)
	}
	if authorizer.request.RequestID != "" {
		t.Fatal("exact public root unexpectedly called auth service")
	}

	appRecorder := httptest.NewRecorder()
	handler.ServeHTTP(appRecorder, httptest.NewRequest(http.MethodGet, "https://huiguang.shiguanglab.com/app", nil))
	if appRecorder.Code != http.StatusFound {
		t.Fatalf("app status = %d", appRecorder.Code)
	}
	if authorizer.request.Path != "/app" {
		t.Fatalf("authorized path = %q", authorizer.request.Path)
	}
}

func TestHandlerUsesLongestPathPrefix(t *testing.T) {
	website := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Write([]byte("website"))
	}))
	defer website.Close()
	auth := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Write([]byte("auth"))
	}))
	defer auth.Close()

	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{
			{
				Host:           "shiguanglab.com",
				PathPrefix:     "/",
				ProductID:      "website",
				Audience:       "website",
				Upstream:       website.URL,
				PublicPrefixes: []string{"/"},
			},
			{
				Host:           "shiguanglab.com",
				PathPrefix:     "/_auth/login/",
				ProductID:      "login",
				Audience:       "auth-service",
				Upstream:       auth.URL,
				PublicPrefixes: []string{"/_auth/login/"},
			},
		},
	}, &fakeAuthorizer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "https://shiguanglab.com/_auth/login/start", nil))
	if body := recorder.Body.String(); body != "auth" {
		t.Fatalf("body = %q", body)
	}
}

func TestHandlerUsesExplicitPriorityForConstrainedRoutes(t *testing.T) {
	identityUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("X-SG-Identity"); got != "signed.assertion" {
			t.Errorf("identity assertion = %q", got)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer identityUpstream.Close()
	apiUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		t.Error("ordinary API route received an identity assertion request")
		response.WriteHeader(http.StatusInternalServerError)
	}))
	defer apiUpstream.Close()

	handler, err := NewHandler(config.Config{SessionCookieName: "__Secure-sg_session", Routes: []config.Route{
		{Host: "model-gateway.shiguanglab.com", PathPrefix: "/api/", ProductID: "model-gateway", Audience: "model-gateway-bff", Upstream: apiUpstream.URL},
		{Host: "model-gateway.shiguanglab.com", PathPrefix: "/", Priority: 100, HeaderMatches: []config.HeaderMatch{{Name: "X-SG-Identity"}}, ProductID: "model-gateway-identity", Audience: "model-gateway-bff", Upstream: identityUpstream.URL, Public: true, ForwardIdentityAssertion: true},
	}}, &fakeAuthorizer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://model-gateway.shiguanglab.com/api/chat", nil)
	request.Header.Set("X-SG-Identity", "signed.assertion")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestMethodConstrainedRouteFallsThroughToAnotherMatchingRoute(t *testing.T) {
	apiUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer apiUpstream.Close()
	handler, err := NewHandler(config.Config{SessionCookieName: "__Secure-sg_session", Routes: []config.Route{
		{Host: "model-gateway.shiguanglab.com", PathPrefix: "/api/", Priority: 200, AllowedMethods: []string{http.MethodOptions}, FallthroughOnMethodMiss: true, Public: true, Response: &config.StaticResponse{Status: http.StatusNoContent}},
		{Host: "model-gateway.shiguanglab.com", PathPrefix: "/api/", ProductID: "model-gateway", Audience: "model-gateway-bff", Upstream: apiUpstream.URL, Public: true},
	}}, &fakeAuthorizer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://model-gateway.shiguanglab.com/api/models", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("GET status = %d", response.Code)
	}
}

func TestHandlerSupportsStaticResponsesAndPathRewrites(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/public-media/images/a.png" {
			t.Errorf("rewritten path = %q", request.URL.Path)
		}
		response.Header().Set("Server", "storage")
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		ResponseHeaders:   map[string]string{"X-Content-Type-Options": "nosniff"},
		Routes: []config.Route{
			{Host: "model-gateway.shiguanglab.com", PathPrefix: "/api/", AllowedMethods: []string{http.MethodOptions}, Public: true, Response: &config.StaticResponse{Status: http.StatusNoContent, Headers: map[string]string{"Access-Control-Allow-Origin": "https://console.shiguanglab.com"}}},
			{Host: "static.shiguanglab.com", PathPrefix: "/", AllowedMethods: []string{http.MethodGet, http.MethodHead}, ProductID: "media", Audience: "media", Upstream: upstream.URL, Public: true, AddPathPrefix: "/public-media", RemoveResponseHeaders: []string{"Server"}},
		},
	}, &fakeAuthorizer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	preflight := httptest.NewRecorder()
	handler.ServeHTTP(preflight, httptest.NewRequest(http.MethodOptions, "https://model-gateway.shiguanglab.com/api/chat", nil))
	if preflight.Code != http.StatusNoContent || preflight.Header().Get("Access-Control-Allow-Origin") != "https://console.shiguanglab.com" || preflight.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("preflight status/headers = %d %#v", preflight.Code, preflight.Header())
	}
	media := httptest.NewRecorder()
	handler.ServeHTTP(media, httptest.NewRequest(http.MethodGet, "https://static.shiguanglab.com/images/a.png", nil))
	if media.Code != http.StatusNoContent || media.Header().Get("Server") != "" {
		t.Fatalf("media status/headers = %d %#v", media.Code, media.Header())
	}
	write := httptest.NewRecorder()
	handler.ServeHTTP(write, httptest.NewRequest(http.MethodPut, "https://static.shiguanglab.com/images/a.png", nil))
	if write.Code != http.StatusMethodNotAllowed {
		t.Fatalf("write status = %d", write.Code)
	}
}

func TestHandlerStripsConfiguredUpstreamPathPrefix(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.URL.Path; got != "/v1/me/points" {
			t.Errorf("upstream path = %q", got)
		}
		if got := request.URL.RawQuery; got != "limit=10" {
			t.Errorf("upstream query = %q", got)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{{
			Host:        "huiguang.shiguanglab.com",
			PathPrefix:  "/api/platform/",
			StripPrefix: "/api/platform",
			ProductID:   "platform",
			Audience:    "platform-service",
			Upstream:    upstream.URL,
		}},
	}, &fakeAuthorizer{decision: authz.DecisionResponse{Allow: true, Status: http.StatusOK}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://huiguang.shiguanglab.com/api/platform/v1/me/points?limit=10", nil)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestCompatibilityPlatformRouteStaysProtected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.URL.Path; got != "/v1/me/points" {
			t.Errorf("upstream path = %q", got)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	authorizer := &fakeAuthorizer{decision: authz.DecisionResponse{
		Allow:         true,
		Status:        http.StatusOK,
		IdentityToken: "trusted.jwt",
	}}
	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{
			{
				Host:                 "point.shiguanglab.com",
				PathPrefix:           "/api/platform/",
				StripPrefix:          "/api/platform",
				ProductID:            "points",
				Audience:             "points-service",
				Upstream:             upstream.URL,
				RequiredEntitlements: []string{"platform:access"},
			},
			{
				Host:           "point.shiguanglab.com",
				PathPrefix:     "/",
				ProductID:      "points-ui",
				Audience:       "points-ui",
				Upstream:       upstream.URL,
				PublicPrefixes: []string{"/"},
			},
		},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://point.shiguanglab.com/api/platform/v1/me/points", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	if authorizer.request.Public {
		t.Fatal("platform route unexpectedly treated as public")
	}
	if authorizer.request.ProductID != "points" || authorizer.request.Audience != "points-service" {
		t.Fatalf("authorization target = %q %q", authorizer.request.ProductID, authorizer.request.Audience)
	}
	if len(authorizer.request.RequiredEntitlements) != 1 || authorizer.request.RequiredEntitlements[0] != "platform:access" {
		t.Fatalf("required entitlements = %#v", authorizer.request.RequiredEntitlements)
	}
}

func TestDedicatedPointsRouteStaysProtected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.URL.Path; got != "/v1/me/points" {
			t.Errorf("upstream path = %q", got)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	authorizer := &fakeAuthorizer{decision: authz.DecisionResponse{
		Allow:         true,
		Status:        http.StatusOK,
		IdentityToken: "trusted.jwt",
	}}
	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{
			{
				Host:                 "point.shiguanglab.com",
				PathPrefix:           "/api/v1/me/",
				StripPrefix:          "/api",
				ProductID:            "points",
				Audience:             "points-service",
				Upstream:             upstream.URL,
				RequiredEntitlements: []string{"platform:access"},
			},
			{
				Host:           "shiguanglab.com",
				PathPrefix:     "/",
				ProductID:      "website",
				Audience:       "website",
				Upstream:       upstream.URL,
				PublicPrefixes: []string{"/"},
			},
		},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://point.shiguanglab.com/api/v1/me/points", nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	if authorizer.request.Public {
		t.Fatal("points route unexpectedly treated as public")
	}
	if authorizer.request.ProductID != "points" || authorizer.request.Audience != "points-service" {
		t.Fatalf("authorization target = %q %q", authorizer.request.ProductID, authorizer.request.Audience)
	}
	if len(authorizer.request.RequiredEntitlements) != 1 || authorizer.request.RequiredEntitlements[0] != "platform:access" {
		t.Fatalf("required entitlements = %#v", authorizer.request.RequiredEntitlements)
	}
}

func TestPointsAuthSessionUsesExactAuthRouteAndGatewayCredential(t *testing.T) {
	authUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/auth/session" {
			t.Errorf("auth path = %q", request.URL.Path)
		}
		if request.Header.Get("X-SG-Gateway-Token") != "gateway-secret" {
			t.Errorf("gateway token = %q", request.Header.Get("X-SG-Gateway-Token"))
		}
		if cookie, err := request.Cookie("__Secure-sg_session"); err != nil || cookie.Value != "session-1" {
			t.Errorf("session cookie was not forwarded: %v, %#v", err, cookie)
		}
		response.Header().Add("Set-Cookie", "__Secure-sg_session=refreshed; Path=/; Secure; HttpOnly")
		response.WriteHeader(http.StatusOK)
	}))
	defer authUpstream.Close()
	uiCalls := 0
	uiUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		uiCalls++
		response.WriteHeader(http.StatusTeapot)
	}))
	defer uiUpstream.Close()

	handler, err := NewHandler(config.Config{
		AuthServiceToken:  "gateway-secret",
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{
			{Host: "point.shiguanglab.com", PathPrefix: "/api/auth/session", ExactPath: true, ProductID: "points-auth", Audience: "auth-service", Upstream: authUpstream.URL, AllowedMethods: []string{http.MethodGet}, PublicPrefixes: []string{"/api/auth/session"}, ForwardGatewayToken: true, ForwardSessionCookie: true},
			{Host: "point.shiguanglab.com", PathPrefix: "/", ProductID: "points-ui", Audience: "points-ui", Upstream: uiUpstream.URL, PublicPrefixes: []string{"/"}},
		},
	}, &fakeAuthorizer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://point.shiguanglab.com/api/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: "__Secure-sg_session", Value: "session-1"})
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || uiCalls != 0 {
		t.Fatalf("session status = %d, UI calls = %d", response.Code, uiCalls)
	}
	if got := response.Header().Get("Set-Cookie"); !strings.Contains(got, "__Secure-sg_session=refreshed") {
		t.Fatalf("auth session Set-Cookie was filtered: %q", got)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://point.shiguanglab.com/api/auth/session", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong-method status = %d", response.Code)
	}
}

func TestPointsIAMRoleManagementUsesProtectedAuthRoute(t *testing.T) {
	authUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/auth/iam/points-role-assignments/search" {
			t.Errorf("auth path = %q", request.URL.Path)
		}
		if request.Header.Get("X-SG-Gateway-Token") != "gateway-secret" {
			t.Errorf("gateway token = %q", request.Header.Get("X-SG-Gateway-Token"))
		}
		if cookie, err := request.Cookie("__Secure-sg_session"); err != nil || cookie.Value != "session-1" {
			t.Errorf("session cookie was not forwarded: %v, %#v", err, cookie)
		}
		if authorization := request.Header.Get("Authorization"); authorization != "" {
			t.Errorf("browser authorization reached Auth Service: %q", authorization)
		}
		if origin := request.Header.Get("Origin"); origin != "https://point.shiguanglab.com" {
			t.Errorf("browser origin was not preserved: %q", origin)
		}
		response.WriteHeader(http.StatusOK)
	}))
	defer authUpstream.Close()

	authorizer := &fakeAuthorizer{decision: authz.DecisionResponse{Allow: true, Status: http.StatusOK, IdentityToken: "trusted.jwt"}}
	handler, err := NewHandler(config.Config{
		AuthServiceToken:  "gateway-secret",
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{
			{
				Host: "point.shiguanglab.com", PathPrefix: "/api/auth/iam/points-role-assignments/",
				ProductID: "points-iam", Audience: "auth-service", Upstream: authUpstream.URL,
				AllowedMethods: []string{http.MethodPost, http.MethodPut}, RequiredEntitlements: []string{"platform:access"},
				ForwardGatewayToken: true, ForwardSessionCookie: true,
			},
		},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://point.shiguanglab.com/api/auth/iam/points-role-assignments/search", strings.NewReader(`{"query":"alice","limit":10}`))
	request.AddCookie(&http.Cookie{Name: "__Secure-sg_session", Value: "session-1"})
	request.Header.Set("Authorization", "Bearer forged-browser-token")
	request.Header.Set("Origin", "https://point.shiguanglab.com")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if authorizer.request.Public {
		t.Fatal("IAM role route was treated as public")
	}
	if authorizer.request.ProductID != "points-iam" || authorizer.request.Audience != "auth-service" {
		t.Fatalf("authorization target = %q %q", authorizer.request.ProductID, authorizer.request.Audience)
	}
	if len(authorizer.request.RequiredEntitlements) != 1 || authorizer.request.RequiredEntitlements[0] != "platform:access" {
		t.Fatalf("required entitlements = %#v", authorizer.request.RequiredEntitlements)
	}
}

func TestPointsBrowserRoutesCannotReachMachineAPI(t *testing.T) {
	pointsCalls := 0
	pointsUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		pointsCalls++
		response.WriteHeader(http.StatusNoContent)
	}))
	defer pointsUpstream.Close()
	uiUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNotFound)
	}))
	defer uiUpstream.Close()

	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes: []config.Route{
			{Host: "point.shiguanglab.com", PathPrefix: "/api/v1/me/", StripPrefix: "/api", ProductID: "points", Audience: "points-service", Upstream: pointsUpstream.URL},
			{Host: "point.shiguanglab.com", PathPrefix: "/api/v1/admin/points/", StripPrefix: "/api", ProductID: "points", Audience: "points-service", Upstream: pointsUpstream.URL},
			{Host: "point.shiguanglab.com", PathPrefix: "/", ProductID: "points-ui", Audience: "points-ui", Upstream: uiUpstream.URL, PublicPrefixes: []string{"/"}},
		},
	}, &fakeAuthorizer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/api/v1/integration/token", "/api/v1/points/reservations"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://point.shiguanglab.com"+path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, response.Code)
		}
	}
	if pointsCalls != 0 {
		t.Fatalf("machine requests reached points upstream %d times", pointsCalls)
	}
}

func TestTrustedProxyMetadataReachesAuthAndUpstream(t *testing.T) {
	_, loopback, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != "point.shiguanglab.com" {
			t.Errorf("host = %q", request.Host)
		}
		if got := request.Header.Get("X-Forwarded-For"); got != "203.0.113.24" {
			t.Errorf("forwarded for = %q", got)
		}
		if got := request.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Errorf("forwarded proto = %q", got)
		}
		if got := request.Header.Get("X-Forwarded-Port"); got != "443" {
			t.Errorf("forwarded port = %q", got)
		}
		if got := request.Header.Get("X-Forwarded-Host"); got != "point.shiguanglab.com" {
			t.Errorf("forwarded host = %q", got)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	authorizer := &fakeAuthorizer{decision: authz.DecisionResponse{Allow: true, Status: http.StatusOK}}
	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		TrustedProxyCIDRs: []*net.IPNet{loopback},
		Routes: []config.Route{{
			Host: "point.shiguanglab.com", PathPrefix: "/", ProductID: "points-ui", Audience: "points-ui", Upstream: upstream.URL,
		}},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://point.shiguanglab.com/app", nil)
	request.RemoteAddr = "127.0.0.1:51000"
	request.Header.Set("X-Forwarded-For", "203.0.113.24")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Port", "443")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	if authorizer.request.ClientIP != "203.0.113.24" || authorizer.request.Scheme != "https" {
		t.Fatalf("auth metadata = %#v", authorizer.request)
	}
}

func TestUntrustedProxyHeadersAreIgnored(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("X-Forwarded-For"); got != "192.0.2.45" {
			t.Errorf("forwarded for = %q", got)
		}
		if got := request.Header.Get("X-Forwarded-Proto"); got != "http" {
			t.Errorf("forwarded proto = %q", got)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	authorizer := &fakeAuthorizer{decision: authz.DecisionResponse{Allow: true, Status: http.StatusOK}}
	handler, err := NewHandler(config.Config{
		SessionCookieName: "__Secure-sg_session",
		Routes:            []config.Route{{Host: "point.shiguanglab.com", PathPrefix: "/", ProductID: "points-ui", Audience: "points-ui", Upstream: upstream.URL}},
	}, authorizer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://point.shiguanglab.com/app", nil)
	request.RemoteAddr = "192.0.2.45:51000"
	request.Header.Set("X-Forwarded-For", "203.0.113.24")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	if authorizer.request.ClientIP != "192.0.2.45" || authorizer.request.Scheme != "http" {
		t.Fatalf("auth metadata = %#v", authorizer.request)
	}
}
