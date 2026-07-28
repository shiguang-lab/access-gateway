package gateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shiguanglab/access-gateway/internal/authz"
	"github.com/shiguanglab/access-gateway/internal/config"
)

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
