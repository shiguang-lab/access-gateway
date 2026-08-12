package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testGatewayToken = "0123456789abcdef0123456789abcdef"

func TestClientAuthorizeDecisionContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/authorize" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get(gatewayTokenHeader); got != testGatewayToken {
			t.Errorf("gateway token = %q", got)
		}
		if got := request.Header.Get("Authorization"); got != "" {
			t.Errorf("unexpected Authorization header = %q", got)
		}
		var input DecisionRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Errorf("decode request: %v", err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}

		decision := DecisionResponse{}
		switch input.Path {
		case "/allow":
			decision = DecisionResponse{
				Allow: true, Status: http.StatusOK, IdentityToken: "signed.identity.jwt",
				SetCookies: []string{"__Secure-sg_session=refreshed; Path=/; Secure; HttpOnly"},
			}
		case "/unauthorized":
			decision = DecisionResponse{Allow: false, Status: http.StatusUnauthorized, Reason: "session_missing"}
		case "/forbidden":
			decision = DecisionResponse{Allow: false, Status: http.StatusForbidden, Reason: "missing_entitlement"}
		case "/redirect":
			decision = DecisionResponse{Allow: false, Status: http.StatusFound, Reason: "session_missing", Location: "https://shiguanglab.com/login?return_to=%2Fredirect"}
		default:
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(decision); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, testGatewayToken, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path           string
		wantStatus     int
		wantReason     string
		wantLocation   bool
		wantIdentity   bool
		wantSetCookies bool
	}{
		{path: "/allow", wantStatus: http.StatusOK, wantIdentity: true, wantSetCookies: true},
		{path: "/unauthorized", wantStatus: http.StatusUnauthorized, wantReason: "session_missing"},
		{path: "/forbidden", wantStatus: http.StatusForbidden, wantReason: "missing_entitlement"},
		{path: "/redirect", wantStatus: http.StatusFound, wantReason: "session_missing", wantLocation: true},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			decision, err := client.Authorize(context.Background(), DecisionRequest{Path: test.path})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Status != test.wantStatus || decision.Reason != test.wantReason {
				t.Fatalf("decision = %#v", decision)
			}
			if (decision.Location != "") != test.wantLocation {
				t.Fatalf("location = %q", decision.Location)
			}
			if (decision.IdentityToken != "") != test.wantIdentity {
				t.Fatalf("identity token presence = %t", decision.IdentityToken != "")
			}
			if (len(decision.SetCookies) > 0) != test.wantSetCookies {
				t.Fatalf("set cookies = %#v", decision.SetCookies)
			}
		})
	}
}

func TestClientAuthorizeFailsClosedOnTransportErrors(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"unauthorized token": func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusUnauthorized)
		},
		"service unavailable": func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusServiceUnavailable)
		},
		"invalid json": func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			response.Write([]byte(`{"allow":`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			client, err := NewClient(server.URL, testGatewayToken, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Authorize(context.Background(), DecisionRequest{Path: "/protected"}); err == nil {
				t.Fatal("expected authorization transport failure")
			}
		})
	}
}
