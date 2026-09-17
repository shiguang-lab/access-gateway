package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	Addr                        string
	AuthServiceURL              string
	AuthServiceToken            string
	IdentityHeaderSigningSecret string
	SessionCookieName           string
	AuthTimeout                 time.Duration
	TrustedProxyCIDRs           []*net.IPNet
	ResponseHeaders             map[string]string
	Routes                      []Route
}

type HeaderMatch struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	ValuePrefix string `json:"value_prefix,omitempty"`
}

type StaticResponse struct {
	Status  int               `json:"status"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type Route struct {
	Host                     string            `json:"host"`
	Priority                 int               `json:"priority,omitempty"`
	PathPrefix               string            `json:"path_prefix"`
	ExactPath                bool              `json:"exact_path,omitempty"`
	StripPrefix              string            `json:"strip_prefix,omitempty"`
	AddPathPrefix            string            `json:"add_path_prefix,omitempty"`
	RewritePath              string            `json:"rewrite_path,omitempty"`
	ProductID                string            `json:"product_id"`
	Audience                 string            `json:"audience"`
	Upstream                 string            `json:"upstream"`
	AllowedMethods           []string          `json:"allowed_methods,omitempty"`
	FallthroughOnMethodMiss  bool              `json:"fallthrough_on_method_mismatch,omitempty"`
	HeaderMatches            []HeaderMatch     `json:"header_matches,omitempty"`
	Public                   bool              `json:"public,omitempty"`
	PublicPaths              []string          `json:"public_paths,omitempty"`
	PublicPrefixes           []string          `json:"public_prefixes"`
	RequiredEntitlements     []string          `json:"required_entitlements"`
	ForwardAuthorization     bool              `json:"forward_authorization"`
	ForwardGatewayToken      bool              `json:"forward_gateway_token,omitempty"`
	ForwardSessionCookie     bool              `json:"forward_session_cookie,omitempty"`
	ForwardIdentityAssertion bool              `json:"forward_identity_assertion,omitempty"`
	SignIdentityHeaders      bool              `json:"sign_identity_headers,omitempty"`
	RequestHeaders           map[string]string `json:"request_headers,omitempty"`
	RemoveRequestHeaders     []string          `json:"remove_request_headers,omitempty"`
	ResponseHeaders          map[string]string `json:"response_headers,omitempty"`
	RemoveResponseHeaders    []string          `json:"remove_response_headers,omitempty"`
	Response                 *StaticResponse   `json:"response,omitempty"`
}

type routeFile struct {
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	Routes          []Route           `json:"routes"`
}

func Load() (Config, error) {
	authServiceToken, err := readSecret("AUTH_SERVICE_TOKEN", "AUTH_SERVICE_TOKEN_FILE")
	if err != nil {
		return Config{}, err
	}
	identityHeaderSigningSecret, err := readSecret("IDENTITY_HEADER_SIGNING_SECRET", "IDENTITY_HEADER_SIGNING_SECRET_FILE")
	if err != nil {
		return Config{}, err
	}
	trustedProxyCIDRs, err := parseCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Addr:                        envOr("GATEWAY_ADDR", ":8080"),
		AuthServiceURL:              strings.TrimSpace(os.Getenv("AUTH_SERVICE_URL")),
		AuthServiceToken:            authServiceToken,
		IdentityHeaderSigningSecret: identityHeaderSigningSecret,
		SessionCookieName:           envOr("SESSION_COOKIE_NAME", "__Secure-sg_session"),
		AuthTimeout:                 3 * time.Second,
		TrustedProxyCIDRs:           trustedProxyCIDRs,
	}

	routesPath := strings.TrimSpace(os.Getenv("ROUTES_FILE"))
	if routesPath == "" {
		return Config{}, errors.New("ROUTES_FILE is required")
	}
	body, err := os.ReadFile(routesPath)
	if err != nil {
		return Config{}, fmt.Errorf("read routes file: %w", err)
	}
	var file routeFile
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return Config{}, fmt.Errorf("decode routes file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values are not allowed")
		}
		return Config{}, fmt.Errorf("decode routes file: %w", err)
	}
	cfg.ResponseHeaders = file.ResponseHeaders
	cfg.Routes = file.Routes
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.AuthServiceURL == "" {
		return errors.New("AUTH_SERVICE_URL is required")
	}
	if _, err := url.ParseRequestURI(c.AuthServiceURL); err != nil {
		return fmt.Errorf("invalid AUTH_SERVICE_URL: %w", err)
	}
	if c.AuthServiceToken == "" {
		return errors.New("AUTH_SERVICE_TOKEN is required")
	}
	if c.SessionCookieName == "" {
		return errors.New("SESSION_COOKIE_NAME is required")
	}
	if len(c.Routes) == 0 {
		return errors.New("at least one route is required")
	}

	seen := make(map[string]struct{}, len(c.Routes))
	requiresIdentityHeaderSigning := false
	for i := range c.Routes {
		route := &c.Routes[i]
		route.Host = strings.ToLower(strings.TrimSpace(route.Host))
		route.PathPrefix = strings.TrimSpace(route.PathPrefix)
		if route.PathPrefix == "" {
			route.PathPrefix = "/"
		}
		for methodIndex, method := range route.AllowedMethods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if method == "" {
				return fmt.Errorf("route %d: allowed_methods must not contain an empty method", i)
			}
			route.AllowedMethods[methodIndex] = method
		}
		if route.ForwardGatewayToken && route.Audience != "auth-service" {
			return fmt.Errorf("route %d: forward_gateway_token is restricted to auth-service routes", i)
		}
		route.StripPrefix = strings.TrimSuffix(strings.TrimSpace(route.StripPrefix), "/")
		route.AddPathPrefix = strings.TrimSuffix(strings.TrimSpace(route.AddPathPrefix), "/")
		route.RewritePath = strings.TrimSpace(route.RewritePath)
		route.ProductID = strings.TrimSpace(route.ProductID)
		route.Audience = strings.TrimSpace(route.Audience)
		route.Upstream = strings.TrimSpace(route.Upstream)
		if route.Host == "" || strings.Contains(route.Host, "*") {
			return fmt.Errorf("route %d: host must be an exact hostname", i)
		}
		if !strings.HasPrefix(route.PathPrefix, "/") {
			return fmt.Errorf("route %d: path_prefix must start with /", i)
		}
		if route.StripPrefix != "" {
			if !strings.HasPrefix(route.StripPrefix, "/") || route.StripPrefix == "/" {
				return fmt.Errorf("route %d: strip_prefix must be an absolute non-root path", i)
			}
			if !pathPrefixMatch(route.PathPrefix, route.StripPrefix) {
				return fmt.Errorf("route %d: strip_prefix must be a parent of path_prefix", i)
			}
		}
		if route.AddPathPrefix != "" && !strings.HasPrefix(route.AddPathPrefix, "/") {
			return fmt.Errorf("route %d: add_path_prefix must start with /", i)
		}
		if route.RewritePath != "" && !strings.HasPrefix(route.RewritePath, "/") {
			return fmt.Errorf("route %d: rewrite_path must start with /", i)
		}
		if route.RewritePath != "" && (route.StripPrefix != "" || route.AddPathPrefix != "") {
			return fmt.Errorf("route %d: rewrite_path cannot be combined with strip_prefix or add_path_prefix", i)
		}
		for matchIndex := range route.HeaderMatches {
			match := &route.HeaderMatches[matchIndex]
			match.Name = strings.TrimSpace(match.Name)
			if match.Name == "" || match.Value != "" && match.ValuePrefix != "" {
				return fmt.Errorf("route %d: header match requires a name and at most one value matcher", i)
			}
		}
		key := routeSignature(*route)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("route %d: duplicate route matcher for %q %q", i, route.Host, route.PathPrefix)
		}
		seen[key] = struct{}{}
		if route.Response == nil && (route.ProductID == "" || route.Audience == "" || route.Upstream == "") {
			return fmt.Errorf("route %d: product_id, audience, and upstream are required for proxy routes", i)
		}
		for _, publicPath := range route.PublicPaths {
			if !strings.HasPrefix(publicPath, "/") {
				return fmt.Errorf("route %d: public_paths entries must start with /", i)
			}
		}
		if route.Response != nil {
			if route.Response.Status < 200 || route.Response.Status > 599 {
				return fmt.Errorf("route %d: response status must be between 200 and 599", i)
			}
			if route.Upstream != "" {
				return fmt.Errorf("route %d: static response must not define an upstream", i)
			}
		} else {
			target, err := url.Parse(route.Upstream)
			if err != nil || target.Scheme == "" || target.Host == "" {
				return fmt.Errorf("route %d: invalid upstream %q", i, route.Upstream)
			}
		}
		if route.ForwardIdentityAssertion && !route.Public {
			return fmt.Errorf("route %d: forwarded identity assertions require a self-authorizing public route", i)
		}
		requiresIdentityHeaderSigning = requiresIdentityHeaderSigning || route.SignIdentityHeaders
	}
	if requiresIdentityHeaderSigning && len(c.IdentityHeaderSigningSecret) < 32 {
		return errors.New("IDENTITY_HEADER_SIGNING_SECRET must be at least 32 characters when signed identity headers are enabled")
	}
	return nil
}

func routeSignature(route Route) string {
	parts := []string{route.Host, route.PathPrefix, fmt.Sprint(route.ExactPath), strings.Join(route.AllowedMethods, ",")}
	for _, match := range route.HeaderMatches {
		parts = append(parts, strings.ToLower(strings.TrimSpace(match.Name)), match.Value, match.ValuePrefix)
	}
	return strings.Join(parts, "\x00")
}

func readSecret(valueName, fileName string) (string, error) {
	value := strings.TrimSpace(os.Getenv(valueName))
	path := strings.TrimSpace(os.Getenv(fileName))
	if value != "" && path != "" {
		return "", fmt.Errorf("%s and %s must not both be set", valueName, fileName)
	}
	if path != "" {
		body, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fileName, err)
		}
		return strings.TrimSpace(string(body)), nil
	}
	return value, nil
}

func parseCIDRs(raw string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, candidate := range strings.Split(raw, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		_, network, err := net.ParseCIDR(candidate)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXY_CIDRS entry %q: %w", candidate, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func pathPrefixMatch(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
