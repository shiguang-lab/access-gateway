package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	Addr              string
	AuthServiceURL    string
	AuthServiceToken  string
	SessionCookieName string
	AuthTimeout       time.Duration
	Routes            []Route
}

type Route struct {
	Host                 string   `json:"host"`
	PathPrefix           string   `json:"path_prefix"`
	StripPrefix          string   `json:"strip_prefix,omitempty"`
	ProductID            string   `json:"product_id"`
	Audience             string   `json:"audience"`
	Upstream             string   `json:"upstream"`
	PublicPaths          []string `json:"public_paths,omitempty"`
	PublicPrefixes       []string `json:"public_prefixes"`
	RequiredEntitlements []string `json:"required_entitlements"`
	ForwardAuthorization bool     `json:"forward_authorization"`
}

type routeFile struct {
	Routes []Route `json:"routes"`
}

func Load() (Config, error) {
	cfg := Config{
		Addr:              envOr("GATEWAY_ADDR", ":8080"),
		AuthServiceURL:    strings.TrimSpace(os.Getenv("AUTH_SERVICE_URL")),
		AuthServiceToken:  strings.TrimSpace(os.Getenv("AUTH_SERVICE_TOKEN")),
		SessionCookieName: envOr("SESSION_COOKIE_NAME", "__Secure-sg_session"),
		AuthTimeout:       3 * time.Second,
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
	if err := json.Unmarshal(body, &file); err != nil {
		return Config{}, fmt.Errorf("decode routes file: %w", err)
	}
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
	for i := range c.Routes {
		route := &c.Routes[i]
		route.Host = strings.ToLower(strings.TrimSpace(route.Host))
		route.PathPrefix = strings.TrimSpace(route.PathPrefix)
		if route.PathPrefix == "" {
			route.PathPrefix = "/"
		}
		route.StripPrefix = strings.TrimSuffix(strings.TrimSpace(route.StripPrefix), "/")
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
		key := route.Host + "\x00" + route.PathPrefix
		if _, ok := seen[key]; ok {
			return fmt.Errorf("route %d: duplicate host and path_prefix %q %q", i, route.Host, route.PathPrefix)
		}
		seen[key] = struct{}{}
		if route.ProductID == "" || route.Audience == "" {
			return fmt.Errorf("route %d: product_id and audience are required", i)
		}
		for _, publicPath := range route.PublicPaths {
			if !strings.HasPrefix(publicPath, "/") {
				return fmt.Errorf("route %d: public_paths entries must start with /", i)
			}
		}
		target, err := url.Parse(route.Upstream)
		if err != nil || target.Scheme == "" || target.Host == "" {
			return fmt.Errorf("route %d: invalid upstream %q", i, route.Upstream)
		}
	}
	return nil
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
