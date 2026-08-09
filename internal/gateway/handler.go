package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/shiguanglab/access-gateway/internal/authz"
	"github.com/shiguanglab/access-gateway/internal/config"
)

type Handler struct {
	authorizer                  authz.Authorizer
	authServiceToken            string
	identityHeaderSigningSecret []byte
	now                         func() time.Time
	sessionCookieName           string
	routes                      map[string][]*route
	logger                      *slog.Logger
}

type route struct {
	config config.Route
	proxy  *httputil.ReverseProxy
}

func NewHandler(cfg config.Config, authorizer authz.Authorizer, logger *slog.Logger) (*Handler, error) {
	if authorizer == nil {
		return nil, errors.New("authorizer is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	handler := &Handler{
		authorizer:                  authorizer,
		authServiceToken:            cfg.AuthServiceToken,
		identityHeaderSigningSecret: []byte(cfg.IdentityHeaderSigningSecret),
		now:                         time.Now,
		sessionCookieName:           cfg.SessionCookieName,
		routes:                      make(map[string][]*route, len(cfg.Routes)),
		logger:                      logger,
	}
	for _, routeConfig := range cfg.Routes {
		if routeConfig.SignIdentityHeaders && len(handler.identityHeaderSigningSecret) < 32 {
			return nil, errors.New("identity header signing secret must be at least 32 characters")
		}
		if routeConfig.PathPrefix == "" {
			routeConfig.PathPrefix = "/"
		}
		target, err := url.Parse(routeConfig.Upstream)
		if err != nil {
			return nil, err
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(request *httputil.ProxyRequest) {
				if routeConfig.StripPrefix != "" {
					request.Out.URL.Path = strings.TrimPrefix(request.Out.URL.Path, routeConfig.StripPrefix)
					if request.Out.URL.Path == "" {
						request.Out.URL.Path = "/"
					}
					request.Out.URL.RawPath = ""
				}
				request.SetURL(target)
				request.Out.Host = target.Host
				request.SetXForwarded()
			},
			ModifyResponse: func(response *http.Response) error {
				if !routeConfig.ForwardSessionCookie {
					filterResponseCookies(response.Header, cfg.SessionCookieName)
				}
				return nil
			},
			ErrorHandler: func(response http.ResponseWriter, request *http.Request, err error) {
				logger.Error("upstream request failed", "request_id", request.Header.Get("X-SG-Request-ID"), "error", err)
				http.Error(response, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			},
		}
		handler.routes[routeConfig.Host] = append(
			handler.routes[routeConfig.Host],
			&route{config: routeConfig, proxy: proxy},
		)
	}
	for host := range handler.routes {
		sort.Slice(handler.routes[host], func(i, j int) bool {
			return len(handler.routes[host][i].config.PathPrefix) > len(handler.routes[host][j].config.PathPrefix)
		})
	}
	return handler, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/health/live" || request.URL.Path == "/health/ready" {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		response.Write([]byte(`{"status":"ok"}`))
		return
	}

	host := normalizedHost(request.Host)
	matched, ok := h.matchRoute(host, request.URL.Path)
	if !ok {
		http.Error(response, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
		return
	}
	if !methodAllowed(request.Method, matched.config.AllowedMethods) {
		response.Header().Set("Allow", strings.Join(matched.config.AllowedMethods, ", "))
		http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	requestID := request.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = newRequestID()
	}
	public := isPublicPath(request.URL.Path, matched.config.PublicPaths, matched.config.PublicPrefixes)
	decision := authz.DecisionResponse{Allow: true, Status: http.StatusOK}
	if !public {
		var err error
		decision, err = h.authorizer.Authorize(request.Context(), authz.DecisionRequest{
			RequestID:            requestID,
			Method:               request.Method,
			Scheme:               requestScheme(request),
			Host:                 host,
			Path:                 request.URL.RequestURI(),
			ClientIP:             clientIP(request.RemoteAddr),
			Cookie:               request.Header.Get("Cookie"),
			Authorization:        request.Header.Get("Authorization"),
			Origin:               request.Header.Get("Origin"),
			Accept:               request.Header.Get("Accept"),
			ProductID:            matched.config.ProductID,
			Audience:             matched.config.Audience,
			Public:               false,
			RequiredEntitlements: matched.config.RequiredEntitlements,
		})
		if err != nil {
			h.logger.Error("authorization service unavailable", "request_id", requestID, "error", err)
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	}
	for _, cookie := range decision.SetCookies {
		response.Header().Add("Set-Cookie", cookie)
	}
	if !decision.Allow {
		if decision.Location != "" {
			response.Header().Set("Location", decision.Location)
		}
		status := decision.Status
		if status < 300 || status > 599 {
			status = http.StatusForbidden
		}
		http.Error(response, http.StatusText(status), status)
		return
	}

	sanitizeRequest(request.Header, h.sessionCookieName, matched.config.ForwardAuthorization, matched.config.ForwardSessionCookie)
	if matched.config.ForwardGatewayToken {
		request.Header.Set("X-SG-Gateway-Token", h.authServiceToken)
	}
	request.Header.Set("X-SG-Request-ID", requestID)
	if decision.IdentityToken != "" {
		request.Header.Set("X-SG-Identity", decision.IdentityToken)
		if matched.config.SignIdentityHeaders {
			timestamp := h.now().UTC().Format(time.RFC3339Nano)
			request.Header.Set("X-SG-Identity-Timestamp", timestamp)
			request.Header.Set("X-SG-Identity-Signature", signIdentityHeader(timestamp, decision.IdentityToken, h.identityHeaderSigningSecret))
		}
	}
	matched.proxy.ServeHTTP(response, request)
}

func signIdentityHeader(timestamp, identity string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp + "." + identity))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *Handler) matchRoute(host, path string) (*route, bool) {
	for _, candidate := range h.routes[host] {
		if candidate.config.ExactPath && path == candidate.config.PathPrefix ||
			!candidate.config.ExactPath && pathPrefixMatch(path, candidate.config.PathPrefix) {
			return candidate, true
		}
	}
	return nil, false
}

func methodAllowed(method string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if method == candidate || method == http.MethodHead && candidate == http.MethodGet {
			return true
		}
	}
	return false
}

func sanitizeRequest(header http.Header, sessionCookieName string, forwardAuthorization, forwardSessionCookie bool) {
	for name := range header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-sg-") || strings.HasPrefix(lower, "x-user-") {
			header.Del(name)
		}
	}
	header.Del("Forwarded")
	header.Del("X-Forwarded-For")
	header.Del("X-Forwarded-Host")
	header.Del("X-Forwarded-Proto")
	if !forwardAuthorization {
		header.Del("Authorization")
	}
	if !forwardSessionCookie {
		filterRequestCookie(header, sessionCookieName)
	}
}

func filterRequestCookie(header http.Header, blockedName string) {
	raw := header.Get("Cookie")
	if raw == "" {
		return
	}
	parts := strings.Split(raw, ";")
	kept := parts[:0]
	for _, part := range parts {
		name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && name != blockedName {
			kept = append(kept, strings.TrimSpace(part))
		}
	}
	if len(kept) == 0 {
		header.Del("Cookie")
		return
	}
	header.Set("Cookie", strings.Join(kept, "; "))
}

func filterResponseCookies(header http.Header, blockedName string) {
	values := header.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, value := range values {
		name, _, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(name) == blockedName {
			continue
		}
		header.Add("Set-Cookie", value)
	}
}

func normalizedHost(hostport string) string {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func requestScheme(request *http.Request) string {
	if request.TLS != nil {
		return "https"
	}
	return "http"
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func isPublicPath(path string, exactPaths, prefixes []string) bool {
	for _, publicPath := range exactPaths {
		if path == publicPath {
			return true
		}
	}
	for _, prefix := range prefixes {
		if strings.HasSuffix(prefix, "/") {
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if path == prefix {
			return true
		}
	}
	return false
}

func pathPrefixMatch(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "request-id-unavailable"
	}
	return hex.EncodeToString(value[:])
}
