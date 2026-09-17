package gateway

import (
	"context"
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
	"strconv"
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
	responseHeaders             map[string]string
	routes                      map[string][]*route
	trustedProxyCIDRs           []*net.IPNet
	logger                      *slog.Logger
}

type requestMetadata struct {
	clientIP string
	host     string
	port     string
	scheme   string
}

type requestMetadataKey struct{}

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
		responseHeaders:             cfg.ResponseHeaders,
		routes:                      make(map[string][]*route, len(cfg.Routes)),
		trustedProxyCIDRs:           cfg.TrustedProxyCIDRs,
		logger:                      logger,
	}
	for _, routeConfig := range cfg.Routes {
		if routeConfig.SignIdentityHeaders && len(handler.identityHeaderSigningSecret) < 32 {
			return nil, errors.New("identity header signing secret must be at least 32 characters")
		}
		if routeConfig.PathPrefix == "" {
			routeConfig.PathPrefix = "/"
		}
		if routeConfig.Response != nil {
			handler.routes[routeConfig.Host] = append(handler.routes[routeConfig.Host], &route{config: routeConfig})
			continue
		}
		target, err := url.Parse(routeConfig.Upstream)
		if err != nil {
			return nil, err
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(request *httputil.ProxyRequest) {
				metadata, _ := request.In.Context().Value(requestMetadataKey{}).(requestMetadata)
				if routeConfig.StripPrefix != "" {
					request.Out.URL.Path = strings.TrimPrefix(request.Out.URL.Path, routeConfig.StripPrefix)
					if request.Out.URL.Path == "" {
						request.Out.URL.Path = "/"
					}
					request.Out.URL.RawPath = ""
				}
				request.SetURL(target)
				if routeConfig.RewritePath != "" {
					request.Out.URL.Path = routeConfig.RewritePath
					request.Out.URL.RawPath = ""
				} else if routeConfig.AddPathPrefix != "" {
					request.Out.URL.Path = routeConfig.AddPathPrefix + ensureLeadingSlash(request.Out.URL.Path)
					request.Out.URL.RawPath = ""
				}
				request.Out.Host = metadata.host
				request.Out.Header.Set("X-Forwarded-For", metadata.clientIP)
				request.Out.Header.Set("X-Forwarded-Host", metadata.host)
				request.Out.Header.Set("X-Forwarded-Proto", metadata.scheme)
				request.Out.Header.Set("X-Forwarded-Port", metadata.port)
				request.Out.Header.Set("X-Real-IP", metadata.clientIP)
			},
			ModifyResponse: func(response *http.Response) error {
				if !routeConfig.ForwardSessionCookie {
					filterResponseCookies(response.Header, cfg.SessionCookieName)
				}
				applyResponseHeaders(response.Header, cfg.ResponseHeaders, routeConfig.ResponseHeaders, routeConfig.RemoveResponseHeaders)
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
		sort.SliceStable(handler.routes[host], func(i, j int) bool {
			left := handler.routes[host][i].config
			right := handler.routes[host][j].config
			if left.Priority != right.Priority {
				return left.Priority > right.Priority
			}
			if len(left.PathPrefix) != len(right.PathPrefix) {
				return len(left.PathPrefix) > len(right.PathPrefix)
			}
			return len(left.HeaderMatches) > len(right.HeaderMatches)
		})
	}
	return handler, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	applyResponseHeaders(response.Header(), h.responseHeaders, nil, nil)
	if request.URL.Path == "/health/live" || request.URL.Path == "/health/ready" {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		response.Write([]byte(`{"status":"ok"}`))
		return
	}

	metadata := h.metadataFor(request)
	request = request.WithContext(context.WithValue(request.Context(), requestMetadataKey{}, metadata))
	host := metadata.host
	matched, ok, methodMismatch := h.matchRoute(host, request)
	if !ok {
		if methodMismatch {
			http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		http.Error(response, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
		return
	}

	requestID := request.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = newRequestID()
	}
	public := matched.config.Public || isPublicPath(request.URL.Path, matched.config.PublicPaths, matched.config.PublicPrefixes)
	decision := authz.DecisionResponse{Allow: true, Status: http.StatusOK}
	if !public {
		var err error
		decision, err = h.authorizer.Authorize(request.Context(), authz.DecisionRequest{
			RequestID:            requestID,
			Method:               request.Method,
			Scheme:               metadata.scheme,
			Host:                 host,
			Path:                 request.URL.RequestURI(),
			ClientIP:             metadata.clientIP,
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

	inboundIdentity := request.Header.Get("X-SG-Identity")
	sanitizeRequest(request.Header, h.sessionCookieName, matched.config.ForwardAuthorization, matched.config.ForwardSessionCookie)
	if matched.config.ForwardIdentityAssertion && inboundIdentity != "" {
		request.Header.Set("X-SG-Identity", inboundIdentity)
	}
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
	for _, name := range matched.config.RemoveRequestHeaders {
		request.Header.Del(name)
	}
	for name, value := range matched.config.RequestHeaders {
		request.Header.Set(name, value)
	}
	if matched.config.Response != nil {
		applyResponseHeaders(response.Header(), matched.config.Response.Headers, matched.config.ResponseHeaders, matched.config.RemoveResponseHeaders)
		response.WriteHeader(matched.config.Response.Status)
		_, _ = response.Write([]byte(matched.config.Response.Body))
		return
	}
	matched.proxy.ServeHTTP(response, request)
}

func signIdentityHeader(timestamp, identity string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp + "." + identity))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *Handler) matchRoute(host string, request *http.Request) (*route, bool, bool) {
	for _, candidate := range h.routes[host] {
		path := request.URL.Path
		pathMatches := candidate.config.ExactPath && path == candidate.config.PathPrefix ||
			!candidate.config.ExactPath && pathPrefixMatch(path, candidate.config.PathPrefix)
		if !pathMatches || !headersMatch(request.Header, candidate.config.HeaderMatches) {
			continue
		}
		if !methodAllowed(request.Method, candidate.config.AllowedMethods) {
			if candidate.config.FallthroughOnMethodMiss {
				continue
			}
			return nil, false, true
		}
		return candidate, true, false
	}
	return nil, false, false
}

func headersMatch(header http.Header, matches []config.HeaderMatch) bool {
	for _, match := range matches {
		value := header.Get(match.Name)
		if value == "" || match.Value != "" && value != match.Value || match.ValuePrefix != "" && !strings.HasPrefix(value, match.ValuePrefix) {
			return false
		}
	}
	return true
}

func applyResponseHeaders(header http.Header, first, second map[string]string, remove []string) {
	for name, value := range first {
		header.Set(name, value)
	}
	for name, value := range second {
		header.Set(name, value)
	}
	for _, name := range remove {
		header.Del(name)
	}
}

func ensureLeadingSlash(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
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

func (h *Handler) metadataFor(request *http.Request) requestMetadata {
	directIP := clientIP(request.RemoteAddr)
	metadata := requestMetadata{
		clientIP: directIP,
		host:     normalizedHost(request.Host),
		port:     "80",
		scheme:   "http",
	}
	if request.TLS != nil {
		metadata.port = "443"
		metadata.scheme = "https"
	}
	if !h.isTrustedProxy(directIP) {
		return metadata
	}

	if scheme := firstHeaderValue(request.Header.Get("X-Forwarded-Proto")); scheme == "http" || scheme == "https" {
		metadata.scheme = scheme
		metadata.port = map[string]string{"http": "80", "https": "443"}[scheme]
	}
	if port := firstHeaderValue(request.Header.Get("X-Forwarded-Port")); validPort(port) {
		metadata.port = port
	}
	if forwardedIP := firstForwardedIP(request.Header.Get("X-Forwarded-For")); forwardedIP != "" {
		metadata.clientIP = forwardedIP
	} else if realIP := net.ParseIP(strings.TrimSpace(request.Header.Get("X-Real-IP"))); realIP != nil {
		metadata.clientIP = realIP.String()
	}
	return metadata
}

func (h *Handler) isTrustedProxy(address string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	for _, network := range h.trustedProxyCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func firstHeaderValue(value string) string {
	first, _, _ := strings.Cut(value, ",")
	return strings.ToLower(strings.TrimSpace(first))
}

func firstForwardedIP(value string) string {
	first, _, _ := strings.Cut(value, ",")
	if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
		return ip.String()
	}
	return ""
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535
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
