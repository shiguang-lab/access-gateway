package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DecisionRequest struct {
	RequestID            string   `json:"request_id"`
	Method               string   `json:"method"`
	Scheme               string   `json:"scheme"`
	Host                 string   `json:"host"`
	Path                 string   `json:"path"`
	ClientIP             string   `json:"client_ip,omitempty"`
	Cookie               string   `json:"cookie,omitempty"`
	Authorization        string   `json:"authorization,omitempty"`
	Origin               string   `json:"origin,omitempty"`
	Accept               string   `json:"accept,omitempty"`
	ProductID            string   `json:"product_id"`
	Audience             string   `json:"audience"`
	Public               bool     `json:"public"`
	RequiredEntitlements []string `json:"required_entitlements,omitempty"`
}

type DecisionResponse struct {
	Allow         bool     `json:"allow"`
	Status        int      `json:"status"`
	Reason        string   `json:"reason,omitempty"`
	IdentityToken string   `json:"identity_token,omitempty"`
	Location      string   `json:"location,omitempty"`
	SetCookies    []string `json:"set_cookies,omitempty"`
}

type Authorizer interface {
	Authorize(context.Context, DecisionRequest) (DecisionResponse, error)
}

type Client struct {
	endpoint   string
	token      string
	httpClient *http.Client
}

func NewClient(baseURL, token string, timeout time.Duration) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("invalid auth service URL")
	}
	if token == "" {
		return nil, errors.New("auth service token is required")
	}
	return &Client{
		endpoint: parsed.String() + "/v1/authorize",
		token:    token,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (c *Client) Authorize(ctx context.Context, input DecisionRequest) (DecisionResponse, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return DecisionResponse{}, fmt.Errorf("encode authorization request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return DecisionResponse{}, fmt.Errorf("create authorization request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return DecisionResponse{}, fmt.Errorf("call auth service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return DecisionResponse{}, fmt.Errorf("auth service returned %s", resp.Status)
	}
	var decision DecisionResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err := decoder.Decode(&decision); err != nil {
		return DecisionResponse{}, fmt.Errorf("decode authorization response: %w", err)
	}
	return decision, nil
}
