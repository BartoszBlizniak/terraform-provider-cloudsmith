package cloudsmith

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cloudsmith-io/cloudsmith-api-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	defaultOIDCAudience = "cloudsmith"
	tokenRefreshSkew    = time.Minute
	opaqueTokenLifetime = 15 * time.Minute
	oidcHTTPTimeout     = 30 * time.Second
	adoOIDCAPIVersion   = "7.1"

	oidcMintGeneric = "generic"
	oidcMintGitHub  = "github"
	oidcMintADO     = "ado"
)

var (
	errMixedCredentials      = errors.New("api_key and oidc cannot be set together")
	errMissingCredentials    = errors.New("set api_key, an oidc block, or CLOUDSMITH_USE_OIDC")
	errMissingOIDCToken      = errors.New("oidc requires an identity token from CLOUDSMITH_OIDC_TOKEN, CLOUDSMITH_OIDC_TOKEN_FILE, TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH, TFC_WORKLOAD_IDENTITY_TOKEN, a GitHub Actions or Azure DevOps OIDC request, CIRCLE_OIDC_TOKEN_V2, CIRCLE_OIDC_TOKEN, or BITBUCKET_STEP_OIDC_TOKEN")
	errIncompleteOIDC        = errors.New("oidc requires organization and service_slug (set the attributes or CLOUDSMITH_ORG and CLOUDSMITH_SERVICE_SLUG)")
	errEmptyExchangeToken    = errors.New("OIDC token exchange returned an empty token")
	errEmptyTokenFile        = errors.New("CLOUDSMITH_OIDC_TOKEN_FILE is empty")
	errOIDCRequestIncomplete = errors.New("OIDC request URL is set but the request token is missing")
	errInvalidCredential     = errors.New("invalid credential")
	errInvalidAPIHost        = errors.New("api_host must be an absolute URL")
)

type tokenSource interface {
	Token(ctx context.Context) (string, error)
	invalidate(used string)
	canRetryAuth() bool
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }
func (s staticToken) invalidate(string)                     {}
func (s staticToken) canRetryAuth() bool                    { return false }

type oidcTokenSource struct {
	mu        sync.Mutex
	cached    string
	expiry    time.Time
	identity  oidcIdentity
	apiHost   string
	headers   map[string]interface{}
	userAgent string
	getenv    func(string) string
	readFile  func(string) ([]byte, error)
	client    *http.Client
	now       func() time.Time
}

func (s *oidcTokenSource) canRetryAuth() bool { return true }

// invalidate drops the cached token only when it is still the one the caller
// used. Without that check, N requests failing a 401 in parallel would each
// discard the token a sibling had already refreshed, forcing N exchanges.
func (s *oidcTokenSource) invalidate(used string) {
	s.mu.Lock()
	if used == "" || s.cached == used {
		s.cached = ""
		s.expiry = time.Time{}
	}
	s.mu.Unlock()
}

func (s *oidcTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.cached != "" && now.Add(tokenRefreshSkew).Before(s.expiry) {
		return s.cached, nil
	}
	assertion, err := loadAssertion(ctx, s.getenv, s.readFile, s.client)
	if err != nil {
		return "", err
	}
	token, err := exchangeOIDC(ctx, s.apiHost, s.headers, s.userAgent, s.identity, assertion)
	if err != nil {
		return "", err
	}
	s.cached = token
	s.expiry = jwtExpiry(token)
	if s.expiry.IsZero() {
		// The exchange returned something we cannot read an exp from. Refresh on
		// a timer rather than caching forever: a token with no readable expiry
		// would otherwise only ever be replaced by a 401.
		s.expiry = now.Add(opaqueTokenLifetime)
	}
	return token, nil
}

type credential struct {
	static *string
	oidc   *oidcIdentity
}

type oidcIdentity struct {
	organization string
	serviceSlug  string
}

type authSpec struct {
	apiKey string
	oidc   *oidcBlockSpec
}

type oidcBlockSpec struct {
	organization string
	serviceSlug  string
}

func authSpecFromResourceData(d *schema.ResourceData) authSpec {
	spec := authSpec{apiKey: strings.TrimSpace(requiredString(d, "api_key"))}
	raw, ok := d.Get("oidc").([]interface{})
	if !ok || len(raw) == 0 {
		return spec
	}
	block := oidcBlockSpec{}
	if m, ok := raw[0].(map[string]interface{}); ok && m != nil {
		if v, ok := m["organization"].(string); ok {
			block.organization = strings.TrimSpace(v)
		}
		if v, ok := m["service_slug"].(string); ok {
			block.serviceSlug = strings.TrimSpace(v)
		}
	}
	spec.oidc = &block
	return spec
}

func envEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseCredential(spec authSpec, getenv func(string) string) (credential, error) {
	oidcOn := spec.oidc != nil || envEnabled(getenv("CLOUDSMITH_USE_OIDC"))
	if oidcOn && spec.apiKey != "" {
		return credential{}, errMixedCredentials
	}
	if oidcOn {
		org := ""
		slug := ""
		if spec.oidc != nil {
			org = spec.oidc.organization
			slug = spec.oidc.serviceSlug
		}
		if org == "" {
			org = strings.TrimSpace(getenv("CLOUDSMITH_ORG"))
		}
		if slug == "" {
			slug = strings.TrimSpace(getenv("CLOUDSMITH_SERVICE_SLUG"))
		}
		if org == "" || slug == "" {
			return credential{}, errIncompleteOIDC
		}
		return credential{oidc: &oidcIdentity{organization: org, serviceSlug: slug}}, nil
	}
	if spec.apiKey != "" {
		key := spec.apiKey
		return credential{static: &key}, nil
	}
	if key := strings.TrimSpace(getenv("CLOUDSMITH_API_KEY")); key != "" {
		return credential{static: &key}, nil
	}
	return credential{}, errMissingCredentials
}

func tokenSourceFromCredential(
	cred credential,
	apiHost string,
	headers map[string]interface{},
	userAgent string,
	getenv func(string) string,
	readFile func(string) ([]byte, error),
	client *http.Client,
	now func() time.Time,
) (tokenSource, error) {
	switch {
	case cred.static != nil:
		return staticToken(*cred.static), nil
	case cred.oidc != nil:
		if now == nil {
			now = time.Now
		}
		if client == nil {
			client = &http.Client{Timeout: oidcHTTPTimeout}
		}
		return &oidcTokenSource{
			identity:  *cred.oidc,
			apiHost:   apiHost,
			headers:   headers,
			userAgent: userAgent,
			getenv:    getenv,
			readFile:  readFile,
			client:    client,
			now:       now,
		}, nil
	default:
		return nil, errInvalidCredential
	}
}

func loadAssertion(ctx context.Context, getenv func(string) string, readFile func(string) ([]byte, error), client *http.Client) (string, error) {
	if v := strings.TrimSpace(getenv("CLOUDSMITH_OIDC_TOKEN")); v != "" {
		return v, nil
	}
	if path := strings.TrimSpace(getenv("CLOUDSMITH_OIDC_TOKEN_FILE")); path != "" {
		b, err := readFile(path)
		if err != nil {
			return "", fmt.Errorf("read CLOUDSMITH_OIDC_TOKEN_FILE: %w", err)
		}
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, nil
		}
		return "", errEmptyTokenFile
	}
	if v := strings.TrimSpace(getenv("TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH")); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(getenv("TFC_WORKLOAD_IDENTITY_TOKEN")); v != "" {
		return v, nil
	}
	minted, err := mintFromRequest(ctx, getenv, client)
	if err != nil {
		return "", err
	}
	if minted != "" {
		return minted, nil
	}
	for _, key := range []string{"CIRCLE_OIDC_TOKEN_V2", "CIRCLE_OIDC_TOKEN", "BITBUCKET_STEP_OIDC_TOKEN"} {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v, nil
		}
	}
	return "", errMissingOIDCToken
}

type oidcMintRequest struct {
	url   string
	token string
	kind  string
}

func mintFromRequest(ctx context.Context, getenv func(string) string, client *http.Client) (string, error) {
	req, err := oidcRequestPair(getenv)
	if err != nil {
		return "", err
	}
	if req.url == "" {
		return "", nil
	}
	if req.kind == oidcMintADO || isAzureDevOpsOIDCURL(req.url) {
		return mintAzureDevOpsAssertion(ctx, req.url, req.token, getenv, client)
	}
	return mintGitHubAssertion(ctx, req.url, req.token, getenv, client)
}

func mintGitHubAssertion(ctx context.Context, reqURL, reqToken string, getenv func(string) string, client *http.Client) (string, error) {
	audience := strings.TrimSpace(getenv("CLOUDSMITH_OIDC_AUDIENCE"))
	if audience == "" {
		audience = defaultOIDCAudience
	}
	endpoint, err := requestURLWithAudience(reqURL, audience)
	if err != nil {
		return "", fmt.Errorf("OIDC request URL: %w", err)
	}
	return doMintRequest(ctx, client, http.MethodGet, endpoint, reqToken, nil, map[string]string{
		// Matches the GitHub Actions toolkit and cloudsmith-cli.
		"Accept": "application/json; api-version=2.0",
	})
}

func mintAzureDevOpsAssertion(ctx context.Context, reqURL, reqToken string, getenv func(string) string, client *http.Client) (string, error) {
	endpoint, err := azureDevOpsRequestURL(reqURL, adoServiceConnectionID(getenv))
	if err != nil {
		return "", fmt.Errorf("OIDC request URL: %w", err)
	}
	// Azure DevOps always mints with a fixed audience and ignores any request
	// body, so this is an empty POST (matching cloudsmith-cli and azidentity's
	// AzurePipelinesCredential). X-TFS-FedAuthRedirect stops Azure DevOps from
	// answering an auth failure with a 200 HTML sign-in page.
	return doMintRequest(ctx, client, http.MethodPost, endpoint, reqToken, nil, map[string]string{
		"X-TFS-FedAuthRedirect": "Suppress",
	})
}

func doMintRequest(ctx context.Context, client *http.Client, method, endpoint, bearer string, body io.Reader, extraHeaders map[string]string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: oidcHTTPTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return "", fmt.Errorf("OIDC identity token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC identity token request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("OIDC identity token request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("OIDC identity token request failed: %s", resp.Status)
	}
	token, err := parseMintedToken(raw)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("OIDC identity token request returned an empty token")
	}
	return token, nil
}

func oidcRequestPair(getenv func(string) string) (oidcMintRequest, error) {
	pairs := []struct {
		url, token, kind string
	}{
		{"CLOUDSMITH_OIDC_REQUEST_URL", "CLOUDSMITH_OIDC_REQUEST_TOKEN", oidcMintGeneric},
		{"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", oidcMintGitHub},
		{"SYSTEM_OIDCREQUESTURI", "SYSTEM_ACCESSTOKEN", oidcMintADO},
	}
	for _, pair := range pairs {
		reqURL := strings.TrimSpace(getenv(pair.url))
		reqToken := strings.TrimSpace(getenv(pair.token))
		if reqURL == "" && reqToken == "" {
			continue
		}
		if reqURL == "" || reqToken == "" {
			return oidcMintRequest{}, fmt.Errorf("%w (%s / %s)", errOIDCRequestIncomplete, pair.url, pair.token)
		}
		return oidcMintRequest{url: reqURL, token: reqToken, kind: pair.kind}, nil
	}
	return oidcMintRequest{}, nil
}

func requestURLWithAudience(raw, audience string) (string, error) {
	u, err := parseAbsoluteURL(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if audience != "" {
		q.Set("audience", audience)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func azureDevOpsRequestURL(raw, serviceConnectionID string) (string, error) {
	u, err := parseAbsoluteURL(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if q.Get("api-version") == "" {
		q.Set("api-version", adoOIDCAPIVersion)
	}
	if serviceConnectionID != "" {
		q.Set("serviceConnectionId", serviceConnectionID)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func parseAbsoluteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("must be an absolute URL")
	}
	return u, nil
}

func isAzureDevOpsOIDCURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	return strings.Contains(path, "/_apis/distributedtask/") && strings.Contains(path, "/oidctoken")
}

// adoServiceConnectionID is read from an explicit opt-in variable only.
// Ambient variables such as AZURESUBSCRIPTION_SERVICE_CONNECTION_ID are set
// automatically by tasks like AzureCLI@2, and using them would silently switch
// the minted token subject from the pipeline (p://) to a service connection
// (sc://), breaking the Cloudsmith claim match the user configured.
func adoServiceConnectionID(getenv func(string) string) string {
	return strings.TrimSpace(getenv("CLOUDSMITH_ADO_SERVICE_CONNECTION_ID"))
}

func parseMintedToken(body []byte) (string, error) {
	var payload struct {
		Value       string `json:"value"`
		AccessToken string `json:"access_token"`
		Token       string `json:"token"`
		OidcToken   string `json:"oidcToken"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode OIDC identity token response: %w", err)
	}
	for _, v := range []string{payload.Value, payload.AccessToken, payload.Token, payload.OidcToken} {
		if s := strings.TrimSpace(v); s != "" {
			return s, nil
		}
	}
	return "", nil
}

func exchangeOIDC(ctx context.Context, apiHost string, headers map[string]interface{}, userAgent string, id oidcIdentity, assertion string) (string, error) {
	openIDBase, err := openIDServerURL(apiHost)
	if err != nil {
		return "", err
	}

	cfg := cloudsmith.NewConfiguration()
	cfg.Debug = false
	cfg.HTTPClient = &http.Client{
		Timeout: oidcHTTPTimeout,
		Transport: &headerTransport{
			headers: headers,
			rt:      http.DefaultTransport,
		},
	}
	cfg.Servers = cloudsmith.ServerConfigurations{{URL: openIDBase}}
	cfg.UserAgent = userAgent

	client := cloudsmith.NewAPIClient(cfg)
	out, _, err := client.OpenidApi.OpenidCreate(ctx, id.organization).
		Data(cloudsmith.OidcRequest{
			OidcToken:   assertion,
			ServiceSlug: id.serviceSlug,
		}).
		Execute()
	if err != nil {
		return "", fmt.Errorf("OIDC token exchange failed: %w", err)
	}
	token := ""
	if out != nil {
		token = out.GetToken()
	}
	if token == "" {
		return "", errEmptyExchangeToken
	}
	return token, nil
}

func openIDServerURL(apiHost string) (string, error) {
	if apiHost == "" {
		return "", errInvalidAPIHost
	}
	u, err := url.Parse(apiHost)
	if err != nil {
		return "", fmt.Errorf("api_host: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errInvalidAPIHost
	}

	path := strings.TrimSuffix(u.Path, "/")
	segments := strings.Split(path, "/")
	if n := len(segments); n > 0 && segments[n-1] == "v1" {
		segments = segments[:n-1]
	}
	u.Path = strings.Join(segments, "/")
	u.RawQuery = ""
	u.Fragment = ""
	u.RawPath = ""

	out := u.String()
	if u.Path == "" || u.Path == "/" {
		out = strings.TrimSuffix(out, "/")
	}
	return out, nil
}

func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		padded, padErr := base64.URLEncoding.DecodeString(parts[1])
		if padErr != nil {
			return time.Time{}
		}
		payload = padded
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}
