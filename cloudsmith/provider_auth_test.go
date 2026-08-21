//nolint:testpackage
package cloudsmith

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestOpenIDServerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "https://api.cloudsmith.io/v1", want: "https://api.cloudsmith.io"},
		{in: "https://api.cloudsmith.io/v1/", want: "https://api.cloudsmith.io"},
		{in: "http://127.0.0.1:1234", want: "http://127.0.0.1:1234"},
		{in: "http://127.0.0.1:1234/v1", want: "http://127.0.0.1:1234"},
		{in: "https://api.example.com/prefix/v1", want: "https://api.example.com/prefix"},
		{in: "https://api.example.com/prefix/v1/", want: "https://api.example.com/prefix"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := openIDServerURL(tc.in)
			if err != nil {
				t.Fatalf("openIDServerURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("openIDServerURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    authSpec
		env     map[string]string
		wantKey string
		wantOrg string
		wantErr error
	}{
		{
			name:    "static api key",
			spec:    authSpec{apiKey: "csap_static"},
			wantKey: "csap_static",
		},
		{
			name: "mixed api_key and oidc",
			spec: authSpec{
				apiKey: "csap_static",
				oidc:   &oidcBlockSpec{organization: "acme", serviceSlug: "tfc"},
			},
			env:     map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt"},
			wantErr: errMixedCredentials,
		},
		{
			name:    "empty provider is not oidc",
			spec:    authSpec{},
			env:     map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt", "CLOUDSMITH_ORG": "acme", "CLOUDSMITH_SERVICE_SLUG": "tfc"},
			wantErr: errMissingCredentials,
		},
		{
			name:    "empty provider uses CLOUDSMITH_API_KEY env",
			spec:    authSpec{},
			env:     map[string]string{"CLOUDSMITH_API_KEY": "env-static"},
			wantKey: "env-static",
		},
		{
			name: "oidc ignores ambient CLOUDSMITH_API_KEY",
			spec: authSpec{oidc: &oidcBlockSpec{organization: "acme", serviceSlug: "tfc"}},
			env: map[string]string{
				"CLOUDSMITH_API_KEY": "ambient-static",
			},
			wantOrg: "acme",
		},
		{
			name:    "oidc missing organization",
			spec:    authSpec{oidc: &oidcBlockSpec{serviceSlug: "tfc"}},
			wantErr: errIncompleteOIDC,
		},
		{
			name:    "oidc env fills org and slug",
			spec:    authSpec{oidc: &oidcBlockSpec{}},
			env:     map[string]string{"CLOUDSMITH_ORG": "acme", "CLOUDSMITH_SERVICE_SLUG": "tfc"},
			wantOrg: "acme",
		},
		{
			name:    "CLOUDSMITH_USE_OIDC enables oidc without a block",
			spec:    authSpec{},
			env:     map[string]string{"CLOUDSMITH_USE_OIDC": "true", "CLOUDSMITH_ORG": "acme", "CLOUDSMITH_SERVICE_SLUG": "tfc"},
			wantOrg: "acme",
		},
		{
			name:    "CLOUDSMITH_USE_OIDC ignores leftover API key",
			spec:    authSpec{},
			env:     map[string]string{"CLOUDSMITH_USE_OIDC": "yes", "CLOUDSMITH_ORG": "acme", "CLOUDSMITH_SERVICE_SLUG": "tfc", "CLOUDSMITH_API_KEY": "ambient-static"},
			wantOrg: "acme",
		},
		{
			name:    "CLOUDSMITH_USE_OIDC with HCL api_key is mixed",
			spec:    authSpec{apiKey: "csap_static"},
			env:     map[string]string{"CLOUDSMITH_USE_OIDC": "1"},
			wantErr: errMixedCredentials,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cred, err := parseCredential(tc.spec, func(k string) string { return tc.env[k] })
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				assertNoSecret(t, diag.FromErr(err), "csap_static", "tfc-jwt", "ambient-static")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantKey != "" {
				if cred.static == nil || *cred.static != tc.wantKey {
					t.Fatalf("static key = %v, want %q", cred.static, tc.wantKey)
				}
				if cred.oidc != nil {
					t.Fatal("static credential must not carry oidc")
				}
				return
			}
			if cred.oidc == nil {
				t.Fatal("expected oidc credential")
			}
			if cred.static != nil {
				t.Fatal("oidc credential must not carry static")
			}
			if cred.oidc.organization != tc.wantOrg {
				t.Fatalf("organization = %q, want %q", cred.oidc.organization, tc.wantOrg)
			}
		})
	}
}

func TestLoadAssertion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr error
	}{
		{
			name: "untagged token",
			env:  map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt"},
			want: "tfc-jwt",
		},
		{
			name: "tagged token before untagged",
			env: map[string]string{
				"TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH": "tagged-jwt",
				"TFC_WORKLOAD_IDENTITY_TOKEN":            "tfc-jwt",
			},
			want: "tagged-jwt",
		},
		{
			name:    "whitespace only is not a token",
			env:     map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN": "  \n"},
			wantErr: errMissingOIDCToken,
		},
		{
			name:    "missing",
			wantErr: errMissingOIDCToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := loadAssertion(func(k string) string { return tc.env[k] })
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				assertNoSecret(t, diag.FromErr(err), "tfc-jwt", "tagged-jwt")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("assertion = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJwtExpiry(t *testing.T) {
	t.Parallel()
	exp := time.Unix(1_700_000_000, 0)
	if got := jwtExpiry(signedTestJWT(exp)); !got.Equal(exp) {
		t.Fatalf("jwtExpiry = %v, want %v", got, exp)
	}
	if !jwtExpiry("not-a-jwt").IsZero() {
		t.Fatal("expected zero expiry")
	}
}

func TestOIDCTokenSourceRefresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	firstExp := now.Add(2 * time.Hour)
	secondExp := now.Add(4 * time.Hour)
	exchanges := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n := exchanges.Add(1)
		token := signedTestJWT(firstExp)
		if n > 1 {
			token = signedTestJWT(secondExp)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, token)
	}))
	t.Cleanup(srv.Close)

	clock := now
	src := &oidcTokenSource{
		identity: oidcIdentity{organization: "acme", serviceSlug: "tfc"},
		apiHost:  srv.URL + "/v1",
		getenv: func(k string) string {
			if k == "TFC_WORKLOAD_IDENTITY_TOKEN" {
				return "tfc-jwt"
			}
			return ""
		},
		now: func() time.Time { return clock },
	}

	tok1, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok1 != tok2 {
		t.Fatal("expected cached token")
	}
	if exchanges.Load() != 1 {
		t.Fatalf("exchanges = %d, want 1", exchanges.Load())
	}

	clock = firstExp.Add(-30 * time.Second)
	tok3, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok3 == tok1 {
		t.Fatal("expected refresh near expiry")
	}
	if exchanges.Load() != 2 {
		t.Fatalf("exchanges = %d, want 2", exchanges.Load())
	}
}

func TestOIDCTokenSourceInvalidateOnlyDropsTheTokenThatFailed(t *testing.T) {
	src := &oidcTokenSource{
		cached: "fresh-jwt",
		expiry: time.Now().Add(time.Hour),
		now:    time.Now,
	}
	src.invalidate("stale-jwt")
	if src.cached != "fresh-jwt" {
		t.Fatalf("cached = %q, want the refreshed token to survive", src.cached)
	}
	src.invalidate("fresh-jwt")
	if src.cached != "" {
		t.Fatalf("cached = %q, want the failing token dropped", src.cached)
	}
}

func TestProviderConfigure_StaticAPIKeySkipsExchange(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, _ := newAuthServer(t, authServerOpts{
		staticKey: "static-key",
	})

	cfg, diags := configureProviderRaw(t, map[string]interface{}{
		"api_key":  "static-key",
		"api_host": srv.URL,
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	if mustAPIKey(t, cfg.(*providerConfig)) != "static-key" {
		t.Fatalf("GetAPIKey() = %q, want static-key", mustAPIKey(t, cfg.(*providerConfig)))
	}
	if posts.Load() != 0 {
		t.Fatalf("openid POSTs = %d, want 0", posts.Load())
	}
}

func TestProviderConfigure_EnvAPIKeyWithoutOIDC(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		staticKey: "static-key",
	})
	t.Setenv("CLOUDSMITH_API_KEY", "static-key")

	cfg, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL,
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	if mustAPIKey(t, cfg.(*providerConfig)) != "static-key" {
		t.Fatalf("GetAPIKey() = %q, want static-key", mustAPIKey(t, cfg.(*providerConfig)))
	}
	if posts.Load() != 0 {
		t.Fatalf("openid POSTs = %d, want 0", posts.Load())
	}
	if gets.Load() != 1 {
		t.Fatalf("user/self GETs = %d, want 1", gets.Load())
	}
}

func TestProviderConfigure_TFCOIDC(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "tfc",
		oidcToken:     "tfc-jwt",
		exchangeToken: "exchanged-jwt",
	})
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")

	cfg, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "tfc",
			},
		},
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	if mustAPIKey(t, cfg.(*providerConfig)) != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q", mustAPIKey(t, cfg.(*providerConfig)))
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
	}
}

func TestProviderConfigure_TFCTaggedTokenWins(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "tfc",
		oidcToken:     "tagged-jwt",
		exchangeToken: "exchanged-jwt",
	})
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH", "tagged-jwt")

	cfg, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "tfc",
			},
		},
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	if mustAPIKey(t, cfg.(*providerConfig)) != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q", mustAPIKey(t, cfg.(*providerConfig)))
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
	}
}

func TestProviderConfigure_OIDCIgnoresAmbientAPIKey(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "tfc",
		oidcToken:     "tfc-jwt",
		exchangeToken: "exchanged-jwt",
	})
	t.Setenv("CLOUDSMITH_API_KEY", "ambient-static")
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")

	cfg, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "tfc",
			},
		},
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	pc := cfg.(*providerConfig)
	if mustAPIKey(t, pc) != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q, want exchanged-jwt", mustAPIKey(t, pc))
	}
	if posts.Load() != 1 {
		t.Fatalf("openid POSTs = %d, want 1", posts.Load())
	}
	if gets.Load() != 1 {
		t.Fatalf("user/self GETs = %d, want 1", gets.Load())
	}
}

func TestProviderConfigure_UseOIDCEnv(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "tfc",
		oidcToken:     "tfc-jwt",
		exchangeToken: "exchanged-jwt",
	})
	t.Setenv("CLOUDSMITH_USE_OIDC", "true")
	t.Setenv("CLOUDSMITH_ORG", "acme")
	t.Setenv("CLOUDSMITH_SERVICE_SLUG", "tfc")
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")
	t.Setenv("CLOUDSMITH_API_KEY", "ambient-static")

	cfg, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	if mustAPIKey(t, cfg.(*providerConfig)) != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q", mustAPIKey(t, cfg.(*providerConfig)))
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
	}
}

func TestProviderConfigure_MixedAPIKeyAndOIDC(t *testing.T) {
	clearOIDCEnv(t)
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")

	_, diags := configureProviderRaw(t, map[string]interface{}{
		"api_key":  "static-key",
		"api_host": "https://api.cloudsmith.io/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "tfc",
			},
		},
	})
	if !diags.HasError() {
		t.Fatal("expected mixed credential error")
	}
	if !strings.Contains(fmt.Sprint(diags), errMixedCredentials.Error()) {
		t.Fatalf("diagnostics = %v", diags)
	}
	assertNoSecret(t, diags, "static-key", "tfc-jwt")
}

// ConflictsWith cannot see this one: CLOUDSMITH_USE_OIDC is not part of the
// configuration, so the clash is only detectable at configure time.
func TestProviderConfigure_UseOIDCEnvWithHCLAPIKey(t *testing.T) {
	clearOIDCEnv(t)
	t.Setenv("CLOUDSMITH_USE_OIDC", "true")
	t.Setenv("CLOUDSMITH_ORG", "acme")
	t.Setenv("CLOUDSMITH_SERVICE_SLUG", "tfc")
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")

	_, diags := configureProviderRaw(t, map[string]interface{}{
		"api_key":  "static-key",
		"api_host": "https://api.cloudsmith.io/v1",
	})
	if !diags.HasError() {
		t.Fatal("expected mixed credential error")
	}
	if !strings.Contains(fmt.Sprint(diags), errMixedCredentials.Error()) {
		t.Fatalf("diagnostics = %v", diags)
	}
	assertNoSecret(t, diags, "static-key", "tfc-jwt")
}

func TestProviderConfigure_OIDCWithoutToken(t *testing.T) {
	clearOIDCEnv(t)

	_, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": "https://api.cloudsmith.io/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "tfc",
			},
		},
	})
	if !diags.HasError() {
		t.Fatal("expected missing token error")
	}
	msg := fmt.Sprint(diags)
	for _, name := range []string{
		"TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH",
		"TFC_WORKLOAD_IDENTITY_TOKEN",
		"TFC_WORKLOAD_IDENTITY_AUDIENCE",
	} {
		if !strings.Contains(msg, name) {
			t.Fatalf("diagnostics %q missing %s", msg, name)
		}
	}
}

func TestProviderConfigure_ExchangeUnauthorized(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:         "acme",
		serviceSlug: "tfc",
		oidcToken:   "tfc-jwt",
		exchangeErr: http.StatusUnauthorized,
	})
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")

	_, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "tfc",
			},
		},
	})
	if !diags.HasError() {
		t.Fatal("expected exchange failure")
	}
	if posts.Load() != 1 {
		t.Fatalf("openid POSTs = %d, want 1", posts.Load())
	}
	if gets.Load() != 0 {
		t.Fatalf("user/self GETs = %d, want 0", gets.Load())
	}
	assertNoSecret(t, diags, "tfc-jwt")
}

func TestProviderConfigure_ExchangeEmptyToken(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "tfc",
		oidcToken:     "tfc-jwt",
		exchangeToken: "",
	})
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")

	_, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "tfc",
			},
		},
	})
	if !diags.HasError() {
		t.Fatal("expected empty token failure")
	}
	if !strings.Contains(fmt.Sprint(diags), errEmptyExchangeToken.Error()) {
		t.Fatalf("diagnostics = %v", diags)
	}
	if posts.Load() != 1 {
		t.Fatalf("openid POSTs = %d, want 1", posts.Load())
	}
	if gets.Load() != 0 {
		t.Fatalf("user/self GETs = %d, want 0", gets.Load())
	}
}

func TestProviderConfigure_UserSelf401RetriesExchange(t *testing.T) {
	clearOIDCEnv(t)
	var posts, gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/openid/"):
			n := posts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":"jwt-%d"}`, n)
		case strings.Contains(r.URL.Path, "/user/self"):
			gets.Add(1)
			if r.Header.Get("X-Api-Key") != "jwt-2" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"email":"sa@example.com","name":"tfc","slug":"tfc","slug_perm":"tfc"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("TFC_WORKLOAD_IDENTITY_TOKEN", "tfc-jwt")

	cfg, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "tfc",
			},
		},
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	if mustAPIKey(t, cfg.(*providerConfig)) != "jwt-2" {
		t.Fatalf("GetAPIKey() = %q, want jwt-2", mustAPIKey(t, cfg.(*providerConfig)))
	}
	if posts.Load() != 2 {
		t.Fatalf("openid POSTs = %d, want 2", posts.Load())
	}
	if gets.Load() != 2 {
		t.Fatalf("user/self GETs = %d, want 2", gets.Load())
	}
}

func TestCredentialIsNotSentToOtherHosts(t *testing.T) {
	var mu sync.Mutex
	var apiKeys []string
	var cdnKeys []string

	// Stands in for object storage: the host a dl.cloudsmith.io download, or an
	// api-host redirect, ends up at.
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cdnKeys = append(cdnKeys, r.Header.Get("X-Api-Key"))
		mu.Unlock()
		fmt.Fprint(w, "package-bytes")
	}))
	t.Cleanup(cdn.Close)

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		apiKeys = append(apiKeys, r.Header.Get("X-Api-Key"))
		mu.Unlock()
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, cdn.URL+"/package.tgz", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"email":"sa@example.com","name":"tfc","slug":"tfc","slug_perm":"tfc"}`)
	}))
	t.Cleanup(api.Close)

	pc, diags := newProviderConfig(context.Background(), api.URL, staticToken("valid-token"), map[string]interface{}{}, "test-agent")
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	mu.Lock()
	sentToAPI := append([]string(nil), apiKeys...)
	mu.Unlock()
	if len(sentToAPI) == 0 || sentToAPI[0] != "valid-token" {
		t.Fatalf("api host X-Api-Key = %v, want the credential to be sent", sentToAPI)
	}

	client := pc.APIClient.GetConfig().HTTPClient

	// A direct download, as the package data source does.
	resp, err := client.Get(cdn.URL + "/package.tgz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// An api-host request that already carries the credential, redirected off
	// host. Go copies caller-set headers across hops and does not strip
	// X-Api-Key, so the transport has to drop it itself.
	req, err := http.NewRequest(http.MethodGet, api.URL+"/redirect", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Api-Key", "valid-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	mu.Lock()
	got := append([]string(nil), cdnKeys...)
	mu.Unlock()

	if len(got) != 2 {
		t.Fatalf("requests reaching the non-API host = %d, want 2", len(got))
	}
	for i, key := range got {
		if key != "" {
			t.Errorf("request %d sent X-Api-Key %q to a non-API host, want it withheld", i, key)
		}
	}
}

func TestCredentialHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		want    string
		wantErr error
	}{
		{name: "empty stays permissive", host: "", want: ""},
		{name: "absolute", host: "https://api.cloudsmith.io/v1", want: "api.cloudsmith.io"},
		{name: "port is kept", host: "http://localhost:8080/v1", want: "localhost:8080"},
		{name: "scheme-less is rejected", host: "api.cloudsmith.io/v1", wantErr: errInvalidAPIHost},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := credentialHost(tc.host)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("credentialHost(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestUnreplayableRequestInvalidatesWithoutRetrying(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"exchanged-jwt"}`)
	}))
	t.Cleanup(exchange.Close)

	src := &oidcTokenSource{
		identity: oidcIdentity{organization: "acme-org", serviceSlug: "ci-prod"},
		apiHost:  exchange.URL,
		getenv:   func(k string) string { return map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt"}[k] },
		now:      time.Now,
	}
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}

	host, err := credentialHost(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &apiKeyTransport{tokens: src, apiHost: host, rt: http.DefaultTransport}

	// A body with no GetBody cannot be replayed, so the 401 must come back
	// as-is rather than being retried.
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/write", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = nil

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error = %v, want the 401 returned", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	// The response body is still owned by the caller, so it must be readable.
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 (must not retry a non-replayable body)", got)
	}

	src.mu.Lock()
	cached := src.cached
	src.mu.Unlock()
	if cached != "" {
		t.Fatalf("cached token = %q, want it invalidated", cached)
	}
}

func TestOpaqueExchangeTokenStillRefreshes(t *testing.T) {
	var exchanges atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"opaque-not-a-jwt"}`)
	}))
	t.Cleanup(srv.Close)

	current := time.Now()
	src := &oidcTokenSource{
		identity: oidcIdentity{organization: "acme-org", serviceSlug: "ci-prod"},
		apiHost:  srv.URL,
		getenv:   func(k string) string { return map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt"}[k] },
		now:      func() time.Time { return current },
	}

	if _, err := src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := exchanges.Load(); got != 1 {
		t.Fatalf("exchanges = %d, want 1 (opaque token must still be cached)", got)
	}

	current = current.Add(opaqueTokenLifetime + time.Minute)
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := exchanges.Load(); got != 2 {
		t.Fatalf("exchanges = %d, want 2 (opaque token must expire, not cache forever)", got)
	}
}

func configureProviderRaw(t *testing.T, raw map[string]interface{}) (interface{}, diag.Diagnostics) {
	t.Helper()
	p := Provider()
	d := schema.TestResourceDataRaw(t, p.Schema, raw)
	return p.ConfigureContextFunc(context.Background(), d)
}

func clearOIDCEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"CLOUDSMITH_API_KEY",
		"CLOUDSMITH_USE_OIDC",
		"CLOUDSMITH_ORG",
		"CLOUDSMITH_SERVICE_SLUG",
		"TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH",
		"TFC_WORKLOAD_IDENTITY_TOKEN",
	} {
		t.Setenv(key, "")
	}
}

func signedTestJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]int64{"exp": exp.Unix()})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

type authServerOpts struct {
	org           string
	serviceSlug   string
	oidcToken     string
	exchangeToken string
	exchangeErr   int
	staticKey     string
}

func newAuthServer(t *testing.T, opts authServerOpts) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var posts, gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/openid/"):
			posts.Add(1)
			if r.Header.Get("X-Api-Key") != "" {
				t.Error("exchange must not send X-Api-Key")
			}
			if opts.org != "" && r.URL.Path != "/openid/"+opts.org+"/" {
				t.Errorf("openid path = %q", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			var payload struct {
				OidcToken   string `json:"oidc_token"`
				ServiceSlug string `json:"service_slug"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Errorf("decode body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if payload.OidcToken != opts.oidcToken || payload.ServiceSlug != opts.serviceSlug {
				t.Errorf("body oidc_token=%q service_slug=%q", payload.OidcToken, payload.ServiceSlug)
			}
			if opts.exchangeErr != 0 {
				w.WriteHeader(opts.exchangeErr)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, opts.exchangeToken)
		case strings.TrimSuffix(r.URL.Path, "/") == "/user/self" || strings.TrimSuffix(r.URL.Path, "/") == "/v1/user/self":
			gets.Add(1)
			wantKey := opts.exchangeToken
			if opts.staticKey != "" {
				wantKey = opts.staticKey
			}
			if r.Header.Get("X-Api-Key") != wantKey {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"email":"sa@example.com","name":"tfc","slug":"tfc","slug_perm":"tfc"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &posts, &gets
}

func assertNoSecret(t *testing.T, diags diag.Diagnostics, secrets ...string) {
	t.Helper()
	msg := fmt.Sprint(diags)
	for _, secret := range secrets {
		if secret != "" && strings.Contains(msg, secret) {
			t.Fatalf("diagnostics leaked %q: %s", secret, msg)
		}
	}
}

// mustAPIKey reads the configured credential and fails the test if the token
// source errors, so assertions stay one-liners.
func mustAPIKey(t *testing.T, pc *providerConfig) string {
	t.Helper()
	key, err := pc.GetAPIKey()
	if err != nil {
		t.Fatalf("GetAPIKey() error = %v", err)
	}
	return key
}

// failingTokenSource hands out a token for the first okCalls requests, then
// fails, standing in for a refresh that breaks partway through an apply.
type failingTokenSource struct {
	calls   atomic.Int32
	okCalls int32
	err     error
}

func (f *failingTokenSource) Token(context.Context) (string, error) {
	if f.calls.Add(1) <= f.okCalls {
		return "first-token", nil
	}
	return "", f.err
}
func (f *failingTokenSource) invalidate(string)  {}
func (f *failingTokenSource) canRetryAuth() bool { return true }

func TestGetAPIKeySurfacesRefreshFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"email":"sa@example.com","name":"tfc","slug":"tfc","slug_perm":"tfc"}`)
	}))
	t.Cleanup(srv.Close)

	wantErr := errors.New("OIDC token exchange failed")
	// Two successes cover provider configure: one direct call, one through the
	// transport for the user/self probe.
	tokens := &failingTokenSource{okCalls: 2, err: wantErr}

	pc, diags := newProviderConfig(context.Background(), srv.URL, tokens, map[string]interface{}{}, "test-agent")
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	// The configure-time token is "first-token". A caller asking now must get
	// the refresh error, not that stale value.
	got, err := pc.GetAPIKey()
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if got == "first-token" {
		t.Fatal("returned the configure-time token instead of reporting the refresh failure")
	}
}
