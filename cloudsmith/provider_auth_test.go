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
	"os"
	"path/filepath"
	"strings"
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
			env:     map[string]string{"CLOUDSMITH_OIDC_TOKEN": "jwt"},
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
				assertNoSecret(t, diag.FromErr(err), "csap_static", "jwt", "tfc-jwt", "ambient-static")
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
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("file-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(emptyFile, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer mint-token" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Query().Get("audience") != "cloudsmith" {
			t.Errorf("audience = %q", r.URL.Query().Get("audience"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":"gha-jwt"}`)
	}))
	t.Cleanup(mint.Close)

	tests := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr error
	}{
		{
			name: "prefers CLOUDSMITH_OIDC_TOKEN",
			env:  map[string]string{"CLOUDSMITH_OIDC_TOKEN": "env-jwt", "CLOUDSMITH_OIDC_TOKEN_FILE": tokenFile, "TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt"},
			want: "env-jwt",
		},
		{
			name: "token file before TFC",
			env:  map[string]string{"CLOUDSMITH_OIDC_TOKEN_FILE": tokenFile, "TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt"},
			want: "file-jwt",
		},
		{
			name:    "empty token file does not fall through",
			env:     map[string]string{"CLOUDSMITH_OIDC_TOKEN_FILE": emptyFile, "TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt"},
			wantErr: errEmptyTokenFile,
		},
		{
			name: "TFC untagged token",
			env:  map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN": "tfc-jwt"},
			want: "tfc-jwt",
		},
		{
			name: "tagged TFC token before untagged",
			env: map[string]string{
				"TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH": "tagged-jwt",
				"TFC_WORKLOAD_IDENTITY_TOKEN":            "tfc-jwt",
			},
			want: "tagged-jwt",
		},
		{
			name: "TFC before GitHub mint",
			env: map[string]string{
				"TFC_WORKLOAD_IDENTITY_TOKEN":    "tfc-jwt",
				"ACTIONS_ID_TOKEN_REQUEST_URL":   mint.URL,
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "mint-token",
			},
			want: "tfc-jwt",
		},
		{
			name: "GitHub Actions mint",
			env: map[string]string{
				"ACTIONS_ID_TOKEN_REQUEST_URL":   mint.URL,
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "mint-token",
			},
			want: "gha-jwt",
		},
		{
			name: "generic request URL is GitHub-shaped GET",
			env: map[string]string{
				"CLOUDSMITH_OIDC_REQUEST_URL":   mint.URL,
				"CLOUDSMITH_OIDC_REQUEST_TOKEN": "mint-token",
			},
			want: "gha-jwt",
		},
		{
			name:    "GitHub URL without token",
			env:     map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": mint.URL},
			wantErr: errOIDCRequestIncomplete,
		},
		{
			name:    "Azure DevOps URL without token",
			env:     map[string]string{"SYSTEM_OIDCREQUESTURI": mint.URL},
			wantErr: errOIDCRequestIncomplete,
		},
		{
			name: "CircleCI v2 before v1",
			env:  map[string]string{"CIRCLE_OIDC_TOKEN_V2": "circle-v2", "CIRCLE_OIDC_TOKEN": "circle-v1"},
			want: "circle-v2",
		},
		{
			name: "Bitbucket",
			env:  map[string]string{"BITBUCKET_STEP_OIDC_TOKEN": "bb-jwt"},
			want: "bb-jwt",
		},
		{
			name:    "missing",
			wantErr: errMissingOIDCToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadAssertion(context.Background(), func(k string) string { return tc.env[k] }, os.ReadFile, mint.Client())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				assertNoSecret(t, diag.FromErr(err), "env-jwt", "file-jwt", "tfc-jwt", "tagged-jwt", "gha-jwt", "mint-token", "circle-v2", "bb-jwt")
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

func TestLoadAssertionAzureDevOps(t *testing.T) {
	ado := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer ado-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-TFS-FedAuthRedirect"); got != "Suppress" {
			t.Errorf("X-TFS-FedAuthRedirect = %q, want Suppress", got)
		}
		if r.URL.Query().Get("audience") != "" {
			t.Errorf("Azure DevOps mint must not set audience, got %q", r.URL.Query().Get("audience"))
		}
		if r.URL.Query().Get("api-version") != adoOIDCAPIVersion {
			t.Errorf("api-version = %q, want %q", r.URL.Query().Get("api-version"), adoOIDCAPIVersion)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if strings.TrimSpace(string(body)) != "" {
			t.Errorf("body = %q, want empty", body)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"oidcToken":"ado-jwt"}`)
	}))
	t.Cleanup(ado.Close)

	got, err := loadAssertion(context.Background(), func(k string) string {
		switch k {
		case "SYSTEM_OIDCREQUESTURI":
			return ado.URL + "/_apis/distributedtask/hubs/build/plans/p/jobs/j/oidctoken"
		case "SYSTEM_ACCESSTOKEN":
			return "ado-token"
		default:
			return ""
		}
	}, os.ReadFile, ado.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got != "ado-jwt" {
		t.Fatalf("assertion = %q, want ado-jwt", got)
	}
}

func TestLoadAssertionAzureDevOpsServiceConnection(t *testing.T) {
	ado := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("serviceConnectionId") != "sc-123" {
			t.Errorf("serviceConnectionId = %q, want sc-123", r.URL.Query().Get("serviceConnectionId"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"oidcToken":"ado-sc-jwt"}`)
	}))
	t.Cleanup(ado.Close)

	got, err := loadAssertion(context.Background(), func(k string) string {
		switch k {
		case "SYSTEM_OIDCREQUESTURI":
			return ado.URL + "/_apis/distributedtask/hubs/build/plans/p/jobs/j/oidctoken"
		case "SYSTEM_ACCESSTOKEN":
			return "ado-token"
		case "CLOUDSMITH_ADO_SERVICE_CONNECTION_ID":
			return "sc-123"
		default:
			return ""
		}
	}, os.ReadFile, ado.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got != "ado-sc-jwt" {
		t.Fatalf("assertion = %q, want ado-sc-jwt", got)
	}
}

func TestLoadAssertionAzureDevOpsGenericRequestURL(t *testing.T) {
	ado := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("audience") != "" {
			t.Errorf("Azure DevOps mint must not set audience, got %q", r.URL.Query().Get("audience"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"oidcToken":"ado-generic-jwt"}`)
	}))
	t.Cleanup(ado.Close)

	got, err := loadAssertion(context.Background(), func(k string) string {
		switch k {
		case "CLOUDSMITH_OIDC_REQUEST_URL":
			return ado.URL + "/_apis/distributedtask/hubs/build/plans/p/jobs/j/oidctoken"
		case "CLOUDSMITH_OIDC_REQUEST_TOKEN":
			return "ado-token"
		default:
			return ""
		}
	}, os.ReadFile, ado.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got != "ado-generic-jwt" {
		t.Fatalf("assertion = %q, want ado-generic-jwt", got)
	}
}

func TestParseMintedToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "github value", body: `{"value":"gha"}`, want: "gha"},
		{name: "access_token", body: `{"access_token":"at"}`, want: "at"},
		{name: "token", body: `{"token":"tok"}`, want: "tok"},
		{name: "azure oidcToken", body: `{"oidcToken":"ado"}`, want: "ado"},
		{name: "empty", body: `{}`, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseMintedToken([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("parseMintedToken = %q, want %q", got, tc.want)
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
			if k == "CLOUDSMITH_OIDC_TOKEN" {
				return "env-jwt"
			}
			return ""
		},
		readFile: os.ReadFile,
		client:   srv.Client(),
		now:      func() time.Time { return clock },
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

func TestProviderConfigure_OIDCEnvToken(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "tfc",
		oidcToken:     "env-jwt",
		exchangeToken: "exchanged-jwt",
	})
	t.Setenv("CLOUDSMITH_OIDC_TOKEN", "env-jwt")

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
	if pc.GetAPIKey() != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q, want exchanged-jwt", pc.GetAPIKey())
	}
	if posts.Load() != 1 {
		t.Fatalf("openid POSTs = %d, want 1", posts.Load())
	}
	if gets.Load() != 1 {
		t.Fatalf("user/self GETs = %d, want 1", gets.Load())
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
	if cfg.(*providerConfig).GetAPIKey() != "static-key" {
		t.Fatalf("GetAPIKey() = %q, want static-key", cfg.(*providerConfig).GetAPIKey())
	}
	if posts.Load() != 0 {
		t.Fatalf("openid POSTs = %d, want 0", posts.Load())
	}
}

func TestProviderConfigure_OIDCIgnoresAmbientAPIKey(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "tfc",
		oidcToken:     "env-jwt",
		exchangeToken: "exchanged-jwt",
	})
	t.Setenv("CLOUDSMITH_API_KEY", "ambient-static")
	t.Setenv("CLOUDSMITH_OIDC_TOKEN", "env-jwt")

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
	if pc.GetAPIKey() != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q, want exchanged-jwt", pc.GetAPIKey())
	}
	if posts.Load() != 1 {
		t.Fatalf("openid POSTs = %d, want 1", posts.Load())
	}
	if gets.Load() != 1 {
		t.Fatalf("user/self GETs = %d, want 1", gets.Load())
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
	if cfg.(*providerConfig).GetAPIKey() != "static-key" {
		t.Fatalf("GetAPIKey() = %q, want static-key", cfg.(*providerConfig).GetAPIKey())
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
	if cfg.(*providerConfig).GetAPIKey() != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q", cfg.(*providerConfig).GetAPIKey())
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
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
	if cfg.(*providerConfig).GetAPIKey() != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q", cfg.(*providerConfig).GetAPIKey())
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
	}
}

func TestProviderConfigure_GitHubActionsMint(t *testing.T) {
	clearOIDCEnv(t)
	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gha-req" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("audience") != "cloudsmith" {
			t.Errorf("audience = %q", r.URL.Query().Get("audience"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"value":"gha-jwt"}`)
	}))
	t.Cleanup(mint.Close)

	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "gha",
		oidcToken:     "gha-jwt",
		exchangeToken: "exchanged-jwt",
	})
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", mint.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gha-req")

	cfg, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "gha",
			},
		},
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	if cfg.(*providerConfig).GetAPIKey() != "exchanged-jwt" {
		t.Fatalf("GetAPIKey() = %q", cfg.(*providerConfig).GetAPIKey())
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
	}
}

func TestProviderConfigure_CircleCI(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "circle",
		oidcToken:     "circle-jwt",
		exchangeToken: "exchanged-jwt",
	})
	t.Setenv("CIRCLE_OIDC_TOKEN_V2", "circle-jwt")

	_, diags := configureProviderRaw(t, map[string]interface{}{
		"api_host": srv.URL + "/v1",
		"oidc": []interface{}{
			map[string]interface{}{
				"organization": "acme",
				"service_slug": "circle",
			},
		},
	})
	if diags.HasError() {
		t.Fatalf("%v", diags)
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
	}
}

func TestProviderConfigure_MixedAPIKeyAndOIDC(t *testing.T) {
	clearOIDCEnv(t)
	t.Setenv("CLOUDSMITH_OIDC_TOKEN", "env-jwt")

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
	assertNoSecret(t, diags, "static-key", "env-jwt")
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
	for _, name := range []string{"CLOUDSMITH_OIDC_TOKEN", "TFC_WORKLOAD_IDENTITY_TOKEN", "CIRCLE_OIDC_TOKEN", "BITBUCKET_STEP_OIDC_TOKEN"} {
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
		oidcToken:   "env-jwt",
		exchangeErr: http.StatusUnauthorized,
	})
	t.Setenv("CLOUDSMITH_OIDC_TOKEN", "env-jwt")

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
	assertNoSecret(t, diags, "env-jwt")
}

func TestProviderConfigure_ExchangeEmptyToken(t *testing.T) {
	clearOIDCEnv(t)
	srv, posts, gets := newAuthServer(t, authServerOpts{
		org:           "acme",
		serviceSlug:   "tfc",
		oidcToken:     "env-jwt",
		exchangeToken: "",
	})
	t.Setenv("CLOUDSMITH_OIDC_TOKEN", "env-jwt")

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
			if r.Header.Get("X-Api-Key") == "jwt-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
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
	t.Setenv("CLOUDSMITH_OIDC_TOKEN", "env-jwt")

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
	if cfg.(*providerConfig).GetAPIKey() != "jwt-2" {
		t.Fatalf("GetAPIKey() = %q, want jwt-2", cfg.(*providerConfig).GetAPIKey())
	}
	if posts.Load() != 2 {
		t.Fatalf("openid POSTs = %d, want 2", posts.Load())
	}
	if gets.Load() != 2 {
		t.Fatalf("user/self GETs = %d, want 2", gets.Load())
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
		"CLOUDSMITH_OIDC_TOKEN",
		"CLOUDSMITH_OIDC_TOKEN_FILE",
		"CLOUDSMITH_OIDC_REQUEST_URL",
		"CLOUDSMITH_OIDC_REQUEST_TOKEN",
		"CLOUDSMITH_OIDC_AUDIENCE",
		"TFC_WORKLOAD_IDENTITY_TOKEN_CLOUDSMITH",
		"TFC_WORKLOAD_IDENTITY_TOKEN",
		"ACTIONS_ID_TOKEN_REQUEST_URL",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
		"SYSTEM_OIDCREQUESTURI",
		"SYSTEM_ACCESSTOKEN",
		"CIRCLE_OIDC_TOKEN_V2",
		"CIRCLE_OIDC_TOKEN",
		"BITBUCKET_STEP_OIDC_TOKEN",
		"CLOUDSMITH_ADO_SERVICE_CONNECTION_ID",
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

func TestCredentialIsNotSentToOtherHosts(t *testing.T) {
	var apiKeys []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKeys = append(apiKeys, r.Header.Get("X-Api-Key"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"email":"sa@example.com","name":"tfc","slug":"tfc","slug_perm":"tfc"}`)
	}))
	t.Cleanup(api.Close)

	// Stands in for dl.cloudsmith.io and the object storage it redirects to.
	var cdnKey string
	var cdnKeySet bool
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnKey, cdnKeySet = r.Header.Get("X-Api-Key"), true
		fmt.Fprint(w, "package-bytes")
	}))
	t.Cleanup(cdn.Close)

	pc, diags := newProviderConfig(context.Background(), api.URL, staticToken("valid-token"), map[string]interface{}{}, "test-agent")
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if len(apiKeys) == 0 || apiKeys[0] != "valid-token" {
		t.Fatalf("api host X-Api-Key = %v, want the credential to be sent", apiKeys)
	}

	// The package data source downloads through this same shared client.
	resp, err := pc.APIClient.GetConfig().HTTPClient.Get(cdn.URL + "/package.tgz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !cdnKeySet {
		t.Fatal("download request never reached the test server")
	}
	if cdnKey != "" {
		t.Fatalf("X-Api-Key sent to a non-API host = %q, want it withheld", cdnKey)
	}
}

func TestOpaqueExchangeTokenStillRefreshes(t *testing.T) {
	var exchanges atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"opaque-not-a-jwt"}`)
	}))
	t.Cleanup(srv.Close)

	current := time.Now()
	src := &oidcTokenSource{
		identity: oidcIdentity{organization: "acme-org", serviceSlug: "ci-prod"},
		apiHost:  srv.URL,
		getenv:   func(k string) string { return map[string]string{"CLOUDSMITH_OIDC_TOKEN": "env-jwt"}[k] },
		readFile: os.ReadFile,
		client:   srv.Client(),
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
