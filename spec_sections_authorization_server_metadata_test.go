package simpleidp

// Reference material:
// RFC 8414: https://www.rfc-editor.org/rfc/rfc8414.txt
// OIDC Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html

import (
	"encoding/json/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func testAuthorizationServerMetadata(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	resp, body := fetchAuthorizationServerMetadataResponse(t, provider)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	payload := decodeJSONMap(t, body)
	var metadata discoveryDocument
	if err := json.Unmarshal(body, &metadata); err != nil {
		t.Fatalf("failed to decode metadata response: %v\nbody=%s", err, body)
	}

	t.Run("publishes the required and recommended metadata", func(t *testing.T) {
		for _, name := range []string{"issuer", "authorization_endpoint", "token_endpoint", "response_types_supported", "scopes_supported"} {
			if _, ok := payload[name]; !ok {
				t.Fatalf("expected metadata field %q in %#v", name, payload)
			}
		}
	})

	t.Run("publishes the endpoint locations", func(t *testing.T) {
		for _, endpoint := range []struct {
			name string
			got  string
			want string
		}{
			{name: "authorization_endpoint", got: metadata.AuthorizationEndpoint, want: provider.endpoint("/authorize")},
			{name: "token_endpoint", got: metadata.TokenEndpoint, want: provider.endpoint("/token")},
			{name: "jwks_uri", got: metadata.JWKSURI, want: provider.endpoint("/jwks")},
			{name: "revocation_endpoint", got: metadata.RevocationEndpoint, want: provider.endpoint("/revoke")},
			{name: "introspection_endpoint", got: metadata.IntrospectionEndpoint, want: provider.endpoint("/introspect")},
		} {
			if endpoint.got != endpoint.want {
				t.Fatalf("%s mismatch: got %q, want %q", endpoint.name, endpoint.got, endpoint.want)
			}
		}
	})

	t.Run("publishes the client authentication methods of each endpoint", func(t *testing.T) {
		for _, methods := range []struct {
			name string
			got  []string
			want []string
		}{
			{name: "token_endpoint_auth_methods_supported", got: metadata.TokenEndpointAuthMethodsSupported, want: []string{"client_secret_basic", "client_secret_post", "none"}},
			{name: "revocation_endpoint_auth_methods_supported", got: metadata.RevocationEndpointAuthMethodsSupported, want: []string{"client_secret_basic", "client_secret_post", "none"}},
			{name: "introspection_endpoint_auth_methods_supported", got: metadata.IntrospectionEndpointAuthMethodsSupported, want: []string{"client_secret_basic", "client_secret_post"}},
		} {
			if !slices.Equal(slices.Sorted(slices.Values(methods.got)), methods.want) {
				t.Fatalf("unexpected %s: %#v", methods.name, methods.got)
			}
		}
	})

	t.Run("publishes the supported grants and PKCE methods", func(t *testing.T) {
		if got := slices.Sorted(slices.Values(metadata.GrantTypesSupported)); !slices.Equal(got, []string{"authorization_code", "client_credentials", "refresh_token"}) {
			t.Fatalf("unexpected supported grant types: %#v", metadata.GrantTypesSupported)
		}
		if !slices.Equal(metadata.ResponseModesSupported, []string{"query"}) {
			t.Fatalf("unexpected supported response modes: %#v", metadata.ResponseModesSupported)
		}
		if !slices.Equal(metadata.CodeChallengeMethodsSupported, []string{"S256"}) {
			t.Fatalf("unexpected supported code challenge methods: %#v", metadata.CodeChallengeMethodsSupported)
		}
	})

	t.Run("omits metadata for unsupported features", func(t *testing.T) {
		for _, name := range []string{
			"registration_endpoint",
			"signed_metadata",
			"token_endpoint_auth_signing_alg_values_supported",
			"revocation_endpoint_auth_signing_alg_values_supported",
			"introspection_endpoint_auth_signing_alg_values_supported",
		} {
			if value, ok := payload[name]; ok {
				t.Fatalf("did not expect metadata field %q, got %#v", name, value)
			}
		}
	})
}

func testObtainingAuthorizationServerMetadata(t *testing.T) {
	t.Run("inserts the well-known path before the issuer path", func(t *testing.T) {
		for _, testCase := range []struct {
			name       string
			issuerPath string
			wellKnown  string
		}{
			{name: "without an issuer path", wellKnown: "/.well-known/oauth-authorization-server"},
			{name: "with an issuer path", issuerPath: "/issuer1", wellKnown: "/.well-known/oauth-authorization-server/issuer1"},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				config := defaultProviderConfig()
				config.IssuerPath = testCase.issuerPath
				provider := startProvider(t, config)
				issuerURL, err := url.Parse(provider.issuer)
				if err != nil {
					t.Fatalf("failed to parse issuer: %v", err)
				}
				if got, want := authorizationServerMetadataURL(t, provider.issuer), "http://"+issuerURL.Host+testCase.wellKnown; got != want {
					t.Fatalf("metadata URL mismatch: got %q, want %q", got, want)
				}
				resp, body := fetchAuthorizationServerMetadataResponse(t, provider)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("metadata status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
				}
			})
		}
	})

	t.Run("does not append the well-known path to the issuer", func(t *testing.T) {
		config := defaultProviderConfig()
		config.IssuerPath = "/issuer1"
		provider := startProvider(t, config)
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/.well-known/oauth-authorization-server"), nil)
		if err != nil {
			t.Fatalf("failed to create metadata request: %v", err)
		}
		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("appended metadata status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusNotFound, body)
		}
	})

}

func testAuthorizationServerMetadataRequest(t *testing.T) {
	t.Run("serves the metadata to GET requests", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		resp, body := fetchAuthorizationServerMetadataResponse(t, provider)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("metadata status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("removes a terminating slash from the issuer path", func(t *testing.T) {
		config := defaultProviderConfig()
		config.IssuerPath = "/tenant/issuer/"
		provider := startProvider(t, config)
		if got := authorizationServerMetadataURL(t, provider.issuer); !strings.HasSuffix(got, "/.well-known/oauth-authorization-server/tenant/issuer") {
			t.Fatalf("unexpected metadata URL: %q", got)
		}
		resp, body := fetchAuthorizationServerMetadataResponse(t, provider)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("metadata status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("rejects other methods", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		resp := provider.postFormURL(t, authorizationServerMetadataURL(t, provider.issuer), url.Values{}, "", false)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("metadata status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusMethodNotAllowed, body)
		}
	})
}

func testAuthorizationServerMetadataResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	resp, body := fetchAuthorizationServerMetadataResponse(t, provider)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	assertMediaType(t, resp.Header.Get("Content-Type"), "application/json")
	for name, value := range decodeJSONMap(t, body) {
		if values, ok := value.([]any); ok && len(values) == 0 {
			t.Fatalf("expected metadata field %q with zero elements to be omitted", name)
		}
	}
}

func testAuthorizationServerMetadataValidation(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		issuerPath string
	}{
		{name: "without an issuer path"},
		{name: "with an issuer path", issuerPath: "/tenant-a"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := defaultProviderConfig()
			config.IssuerPath = testCase.issuerPath
			provider := startProvider(t, config)
			_, body := fetchAuthorizationServerMetadataResponse(t, provider)
			if issuer := decodeJSONMap(t, body)["issuer"]; issuer != provider.issuer {
				t.Fatalf("metadata issuer mismatch: got %#v, want %q", issuer, provider.issuer)
			}
		})
	}
}

func testAuthorizationServerMetadataCompatibility(t *testing.T) {
	config := defaultProviderConfig()
	config.IssuerPath = "/issuer1"
	provider := startProvider(t, config)
	_, metadataBody := fetchAuthorizationServerMetadataResponse(t, provider)
	_, discoveryBody := fetchDiscoveryResponse(t, provider)

	if string(metadataBody) != string(discoveryBody) {
		t.Fatalf("metadata mismatch between locations:\nauthorization server metadata=%s\nopenid configuration=%s", metadataBody, discoveryBody)
	}
}

func authorizationServerMetadataURL(t *testing.T, issuer string) string {
	t.Helper()

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		t.Fatalf("failed to parse issuer: %v", err)
	}
	issuerURL.Path = "/.well-known/oauth-authorization-server" + strings.TrimRight(issuerURL.Path, "/")
	return issuerURL.String()
}

func fetchAuthorizationServerMetadataResponse(t *testing.T, provider *providerProcess) (*http.Response, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, authorizationServerMetadataURL(t, provider.issuer), nil)
	if err != nil {
		t.Fatalf("failed to create metadata request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	return resp, readBody(t, resp)
}
