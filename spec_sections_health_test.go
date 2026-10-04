package simpleidp

// Reference material:
// Simple IdP: README.md

import (
	"net/http"
	"net/url"
	"testing"
)

func testHealthcheck(t *testing.T) {
	t.Run("responds without content", func(t *testing.T) {
		for _, issuerPath := range []string{"", "/tenant/issuer/", "/healthz"} {
			t.Run(issuerPath, func(t *testing.T) {
				config := defaultProviderConfig()
				config.IssuerPath = issuerPath
				provider := startProvider(t, config)
				endpoint, err := url.Parse(provider.issuer)
				if err != nil {
					t.Fatalf("invalid issuer URL: %v", err)
				}
				endpoint.Path = "/healthz"
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					t.Run(method, func(t *testing.T) {
						req, err := http.NewRequest(method, endpoint.String(), nil)
						if err != nil {
							t.Fatalf("failed to create healthcheck request: %v", err)
						}
						resp := provider.do(t, provider.redirectless, req)
						body := readBody(t, resp)
						if resp.StatusCode != http.StatusNoContent {
							t.Fatalf("healthcheck status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusNoContent, body)
						}
						if len(body) != 0 {
							t.Fatalf("healthcheck must have no response body, got %q", body)
						}
						if resp.Header.Get("Location") != "" || len(resp.Cookies()) != 0 {
							t.Fatal("healthcheck must not redirect or establish a session")
						}
					})
				}
			})
		}
	})

	t.Run("rejects other methods", func(t *testing.T) {
		for _, issuerPath := range []string{"", "/tenant/issuer/", "/healthz"} {
			t.Run(issuerPath, func(t *testing.T) {
				config := defaultProviderConfig()
				config.IssuerPath = issuerPath
				provider := startProvider(t, config)
				endpoint, err := url.Parse(provider.issuer)
				if err != nil {
					t.Fatalf("invalid issuer URL: %v", err)
				}
				endpoint.Path = "/healthz"
				req, err := http.NewRequest(http.MethodPost, endpoint.String(), nil)
				if err != nil {
					t.Fatalf("failed to create healthcheck request: %v", err)
				}
				resp := provider.do(t, provider.redirectless, req)
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusMethodNotAllowed {
					t.Fatalf("healthcheck status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusMethodNotAllowed, body)
				}
			})
		}
	})
}
