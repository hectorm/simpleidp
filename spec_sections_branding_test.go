package simpleidp

// Reference material:
// Simple IdP: README.md

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func testBranding(t *testing.T) {
	t.Run("shows the title when no logo is configured", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		body := fetchLoginForm(t, provider)
		if got := extractPageTitle(t, body); got != testTitle {
			t.Fatalf("page title mismatch: got %q, want %q", got, testTitle)
		}
		for _, unexpected := range []string{"<img", `data-testid="logo"`, `rel="icon"`} {
			if strings.Contains(string(body), unexpected) {
				t.Fatalf("unexpected branding content %q, got body=%s", unexpected, body)
			}
		}
	})

	t.Run("replaces the title with the logo on every page", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			logo string
		}{
			{name: "https", logo: "https://cdn.example.com/logo.svg?v=1&theme=dark"},
			{name: "data URI", logo: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4="},
		} {
			t.Run(tc.name, func(t *testing.T) {
				config := defaultProviderConfig()
				config.Logo = tc.logo
				provider := startProvider(t, config)

				req, err := http.NewRequest(http.MethodGet, provider.endpoint("/login"), nil)
				if err != nil {
					t.Fatalf("failed to create login request: %v", err)
				}
				resp := provider.do(t, provider.redirectless, req)
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("login page status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
				}
				expectLogo(t, body, tc.logo)
				if !strings.Contains(string(body), "<title>"+testTitle+"</title>") {
					t.Fatalf("expected the document title to keep the configured title, got body=%s", body)
				}
				if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "img-src 'self' data: https: http:") {
					t.Fatalf("expected the CSP to allow the logo, got %q", csp)
				}

				_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("branding-logo"))
				expectLogo(t, fetchProfilePage(t, provider), tc.logo)

				request := newDefaultConfidentialAuthorizationRequest("branding-consent")
				request.Prompt = "consent"
				resp = provider.getAuthorize(t, authorizeParams(request))
				body = readBody(t, resp)
				if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-testid="page-consent"`) {
					t.Fatalf("expected consent form, got %s; body=%s", resp.Status, body)
				}
				expectLogo(t, body, tc.logo)

				expectLogo(t, fetchLogoutForm(t, provider, url.Values{}), tc.logo)
			})
		}
	})

	t.Run("escapes the logo URL in the page markup", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Logo = `https://cdn.example.com/logo.svg" onerror="alert(1)`
		provider := startProvider(t, config)
		src, _ := extractLogo(t, fetchLoginForm(t, provider))
		if !strings.HasPrefix(src, "https://cdn.example.com/logo.svg") || strings.Contains(src, `"`) {
			t.Fatalf("expected the logo URL to stay inside its attribute, got %q", src)
		}
	})

	t.Run("links the configured favicon", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Favicon = "https://cdn.example.com/favicon.svg?v=1&theme=dark"
		provider := startProvider(t, config)
		body := fetchLoginForm(t, provider)
		if got := extractFavicon(t, body); got != config.Favicon {
			t.Fatalf("favicon mismatch: got %q, want %q", got, config.Favicon)
		}
		if got := extractPageTitle(t, body); got != testTitle {
			t.Fatalf("page title mismatch: got %q, want %q", got, testTitle)
		}
	})

	t.Run("applies the configured color scheme", func(t *testing.T) {
		for _, testCase := range []struct {
			name        string
			colorScheme string
			want        string
		}{
			{name: "default", want: "light dark"},
			{name: "configured", colorScheme: "only light", want: "only light"},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				config := defaultProviderConfig()
				config.ColorScheme = testCase.colorScheme
				provider := startProvider(t, config)
				body := fetchLoginForm(t, provider)
				for _, want := range []string{
					`<meta name="color-scheme" content="` + testCase.want + `">`,
					"color-scheme: " + testCase.want + ";",
				} {
					if !strings.Contains(string(body), want) {
						t.Fatalf("expected color scheme %q, got body=%s", want, body)
					}
				}
			})
		}
	})
}

func extractLogo(t *testing.T, body []byte) (src, alt string) {
	t.Helper()

	title := extractPageTitle(t, body)
	matches := regexp.MustCompile(`^<img src="([^"]*)" alt="([^"]*)" data-testid="logo">$`).FindStringSubmatch(title)
	if len(matches) != 3 {
		t.Fatalf("failed to extract logo from page title %q", title)
	}
	return html.UnescapeString(matches[1]), html.UnescapeString(matches[2])
}

func extractFavicon(t *testing.T, body []byte) string {
	t.Helper()

	matches := regexp.MustCompile(`<link rel="icon" href="([^"]*)">`).FindSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("failed to extract favicon from body:\n%s", body)
	}
	return html.UnescapeString(string(matches[1]))
}

func expectLogo(t *testing.T, body []byte, logo string) {
	t.Helper()

	src, alt := extractLogo(t, body)
	if src != logo {
		t.Fatalf("logo source mismatch: got %q, want %q", src, logo)
	}
	if alt != testTitle {
		t.Fatalf("logo alternative text mismatch: got %q, want %q", alt, testTitle)
	}
}
