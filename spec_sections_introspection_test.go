package simpleidp

// Reference material:
// RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.txt

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func testIntrospectionEndpoint(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("introspection-endpoint")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	resp := provider.postIntrospect(t, introspectionRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		Token:        token.AccessToken,
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspection status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("content type mismatch: got %q", got)
	}
}

func testIntrospectionRequest(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("requires the token parameter", func(t *testing.T) {
		errResp := expectJSONError(t, provider.postIntrospect(t, introspectionRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("rejects duplicate token parameters", func(t *testing.T) {
		form := url.Values{
			"token": {"first", "second"},
		}
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/introspect"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create introspection request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(webClientID), url.QueryEscape(webClientSecret))

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("returns invalid_request for malformed request bodies", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/introspect"), strings.NewReader("token=%zz"))
		if err != nil {
			t.Fatalf("failed to create introspection request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("returns invalid_request for multiple client authentication methods", func(t *testing.T) {
		form := url.Values{
			"token":         {"any-token"},
			"client_id":     {webClientID},
			"client_secret": {webClientSecret},
		}
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/introspect"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create introspection request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(webClientID), url.QueryEscape(webClientSecret))

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("does not rely on token_type_hint when looking up access tokens", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-token-type-hint")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		response := introspectToken(t, provider, introspectionRequest{
			ClientID:      request.ClientID,
			ClientSecret:  webClientSecret,
			Token:         token.AccessToken,
			TokenTypeHint: "refresh_token",
		})
		if !response.Active {
			t.Fatalf("expected active token response, got %#v", response)
		}
	})

	t.Run("does not rely on token_type_hint when looking up refresh tokens", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-refresh-token-type-hint")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		response := introspectToken(t, provider, introspectionRequest{
			ClientID:      request.ClientID,
			ClientSecret:  webClientSecret,
			Token:         token.RefreshToken,
			TokenTypeHint: "access_token",
		})
		if !response.Active {
			t.Fatalf("expected active token response, got %#v", response)
		}
	})
}

func testIntrospectionResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("returns an active response for valid access tokens", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-response")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		response := introspectToken(t, provider, introspectionRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Token:        token.AccessToken,
		})
		if !response.Active {
			t.Fatalf("expected active token response, got %#v", response)
		}
		if response.Scope != "" && response.Scope != request.Scope {
			t.Fatalf("scope mismatch: got %q, want %q", response.Scope, request.Scope)
		}
		if response.ClientID != "" && response.ClientID != request.ClientID {
			t.Fatalf("client_id mismatch: got %q, want %q", response.ClientID, request.ClientID)
		}
		if response.TokenType != "" && response.TokenType != "Bearer" {
			t.Fatalf("token_type mismatch: got %q, want %q", response.TokenType, "Bearer")
		}
		if response.Exp != 0 && response.Exp <= time.Now().Unix() {
			t.Fatalf("expected exp in the future, got %d", response.Exp)
		}
	})

	t.Run("returns an active response for valid refresh tokens", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-refresh-response")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		response := introspectToken(t, provider, introspectionRequest{
			ClientID:      request.ClientID,
			ClientSecret:  webClientSecret,
			Token:         token.RefreshToken,
			TokenTypeHint: "access_token",
		})
		if !response.Active {
			t.Fatalf("expected active token response, got %#v", response)
		}
		if response.Scope != "" && response.Scope != request.Scope {
			t.Fatalf("scope mismatch: got %q, want %q", response.Scope, request.Scope)
		}
		if response.ClientID != "" && response.ClientID != request.ClientID {
			t.Fatalf("client_id mismatch: got %q, want %q", response.ClientID, request.ClientID)
		}
		if response.Iss != provider.issuer {
			t.Fatalf("issuer mismatch: got %q, want %q", response.Iss, provider.issuer)
		}
		if response.Sub != testSubject {
			t.Fatalf("subject mismatch: got %q, want %q", response.Sub, testSubject)
		}
		if response.Exp != 0 && response.Exp <= time.Now().Unix() {
			t.Fatalf("expected exp in the future, got %d", response.Exp)
		}
	})

	t.Run("returns only active false for unknown tokens", func(t *testing.T) {
		resp := provider.postIntrospect(t, introspectionRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			Token:        "unknown-token",
		})
		expectInactiveIntrospectionResponse(t, resp)
	})
}

func testIntrospectionErrorResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("returns invalid_client when protected-resource authentication is missing", func(t *testing.T) {
		resp := provider.postIntrospect(t, introspectionRequest{Token: "any-token"})
		errResp := expectJSONError(t, resp, http.StatusUnauthorized)
		if errResp.Error != "invalid_client" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_client")
		}
	})

	t.Run("returns invalid_client for failed protected-resource authentication", func(t *testing.T) {
		resp := provider.postIntrospect(t, introspectionRequest{
			ClientID:     webClientID,
			ClientSecret: "wrong-secret",
			Token:        "any-token",
		})
		errResp := expectJSONError(t, resp, http.StatusUnauthorized)
		if errResp.Error != "invalid_client" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_client")
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="token"` {
			t.Fatalf("expected basic challenge, got %q", got)
		}
	})
}

func testIntrospectionSecurityConsiderations(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("returns only active false for tokens issued to a different client", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-other-client")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		resp := provider.postIntrospect(t, introspectionRequest{
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
			Token:        token.AccessToken,
		})
		expectInactiveIntrospectionResponse(t, resp)
	})

	t.Run("returns only active false for expired access tokens", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-expired-token")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		provider.expireAccessToken(t, token.AccessToken)

		resp := provider.postIntrospect(t, introspectionRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Token:        token.AccessToken,
		})
		expectInactiveIntrospectionResponse(t, resp)
	})

	t.Run("returns only active false for expired refresh tokens", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-expired-refresh-token")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		provider.expireRefreshTokenIdle(t, token.RefreshToken)

		resp := provider.postIntrospect(t, introspectionRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Token:        token.RefreshToken,
		})
		expectInactiveIntrospectionResponse(t, resp)
	})

	t.Run("returns only active false after logout revokes the token", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		redirect := expectRedirect(t, submitConsentForm(t, fixture.provider, fixture.formBody, "yes"), http.StatusSeeOther)
		assertRedirectTarget(t, redirect, webClientPostLogoutRedirect)

		resp := fixture.provider.postIntrospect(t, introspectionRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			Token:        fixture.token.AccessToken,
		})
		expectInactiveIntrospectionResponse(t, resp)
	})
}

func testIntrospectionPrivacyConsiderations(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("does not disclose claims to protected resources that are not allowed to introspect the token", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-privacy-other-client")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		resp := provider.postIntrospect(t, introspectionRequest{
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
			Token:        token.AccessToken,
		})
		expectInactiveIntrospectionResponse(t, resp)
	})

	t.Run("does not disclose claims for inactive tokens", func(t *testing.T) {
		resp := provider.postIntrospect(t, introspectionRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			Token:        "unknown-token",
		})
		expectInactiveIntrospectionResponse(t, resp)
	})
}

func expectInactiveIntrospectionResponse(t *testing.T, resp *http.Response) {
	t.Helper()

	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspection status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	payload := decodeJSONMap(t, body)
	if payload["active"] != false {
		t.Fatalf("expected inactive response, got %#v", payload)
	}
	if len(payload) != 1 {
		t.Fatalf("expected only active=false for inactive response, got %#v", payload)
	}
}

func TestIntrospectionImplementationClaims(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("introspection-implementation-claims")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	response := introspectToken(t, provider, introspectionRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		Token:        token.AccessToken,
	})
	if !response.Active {
		t.Fatalf("expected active token response, got %#v", response)
	}
	if response.Scope != request.Scope {
		t.Fatalf("scope mismatch: got %q, want %q", response.Scope, request.Scope)
	}
	if response.ClientID != request.ClientID {
		t.Fatalf("client_id mismatch: got %q, want %q", response.ClientID, request.ClientID)
	}
	if response.TokenType != "Bearer" {
		t.Fatalf("token_type mismatch: got %q, want %q", response.TokenType, "Bearer")
	}
	if response.Exp <= time.Now().Unix() {
		t.Fatalf("expected exp in the future, got %d", response.Exp)
	}
	if response.Iss != provider.issuer {
		t.Fatalf("issuer mismatch: got %q, want %q", response.Iss, provider.issuer)
	}
	if response.Sub != testSubject {
		t.Fatalf("subject mismatch: got %q, want %q", response.Sub, testSubject)
	}
	if response.Name != testName || response.PreferredUsername != testPreferredUsername {
		t.Fatalf("unexpected profile claims: %#v", response)
	}
	if response.Email != testEmail || !response.EmailVerified {
		t.Fatalf("unexpected email claims: %#v", response)
	}
	if response.Profile != testProfile || response.Picture != testPicture || response.Locale != testLocale {
		t.Fatalf("unexpected profile metadata: %#v", response)
	}
	if !slices.Equal(response.Groups, testGroups) {
		t.Fatalf("groups mismatch: got %#v, want %#v", response.Groups, testGroups)
	}
}
