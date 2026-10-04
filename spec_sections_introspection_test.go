package simpleidp

// Reference material:
// RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.txt

import (
	"encoding/json/v2"
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
	assertMediaType(t, resp.Header.Get("Content-Type"), "application/json")
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

	t.Run("rejects an empty token parameter", func(t *testing.T) {
		form := url.Values{
			"client_id":     {webClientID},
			"client_secret": {webClientSecret},
			"token":         {""},
		}
		errResp := expectJSONError(t, provider.postFormURL(t, provider.endpoint("/introspect"), form, "", false), http.StatusBadRequest)
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

		errResp := expectJSONError(t, provider.do(t, provider.redirectless, req), http.StatusBadRequest)
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

		errResp := expectJSONError(t, provider.do(t, provider.redirectless, req), http.StatusBadRequest)
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

		errResp := expectJSONError(t, provider.do(t, provider.redirectless, req), http.StatusBadRequest)
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
		if response.TokenType != "" && !strings.EqualFold(response.TokenType, "Bearer") {
			t.Fatalf("token_type mismatch: got %q, want %q", response.TokenType, "Bearer")
		}
		if response.Exp != 0 && response.Exp <= time.Now().Unix() {
			t.Fatalf("expected exp in the future, got %d", response.Exp)
		}
	})

	t.Run("includes the implemented members and claims for access tokens", func(t *testing.T) {
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
		if !strings.EqualFold(response.TokenType, "Bearer") {
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

	t.Run("rejects public clients without protected-resource authentication", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49173/callback",
			Scope:       "openid profile",
			State:       "public-client-introspection",
			Verifier:    pkceVerifier("public-client-introspection"),
		}
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			CodeVerifier: request.Verifier,
		})
		for tokenType, rawToken := range map[string]string{"access token": token.AccessToken, "refresh token": token.RefreshToken} {
			t.Run(tokenType, func(t *testing.T) {
				if rawToken == "" {
					t.Fatalf("expected %s, got %#v", tokenType, token)
				}
				resp := provider.postIntrospect(t, introspectionRequest{
					ClientID: request.ClientID,
					Token:    rawToken,
				})
				errResp := expectJSONError(t, resp, http.StatusUnauthorized)
				if errResp.Error != "invalid_client" {
					t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_client")
				}
			})
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

		for tokenType, value := range map[string]string{"access token": token.AccessToken, "refresh token": token.RefreshToken} {
			t.Run(tokenType, func(t *testing.T) {
				ownerResponse := introspectToken(t, provider, introspectionRequest{
					ClientID:     webClientID,
					ClientSecret: webClientSecret,
					Token:        value,
				})
				if !ownerResponse.Active {
					t.Fatal("expected a live token before testing introspection by another client")
				}
				resp := provider.postIntrospect(t, introspectionRequest{
					ClientID:     otherClientID,
					ClientSecret: otherClientSecret,
					Token:        value,
				})
				expectInactiveIntrospectionResponse(t, resp)
			})
		}
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
	config := defaultProviderConfig()
	roles := []string{"reader", "operator"}
	config.Users[0].Roles = roles
	provider := startProvider(t, config)

	t.Run("limits active responses to the token's granted scopes", func(t *testing.T) {
		for _, scope := range []string{"openid", "openid profile", "openid email", "openid groups", "openid roles", "openid profile email groups roles"} {
			t.Run(scope, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("introspection-privacy-scope-" + scope)
				request.Scope = scope
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				for tokenType, rawToken := range map[string]string{"access token": token.AccessToken, "refresh token": token.RefreshToken} {
					t.Run(tokenType, func(t *testing.T) {
						resp := provider.postIntrospect(t, introspectionRequest{
							ClientID:     request.ClientID,
							ClientSecret: webClientSecret,
							Token:        rawToken,
						})
						expectScopedIntrospectionResponse(t, resp, scope, roles)
					})
				}
			})
		}
	})

	t.Run("uses the reduced access scope and original refresh scope after refresh", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("introspection-privacy-refresh-scope")
		request.Scope = "openid profile email groups roles"
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
			Scope:        "openid",
		})
		for _, token := range []struct {
			name  string
			value string
			scope string
		}{
			{"access token", refreshed.AccessToken, "openid"},
			{"refresh token", refreshed.RefreshToken, request.Scope},
		} {
			t.Run(token.name, func(t *testing.T) {
				resp := provider.postIntrospect(t, introspectionRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					Token:        token.value,
				})
				expectScopedIntrospectionResponse(t, resp, token.scope, roles)
			})
		}
	})

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

func expectScopedIntrospectionResponse(t *testing.T, resp *http.Response, scope string, roles []string) {
	t.Helper()

	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspection status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	claims := decodeJSONMap(t, body)
	if claims["active"] != true || claims["sub"] != testSubject || claims["scope"] != scope {
		t.Fatalf("unexpected introspection response: %#v", claims)
	}
	for scopeName, expected := range map[string]map[string]any{
		"profile": {
			"name": testName, "preferred_username": testPreferredUsername,
			"profile": testProfile, "picture": testPicture, "locale": testLocale,
		},
		"email": {"email": testEmail, "email_verified": true},
	} {
		granted := slices.Contains(strings.Fields(scope), scopeName)
		for name, want := range expected {
			value, present := claims[name]
			if present != granted || (granted && value != want) {
				t.Fatalf("claim %s for scope %q: got %#v (present=%t), want %#v (present=%t)", name, scope, value, present, want, granted)
			}
		}
	}
	var response introspectionResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("failed to decode introspection response: %v\nbody=%s", err, body)
	}
	for _, claim := range []struct {
		name string
		got  []string
		want []string
	}{
		{"groups", response.Groups, testGroups},
		{"roles", response.Roles, roles},
	} {
		granted := slices.Contains(strings.Fields(scope), claim.name)
		_, present := claims[claim.name]
		if present != granted || (granted && !slices.Equal(claim.got, claim.want)) {
			t.Fatalf("claim %s for scope %q: got %#v (present=%t), want %#v (present=%t)", claim.name, scope, claim.got, present, claim.want, granted)
		}
	}
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
