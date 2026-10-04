package simpleidp

// Reference material:
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt

import (
	"encoding/json/v2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func testOAuth21ClientTypes(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("confidential clients authenticate with a client secret", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-client-types-confidential")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		if token.AccessToken == "" {
			t.Fatalf("expected access token, got %#v", token)
		}
	})

	t.Run("native loopback clients behave as public clients", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49200/callback",
			Scope:       "openid profile",
			State:       "oauth21-client-types-public",
			Verifier:    pkceVerifier("oauth21-client-types-public"),
		}
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		if token.AccessToken == "" {
			t.Fatalf("expected access token, got %#v", token)
		}
	})
}

func testOAuth21ClientIdentifier(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("rejects duplicate configured client identifiers", func(t *testing.T) {
		environ := []string{
			"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
			"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
			"SIMPLE_IDP_CLIENT_OTHER_ID=" + webClientID,
			"SIMPLE_IDP_CLIENT_OTHER_SECRET=" + otherClientSecret,
		}
		_, err := loadClients(environ, func(name string) string {
			for _, item := range environ {
				key, value, _ := strings.Cut(item, "=")
				if key == name {
					return value
				}
			}
			return ""
		})
		if err == nil || !strings.Contains(err.Error(), "duplicate client ID") {
			t.Fatalf("expected duplicate client identifier error, got %v", err)
		}
	})

	t.Run("rejects incomplete client configuration for every supported field", func(t *testing.T) {
		for _, field := range []string{
			"ID", "SECRET", "AUDIENCE", "REDIRECT_URL", "POST_LOGOUT_REDIRECT_URL",
			"BACKCHANNEL_LOGOUT_URI", "BACKCHANNEL_LOGOUT_SESSION_REQUIRED",
		} {
			t.Run(field, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
					"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
					"SIMPLE_IDP_CLIENT_WEB_REDIRECT_URL=" + webClientRedirect,
					"SIMPLE_IDP_CLIENT_OTHER_" + field + "=other",
				}
				_, err := loadClients(environ, func(name string) string {
					for _, item := range environ {
						key, value, _ := strings.Cut(item, "=")
						if key == name {
							return value
						}
					}
					return ""
				})
				if err == nil || !strings.Contains(err.Error(), "incomplete client configuration") {
					t.Fatalf("expected incomplete client configuration error, got %v", err)
				}
			})
		}
	})

	t.Run("rejects unknown clients at the authorization endpoint", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-client-identifier-auth")
		request.ClientID = "unknown-client"

		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
	})

	t.Run("rejects unknown clients at the token endpoint", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-client-identifier-token")
		authorization := authorizeAndLogin(t, provider, request)
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     "unknown-client",
			ClientSecret: "wrong-secret",
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		}), http.StatusUnauthorized)
		if errResp.Error != "invalid_client" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_client")
		}
	})
}

func testOAuth21RegistrationRequirements(t *testing.T) {
	t.Run("rejects invalid registered redirect uris", func(t *testing.T) {
		for _, redirectURL := range []string{
			"http://127.0.0.1/callback#fragment",
			"http://127.0.0.1/callback#",
			"/callback",
			"https:/callback",
			"https:///callback",
			"ftp://127.0.0.1/callback",
			"http://user:password@127.0.0.1/callback",
			"http://127.0.0.1/%invalid",
		} {
			t.Run(redirectURL, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
					"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
					"SIMPLE_IDP_CLIENT_WEB_REDIRECT_URL=" + redirectURL,
				}
				_, err := loadClients(environ, func(name string) string {
					for _, item := range environ {
						key, value, _ := strings.Cut(item, "=")
						if key == name {
							return value
						}
					}
					return ""
				})
				if err == nil || !strings.Contains(err.Error(), "redirect URL") {
					t.Fatalf("expected invalid redirect URL error, got %v", err)
				}
			})
		}
	})
}

func testOAuth21PreventingCSRFAttacks(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("round-trips state on successful authorization responses", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-csrf-state")
		request.State = "oauth21-csrf-state-value"
		authorization := authorizeAndLogin(t, provider, request)
		if authorization.State != request.State {
			t.Fatalf("state mismatch: got %q, want %q", authorization.State, request.State)
		}
	})

	t.Run("enforces PKCE inputs that protect authorization code exchanges", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-csrf-pkce")
		params := authorizeParams(request)
		params.Del("code_challenge")

		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
	})
}

func testOAuth21PreventingMixUpAttacks(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	discovery := fetchDiscovery(t, provider)
	request := newDefaultConfidentialAuthorizationRequest("oauth21-mixup")
	authorization := authorizeAndLogin(t, provider, request)

	if !discovery.AuthorizationResponseIssParameterSupported {
		t.Fatal("expected authorization_response_iss_parameter_supported")
	}
	if authorization.Issuer != discovery.Issuer {
		t.Fatalf("issuer mismatch: got %q, want %q", authorization.Issuer, discovery.Issuer)
	}
}

func testOAuth21InvalidEndpoint(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	for _, clientID := range []string{webClientID, nativeClientID} {
		t.Run(clientID, func(t *testing.T) {
			for _, redirectURI := range []string{
				"http://127.0.0.1/unregistered/callback",
				"HTTP://127.0.0.1/callback",
				"HTTP://127.0.0.1:49204/callback",
				"https://127.0.0.1/callback",
				"http://localhost/callback",
				"http://127.0.0.1/Callback",
				"http://127.0.0.1/%63allback",
				"http://127.0.0.1:49204/%63allback",
				"http://127.0.0.1:49204/callback?tenant=alpha",
				webClientRedirect + "?tenant=alpha",
				webClientRedirect + "?",
				webClientRedirect + "#fragment",
				webClientRedirect + "#",
			} {
				t.Run(redirectURI, func(t *testing.T) {
					request := newDefaultConfidentialAuthorizationRequest("oauth21-invalid-endpoint")
					request.ClientID = clientID
					request.RedirectURI = redirectURI
					resp := provider.getAuthorize(t, authorizeParams(request))
					body := readBody(t, resp)
					if resp.StatusCode != http.StatusBadRequest {
						t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
					}
					if resp.Header.Get("Location") != "" {
						t.Fatalf("did not expect redirect location, got %q", resp.Header.Get("Location"))
					}
				})
			}
		})
	}

	t.Run("compares registered query strings without normalization", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Clients[0].RedirectURL = webClientRedirect + "?tenant=alpha&tag=one&tag=two"
		provider := startProvider(t, config)
		for _, redirectURI := range []string{
			webClientRedirect,
			webClientRedirect + "?tag=one&tag=two&tenant=alpha",
			webClientRedirect + "?tenant=%61lpha&tag=one&tag=two",
			webClientRedirect + "?tenant=alpha&tag=two&tag=one",
		} {
			t.Run(redirectURI, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("oauth21-invalid-endpoint-query")
				request.RedirectURI = redirectURI
				resp := provider.getAuthorize(t, authorizeParams(request))
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
				}
				if resp.Header.Get("Location") != "" {
					t.Fatalf("did not expect redirect location, got %q", resp.Header.Get("Location"))
				}
			})
		}
	})
}

func testOAuth21AuthorizationEndpoint(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	resp := provider.getAuthorize(t, authorizeParams(newDefaultConfidentialAuthorizationRequest("oauth21-authorization-endpoint")))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if !strings.Contains(string(body), "Sign in") {
		t.Fatalf("expected login form, got body=%s", body)
	}
}

func testOAuth21AuthorizationCodeGrant(t *testing.T) {
	testAuthorizationCodeFlowSteps(t)
}

func testOAuth21AuthorizationErrorResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("redirects invalid_request errors to valid redirect uris", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-auth-error-missing-code-challenge")
		params := authorizeParams(request)
		params.Del("code_challenge")

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "code_challenge") {
			t.Fatalf("expected code_challenge error, got %q", got)
		}
	})

	t.Run("preserves registered query parameters in error redirects", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Clients[0].RedirectURL = webClientRedirect + "?tenant=alpha&tag=one&tag=two"
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("oauth21-auth-error-query")
		request.RedirectURI = config.Clients[0].RedirectURL
		params := authorizeParams(request)
		params.Del("code_challenge")

		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
	})

	t.Run("does not redirect invalid redirect uris", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-auth-error-invalid-redirect")
		request.RedirectURI = "http://127.0.0.1/unregistered/callback"

		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if resp.Header.Get("Location") != "" {
			t.Fatalf("did not expect redirect location, got %q", resp.Header.Get("Location"))
		}
	})
}

func testOAuth21TokenEndpointExtension(t *testing.T) {
	testTokenRequestValidation(t)
}

func testOAuth21ClientCredentialsGrant(t *testing.T) {
	config := defaultProviderConfig()
	config.Clients = append(config.Clients, clientConfig{
		Label:    "SERVICE",
		ID:       "service-client",
		Secret:   "service-secret",
		Audience: "https://api.example",
	})
	provider := startProvider(t, config)

	t.Run("issues access tokens to confidential clients", func(t *testing.T) {
		token := exchangeClientCredentials(t, provider, tokenRequest{
			ClientID:     "service-client",
			ClientSecret: "service-secret",
			Scope:        "orders:read",
		})
		if !strings.EqualFold(token.TokenType, "Bearer") || token.Scope != "orders:read" || token.RefreshToken != "" || token.IDToken != "" {
			t.Fatalf("unexpected token response: %#v", token)
		}
		claims := verifyAccessToken(t, provider, token.AccessToken)
		if claims.Sub != "service-client" || claims.ClientID != "service-client" || claims.Aud != "https://api.example" || claims.Scope != "orders:read" {
			t.Fatalf("unexpected access token claims: %#v", claims)
		}
	})

	t.Run("identifies the client instead of an end-user", func(t *testing.T) {
		token := exchangeClientCredentials(t, provider, tokenRequest{
			ClientID:     "service-client",
			ClientSecret: "service-secret",
		})
		response := introspectToken(t, provider, introspectionRequest{
			ClientID:     "service-client",
			ClientSecret: "service-secret",
			Token:        token.AccessToken,
		})
		if !response.Active || response.Sub != "service-client" || response.ClientID != "service-client" {
			t.Fatalf("unexpected introspection response: %#v", response)
		}

		resp := provider.getUserInfoResponse(t, token.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusForbidden, body)
		}
	})
}

func testOAuth21ClientCredentialsRequest(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("rejects public clients", func(t *testing.T) {
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:  nativeClientID,
			GrantType: "client_credentials",
		}), http.StatusBadRequest)
		if errResp.Error != "unauthorized_client" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "unauthorized_client")
		}
	})

	t.Run("rejects the openid scope", func(t *testing.T) {
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			GrantType:    "client_credentials",
			Scope:        "openid",
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_scope" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_scope")
		}
	})
}

func testOAuth21RefreshTokenGrant(t *testing.T) {
	testRefreshRequest(t)
	testSuccessfulRefreshResponse(t)
	testRefreshErrorResponse(t)
}

func testOAuth21RefreshTokenRequest(t *testing.T) {
	testRefreshRequest(t)
}

func testOAuth21RefreshTokenResponse(t *testing.T) {
	testSuccessfulRefreshResponse(t)
}

func testOAuth21RefreshTokenRecommendations(t *testing.T) {
	testRefreshTokenRecommendations(t)
}

func testOAuth21BearerAuthorizationHeaderField(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-bearer-header")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "bEaReR"} {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/userinfo"), nil)
		if err != nil {
			t.Fatalf("failed to create userinfo request: %v", err)
		}
		req.Header.Set("Authorization", scheme+" "+token.AccessToken)

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("userinfo status mismatch for scheme %q: got %s, want %d; body=%s", scheme, resp.Status, http.StatusOK, body)
		}
	}

	t.Run("rejects non-bearer authorization schemes", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/userinfo"), nil)
		if err != nil {
			t.Fatalf("failed to create userinfo request: %v", err)
		}
		req.Header.Set("Authorization", "Token "+token.AccessToken)

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="userinfo"` {
			t.Fatalf("unexpected bearer challenge: %q", got)
		}
	})
}

func testOAuth21FormEncodedContentParameter(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-form-encoded-token")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	t.Run("accepts access tokens in form-encoded POST bodies", func(t *testing.T) {
		resp := provider.postUserInfo(t, url.Values{"access_token": {token.AccessToken}}, "")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("does not accept access tokens in URL query parameters", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/userinfo")+"?"+url.Values{"access_token": {token.AccessToken}}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create userinfo request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
		}
	})
}

func testOAuth21BearerTokenRequests(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-bearer-requests")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	t.Run("rejects requests that use more than one bearer token method", func(t *testing.T) {
		resp := provider.postUserInfo(t, url.Values{"access_token": {token.AccessToken}}, "Bearer "+token.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_request"`) {
			t.Fatalf("expected invalid_request challenge, got %q", got)
		}
	})

	t.Run("ignores bearer tokens sent in URI query parameters", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/userinfo")+"?"+url.Values{"access_token": {token.AccessToken}}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create userinfo request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
		}
	})
}

func testOAuth21AccessTokenValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-access-token-validation")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	resp := provider.getUserInfoResponse(t, token.AccessToken)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	invalid := provider.getUserInfoResponse(t, "invalid-access-token")
	body = readBody(t, invalid)
	if invalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", invalid.Status, http.StatusUnauthorized, body)
	}

	provider.expireAccessToken(t, token.AccessToken)
	expired := provider.getUserInfoResponse(t, token.AccessToken)
	body = readBody(t, expired)
	if expired.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", expired.Status, http.StatusUnauthorized, body)
	}
}

func testOAuth21WWWAuthenticateResponseHeaderField(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	resp := provider.postUserInfo(t, url.Values{}, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="userinfo"` {
		t.Fatalf("unexpected bearer challenge: %q", got)
	}

	invalid := provider.getUserInfoResponse(t, "invalid-access-token")
	body = readBody(t, invalid)
	if invalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", invalid.Status, http.StatusUnauthorized, body)
	}
	if got := invalid.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) || !strings.Contains(got, `error_description=`) {
		t.Fatalf("unexpected bearer challenge: %q", got)
	}
}

func testOAuth21ErrorCodes(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-error-codes")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	resp := provider.postUserInfo(t, url.Values{"access_token": {token.AccessToken, token.AccessToken}}, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_request"`) {
		t.Fatalf("expected invalid_request challenge, got %q", got)
	}

	invalid := provider.getUserInfoResponse(t, "invalid-access-token")
	body = readBody(t, invalid)
	if invalid.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", invalid.Status, http.StatusUnauthorized, body)
	}
	if got := invalid.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
		t.Fatalf("expected invalid_token challenge, got %q", got)
	}

	refreshed := exchangeRefreshToken(t, provider, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		RefreshToken: token.RefreshToken,
		Scope:        "profile",
	})
	insufficient := provider.getUserInfoResponse(t, refreshed.AccessToken)
	body = readBody(t, insufficient)
	if insufficient.StatusCode != http.StatusForbidden {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", insufficient.Status, http.StatusForbidden, body)
	}
	if got := insufficient.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="insufficient_scope"`) {
		t.Fatalf("expected insufficient_scope challenge, got %q", got)
	}
}

func testOAuth21DontStoreBearerTokensInHTTPCookies(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-no-cookies")

	authorizeResp := provider.getAuthorize(t, authorizeParams(request))
	body := readBody(t, authorizeResp)
	if authorizeResp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", authorizeResp.Status, http.StatusOK, body)
	}

	authorization := authorizeAndLogin(t, provider, request)
	tokenResp := provider.postToken(t, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		Code:         authorization.Code,
		RedirectURI:  request.RedirectURI,
		CodeVerifier: request.Verifier,
	})
	body = readBody(t, tokenResp)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token status mismatch: got %s, want %d; body=%s", tokenResp.Status, http.StatusOK, body)
	}
	if got := tokenResp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("did not expect token cookies, got %#v", got)
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("failed to decode token response: %v\nbody=%s", err, body)
	}

	for _, cookie := range tokenResp.Cookies() {
		if cookie.Value == token.AccessToken || cookie.Value == token.RefreshToken || cookie.Value == token.IDToken {
			t.Fatalf("token endpoint stored a bearer token in cookie %q", cookie.Name)
		}
	}

	userInfoResp := provider.getUserInfoResponse(t, token.AccessToken)
	body = readBody(t, userInfoResp)
	if userInfoResp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", userInfoResp.Status, http.StatusOK, body)
	}
	if got := userInfoResp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("did not expect userinfo cookies, got %#v", got)
	}
}

func testOAuth21IssueShortLivedBearerTokens(t *testing.T) {
	config := defaultProviderConfig()
	config.AccessTokenTTL = 30 * time.Second
	provider := startProvider(t, config)

	for _, grantType := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		t.Run(grantType, func(t *testing.T) {
			var token tokenResponse
			if grantType == "client_credentials" {
				token = exchangeClientCredentials(t, provider, tokenRequest{
					ClientID:     webClientID,
					ClientSecret: webClientSecret,
				})
			} else {
				request := newDefaultConfidentialAuthorizationRequest("short-lived-tokens-" + grantType)
				token = authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				if grantType == "refresh_token" {
					token = exchangeRefreshToken(t, provider, tokenRequest{
						ClientID:     webClientID,
						ClientSecret: webClientSecret,
						RefreshToken: token.RefreshToken,
					})
				}
			}

			if token.ExpiresIn != int(config.AccessTokenTTL.Seconds()) {
				t.Fatalf("expires_in mismatch: got %d, want %d", token.ExpiresIn, int(config.AccessTokenTTL.Seconds()))
			}
			claims := verifyAccessToken(t, provider, token.AccessToken)
			if claims.Exp-claims.Iat != int64(token.ExpiresIn) {
				t.Fatalf("access token lifetime mismatch: got %d, want %d", claims.Exp-claims.Iat, token.ExpiresIn)
			}
			if expiry := provider.accessTokenExpiry(t, token.AccessToken); !expiry.Equal(time.Unix(claims.Exp, 0)) {
				t.Fatalf("stored expiry mismatch: got %s, want %s", expiry, time.Unix(claims.Exp, 0))
			}
			if grantType != "client_credentials" {
				if idClaims := verifyIDToken(t, provider, token.IDToken); idClaims.Iat != claims.Iat || idClaims.Exp != claims.Exp {
					t.Fatalf("access and ID token timestamps differ: access=(%d, %d), id=(%d, %d)", claims.Iat, claims.Exp, idClaims.Iat, idClaims.Exp)
				}
			}
		})
	}

	t.Run("rejects lifetimes that are not whole seconds", func(t *testing.T) {
		for _, lifetime := range []string{"1ns", "500ms", "1500ms"} {
			t.Run(lifetime, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_ISSUER=http://127.0.0.1",
					"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
					"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
					"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
					"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
					"SIMPLE_IDP_ACCESS_TOKEN_TTL=" + lifetime,
				}
				_, _, err := newIdentityProvider(environ, func(name string) string {
					for _, item := range environ {
						key, value, _ := strings.Cut(item, "=")
						if key == name {
							return value
						}
					}
					return ""
				}, os.ReadFile)
				if err == nil || !strings.Contains(err.Error(), "whole number of seconds") {
					t.Fatalf("expected whole-second lifetime error, got %v", err)
				}
			})
		}
	})
}

func testOAuth21AccessTokenScope(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-scoped-bearer-tokens")
	request.Scope = "openid profile"
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	if token.Scope != request.Scope {
		t.Fatalf("scope mismatch: got %q, want %q", token.Scope, request.Scope)
	}

	resp := provider.getUserInfoResponse(t, token.AccessToken)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	payload := decodeJSONMap(t, body)
	if payload["sub"] != testSubject {
		t.Fatalf("subject mismatch: got %#v, want %q", payload["sub"], testSubject)
	}
	if _, ok := payload["name"]; !ok {
		t.Fatalf("expected profile claims, got %#v", payload)
	}
	if _, ok := payload["email"]; ok {
		t.Fatalf("did not expect email claim, got %#v", payload)
	}
}

func testOAuth21DontPassBearerTokensInPageURLs(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-no-url-bearer-tokens")
	resp := provider.getAuthorize(t, authorizeParams(request))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
	for _, unexpected := range []string{"access_token", "id_token", "token_type"} {
		if got := redirect.Query().Get(unexpected); got != "" {
			t.Fatalf("did not expect %s in redirect, got %q", unexpected, redirect.String())
		}
	}

	token := exchangeAuthorizationCode(t, provider, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		Code:         redirect.Query().Get("code"),
		RedirectURI:  request.RedirectURI,
		CodeVerifier: request.Verifier,
	})
	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/userinfo")+"?"+url.Values{"access_token": {token.AccessToken}}.Encode(), nil)
	if err != nil {
		t.Fatalf("failed to create userinfo request: %v", err)
	}
	resp = provider.do(t, provider.redirectless, req)
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
	}
}

func testOAuth21ImpersonationOfNativeApps(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("oauth21-native-impersonation-session"))
	request := authorizationRequest{
		ClientID:    nativeClientID,
		RedirectURI: "http://127.0.0.1:49207/callback",
		Scope:       "openid profile",
		State:       "oauth21-native-impersonation",
		Verifier:    pkceVerifier("oauth21-native-impersonation"),
	}

	t.Run("requires end-user interaction before reusing a session for public clients", func(t *testing.T) {
		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), `data-testid="page-consent"`) {
			t.Fatalf("expected consent form, got body=%s", body)
		}
		code := expectAuthorizationCodeRedirect(t, submitConsentForm(t, provider, body, "yes"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
		_ = exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			Code:         code,
			CodeVerifier: request.Verifier,
		})
	})

	t.Run("returns interaction_required for prompt none from public clients", func(t *testing.T) {
		silentRequest := request
		silentRequest.Prompt = "none"
		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(silentRequest)), http.StatusFound, silentRequest.RedirectURI, silentRequest.State, provider.issuer, "interaction_required")
	})

	t.Run("does not add a consent step after interactive authentication", func(t *testing.T) {
		authorization := authorizeAndLogin(t, provider, request)
		if authorization.Code == "" {
			t.Fatalf("expected authorization code, got %#v", authorization)
		}
	})
}

func testOAuth21AuthorizationCodeInjectionCountermeasures(t *testing.T) {
	testAuthenticationRequestValidation(t)
}

func testOAuth21ReuseOfAuthorizationCodes(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("revokes the first token after a valid replay", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-valid-code-replay")
		authorization := authorizeAndLogin(t, provider, request)
		firstToken := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}

		resp := provider.getUserInfoResponse(t, firstToken.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
		}
	})

	t.Run("does not revoke the first token after an invalid replay attempt", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-invalid-code-replay")
		authorization := authorizeAndLogin(t, provider, request)
		firstToken := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: pkceVerifier("different-code-verifier"),
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}

		resp := provider.getUserInfoResponse(t, firstToken.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("revokes grants after replay beyond the code redemption lifetime", func(t *testing.T) {
		for _, phase := range []string{"before cleanup", "after cleanup"} {
			t.Run(phase, func(t *testing.T) {
				provider := startProvider(t, defaultProviderConfig())
				request := newDefaultConfidentialAuthorizationRequest("late-code-replay")
				request.ClientID = nativeClientID
				request.RedirectURI = nativeClientRedirect
				authorization := authorizeAndLogin(t, provider, request)
				exchange := tokenRequest{
					ClientID: nativeClientID, Code: authorization.Code,
					RedirectURI: request.RedirectURI, CodeVerifier: request.Verifier,
				}
				token := exchangeAuthorizationCode(t, provider, exchange)
				provider.expireAuthorizationCode(t, authorization.Code)
				if phase == "after cleanup" {
					_ = introspectToken(t, provider, introspectionRequest{
						ClientID: webClientID, ClientSecret: webClientSecret, Token: "unknown",
					})
				}

				invalid := exchange
				invalid.CodeVerifier = pkceVerifier("wrong-verifier")
				expectJSONError(t, provider.postToken(t, invalid), http.StatusBadRequest)
				refreshed := exchangeRefreshToken(t, provider, tokenRequest{
					ClientID: nativeClientID, RefreshToken: token.RefreshToken,
				})
				errResponse := expectJSONError(t, provider.postToken(t, exchange), http.StatusBadRequest)
				if errResponse.Error != "invalid_grant" {
					t.Fatalf("replay error = %q, want invalid_grant", errResponse.Error)
				}
				for _, access := range []string{token.AccessToken, refreshed.AccessToken} {
					resp := provider.getUserInfoResponse(t, access)
					readBody(t, resp)
					if resp.StatusCode != http.StatusUnauthorized {
						t.Fatalf("access token survived code replay: %s", resp.Status)
					}
				}
				errResponse = expectJSONError(t, provider.postToken(t, tokenRequest{
					GrantType: "refresh_token", ClientID: nativeClientID, RefreshToken: refreshed.RefreshToken,
				}), http.StatusBadRequest)
				if errResponse.Error != "invalid_grant" {
					t.Fatalf("refresh error = %q, want invalid_grant", errResponse.Error)
				}
			})
		}
	})

	t.Run("retains replay detection through the final access token lifetime", func(t *testing.T) {
		for _, phase := range []string{"last access token active", "all tokens expired"} {
			t.Run(phase, func(t *testing.T) {
				provider := startProvider(t, defaultProviderConfig())
				request := newDefaultConfidentialAuthorizationRequest("replay-final-access-token")
				authorization := authorizeAndLogin(t, provider, request)
				exchange := tokenRequest{
					ClientID:     webClientID,
					ClientSecret: webClientSecret,
					Code:         authorization.Code,
					CodeVerifier: request.Verifier,
				}
				token := exchangeAuthorizationCode(t, provider, exchange)
				age := provider.idp.refreshTokenMaxTTL + time.Minute
				if phase == "all tokens expired" {
					age += provider.idp.accessTokenTTL
					provider.expireAccessToken(t, token.AccessToken)
				}
				provider.ageConsumedAuthorizationCode(t, authorization.Code, age)
				provider.expireRefreshTokenMax(t, token.RefreshToken)
				info := introspectToken(t, provider, introspectionRequest{
					ClientID:     webClientID,
					ClientSecret: webClientSecret,
					Token:        token.AccessToken,
				})
				if info.Active != (phase == "last access token active") {
					t.Fatalf("unexpected final access token activity: %t", info.Active)
				}
				if phase == "all tokens expired" {
					provider.idp.mu.Lock()
					_, retained := provider.idp.pendingCodes[authorization.Code]
					provider.idp.mu.Unlock()
					if retained {
						t.Fatal("consumed code remained after its replay detection window")
					}
					return
				}

				errResp := expectJSONError(t, provider.postToken(t, exchange), http.StatusBadRequest)
				if errResp.Error != "invalid_grant" {
					t.Fatalf("replay error = %q, want invalid_grant", errResp.Error)
				}
				resp := provider.getUserInfoResponse(t, token.AccessToken)
				readBody(t, resp)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("final access token survived code replay: %s", resp.Status)
				}
			})
		}
	})
}

func testOAuth21InjectionAndInputValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("preserves opaque state values without interpreting them", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-input-state")
		request.State = "state with spaces/+?&=<script>"

		authorization := authorizeAndLogin(t, provider, request)
		if authorization.State != request.State {
			t.Fatalf("state mismatch: got %q, want %q", authorization.State, request.State)
		}
	})

	t.Run("does not redirect invalid redirect_uri values", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-input-redirect-uri")
		request.RedirectURI = "http://127.0.0.1/unregistered/callback"

		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if resp.Header.Get("Location") != "" {
			t.Fatalf("did not expect redirect location, got %q", resp.Header.Get("Location"))
		}
	})
}

func testOAuth21MixUpDefenseViaIssuerIdentification(t *testing.T) {
	testOAuth21PreventingMixUpAttacks(t)
}

func testOAuth21Clickjacking(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	resp := provider.getAuthorize(t, authorizeParams(newDefaultConfidentialAuthorizationRequest("oauth21-clickjacking")))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("x-frame-options mismatch: got %q, want %q", got, "DENY")
	}
	if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("expected frame-ancestors none, got %q", got)
	}
}

func testOAuth21ClientAuthenticationOfNativeApps(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("does not require client authentication for native apps", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49168/callback",
			Scope:       "openid profile",
			State:       "oauth21-native-no-auth",
			Verifier:    pkceVerifier("oauth21-native-no-auth"),
		}
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		if token.AccessToken == "" {
			t.Fatalf("expected access token, got %#v", token)
		}
	})

	t.Run("rejects native apps that send client secrets", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49169/callback",
			Scope:       "openid profile",
			State:       "oauth21-native-secret",
			Verifier:    pkceVerifier("oauth21-native-secret"),
		}
		authorization := authorizeAndLogin(t, provider, request)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: "unexpected-secret",
			AuthMethod:   authMethodClientSecretPost,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("rejects native apps using basic authentication", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49170/callback",
			Scope:       "openid profile",
			State:       "oauth21-native-basic",
			Verifier:    pkceVerifier("oauth21-native-basic"),
		}
		authorization := authorizeAndLogin(t, provider, request)

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authorization.Code},
			"redirect_uri":  {request.RedirectURI},
			"code_verifier": {request.Verifier},
		}
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/token"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create token request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(request.ClientID), "")

		errResp := expectJSONError(t, provider.do(t, provider.redirectless, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})
}

func testOAuth21RegistrationOfNativeAppClients(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	registered, ok := provider.idp.clients[nativeClientID]
	if !ok {
		t.Fatalf("expected native client registration for %q", nativeClientID)
	}
	if !registered.isPublic || registered.secret != "" {
		t.Fatalf("expected native client to be recorded as public, got %#v", registered)
	}
	request := authorizationRequest{
		ClientID:    nativeClientID,
		RedirectURI: "http://127.0.0.1:49203/callback",
		Scope:       "openid profile",
		State:       "oauth21-native-registration",
		Verifier:    pkceVerifier("oauth21-native-registration"),
	}
	authorization := authorizeAndLogin(t, provider, request)
	if authorization.Code == "" {
		t.Fatalf("expected authorization code, got %#v", authorization)
	}
}

func testOAuth21TokenEndpointResponse(t *testing.T) {
	for _, grantType := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		t.Run(grantType, func(t *testing.T) {
			provider := startProvider(t, defaultProviderConfig())
			request := newDefaultConfidentialAuthorizationRequest("oauth21-token-endpoint-response-" + grantType)
			tokenReq := tokenRequest{
				ClientID:     request.ClientID,
				ClientSecret: webClientSecret,
				GrantType:    grantType,
			}
			scope := request.Scope
			switch grantType {
			case "authorization_code":
				authorization := authorizeAndLogin(t, provider, request)
				tokenReq.Code = authorization.Code
				tokenReq.RedirectURI = request.RedirectURI
				tokenReq.CodeVerifier = request.Verifier
			case "refresh_token":
				original := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				tokenReq.RefreshToken = original.RefreshToken
			case "client_credentials":
				scope = "orders:read"
				tokenReq.Scope = scope
			}

			resp := provider.postToken(t, tokenReq)
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
			}
			assertTokenResponseHeaders(t, resp)

			var token tokenResponse
			if err := json.Unmarshal(body, &token); err != nil {
				t.Fatalf("failed to decode token response: %v\nbody=%s", err, body)
			}
			if token.AccessToken == "" {
				t.Fatalf("expected access token, got %#v", token)
			}
			if !strings.EqualFold(token.TokenType, "Bearer") {
				t.Fatalf("token type mismatch: got %q, want %q", token.TokenType, "Bearer")
			}
			if token.ExpiresIn <= 0 {
				t.Fatalf("expected positive expires_in, got %d", token.ExpiresIn)
			}
			if token.Scope != "" && token.Scope != scope {
				t.Fatalf("scope mismatch: got %q, want %q", token.Scope, scope)
			}
			if grantType == "authorization_code" && token.RefreshToken == "" {
				t.Fatalf("expected refresh token, got %#v", token)
			}
		})
	}
}

func testOAuth21LoopbackInterfaceRedirection(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("allows any loopback port for public native clients", func(t *testing.T) {
		for _, redirect := range []struct {
			registered string
			requested  string
		}{
			{nativeClientRedirect, "http://127.0.0.1:49204/callback"},
			{"http://127.0.0.1:49200/callback", "http://127.0.0.1:49204/callback"},
			{"http://[::1]:49200/callback", "http://[::1]:49204/callback"},
			{"HTTP://127.0.0.1/callback?tenant=alpha", "HTTP://127.0.0.1:49204/callback?tenant=alpha"},
		} {
			t.Run(redirect.registered, func(t *testing.T) {
				config := defaultProviderConfig()
				config.Clients[2].RedirectURL = redirect.registered
				provider := startProvider(t, config)
				request := authorizationRequest{
					ClientID:    nativeClientID,
					RedirectURI: redirect.requested,
					Scope:       "openid profile",
					State:       "oauth21-loopback-public",
					Verifier:    pkceVerifier("oauth21-loopback-public"),
				}
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					CodeVerifier: request.Verifier,
				})
				if token.AccessToken == "" {
					t.Fatalf("expected access token, got %#v", token)
				}
			})
		}
	})

	t.Run("does not allow arbitrary loopback ports for confidential clients", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-loopback-confidential")
		request.RedirectURI = "http://127.0.0.1:49205/callback"
		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
	})

	t.Run("rejects non-loopback redirect uris for public clients", func(t *testing.T) {
		for _, redirectURL := range []string{
			"https://rp.example/callback",
			nativeClientRedirect + " https://rp.example/callback",
		} {
			t.Run(redirectURL, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_CLIENT_NATIVE_ID=" + nativeClientID,
					"SIMPLE_IDP_CLIENT_NATIVE_REDIRECT_URL=" + redirectURL,
				}
				_, err := loadClients(environ, func(name string) string {
					for _, item := range environ {
						key, value, _ := strings.Cut(item, "=")
						if key == name {
							return value
						}
					}
					return ""
				})
				if err == nil || !strings.Contains(err.Error(), "loopback redirect URLs") {
					t.Fatalf("expected loopback redirect URL error, got %v", err)
				}
			})
		}
	})
}

func testOAuth21LoopbackRedirectConsiderations(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := authorizationRequest{
		ClientID:    nativeClientID,
		RedirectURI: "http://127.0.0.1:49206/callback",
		Scope:       "openid profile",
		State:       "oauth21-loopback-http",
		Verifier:    pkceVerifier("oauth21-loopback-http"),
	}
	authorization := authorizeAndLogin(t, provider, request)
	if authorization.Code == "" {
		t.Fatalf("expected authorization code, got %#v", authorization)
	}
}

func testOAuth21RemovalOfImplicitGrant(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-no-implicit")
	params := authorizeParams(request)
	params.Set("response_type", "token")

	expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "unsupported_response_type")
}

func testOAuth21RedirectURIParameterInTokenRequest(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-redirect-uri-token")
	authorization := authorizeAndLogin(t, provider, request)

	t.Run("allows token requests without redirect_uri", func(t *testing.T) {
		resp := provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			CodeVerifier: request.Verifier,
		})
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("allows token requests without redirect_uri with several registered URIs", func(t *testing.T) {
		config := defaultProviderConfig()
		const secondRedirect = "http://localhost/alt/callback"
		config.Clients[0].RedirectURL = webClientRedirect + " " + secondRedirect
		provider := startProvider(t, config)
		for _, redirectURI := range []string{webClientRedirect, secondRedirect} {
			t.Run(redirectURI, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("oauth21-omit-token-redirect-uri-multiple")
				request.RedirectURI = redirectURI
				authorization := authorizeAndLogin(t, provider, request)
				token := exchangeAuthorizationCode(t, provider, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					Code:         authorization.Code,
					CodeVerifier: request.Verifier,
				})
				if token.AccessToken == "" {
					t.Fatalf("expected access token for redirect URI %q, got %#v", redirectURI, token)
				}
			})
		}
	})

	t.Run("still accepts token requests that include redirect_uri", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-redirect-uri-token-compat")
		authorization := authorizeAndLogin(t, provider, request)
		resp := provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("enforces redirect_uri when clients still send it", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("oauth21-redirect-uri-token-mismatch")
		authorization := authorizeAndLogin(t, provider, request)
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  "http://127.0.0.1/other-callback",
			CodeVerifier: request.Verifier,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
		_ = exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
	})

	t.Run("compares redirect_uri without normalizing its scheme", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Clients[0].RedirectURL = "HTTP://127.0.0.1/callback"
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("oauth21-redirect-uri-token-scheme")
		request.RedirectURI = config.Clients[0].RedirectURL
		authorization := authorizeAndLogin(t, provider, request)
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  webClientRedirect,
			CodeVerifier: request.Verifier,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
		_ = exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
	})
}

func testOAuth21MultipleRedirectURIs(t *testing.T) {
	const secondRedirect = "http://localhost/alt/callback"
	redirectURIs := []string{
		webClientRedirect,
		secondRedirect,
		webClientRedirect + "?tenant=alpha&tag=one&tag=two",
		"HTTP://127.0.0.1/callback",
		"http://127.0.0.1/%63allback",
	}

	config := defaultProviderConfig()
	for i, c := range config.Clients {
		if c.ID == webClientID {
			config.Clients[i].RedirectURL = strings.Join(redirectURIs, " ")
		}
	}
	provider := startProvider(t, config)

	for _, redirectURI := range redirectURIs {
		t.Run(redirectURI, func(t *testing.T) {
			request := newDefaultConfidentialAuthorizationRequest("oauth21-multiple-redirect-uris")
			request.RedirectURI = redirectURI
			token := authorizeAndExchange(t, provider, request, tokenRequest{
				ClientID:     request.ClientID,
				ClientSecret: webClientSecret,
				CodeVerifier: request.Verifier,
			})
			if token.AccessToken == "" {
				t.Fatalf("expected access token for redirect uri %q, got %#v", redirectURI, token)
			}
		})
	}
}
