package simpleidp

// Reference material:
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
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
	request := newDefaultConfidentialAuthorizationRequest("oauth21-invalid-endpoint")
	request.RedirectURI = "http://127.0.0.1/unregistered/callback"

	resp := provider.getAuthorize(t, authorizeParams(request))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
	}
	if resp.Header.Get("Location") != "" {
		t.Fatalf("did not expect redirect location, got %q", resp.Header.Get("Location"))
	}
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

func testOAuth21AuthorizationResponse(t *testing.T) {
	testSuccessfulAuthenticationResponse(t)
	testOAuth21AuthorizationErrorResponse(t)
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

		resp := provider.do(t, provider.http, req)
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

		resp := provider.do(t, provider.http, req)
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

		resp := provider.do(t, provider.http, req)
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

		resp := provider.do(t, provider.http, req)
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
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-short-lived-tokens")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	if token.ExpiresIn <= 0 {
		t.Fatalf("expected positive expires_in, got %d", token.ExpiresIn)
	}
	if token.ExpiresIn != int(accessTokenTTL.Seconds()) {
		t.Fatalf("expires_in mismatch: got %d, want %d", token.ExpiresIn, int(accessTokenTTL.Seconds()))
	}
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
	resp = provider.do(t, provider.http, req)
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
	}
}

func testOAuth21SummaryOfRecommendations(t *testing.T) {
	testOAuth21DontStoreBearerTokensInHTTPCookies(t)
	testOAuth21IssueShortLivedBearerTokens(t)
	testOAuth21DontPassBearerTokensInPageURLs(t)
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

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
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
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("oauth21-token-endpoint-response")
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
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("content type mismatch: got %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control mismatch: got %q", got)
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("failed to decode token response: %v\nbody=%s", err, body)
	}
	if token.AccessToken == "" {
		t.Fatalf("expected access token, got %#v", token)
	}
	if token.TokenType != "Bearer" {
		t.Fatalf("token type mismatch: got %q, want %q", token.TokenType, "Bearer")
	}
	if token.ExpiresIn <= 0 {
		t.Fatalf("expected positive expires_in, got %d", token.ExpiresIn)
	}
	if token.Scope != "" && token.Scope != request.Scope {
		t.Fatalf("scope mismatch: got %q, want %q", token.Scope, request.Scope)
	}
	if token.RefreshToken == "" {
		t.Fatalf("expected refresh token, got %#v", token)
	}
}

func testOAuth21LoopbackInterfaceRedirection(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("allows any loopback port for public native clients", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49204/callback",
			Scope:       "openid profile",
			State:       "oauth21-loopback-public",
			Verifier:    pkceVerifier("oauth21-loopback-public"),
		}
		authorization := authorizeAndLogin(t, provider, request)
		if authorization.Code == "" {
			t.Fatalf("expected authorization code, got %#v", authorization)
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
	})
}
