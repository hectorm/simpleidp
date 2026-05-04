package simpleidp

// Reference material:
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func testAuthorizationCodeFlowSteps(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("code-flow-steps")

	authorization := authorizeAndLogin(t, provider, request)
	if authorization.Code == "" {
		t.Fatal("expected authorization code")
	}

	token := exchangeAuthorizationCode(t, provider, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		Code:         authorization.Code,
		RedirectURI:  request.RedirectURI,
		CodeVerifier: request.Verifier,
	})
	if token.AccessToken == "" || token.IDToken == "" {
		t.Fatalf("expected access token and id token, got %#v", token)
	}
	claims := verifyIDToken(t, provider, token.IDToken)
	if claims.Nonce != request.Nonce {
		t.Fatalf("id token nonce mismatch: got %q, want %q", claims.Nonce, request.Nonce)
	}

	userInfo := fetchUserInfo(t, provider, token.AccessToken)
	if userInfo.Sub != testSubject {
		t.Fatalf("userinfo subject mismatch: got %q, want %q", userInfo.Sub, testSubject)
	}
}

func testAuthenticationRequest(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("supports GET authorization requests", func(t *testing.T) {
		resp := provider.getAuthorize(t, authorizeParams(newDefaultConfidentialAuthorizationRequest("auth-request-get")))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Sign in") {
			t.Fatalf("expected login form, got body=%s", body)
		}
	})

	t.Run("supports POST authorization requests", func(t *testing.T) {
		body := authorizeByPostExpectLoginPage(t, provider, newDefaultConfidentialAuthorizationRequest("auth-request-post"))
		if !strings.Contains(string(body), `method="POST"`) {
			t.Fatalf("expected POST form, got body=%s", body)
		}
	})
}

func testAuthenticationRequestValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("rejects missing required parameters", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("missing-scope")
		params := authorizeParams(request)
		params.Del("scope")

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "scope") {
			t.Fatalf("expected missing scope error, got %q", got)
		}
	})

	t.Run("does not redirect when redirect_uri is missing", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("missing-redirect-uri")
		params := authorizeParams(request)
		params.Del("redirect_uri")

		resp := provider.getAuthorize(t, params)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if resp.Header.Get("Location") != "" {
			t.Fatalf("did not expect redirect location, got %q", resp.Header.Get("Location"))
		}
	})

	t.Run("rejects requests without openid scope", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("missing-openid")
		request.Scope = "profile email"
		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_scope")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "openid") {
			t.Fatalf("expected openid scope error, got %q", got)
		}
	})

	t.Run("rejects unsupported response types", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("unsupported-response-type")
		params := authorizeParams(request)
		params.Set("response_type", "token")
		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "unsupported_response_type")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "'code'") {
			t.Fatalf("expected code response type error, got %q", got)
		}
	})

	t.Run("rejects unsupported response modes without redirecting", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("unsupported-response-mode")
		params := authorizeParams(request)
		params.Set("response_mode", "fragment")

		resp := provider.getAuthorize(t, params)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if resp.Header.Get("Location") != "" {
			t.Fatalf("did not expect redirect location, got %q", resp.Header.Get("Location"))
		}
	})

	t.Run("rejects invalid prompts", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("invalid-prompt")
		params := authorizeParams(request)
		params.Set("prompt", "none consent")

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "prompt") {
			t.Fatalf("expected prompt error, got %q", got)
		}
	})

	t.Run("rejects invalid id token hints", func(t *testing.T) {
		source := authorizeAndExchange(t, provider, newDefaultConfidentialAuthorizationRequest("id-token-hint-source"), tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: pkceVerifier("id-token-hint-source"),
		})

		request := newDefaultConfidentialAuthorizationRequest("invalid-id-token-hint")
		request.ClientID = otherClientID
		request.RedirectURI = otherClientRedirect
		params := authorizeParams(request)
		params.Set("id_token_hint", source.IDToken)

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "id_token_hint") {
			t.Fatalf("expected id_token_hint error, got %q", got)
		}
	})

	t.Run("rejects id token hints with invalid signatures", func(t *testing.T) {
		source := authorizeAndExchange(t, provider, newDefaultConfidentialAuthorizationRequest("tampered-id-token-hint-source"), tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: pkceVerifier("tampered-id-token-hint-source"),
		})

		request := newDefaultConfidentialAuthorizationRequest("tampered-id-token-hint")
		params := authorizeParams(request)
		params.Set("id_token_hint", tamperJWTSignature(t, source.IDToken))

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "id_token_hint") {
			t.Fatalf("expected id_token_hint error, got %q", got)
		}
	})

	t.Run("returns login_required when the authenticated user does not match the id token hint", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users = append(config.Users, userConfig{
			Label:         "BOB",
			Username:      "bob",
			Password:      "hunter2",
			Sub:           "bob-subject",
			Name:          "Bob Example",
			Email:         "bob@example.com",
			EmailVerified: true,
		})
		provider := startProvider(t, config)
		source := authorizeAndExchange(t, provider, newDefaultConfidentialAuthorizationRequest("id-token-hint-user-mismatch-source"), tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: pkceVerifier("id-token-hint-user-mismatch-source"),
		})

		request := newDefaultConfidentialAuthorizationRequest("id-token-hint-user-mismatch")
		request.Prompt = "login"
		params := authorizeParams(request)
		params.Set("id_token_hint", source.IDToken)

		resp := provider.getAuthorize(t, params)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}

		redirect := expectAuthorizationErrorRedirect(t, submitLoginForm(t, provider, body, "bob", "hunter2"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer, "login_required")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "id_token_hint") {
			t.Fatalf("expected id_token_hint mismatch error, got %q", got)
		}
	})

	t.Run("rejects unsupported request objects", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("unsupported-request-object")
		params := authorizeParams(request)
		params.Set("request", "unsigned-request-object")

		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "request_not_supported")
	})

	t.Run("rejects unsupported request uris", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("unsupported-request-uri")
		params := authorizeParams(request)
		params.Set("request_uri", "https://rp.example/request.jwt")

		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "request_uri_not_supported")
	})

	t.Run("rejects duplicate parameters", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("duplicate-scope")
		params := authorizeParams(request)
		params["scope"] = []string{"openid profile", "openid email"}

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "Duplicate parameter") {
			t.Fatalf("expected duplicate parameter error, got %q", got)
		}
	})

	t.Run("does not redirect duplicate client identifiers", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("duplicate-client-id")
		params := authorizeParams(request)
		params["client_id"] = []string{request.ClientID, request.ClientID}

		resp := provider.getAuthorize(t, params)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if resp.Header.Get("Location") != "" {
			t.Fatalf("did not expect redirect location, got %q", resp.Header.Get("Location"))
		}
	})

	t.Run("does not redirect invalid redirect uris", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("invalid-redirect-uri")
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

	t.Run("rejects missing code challenge even for confidential requests using nonce", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("missing-code-challenge")
		params := authorizeParams(request)
		params.Del("code_challenge")

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "code_challenge") {
			t.Fatalf("expected code_challenge error, got %q", got)
		}
	})

	t.Run("rejects short code challenges", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("short-code-challenge")
		params := authorizeParams(request)
		params.Set("code_challenge", strings.Repeat("a", 42))

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "code_challenge") {
			t.Fatalf("expected code_challenge error, got %q", got)
		}
	})

	t.Run("rejects malformed code challenges", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("malformed-code-challenge")
		params := authorizeParams(request)
		params.Set("code_challenge", strings.Repeat("a", 42)+"!")

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "code_challenge") {
			t.Fatalf("expected code_challenge error, got %q", got)
		}
	})

	t.Run("rejects unsupported code challenge methods", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("plain-code-challenge")
		params := authorizeParams(request)
		params.Set("code_challenge", request.Verifier)
		params.Set("code_challenge_method", "plain")

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "S256") {
			t.Fatalf("expected S256 error, got %q", got)
		}
	})
}

func testAuthorizationServerAuthenticatesEndUser(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("authenticate-end-user")

	t.Run("renders an error for invalid credentials", func(t *testing.T) {
		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}

		resp = submitLoginForm(t, provider, body, testUsername, "wrong-password")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Invalid username or password") {
			t.Fatalf("expected invalid credentials message, got body=%s", body)
		}
	})

	t.Run("returns login_required for prompt none", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("prompt-none")
		request.Prompt = "none"

		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
	})

	t.Run("reuses authenticated sessions without prompting again", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		initialRequest := newDefaultConfidentialAuthorizationRequest("session-reuse-initial")
		initialToken := authorizeAndExchange(t, provider, initialRequest, tokenRequest{
			ClientID:     initialRequest.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: initialRequest.Verifier,
		})
		initialClaims := verifyIDToken(t, provider, initialToken.IDToken)

		request := newDefaultConfidentialAuthorizationRequest("session-reuse-follow-up")
		code := expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		if claims.AuthTime != initialClaims.AuthTime {
			t.Fatalf("expected reused session auth_time %d, got %d", initialClaims.AuthTime, claims.AuthTime)
		}
	})

	t.Run("expires authenticated sessions after the maximum lifespan", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		initialRequest := newDefaultConfidentialAuthorizationRequest("session-max-initial")
		_ = authorizeAndExchange(t, provider, initialRequest, tokenRequest{
			ClientID:     initialRequest.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: initialRequest.Verifier,
		})
		provider.expireSessionMax(t)

		request := newDefaultConfidentialAuthorizationRequest("session-max-expired")
		request.Prompt = "none"

		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
	})

	t.Run("returns a positive response for prompt none when a session exists", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		initialRequest := newDefaultConfidentialAuthorizationRequest("prompt-none-session-initial")
		initialToken := authorizeAndExchange(t, provider, initialRequest, tokenRequest{
			ClientID:     initialRequest.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: initialRequest.Verifier,
		})
		initialClaims := verifyIDToken(t, provider, initialToken.IDToken)

		request := newDefaultConfidentialAuthorizationRequest("prompt-none-session")
		request.Prompt = "none"
		code := expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		if claims.AuthTime != initialClaims.AuthTime {
			t.Fatalf("expected reused session auth_time %d, got %d", initialClaims.AuthTime, claims.AuthTime)
		}
	})

	t.Run("forces reauthentication for prompt login despite an active session", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		baseline := newDefaultConfidentialAuthorizationRequest("prompt-login-active-session-baseline")
		_ = authorizeAndExchange(t, provider, baseline, tokenRequest{
			ClientID:     baseline.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: baseline.Verifier,
		})

		request := newDefaultConfidentialAuthorizationRequest("prompt-login-active-session")
		request.Prompt = "login"
		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Sign in") {
			t.Fatalf("expected login form, got body=%s", body)
		}
	})

	t.Run("requires interactive account selection for prompt select_account", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		baseline := newDefaultConfidentialAuthorizationRequest("select-account-baseline")
		_ = authorizeAndExchange(t, provider, baseline, tokenRequest{
			ClientID:     baseline.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: baseline.Verifier,
		})

		request := newDefaultConfidentialAuthorizationRequest("select-account")
		request.Prompt = "select_account"
		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Sign in") {
			t.Fatalf("expected account-selection interaction, got body=%s", body)
		}
	})

	t.Run("rejects interactive posts without csrf protection", func(t *testing.T) {
		resp := provider.postAuthorize(t, authorizeParams(request), url.Values{
			"username": {testUsername},
			"password": {testPassword},
		})
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if !strings.Contains(string(body), "Invalid or expired session") {
			t.Fatalf("expected invalid session error, got body=%s", body)
		}
	})
}

func testAuthorizationServerObtainsEndUserConsentAuthorization(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("end-user-consent")
	request.Prompt = "consent"

	t.Run("allows the end user to approve consent", func(t *testing.T) {
		body := authorizeAndLoginExpectPage(t, provider, request)
		if !strings.Contains(string(body), "Allow") || !strings.Contains(string(body), "Deny") {
			t.Fatalf("expected consent form, got body=%s", body)
		}

		code := expectAuthorizationCodeRedirect(t, submitConsentForm(t, provider, body, "yes"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
		if code == "" {
			t.Fatal("expected authorization code")
		}
	})

	t.Run("allows the end user to deny consent", func(t *testing.T) {
		body := authorizeAndLoginExpectPage(t, provider, request)
		expectAuthorizationErrorRedirect(t, submitConsentForm(t, provider, body, "no"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer, "access_denied")
	})

	t.Run("rejects consent submissions without csrf protection", func(t *testing.T) {
		body := authorizeAndLoginExpectPage(t, provider, request)
		resp := provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, body)), url.Values{
			"confirm": {"yes"},
		}, "", false)
		raw := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("consent status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, raw)
		}
		if !strings.Contains(string(raw), "Invalid or expired session") {
			t.Fatalf("expected invalid session error, got body=%s", raw)
		}
	})
}

func testSuccessfulAuthenticationResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("successful-auth-response")

	resp := provider.getAuthorize(t, authorizeParams(request))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
	assertRedirectTarget(t, redirect, request.RedirectURI)
	assertAuthorizationResponseMetadata(t, redirect, request.State, provider.issuer)
	if got := redirect.Query().Get("code"); got == "" {
		t.Fatalf("expected code, got %q", redirect.String())
	}
	for _, unexpected := range []string{"access_token", "id_token", "token_type"} {
		if got := redirect.Query().Get(unexpected); got != "" {
			t.Fatalf("did not expect %s in redirect, got %q", unexpected, redirect.String())
		}
	}
}

func testAuthenticationErrorResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("redirects oauth errors to valid redirect uris", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("auth-error-response")
		request.Prompt = "none"

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
		if got := redirect.Query().Get("error_description"); got == "" {
			t.Fatalf("expected error description, got %q", redirect.String())
		}
	})

	t.Run("does not redirect invalid redirect uris", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("auth-error-invalid-redirect")
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

func testAuthenticationResponseValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("response-validation")
	request.State = "state with spaces/+?&="

	resp := provider.getAuthorize(t, authorizeParams(request))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
	assertRedirectTarget(t, redirect, request.RedirectURI)
	assertAuthorizationResponseMetadata(t, redirect, request.State, provider.issuer)
	if redirect.Fragment != "" {
		t.Fatalf("did not expect redirect fragment, got %q", redirect.String())
	}
}

func testTokenRequest(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("accepts client_secret_basic for confidential clients", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("token-request-basic")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		if token.AccessToken == "" || token.IDToken == "" {
			t.Fatalf("expected tokens, got %#v", token)
		}
	})

	t.Run("accepts client_secret_post for confidential clients", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("token-request-post")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			AuthMethod:   authMethodClientSecretPost,
			CodeVerifier: request.Verifier,
		})
		if token.AccessToken == "" || token.IDToken == "" {
			t.Fatalf("expected tokens, got %#v", token)
		}
	})

	t.Run("accepts public client token requests without a client secret", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49170/callback",
			Scope:       "openid profile",
			State:       "public-client-token-request",
			Verifier:    pkceVerifier("public-client-token-request"),
		}
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		if token.AccessToken == "" || token.IDToken == "" {
			t.Fatalf("expected tokens, got %#v", token)
		}
	})
}

func testTokenRequestValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("requires a matching code verifier", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("missing-code-verifier")
		authorization := authorizeAndLogin(t, provider, request)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})

	t.Run("rejects mismatched code verifiers", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("wrong-code-verifier")
		authorization := authorizeAndLogin(t, provider, request)

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
	})

	t.Run("rejects short code verifiers", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("short-code-verifier")
		authorization := authorizeAndLogin(t, provider, request)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: strings.Repeat("a", 42),
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})

	t.Run("rejects malformed code verifiers", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("malformed-code-verifier")
		authorization := authorizeAndLogin(t, provider, request)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: strings.Repeat("a", 42) + "!",
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})

	t.Run("binds authorization codes to the issuing client", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("different-client-code")
		authorization := authorizeAndLogin(t, provider, request)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
			Code:         authorization.Code,
			RedirectURI:  otherClientRedirect,
			CodeVerifier: request.Verifier,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})

	t.Run("binds authorization codes to the redirect uri", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("redirect-uri-binding")
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
	})

	t.Run("rejects reused authorization codes", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("reused-authorization-code")
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

	t.Run("rejects expired authorization codes", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("expired-authorization-code")
		authorization := authorizeAndLogin(t, provider, request)
		provider.expireAuthorizationCode(t, authorization.Code)

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
	})
}

func testSuccessfulTokenResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("successful-token-response")
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
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Fatalf("pragma mismatch: got %q", got)
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("failed to decode token response: %v\nbody=%s", err, body)
	}
	if token.AccessToken == "" || token.IDToken == "" {
		t.Fatalf("expected tokens, got %#v", token)
	}
	if token.TokenType != "Bearer" {
		t.Fatalf("token type mismatch: got %q, want %q", token.TokenType, "Bearer")
	}
	if token.ExpiresIn <= 0 {
		t.Fatalf("expected positive expires_in, got %d", token.ExpiresIn)
	}
	if token.RefreshToken == "" {
		t.Fatalf("expected refresh token, got %#v", token)
	}
}

func testRefreshRequest(t *testing.T) {
	t.Run("accepts confidential client refresh requests with client_secret_basic", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-request-basic")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})
		if refreshed.AccessToken == "" {
			t.Fatalf("expected access token, got %#v", refreshed)
		}
	})

	t.Run("accepts confidential client refresh requests with client_secret_post", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-request-post")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			AuthMethod:   authMethodClientSecretPost,
			RefreshToken: token.RefreshToken,
		})
		if refreshed.AccessToken == "" {
			t.Fatalf("expected access token, got %#v", refreshed)
		}
	})

	t.Run("accepts narrower refresh scopes", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-request-narrow-scope")
		request.Scope = "openid profile"
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
		if refreshed.Scope != "openid" {
			t.Fatalf("scope mismatch: got %q, want %q", refreshed.Scope, "openid")
		}
	})

	t.Run("rejects refresh requests that exceed the original scope", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-request-invalid-scope")
		request.Scope = "openid profile"
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			GrantType:    "refresh_token",
			RefreshToken: token.RefreshToken,
			Scope:        "openid email",
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_scope" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_scope")
		}
	})

	t.Run("rejects non-POST refresh requests", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-request-post-only")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		params := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token.RefreshToken},
			"client_id":     {request.ClientID},
			"client_secret": {webClientSecret},
		}
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/token")+"?"+params.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create token request: %v", err)
		}

		resp := provider.do(t, provider.http, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusMethodNotAllowed, body)
		}
	})
}

func testSuccessfulRefreshResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("successful-refresh-response")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	originalClaims := verifyIDToken(t, provider, token.IDToken)

	refreshed := exchangeRefreshToken(t, provider, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		RefreshToken: token.RefreshToken,
	})
	if refreshed.AccessToken == "" {
		t.Fatalf("expected access token, got %#v", refreshed)
	}
	if refreshed.TokenType != "Bearer" {
		t.Fatalf("token type mismatch: got %q, want %q", refreshed.TokenType, "Bearer")
	}
	if refreshed.ExpiresIn <= 0 {
		t.Fatalf("expected positive expires_in, got %d", refreshed.ExpiresIn)
	}
	if refreshed.Scope != token.Scope {
		t.Fatalf("scope mismatch: got %q, want %q", refreshed.Scope, token.Scope)
	}
	if refreshed.AccessToken == token.AccessToken {
		t.Fatalf("expected a new access token, got %#v", refreshed)
	}
	if refreshed.IDToken == "" {
		return
	}

	refreshedClaims := verifyIDToken(t, provider, refreshed.IDToken)
	if refreshedClaims.Iss != originalClaims.Iss || refreshedClaims.Sub != originalClaims.Sub || refreshedClaims.Aud != originalClaims.Aud {
		t.Fatalf("unexpected refreshed id token claims: %#v", refreshedClaims)
	}
	if refreshedClaims.AuthTime != originalClaims.AuthTime {
		t.Fatalf("auth_time mismatch: got %d, want %d", refreshedClaims.AuthTime, originalClaims.AuthTime)
	}
	if refreshedClaims.Iat < originalClaims.Iat {
		t.Fatalf("expected refreshed iat >= %d, got %d", originalClaims.Iat, refreshedClaims.Iat)
	}
	if refreshedClaims.Nonce != "" {
		t.Fatalf("expected refreshed id token nonce to be omitted, got %q", refreshedClaims.Nonce)
	}
}

func testRefreshErrorResponse(t *testing.T) {
	t.Run("returns invalid_request when refresh_token is missing", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			GrantType:    "refresh_token",
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("returns invalid_client when refresh client authentication fails", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-error-invalid-client")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		resp := provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: "wrong-secret",
			GrantType:    "refresh_token",
			RefreshToken: token.RefreshToken,
		})
		errResp := expectJSONError(t, resp, http.StatusUnauthorized)
		if errResp.Error != "invalid_client" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_client")
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="token"` {
			t.Fatalf("expected basic challenge, got %q", got)
		}
	})

	t.Run("returns invalid_grant when refresh tokens are used by a different client", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-error-client-binding")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
			GrantType:    "refresh_token",
			RefreshToken: token.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})
}

func testRefreshTokenRecommendations(t *testing.T) {
	t.Run("keeps refresh token scope after issuing a narrowed access token", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-token-scope-retention")
		request.Scope = "openid profile email"
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		narrowed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
			Scope:        "openid",
		})
		if narrowed.Scope != "openid" {
			t.Fatalf("scope mismatch: got %q, want %q", narrowed.Scope, "openid")
		}

		broadened := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: narrowed.RefreshToken,
		})
		if broadened.Scope != token.Scope {
			t.Fatalf("scope mismatch: got %q, want %q", broadened.Scope, token.Scope)
		}
	})

	t.Run("rotates public-client refresh tokens and revokes the active grant after replay", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49207/callback",
			Scope:       "openid profile",
			State:       "refresh-token-rotation-public",
			Verifier:    pkceVerifier("refresh-token-rotation-public"),
		}
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})

		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			RefreshToken: token.RefreshToken,
		})
		if refreshed.RefreshToken == "" || refreshed.RefreshToken == token.RefreshToken {
			t.Fatalf("expected refresh token rotation, got %#v", refreshed)
		}

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			GrantType:    "refresh_token",
			RefreshToken: token.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}

		errResp = expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			GrantType:    "refresh_token",
			RefreshToken: refreshed.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})

	t.Run("expires refresh tokens after inactivity", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-token-idle-expiry")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		provider.expireRefreshTokenIdle(t, token.RefreshToken)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			GrantType:    "refresh_token",
			RefreshToken: token.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})

	t.Run("expires refresh tokens after the client session max", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-token-session-max")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		rotatedToken := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})
		provider.expireRefreshTokenMax(t, rotatedToken.RefreshToken)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			GrantType:    "refresh_token",
			RefreshToken: rotatedToken.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})
}

func testTokenErrorResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("returns invalid_request for malformed token requests", func(t *testing.T) {
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			RedirectURI:  webClientRedirect,
			CodeVerifier: pkceVerifier("missing-code"),
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("returns invalid_request when the request body is malformed", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/token"), strings.NewReader("grant_type=%zz"))
		if err != nil {
			t.Fatalf("failed to create token request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("returns invalid_request when grant_type is missing", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("missing-grant-type")
		authorization := authorizeAndLogin(t, provider, request)
		form := url.Values{
			"code":          {authorization.Code},
			"client_id":     {request.ClientID},
			"client_secret": {webClientSecret},
			"redirect_uri":  {request.RedirectURI},
			"code_verifier": {request.Verifier},
		}
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/token"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create token request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("returns unsupported_grant_type for unsupported grants", func(t *testing.T) {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {webClientID},
			"client_secret": {webClientSecret},
		}
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/token"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create token request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "unsupported_grant_type" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "unsupported_grant_type")
		}
	})

	t.Run("returns invalid_client for failed client authentication", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("invalid-client-token-error")
		authorization := authorizeAndLogin(t, provider, request)

		resp := provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: "wrong-secret",
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		errResp := expectJSONError(t, resp, http.StatusUnauthorized)
		if errResp.Error != "invalid_client" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_client")
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="token"` {
			t.Fatalf("expected basic challenge, got %q", got)
		}
	})

	t.Run("returns invalid_grant for invalid authorization grants", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("invalid-grant-token-error")
		authorization := authorizeAndLogin(t, provider, request)

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
	})
}

func testTokenResponseValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("token-response-validation")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	claims := verifyIDToken(t, provider, token.IDToken)

	if claims.Iss != provider.issuer {
		t.Fatalf("issuer mismatch: got %q, want %q", claims.Iss, provider.issuer)
	}
	if claims.Aud != request.ClientID {
		t.Fatalf("audience mismatch: got %q, want %q", claims.Aud, request.ClientID)
	}
	if claims.AtHash != "" && claims.AtHash != accessTokenHash(token.AccessToken) {
		t.Fatalf("at_hash mismatch: got %q, want %q", claims.AtHash, accessTokenHash(token.AccessToken))
	}
}

func testIDToken(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("id-token-contents")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	claims := verifyIDToken(t, provider, token.IDToken)

	if claims.Iss != provider.issuer || claims.Sub != testSubject || claims.Aud != request.ClientID {
		t.Fatalf("unexpected id token claims: %#v", claims)
	}
	if claims.Nonce != request.Nonce {
		t.Fatalf("nonce mismatch: got %q, want %q", claims.Nonce, request.Nonce)
	}
	if claims.AuthTime == 0 {
		t.Fatalf("expected auth_time claim, got %#v", claims)
	}
	if claims.Iat == 0 || claims.Exp <= claims.Iat {
		t.Fatalf("invalid iat/exp claims: %#v", claims)
	}
}

func testTokenEndpointIDToken(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("token-endpoint-id-token")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	claims := verifyIDToken(t, provider, token.IDToken)

	if claims.AtHash == "" {
		t.Fatalf("expected at_hash claim, got %#v", claims)
	}
	if claims.AtHash != accessTokenHash(token.AccessToken) {
		t.Fatalf("at_hash mismatch: got %q, want %q", claims.AtHash, accessTokenHash(token.AccessToken))
	}
}

func testIDTokenValidation(t *testing.T) {
	config := defaultProviderConfig()
	config.IssuerPath = "/issuer"
	provider := startProvider(t, config)
	request := newDefaultConfidentialAuthorizationRequest("id-token-validation")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	header := decodeJWTHeader(t, token.IDToken)
	claims := verifyIDToken(t, provider, token.IDToken)

	if header.Alg != "RS256" || header.Typ != "JWT" || header.Kid == "" {
		t.Fatalf("unexpected jwt header: %#v", header)
	}
	if claims.Iss != provider.issuer {
		t.Fatalf("issuer mismatch: got %q, want %q", claims.Iss, provider.issuer)
	}
	if claims.Aud != request.ClientID {
		t.Fatalf("audience mismatch: got %q, want %q", claims.Aud, request.ClientID)
	}
	if claims.Exp <= claims.Iat {
		t.Fatalf("expected exp > iat, got iat=%d exp=%d", claims.Iat, claims.Exp)
	}
}

func testAccessTokenValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("access-token-validation")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	claims := verifyIDToken(t, provider, token.IDToken)

	if claims.AtHash == "" {
		t.Fatalf("expected at_hash claim, got %#v", claims)
	}
	if claims.AtHash != accessTokenHash(token.AccessToken) {
		t.Fatalf("at_hash mismatch: got %q, want %q", claims.AtHash, accessTokenHash(token.AccessToken))
	}
}

func testQuerySerialization(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("query-serialization")
	request.State = "state with spaces/+?&="

	resp := provider.getAuthorize(t, authorizeParams(request))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
	if got := redirect.Query().Get("state"); got != request.State {
		t.Fatalf("state mismatch: got %q, want %q", got, request.State)
	}
}

func testFormSerialization(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("form-serialization")

	t.Run("accepts authorization requests in form-encoded POST bodies", func(t *testing.T) {
		body := authorizeByPostExpectLoginPage(t, provider, request)
		if !strings.Contains(string(body), `method="POST"`) {
			t.Fatalf("expected form POST login page, got body=%s", body)
		}
	})

	t.Run("accepts token requests in form-encoded POST bodies", func(t *testing.T) {
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		if token.AccessToken == "" {
			t.Fatalf("expected access token, got %#v", token)
		}
	})
}

func testJSONSerialization(t *testing.T) {
	t.Run("serializes token responses as JSON objects", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("json-token")
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
		payload := decodeJSONMap(t, body)
		if got, ok := payload["access_token"].(string); !ok || got == "" {
			t.Fatalf("expected access_token in token response, got %#v", payload)
		}
		if _, ok := payload["token_type"].(string); !ok {
			t.Fatalf("expected token_type to be a string, got %#v", payload["token_type"])
		}
		if _, ok := payload["expires_in"].(float64); !ok {
			t.Fatalf("expected expires_in to be numeric, got %#v", payload["expires_in"])
		}
		if _, ok := payload["scope"].(string); !ok {
			t.Fatalf("expected scope to be a string, got %#v", payload["scope"])
		}
		if _, ok := payload["refresh_token"].(string); !ok {
			t.Fatalf("expected refresh_token to be a string, got %#v", payload["refresh_token"])
		}
		if _, ok := payload["id_token"].(string); !ok {
			t.Fatalf("expected id_token to be a string, got %#v", payload["id_token"])
		}
		for key, value := range payload {
			if value == nil {
				t.Fatalf("did not expect null JSON member %q in %#v", key, payload)
			}
		}
	})

	t.Run("serializes userinfo responses as JSON objects", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].Profile = ""
		config.Users[0].Picture = ""
		config.Users[0].Locale = ""
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("json-userinfo")
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
		payload := decodeJSONMap(t, body)
		if got, ok := payload["sub"].(string); !ok || got == "" {
			t.Fatalf("expected sub in userinfo response, got %#v", payload)
		}
		if _, ok := payload["email_verified"].(bool); !ok {
			t.Fatalf("expected email_verified to be a boolean, got %#v", payload["email_verified"])
		}
		for key, value := range payload {
			if value == nil {
				t.Fatalf("did not expect null JSON member %q in %#v", key, payload)
			}
		}
		for _, claim := range []string{"profile", "picture", "locale"} {
			if _, ok := payload[claim]; ok {
				t.Fatalf("did not expect %s claim when its value is empty, got %#v", claim, payload)
			}
		}
	})
}

func testStringOperations(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("treats scope values as case-sensitive", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("scope-case-sensitive")
		request.Scope = "OpenID profile"

		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_scope")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "openid") {
			t.Fatalf("expected openid scope error, got %q", got)
		}
	})

	t.Run("matches client identifiers exactly", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("client-id-string-ops")
		request.ClientID = strings.ToUpper(request.ClientID)

		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
	})

	t.Run("rejects invalid prompt tokenization", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("prompt-string-ops")
		params := authorizeParams(request)
		params.Set("prompt", "none consent")

		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
	})
}

func testMandatoryToImplementFeaturesForAllOpenIDProviders(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("signs issued id tokens with RS256", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("mti-op-rs256")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		header := decodeJWTHeader(t, token.IDToken)
		if header.Alg != "RS256" {
			t.Fatalf("signing algorithm mismatch: got %q, want %q", header.Alg, "RS256")
		}
	})

	t.Run("accepts supported prompt and localization parameters", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("mti-op-supported-inputs")
		params := authorizeParams(request)
		params.Set("display", "page")
		params.Set("ui_locales", "fr-CA fr en")
		params.Set("claims_locales", "fr en")
		params.Set("acr_values", "urn:example:loa:1")
		params.Set("prompt", "login")

		resp := provider.getAuthorize(t, params)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Sign in") {
			t.Fatalf("expected login form, got body=%s", body)
		}
	})

	t.Run("supports prompt=none for existing sessions", func(t *testing.T) {
		baseline := newDefaultConfidentialAuthorizationRequest("mti-op-prompt-none-baseline")
		_ = authorizeAndExchange(t, provider, baseline, tokenRequest{
			ClientID:     baseline.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: baseline.Verifier,
		})

		request := newDefaultConfidentialAuthorizationRequest("mti-op-prompt-none")
		request.Prompt = "none"

		_ = expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
	})

	t.Run("accepts max_age and returns auth_time", func(t *testing.T) {
		baseline := newDefaultConfidentialAuthorizationRequest("mti-op-max-age-baseline")
		baselineToken := authorizeAndExchange(t, provider, baseline, tokenRequest{
			ClientID:     baseline.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: baseline.Verifier,
		})
		baselineClaims := verifyIDToken(t, provider, baselineToken.IDToken)

		request := newDefaultConfidentialAuthorizationRequest("mti-op-max-age-within-window")
		params := authorizeParams(request)
		params.Set("max_age", "300")

		code := expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		if claims.AuthTime != baselineClaims.AuthTime {
			t.Fatalf("expected reused session auth_time %d, got %d", baselineClaims.AuthTime, claims.AuthTime)
		}

		request = newDefaultConfidentialAuthorizationRequest("mti-op-max-age")
		params = authorizeParams(request)
		params.Set("max_age", "0")

		resp := provider.getAuthorize(t, params)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Sign in") {
			t.Fatalf("expected login form, got body=%s", body)
		}

		token = exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer),
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		claims = verifyIDToken(t, provider, token.IDToken)
		if claims.AuthTime == 0 {
			t.Fatalf("expected auth_time claim, got %#v", claims)
		}
	})
}

func testTokenReuse(t *testing.T) {
	t.Run("rejects reused authorization codes", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("oidc-code-reuse")
		authorization := authorizeAndLogin(t, provider, request)

		_ = exchangeAuthorizationCode(t, provider, tokenRequest{
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
	})

	t.Run("rejects replayed refresh tokens and revokes the active grant", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("oidc-refresh-token-reuse")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			GrantType:    "refresh_token",
			RefreshToken: token.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}

		errResp = expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			GrantType:    "refresh_token",
			RefreshToken: refreshed.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})
}

func testHTTP307Redirects(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("login POST redirects use 303", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("no-307-login")
		resp := provider.getAuthorize(t, authorizeParams(request))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}

		redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
		if redirect.Query().Get("code") == "" {
			t.Fatalf("expected authorization code, got %q", redirect.String())
		}
	})

	t.Run("consent POST redirects use 303", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("no-307-consent")
		request.Prompt = "consent"
		body := authorizeAndLoginExpectPage(t, provider, request)

		redirect := expectRedirect(t, submitConsentForm(t, provider, body, "yes"), http.StatusSeeOther)
		if redirect.Query().Get("code") == "" {
			t.Fatalf("expected authorization code, got %q", redirect.String())
		}
	})
}
