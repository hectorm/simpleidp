package simpleidp

// Reference material:
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt

import (
	"encoding/json/v2"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
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

	t.Run("keeps POSTed authorization parameters out of the login form URL", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("auth-request-post-hidden")
		body := authorizeByPostExpectLoginPage(t, provider, request)
		if action := extractFormAction(t, body); strings.Contains(action, "?") {
			t.Fatalf("login form action must not carry request parameters, got %q", action)
		}
		hidden := extractHiddenInputs(t, body)
		hidden.Del("csrf_token")
		if got := hidden.Encode(); got != authorizeParams(request).Encode() {
			t.Fatalf("hidden parameters mismatch: got %q, want %q", got, authorizeParams(request).Encode())
		}
	})

	t.Run("reuses the session for cross-site POST authorization requests", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("auth-request-cross-site-session"))
		request := newDefaultConfidentialAuthorizationRequest("auth-request-cross-site")
		request.Prompt = "none"
		params := authorizeParams(request)
		body := expectResubmitForm(t, provider.postCrossSite(t, provider.endpoint("/authorize"), params), params)

		code := expectAuthorizationCodeRedirect(t, submitResubmitForm(t, provider, body), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
		_ = exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			CodeVerifier: request.Verifier,
		})
	})

	t.Run("signs in from cross-site POST authorization requests without a session", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("auth-request-cross-site-login")
		params := authorizeParams(request)
		body := expectResubmitForm(t, provider.postCrossSite(t, provider.endpoint("/authorize"), params), params)

		resp := submitResubmitForm(t, provider, body)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Sign in") {
			t.Fatalf("expected login form, got body=%s", body)
		}
		_ = expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
	})

	t.Run("auto-submits cross-site POST authorization requests whose parameters shadow form methods", func(t *testing.T) {
		params := authorizeParams(newDefaultConfidentialAuthorizationRequest("auth-request-cross-site-shadowing"))
		params.Set("submit", "shadowed")
		_ = expectResubmitForm(t, provider.postCrossSite(t, provider.endpoint("/authorize"), params), params)
	})
}

func testAuthenticationRequestValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("rejects missing required parameters", func(t *testing.T) {
		for _, parameter := range []string{"scope", "response_type"} {
			t.Run(parameter, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("missing-" + parameter)
				params := authorizeParams(request)
				params.Del(parameter)

				redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
				if got := redirect.Query().Get("error_description"); !strings.Contains(got, parameter) {
					t.Fatalf("expected missing %s error, got %q", parameter, got)
				}
			})
		}
	})

	t.Run("does not redirect when client_id or redirect_uri is missing", func(t *testing.T) {
		for _, parameter := range []string{"client_id", "redirect_uri"} {
			t.Run(parameter, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("missing-" + parameter)
				params := authorizeParams(request)
				params.Del(parameter)

				resp := provider.getAuthorize(t, params)
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
		for _, prompt := range []string{"none consent", "unknown"} {
			t.Run(prompt, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("invalid-prompt")
				params := authorizeParams(request)
				params.Set("prompt", prompt)

				redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
				if got := redirect.Query().Get("error_description"); !strings.Contains(got, "prompt") {
					t.Fatalf("expected prompt error, got %q", got)
				}
			})
		}
	})

	t.Run("rejects invalid max_age values", func(t *testing.T) {
		for _, maxAge := range []string{"-1", "1.5"} {
			t.Run(maxAge, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("invalid-max-age")
				params := authorizeParams(request)
				params.Set("max_age", maxAge)

				redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
				if got := redirect.Query().Get("error_description"); !strings.Contains(got, "max_age") {
					t.Fatalf("expected max_age error, got %q", got)
				}
			})
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

	t.Run("rejects access and logout tokens as id token hints", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("id-token-hint-token-types-source")
		source := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		_ = verifyAccessToken(t, provider, source.AccessToken)
		claims := verifyIDToken(t, provider, source.IDToken)
		user, ok := provider.idp.lookupUser("ALICE")
		if !ok {
			t.Fatal("expected configured user")
		}
		logoutToken, err := provider.idp.mintLogoutToken(user, provider.idp.clients[webClientID], claims.Sid)
		if err != nil {
			t.Fatalf("failed to mint logout token: %v", err)
		}
		_ = verifyLogoutToken(t, provider, logoutToken)

		for tokenType, hint := range map[string]string{"access token": source.AccessToken, "logout token": logoutToken} {
			t.Run(tokenType, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("id-token-hint-token-types")
				request.Prompt = "none"
				params := authorizeParams(request)
				params.Set("id_token_hint", hint)
				redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
				if got := redirect.Query().Get("error_description"); !strings.Contains(got, "id_token_hint") {
					t.Fatalf("expected id_token_hint error, got %q", got)
				}
			})
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

	t.Run("returns login_required when the active session does not match the id token hint", func(t *testing.T) {
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
		source := authorizeAndExchange(t, provider, newDefaultConfidentialAuthorizationRequest("id-token-hint-session-mismatch-source"), tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: pkceVerifier("id-token-hint-session-mismatch-source"),
		})

		browser := newProviderBrowser(t, provider)
		loginRequest := newDefaultConfidentialAuthorizationRequest("id-token-hint-session-mismatch-login")
		resp := browser.getAuthorize(t, authorizeParams(loginRequest))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		expectAuthorizationCodeRedirect(t, submitLoginForm(t, browser, body, "bob", "hunter2"), http.StatusSeeOther, loginRequest.RedirectURI, loginRequest.State, provider.issuer)

		request := newDefaultConfidentialAuthorizationRequest("id-token-hint-session-mismatch")
		request.Prompt = "none"
		params := authorizeParams(request)
		code := expectAuthorizationCodeRedirect(t, browser.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
		token := exchangeAuthorizationCode(t, browser, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		if claims := verifyIDToken(t, browser, token.IDToken); claims.Sub != "bob-subject" {
			t.Fatalf("expected an active Bob session, got subject %q", claims.Sub)
		}
		params.Set("id_token_hint", source.IDToken)

		expectAuthorizationErrorRedirect(t, browser.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
	})

	t.Run("rejects nonce values that are not valid UTF-8", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("invalid-utf8-nonce")
		request.Nonce = "\xff"
		redirect := expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "invalid_request")
		if got := redirect.Query().Get("error_description"); !strings.Contains(got, "nonce") {
			t.Fatalf("expected nonce error, got %q", got)
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

	t.Run("rejects duplicate recognized parameters", func(t *testing.T) {
		hintRequest := newDefaultConfidentialAuthorizationRequest("duplicate-parameter-id-token-hint")
		hintToken := authorizeAndExchange(t, provider, hintRequest, tokenRequest{
			ClientID:     hintRequest.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: hintRequest.Verifier,
		})
		parameterValues := map[string]string{
			"response_mode": "query", "prompt": "login", "max_age": "300",
			"display": "page", "ui_locales": "en", "claims_locales": "en",
			"claims": "{}", "registration": "{}",
			"id_token_hint": hintToken.IDToken, "login_hint": testUsername,
			"acr_values": "urn:example:authentication",
		}
		for _, method := range []string{http.MethodGet, "POST query", "POST body"} {
			t.Run(method, func(t *testing.T) {
				for _, parameter := range []string{
					"response_type", "response_mode", "scope", "state", "nonce", "display",
					"prompt", "max_age", "ui_locales", "claims_locales", "id_token_hint",
					"login_hint", "acr_values", "claims", "registration",
					"code_challenge", "code_challenge_method",
				} {
					t.Run(parameter, func(t *testing.T) {
						request := newDefaultConfidentialAuthorizationRequest("duplicate-" + parameter)
						params := authorizeParams(request)
						if !params.Has(parameter) {
							params.Set(parameter, parameterValues[parameter])
						}
						params.Add(parameter, params.Get(parameter))

						var resp *http.Response
						status := http.StatusSeeOther
						switch method {
						case http.MethodGet:
							resp = provider.getAuthorize(t, params)
							status = http.StatusFound
						case "POST query":
							resp = provider.postAuthorize(t, params, nil)
						case "POST body":
							resp = provider.postAuthorize(t, nil, params)
						}
						redirect := expectAuthorizationErrorRedirect(t, resp, status, request.RedirectURI, request.State, provider.issuer, "invalid_request")
						if got := redirect.Query().Get("error_description"); !strings.Contains(got, "Duplicate parameter") {
							t.Fatalf("expected duplicate parameter error, got %q", got)
						}
					})
				}
			})
		}
	})

	t.Run("ignores repeated unknown parameters", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(method, func(t *testing.T) {
				provider := startProvider(t, defaultProviderConfig())
				request := newDefaultConfidentialAuthorizationRequest("unknown-authorize-parameters-" + method)
				params := authorizeParams(request)
				params["unknown_parameter"] = []string{"first", "second"}

				var resp *http.Response
				if method == http.MethodPost {
					body := expectResubmitForm(t, provider.postAuthorize(t, nil, params), params)
					resp = submitResubmitForm(t, provider, body)
				} else {
					resp = provider.getAuthorize(t, params)
				}
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
				}
				code := expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
				token := exchangeAuthorizationCode(t, provider, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					Code:         code,
					CodeVerifier: request.Verifier,
				})
				if token.AccessToken == "" {
					t.Fatalf("expected access token, got %#v", token)
				}
			})
		}
	})

	t.Run("does not redirect duplicate client identifiers or redirect uris", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, "POST query", "POST body"} {
			t.Run(method, func(t *testing.T) {
				for _, parameter := range []string{"client_id", "redirect_uri"} {
					t.Run(parameter, func(t *testing.T) {
						request := newDefaultConfidentialAuthorizationRequest("duplicate-" + parameter)
						params := authorizeParams(request)
						params.Add(parameter, params.Get(parameter))

						var resp *http.Response
						switch method {
						case http.MethodGet:
							resp = provider.getAuthorize(t, params)
						case "POST query":
							resp = provider.postAuthorize(t, params, nil)
						case "POST body":
							resp = provider.postAuthorize(t, nil, params)
						}
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
		_ = authorizeAndLogin(t, provider, initialRequest)
		authenticatedAt := provider.ageSession(t, 2*time.Minute, 0).Unix()

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
		if claims.AuthTime != authenticatedAt {
			t.Fatalf("expected reused session auth_time %d, got %d", authenticatedAt, claims.AuthTime)
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

	t.Run("creates a new session when the previous one expires during reauthentication", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("reauthentication-expired-session")
		_ = authorizeAndLogin(t, provider, request)
		sessionID := provider.currentSessionID(t)
		request.Prompt = "login"
		body := readBody(t, provider.getAuthorize(t, authorizeParams(request)))
		provider.expireSessionMax(t)

		code := expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		if claims.Sid == sessionID {
			t.Fatal("expected a new session identifier after the previous session expired")
		}
		if claims.Sub != testSubject {
			t.Fatalf("subject mismatch after reauthentication: got %q, want %q", claims.Sub, testSubject)
		}
	})

	t.Run("rotates the session cookie when the same user reauthenticates", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("reauthentication-cookie-rotation")
		_ = authorizeAndLogin(t, provider, request)
		sessionID := provider.currentSessionID(t)
		previousCookie := provider.currentSessionCookie(t)

		_ = authorizeAndLogin(t, provider, request)
		if provider.currentSessionCookie(t).Value == previousCookie.Value {
			t.Fatal("expected a new session cookie after reauthentication")
		}
		if got := provider.currentSessionID(t); got != sessionID {
			t.Fatalf("session changed after reauthentication: got %q, want %q", got, sessionID)
		}

		request.Prompt = "none"
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/authorize")+"?"+authorizeParams(request).Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create authorization request: %v", err)
		}
		req.AddCookie(previousCookie)
		browser := newProviderBrowser(t, provider)
		expectAuthorizationErrorRedirect(t, browser.do(t, browser.redirectless, req), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
		expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
	})

	t.Run("returns a positive response for prompt none when a session exists", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		initialRequest := newDefaultConfidentialAuthorizationRequest("prompt-none-session-initial")
		_ = authorizeAndLogin(t, provider, initialRequest)
		authenticatedAt := provider.ageSession(t, 2*time.Minute, 0).Unix()

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
		if claims.AuthTime != authenticatedAt {
			t.Fatalf("expected reused session auth_time %d, got %d", authenticatedAt, claims.AuthTime)
		}
	})

	t.Run("handles whitespace around prompt none without interaction", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("prompt-none-whitespace")
		anonymous := newProviderBrowser(t, provider)
		authorizeAndLogin(t, provider, request)
		for _, prompt := range []string{"none", " none", "none ", " none ", "\tnone\n"} {
			t.Run(fmt.Sprintf("%q", prompt), func(t *testing.T) {
				request.Prompt = prompt
				expectAuthorizationErrorRedirect(t, anonymous.getAuthorize(t, authorizeParams(request)), http.StatusFound,
					request.RedirectURI, request.State, provider.issuer, "login_required")
				expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound,
					request.RedirectURI, request.State, provider.issuer)
			})
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

	t.Run("renews the pre-auth cookie whenever it renders a login form", func(t *testing.T) {
		browser := newProviderBrowser(t, provider)
		var preAuthIDs []string
		for range 2 {
			resp := browser.getAuthorize(t, authorizeParams(request))
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
			}
			var renewed *http.Cookie
			for _, cookie := range resp.Cookies() {
				if cookie.Name == provider.idp.cookieName(preAuthSessionCookieBaseName) {
					renewed = cookie
				}
			}
			if renewed == nil || renewed.MaxAge != int(loginActionTTL.Seconds()) {
				t.Fatalf("expected a renewed pre-auth cookie, got %v", resp.Cookies())
			}
			preAuthIDs = append(preAuthIDs, renewed.Value)
		}
		if preAuthIDs[0] != preAuthIDs[1] {
			t.Fatalf("expected the pre-auth ID to be kept, got %q then %q", preAuthIDs[0], preAuthIDs[1])
		}
	})

	t.Run("asks users with a TOTP secret for an authentication code", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("totp-authentication")
		body := authorizeAndLoginExpectPage(t, provider, request)
		if !strings.Contains(string(body), `data-testid="page-totp"`) {
			t.Fatalf("expected TOTP form, got body=%s", body)
		}
		expectAuthorizationCodeRedirect(t, submitTOTPForm(t, provider, body, currentTOTPCode()), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
	})

	t.Run("allows retrying after an empty authentication code", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("totp-empty-code")
		body := authorizeAndLoginExpectPage(t, provider, request)
		resp := submitTOTPForm(t, provider, body, "")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), `data-testid="page-totp"`) || !strings.Contains(string(body), "Invalid authentication code") {
			t.Fatalf("expected TOTP form with an authentication error, got body=%s", body)
		}
		expectAuthorizationCodeRedirect(t, submitTOTPForm(t, provider, body, currentTOTPCode()), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
	})

	t.Run("does not sign in before the authentication code is verified", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("totp-pending-authentication")
		_ = authorizeAndLoginExpectPage(t, provider, request)

		request.Prompt = "none"
		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
	})

	t.Run("rejects duplicate authentication codes", func(t *testing.T) {
		for _, method := range []string{"POST query", "POST body"} {
			t.Run(method, func(t *testing.T) {
				config := defaultProviderConfig()
				config.Users[0].TOTPSecret = testTOTPKeyBase32
				provider := startProvider(t, config)
				request := newDefaultConfidentialAuthorizationRequest("totp-duplicate-code")
				body := authorizeAndLoginExpectPage(t, provider, request)
				params := authorizeParams(request)
				form := url.Values{
					"csrf_token": {extractHiddenInputValue(t, body, "csrf_token")},
					"totp":       {currentTOTPCode(), currentTOTPCode()},
				}

				var resp *http.Response
				if method == "POST query" {
					resp = provider.postAuthorize(t, params, form)
				} else {
					maps.Copy(form, params)
					resp = provider.postAuthorize(t, nil, form)
				}
				redirect := expectAuthorizationErrorRedirect(t, resp, http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer, "invalid_request")
				if got := redirect.Query().Get("error_description"); !strings.Contains(got, "Duplicate parameter") {
					t.Fatalf("expected duplicate parameter error, got %q", got)
				}
			})
		}
	})

	t.Run("rejects authentication codes without csrf protection", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("totp-csrf")
		_ = authorizeAndLoginExpectPage(t, provider, request)

		resp := provider.postAuthorize(t, authorizeParams(request), url.Values{
			"totp": {currentTOTPCode()},
		})
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
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

	t.Run("shows the end user the granted scopes and redirect URI", func(t *testing.T) {
		spoofedRequest := request
		spoofedRequest.Scope = "openid email -- note: this app will NOT read your email address"
		body := authorizeAndLoginExpectPage(t, provider, spoofedRequest)
		if want := `data-testid="message">Allow ` + webClientID + ` to access these scopes: openid email?</p>`; !strings.Contains(string(body), want) {
			t.Fatalf("expected consent message %q, got body=%s", want, body)
		}
		if want := "<dd>" + spoofedRequest.RedirectURI + "</dd>"; !strings.Contains(string(body), want) {
			t.Fatalf("expected consent redirect URI %q, got body=%s", want, body)
		}

		code := expectAuthorizationCodeRedirect(t, submitConsentForm(t, provider, body, "yes"), http.StatusSeeOther, spoofedRequest.RedirectURI, spoofedRequest.State, provider.issuer)
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     spoofedRequest.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			CodeVerifier: spoofedRequest.Verifier,
		})
		if token.Scope != "openid email" {
			t.Fatalf("scope mismatch: got %q, want %q", token.Scope, "openid email")
		}
	})

	t.Run("keeps the issued authorization code out of the consent page", func(t *testing.T) {
		body := authorizeAndLoginExpectPage(t, provider, request)
		if action := extractFormAction(t, body); strings.Contains(action, "?") {
			t.Fatalf("consent form action must not carry request parameters, got %q", action)
		}
		pending := extractHiddenInputValue(t, body, "code")
		code := expectAuthorizationCodeRedirect(t, submitConsentForm(t, provider, body, "yes"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
		if code == pending {
			t.Fatal("expected a fresh authorization code after consent")
		}
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         pending,
			CodeVerifier: request.Verifier,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
		_ = exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			CodeVerifier: request.Verifier,
		})
	})

	t.Run("rejects consent submissions without csrf protection", func(t *testing.T) {
		body := authorizeAndLoginExpectPage(t, provider, request)
		form := extractHiddenInputs(t, body)
		form.Del("csrf_token")
		form.Set("confirm", "yes")
		resp := provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, body)), form, "", false)
		raw := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("consent status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, raw)
		}
		if !strings.Contains(string(raw), "Invalid or expired session") {
			t.Fatalf("expected invalid session error, got body=%s", raw)
		}
	})

	t.Run("binds consent to the browser session that requested it", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users = append(config.Users, userConfig{
			Label:    "BOB",
			Username: "bob",
			Password: "bob-password",
			Sub:      "bob-subject",
			Name:     "Bob Example",
			Email:    "bob@example.com",
		})
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("consent-session-binding")
		request.Prompt = "consent"
		consentBody := authorizeAndLoginExpectPage(t, provider, request)

		for _, username := range []string{testUsername, "bob"} {
			t.Run(username, func(t *testing.T) {
				browser := newProviderBrowser(t, provider)
				loginBody := readBody(t, browser.getAuthorize(t, authorizeParams(request)))
				password := testPassword
				if username == "bob" {
					password = "bob-password"
				}
				otherConsentBody := readBody(t, submitLoginForm(t, browser, loginBody, username, password))
				form := extractHiddenInputs(t, consentBody)
				form.Set("state", "other-browser-state")
				form.Set("confirm", "yes")
				form.Set("csrf_token", extractHiddenInputValue(t, otherConsentBody, "csrf_token"))
				resp := browser.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, consentBody)), form, "", false)
				expectAuthorizationErrorRedirect(t, resp, http.StatusSeeOther, request.RedirectURI, "other-browser-state", provider.issuer, "invalid_request")
			})
		}

		code := expectAuthorizationCodeRedirect(t, submitConsentForm(t, provider, consentBody, "yes"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			CodeVerifier: request.Verifier,
		})
		if claims := verifyIDToken(t, provider, token.IDToken); claims.Sub != testSubject {
			t.Fatalf("subject mismatch after consent: got %q, want %q", claims.Sub, testSubject)
		}
	})

	t.Run("binds consent to the client that requested it", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Clients[1].RedirectURL = webClientRedirect
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("consent-client-binding")
		request.Prompt = "consent"
		body := authorizeAndLoginExpectPage(t, provider, request)
		form := extractHiddenInputs(t, body)
		form.Set("client_id", otherClientID)
		form.Set("confirm", "yes")
		resp := provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, body)), form, "", false)
		expectAuthorizationErrorRedirect(t, resp, http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer, "invalid_request")
	})

	t.Run("binds consent to the redirect uri that requested it", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Clients[0].RedirectURL += " " + otherClientRedirect
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("consent-redirect-binding")
		request.Prompt = "consent"
		body := authorizeAndLoginExpectPage(t, provider, request)
		form := extractHiddenInputs(t, body)
		form.Set("redirect_uri", otherClientRedirect)
		form.Set("confirm", "yes")
		resp := provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, body)), form, "", false)
		expectAuthorizationErrorRedirect(t, resp, http.StatusSeeOther, otherClientRedirect, request.State, provider.issuer, "invalid_request")
	})

	t.Run("rejects consent after the browser session expires", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("consent-expired-session")
		request.Prompt = "consent"
		body := authorizeAndLoginExpectPage(t, provider, request)
		provider.expireSessionMax(t)
		expectAuthorizationErrorRedirect(t, submitConsentForm(t, provider, body, "yes"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer, "invalid_request")
	})

	t.Run("rejects consent after the pending authorization code expires", func(t *testing.T) {
		body := authorizeAndLoginExpectPage(t, provider, request)
		pending := extractHiddenInputValue(t, body, "code")
		provider.expireAuthorizationCode(t, pending)
		expectAuthorizationErrorRedirect(t, submitConsentForm(t, provider, body, "yes"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer, "invalid_request")
	})
}

func testSuccessfulAuthenticationResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("successful-auth-response")
	request.State = "state with spaces/+?&="

	resp := provider.getAuthorize(t, authorizeParams(request))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
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

	t.Run("accepts form-encoded client_secret_basic credentials", func(t *testing.T) {
		for _, credentials := range []struct {
			name         string
			clientID     string
			clientSecret string
		}{
			{"space in client ID", "client id", webClientSecret},
			{"plus in client ID", "client+id", webClientSecret},
			{"percent in client ID", "client%2Bid", webClientSecret},
			{"colon in client ID", "client:id", webClientSecret},
			{"space in client secret", webClientID, "secret value"},
			{"plus in client secret", webClientID, "secret+value"},
			{"percent in client secret", webClientID, "secret%2Bvalue"},
			{"colon in client secret", webClientID, "secret:value"},
		} {
			t.Run(credentials.name, func(t *testing.T) {
				config := defaultProviderConfig()
				config.Clients[0].ID = credentials.clientID
				config.Clients[0].Secret = credentials.clientSecret
				provider := startProvider(t, config)
				request := newDefaultConfidentialAuthorizationRequest("token-request-encoded-credentials")
				request.ClientID = credentials.clientID
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: credentials.clientSecret,
					CodeVerifier: request.Verifier,
				})
				if token.AccessToken == "" || token.IDToken == "" {
					t.Fatalf("expected tokens, got %#v", token)
				}
				claims := verifyAccessToken(t, provider, token.AccessToken)
				if claims.ClientID != request.ClientID {
					t.Fatalf("client_id mismatch: got %q, want %q", claims.ClientID, request.ClientID)
				}
			})
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

	t.Run("returns invalid_request when the code verifier is missing", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("missing-code-verifier")
		authorization := authorizeAndLogin(t, provider, request)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
		_ = exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
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

	for _, testCase := range []struct {
		name     string
		verifier string
	}{
		{"rejects short code verifiers", strings.Repeat("a", 42)},
		{"rejects long code verifiers", strings.Repeat("a", 129)},
		{"rejects malformed code verifiers", strings.Repeat("a", 42) + "!"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := newDefaultConfidentialAuthorizationRequest(testCase.name)
			request.Verifier = testCase.verifier
			authorization := authorizeAndLogin(t, provider, request)

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

	t.Run("accepts the full code verifier syntax and length boundaries", func(t *testing.T) {
		for _, verifier := range []string{
			strings.Repeat("a", 43),
			strings.Repeat("a", 128),
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
		} {
			t.Run(verifier, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("valid-code-verifier")
				request.Verifier = verifier
				_ = authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
			})
		}
	})

	t.Run("binds authorization codes to the issuing client", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("different-client-code")
		authorization := authorizeAndLogin(t, provider, request)

		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
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

	t.Run("rejects authorization codes after their browser session expires", func(t *testing.T) {
		for _, phase := range []string{"before cleanup", "after cleanup"} {
			t.Run(phase, func(t *testing.T) {
				provider := startProvider(t, defaultProviderConfig())
				request := newDefaultConfidentialAuthorizationRequest("code-expired-session")
				authorization := authorizeAndLogin(t, provider, request)
				provider.expireSessionMax(t)
				if phase == "after cleanup" {
					request.Prompt = "none"
					expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
				}
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
	assertTokenResponseHeaders(t, resp)

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("failed to decode token response: %v\nbody=%s", err, body)
	}
	if token.AccessToken == "" || token.IDToken == "" {
		t.Fatalf("expected tokens, got %#v", token)
	}
	if !strings.EqualFold(token.TokenType, "Bearer") {
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

	t.Run("omits the id token when a narrower refresh scope drops openid", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-request-without-openid")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
			Scope:        "email",
		})
		if refreshed.Scope != "email" {
			t.Fatalf("scope mismatch: got %q, want %q", refreshed.Scope, "email")
		}
		if refreshed.IDToken != "" {
			t.Fatalf("did not expect an id token without the openid scope, got %q", refreshed.IDToken)
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

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusMethodNotAllowed, body)
		}
	})
}

func testSuccessfulRefreshResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("successful-refresh-response")
	_ = authorizeAndLogin(t, provider, request)
	authenticatedAt := provider.ageSession(t, 2*time.Minute, 0).Unix()
	request.Prompt = "none"
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	originalClaims := verifyIDToken(t, provider, token.IDToken)
	if originalClaims.AuthTime != authenticatedAt {
		t.Fatalf("auth_time mismatch: got %d, want %d", originalClaims.AuthTime, authenticatedAt)
	}

	issuedAfter := time.Now().Unix()
	refreshed := exchangeRefreshToken(t, provider, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		RefreshToken: token.RefreshToken,
	})
	if refreshed.AccessToken == "" {
		t.Fatalf("expected access token, got %#v", refreshed)
	}
	if !strings.EqualFold(refreshed.TokenType, "Bearer") {
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
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == token.RefreshToken {
		t.Fatalf("expected confidential-client refresh token rotation, got %#v", refreshed)
	}
	if refreshed.IDToken == "" {
		t.Fatal("expected the provider to issue an ID Token when the refreshed scope includes openid")
	}

	refreshedClaims := verifyIDToken(t, provider, refreshed.IDToken)
	if got, want := refreshedClaims.AtHash, accessTokenHash(refreshed.AccessToken); got != want {
		t.Fatalf("refreshed at_hash mismatch: got %q, want %q", got, want)
	}
	if refreshedClaims.Iss != originalClaims.Iss || refreshedClaims.Sub != originalClaims.Sub || refreshedClaims.Aud != originalClaims.Aud {
		t.Fatalf("unexpected refreshed id token claims: %#v", refreshedClaims)
	}
	if refreshedClaims.AuthTime != originalClaims.AuthTime {
		t.Fatalf("auth_time mismatch: got %d, want %d", refreshedClaims.AuthTime, originalClaims.AuthTime)
	}
	now := time.Now().Unix()
	if refreshedClaims.Iat < issuedAfter || refreshedClaims.Iat > now || refreshedClaims.Exp <= now || refreshedClaims.Exp-refreshedClaims.Iat != int64(refreshed.ExpiresIn) {
		t.Fatalf("unexpected refreshed id token metadata: %#v", refreshedClaims)
	}
	if _, present := decodeJWTClaims(t, refreshed.IDToken)["nonce"]; present {
		t.Fatal("expected refreshed ID Token nonce to be omitted")
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

	t.Run("detects refresh token replay after the consumed token idle timeout", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-replay-after-idle-timeout")
		request.ClientID = nativeClientID
		request.RedirectURI = nativeClientRedirect
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			CodeVerifier: request.Verifier,
		})
		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			RefreshToken: token.RefreshToken,
		})
		provider.expireRefreshTokenIdle(t, token.RefreshToken)

		request.Prompt = "none"
		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "interaction_required")
		for _, refreshToken := range []string{token.RefreshToken, refreshed.RefreshToken} {
			errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
				ClientID:     request.ClientID,
				GrantType:    "refresh_token",
				RefreshToken: refreshToken,
			}), http.StatusBadRequest)
			if errResp.Error != "invalid_grant" {
				t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
			}
		}
		resp := provider.getUserInfoResponse(t, refreshed.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch after replay: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
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

	t.Run("measures inactivity from the precise issue time", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("refresh-token-precise-issue-time")
		authorization := authorizeAndLogin(t, provider, request)

		issuedAfter := time.Now()
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		provider.assertRefreshTokenIssueTime(t, token.RefreshToken, issuedAfter, time.Now())
		issuedAfter = time.Now()
		rotatedToken := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})
		provider.assertRefreshTokenIssueTime(t, rotatedToken.RefreshToken, issuedAfter, time.Now())
		_ = exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: rotatedToken.RefreshToken,
		})
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

	t.Run("rejects duplicate recognized parameters and ignores repeated unknown parameters", func(t *testing.T) {
		for _, grantType := range []string{"authorization_code", "refresh_token", "client_credentials"} {
			t.Run(grantType, func(t *testing.T) {
				provider := startProvider(t, defaultProviderConfig())
				form := url.Values{
					"grant_type":        {grantType},
					"client_id":         {webClientID},
					"client_secret":     {webClientSecret},
					"unknown_parameter": {"first", "second"},
				}
				switch grantType {
				case "authorization_code":
					request := newDefaultConfidentialAuthorizationRequest("duplicate-token-parameters")
					authorization := authorizeAndLogin(t, provider, request)
					form.Set("code", authorization.Code)
					form.Set("redirect_uri", request.RedirectURI)
					form.Set("code_verifier", request.Verifier)
				case "refresh_token":
					request := newDefaultConfidentialAuthorizationRequest("duplicate-refresh-parameters")
					token := authorizeAndExchange(t, provider, request, tokenRequest{
						ClientID:     request.ClientID,
						ClientSecret: webClientSecret,
						CodeVerifier: request.Verifier,
					})
					form.Set("refresh_token", token.RefreshToken)
					form.Set("scope", "openid")
				case "client_credentials":
					form.Set("scope", "orders:read")
				}

				for _, parameter := range []string{"grant_type", "client_id", "client_secret", "code", "redirect_uri", "code_verifier", "refresh_token", "scope"} {
					if !form.Has(parameter) {
						continue
					}
					t.Run(parameter, func(t *testing.T) {
						duplicateForm := url.Values{}
						for name, values := range form {
							duplicateForm[name] = append([]string(nil), values...)
						}
						duplicateForm.Add(parameter, form.Get(parameter))

						errResp := expectJSONError(t, provider.postFormURL(t, provider.endpoint("/token"), duplicateForm, "", false), http.StatusBadRequest)
						if errResp.Error != "invalid_request" {
							t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
						}
					})
				}

				resp := provider.postFormURL(t, provider.endpoint("/token"), form, "", false)
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
				}
				var token tokenResponse
				if err := json.Unmarshal(body, &token); err != nil {
					t.Fatalf("failed to decode token response: %v; body=%s", err, body)
				}
				if token.AccessToken == "" {
					t.Fatalf("expected access token, got %#v", token)
				}
			})
		}
	})

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

		errResp := expectJSONError(t, provider.do(t, provider.redirectless, req), http.StatusBadRequest)
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

		errResp := expectJSONError(t, provider.do(t, provider.redirectless, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("returns unsupported_grant_type for unsupported grants", func(t *testing.T) {
		form := url.Values{
			"grant_type":    {"password"},
			"client_id":     {webClientID},
			"client_secret": {webClientSecret},
		}
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/token"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create token request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		errResp := expectJSONError(t, provider.do(t, provider.redirectless, req), http.StatusBadRequest)
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

func testIDToken(t *testing.T) {
	config := defaultProviderConfig()
	config.IssuerPath = "/issuer"
	provider := startProvider(t, config)
	request := newDefaultConfidentialAuthorizationRequest("id-token-contents")
	issuedAfter := time.Now().Unix()
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
	now := time.Now().Unix()
	if claims.Iat < issuedAfter || claims.Iat > now || claims.Exp <= now || claims.Exp-claims.Iat != int64(token.ExpiresIn) {
		t.Fatalf("unexpected id token metadata: %#v", claims)
	}

	t.Run("accepts a 255-character ASCII subject", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].Sub = strings.Repeat("a", 255)
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("maximum-length-subject")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		if claims := verifyIDToken(t, provider, token.IDToken); claims.Sub != config.Users[0].Sub {
			t.Fatalf("subject mismatch: got %q, want %q", claims.Sub, config.Users[0].Sub)
		}
	})

	for _, testCase := range []struct {
		name string
		sub  string
	}{
		{name: "rejects a 256-character ASCII subject", sub: strings.Repeat("a", 256)},
		{name: "rejects a non-ASCII subject", sub: "josé"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			environ := []string{
				"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
				"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
				"SIMPLE_IDP_USER_ALICE_SUB=" + testCase.sub,
			}
			_, err := loadUsers(environ, func(name string) string {
				for _, item := range environ {
					key, value, _ := strings.Cut(item, "=")
					if key == name {
						return value
					}
				}
				return ""
			})
			if err == nil || !strings.Contains(err.Error(), "sub claim") {
				t.Fatalf("expected invalid subject configuration error, got %v", err)
			}
		})
	}

	t.Run("rejects invalid issuer urls", func(t *testing.T) {
		for _, issuer := range []string{
			"http://127.0.0.1/issuer?tenant=alpha",
			"http://127.0.0.1/issuer#fragment",
			"/issuer",
			"https:/issuer",
			"https:///issuer",
			"ftp://127.0.0.1/issuer",
			"http://user:password@127.0.0.1/issuer",
			"http://127.0.0.1/%invalid",
		} {
			t.Run(issuer, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_ISSUER=" + issuer,
					"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
					"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
					"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
					"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
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
				if err == nil || !strings.Contains(err.Error(), "SIMPLE_IDP_ISSUER") {
					t.Fatalf("expected invalid issuer error, got %v", err)
				}
			})
		}
	})
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
	request.Nonce = " %&+£€"

	t.Run("accepts authorization requests in form-encoded POST bodies", func(t *testing.T) {
		body := authorizeByPostExpectLoginPage(t, provider, request)
		if !strings.Contains(string(body), `method="POST"`) {
			t.Fatalf("expected form POST login page, got body=%s", body)
		}
		redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
		if got := redirect.Query().Get("state"); got != request.State {
			t.Fatalf("state mismatch: got %q, want %q", got, request.State)
		}
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         redirect.Query().Get("code"),
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		if claims.Nonce != request.Nonce {
			t.Fatalf("nonce mismatch: got %q, want %q", claims.Nonce, request.Nonce)
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
		_ = authorizeAndLogin(t, provider, baseline)
		authenticatedAt := provider.ageSession(t, 2*time.Minute, 0).Unix()

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
		if claims.AuthTime != authenticatedAt {
			t.Fatalf("expected reused session auth_time %d, got %d", authenticatedAt, claims.AuthTime)
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

		reauthenticatedAt := time.Now().Unix()
		token = exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer),
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		claims = verifyIDToken(t, provider, token.IDToken)
		if claims.AuthTime < reauthenticatedAt || claims.AuthTime > time.Now().Unix() {
			t.Fatalf("expected fresh auth_time, got %d, want at least %d", claims.AuthTime, reauthenticatedAt)
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
