package simpleidp

// Reference material:
// OIDC Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
// OIDC RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func testProviderMetadata(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	discovery := fetchDiscovery(t, provider)
	_, body := fetchDiscoveryResponse(t, provider)
	payload := decodeJSONMap(t, body)

	if discovery.Issuer != provider.issuer {
		t.Fatalf("issuer mismatch: got %q, want %q", discovery.Issuer, provider.issuer)
	}
	if discovery.AuthorizationEndpoint != provider.endpoint("/authorize") {
		t.Fatalf("authorization endpoint mismatch: got %q", discovery.AuthorizationEndpoint)
	}
	if discovery.TokenEndpoint != provider.endpoint("/token") {
		t.Fatalf("token endpoint mismatch: got %q", discovery.TokenEndpoint)
	}
	if discovery.UserInfoEndpoint != provider.endpoint("/userinfo") {
		t.Fatalf("userinfo endpoint mismatch: got %q", discovery.UserInfoEndpoint)
	}
	if discovery.JWKSURI != provider.endpoint("/jwks") {
		t.Fatalf("jwks uri mismatch: got %q", discovery.JWKSURI)
	}
	_ = fetchJWKS(t, provider)
	slices.Sort(discovery.ScopesSupported)
	if !slices.Equal(discovery.ScopesSupported, []string{"email", "groups", "openid", "profile", "roles"}) {
		t.Fatalf("unexpected supported scopes: %#v", discovery.ScopesSupported)
	}
	if !slices.Equal(discovery.ResponseTypesSupported, []string{"code"}) {
		t.Fatalf("unexpected supported response types: %#v", discovery.ResponseTypesSupported)
	}
	if !slices.Equal(discovery.ResponseModesSupported, []string{"query"}) {
		t.Fatalf("unexpected supported response modes: %#v", discovery.ResponseModesSupported)
	}
	slices.Sort(discovery.GrantTypesSupported)
	if !slices.Equal(discovery.GrantTypesSupported, []string{"authorization_code", "client_credentials", "refresh_token"}) {
		t.Fatalf("unexpected supported grant types: %#v", discovery.GrantTypesSupported)
	}
	if !slices.Equal(discovery.SubjectTypesSupported, []string{"public"}) {
		t.Fatalf("unexpected supported subject types: %#v", discovery.SubjectTypesSupported)
	}
	if !slices.Equal(discovery.IDTokenSigningAlgValuesSupported, []string{"RS256"}) {
		t.Fatalf("unexpected supported ID token signing algorithms: %#v", discovery.IDTokenSigningAlgValuesSupported)
	}
	slices.Sort(discovery.TokenEndpointAuthMethodsSupported)
	if !slices.Equal(discovery.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic", "client_secret_post", "none"}) {
		t.Fatalf("unexpected token endpoint auth methods: %#v", discovery.TokenEndpointAuthMethodsSupported)
	}
	if !slices.Equal(discovery.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Fatalf("unexpected supported code challenge methods: %#v", discovery.CodeChallengeMethodsSupported)
	}
	slices.Sort(discovery.ClaimsSupported)
	if !slices.Equal(discovery.ClaimsSupported, []string{"aud", "auth_time", "email", "email_verified", "exp", "groups", "iat", "iss", "locale", "name", "nonce", "picture", "preferred_username", "profile", "roles", "sid", "sub"}) {
		t.Fatalf("unexpected claims_supported: %#v", discovery.ClaimsSupported)
	}
	slices.Sort(discovery.PromptValuesSupported)
	if !slices.Equal(discovery.PromptValuesSupported, []string{"consent", "login", "none", "select_account"}) {
		t.Fatalf("unexpected supported prompt values: %#v", discovery.PromptValuesSupported)
	}
	if discovery.ClaimsParameterSupported {
		t.Fatal("claims_parameter_supported should be false")
	}
	if discovery.RequestParameterSupported {
		t.Fatal("request_parameter_supported should be false")
	}
	if value, ok := payload["request_uri_parameter_supported"]; !ok || value != false {
		t.Fatalf("request_uri_parameter_supported mismatch: got %#v", payload["request_uri_parameter_supported"])
	}
	if discovery.RequireRequestURIRegistration {
		t.Fatal("require_request_uri_registration should be false")
	}
}

func testProviderConfigurationRequest(t *testing.T) {
	t.Run("serves provider configuration at the well-known path", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		resp, body := fetchDiscoveryResponse(t, provider)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("supports issuer paths when forming the well-known path", func(t *testing.T) {
		for _, issuerPath := range []string{"/issuer1", "/tenant/issuer/"} {
			t.Run(issuerPath, func(t *testing.T) {
				config := defaultProviderConfig()
				config.IssuerPath = issuerPath
				provider := startProvider(t, config)
				resp, body := fetchDiscoveryResponse(t, provider)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("discovery status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
				}
				issuer := decodeJSONMap(t, body)["issuer"]
				if issuer != provider.issuer || !strings.HasSuffix(provider.issuer, strings.TrimRight(issuerPath, "/")) {
					t.Fatalf("discovery did not retain the configured issuer path %q: got %#v", issuerPath, issuer)
				}
			})
		}
	})
}

func testProviderConfigurationResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	resp, body := fetchDiscoveryResponse(t, provider)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	assertMediaType(t, resp.Header.Get("Content-Type"), "application/json")
	payload := decodeJSONMap(t, body)
	for _, required := range []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	} {
		if _, ok := payload[required]; !ok {
			t.Fatalf("expected discovery field %q in %#v", required, payload)
		}
	}
}

func testProviderConfigurationValidation(t *testing.T) {
	config := defaultProviderConfig()
	config.IssuerPath = "/tenant-a"
	provider := startProvider(t, config)
	discovery := fetchDiscovery(t, provider)
	request := newDefaultConfidentialAuthorizationRequest("provider-config-validation")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	claims := verifyIDToken(t, provider, token.IDToken)

	if discovery.Issuer != provider.issuer {
		t.Fatalf("discovery issuer mismatch: got %q, want %q", discovery.Issuer, provider.issuer)
	}
	if claims.Iss != discovery.Issuer {
		t.Fatalf("id token issuer mismatch: got %q, want %q", claims.Iss, discovery.Issuer)
	}

	for name, endpoint := range map[string]string{
		"authorization_endpoint": discovery.AuthorizationEndpoint,
		"token_endpoint":         discovery.TokenEndpoint,
		"userinfo_endpoint":      discovery.UserInfoEndpoint,
		"jwks_uri":               discovery.JWKSURI,
	} {
		if !strings.HasPrefix(endpoint, provider.issuer+"/") {
			t.Fatalf("%s did not retain the issuer path: got %q", name, endpoint)
		}
	}
	if accessClaims := verifyAccessToken(t, provider, token.AccessToken); accessClaims.Iss != discovery.Issuer {
		t.Fatalf("access token issuer mismatch: got %q, want %q", accessClaims.Iss, discovery.Issuer)
	}
}

func testRPInitiatedLogout(t *testing.T) {
	t.Run("accepts an expired id token hint for the current session", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		claims := decodeJWTClaims(t, fixture.token.IDToken)
		claims["iat"] = time.Now().Add(-10 * time.Minute).Unix()
		claims["auth_time"] = claims["iat"]
		claims["exp"] = time.Now().Add(-5 * time.Minute).Unix()
		hint := replaceJWTClaims(t, fixture.provider, fixture.token.IDToken, claims)
		if verified := verifyIDToken(t, fixture.provider, hint); verified.Exp >= time.Now().Unix() {
			t.Fatal("expected a correctly signed, expired ID Token hint")
		}
		body := fetchLogoutForm(t, fixture.provider, url.Values{
			"id_token_hint":            {hint},
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
			"state":                    {"expired-hint-state"},
		})
		redirect := expectRedirect(t, submitConsentForm(t, fixture.provider, body, "yes"), http.StatusSeeOther)
		assertRedirectTarget(t, redirect, webClientPostLogoutRedirect)
		if got := redirect.Query().Get("state"); got != "expired-hint-state" {
			t.Fatalf("state mismatch: got %q, want %q", got, "expired-hint-state")
		}
	})

	t.Run("supports RP-initiated logout over GET and POST", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		if !strings.Contains(string(fixture.formBody), "Log out of this identity provider?") {
			t.Fatalf("logout page did not render expected message:\n%s", fixture.formBody)
		}

		postFixture := prepareRPInitiatedLogout(t)
		resp := postFixture.provider.postFormURL(t, postFixture.provider.endpoint("/end-session"), url.Values{
			"id_token_hint":            {postFixture.token.IDToken},
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
			"state":                    {"logout-state"},
			"ui_locales":               {"fr-CA fr en"},
		}, "", false)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logout POST status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Log out of this identity provider?") {
			t.Fatalf("expected logout confirmation form, got body=%s", body)
		}
	})

	t.Run("keeps POSTed logout parameters out of the confirmation form URL", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		params := url.Values{
			"id_token_hint":            {fixture.token.IDToken},
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
			"state":                    {"logout-state"},
		}
		resp := fixture.provider.postFormURL(t, fixture.provider.endpoint("/end-session"), params, "", false)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logout POST status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if action := extractFormAction(t, body); strings.Contains(action, "?") {
			t.Fatalf("logout form action must not carry request parameters, got %q", action)
		}
		hidden := extractHiddenInputs(t, body)
		hidden.Del("csrf_token")
		if got := hidden.Encode(); got != params.Encode() {
			t.Fatalf("hidden parameters mismatch: got %q, want %q", got, params.Encode())
		}
	})

	t.Run("logs out the session for cross-site POST logout requests", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		params := url.Values{
			"id_token_hint":            {fixture.token.IDToken},
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
			"state":                    {"logout-state"},
		}
		body := expectResubmitForm(t, fixture.provider.postCrossSite(t, fixture.provider.endpoint("/end-session"), params), params)

		resp := submitResubmitForm(t, fixture.provider, body)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logout form status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Log out of this identity provider?") {
			t.Fatalf("expected logout confirmation form, got body=%s", body)
		}
		hidden := extractHiddenInputs(t, body)
		hidden.Del("csrf_token")
		if got := hidden.Encode(); got != params.Encode() {
			t.Fatalf("hidden parameters mismatch: got %q, want %q", got, params.Encode())
		}

		_ = expectRedirect(t, submitConsentForm(t, fixture.provider, body, "yes"), http.StatusSeeOther)
		userInfoResp := fixture.provider.getUserInfoResponse(t, fixture.token.AccessToken)
		body = readBody(t, userInfoResp)
		if userInfoResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", userInfoResp.Status, http.StatusUnauthorized, body)
		}
	})

	t.Run("completes cross-site POST logout requests without a session", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		browser := newProviderBrowser(t, fixture.provider)
		params := url.Values{
			"id_token_hint":            {fixture.token.IDToken},
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
			"state":                    {"logout-state"},
		}
		body := expectResubmitForm(t, browser.postCrossSite(t, browser.endpoint("/end-session"), params), params)

		redirect := expectRedirect(t, submitResubmitForm(t, browser, body), http.StatusSeeOther)
		assertRedirectTarget(t, redirect, webClientPostLogoutRedirect)
	})

	t.Run("supports confirmed logout without a post-logout redirect uri", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("logout-without-redirect")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"id_token_hint": {token.IDToken},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logout form status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}

		resp = submitConsentForm(t, provider, body, "yes")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logout completion status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "You have been signed out.") {
			t.Fatalf("expected logged out message, got body=%s", body)
		}
	})

	t.Run("revokes tokens after confirmed logout", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("logout-revokes-token")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"id_token_hint": {token.IDToken},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logout form status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}

		_ = readBody(t, submitConsentForm(t, provider, body, "yes"))
		userInfoResp := provider.getUserInfoResponse(t, token.AccessToken)
		body = readBody(t, userInfoResp)
		if userInfoResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", userInfoResp.Status, http.StatusUnauthorized, body)
		}
	})
}

func testLogoutDiscoveryMetadata(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	discovery := fetchDiscovery(t, provider)

	if discovery.EndSessionEndpoint != provider.endpoint("/end-session") {
		t.Fatalf("end session endpoint mismatch: got %q, want %q", discovery.EndSessionEndpoint, provider.endpoint("/end-session"))
	}
}

func testLogoutRedirection(t *testing.T) {
	for _, redirectURI := range []string{
		webClientPostLogoutRedirect,
		webClientPostLogoutRedirect + "?tenant=alpha&tag=one&tag=two",
		"HTTP://127.0.0.1/logout/callback",
	} {
		t.Run(redirectURI, func(t *testing.T) {
			config := defaultProviderConfig()
			config.Clients[0].PostLogoutRedirectURL = redirectURI
			provider := startProvider(t, config)
			request := newDefaultConfidentialAuthorizationRequest("logout-redirection")
			token := authorizeAndExchange(t, provider, request, tokenRequest{
				ClientID:     request.ClientID,
				ClientSecret: webClientSecret,
				CodeVerifier: request.Verifier,
			})
			body := fetchLogoutForm(t, provider, url.Values{
				"id_token_hint":            {token.IDToken},
				"post_logout_redirect_uri": {redirectURI},
				"state":                    {"logout-state"},
			})
			redirect := expectRedirect(t, submitConsentForm(t, provider, body, "yes"), http.StatusSeeOther)
			assertRedirectTarget(t, redirect, redirectURI)
			if got := redirect.Query().Get("state"); got != "logout-state" {
				t.Fatalf("state mismatch: got %q, want %q", got, "logout-state")
			}
		})
	}
}

func testLogoutClientRegistrationMetadata(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("accepts registered post-logout redirect uris", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		redirect := expectRedirect(t, submitConsentForm(t, fixture.provider, fixture.formBody, "yes"), http.StatusSeeOther)
		assertRedirectTarget(t, redirect, webClientPostLogoutRedirect)
	})

	t.Run("requires exact matching of registered post-logout redirect uris", func(t *testing.T) {
		for _, redirectURI := range []string{
			"http://127.0.0.1/unregistered/logout",
			"HTTP://127.0.0.1/logout/callback",
			"http://127.0.0.1:49170/logout/callback",
			"http://127.0.0.1/logout/%63allback",
			webClientPostLogoutRedirect + "?tenant=alpha",
			webClientPostLogoutRedirect + "#fragment",
		} {
			t.Run(redirectURI, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
					"client_id":                {webClientID},
					"post_logout_redirect_uri": {redirectURI},
				}.Encode(), nil)
				if err != nil {
					t.Fatalf("failed to create logout request: %v", err)
				}

				resp := provider.do(t, provider.redirectless, req)
				body := readBody(t, resp)
				expectRejectedLogoutRequest(t, resp, body)
			})
		}
	})

	t.Run("rejects invalid registered post-logout redirect uris", func(t *testing.T) {
		for _, redirectURL := range []string{
			"http://127.0.0.1/logout/callback#fragment",
			"http://127.0.0.1/logout/callback#",
			"/logout/callback",
			"https:/logout/callback",
			"https:///logout/callback",
			"ftp://127.0.0.1/logout/callback",
			"http://user:password@127.0.0.1/logout/callback",
			"http://127.0.0.1/%invalid",
		} {
			t.Run(redirectURL, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
					"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
					"SIMPLE_IDP_CLIENT_WEB_REDIRECT_URL=" + webClientRedirect,
					"SIMPLE_IDP_CLIENT_WEB_POST_LOGOUT_REDIRECT_URL=" + redirectURL,
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
				if err == nil || !strings.Contains(err.Error(), "post-logout redirect URL") {
					t.Fatalf("expected invalid post-logout redirect URL error, got %v", err)
				}
			})
		}
	})
}

func testLogoutValidationAndErrorHandling(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("keeps logout idempotent after the session has ended", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		_ = expectRedirect(t, submitConsentForm(t, fixture.provider, fixture.formBody, "yes"), http.StatusSeeOther)
		params := url.Values{
			"id_token_hint":            {fixture.token.IDToken},
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
			"state":                    {"repeated-logout-state"},
		}
		for range 2 {
			req, err := http.NewRequest(http.MethodGet, fixture.provider.endpoint("/end-session")+"?"+params.Encode(), nil)
			if err != nil {
				t.Fatalf("failed to create repeated logout request: %v", err)
			}
			redirect := expectRedirect(t, fixture.provider.do(t, fixture.provider.redirectless, req), http.StatusFound)
			assertRedirectTarget(t, redirect, webClientPostLogoutRedirect)
			if got := redirect.Query().Get("state"); got != params.Get("state") {
				t.Fatalf("state mismatch after repeated logout: got %q, want %q", got, params.Get("state"))
			}
		}
	})

	t.Run("rejects invalid id token hints", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"id_token_hint": {"not-a-jwt"},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		expectRejectedLogoutRequest(t, resp, body)
	})

	t.Run("rejects id token hints with invalid signatures", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("logout-invalid-signature-source")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"id_token_hint": {tamperJWTSignature(t, token.IDToken)},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		expectRejectedLogoutRequest(t, resp, body)
	})

	t.Run("rejects access and logout tokens as id token hints", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("logout-token-types-source")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		_ = verifyAccessToken(t, provider, token.AccessToken)
		claims := verifyIDToken(t, provider, token.IDToken)
		user, ok := provider.idp.lookupUser("ALICE")
		if !ok {
			t.Fatal("expected configured user")
		}
		logoutToken, err := provider.idp.mintLogoutToken(user, provider.idp.clients[webClientID], claims.Sid)
		if err != nil {
			t.Fatalf("failed to mint logout token: %v", err)
		}
		_ = verifyLogoutToken(t, provider, logoutToken)

		for tokenType, hint := range map[string]string{"access token": token.AccessToken, "logout token": logoutToken} {
			t.Run(tokenType, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
					"id_token_hint":            {hint},
					"post_logout_redirect_uri": {webClientPostLogoutRedirect},
				}.Encode(), nil)
				if err != nil {
					t.Fatalf("failed to create logout request: %v", err)
				}
				resp := provider.do(t, provider.redirectless, req)
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("logout status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
				}
				expectRejectedLogoutRequest(t, resp, body)
			})
		}
	})

	t.Run("rejects mismatched client identifiers", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		req, err := http.NewRequest(http.MethodGet, fixture.provider.endpoint("/end-session")+"?"+url.Values{
			"id_token_hint": {fixture.token.IDToken},
			"client_id":     {otherClientID},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := fixture.provider.do(t, fixture.provider.redirectless, req)
		body := readBody(t, resp)
		expectRejectedLogoutRequest(t, resp, body)
	})

	t.Run("does not redirect id token hints from a different issuer", func(t *testing.T) {
		otherProvider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("logout-different-issuer")
		token := authorizeAndExchange(t, otherProvider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		browser := newProviderBrowser(t, provider)
		req, err := http.NewRequest(http.MethodGet, browser.endpoint("/end-session")+"?"+url.Values{
			"id_token_hint":            {token.IDToken},
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := browser.do(t, browser.redirectless, req)
		body := readBody(t, resp)
		expectRejectedLogoutRequest(t, resp, body)
	})

	t.Run("rejects post-logout uris without a client identifier or id token hint", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		expectRejectedLogoutRequest(t, resp, body)
	})

	t.Run("rejects duplicate logout parameters", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"client_id": {webClientID, webClientID},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		expectRejectedLogoutRequest(t, resp, body)
	})
}

func expectRejectedLogoutRequest(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected a rejected logout request, got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
	}
	if location := resp.Header.Get("Location"); location != "" {
		t.Fatalf("did not expect logout redirect, got %q", location)
	}
}

func testLogoutSecurityConsiderations(t *testing.T) {
	t.Run("requires confirmation and preserves the session when logout is canceled", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		_ = fetchUserInfo(t, fixture.provider, fixture.token.AccessToken)
		resp := submitConsentForm(t, fixture.provider, fixture.formBody, "no")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-testid="page-logout-canceled"`) {
			t.Fatalf("expected canceled logout, got %s; body=%s", resp.Status, body)
		}
		if got := resp.Header.Get("Location"); got != "" {
			t.Fatalf("canceled logout must not redirect, got %q", got)
		}
		_ = fetchUserInfo(t, fixture.provider, fixture.token.AccessToken)
		request := newDefaultConfidentialAuthorizationRequest("logout-canceled-session")
		request.Prompt = "none"
		expectAuthorizationCodeRedirect(t, fixture.provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, fixture.provider.issuer)
	})

	t.Run("rejects confirmed RP-initiated logout without CSRF protection", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		form := extractHiddenInputs(t, fixture.formBody)
		form.Del("csrf_token")
		form.Set("confirm", "yes")
		resp := fixture.provider.postFormURL(t, fixture.formAction, form, "", false)
		expectRejectedLogoutRequest(t, resp, readBody(t, resp))
		_ = fetchUserInfo(t, fixture.provider, fixture.token.AccessToken)
		request := newDefaultConfidentialAuthorizationRequest("logout-missing-csrf-session")
		request.Prompt = "none"
		expectAuthorizationCodeRedirect(t, fixture.provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, fixture.provider.issuer)
	})

	provider := startProvider(t, defaultProviderConfig())
	verifier := pkceVerifier("logout-security-considerations")
	authorizeAndExchange(t, provider, authorizationRequest{
		ClientID:    webClientID,
		RedirectURI: webClientRedirect,
		Scope:       "openid",
		State:       "logout-security-state",
		Verifier:    verifier,
	}, tokenRequest{
		ClientID:     webClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: verifier,
	})

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session"), nil)
	if err != nil {
		t.Fatalf("failed to create logout request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if !strings.Contains(string(body), "Log out of this identity provider?") {
		t.Fatalf("expected confirmation form, got body=%s", body)
	}
}
