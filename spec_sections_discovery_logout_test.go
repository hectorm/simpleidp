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
	if !slices.Contains(discovery.ScopesSupported, "openid") || !slices.Contains(discovery.ScopesSupported, "profile") || !slices.Contains(discovery.ScopesSupported, "email") {
		t.Fatalf("unexpected supported scopes: %#v", discovery.ScopesSupported)
	}
	if !slices.Contains(discovery.ResponseTypesSupported, "code") {
		t.Fatalf("response_types_supported missing code: %#v", discovery.ResponseTypesSupported)
	}
	if !slices.Contains(discovery.ResponseModesSupported, "query") {
		t.Fatalf("response_modes_supported missing query: %#v", discovery.ResponseModesSupported)
	}
	if !slices.Contains(discovery.GrantTypesSupported, "authorization_code") {
		t.Fatalf("grant_types_supported missing authorization_code: %#v", discovery.GrantTypesSupported)
	}
	if !slices.Contains(discovery.GrantTypesSupported, "refresh_token") {
		t.Fatalf("grant_types_supported missing refresh_token: %#v", discovery.GrantTypesSupported)
	}
	if !slices.Contains(discovery.SubjectTypesSupported, "public") {
		t.Fatalf("subject_types_supported missing public: %#v", discovery.SubjectTypesSupported)
	}
	if !slices.Contains(discovery.IDTokenSigningAlgValuesSupported, "RS256") {
		t.Fatalf("id_token_signing_alg_values_supported missing RS256: %#v", discovery.IDTokenSigningAlgValuesSupported)
	}
	if !slices.Contains(discovery.TokenEndpointAuthMethodsSupported, "client_secret_basic") || !slices.Contains(discovery.TokenEndpointAuthMethodsSupported, "client_secret_post") {
		t.Fatalf("unexpected token endpoint auth methods: %#v", discovery.TokenEndpointAuthMethodsSupported)
	}
	if !slices.Contains(discovery.ClaimsSupported, "sub") || !slices.Contains(discovery.ClaimsSupported, "email") {
		t.Fatalf("unexpected claims_supported: %#v", discovery.ClaimsSupported)
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
		config := defaultProviderConfig()
		config.IssuerPath = "/issuer1"
		provider := startProvider(t, config)
		resp, body := fetchDiscoveryResponse(t, provider)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if provider.issuer != provider.endpoint("") {
			t.Fatalf("issuer mismatch: got %q, want %q", provider.issuer, provider.endpoint(""))
		}
	})
}

func testProviderConfigurationResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	resp, body := fetchDiscoveryResponse(t, provider)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("content type mismatch: got %q", got)
	}
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

	t.Run("detects issuer mismatches against discovered configuration", func(t *testing.T) {
		otherProvider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("provider-config-validation-mismatch")
		otherToken := authorizeAndExchange(t, otherProvider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		otherClaims := verifyIDToken(t, otherProvider, otherToken.IDToken)
		if otherClaims.Iss == discovery.Issuer {
			t.Fatalf("expected discovery issuer %q to differ from token issuer %q", discovery.Issuer, otherClaims.Iss)
		}
	})
}

func testRPInitiatedLogout(t *testing.T) {
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
		}, "", false)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logout POST status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Log out of this identity provider?") {
			t.Fatalf("expected logout confirmation form, got body=%s", body)
		}
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
	fixture := prepareRPInitiatedLogout(t)
	redirect := expectRedirect(t, submitConsentForm(t, fixture.provider, fixture.formBody, "yes"), http.StatusSeeOther)

	assertRedirectTarget(t, redirect, webClientPostLogoutRedirect)
	if got := redirect.Query().Get("state"); got != "logout-state" {
		t.Fatalf("state mismatch: got %q, want %q", got, "logout-state")
	}
}

func testLogoutClientRegistrationMetadata(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("accepts registered post-logout redirect uris", func(t *testing.T) {
		fixture := prepareRPInitiatedLogout(t)
		redirect := expectRedirect(t, submitConsentForm(t, fixture.provider, fixture.formBody, "yes"), http.StatusSeeOther)
		assertRedirectTarget(t, redirect, webClientPostLogoutRedirect)
	})

	t.Run("rejects unregistered post-logout redirect uris", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"client_id":                {webClientID},
			"post_logout_redirect_uri": {"http://127.0.0.1/unregistered/logout"},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		expectNoLogoutRedirect(t, resp, body)
	})
}

func testLogoutValidationAndErrorHandling(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("rejects invalid id token hints", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"id_token_hint": {"not-a-jwt"},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		expectNoLogoutRedirect(t, resp, body)
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
		expectNoLogoutRedirect(t, resp, body)
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
		expectNoLogoutRedirect(t, resp, body)
	})

	t.Run("does not redirect id token hints from a different issuer", func(t *testing.T) {
		otherProvider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("logout-different-issuer")
		token := authorizeAndExchange(t, otherProvider, request, tokenRequest{
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
		expectNoLogoutRedirect(t, resp, body)
	})

	t.Run("does not redirect post-logout uris without proof of client identity", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
			"post_logout_redirect_uri": {webClientPostLogoutRedirect},
		}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}

		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		expectNoLogoutRedirect(t, resp, body)
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
		expectNoLogoutRedirect(t, resp, body)
	})
}

func expectNoLogoutRedirect(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()

	if resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		t.Fatalf("expected a non-redirecting logout response, got %s; body=%s", resp.Status, body)
	}
	if location := resp.Header.Get("Location"); location != "" {
		t.Fatalf("did not expect logout redirect, got %q", location)
	}
}

func testLogoutSecurityConsiderations(t *testing.T) {
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
