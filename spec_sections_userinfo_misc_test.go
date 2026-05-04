package simpleidp

// Reference material:
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func testStandardClaims(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("returns implemented standard claims with their configured values", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("standard-claims")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		if claims.Sub != testSubject {
			t.Fatalf("subject mismatch: got %q, want %q", claims.Sub, testSubject)
		}
		if claims.Name != testName || claims.PreferredUsername != testPreferredUsername || claims.Profile != testProfile || claims.Picture != testPicture || claims.Locale != testLocale {
			t.Fatalf("unexpected profile claims: %#v", claims)
		}
		if claims.Email != testEmail || !claims.EmailVerified {
			t.Fatalf("unexpected email claims: %#v", claims)
		}
	})
}

func testUserInfoRequest(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("userinfo-request")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	t.Run("accepts bearer tokens in the authorization header", func(t *testing.T) {
		resp := provider.getUserInfoResponse(t, token.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("accepts bearer tokens in a form-encoded body", func(t *testing.T) {
		resp := provider.postUserInfo(t, url.Values{"access_token": {token.AccessToken}}, "")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})
}

func testSuccessfulUserInfoResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("successful-userinfo-response")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	t.Run("returns JSON claims for the requested scopes", func(t *testing.T) {
		resp := provider.getUserInfoResponse(t, token.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Fatalf("content type mismatch: got %q", got)
		}
		payload := decodeJSONMap(t, body)
		if payload["sub"] != testSubject {
			t.Fatalf("subject mismatch: got %#v", payload["sub"])
		}
		if payload["email"] != testEmail {
			t.Fatalf("email mismatch: got %#v", payload["email"])
		}
	})

	t.Run("always returns the subject claim", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("successful-userinfo-sub")
		request.Scope = "openid"
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
		if payload["sub"] != testSubject {
			t.Fatalf("subject mismatch: got %#v", payload)
		}
	})
}

func testUserInfoErrorResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("returns a bearer challenge when the access token is missing", func(t *testing.T) {
		resp := provider.postUserInfo(t, url.Values{}, "")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="userinfo"` {
			t.Fatalf("unexpected bearer challenge: %q", got)
		}
	})

	t.Run("returns invalid_token for unknown access tokens", func(t *testing.T) {
		resp := provider.getUserInfoResponse(t, "unknown-access-token")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
			t.Fatalf("expected invalid_token challenge, got %q", got)
		}
	})

	t.Run("returns invalid_request for malformed bearer authorization headers", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("userinfo-error-response-malformed-header")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/userinfo"), nil)
		if err != nil {
			t.Fatalf("failed to create userinfo request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken+" extra")

		resp := provider.do(t, provider.http, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_request"`) {
			t.Fatalf("expected invalid_request challenge, got %q", got)
		}
	})

	t.Run("returns invalid_request for multiple token transmission methods", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("userinfo-error-response-multiple-methods")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		resp := provider.postUserInfo(t, url.Values{"access_token": {token.AccessToken}}, "Bearer "+token.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_request"`) {
			t.Fatalf("expected invalid_request challenge, got %q", got)
		}
	})

	t.Run("returns invalid_request for malformed userinfo requests", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("userinfo-error-response")
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
	})

	t.Run("returns invalid_request for malformed form-encoded bodies", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/userinfo"), strings.NewReader("access_token=%zz"))
		if err != nil {
			t.Fatalf("failed to create userinfo request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp := provider.do(t, provider.http, req)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_request"`) {
			t.Fatalf("expected invalid_request challenge, got %q", got)
		}
	})
}

func testUserInfoResponseValidation(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("userinfo-response-validation")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	idTokenClaims := verifyIDToken(t, provider, token.IDToken)
	resp := provider.getUserInfoResponse(t, token.AccessToken)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("content type mismatch: got %q", got)
	}
	payload := decodeJSONMap(t, body)
	if payload["sub"] != idTokenClaims.Sub {
		t.Fatalf("userinfo subject mismatch: got %#v, want %q", payload["sub"], idTokenClaims.Sub)
	}
}

func TestOIDCProviderOutputSanity(t *testing.T) {
	t.Run("authorization response metadata", testAuthenticationResponseValidation)
	t.Run("token response consistency", testTokenResponseValidation)
	t.Run("id token signing metadata", testIDTokenValidation)
	t.Run("access token hash consistency", testAccessTokenValidation)
	t.Run("userinfo subject consistency", testUserInfoResponseValidation)
}

func testScopeBasedClaims(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("profile scope controls profile claims", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("scope-profile")
		request.Scope = "openid profile"
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
		if payload["name"] != testName || payload["preferred_username"] != testPreferredUsername || payload["profile"] != testProfile || payload["picture"] != testPicture || payload["locale"] != testLocale {
			t.Fatalf("unexpected profile claims: %#v", payload)
		}
		if _, ok := payload["email"]; ok {
			t.Fatalf("did not expect email claim, got %#v", payload)
		}
	})

	t.Run("email scope controls email claims", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("scope-email")
		request.Scope = "openid email"
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
		if payload["email"] != testEmail || payload["email_verified"] != true {
			t.Fatalf("unexpected email claims: %#v", payload)
		}
		if _, ok := payload["name"]; ok {
			t.Fatalf("did not expect profile claims, got %#v", payload)
		}
	})
}

func testNormalClaims(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("normal-claims")
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
	if payload["sub"] != testSubject || payload["name"] != testName || payload["email"] != testEmail {
		t.Fatalf("unexpected normal claims payload: %#v", payload)
	}
	for _, unexpected := range []string{"_claim_names", "_claim_sources"} {
		if _, ok := payload[unexpected]; ok {
			t.Fatalf("did not expect aggregated or distributed claim marker %q in %#v", unexpected, payload)
		}
	}
}

func testClaimStabilityAndUniqueness(t *testing.T) {
	t.Run("returns a stable subject for the same user", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("claim-stability")

		first := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		secondRequest := newDefaultConfidentialAuthorizationRequest("claim-stability-second")
		second := authorizeAndExchange(t, provider, secondRequest, tokenRequest{
			ClientID:     secondRequest.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: secondRequest.Verifier,
		})

		firstClaims := verifyIDToken(t, provider, first.IDToken)
		secondClaims := verifyIDToken(t, provider, second.IDToken)
		if firstClaims.Sub != secondClaims.Sub {
			t.Fatalf("expected stable subject, got %q and %q", firstClaims.Sub, secondClaims.Sub)
		}
	})

	t.Run("returns different subjects for different users", func(t *testing.T) {
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

		aliceRequest := newDefaultConfidentialAuthorizationRequest("claim-uniqueness-alice")
		alice := authorizeAndExchange(t, provider, aliceRequest, tokenRequest{
			ClientID:     aliceRequest.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: aliceRequest.Verifier,
		})

		bobRequest := newDefaultConfidentialAuthorizationRequest("claim-uniqueness-bob")
		bobRequest.Prompt = "select_account"
		resp := provider.getAuthorize(t, authorizeParams(bobRequest))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		code := expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, "bob", "hunter2"), http.StatusSeeOther, bobRequest.RedirectURI, bobRequest.State, provider.issuer)
		bob := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     bobRequest.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			RedirectURI:  bobRequest.RedirectURI,
			CodeVerifier: bobRequest.Verifier,
		})

		aliceClaims := verifyIDToken(t, provider, alice.IDToken)
		bobClaims := verifyIDToken(t, provider, bob.IDToken)
		if aliceClaims.Sub == bobClaims.Sub {
			t.Fatalf("expected unique subjects, got %q for both users", aliceClaims.Sub)
		}
	})
}

func testSubjectIdentifierTypes(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	webRequest := newDefaultConfidentialAuthorizationRequest("public-subject-web")
	otherRequest := newDefaultConfidentialAuthorizationRequest("public-subject-other")
	otherRequest.ClientID = otherClientID
	otherRequest.RedirectURI = otherClientRedirect

	webToken := authorizeAndExchange(t, provider, webRequest, tokenRequest{
		ClientID:     webRequest.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: webRequest.Verifier,
	})
	otherToken := authorizeAndExchange(t, provider, otherRequest, tokenRequest{
		ClientID:     otherRequest.ClientID,
		ClientSecret: otherClientSecret,
		CodeVerifier: otherRequest.Verifier,
	})

	webClaims := verifyIDToken(t, provider, webToken.IDToken)
	otherClaims := verifyIDToken(t, provider, otherToken.IDToken)
	if webClaims.Sub != otherClaims.Sub {
		t.Fatalf("expected same public subject across clients, got %q and %q", webClaims.Sub, otherClaims.Sub)
	}
}

func testClientAuthentication(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("accepts confidential clients using client_secret_basic", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("client-auth-basic")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		if token.AccessToken == "" || token.IDToken == "" {
			t.Fatalf("expected tokens, got %#v", token)
		}
	})

	t.Run("accepts confidential clients using client_secret_post", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("client-auth-post")
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

	t.Run("rejects invalid client secrets", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("client-auth-invalid-secret")
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
	})

	t.Run("rejects confidential clients that do not authenticate", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("client-auth-missing-secret")
		authorization := authorizeAndLogin(t, provider, request)

		resp := provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			Code:         authorization.Code,
			RedirectURI:  request.RedirectURI,
			CodeVerifier: request.Verifier,
		})
		errResp := expectJSONError(t, resp, http.StatusUnauthorized)
		if errResp.Error != "invalid_client" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_client")
		}
	})

	t.Run("rejects multiple client authentication methods", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("client-auth-multiple-methods")
		authorization := authorizeAndLogin(t, provider, request)

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authorization.Code},
			"redirect_uri":  {request.RedirectURI},
			"code_verifier": {request.Verifier},
			"client_id":     {request.ClientID},
			"client_secret": {webClientSecret},
		}
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/token"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create token request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(request.ClientID), url.QueryEscape(webClientSecret))

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("rejects public clients sending client secrets", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49171/callback",
			Scope:       "openid profile",
			State:       "client-auth-public-client-secret",
			Verifier:    pkceVerifier("client-auth-public-client-secret"),
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

	t.Run("rejects public clients using basic authentication", func(t *testing.T) {
		request := authorizationRequest{
			ClientID:    nativeClientID,
			RedirectURI: "http://127.0.0.1:49172/callback",
			Scope:       "openid profile",
			State:       "client-auth-public-basic",
			Verifier:    pkceVerifier("client-auth-public-basic"),
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

func testSigning(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("signing")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	header := decodeJWTHeader(t, token.IDToken)
	jwks := fetchJWKS(t, provider)

	if header.Alg != "RS256" || header.Kid == "" || header.Typ != "JWT" {
		t.Fatalf("unexpected jwt header: %#v", header)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected one jwk, got %#v", jwks.Keys)
	}
	if jwks.Keys[0].KeyID != header.Kid {
		t.Fatalf("kid mismatch: got %q, want %q", jwks.Keys[0].KeyID, header.Kid)
	}
	_ = verifyIDToken(t, provider, token.IDToken)
}
