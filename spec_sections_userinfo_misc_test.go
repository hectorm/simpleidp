package simpleidp

// Reference material:
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html"
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

	t.Run("supports configured preferred usernames without creating extra users", func(t *testing.T) {
		for _, label := range []string{"ALICE", "ALICE_PREFERRED", "ALICE_PREFERRED_PREFERRED"} {
			t.Run(label, func(t *testing.T) {
				config := defaultProviderConfig()
				config.Users[0].Label = label
				config.Users[0].PreferredUsername = "alice.display"
				provider := startProvider(t, config)
				request := newDefaultConfidentialAuthorizationRequest("configured-preferred-username")
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				claims := verifyIDToken(t, provider, token.IDToken)
				userInfo := fetchUserInfo(t, provider, token.AccessToken)
				if claims.PreferredUsername != "alice.display" || userInfo.PreferredUsername != "alice.display" {
					t.Fatalf("preferred_username mismatch: id_token=%q, userinfo=%q", claims.PreferredUsername, userInfo.PreferredUsername)
				}
			})
		}
	})

	t.Run("keeps overlapping user labels distinct regardless of configuration order", func(t *testing.T) {
		for _, order := range []string{"parent first", "child first"} {
			t.Run(order, func(t *testing.T) {
				config := defaultProviderConfig()
				config.Users[0].PreferredUsername = "bob"
				config.Users = append(config.Users, userConfig{
					Label:    "ALICE_PREFERRED",
					Username: "bob",
					Password: "bob-password",
				})
				if order == "child first" {
					config.Users[0], config.Users[1] = config.Users[1], config.Users[0]
				}
				provider := startProvider(t, config)
				if len(provider.idp.users) != 2 {
					t.Fatalf("expected 2 users, got %d", len(provider.idp.users))
				}
				for _, username := range []string{testUsername, "bob"} {
					user, ok := provider.idp.users[username]
					if !ok || user.preferredUsername != "bob" {
						t.Fatalf("preferred username mismatch for %q: got %q, want %q", username, user.preferredUsername, "bob")
					}
				}
			})
		}
	})

	t.Run("rejects incomplete user configuration for every supported field", func(t *testing.T) {
		for _, field := range []string{
			"USERNAME", "PASSWORD", "SUB", "NAME", "PREFERRED_USERNAME", "EMAIL",
			"EMAIL_VERIFIED", "PROFILE", "PICTURE", "LOCALE", "GROUPS", "ROLES",
		} {
			t.Run(field, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
					"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
					"SIMPLE_IDP_USER_BOB_" + field + "=bob",
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
				if err == nil || !strings.Contains(err.Error(), "incomplete user configuration") {
					t.Fatalf("expected incomplete user configuration error, got %v", err)
				}
			})
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

	t.Run("enforces the minimum RSA signing key size for imported keys", func(t *testing.T) {
		for _, bits := range []int{1024, 2048} {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range []string{"KEY_FILE", "KEY_B64"} {
				t.Run(fmt.Sprintf("%d/%s", bits, source), func(t *testing.T) {
					value := "key.pem"
					if source == "KEY_B64" {
						value = base64.StdEncoding.EncodeToString(der)
					}
					loaded, err := loadOrGenerateKey(func(name string) string {
						if name == "SIMPLE_IDP_"+source {
							return value
						}
						return ""
					}, func(string) ([]byte, error) {
						return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
					})
					if bits < 2048 {
						if err == nil || !strings.Contains(err.Error(), "at least 2048 bits") {
							t.Fatalf("expected minimum key size error, got %v", err)
						}
					} else if err != nil || loaded.N.Cmp(key.N) != 0 {
						t.Fatalf("failed to load compliant RSA key: %v", err)
					}
				})
			}
		}
	})

	t.Run("generates a 3072-bit RSA signing key when none is configured", func(t *testing.T) {
		key, err := loadOrGenerateKey(func(string) string { return "" }, func(name string) ([]byte, error) {
			return nil, fmt.Errorf("unexpected key file read: %s", name)
		})
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		if bits := key.N.BitLen(); bits != 3072 {
			t.Fatalf("generated key size mismatch: got %d, want %d", bits, 3072)
		}
	})
}

func testProfilePage(t *testing.T) {
	t.Run("shows the current browser user at the issuer URL", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].Password = "alice-profile-password"
		config.Users = append(config.Users, userConfig{
			Label:    "BOB",
			Username: "bob",
			Password: "bob-profile-password",
			Sub:      "bob-subject",
			Name:     `Bob <script>alert("profile")</script>`,
			Email:    "bob@example.com",
		})
		provider := startProvider(t, config)

		for _, user := range config.Users {
			t.Run(user.Username, func(t *testing.T) {
				browser := newProviderBrowser(t, provider)
				request := newDefaultConfidentialAuthorizationRequest("profile-" + user.Username)
				body := readBody(t, browser.getAuthorize(t, authorizeParams(request)))
				expectAuthorizationCodeRedirect(t, submitLoginForm(t, browser, body, user.Username, user.Password), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)

				body = fetchProfilePage(t, browser)
				for _, value := range []string{user.Name, user.Username, user.Email} {
					if !strings.Contains(string(body), "<dd>"+html.EscapeString(value)+"</dd>") {
						t.Fatalf("expected profile value %q, got body=%s", value, body)
					}
				}
				for _, unexpected := range []string{"<script>", user.Password, webClientSecret} {
					if strings.Contains(string(body), unexpected) {
						t.Fatalf("unexpected profile content %q, got body=%s", unexpected, body)
					}
				}
			})
		}
	})

	t.Run("supports issuer paths on the profile page", func(t *testing.T) {
		config := defaultProviderConfig()
		config.IssuerPath = "/tenant-a"
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("profile-issuer-path")
		_ = authorizeAndLogin(t, provider, request)
		body := fetchProfilePage(t, provider)
		if !strings.Contains(string(body), testName) || !strings.Contains(string(body), testEmail) {
			t.Fatalf("expected signed-in profile, got body=%s", body)
		}
	})

	t.Run("redirects to login without a live browser session", func(t *testing.T) {
		for _, state := range []string{"missing", "expired"} {
			t.Run(state, func(t *testing.T) {
				provider := startProvider(t, defaultProviderConfig())
				request := newDefaultConfidentialAuthorizationRequest("profile-session")
				_ = authorizeAndLogin(t, provider, request)
				browser := provider
				if state == "missing" {
					browser = newProviderBrowser(t, provider)
				} else {
					provider.expireSessionMax(t)
				}

				req, err := http.NewRequest(http.MethodGet, browser.endpoint("/"), nil)
				if err != nil {
					t.Fatalf("failed to create profile request: %v", err)
				}
				redirect := expectRedirect(t, browser.do(t, browser.redirectless, req), http.StatusFound)
				assertRedirectTarget(t, redirect, "/login")
				body := fetchLoginForm(t, browser)
				for _, unexpected := range []string{testName, testEmail, `data-testid="details"`, `data-testid="page-profile"`} {
					if strings.Contains(string(body), unexpected) {
						t.Fatalf("unexpected signed-out login content %q, got body=%s", unexpected, body)
					}
				}
			})
		}
	})

	t.Run("does not serve the profile at unknown paths", func(t *testing.T) {
		for _, issuerPath := range []string{"", "/tenant-a"} {
			config := defaultProviderConfig()
			config.IssuerPath = issuerPath
			provider := startProvider(t, config)
			for _, path := range []string{"/unknown", "/unknown/"} {
				req, err := http.NewRequest(http.MethodGet, provider.endpoint(path), nil)
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}
				resp := provider.do(t, provider.http, req)
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusNotFound {
					t.Fatalf("unknown path %q status mismatch: got %s, want %d; body=%s", req.URL.Path, resp.Status, http.StatusNotFound, body)
				}
			}
		}
	})
}

func testProfileLogin(t *testing.T) {
	t.Run("signs in and returns to the profile", func(t *testing.T) {
		for _, issuerPath := range []string{"", "/tenant-a"} {
			config := defaultProviderConfig()
			config.IssuerPath = issuerPath
			provider := startProvider(t, config)
			req, err := http.NewRequest(http.MethodGet, provider.endpoint(""), nil)
			if err != nil {
				t.Fatalf("failed to create profile request: %v", err)
			}
			resp := provider.do(t, provider.http, req)
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("profile login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
			}
			if !strings.Contains(string(body), `data-testid="page-login"`) {
				t.Fatalf("expected login form from profile URL, got body=%s", body)
			}

			redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
			assertRedirectTarget(t, redirect, issuerPath+"/")
			body = fetchProfilePage(t, provider)
			if !strings.Contains(string(body), testName) || !strings.Contains(string(body), testEmail) {
				t.Fatalf("expected signed-in profile, got body=%s", body)
			}
		}
	})

	t.Run("allows retrying after invalid credentials", func(t *testing.T) {
		config := defaultProviderConfig()
		config.IssuerPath = "/tenant-a"
		provider := startProvider(t, config)
		body := fetchLoginForm(t, provider)
		resp := submitLoginForm(t, provider, body, testUsername, "wrong-password")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Invalid username or password") {
			t.Fatalf("expected invalid credentials message, got body=%s", body)
		}
		request := newDefaultConfidentialAuthorizationRequest("profile-login-invalid-credentials")
		request.Prompt = "none"
		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")

		redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
		assertRedirectTarget(t, redirect, config.IssuerPath+"/")
		_ = fetchProfilePage(t, provider)
	})

	t.Run("redirects signed-in browsers to the profile", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("profile-login-existing-session")
		_ = authorizeAndLogin(t, provider, request)
		sessionID := provider.currentSessionID(t)

		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/login"), nil)
		if err != nil {
			t.Fatalf("failed to create login request: %v", err)
		}
		redirect := expectRedirect(t, provider.do(t, provider.redirectless, req), http.StatusFound)
		assertRedirectTarget(t, redirect, "/")
		if got := provider.currentSessionID(t); got != sessionID {
			t.Fatalf("session changed after visiting login: got %q, want %q", got, sessionID)
		}
	})

	t.Run("reuses the profile session for authorization", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		body := fetchLoginForm(t, provider)
		redirect := expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
		assertRedirectTarget(t, redirect, "/")
		sessionID := provider.currentSessionID(t)

		request := newDefaultConfidentialAuthorizationRequest("profile-login-sso")
		request.Prompt = "none"
		code := expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
		token := exchangeAuthorizationCode(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		if claims.Sub != testSubject {
			t.Fatalf("subject mismatch: got %q, want %q", claims.Sub, testSubject)
		}
		if claims.Sid != sessionID {
			t.Fatalf("session mismatch: got %q, want %q", claims.Sid, sessionID)
		}
	})

	t.Run("rejects invalid login forms", func(t *testing.T) {
		for _, invalid := range []string{"missing csrf token", "invalid csrf token", "other browser csrf token", "missing cookie", "duplicate username"} {
			t.Run(invalid, func(t *testing.T) {
				provider := startProvider(t, defaultProviderConfig())
				body := fetchLoginForm(t, provider)
				form := url.Values{
					"username":   {testUsername},
					"password":   {testPassword},
					"csrf_token": {extractHiddenInputValue(t, body, "csrf_token")},
				}
				browser := provider
				switch invalid {
				case "missing csrf token":
					form.Del("csrf_token")
				case "invalid csrf token":
					form.Set("csrf_token", "invalid")
				case "other browser csrf token":
					otherBrowser := newProviderBrowser(t, provider)
					form.Set("csrf_token", extractHiddenInputValue(t, fetchLoginForm(t, otherBrowser), "csrf_token"))
				case "missing cookie":
					browser = newProviderBrowser(t, provider)
				case "duplicate username":
					form.Add("username", "bob")
				}
				resp := browser.postFormURL(t, browser.endpoint("/login"), form, "", false)
				body = readBody(t, resp)
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("invalid login form status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
				}
				_ = fetchLoginForm(t, browser)
			})
		}
	})
}

func testProfileLogout(t *testing.T) {
	config := defaultProviderConfig()
	config.IssuerPath = "/tenant-a"
	provider := startProvider(t, config)
	request := newDefaultConfidentialAuthorizationRequest("profile-logout")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})
	body := fetchProfilePage(t, provider)
	action := resolveProviderURL(t, provider.issuer, extractFormAction(t, body))
	resp := provider.postFormURL(t, action, url.Values{"confirm": {"yes"}}, "", false)
	raw := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("logout status without CSRF token mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, raw)
	}

	resp = submitConsentForm(t, provider, body, "yes")
	raw = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout completion status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, raw)
	}
	if !strings.Contains(string(raw), "You have been signed out.") {
		t.Fatalf("expected logged out message, got body=%s", raw)
	}
	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/"), nil)
	if err != nil {
		t.Fatalf("failed to create profile request: %v", err)
	}
	redirect := expectRedirect(t, provider.do(t, provider.redirectless, req), http.StatusFound)
	assertRedirectTarget(t, redirect, config.IssuerPath+"/login")
	resp = provider.getUserInfoResponse(t, token.AccessToken)
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo status after logout mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
	}
}

func TestProfileImplementation(t *testing.T) {
	t.Run("profile page", testProfilePage)
	t.Run("profile login", testProfileLogin)
	t.Run("profile logout", testProfileLogout)
}
