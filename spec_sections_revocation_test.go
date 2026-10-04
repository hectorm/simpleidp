package simpleidp

// Reference material:
// RFC 7009: https://www.rfc-editor.org/rfc/rfc7009.txt

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func testRevocationEndpoint(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("revoke-endpoint")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	resp := postRevoke(t, provider, revocationRequest{
		ClientID:     webClientID,
		ClientSecret: webClientSecret,
		Token:        token.AccessToken,
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revocation status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	expectInactiveIntrospectionResponse(t, provider.postIntrospect(t, introspectionRequest{
		ClientID:     webClientID,
		ClientSecret: webClientSecret,
		Token:        token.AccessToken,
	}))
}

func testRevocationRequest(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("requires the token parameter", func(t *testing.T) {
		errResp := expectJSONError(t, postRevoke(t, provider, revocationRequest{
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
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/revoke"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create revoke request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(webClientID), url.QueryEscape(webClientSecret))

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("returns invalid_request for malformed request bodies", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, provider.endpoint("/revoke"), strings.NewReader("token=%zz"))
		if err != nil {
			t.Fatalf("failed to create revoke request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		errResp := expectJSONError(t, provider.do(t, provider.http, req), http.StatusBadRequest)
		if errResp.Error != "invalid_request" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_request")
		}
	})

	t.Run("accepts a refresh token with token_type_hint", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("revoke-refresh-token-hint")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		resp := postRevoke(t, provider, revocationRequest{
			ClientID:      webClientID,
			ClientSecret:  webClientSecret,
			Token:         token.RefreshToken,
			TokenTypeHint: "refresh_token",
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation status mismatch: got %s, want %d", resp.Status, http.StatusOK)
		}
		_ = readBody(t, resp)
	})

	t.Run("does not rely on token_type_hint when looking up tokens", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("revoke-wrong-hint")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		resp := postRevoke(t, provider, revocationRequest{
			ClientID:      webClientID,
			ClientSecret:  webClientSecret,
			Token:         token.AccessToken,
			TokenTypeHint: "refresh_token",
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation status mismatch: got %s, want %d", resp.Status, http.StatusOK)
		}
		_ = readBody(t, resp)
		expectInactiveIntrospectionResponse(t, provider.postIntrospect(t, introspectionRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			Token:        token.AccessToken,
		}))
	})

	t.Run("ignores unknown token_type_hint values", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("revoke-unknown-hint")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		resp := postRevoke(t, provider, revocationRequest{
			ClientID:      webClientID,
			ClientSecret:  webClientSecret,
			Token:         token.AccessToken,
			TokenTypeHint: "totally-unknown",
		})
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}

		expectInactiveIntrospectionResponse(t, provider.postIntrospect(t, introspectionRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			Token:        token.AccessToken,
		}))
	})
}

func testRevocationResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("revokes public-client tokens using only client_id", func(t *testing.T) {
		for _, tokenType := range []string{"access_token", "refresh_token"} {
			t.Run(tokenType, func(t *testing.T) {
				provider := startProvider(t, defaultProviderConfig())
				request := authorizationRequest{
					ClientID:    nativeClientID,
					RedirectURI: nativeClientRedirect,
					Scope:       "openid profile",
					State:       "revoke-public-client-" + tokenType,
					Verifier:    pkceVerifier("revoke-public-client-" + tokenType),
				}
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					CodeVerifier: request.Verifier,
				})
				_ = fetchUserInfo(t, provider, token.AccessToken)
				value := token.AccessToken
				if tokenType == "refresh_token" {
					value = token.RefreshToken
				}
				if value == "" {
					t.Fatalf("expected %s, got %#v", tokenType, token)
				}

				resp := postRevoke(t, provider, revocationRequest{
					ClientID:      nativeClientID,
					Token:         value,
					TokenTypeHint: tokenType,
				})
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("revocation status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
				}

				resp = provider.getUserInfoResponse(t, token.AccessToken)
				body = readBody(t, resp)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
				}
				if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
					t.Fatalf("expected invalid_token challenge, got %q", got)
				}
				if tokenType == "refresh_token" {
					errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
						ClientID:     nativeClientID,
						GrantType:    "refresh_token",
						RefreshToken: token.RefreshToken,
					}), http.StatusBadRequest)
					if errResp.Error != "invalid_grant" {
						t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
					}
				}
			})
		}
	})

	t.Run("returns 200 even for unknown tokens", func(t *testing.T) {
		resp := postRevoke(t, provider, revocationRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			Token:        "totally-unknown-token",
		})
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
	})

	t.Run("revokes all access tokens of the refresh grant and preserves other grants", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("revoke-cascade-refresh")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})
		otherGrant := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		resp := postRevoke(t, provider, revocationRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			Token:        refreshed.RefreshToken,
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("revocation status mismatch: got %s, want %d", resp.Status, http.StatusOK)
		}
		_ = readBody(t, resp)

		for _, value := range []string{token.AccessToken, refreshed.AccessToken, refreshed.RefreshToken} {
			expectInactiveIntrospectionResponse(t, provider.postIntrospect(t, introspectionRequest{
				ClientID:     webClientID,
				ClientSecret: webClientSecret,
				Token:        value,
			}))
		}
		for _, value := range []string{otherGrant.AccessToken, otherGrant.RefreshToken} {
			response := introspectToken(t, provider, introspectionRequest{
				ClientID:     webClientID,
				ClientSecret: webClientSecret,
				Token:        value,
			})
			if !response.Active {
				t.Fatal("revoking a refresh grant must preserve other grants for the same client and session")
			}
		}
	})
}

func testRevocationErrorResponse(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("returns invalid_client when client authentication is missing", func(t *testing.T) {
		resp := postRevoke(t, provider, revocationRequest{Token: "any-token"})
		errResp := expectJSONError(t, resp, http.StatusUnauthorized)
		if errResp.Error != "invalid_client" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_client")
		}
	})

	t.Run("returns invalid_client for failed client authentication", func(t *testing.T) {
		resp := postRevoke(t, provider, revocationRequest{
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

func testRevocationImplementationNote(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("revoke-implementation-note")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	resp := postRevoke(t, provider, revocationRequest{
		ClientID:     webClientID,
		ClientSecret: webClientSecret,
		Token:        token.RefreshToken,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revocation status mismatch: got %s, want %d", resp.Status, http.StatusOK)
	}
	_ = readBody(t, resp)

	expectInactiveIntrospectionResponse(t, provider.postIntrospect(t, introspectionRequest{
		ClientID:     webClientID,
		ClientSecret: webClientSecret,
		Token:        token.AccessToken,
	}))
}

func testRevocationSecurityConsiderations(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("does not revoke tokens issued to a different client", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("revoke-other-client")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		for tokenType, value := range map[string]string{"access token": token.AccessToken, "refresh token": token.RefreshToken} {
			t.Run(tokenType, func(t *testing.T) {
				resp := postRevoke(t, provider, revocationRequest{
					ClientID:     otherClientID,
					ClientSecret: otherClientSecret,
					Token:        value,
				})
				body := readBody(t, resp)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("revocation status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
				}

				for _, value := range []string{token.AccessToken, token.RefreshToken} {
					response := introspectToken(t, provider, introspectionRequest{
						ClientID:     webClientID,
						ClientSecret: webClientSecret,
						Token:        value,
					})
					if !response.Active {
						t.Fatal("expected the owner's tokens to remain active after another client tried to revoke them")
					}
				}
			})
		}
	})
}

type revocationRequest struct {
	ClientID      string
	ClientSecret  string
	AuthMethod    string
	Token         string
	TokenTypeHint string
}

func postRevoke(t *testing.T, provider *providerProcess, request revocationRequest) *http.Response {
	t.Helper()

	form := url.Values{}
	if request.Token != "" {
		form.Set("token", request.Token)
	}
	if request.TokenTypeHint != "" {
		form.Set("token_type_hint", request.TokenTypeHint)
	}
	if request.ClientID != "" {
		form.Set("client_id", request.ClientID)
	}
	if request.ClientSecret != "" && request.AuthMethod == authMethodClientSecretPost {
		form.Set("client_secret", request.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, provider.endpoint("/revoke"), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to create revoke request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if request.ClientSecret != "" && request.AuthMethod != authMethodClientSecretPost {
		req.SetBasicAuth(url.QueryEscape(request.ClientID), url.QueryEscape(request.ClientSecret))
		form.Del("client_id")
		form.Del("client_secret")
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		req.ContentLength = int64(len(form.Encode()))
	}
	return provider.do(t, provider.http, req)
}
