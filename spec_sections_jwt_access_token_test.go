package simpleidp

// Reference material:
// RFC 9068: https://www.rfc-editor.org/rfc/rfc9068.txt

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func testJWTAccessTokenHeader(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-header")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	if header := decodeJWTHeader(t, token.AccessToken); header.Alg != "RS256" || header.Typ != "at+jwt" || header.Kid == "" {
		t.Fatalf("unexpected access token header: %#v", header)
	}
	_ = verifyAccessToken(t, provider, token.AccessToken)
}

func testJWTAccessTokenDataStructure(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-data-structure")
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	claims := verifyAccessToken(t, provider, token.AccessToken)
	if claims.Iss != provider.issuer || claims.Sub != testSubject || claims.Aud == "" || claims.ClientID != request.ClientID {
		t.Fatalf("unexpected access token claims: %#v", claims)
	}
	if claims.Jti == "" || claims.Iat <= 0 || claims.Iat > time.Now().Unix() || claims.Exp <= time.Now().Unix() || claims.Exp-claims.Iat != int64(token.ExpiresIn) {
		t.Fatalf("unexpected access token metadata: %#v", claims)
	}
}

func testJWTAccessTokenIdentityClaims(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	profileClaims := map[string]any{
		"name": testName, "preferred_username": testPreferredUsername,
		"profile": testProfile, "picture": testPicture, "locale": testLocale,
	}
	emailClaims := map[string]any{"email": testEmail, "email_verified": true}
	for _, scope := range []string{"openid", "openid profile", "openid email", "openid profile email"} {
		t.Run(scope, func(t *testing.T) {
			request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-identity-" + scope)
			request.Scope = scope
			token := authorizeAndExchange(t, provider, request, tokenRequest{
				ClientID:     request.ClientID,
				ClientSecret: webClientSecret,
				CodeVerifier: request.Verifier,
			})
			_ = verifyAccessToken(t, provider, token.AccessToken)
			claims := decodeJWTClaims(t, token.AccessToken)
			for scopeName, expected := range map[string]map[string]any{"profile": profileClaims, "email": emailClaims} {
				granted := slices.Contains(strings.Fields(scope), scopeName)
				for name, want := range expected {
					value, present := claims[name]
					if present != granted || (granted && value != want) {
						t.Fatalf("claim %s for scope %q: got %#v (present=%t), want %#v (present=%t)", name, scope, value, present, want, granted)
					}
				}
			}
		})
	}
}

func testJWTAccessTokenAuthorizationClaims(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-scope")
	request.Scope = "openid profile"
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	if claims := verifyAccessToken(t, provider, token.AccessToken); claims.Scope != request.Scope {
		t.Fatalf("scope mismatch: got %q, want %q", claims.Scope, request.Scope)
	}
}

func testJWTAccessTokenGroupsAndRolesClaims(t *testing.T) {
	config := defaultProviderConfig()
	roles := []string{"reader", "operator"}
	config.Users[0].Roles = roles
	provider := startProvider(t, config)

	for _, scope := range []string{"openid", "openid groups", "openid roles", "openid groups roles"} {
		t.Run(scope, func(t *testing.T) {
			request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-authorization-" + scope)
			request.Scope = scope
			token := authorizeAndExchange(t, provider, request, tokenRequest{
				ClientID:     request.ClientID,
				ClientSecret: webClientSecret,
				CodeVerifier: request.Verifier,
			})
			claims := verifyAccessToken(t, provider, token.AccessToken)
			raw := decodeJWTClaims(t, token.AccessToken)
			for _, claim := range []struct {
				name string
				got  []string
				want []string
			}{
				{"groups", claims.Groups, testGroups},
				{"roles", claims.Roles, roles},
			} {
				granted := slices.Contains(strings.Fields(scope), claim.name)
				_, present := raw[claim.name]
				if present != granted || (granted && !slices.Equal(claim.got, claim.want)) {
					t.Fatalf("claim %s for scope %q: got %#v (present=%t), want %#v (present=%t)", claim.name, scope, claim.got, present, claim.want, granted)
				}
			}
		})
	}
}

func testRequestingJWTAccessToken(t *testing.T) {
	config := defaultProviderConfig()
	config.Clients[1].Audience = "https://api.example"
	provider := startProvider(t, config)

	t.Run("uses the client ID as the default audience", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-default-audience")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		if claims := verifyAccessToken(t, provider, token.AccessToken); claims.Aud != webClientID {
			t.Fatalf("audience mismatch: got %q, want %q", claims.Aud, webClientID)
		}
	})

	t.Run("uses the configured audience", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-configured-audience")
		request.ClientID = otherClientID
		request.RedirectURI = otherClientRedirect
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: otherClientSecret,
			CodeVerifier: request.Verifier,
		})

		if claims := verifyAccessToken(t, provider, token.AccessToken); claims.Aud != "https://api.example" {
			t.Fatalf("audience mismatch: got %q, want %q", claims.Aud, "https://api.example")
		}
	})
}
