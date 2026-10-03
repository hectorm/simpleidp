package simpleidp

// Reference material:
// RFC 9068: https://www.rfc-editor.org/rfc/rfc9068.txt

import (
	"slices"
	"testing"
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
	if claims.Jti == "" || claims.Exp-claims.Iat != int64(token.ExpiresIn) {
		t.Fatalf("unexpected access token metadata: %#v", claims)
	}
}

func testJWTAccessTokenIdentityClaims(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("includes identity claims for the granted scopes", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-identity-claims")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		if claims := verifyAccessToken(t, provider, token.AccessToken); claims.Name != testName || claims.Email != testEmail {
			t.Fatalf("unexpected identity claims: %#v", claims)
		}
	})

	t.Run("omits identity claims for scopes that were not granted", func(t *testing.T) {
		request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-no-identity-claims")
		request.Scope = "openid"
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		if claims := verifyAccessToken(t, provider, token.AccessToken); claims.Name != "" || claims.Email != "" {
			t.Fatalf("unexpected identity claims: %#v", claims)
		}
	})
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

func testJWTAccessTokenGroupsClaim(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	request := newDefaultConfidentialAuthorizationRequest("jwt-access-token-groups")
	request.Scope = "openid groups"
	token := authorizeAndExchange(t, provider, request, tokenRequest{
		ClientID:     request.ClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: request.Verifier,
	})

	if claims := verifyAccessToken(t, provider, token.AccessToken); !slices.Equal(claims.Groups, testGroups) {
		t.Fatalf("groups mismatch: got %#v, want %#v", claims.Groups, testGroups)
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
