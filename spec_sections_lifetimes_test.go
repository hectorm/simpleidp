package simpleidp

// Reference material:
// Simple IdP: README.md

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func testLifetimes(t *testing.T) {
	signingKey, err := testSigningKeyB64()
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	environ := []string{
		"SIMPLE_IDP_ISSUER=http://127.0.0.1",
		"SIMPLE_IDP_KEY_B64=" + signingKey,
		"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
		"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
		"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
		"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
	}
	lifetimes := []struct {
		name     string
		fallback time.Duration
		get      func(*identityProvider) time.Duration
	}{
		{name: "SIMPLE_IDP_SESSION_IDLE_TTL", fallback: 30 * time.Minute, get: func(idp *identityProvider) time.Duration { return idp.sessionIdleTTL }},
		{name: "SIMPLE_IDP_SESSION_MAX_TTL", fallback: 10 * time.Hour, get: func(idp *identityProvider) time.Duration { return idp.sessionMaxTTL }},
		{name: "SIMPLE_IDP_ACCESS_TOKEN_TTL", fallback: 5 * time.Minute, get: func(idp *identityProvider) time.Duration { return idp.accessTokenTTL }},
		{name: "SIMPLE_IDP_REFRESH_TOKEN_IDLE_TTL", fallback: 30 * time.Minute, get: func(idp *identityProvider) time.Duration { return idp.refreshTokenIdleTTL }},
		{name: "SIMPLE_IDP_REFRESH_TOKEN_MAX_TTL", fallback: 10 * time.Hour, get: func(idp *identityProvider) time.Duration { return idp.refreshTokenMaxTTL }},
	}

	t.Run("uses the documented default lifetimes", func(t *testing.T) {
		idp, err := newIdentityProviderFromEnv(environ)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		for _, lifetime := range lifetimes {
			if got := lifetime.get(idp); got != lifetime.fallback {
				t.Fatalf("%s default mismatch: got %s, want %s", lifetime.name, got, lifetime.fallback)
			}
		}
	})

	t.Run("applies configured lifetimes", func(t *testing.T) {
		for _, lifetime := range lifetimes {
			t.Run(lifetime.name, func(t *testing.T) {
				idp, err := newIdentityProviderFromEnv(append(slices.Clone(environ), lifetime.name+"=90m"))
				if err != nil {
					t.Fatalf("failed to create provider: %v", err)
				}
				if got := lifetime.get(idp); got != 90*time.Minute {
					t.Fatalf("%s mismatch: got %s, want %s", lifetime.name, got, 90*time.Minute)
				}
			})
		}
	})

	t.Run("rejects lifetimes that are not positive durations", func(t *testing.T) {
		for _, lifetime := range lifetimes {
			for _, value := range []string{"soon", "0s", "-1m"} {
				t.Run(lifetime.name+"/"+value, func(t *testing.T) {
					_, err := newIdentityProviderFromEnv(append(slices.Clone(environ), lifetime.name+"="+value))
					if err == nil || !strings.Contains(err.Error(), lifetime.name+": must be a positive duration") {
						t.Fatalf("expected invalid lifetime error, got %v", err)
					}
				})
			}
		}
	})
}
