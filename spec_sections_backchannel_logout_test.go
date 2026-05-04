package simpleidp

// Reference material:
// OIDC Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func testBackChannelLogout(t *testing.T) {
	t.Run("sends a logout token to the client back-channel logout URI on logout", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}
		if requests[0].rawToken == "" {
			t.Fatal("expected a logout_token in the backchannel request")
		}
	})

	t.Run("does not send a logout token to clients without a back-channel logout URI", func(t *testing.T) {
		receiver, _ := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, defaultProviderConfig())
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 0 {
			t.Fatalf("expected 0 backchannel logout requests, got %d", len(requests))
		}
	})

	t.Run("revokes tokens and sends back-channel notification on IdP-initiated logout", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		token := performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}

		userInfoResp := provider.getUserInfoResponse(t, token.AccessToken)
		body := readBody(t, userInfoResp)
		if userInfoResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", userInfoResp.Status, http.StatusUnauthorized, body)
		}
	})
}

func testBackChannelLogoutDiscoveryMetadata(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())
	discovery := fetchDiscovery(t, provider)

	if !discovery.BackchannelLogoutSupported {
		t.Fatal("backchannel_logout_supported should be true")
	}
	if !discovery.BackchannelLogoutSessionSupported {
		t.Fatal("backchannel_logout_session_supported should be true")
	}
}

func testBackChannelLogoutClientRegistration(t *testing.T) {
	t.Run("accepts clients with a back-channel logout URI", func(t *testing.T) {
		_, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		if _, ok := provider.idp.clients[webClientID]; !ok {
			t.Fatal("expected web client to be registered")
		}
	})

	t.Run("accepts clients with backchannel_logout_session_required", func(t *testing.T) {
		_, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, true))
		c := provider.idp.clients[webClientID]
		if !c.backchannelLogoutSessionRequired {
			t.Fatal("expected backchannelLogoutSessionRequired to be true")
		}
	})
}

func testBackChannelLogoutRememberingRPs(t *testing.T) {
	t.Run("only notifies clients the user has interacted with", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)

		config := defaultProviderConfig()
		for i, c := range config.Clients {
			if c.ID == webClientID {
				config.Clients[i].BackchannelLogoutURI = receiverURL
			}
			if c.ID == otherClientID {
				config.Clients[i].BackchannelLogoutURI = receiverURL
			}
		}

		provider := startProvider(t, config)

		verifier := pkceVerifier("backchannel-remembering")
		authorizeAndExchange(t, provider, authorizationRequest{
			ClientID:    webClientID,
			RedirectURI: webClientRedirect,
			Scope:       "openid",
			State:       "remembering-state",
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
		_ = readBody(t, submitConsentForm(t, provider, body, "yes"))

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request (only web-client), got %d", len(requests))
		}
		claims := decodeLogoutToken(t, requests[0].rawToken)
		if claims.Aud != webClientID {
			t.Fatalf("expected logout token audience %q, got %q", webClientID, claims.Aud)
		}
	})
}

func testBackChannelLogoutToken(t *testing.T) {
	t.Run("logout token contains required claims", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}
		claims := verifyLogoutToken(t, provider, requests[0].rawToken)

		if claims.Iss != provider.issuer {
			t.Fatalf("iss mismatch: got %q, want %q", claims.Iss, provider.issuer)
		}
		if claims.Sub != testSubject {
			t.Fatalf("sub mismatch: got %q, want %q", claims.Sub, testSubject)
		}
		if claims.Aud != webClientID {
			t.Fatalf("aud mismatch: got %q, want %q", claims.Aud, webClientID)
		}
		if claims.Iat == 0 {
			t.Fatal("iat must be present")
		}
		if claims.Exp == 0 {
			t.Fatal("exp must be present")
		}
		if claims.Jti == "" {
			t.Fatal("jti must be present")
		}
		if claims.Events == nil {
			t.Fatal("events claim must be present")
		}
		if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
			t.Fatalf("events claim missing backchannel-logout member: %#v", claims.Events)
		}
	})

	t.Run("logout token includes sid when backchannel_logout_session_required is true", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, true))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}
		claims := verifyLogoutToken(t, provider, requests[0].rawToken)

		if claims.Sid == "" {
			t.Fatal("sid must be present when backchannel_logout_session_required is true")
		}
	})

	t.Run("logout token does not include a nonce claim", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}

		parts := strings.Split(requests[0].rawToken, ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var raw map[string]any
		_ = json.Unmarshal(payload, &raw)
		if _, hasNonce := raw["nonce"]; hasNonce {
			t.Fatal("logout token must not contain a nonce claim")
		}
	})

	t.Run("logout token header uses the correct signing metadata", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}
		header := decodeJWTHeader(t, requests[0].rawToken)
		if header.Alg != "RS256" {
			t.Fatalf("expected alg RS256, got %q", header.Alg)
		}
		if header.Typ != "logout+jwt" {
			t.Fatalf("expected typ logout+jwt, got %q", header.Typ)
		}
	})

	t.Run("logout token sid matches the session id in the id token", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, true))

		verifier := pkceVerifier("backchannel-sid-match")
		token := authorizeAndExchange(t, provider, authorizationRequest{
			ClientID:    webClientID,
			RedirectURI: webClientRedirect,
			Scope:       "openid",
			State:       "sid-match-state",
			Verifier:    verifier,
		}, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: verifier,
		})

		idClaims := verifyIDToken(t, provider, token.IDToken)
		if idClaims.Sid == "" {
			t.Fatal("id token must contain a sid claim")
		}

		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session"), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}
		resp := provider.do(t, provider.redirectless, req)
		body := readBody(t, resp)
		_ = readBody(t, submitConsentForm(t, provider, body, "yes"))

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}
		logoutClaims := verifyLogoutToken(t, provider, requests[0].rawToken)
		if logoutClaims.Sid != idClaims.Sid {
			t.Fatalf("sid mismatch: id_token sid=%q, logout_token sid=%q", idClaims.Sid, logoutClaims.Sid)
		}
	})

	t.Run("id token sid is preserved after refresh token exchange", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())

		verifier := pkceVerifier("backchannel-sid-refresh")
		token := authorizeAndExchange(t, provider, authorizationRequest{
			ClientID:    webClientID,
			RedirectURI: webClientRedirect,
			Scope:       "openid",
			State:       "sid-refresh-state",
			Verifier:    verifier,
		}, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: verifier,
		})

		originalClaims := verifyIDToken(t, provider, token.IDToken)
		if originalClaims.Sid == "" {
			t.Fatal("original id token must contain a sid claim")
		}

		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})

		refreshedClaims := verifyIDToken(t, provider, refreshed.IDToken)
		if refreshedClaims.Sid != originalClaims.Sid {
			t.Fatalf("sid mismatch after refresh: original=%q, refreshed=%q", originalClaims.Sid, refreshedClaims.Sid)
		}
	})
}

func testBackChannelLogoutTokenValidation(t *testing.T) {
	t.Run("logout token is signed with the provider key and verifiable via JWKS", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}

		claims := verifyLogoutToken(t, provider, requests[0].rawToken)
		if claims.Iss != provider.issuer {
			t.Fatalf("iss mismatch: got %q, want %q", claims.Iss, provider.issuer)
		}
	})

	t.Run("logout token contains sub claim identifying the user", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		claims := verifyLogoutToken(t, provider, requests[0].rawToken)
		if claims.Sub != testSubject {
			t.Fatalf("sub mismatch: got %q, want %q", claims.Sub, testSubject)
		}
	})

	t.Run("logout token audience matches the client ID", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		claims := verifyLogoutToken(t, provider, requests[0].rawToken)
		if claims.Aud != webClientID {
			t.Fatalf("aud mismatch: got %q, want %q", claims.Aud, webClientID)
		}
	})
}

func testBackChannelLogoutRequest(t *testing.T) {
	t.Run("sends logout token as application/x-www-form-urlencoded POST", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}
		if !strings.HasPrefix(requests[0].contentType, "application/x-www-form-urlencoded") {
			t.Fatalf("expected application/x-www-form-urlencoded content type, got %q", requests[0].contentType)
		}
		if requests[0].rawToken == "" {
			t.Fatal("expected logout_token parameter in POST body")
		}
	})
}

func testBackChannelLogoutResponse(t *testing.T) {
	t.Run("treats HTTP 204 No Content as a successful back-channel logout response", func(t *testing.T) {
		listener, err := listenLocal(t)
		if err != nil {
			t.Fatalf("failed to open listener: %v", err)
		}
		addr := listener.Addr().String()
		mux := http.NewServeMux()
		mux.HandleFunc("POST /backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(listener) }()
		t.Cleanup(func() { _ = srv.Close() })

		receiverURL := "http://" + addr + "/backchannel-logout"
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		token := performLogoutWithBackchannel(t, provider)

		userInfoResp := provider.getUserInfoResponse(t, token.AccessToken)
		body := readBody(t, userInfoResp)
		if userInfoResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", userInfoResp.Status, http.StatusUnauthorized, body)
		}
	})

	t.Run("completes logout even when the back-channel endpoint returns HTTP 400", func(t *testing.T) {
		listener, err := listenLocal(t)
		if err != nil {
			t.Fatalf("failed to open listener: %v", err)
		}
		addr := listener.Addr().String()
		mux := http.NewServeMux()
		mux.HandleFunc("POST /backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		})
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(listener) }()
		t.Cleanup(func() { _ = srv.Close() })

		receiverURL := "http://" + addr + "/backchannel-logout"
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		token := performLogoutWithBackchannel(t, provider)

		userInfoResp := provider.getUserInfoResponse(t, token.AccessToken)
		body := readBody(t, userInfoResp)
		if userInfoResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", userInfoResp.Status, http.StatusUnauthorized, body)
		}
	})
}

func testBackChannelLogoutSecurity(t *testing.T) {
	t.Run("logout token has a unique jti for each request", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))

		performLogoutWithBackchannel(t, provider)
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		if len(requests) != 2 {
			t.Fatalf("expected 2 backchannel logout requests, got %d", len(requests))
		}

		jti1 := decodeLogoutToken(t, requests[0].rawToken).Jti
		jti2 := decodeLogoutToken(t, requests[1].rawToken).Jti
		if jti1 == jti2 {
			t.Fatalf("logout tokens must have unique jti values, both are %q", jti1)
		}
	})

	t.Run("logout token exp is within a reasonable window", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		claims := decodeLogoutToken(t, requests[0].rawToken)
		window := claims.Exp - claims.Iat
		if window <= 0 || window > 300 {
			t.Fatalf("exp-iat window should be positive and at most 300s, got %d", window)
		}
	})

	t.Run("discovery advertises sid in claims_supported", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		discovery := fetchDiscovery(t, provider)
		if !slices.Contains(discovery.ClaimsSupported, "sid") {
			t.Fatalf("claims_supported should include sid: %#v", discovery.ClaimsSupported)
		}
	})
}
