package simpleidp

// Reference material:
// OIDC Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
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

	t.Run("only logs out the current browser session", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		otherBrowser := newProviderBrowser(t, provider)
		request := newDefaultConfidentialAuthorizationRequest("logout-browser-scope")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		otherToken := authorizeAndExchange(t, otherBrowser, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		otherClaims := verifyIDToken(t, provider, otherToken.IDToken)
		if claims.Sid == otherClaims.Sid {
			t.Fatal("expected distinct session identifiers for the two browsers")
		}

		body := fetchLogoutForm(t, provider, url.Values{})
		_ = readBody(t, submitConsentForm(t, provider, body, "yes"))
		requests := receiver.receivedRequests()
		if len(requests) != 1 {
			t.Fatalf("expected 1 backchannel logout request, got %d", len(requests))
		}
		logoutClaims := verifyLogoutToken(t, provider, requests[0].rawToken)
		if logoutClaims.Sid != claims.Sid {
			t.Fatalf("logout sid mismatch: got %q, want %q", logoutClaims.Sid, claims.Sid)
		}
		resp := provider.getUserInfoResponse(t, token.AccessToken)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
		}
		if userInfo := fetchUserInfo(t, otherBrowser, otherToken.AccessToken); userInfo.Sub != testSubject {
			t.Fatalf("other browser subject mismatch: got %q, want %q", userInfo.Sub, testSubject)
		}
		_ = exchangeRefreshToken(t, otherBrowser, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: otherToken.RefreshToken,
		})
		request.Prompt = "none"
		expectAuthorizationCodeRedirect(t, otherBrowser.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
	})

	t.Run("preserves grants when the browser reauthenticates as the same user", func(t *testing.T) {
		for _, trigger := range []string{"prompt login", "max_age", "select_account"} {
			t.Run(trigger, func(t *testing.T) {
				receiver, receiverURL := startBackchannelLogoutReceiver(t)
				config := defaultProviderConfig()
				for i := range config.Clients {
					config.Clients[i].BackchannelLogoutURI = receiverURL
				}
				provider := startProvider(t, config)
				otherBrowser := newProviderBrowser(t, provider)
				request := newDefaultConfidentialAuthorizationRequest("reauthentication-grants")
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				otherToken := authorizeAndExchange(t, otherBrowser, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				claims := verifyIDToken(t, provider, token.IDToken)
				provider.idp.mu.Lock()
				currentSession := provider.idp.sessions[claims.Sid]
				currentSession.authenticatedAt = time.Now().Add(-time.Minute)
				provider.idp.sessions[claims.Sid] = currentSession
				provider.idp.mu.Unlock()

				request.ClientID = otherClientID
				request.RedirectURI = otherClientRedirect
				params := authorizeParams(request)
				switch trigger {
				case "prompt login":
					params.Set("prompt", "login")
				case "max_age":
					params.Set("max_age", "30")
				case "select_account":
					params.Set("prompt", "select_account")
				}
				body := readBody(t, provider.getAuthorize(t, params))
				body = readBody(t, submitLoginForm(t, provider, body, testUsername, "wrong-password"))
				_ = fetchUserInfo(t, provider, token.AccessToken)
				if requests := receiver.receivedRequests(); len(requests) != 0 {
					t.Fatalf("expected no logout after failed authentication, got %d requests", len(requests))
				}

				reauthenticatedAt := time.Now().Unix()
				code := expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
				reauthenticated := exchangeAuthorizationCode(t, provider, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: otherClientSecret,
					Code:         code,
					CodeVerifier: request.Verifier,
				})
				reauthenticatedClaims := verifyIDToken(t, provider, reauthenticated.IDToken)
				if reauthenticatedClaims.Sid != claims.Sid {
					t.Fatalf("session changed after reauthentication: got %q, want %q", reauthenticatedClaims.Sid, claims.Sid)
				}
				if reauthenticatedClaims.AuthTime < reauthenticatedAt {
					t.Fatalf("expected fresh auth_time, got %d, want at least %d", reauthenticatedClaims.AuthTime, reauthenticatedAt)
				}
				if requests := receiver.receivedRequests(); len(requests) != 0 {
					t.Fatalf("expected no logout after reauthentication, got %d requests", len(requests))
				}
				_ = fetchUserInfo(t, provider, token.AccessToken)
				refreshed := exchangeRefreshToken(t, provider, tokenRequest{
					ClientID:     webClientID,
					ClientSecret: webClientSecret,
					RefreshToken: token.RefreshToken,
				})
				if refreshedClaims := verifyIDToken(t, provider, refreshed.IDToken); refreshedClaims.AuthTime != claims.AuthTime {
					t.Fatalf("original grant auth_time changed: got %d, want %d", refreshedClaims.AuthTime, claims.AuthTime)
				}

				params.Set("prompt", "none")
				params.Set("max_age", "30")
				code = expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, params), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
				silent := exchangeAuthorizationCode(t, provider, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: otherClientSecret,
					Code:         code,
					CodeVerifier: request.Verifier,
				})
				if silentClaims := verifyIDToken(t, provider, silent.IDToken); silentClaims.AuthTime != reauthenticatedClaims.AuthTime {
					t.Fatalf("session auth_time mismatch: got %d, want %d", silentClaims.AuthTime, reauthenticatedClaims.AuthTime)
				}

				body = fetchLogoutForm(t, provider, url.Values{})
				_ = readBody(t, submitConsentForm(t, provider, body, "yes"))
				requests := receiver.receivedRequests()
				if len(requests) != 2 {
					t.Fatalf("expected 2 logout notifications, got %d", len(requests))
				}
				audiences := map[string]bool{}
				for _, request := range requests {
					logoutClaims := verifyLogoutToken(t, provider, request.rawToken)
					if logoutClaims.Sid != claims.Sid || logoutClaims.Sub != testSubject {
						t.Fatalf("unexpected logout claims: %#v", logoutClaims)
					}
					audiences[logoutClaims.Aud] = true
				}
				if !audiences[webClientID] || !audiences[otherClientID] {
					t.Fatalf("unexpected logout audiences: %#v", audiences)
				}
				for _, accessToken := range []string{token.AccessToken, refreshed.AccessToken, reauthenticated.AccessToken, silent.AccessToken} {
					resp := provider.getUserInfoResponse(t, accessToken)
					body := readBody(t, resp)
					if resp.StatusCode != http.StatusUnauthorized {
						t.Fatalf("userinfo status after logout mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
					}
				}
				for _, request := range []tokenRequest{
					{ClientID: webClientID, ClientSecret: webClientSecret, GrantType: "refresh_token", RefreshToken: refreshed.RefreshToken},
					{ClientID: otherClientID, ClientSecret: otherClientSecret, GrantType: "refresh_token", RefreshToken: reauthenticated.RefreshToken},
				} {
					errResp := expectJSONError(t, provider.postToken(t, request), http.StatusBadRequest)
					if errResp.Error != "invalid_grant" {
						t.Fatalf("refresh error after logout mismatch: got %q, want %q", errResp.Error, "invalid_grant")
					}
				}
				_ = fetchUserInfo(t, otherBrowser, otherToken.AccessToken)
			})
		}
	})

	t.Run("ends the previous session when the browser switches accounts", func(t *testing.T) {
		for _, trigger := range []string{"prompt login", "max_age", "select_account"} {
			t.Run(trigger, func(t *testing.T) {
				receiver, receiverURL := startBackchannelLogoutReceiver(t)
				config := defaultProviderConfig()
				config.Users = append(config.Users, userConfig{
					Label:    "BOB",
					Username: "bob",
					Password: "bob-password",
					Sub:      "bob-subject",
					Name:     "Bob Example",
					Email:    "bob@example.com",
				})
				for i := range config.Clients {
					config.Clients[i].BackchannelLogoutURI = receiverURL
				}
				provider := startProvider(t, config)
				otherBrowser := newProviderBrowser(t, provider)
				request := newDefaultConfidentialAuthorizationRequest("account-switch-logout")
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				otherToken := authorizeAndExchange(t, otherBrowser, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				claims := verifyIDToken(t, provider, token.IDToken)
				request.ClientID = otherClientID
				request.RedirectURI = otherClientRedirect
				params := authorizeParams(request)
				switch trigger {
				case "prompt login":
					params.Set("prompt", "login")
				case "max_age":
					params.Set("max_age", "0")
				case "select_account":
					params.Set("prompt", "select_account")
				}
				body := readBody(t, provider.getAuthorize(t, params))
				body = readBody(t, submitLoginForm(t, provider, body, testUsername, "wrong-password"))
				_ = fetchUserInfo(t, provider, token.AccessToken)
				if requests := receiver.receivedRequests(); len(requests) != 0 {
					t.Fatalf("expected no logout before successful authentication, got %d requests", len(requests))
				}
				code := expectAuthorizationCodeRedirect(t, submitLoginForm(t, provider, body, "bob", "bob-password"), http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
				replacement := exchangeAuthorizationCode(t, provider, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: otherClientSecret,
					Code:         code,
					CodeVerifier: request.Verifier,
				})
				replacementClaims := verifyIDToken(t, provider, replacement.IDToken)
				if replacementClaims.Sub != "bob-subject" {
					t.Fatalf("subject after account switch mismatch: got %q, want %q", replacementClaims.Sub, "bob-subject")
				}
				if replacementClaims.Sid == claims.Sid {
					t.Fatal("expected a new session identifier after switching accounts")
				}
				requests := receiver.receivedRequests()
				if len(requests) != 1 {
					t.Fatalf("expected 1 logout notification for the superseded session, got %d", len(requests))
				}
				logoutClaims := verifyLogoutToken(t, provider, requests[0].rawToken)
				if logoutClaims.Aud != webClientID || logoutClaims.Sid != claims.Sid || logoutClaims.Sub != testSubject {
					t.Fatalf("unexpected superseded-session logout claims: %#v", logoutClaims)
				}
				resp := provider.getUserInfoResponse(t, token.AccessToken)
				body = readBody(t, resp)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("userinfo status mismatch after switching accounts: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
				}
				errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
					ClientID:     webClientID,
					ClientSecret: webClientSecret,
					GrantType:    "refresh_token",
					RefreshToken: token.RefreshToken,
				}), http.StatusBadRequest)
				if errResp.Error != "invalid_grant" {
					t.Fatalf("refresh error mismatch after switching accounts: got %q, want %q", errResp.Error, "invalid_grant")
				}
				body = fetchLogoutForm(t, provider, url.Values{})
				_ = readBody(t, submitConsentForm(t, provider, body, "yes"))
				requests = receiver.receivedRequests()
				if len(requests) != 2 {
					t.Fatalf("expected 2 logout notifications after ending both sessions, got %d", len(requests))
				}
				logoutClaims = verifyLogoutToken(t, provider, requests[1].rawToken)
				if logoutClaims.Aud != otherClientID || logoutClaims.Sid != replacementClaims.Sid || logoutClaims.Sub != "bob-subject" {
					t.Fatalf("unexpected replacement-session logout claims: %#v", logoutClaims)
				}
				_ = fetchUserInfo(t, otherBrowser, otherToken.AccessToken)
			})
		}
	})

	t.Run("ends the OP session before waiting for parallel back-channel responses", func(t *testing.T) {
		entered := make(chan struct{}, 2)
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		listener, err := listenLocal(t)
		if err != nil {
			t.Fatalf("failed to open listener: %v", err)
		}
		addr := listener.Addr().String()
		mux := http.NewServeMux()
		mux.HandleFunc("POST /backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusOK)
		})
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(listener) }()
		t.Cleanup(func() { _ = srv.Close() })

		receiverURL := "http://" + addr + "/backchannel-logout"
		config := backchannelProviderConfig(receiverURL, true)
		for i, client := range config.Clients {
			if client.ID == otherClientID {
				config.Clients[i].BackchannelLogoutURI = receiverURL
			}
		}
		provider := startProvider(t, config)
		t.Cleanup(unblock)
		request := newDefaultConfidentialAuthorizationRequest("logout-before-backchannel-response")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		otherRequest := request
		otherRequest.ClientID = otherClientID
		otherRequest.RedirectURI = otherClientRedirect
		_ = authorizeAndExchange(t, provider, otherRequest, tokenRequest{
			ClientID:     otherRequest.ClientID,
			ClientSecret: otherClientSecret,
			CodeVerifier: otherRequest.Verifier,
		})
		body := fetchLogoutForm(t, provider, url.Values{})
		form := url.Values{
			"confirm":    {"yes"},
			"csrf_token": {extractHiddenInputValue(t, body, "csrf_token")},
		}
		req, err := http.NewRequest(http.MethodPost, resolveProviderURL(t, provider.issuer, extractFormAction(t, body)), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		logoutClient := newHTTPClient(false, provider.http.Jar)
		logoutClient.Timeout = 20 * time.Second
		t.Cleanup(logoutClient.CloseIdleConnections)
		var logoutResp *http.Response
		var logoutErr error
		done := make(chan struct{})
		go func() {
			logoutResp, logoutErr = logoutClient.Do(req)
			if logoutResp != nil {
				_ = logoutResp.Body.Close()
			}
			close(done)
		}()
		for range 2 {
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for concurrent back-channel requests")
			}
		}

		request.Prompt = "none"
		expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			GrantType:    "refresh_token",
			RefreshToken: token.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("refresh error mismatch during logout: got %q, want %q", errResp.Error, "invalid_grant")
		}
		select {
		case <-done:
			t.Fatal("logout completed before the back-channel responses were released")
		default:
		}
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for logout to finish")
		}
		if logoutErr != nil {
			t.Fatalf("logout request failed: %v", logoutErr)
		}
		if logoutResp.StatusCode != http.StatusOK {
			t.Fatalf("logout completion status mismatch: got %s, want %d", logoutResp.Status, http.StatusOK)
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

		body := fetchLogoutForm(t, provider, url.Values{})
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

	t.Run("notifies every logged-in RP when one client initiates logout", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		config := defaultProviderConfig()
		for i := range config.Clients {
			config.Clients[i].BackchannelLogoutURI = receiverURL
		}
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("logout-all-rps")
		webToken := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		request.ClientID = otherClientID
		request.RedirectURI = otherClientRedirect
		otherToken := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: otherClientSecret,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, webToken.IDToken)
		if otherClaims := verifyIDToken(t, provider, otherToken.IDToken); otherClaims.Sid != claims.Sid {
			t.Fatal("expected both RPs to share the browser session")
		}

		request.ClientID = nativeClientID
		request.RedirectURI = nativeClientRedirect
		code := authorize(t, provider, request).Code
		body := fetchLogoutForm(t, provider, url.Values{"id_token_hint": {webToken.IDToken}})
		_ = readBody(t, submitConsentForm(t, provider, body, "yes"))

		requests := receiver.receivedRequests()
		if len(requests) != 2 {
			t.Fatalf("expected 2 backchannel logout requests, got %d", len(requests))
		}
		notified := map[string]bool{}
		for _, received := range requests {
			logoutClaims := verifyLogoutToken(t, provider, received.rawToken)
			if logoutClaims.Sid != claims.Sid {
				t.Fatalf("logout sid mismatch: got %q, want %q", logoutClaims.Sid, claims.Sid)
			}
			notified[logoutClaims.Aud] = true
		}
		if !notified[webClientID] || !notified[otherClientID] {
			t.Fatalf("expected both logged-in RPs to be notified, got %#v", notified)
		}
		for _, token := range []tokenResponse{webToken, otherToken} {
			resp := provider.getUserInfoResponse(t, token.AccessToken)
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("userinfo status mismatch after logout: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
			}
		}
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     nativeClientID,
			Code:         code,
			CodeVerifier: request.Verifier,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("pending grant error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
	})

	t.Run("remembers logged-in RPs after their token records are removed", func(t *testing.T) {
		for _, removal := range []string{"revocation", "expiration"} {
			t.Run(removal, func(t *testing.T) {
				receiver, receiverURL := startBackchannelLogoutReceiver(t)
				provider := startProvider(t, backchannelProviderConfig(receiverURL, true))
				request := newDefaultConfidentialAuthorizationRequest("logout-remember-rp")
				authorization := authorizeAndLogin(t, provider, request)
				token := exchangeAuthorizationCode(t, provider, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					Code:         authorization.Code,
					CodeVerifier: request.Verifier,
				})
				provider.expireAuthorizationCode(t, authorization.Code)
				if removal == "revocation" {
					resp := provider.postFormURL(t, provider.endpoint("/revoke"), url.Values{
						"client_id":     {webClientID},
						"client_secret": {webClientSecret},
						"token":         {token.RefreshToken},
					}, "", false)
					body := readBody(t, resp)
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("revocation status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
					}
				} else {
					provider.expireAccessToken(t, token.AccessToken)
					provider.expireRefreshTokenIdle(t, token.RefreshToken)
					provider.ageConsumedAuthorizationCode(t, authorization.Code, provider.idp.refreshTokenMaxTTL+provider.idp.accessTokenTTL+time.Minute)
				}

				body := fetchLogoutForm(t, provider, url.Values{})
				provider.idp.mu.Lock()
				remaining := len(provider.idp.pendingCodes) + len(provider.idp.accessTokens) + len(provider.idp.refreshTokens)
				provider.idp.mu.Unlock()
				if remaining != 0 {
					t.Fatalf("expected token and code records to be removed before logout, got %d", remaining)
				}
				_ = readBody(t, submitConsentForm(t, provider, body, "yes"))
				requests := receiver.receivedRequests()
				if len(requests) != 1 {
					t.Fatalf("expected 1 notification after token %s, got %d", removal, len(requests))
				}
				claims := verifyLogoutToken(t, provider, requests[0].rawToken)
				if claims.Aud != webClientID {
					t.Fatalf("logout audience mismatch: got %q, want %q", claims.Aud, webClientID)
				}
			})
		}
	})

	t.Run("logs out expired browser sessions", func(t *testing.T) {
		for _, expiry := range []string{"idle", "maximum"} {
			for _, phase := range []string{"before cleanup", "after cleanup"} {
				t.Run(expiry+"/"+phase, func(t *testing.T) {
					receiver, uri := startBackchannelLogoutReceiver(t)
					provider := startProvider(t, backchannelProviderConfig(uri, false))
					request := newDefaultConfidentialAuthorizationRequest("expired-session-logout")
					token := authorizeAndExchange(t, provider, request, tokenRequest{
						ClientSecret: webClientSecret,
						CodeVerifier: request.Verifier,
					})
					sessionID := provider.currentSessionID(t)

					if expiry == "idle" {
						provider.expireSessionIdle(t)
					} else {
						provider.expireSessionMax(t)
					}

					if phase == "after cleanup" {
						request.Prompt = "none"
						expectAuthorizationErrorRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound,
							request.RedirectURI, request.State, provider.issuer, "login_required")
					}

					body := fetchLogoutForm(t, provider, url.Values{})
					if len(receiver.receivedRequests()) != 0 {
						t.Fatal("logout must wait for confirmation")
					}
					invalid := provider.postFormURL(t, provider.endpoint("/end-session"), url.Values{
						"confirm": {"yes"}, "csrf_token": {"invalid"},
					}, "", false)
					readBody(t, invalid)
					if invalid.StatusCode != http.StatusBadRequest {
						t.Fatalf("expired-session logout accepted invalid CSRF token: %s", invalid.Status)
					}

					refreshed := exchangeRefreshToken(t, provider, tokenRequest{
						ClientID: webClientID, ClientSecret: webClientSecret, RefreshToken: token.RefreshToken,
					})
					result := readBody(t, submitConsentForm(t, provider, body, "yes"))
					if !strings.Contains(string(result), "You have been signed out.") {
						t.Fatalf("unexpected logout response: %s", result)
					}
					notifications := receiver.receivedRequests()
					if len(notifications) != 1 {
						t.Fatalf("got %d back-channel notifications, want 1", len(notifications))
					}
					if claims := verifyLogoutToken(t, provider, notifications[0].rawToken); claims.Sid != sessionID {
						t.Fatalf("logout sid = %q, want %q", claims.Sid, sessionID)
					}
					for _, access := range []string{token.AccessToken, refreshed.AccessToken} {
						resp := provider.getUserInfoResponse(t, access)
						readBody(t, resp)
						if resp.StatusCode != http.StatusUnauthorized {
							t.Fatalf("access token survived logout: %s", resp.Status)
						}
					}
					errResponse := expectJSONError(t, provider.postToken(t, tokenRequest{
						GrantType: "refresh_token", ClientID: webClientID,
						ClientSecret: webClientSecret, RefreshToken: refreshed.RefreshToken,
					}), http.StatusBadRequest)
					if errResponse.Error != "invalid_grant" {
						t.Fatalf("refresh error = %q, want invalid_grant", errResponse.Error)
					}
				})
			}
		}
	})

	t.Run("retains logout metadata through the final access token lifetime", func(t *testing.T) {
		for _, phase := range []string{"last access token active", "all tokens expired"} {
			t.Run(phase, func(t *testing.T) {
				receiver, uri := startBackchannelLogoutReceiver(t)
				provider := startProvider(t, backchannelProviderConfig(uri, true))
				request := newDefaultConfidentialAuthorizationRequest("logout-final-access-token")
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})
				sessionID := provider.currentSessionID(t)
				age := provider.idp.sessionMaxTTL + provider.idp.refreshTokenMaxTTL + time.Minute
				if phase == "all tokens expired" {
					age += provider.idp.accessTokenTTL
					provider.expireAccessToken(t, token.AccessToken)
				}
				provider.ageSession(t, age, age)
				provider.expireRefreshTokenMax(t, token.RefreshToken)
				info := introspectToken(t, provider, introspectionRequest{
					ClientID:     webClientID,
					ClientSecret: webClientSecret,
					Token:        token.AccessToken,
				})
				if info.Active != (phase == "last access token active") {
					t.Fatalf("unexpected final access token activity: %t", info.Active)
				}
				if phase == "all tokens expired" {
					provider.idp.mu.Lock()
					_, retained := provider.idp.sessions[sessionID]
					provider.idp.mu.Unlock()
					if retained {
						t.Fatal("logout metadata remained after its retention window")
					}
					return
				}

				body := fetchLogoutForm(t, provider, url.Values{})
				_ = readBody(t, submitConsentForm(t, provider, body, "yes"))
				notifications := receiver.receivedRequests()
				if len(notifications) != 1 {
					t.Fatalf("got %d back-channel notifications, want 1", len(notifications))
				}
				if claims := verifyLogoutToken(t, provider, notifications[0].rawToken); claims.Sid != sessionID {
					t.Fatalf("logout sid = %q, want %q", claims.Sid, sessionID)
				}
				resp := provider.getUserInfoResponse(t, token.AccessToken)
				readBody(t, resp)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("final access token survived logout: %s", resp.Status)
				}
			})
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
		now := time.Now().Unix()
		if claims.Iat <= 0 || claims.Iat > now {
			t.Fatalf("iat must identify an issuance time at or before now, got %d", claims.Iat)
		}
		if claims.Exp <= now {
			t.Fatalf("exp must be in the future, got %d", claims.Exp)
		}
		if claims.Jti == "" {
			t.Fatal("jti must be present")
		}
		if claims.Events == nil {
			t.Fatal("events claim must be present")
		}
		if event, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"].(map[string]any); !ok || event == nil {
			t.Fatalf("events claim must contain a backchannel-logout JSON object: %#v", claims.Events)
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

		raw := decodeJWTClaims(t, requests[0].rawToken)
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

	t.Run("completes logout without following redirects from the back-channel endpoint", func(t *testing.T) {
		for _, status := range []int{http.StatusSeeOther, http.StatusTemporaryRedirect} {
			t.Run(http.StatusText(status), func(t *testing.T) {
				listener, err := listenLocal(t)
				if err != nil {
					t.Fatalf("failed to open listener: %v", err)
				}
				addr := listener.Addr().String()
				followed := make(chan struct{}, 1)
				mux := http.NewServeMux()
				mux.HandleFunc("POST /backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "/redirected", status)
				})
				mux.HandleFunc("/redirected", func(w http.ResponseWriter, r *http.Request) {
					select {
					case followed <- struct{}{}:
					default:
					}
					w.WriteHeader(http.StatusOK)
				})
				srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
				go func() { _ = srv.Serve(listener) }()
				t.Cleanup(func() { _ = srv.Close() })

				receiverURL := "http://" + addr + "/backchannel-logout"
				provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
				token := performLogoutWithBackchannel(t, provider)
				if len(followed) != 0 {
					t.Fatalf("back-channel logout followed an HTTP %d redirect", status)
				}

				userInfoResp := provider.getUserInfoResponse(t, token.AccessToken)
				body := readBody(t, userInfoResp)
				if userInfoResp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", userInfoResp.Status, http.StatusUnauthorized, body)
				}
			})
		}
	})
}

func testBackChannelLogoutSecurity(t *testing.T) {
	t.Run("does not accept an id token sid as a browser authentication cookie", func(t *testing.T) {
		provider := startProvider(t, defaultProviderConfig())
		request := newDefaultConfidentialAuthorizationRequest("sid-is-not-a-cookie")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		claims := verifyIDToken(t, provider, token.IDToken)
		if claims.Sid == "" {
			t.Fatal("expected a session identifier in the id token")
		}
		browser := newProviderBrowser(t, provider)
		request.Prompt = "none"
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/authorize")+"?"+authorizeParams(request).Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create authorization request: %v", err)
		}
		req.Header.Set("Cookie", provider.idp.cookieName(sessionCookieBaseName)+"="+claims.Sid)
		resp := browser.do(t, browser.redirectless, req)
		expectAuthorizationErrorRedirect(t, resp, http.StatusFound, request.RedirectURI, request.State, provider.issuer, "login_required")
		expectAuthorizationCodeRedirect(t, provider.getAuthorize(t, authorizeParams(request)), http.StatusFound, request.RedirectURI, request.State, provider.issuer)
	})

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

	t.Run("logout token lifetime follows the recommended two-minute limit", func(t *testing.T) {
		receiver, receiverURL := startBackchannelLogoutReceiver(t)
		provider := startProvider(t, backchannelProviderConfig(receiverURL, false))
		performLogoutWithBackchannel(t, provider)

		requests := receiver.receivedRequests()
		claims := decodeLogoutToken(t, requests[0].rawToken)
		window := claims.Exp - claims.Iat
		if window <= 0 || window > 120 {
			t.Fatalf("exp-iat window should be positive and at most 120s, got %d", window)
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
