package simpleidp

// Reference material:
// Simple IdP: README.md

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testPersistence(t *testing.T) {
	t.Run("keeps state in memory by default", func(t *testing.T) {
		config := defaultProviderConfig()
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("persistence-default")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		restarted := restartProvider(t, provider, config)

		silent := newDefaultConfidentialAuthorizationRequest("persistence-default-silent")
		silent.Prompt = "none"
		expectAuthorizationErrorRedirect(t, restarted.getAuthorize(t, authorizeParams(silent)), http.StatusFound, silent.RedirectURI, silent.State, restarted.issuer, "login_required")
		resp := restarted.getUserInfoResponse(t, token.AccessToken)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, body)
		}
	})

	t.Run("restores sessions and tokens after a restart", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("persistence-restore")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		restarted := restartProvider(t, provider, config)

		silent := newDefaultConfidentialAuthorizationRequest("persistence-restore-silent")
		silent.Prompt = "none"
		_ = authorize(t, restarted, silent)
		if claims := fetchUserInfo(t, restarted, token.AccessToken); claims.Sub != testSubject {
			t.Fatalf("userinfo subject mismatch: got %q, want %q", claims.Sub, testSubject)
		}
		refreshed := exchangeRefreshToken(t, restarted, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})
		if refreshed.AccessToken == "" || refreshed.RefreshToken == token.RefreshToken {
			t.Fatalf("expected a rotated refresh token, got %#v", refreshed)
		}
	})

	t.Run("keeps forms rendered before a restart valid", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		body := fetchLoginForm(t, provider)
		restarted := restartProvider(t, provider, config)

		redirect := expectRedirect(t, submitLoginForm(t, restarted, body, testUsername, testPassword), http.StatusSeeOther)
		assertRedirectTarget(t, redirect, "/")
	})

	t.Run("restores the generated signing key unless keys are configured", func(t *testing.T) {
		signingKey, err := testSigningKeyB64()
		if err != nil {
			t.Fatalf("failed to generate signing key: %v", err)
		}
		environ := []string{
			"SIMPLE_IDP_ISSUER=http://127.0.0.1",
			"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
			"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
			"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
			"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
			"SIMPLE_IDP_STATE_FILE=" + filepath.Join(t.TempDir(), "state.json"),
		}
		keyIDs := func(provider *identityProvider) []string {
			var ids []string
			for _, key := range provider.signingKeys {
				ids = append(ids, key.id)
			}
			return ids
		}
		first, err := newIdentityProviderFromEnv(environ)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		logs := captureLogs(t)
		restored, err := newIdentityProviderFromEnv(environ)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		if len(first.signingKeys) != 2 || !slices.Equal(keyIDs(restored), keyIDs(first)) {
			t.Fatalf("expected the generated signing keys %q to be restored, got %q", keyIDs(first), keyIDs(restored))
		}
		if strings.Contains(logs.String(), "generated RSA and ECDSA keys") {
			t.Fatalf("expected the restored signing keys to be used without generating new ones, got:\n%s", logs.String())
		}
		configured, err := newIdentityProviderFromEnv(append(environ, "SIMPLE_IDP_KEY_B64="+signingKey))
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		if configured.signingKeys[0].generated || slices.Equal(keyIDs(configured), keyIDs(first)) {
			t.Fatal("expected the configured signing key to replace the restored ones")
		}
		restoredAgain, err := newIdentityProviderFromEnv(environ)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}
		if !slices.Equal(keyIDs(restoredAgain), keyIDs(first)) {
			t.Fatalf("expected the generated signing keys %q to be kept while configured keys were in use, got %q", keyIDs(first), keyIDs(restoredAgain))
		}
	})

	t.Run("follows a symlinked state file", func(t *testing.T) {
		for _, testCase := range []struct {
			name     string
			existing bool
			relative bool
		}{
			{name: "existing target", existing: true},
			{name: "missing target"},
			{name: "missing relative target", relative: true},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				target := filepath.Join(t.TempDir(), "state.json")
				if testCase.existing {
					if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
						t.Fatalf("failed to write state file: %v", err)
					}
				}
				link := filepath.Join(t.TempDir(), "state.json")
				linkTarget := target
				if testCase.relative {
					relativeTarget, err := filepath.Rel(filepath.Dir(link), target)
					if err != nil {
						t.Fatalf("failed to compute relative link target: %v", err)
					}
					linkTarget = relativeTarget
				}
				if err := os.Symlink(linkTarget, link); err != nil {
					t.Fatalf("failed to create state file link: %v", err)
				}
				config := defaultProviderConfig()
				config.StateFile = link
				provider := startProvider(t, config)
				_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("persistence-symlink"))

				if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("expected the state file link to be kept, got %v: %v", info, err)
				}
				data, err := os.ReadFile(filepath.Clean(target))
				if err != nil {
					t.Fatalf("failed to read state file: %v", err)
				}
				if sessions, ok := decodeJSONMap(t, data)["Sessions"].(map[string]any); !ok || len(sessions) != 1 {
					t.Fatalf("expected one persisted session in the link target, got %s", data)
				}
			})
		}
	})

	t.Run("treats an empty state file as no state", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(config.StateFile, []byte(" \n"), 0o600); err != nil {
			t.Fatalf("failed to write state file: %v", err)
		}
		provider := startProvider(t, config)
		_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("persistence-empty"))

		data, err := os.ReadFile(filepath.Clean(config.StateFile))
		if err != nil {
			t.Fatalf("failed to read state file: %v", err)
		}
		if sessions, ok := decodeJSONMap(t, data)["Sessions"].(map[string]any); !ok || len(sessions) != 1 {
			t.Fatalf("expected one persisted session, got %s", data)
		}
	})

	t.Run("restores sessions saved without client IDs", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("persistence-client-ids"))
		provider.idp.mu.Lock()
		for id, current := range provider.idp.sessions {
			current.ClientIDs = nil
			provider.idp.sessions[id] = current
		}
		provider.idp.mu.Unlock()
		_ = fetchProfilePage(t, provider)

		restarted := restartProvider(t, provider, config)
		silent := newDefaultConfidentialAuthorizationRequest("persistence-client-ids-silent")
		silent.Prompt = "none"
		_ = exchangeAuthorizationCode(t, restarted, tokenRequest{
			ClientID:     silent.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorize(t, restarted, silent).Code,
			RedirectURI:  silent.RedirectURI,
			CodeVerifier: silent.Verifier,
		})
	})

	t.Run("restores login throttles", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		provider.agePasswordThrottle(t, 5, 0)
		_ = fetchLoginForm(t, provider)

		restarted := restartProvider(t, provider, config)
		restarted.idp.mu.Lock()
		failures := restarted.idp.throttles["password:ALICE"].Failures
		restarted.idp.mu.Unlock()
		if failures != 5 {
			t.Fatalf("restored password failures mismatch: got %d, want %d", failures, 5)
		}
	})

	t.Run("drops the state of users whose subject changed", func(t *testing.T) {
		config := defaultProviderConfig()
		config.EditProfile = true
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("persistence-subject")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		_ = expectRedirect(t, submitProfileForm(t, provider, fetchProfilePage(t, provider), "Alice Edited", testUsername, testEmail), http.StatusSeeOther)
		provider.agePasswordThrottle(t, 5, 0)
		provider.idp.mu.Lock()
		provider.idp.lastTOTPSteps["ALICE"] = 1
		provider.idp.mu.Unlock()
		_ = fetchProfilePage(t, provider)

		config.Users[0].Sub = "another-subject"
		restarted := restartProvider(t, provider, config)
		errResp := expectJSONError(t, restarted.postToken(t, tokenRequest{
			GrantType:    "refresh_token",
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
		silent := newDefaultConfidentialAuthorizationRequest("persistence-subject-silent")
		silent.Prompt = "none"
		expectAuthorizationErrorRedirect(t, restarted.getAuthorize(t, authorizeParams(silent)), http.StatusFound, silent.RedirectURI, silent.State, restarted.issuer, "login_required")
		if alice, _ := restarted.idp.lookupUser("ALICE"); alice.name != testName {
			t.Fatalf("expected the configured name for the new subject, got %q", alice.name)
		}
		restarted.idp.mu.Lock()
		throttles, steps := len(restarted.idp.throttles), len(restarted.idp.lastTOTPSteps)
		restarted.idp.mu.Unlock()
		if throttles != 0 || steps != 0 {
			t.Fatalf("expected no throttles or authentication code steps for the new subject, got %d and %d", throttles, steps)
		}
	})

	t.Run("drops grants issued under another issuer or client type", func(t *testing.T) {
		for _, testCase := range []struct {
			name         string
			change       func(*providerConfig)
			dropsSession bool
		}{
			{name: "issuer", change: func(config *providerConfig) { config.IssuerPath = "/tenant-b" }, dropsSession: true},
			{name: "client type", change: func(config *providerConfig) { config.Clients[0].Secret = "" }},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				config := defaultProviderConfig()
				config.StateFile = filepath.Join(t.TempDir(), "state.json")
				provider := startProvider(t, config)
				request := newDefaultConfidentialAuthorizationRequest("persistence-grant-binding")
				token := authorizeAndExchange(t, provider, request, tokenRequest{
					ClientID:     request.ClientID,
					ClientSecret: webClientSecret,
					CodeVerifier: request.Verifier,
				})

				testCase.change(&config)
				restarted := restartProvider(t, provider, config)
				errResp := expectJSONError(t, restarted.postToken(t, tokenRequest{
					GrantType:    "refresh_token",
					ClientID:     request.ClientID,
					ClientSecret: config.Clients[0].Secret,
					RefreshToken: token.RefreshToken,
				}), http.StatusBadRequest)
				if errResp.Error != "invalid_grant" {
					t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
				}
				if testCase.dropsSession {
					silent := newDefaultConfidentialAuthorizationRequest("persistence-grant-binding-silent")
					silent.Prompt = "none"
					expectAuthorizationErrorRedirect(t, restarted.getAuthorize(t, authorizeParams(silent)), http.StatusFound, silent.RedirectURI, silent.State, restarted.issuer, "login_required")
				}
			})
		}
	})

	t.Run("restores profile edits", func(t *testing.T) {
		config := defaultProviderConfig()
		config.EditProfile = true
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		config.Users = append(config.Users, userConfig{
			Label:         "BOB",
			Username:      "bob",
			Password:      testPassword,
			Sub:           "bob-subject",
			Name:          "Bob Example",
			Email:         "bob@example.com",
			EmailVerified: true,
		})
		provider := startProvider(t, config)
		_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("persistence-profile"))
		_ = expectRedirect(t, submitProfileForm(t, provider, fetchProfilePage(t, provider), "Alice Edited", testUsername, "alice.edited@example.com"), http.StatusSeeOther)

		config.Users[0].Name = "Alice Configured"
		config.Users[1].Name = "Bob Configured"
		restarted := restartProvider(t, provider, config)
		body := fetchProfilePage(t, restarted)
		for _, value := range []string{"Alice Edited", "alice.edited@example.com"} {
			if !strings.Contains(string(body), value) {
				t.Fatalf("expected the edited profile value %q, got body=%s", value, body)
			}
		}
		if bob, _ := restarted.idp.lookupUser("BOB"); bob.name != "Bob Configured" {
			t.Fatalf("expected the unedited profile to follow the configuration, got %q", bob.name)
		}
	})

	t.Run("restores edits that swap usernames", func(t *testing.T) {
		config := defaultProviderConfig()
		config.EditProfile = true
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		config.Users = append(config.Users, userConfig{Label: "BOB", Username: "bob", Password: testPassword})
		provider := startProvider(t, config)
		for _, step := range []struct {
			label    string
			username string
		}{
			{label: "BOB", username: "robert"},
			{label: "ALICE", username: "bob"},
			{label: "BOB", username: testUsername},
		} {
			if !provider.idp.updateUser(step.label, userEdit{Username: step.username, Name: step.label, Email: testEmail}) {
				t.Fatalf("failed to rename %s to %q", step.label, step.username)
			}
		}
		_ = fetchLoginForm(t, provider)

		restarted := restartProvider(t, provider, config)
		for label, want := range map[string]string{"ALICE": "bob", "BOB": testUsername} {
			if restoredUser, _ := restarted.idp.lookupUser(label); restoredUser.username != want {
				t.Fatalf("restored username mismatch for %s: got %q, want %q", label, restoredUser.username, want)
			}
		}
	})

	t.Run("rejects restored edits whose username is now taken", func(t *testing.T) {
		signingKey, err := testSigningKeyB64()
		if err != nil {
			t.Fatalf("failed to generate signing key: %v", err)
		}
		config := defaultProviderConfig()
		config.EditProfile = true
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("persistence-profile-taken"))
		_ = expectRedirect(t, submitProfileForm(t, provider, fetchProfilePage(t, provider), "Alice Edited", "bob", testEmail), http.StatusSeeOther)
		provider.stop(t)

		_, err = newIdentityProviderFromEnv([]string{
			"SIMPLE_IDP_ISSUER=http://127.0.0.1",
			"SIMPLE_IDP_KEY_B64=" + signingKey,
			"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
			"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
			"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
			"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
			"SIMPLE_IDP_USER_ALICE_SUB=" + testSubject,
			"SIMPLE_IDP_USER_BOB_USERNAME=bob",
			"SIMPLE_IDP_USER_BOB_PASSWORD=" + testPassword,
			"SIMPLE_IDP_STATE_FILE=" + config.StateFile,
		})
		if err == nil || !strings.Contains(err.Error(), `duplicate username "bob"`) {
			t.Fatalf("expected duplicate username error, got %v", err)
		}
	})

	t.Run("keeps the authentication methods of restored sessions", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("persistence-amr")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})

		config.Users[0].TOTPSecret = testTOTPKeyBase32
		restarted := restartProvider(t, provider, config)
		silent := newDefaultConfidentialAuthorizationRequest("persistence-amr-silent")
		silent.Prompt = "none"
		silentToken := exchangeAuthorizationCode(t, restarted, tokenRequest{
			ClientID:     silent.ClientID,
			ClientSecret: webClientSecret,
			Code:         authorize(t, restarted, silent).Code,
			RedirectURI:  silent.RedirectURI,
			CodeVerifier: silent.Verifier,
		})
		refreshed := exchangeRefreshToken(t, restarted, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})
		rotated := exchangeRefreshToken(t, restarted, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: refreshed.RefreshToken,
		})
		for _, idToken := range []string{silentToken.IDToken, refreshed.IDToken, rotated.IDToken} {
			if claims := verifyIDToken(t, restarted, idToken); !slices.Equal(claims.Amr, []string{"pwd"}) {
				t.Fatalf("amr mismatch: got %v, want %v", claims.Amr, []string{"pwd"})
			}
		}

		login := newDefaultConfidentialAuthorizationRequest("persistence-amr-login")
		login.Prompt = "login"
		body := authorizeAndLoginExpectPage(t, restarted, login)
		code := expectAuthorizationCodeRedirect(t, submitTOTPForm(t, restarted, body, currentTOTPCode()), http.StatusSeeOther, login.RedirectURI, login.State, restarted.issuer)
		loginToken := exchangeAuthorizationCode(t, restarted, tokenRequest{
			ClientID:     login.ClientID,
			ClientSecret: webClientSecret,
			Code:         code,
			RedirectURI:  login.RedirectURI,
			CodeVerifier: login.Verifier,
		})
		if claims := verifyIDToken(t, restarted, loginToken.IDToken); !slices.Equal(claims.Amr, []string{"pwd", "otp", "mfa"}) {
			t.Fatalf("amr mismatch after signing in again: got %v, want %v", claims.Amr, []string{"pwd", "otp", "mfa"})
		}
	})

	t.Run("drops state of users and clients that are no longer configured", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		otherRequest := newDefaultConfidentialAuthorizationRequest("persistence-removed-client")
		otherRequest.ClientID = otherClientID
		otherRequest.RedirectURI = otherClientRedirect
		otherToken := authorizeAndExchange(t, provider, otherRequest, tokenRequest{
			ClientID:     otherRequest.ClientID,
			ClientSecret: otherClientSecret,
			CodeVerifier: otherRequest.Verifier,
		})
		webRequest := newDefaultConfidentialAuthorizationRequest("persistence-removed-user")
		webToken := authorizeAndExchange(t, provider, webRequest, tokenRequest{
			ClientID:     webRequest.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: webRequest.Verifier,
		})

		config.Clients = slices.Delete(config.Clients, 1, 2)
		provider = restartProvider(t, provider, config)
		if resp := provider.getUserInfoResponse(t, otherToken.AccessToken); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status for a removed client mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, readBody(t, resp))
		}
		if claims := fetchUserInfo(t, provider, webToken.AccessToken); claims.Sub != testSubject {
			t.Fatalf("userinfo subject mismatch: got %q, want %q", claims.Sub, testSubject)
		}

		config.Users = []userConfig{{Label: "BOB", Username: "bob", Password: testPassword}}
		provider = restartProvider(t, provider, config)
		if resp := provider.getUserInfoResponse(t, webToken.AccessToken); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("userinfo status for a removed user mismatch: got %s, want %d; body=%s", resp.Status, http.StatusUnauthorized, readBody(t, resp))
		}
		errResp := expectJSONError(t, provider.postToken(t, tokenRequest{
			GrantType:    "refresh_token",
			ClientID:     webRequest.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: webToken.RefreshToken,
		}), http.StatusBadRequest)
		if errResp.Error != "invalid_grant" {
			t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
		}
		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/"), nil)
		if err != nil {
			t.Fatalf("failed to create profile request: %v", err)
		}
		redirect := expectRedirect(t, provider.do(t, provider.redirectless, req), http.StatusFound)
		assertRedirectTarget(t, redirect, "/login")
	})

	t.Run("restores client credentials access tokens", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		token := exchangeClientCredentials(t, provider, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: webClientSecret,
		})

		restarted := restartProvider(t, provider, config)
		if response := introspectToken(t, restarted, introspectionRequest{ClientID: webClientID, ClientSecret: webClientSecret, Token: token.AccessToken}); !response.Active {
			t.Fatalf("expected the restored access token to be active, got %#v", response)
		}
	})

	t.Run("keeps rejecting reused authentication codes after a restart", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		code := currentTOTPCode()
		_ = expectRedirect(t, submitTOTPForm(t, provider, fetchTOTPForm(t, provider), code), http.StatusSeeOther)

		browser := newProviderBrowser(t, restartProvider(t, provider, config))
		resp := submitTOTPForm(t, browser, fetchTOTPForm(t, browser), code)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Invalid authentication code") {
			t.Fatalf("expected the reused authentication code to be rejected, got %s; body=%s", resp.Status, body)
		}
	})

	t.Run("keeps detecting refresh token reuse after a restart", func(t *testing.T) {
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		request := newDefaultConfidentialAuthorizationRequest("persistence-refresh-reuse")
		token := authorizeAndExchange(t, provider, request, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			CodeVerifier: request.Verifier,
		})
		refreshed := exchangeRefreshToken(t, provider, tokenRequest{
			ClientID:     request.ClientID,
			ClientSecret: webClientSecret,
			RefreshToken: token.RefreshToken,
		})

		restarted := restartProvider(t, provider, config)
		for _, refreshToken := range []string{token.RefreshToken, refreshed.RefreshToken} {
			errResp := expectJSONError(t, restarted.postToken(t, tokenRequest{
				GrantType:    "refresh_token",
				ClientID:     request.ClientID,
				ClientSecret: webClientSecret,
				RefreshToken: refreshToken,
			}), http.StatusBadRequest)
			if errResp.Error != "invalid_grant" {
				t.Fatalf("error mismatch: got %q, want %q", errResp.Error, "invalid_grant")
			}
		}
	})

	t.Run("drops edits of users that are no longer configured", func(t *testing.T) {
		config := defaultProviderConfig()
		config.EditProfile = true
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("persistence-removed-edit"))
		_ = expectRedirect(t, submitProfileForm(t, provider, fetchProfilePage(t, provider), "Alice Edited", testUsername, testEmail), http.StatusSeeOther)

		users := config.Users
		config.Users = []userConfig{{Label: "BOB", Username: "bob", Password: testPassword}}
		provider = restartProvider(t, provider, config)
		_ = fetchLoginForm(t, provider)

		config.Users = users
		provider = restartProvider(t, provider, config)
		if alice, _ := provider.idp.lookupUser("ALICE"); alice.name != testName {
			t.Fatalf("expected the configured name after the user was removed, got %q", alice.name)
		}
	})

	t.Run("drops pending authentication steps of users without TOTP", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		config.StateFile = filepath.Join(t.TempDir(), "state.json")
		provider := startProvider(t, config)
		_ = fetchTOTPForm(t, provider)

		config.Users[0].TOTPSecret = ""
		restarted := restartProvider(t, provider, config)
		if pending := restarted.pendingTOTPCount(t); pending != 0 {
			t.Fatalf("expected no pending authentication steps, got %d", pending)
		}
	})

	t.Run("writes the state file atomically with owner-only permissions", func(t *testing.T) {
		directory := t.TempDir()
		config := defaultProviderConfig()
		config.StateFile = filepath.Join(directory, "state.json")
		if err := os.WriteFile(config.StateFile, []byte("{}"), 0o600); err != nil {
			t.Fatalf("failed to write state file: %v", err)
		}
		initial, err := os.Stat(config.StateFile)
		if err != nil {
			t.Fatalf("failed to stat state file: %v", err)
		}
		provider := startProvider(t, config)
		_ = authorizeAndLogin(t, provider, newDefaultConfidentialAuthorizationRequest("persistence-file"))

		info, err := os.Stat(config.StateFile)
		if err != nil {
			t.Fatalf("failed to stat state file: %v", err)
		}
		if os.SameFile(initial, info) {
			t.Fatal("expected the state file to be replaced instead of rewritten in place")
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("state file permissions mismatch: got %o, want %o", perm, 0o600)
		}
		if entries, err := os.ReadDir(directory); err != nil || len(entries) != 1 {
			t.Fatalf("expected only the state file in its directory, got %v: %v", entries, err)
		}
		data, err := os.ReadFile(filepath.Clean(config.StateFile))
		if err != nil {
			t.Fatalf("failed to read state file: %v", err)
		}
		if sessions, ok := decodeJSONMap(t, data)["Sessions"].(map[string]any); !ok || len(sessions) != 1 {
			t.Fatalf("expected one persisted session, got %s", data)
		}
	})

	t.Run("rejects unusable state files", func(t *testing.T) {
		signingKey, err := testSigningKeyB64()
		if err != nil {
			t.Fatalf("failed to generate signing key: %v", err)
		}
		directory := t.TempDir()
		unparsable := filepath.Join(directory, "unparsable.json")
		if err := os.WriteFile(unparsable, []byte("not JSON"), 0o600); err != nil {
			t.Fatalf("failed to write state file: %v", err)
		}
		for _, testCase := range []struct {
			name      string
			stateFile string
			want      string
		}{
			{name: "unparsable", stateFile: unparsable, want: "failed to parse state file"},
			{name: "unreadable", stateFile: directory, want: "failed to read state file"},
			{name: "unwritable", stateFile: filepath.Join(directory, "missing", "state.json"), want: "failed to write state file"},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				_, err := newIdentityProviderFromEnv([]string{
					"SIMPLE_IDP_ISSUER=http://127.0.0.1",
					"SIMPLE_IDP_KEY_B64=" + signingKey,
					"SIMPLE_IDP_CLIENT_WEB_ID=" + webClientID,
					"SIMPLE_IDP_CLIENT_WEB_SECRET=" + webClientSecret,
					"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
					"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
					"SIMPLE_IDP_STATE_FILE=" + testCase.stateFile,
				})
				if err == nil || !strings.Contains(err.Error(), testCase.want) {
					t.Fatalf("expected error containing %q, got %v", testCase.want, err)
				}
			})
		}
	})
}

func restartProvider(t *testing.T, provider *providerProcess, config providerConfig) *providerProcess {
	t.Helper()

	provider.stop(t)
	issuerURL, err := url.Parse(provider.issuer)
	if err != nil {
		t.Fatalf("failed to parse issuer URL: %v", err)
	}
	config.Listen = issuerURL.Host
	restarted := startProvider(t, config)
	restarted.copyCookiesFrom(t, provider)
	return restarted
}
