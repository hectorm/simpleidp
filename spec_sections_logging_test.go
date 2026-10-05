package simpleidp

// Reference material:
// Simple IdP: README.md

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func testLogging(t *testing.T) {
	t.Run("logs rejected redirect URIs without userinfo, query, or fragment", func(t *testing.T) {
		logs := captureLogs(t)
		provider := startProvider(t, defaultProviderConfig())
		params := authorizeParams(newDefaultConfidentialAuthorizationRequest("unknown-redirect-uri"))
		params.Set("redirect_uri", "https://user:uri-password@unregistered.example.com/callback?token=uri-token#uri-fragment")
		resp := provider.getAuthorize(t, params)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusBadRequest, body)
		}

		record := expectLogRecord(t, logs, "WARN", "authorization request rejected")
		if record["client_id"] != webClientID || record["redirect_uri"] != "https://unregistered.example.com/callback" {
			t.Fatalf("expected the client ID and redirect URI, got %#v", record)
		}
		for _, secret := range []string{"uri-password", "uri-token", "uri-fragment"} {
			if strings.Contains(logs.String(), secret) {
				t.Fatalf("logs contain %q from the redirect URI:\n%s", secret, logs.String())
			}
		}
	})

	t.Run("logs each sign-in step at its level", func(t *testing.T) {
		logs := captureLogs(t)
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		body := fetchLoginForm(t, provider)
		resp := submitLoginForm(t, provider, body, testUsername, "wrong-password")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		resp = submitLoginForm(t, provider, body, testUsername, testPassword)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		resp = submitTOTPForm(t, provider, body, "not-a-code")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		_ = expectRedirect(t, submitTOTPForm(t, provider, body, currentTOTPCode()), http.StatusSeeOther)

		for _, expected := range []struct {
			level   string
			message string
		}{
			{"WARN", "password rejected"},
			{"INFO", "password accepted"},
			{"DEBUG", "authentication code required"},
			{"WARN", "authentication code rejected"},
			{"INFO", "authentication code accepted"},
			{"INFO", "user signed in"},
		} {
			_ = expectLogRecord(t, logs, expected.level, expected.message)
		}
	})

	t.Run("logs throttled attempts with the remaining wait", func(t *testing.T) {
		logs := captureLogs(t)
		provider := startProvider(t, defaultProviderConfig())
		body := fetchLoginForm(t, provider)
		for range 4 {
			resp := submitLoginForm(t, provider, body, testUsername, "wrong-password")
			body = readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
			}
		}

		record := expectLogRecord(t, logs, "WARN", "password attempt throttled")
		if got, ok := record["retry_after"].(string); !ok || got == "" || record["username"] != testUsername {
			t.Fatalf("expected the username and remaining wait, got %#v", record)
		}
	})

	t.Run("logs rejected client secrets without the secret", func(t *testing.T) {
		logs := captureLogs(t)
		provider := startProvider(t, defaultProviderConfig())
		_ = expectJSONError(t, provider.postToken(t, tokenRequest{
			ClientID:     webClientID,
			ClientSecret: "wrong-client-secret",
			GrantType:    "client_credentials",
		}), http.StatusUnauthorized)

		if record := expectLogRecord(t, logs, "WARN", "client secret rejected"); record["client_id"] != webClientID {
			t.Fatalf("client ID mismatch: got %#v, want %q", record["client_id"], webClientID)
		}
		if strings.Contains(logs.String(), "wrong-client-secret") {
			t.Fatalf("logs contain the client secret:\n%s", logs.String())
		}
	})

	t.Run("logs the end of a session", func(t *testing.T) {
		logs := captureLogs(t)
		provider := startProvider(t, defaultProviderConfig())
		body := fetchLoginForm(t, provider)
		_ = expectRedirect(t, submitLoginForm(t, provider, body, testUsername, testPassword), http.StatusSeeOther)
		body = fetchLogoutForm(t, provider, url.Values{})
		resp := submitConsentForm(t, provider, body, "yes")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("logout status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}

		record := expectLogRecord(t, logs, "INFO", "session ended")
		if got, ok := record["sid"].(string); !ok || got == "" || record["label"] != "ALICE" {
			t.Fatalf("expected the user label and session ID, got %#v", record)
		}
	})

	t.Run("caps request values in log records", func(t *testing.T) {
		logs := captureLogs(t)
		provider := startProvider(t, defaultProviderConfig())
		long := strings.Repeat("x", 64<<10)

		body := fetchLoginForm(t, provider)
		resp := submitLoginForm(t, provider, body, long, "wrong-password")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status mismatch: got %s, want %d; body=%.200s", resp.Status, http.StatusOK, body)
		}

		params := authorizeParams(newDefaultConfidentialAuthorizationRequest("long-log-values"))
		params.Set("client_id", long)
		params.Set("redirect_uri", "https://unregistered.example.com/"+long)
		resp = provider.getAuthorize(t, params)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("authorize status mismatch: got %s, want %d; body=%.200s", resp.Status, http.StatusBadRequest, body)
		}

		req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{"client_id": {long}, "post_logout_redirect_uri": {"https://unregistered.example.com/"}}.Encode(), nil)
		if err != nil {
			t.Fatalf("failed to create logout request: %v", err)
		}
		resp = provider.do(t, provider.redirectless, req)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("logout status mismatch: got %s, want %d; body=%.200s", resp.Status, http.StatusBadRequest, body)
		}

		for _, expected := range []struct {
			message, attribute, value string
		}{
			{"password rejected", "username", long[:maxLogValueBytes]},
			{"authorization request rejected", "client_id", long[:maxLogValueBytes]},
			{"authorization request rejected", "redirect_uri", ("https://unregistered.example.com/" + long)[:maxLogValueBytes]},
			{"logout request rejected", "client_id", long[:maxLogValueBytes]},
		} {
			if got := expectLogRecord(t, logs, "WARN", expected.message)[expected.attribute]; got != expected.value {
				t.Fatalf("%s %s mismatch: got %.200v, want %q", expected.message, expected.attribute, got, expected.value)
			}
		}
	})

	t.Run("caps account usernames in log records", func(t *testing.T) {
		logs := captureLogs(t)
		config := defaultProviderConfig()
		config.Users[0].Username = strings.Repeat("u", 64<<10)
		provider := startProvider(t, config)
		body := fetchLoginForm(t, provider)
		_ = expectRedirect(t, submitLoginForm(t, provider, body, config.Users[0].Username, testPassword), http.StatusSeeOther)

		browser := newProviderBrowser(t, provider)
		body = fetchLoginForm(t, browser)
		for range 4 {
			resp := submitLoginForm(t, browser, body, config.Users[0].Username, "wrong-password")
			body = readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("login status mismatch: got %s, want %d; body=%.200s", resp.Status, http.StatusOK, body)
			}
		}

		for _, expected := range []struct {
			level, message string
		}{
			{"INFO", "password accepted"},
			{"WARN", "password rejected"},
			{"WARN", "password attempt throttled"},
		} {
			if got := expectLogRecord(t, logs, expected.level, expected.message)["username"]; got != config.Users[0].Username[:maxLogValueBytes] {
				t.Fatalf("%s username mismatch: got %.200v, want %d bytes", expected.message, got, maxLogValueBytes)
			}
		}
	})

	t.Run("never logs credentials", func(t *testing.T) {
		logs := captureLogs(t)
		config := defaultProviderConfig()
		config.Users[0].Password = "correct-horse-battery"
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		body := fetchLoginForm(t, provider)
		resp := submitLoginForm(t, provider, body, testUsername, "wrong-horse-battery")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		resp = submitLoginForm(t, provider, body, testUsername, "correct-horse-battery")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		invalid := "not-a-code"
		resp = submitTOTPForm(t, provider, body, invalid)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		code := currentTOTPCode()
		_ = expectRedirect(t, submitTOTPForm(t, provider, body, code), http.StatusSeeOther)

		output := logs.String()
		for _, credential := range []string{"correct-horse-battery", "wrong-horse-battery", invalid, code, testTOTPKeyBase32} {
			if strings.Contains(output, credential) {
				t.Fatalf("logs contain the credential %q:\n%s", credential, output)
			}
		}
	})
}
