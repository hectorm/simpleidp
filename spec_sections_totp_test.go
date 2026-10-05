package simpleidp

// Reference material:
// RFC 6238: https://www.rfc-editor.org/rfc/rfc6238.txt

import (
	"crypto/sha1" // #nosec G505
	"encoding/base32"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testTOTPAlgorithmRequirements(t *testing.T) {
	t.Run("accepts base32 secrets regardless of case and padding", func(t *testing.T) {
		for secret, want := range map[string]string{
			testTOTPKeyBase32:                  testTOTPKey,
			strings.ToLower(testTOTPKeyBase32): testTOTPKey,
			"GEZDGNBVGY3TQOJQGEZDGNBVGY======": testTOTPKey[:16],
		} {
			t.Run(secret, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
					"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
					"SIMPLE_IDP_USER_ALICE_TOTP_SECRET=" + secret,
				}
				users, err := loadUsers(environ, func(name string) string {
					for _, item := range environ {
						key, value, _ := strings.Cut(item, "=")
						if key == name {
							return value
						}
					}
					return ""
				})
				if err != nil {
					t.Fatalf("expected the TOTP secret to be accepted, got %v", err)
				}
				if got := string(users["ALICE"].totpSecret); got != want {
					t.Fatalf("TOTP secret mismatch: got %q, want %q", got, want)
				}
			})
		}
	})

	t.Run("rejects invalid TOTP secrets", func(t *testing.T) {
		for _, secret := range []string{"not base32!", "JBSWY3DPEHPK3PXP"} {
			t.Run(secret, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
					"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
					"SIMPLE_IDP_USER_ALICE_TOTP_SECRET=" + secret,
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
				if err == nil || !strings.Contains(err.Error(), "TOTP secret") {
					t.Fatalf("expected invalid TOTP secret error, got %v", err)
				}
			})
		}
	})

	t.Run("rejects TOTP secrets shared by several users", func(t *testing.T) {
		longKey := strings.Repeat("k", sha1.BlockSize+1)
		longKeyDigest := sha1.Sum([]byte(longKey)) // #nosec G401
		for name, secrets := range map[string][2]string{
			"same key":        {testTOTPKeyBase32, strings.ToLower(testTOTPKeyBase32)},
			"zero-padded key": {testTOTPKeyBase32, base32.StdEncoding.EncodeToString([]byte(testTOTPKey + strings.Repeat("\x00", sha1.BlockSize-len(testTOTPKey))))},
			"hashed long key": {base32.StdEncoding.EncodeToString([]byte(longKey)), base32.StdEncoding.EncodeToString(longKeyDigest[:])},
		} {
			t.Run(name, func(t *testing.T) {
				environ := []string{
					"SIMPLE_IDP_USER_ALICE_USERNAME=" + testUsername,
					"SIMPLE_IDP_USER_ALICE_PASSWORD=" + testPassword,
					"SIMPLE_IDP_USER_ALICE_TOTP_SECRET=" + secrets[0],
					"SIMPLE_IDP_USER_BOB_USERNAME=bob",
					"SIMPLE_IDP_USER_BOB_PASSWORD=bob-password",
					"SIMPLE_IDP_USER_BOB_TOTP_SECRET=" + secrets[1],
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
				if err == nil || !strings.Contains(err.Error(), "duplicate TOTP secret") {
					t.Fatalf("expected duplicate TOTP secret error, got %v", err)
				}
			})
		}
	})
}

func testTOTPDescription(t *testing.T) {
	config := defaultProviderConfig()
	config.Users[0].TOTPSecret = testTOTPKeyBase32
	provider := startProvider(t, config)

	t.Run("advances the time step every 30 seconds from the Unix epoch", func(t *testing.T) {
		code := totpCodeAt(3)
		if _, ok := provider.validateTOTPAt(t, code, time.Unix(59, 0), 0); ok {
			t.Fatal("expected time step 3 to be two steps ahead at 59 seconds")
		}
		if step, ok := provider.validateTOTPAt(t, code, time.Unix(60, 0), 0); !ok || step != 3 {
			t.Fatalf("expected time step 3 to be accepted at 60 seconds, got step=%d ok=%t", step, ok)
		}
	})

	t.Run("supports time steps larger than 32 bits", func(t *testing.T) {
		step := int64(1)<<32 + 1
		if accepted, ok := provider.validateTOTPAt(t, totpCodeAt(step), time.Unix(step*totpPeriodSeconds, 0), 0); !ok || accepted != step {
			t.Fatalf("expected the current time step to be accepted, got step=%d ok=%t", accepted, ok)
		}
	})
}

func testTOTPGeneralSecurityConsiderations(t *testing.T) {
	invalid := "not-a-code"

	t.Run("throttles repeated invalid codes", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		body := fetchTOTPForm(t, provider)
		for range 3 {
			resp := submitTOTPForm(t, provider, body, invalid)
			body = readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("invalid authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
			}
			if !strings.Contains(string(body), "Invalid authentication code") {
				t.Fatalf("expected invalid authentication code error, got body=%s", body)
			}
		}

		resp := submitTOTPForm(t, provider, body, currentTOTPCode())
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("throttled authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Too many failed attempts") {
			t.Fatalf("expected throttled authentication error, got body=%s", body)
		}
		_ = fetchLoginForm(t, provider)
	})

	t.Run("counts invalid codes across login sessions", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		for range 3 {
			browser := newProviderBrowser(t, provider)
			body := fetchTOTPForm(t, browser)
			resp := submitTOTPForm(t, browser, body, invalid)
			body = readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("invalid authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
			}
			if !strings.Contains(string(body), "Invalid authentication code") {
				t.Fatalf("expected invalid authentication code error, got body=%s", body)
			}
		}

		body := fetchTOTPForm(t, provider)
		resp := submitTOTPForm(t, provider, body, currentTOTPCode())
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("throttled authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Too many failed attempts") {
			t.Fatalf("expected throttled authentication error, got body=%s", body)
		}
		_ = fetchLoginForm(t, provider)
	})

	t.Run("resets the count after a valid code", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		body := fetchTOTPForm(t, provider)
		for range 2 {
			resp := submitTOTPForm(t, provider, body, invalid)
			body = readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("invalid authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
			}
		}
		_ = expectRedirect(t, submitTOTPForm(t, provider, body, currentTOTPCode()), http.StatusSeeOther)

		browser := newProviderBrowser(t, provider)
		body = fetchTOTPForm(t, browser)
		for range 3 {
			resp := submitTOTPForm(t, browser, body, invalid)
			body = readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("invalid authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
			}
			if !strings.Contains(string(body), "Invalid authentication code") {
				t.Fatalf("expected invalid authentication code error, got body=%s", body)
			}
		}
	})

	t.Run("waits at most 24 hours between invalid codes", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		body := fetchTOTPForm(t, provider)
		provider.ageTOTPThrottle(t, 20, 23*time.Hour)
		resp := submitTOTPForm(t, provider, body, currentTOTPCode())
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("throttled authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Too many failed attempts") {
			t.Fatalf("expected throttled authentication error, got body=%s", body)
		}

		provider.ageTOTPThrottle(t, 20, 25*time.Hour)
		_ = expectRedirect(t, submitTOTPForm(t, provider, body, currentTOTPCode()), http.StatusSeeOther)
	})

	t.Run("keeps the failure count beyond the longest wait", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		body := fetchTOTPForm(t, provider)
		provider.ageTOTPThrottle(t, 20, 25*time.Hour)
		resp := submitTOTPForm(t, provider, body, invalid)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("invalid authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Invalid authentication code") {
			t.Fatalf("expected invalid authentication code error, got body=%s", body)
		}

		resp = submitTOTPForm(t, provider, body, currentTOTPCode())
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("throttled authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Too many failed attempts") {
			t.Fatalf("expected throttled authentication error, got body=%s", body)
		}
	})
}

func testTOTPValidationAndTimeStepSize(t *testing.T) {
	config := defaultProviderConfig()
	config.Users[0].TOTPSecret = testTOTPKeyBase32
	provider := startProvider(t, config)
	now := time.Unix(1234567890, 0)
	current := now.Unix() / totpPeriodSeconds

	t.Run("accepts codes from one time step before or after the current one", func(t *testing.T) {
		for _, offset := range []int64{-1, 0, 1} {
			if step, ok := provider.validateTOTPAt(t, totpCodeAt(current+offset), now, 0); !ok || step != current+offset {
				t.Fatalf("expected the code for time step offset %d to be accepted, got step=%d ok=%t", offset, step, ok)
			}
		}
	})

	t.Run("rejects codes from other time steps", func(t *testing.T) {
		for _, offset := range []int64{-2, 2} {
			if _, ok := provider.validateTOTPAt(t, totpCodeAt(current+offset), now, 0); ok {
				t.Fatalf("expected the code for time step offset %d to be rejected", offset)
			}
		}
	})

	t.Run("rejects codes for time steps at or before the last accepted one", func(t *testing.T) {
		if _, ok := provider.validateTOTPAt(t, totpCodeAt(current), now, current); ok {
			t.Fatal("expected the last accepted time step to be rejected")
		}
		if step, ok := provider.validateTOTPAt(t, totpCodeAt(current+1), now, current); !ok || step != current+1 {
			t.Fatalf("expected a later time step to be accepted, got step=%d ok=%t", step, ok)
		}
	})

	t.Run("rejects colliding codes throughout their validity window", func(t *testing.T) {
		const firstStep int64 = 50424280
		const code = "070562"
		if totpCodeAt(firstStep) != code || totpCodeAt(firstStep+1) != code {
			t.Fatal("unexpected adjacent collision vector")
		}
		for _, offset := range []int64{-1, 0, 1} {
			t.Run(strconv.FormatInt(offset, 10), func(t *testing.T) {
				firstNow := time.Unix((firstStep+offset)*totpPeriodSeconds, 0)
				lastStep, ok := provider.validateTOTPAt(t, code, firstNow, 0)
				if !ok {
					t.Fatal("expected the first submission to be accepted")
				}
				for replayStep := firstStep + offset; replayStep <= firstStep+2; replayStep++ {
					replayNow := time.Unix(replayStep*totpPeriodSeconds, 0)
					if _, ok := provider.validateTOTPAt(t, code, replayNow, lastStep); ok {
						t.Fatalf("replayed code accepted at time step %d", replayStep)
					}
				}
			})
		}
	})

	t.Run("rejects a colliding code after accepting a different code", func(t *testing.T) {
		const firstStep int64 = 50897033
		const code = "407517"
		const nextCode = "223464"
		if totpCodeAt(firstStep) != code || totpCodeAt(firstStep+1) != nextCode || totpCodeAt(firstStep+2) != code {
			t.Fatal("unexpected collision vector")
		}
		lastStep, ok := provider.validateTOTPAt(t, code, time.Unix((firstStep-1)*totpPeriodSeconds, 0), 0)
		if !ok {
			t.Fatal("expected the first code to be accepted")
		}
		lastStep, ok = provider.validateTOTPAt(t, nextCode, time.Unix(firstStep*totpPeriodSeconds, 0), lastStep)
		if !ok {
			t.Fatal("expected the different code to be accepted")
		}
		for replayStep := firstStep + 1; replayStep <= firstStep+3; replayStep++ {
			if _, ok := provider.validateTOTPAt(t, code, time.Unix(replayStep*totpPeriodSeconds, 0), lastStep); ok {
				t.Fatalf("expected the first code to remain rejected at time step %d", replayStep)
			}
		}
	})

	t.Run("rejects a reused authentication code", func(t *testing.T) {
		config := defaultProviderConfig()
		config.Users[0].TOTPSecret = testTOTPKeyBase32
		provider := startProvider(t, config)
		code := currentTOTPCode()
		body := fetchTOTPForm(t, provider)
		_ = expectRedirect(t, submitTOTPForm(t, provider, body, code), http.StatusSeeOther)

		browser := newProviderBrowser(t, provider)
		body = fetchTOTPForm(t, browser)
		resp := submitTOTPForm(t, browser, body, code)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("reused authentication code status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
		}
		if !strings.Contains(string(body), "Invalid authentication code") {
			t.Fatalf("expected invalid authentication code error, got body=%s", body)
		}
		_ = fetchLoginForm(t, browser)
	})
}

func testTOTPTestVectors(t *testing.T) {
	config := defaultProviderConfig()
	config.Users[0].TOTPSecret = testTOTPKeyBase32
	provider := startProvider(t, config)
	for _, vector := range []struct {
		time int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		t.Run(strconv.FormatInt(vector.time, 10), func(t *testing.T) {
			if step, ok := provider.validateTOTPAt(t, vector.code[2:], time.Unix(vector.time, 0), 0); !ok || step != vector.time/totpPeriodSeconds {
				t.Fatalf("expected the vector code to be accepted for its time step, got step=%d ok=%t", step, ok)
			}
		})
	}
}
