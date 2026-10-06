package simpleidp

// Reference material:
// Simple IdP: README.md
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// RFC 9110: https://www.rfc-editor.org/rfc/rfc9110.txt

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func testLocalization(t *testing.T) {
	provider := startProvider(t, defaultProviderConfig())

	t.Run("defaults to English", func(t *testing.T) {
		body := fetchLocalizedPage(t, provider, provider.endpoint("/login"))
		expectPageLanguage(t, body, "en", "ltr")
		if !strings.Contains(string(body), ">Sign in</button>") {
			t.Fatalf("expected English sign-in button, got body=%s", body)
		}
	})

	t.Run("selects the language from the Accept-Language header", func(t *testing.T) {
		for _, testCase := range []struct {
			acceptLanguage string
			lang           string
			dir            string
			signIn         string
		}{
			{acceptLanguage: "ar-EG", lang: "ar", dir: "rtl", signIn: "تسجيل الدخول"},
			{acceptLanguage: "de", lang: "de", dir: "ltr", signIn: "Anmelden"},
			{acceptLanguage: "en-GB", lang: "en", dir: "ltr", signIn: "Sign in"},
			{acceptLanguage: "es-ES,es;q=0.9", lang: "es", dir: "ltr", signIn: "Iniciar sesión"},
			{acceptLanguage: "fr-CA", lang: "fr", dir: "ltr", signIn: "Se connecter"},
			{acceptLanguage: "it-IT", lang: "it", dir: "ltr", signIn: "Accedi"},
			{acceptLanguage: "ja-JP", lang: "ja", dir: "ltr", signIn: "ログイン"},
			{acceptLanguage: "ko-KR", lang: "ko", dir: "ltr", signIn: "로그인"},
			{acceptLanguage: "pt-BR", lang: "pt-BR", dir: "ltr", signIn: "Entrar"},
			{acceptLanguage: "pt-PT", lang: "pt-PT", dir: "ltr", signIn: "Iniciar sessão"},
			{acceptLanguage: "ru-RU", lang: "ru", dir: "ltr", signIn: "Войти"},
			{acceptLanguage: "zh-CN", lang: "zh-Hans", dir: "ltr", signIn: "登录"},
			{acceptLanguage: "zh-TW", lang: "zh-Hant", dir: "ltr", signIn: "登入"},
		} {
			t.Run(testCase.lang, func(t *testing.T) {
				body := fetchLocalizedPage(t, provider, provider.endpoint("/login"), testCase.acceptLanguage)
				expectPageLanguage(t, body, testCase.lang, testCase.dir)
				if !strings.Contains(string(body), ">"+testCase.signIn+"</button>") {
					t.Fatalf("expected sign-in button %q, got body=%s", testCase.signIn, body)
				}
			})
		}
	})

	t.Run("honors Accept-Language quality values", func(t *testing.T) {
		for _, testCase := range []struct {
			acceptLanguage string
			lang           string
		}{
			{acceptLanguage: "eo, de;q=0.5, fr;q=0.8", lang: "fr"},
			{acceptLanguage: "es;q=0, it;q=0.1", lang: "it"},
			{acceptLanguage: "fr;Q=0, de;q=0.9", lang: "de"},
			{acceptLanguage: "es, fr", lang: "es"},
			{acceptLanguage: "DE-at", lang: "de"},
			{acceptLanguage: "eo, *;q=0.5", lang: "en"},
			{acceptLanguage: "es;q=invalid", lang: "en"},
		} {
			t.Run(testCase.acceptLanguage, func(t *testing.T) {
				body := fetchLocalizedPage(t, provider, provider.endpoint("/login"), testCase.acceptLanguage)
				expectPageLanguage(t, body, testCase.lang, "ltr")
			})
		}
	})

	t.Run("combines repeated Accept-Language header lines", func(t *testing.T) {
		body := fetchLocalizedPage(t, provider, provider.endpoint("/login"), "de;q=0.1", "fr;q=0.9")
		expectPageLanguage(t, body, "fr", "ltr")
	})

	t.Run("matches language tags by script and region", func(t *testing.T) {
		for _, testCase := range []struct {
			acceptLanguage string
			lang           string
		}{
			{acceptLanguage: "en-Latn-US", lang: "en"},
			{acceptLanguage: "es-419", lang: "es"},
			{acceptLanguage: "zh", lang: "zh-Hans"},
			{acceptLanguage: "zh-SG", lang: "zh-Hans"},
			{acceptLanguage: "zh-Hans-HK", lang: "zh-Hans"},
			{acceptLanguage: "zh-HK", lang: "zh-Hant"},
			{acceptLanguage: "zh-MO", lang: "zh-Hant"},
			{acceptLanguage: "zh-hant-cn", lang: "zh-Hant"},
			{acceptLanguage: "zh-Latn, de;q=0.5", lang: "de"},
			{acceptLanguage: "pt", lang: "pt-BR"},
			{acceptLanguage: "pt-Latn-PT", lang: "pt-PT"},
			{acceptLanguage: "pt-AO", lang: "pt-PT"},
			{acceptLanguage: "pt-MZ, pt-BR;q=0.5", lang: "pt-PT"},
		} {
			t.Run(testCase.acceptLanguage, func(t *testing.T) {
				body := fetchLocalizedPage(t, provider, provider.endpoint("/login"), testCase.acceptLanguage)
				expectPageLanguage(t, body, testCase.lang, "ltr")
			})
		}

		params := authorizeParams(newDefaultConfidentialAuthorizationRequest("localization-ui-locales-script"))
		params.Set("ui_locales", "zh-Latn en")
		body := fetchLocalizedPage(t, provider, provider.endpoint("/authorize")+"?"+params.Encode(), "zh-CN")
		expectPageLanguage(t, body, "en", "ltr")
	})

	t.Run("prefers ui_locales over Accept-Language throughout authorization", func(t *testing.T) {
		browser := newProviderBrowser(t, provider)
		request := newDefaultConfidentialAuthorizationRequest("localization-ui-locales")
		request.Prompt = "consent"
		params := authorizeParams(request)
		params.Set("ui_locales", "eo fr-CA en")

		body := fetchLocalizedPage(t, browser, browser.endpoint("/authorize")+"?"+params.Encode(), "de")
		expectPageLanguage(t, body, "fr", "ltr")
		if !strings.Contains(string(body), ">Se connecter</button>") {
			t.Fatalf("expected French login form, got body=%s", body)
		}

		body = readBody(t, submitLoginForm(t, browser, body, testUsername, "wrong-password"))
		expectPageLanguage(t, body, "fr", "ltr")
		if want := `data-testid="error">Nom d’utilisateur ou mot de passe incorrect</p>`; !strings.Contains(string(body), want) {
			t.Fatalf("expected French login error %q, got body=%s", want, body)
		}

		resp := submitLoginForm(t, browser, body, testUsername, testPassword)
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-testid="page-consent"`) {
			t.Fatalf("expected consent form, got %s; body=%s", resp.Status, body)
		}
		expectPageLanguage(t, body, "fr", "ltr")
		if want := `data-testid="message">Autoriser ` + isolateText(webClientID) + " à accéder à ces étendues\u00a0: " + isolateText(request.Scope) + "\u00a0?</p>"; !strings.Contains(string(body), want) {
			t.Fatalf("expected French consent message %q, got body=%s", want, body)
		}
	})

	t.Run("falls back to Accept-Language when ui_locales has no supported language", func(t *testing.T) {
		params := authorizeParams(newDefaultConfidentialAuthorizationRequest("localization-ui-locales-fallback"))
		params.Set("ui_locales", "eo nl")
		body := fetchLocalizedPage(t, provider, provider.endpoint("/authorize")+"?"+params.Encode(), "it")
		expectPageLanguage(t, body, "it", "ltr")
	})

	t.Run("ignores ui_locales outside authorization and logout requests", func(t *testing.T) {
		browser := newProviderBrowser(t, provider)
		body := fetchLocalizedPage(t, browser, browser.endpoint("/login")+"?ui_locales=fr", "de")
		expectPageLanguage(t, body, "de", "ltr")

		_ = authorizeAndLogin(t, browser, newDefaultConfidentialAuthorizationRequest("localization-profile-ui-locales"))
		body = fetchLocalizedPage(t, browser, browser.endpoint("")+"?ui_locales=fr", "ru")
		expectPageLanguage(t, body, "ru", "ltr")
	})

	t.Run("localizes the profile and logout pages", func(t *testing.T) {
		browser := newProviderBrowser(t, provider)
		_ = authorizeAndLogin(t, browser, newDefaultConfidentialAuthorizationRequest("localization-profile"))

		body := fetchLocalizedPage(t, browser, browser.endpoint(""), "ru")
		expectPageLanguage(t, body, "ru", "ltr")
		if !strings.Contains(string(body), "<dt>Имя пользователя</dt>") || !strings.Contains(string(body), ">Выйти</button>") {
			t.Fatalf("expected Russian profile page, got body=%s", body)
		}

		body = fetchLogoutForm(t, browser, url.Values{"ui_locales": {"ar"}})
		expectPageLanguage(t, body, "ar", "rtl")
		resp := submitConsentForm(t, browser, body, "yes")
		body = readBody(t, resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-testid="page-logout-complete"`) {
			t.Fatalf("expected logout completion page, got %s; body=%s", resp.Status, body)
		}
		expectPageLanguage(t, body, "ar", "rtl")
		if want := `data-testid="message">تم تسجيل خروجك.</p>`; !strings.Contains(string(body), want) {
			t.Fatalf("expected Arabic logout message %q, got body=%s", want, body)
		}
	})

	t.Run("uses the configured language for every request", func(t *testing.T) {
		for _, testCase := range []struct {
			language string
			lang     string
			dir      string
		}{
			{language: "ar-EG", lang: "ar", dir: "rtl"},
			{language: "es", lang: "es", dir: "ltr"},
			{language: "zh", lang: "zh-Hans", dir: "ltr"},
			{language: "zh-TW", lang: "zh-Hant", dir: "ltr"},
			{language: "pt-PT", lang: "pt-PT", dir: "ltr"},
		} {
			t.Run(testCase.language, func(t *testing.T) {
				config := defaultProviderConfig()
				config.Language = testCase.language
				provider := startProvider(t, config)

				body := fetchLocalizedPage(t, provider, provider.endpoint("/login"), "de")
				expectPageLanguage(t, body, testCase.lang, testCase.dir)

				params := authorizeParams(newDefaultConfidentialAuthorizationRequest("localization-configured"))
				params.Set("ui_locales", "fr")
				body = fetchLocalizedPage(t, provider, provider.endpoint("/authorize")+"?"+params.Encode(), "de")
				expectPageLanguage(t, body, testCase.lang, testCase.dir)

				if got := fetchDiscovery(t, provider).UILocalesSupported; !slices.Equal(got, []string{testCase.lang}) {
					t.Fatalf("unexpected supported UI locales: %#v", got)
				}
			})
		}
	})

	t.Run("rejects unsupported configured languages", func(t *testing.T) {
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
		for _, value := range []string{"eo", "zh-Latn"} {
			t.Run(value, func(t *testing.T) {
				_, err := newIdentityProviderFromEnv(append(slices.Clone(environ), "SIMPLE_IDP_LANGUAGE="+value))
				if want := "SIMPLE_IDP_LANGUAGE: must be one of ar, de, en, es, fr, it, ja, ko, pt-BR, pt-PT, ru, zh-Hans, zh-Hant"; err == nil || err.Error() != want {
					t.Fatalf("expected unsupported language error %q, got %v", want, err)
				}
			})
		}
	})

	t.Run("formats the consent request in every language", func(t *testing.T) {
		browser := newProviderBrowser(t, provider)
		_ = authorizeAndLogin(t, browser, newDefaultConfidentialAuthorizationRequest("localization-consent"))
		for _, lang := range languages {
			t.Run(lang.tag, func(t *testing.T) {
				request := newDefaultConfidentialAuthorizationRequest("localization-consent-" + lang.tag)
				request.Prompt = "consent"
				params := authorizeParams(request)
				params.Set("ui_locales", lang.tag)
				body := fetchLocalizedPage(t, browser, browser.endpoint("/authorize")+"?"+params.Encode())
				expectPageLanguage(t, body, lang.tag, lang.dir)
				message := extractMessage(t, body)
				if !strings.Contains(message, isolateText(webClientID)) || !strings.Contains(message, isolateText(request.Scope)) || strings.Contains(message, "%!") {
					t.Fatalf("expected the consent message to include the isolated client ID and scope, got %q", message)
				}
			})
		}
	})

	t.Run("isolates embedded values from the page direction", func(t *testing.T) {
		browser := newProviderBrowser(t, provider)
		_ = authorizeAndLogin(t, browser, newDefaultConfidentialAuthorizationRequest("localization-isolation"))
		request := newDefaultConfidentialAuthorizationRequest("localization-isolation-consent")
		request.Prompt = "consent"
		params := authorizeParams(request)
		params.Set("ui_locales", "ar")
		body := fetchLocalizedPage(t, browser, browser.endpoint("/authorize")+"?"+params.Encode())
		expectPageLanguage(t, body, "ar", "rtl")
		for _, want := range []string{
			`<h1 id="page-title" dir="auto" data-testid="page-title">`,
			"\u2068" + webClientID + "\u2069",
			"\u2068" + request.Scope + "\u2069",
			"<dd><bdi>" + request.RedirectURI + "</bdi></dd>",
		} {
			if !strings.Contains(string(body), want) {
				t.Fatalf("expected %q in the consent page, got body=%s", want, body)
			}
		}
	})

	t.Run("translates every message into every language", func(t *testing.T) {
		english, _ := resolveLanguage(languages, "en")
		for _, lang := range languages {
			t.Run(lang.tag, func(t *testing.T) {
				if len(lang.messages) != len(english.messages) {
					t.Fatalf("message count mismatch: got %d, want %d", len(lang.messages), len(english.messages))
				}
				for id, text := range english.messages {
					translated := lang.messages[id]
					if strings.TrimSpace(translated) == "" {
						t.Fatalf("missing translation of %q", text)
					}
					if strings.Count(translated, "%") != strings.Count(text, "%") {
						t.Fatalf("formatting verbs mismatch: %q translated as %q", text, translated)
					}
				}
			})
		}
	})
}

func fetchLocalizedPage(t *testing.T, provider *providerProcess, target string, acceptLanguages ...string) []byte {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	for _, acceptLanguage := range acceptLanguages {
		req.Header.Add("Accept-Language", acceptLanguage)
	}
	resp := provider.do(t, provider.redirectless, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if got := resp.Header.Get("Vary"); !strings.Contains(got, "Accept-Language") {
		t.Fatalf("expected the response to vary on Accept-Language, got %q", got)
	}
	return body
}

func extractMessage(t *testing.T, body []byte) string {
	t.Helper()

	matches := regexp.MustCompile(`<p id="form-description" data-testid="message">(.*?)</p>`).FindSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("failed to extract message from body:\n%s", body)
	}
	return html.UnescapeString(string(matches[1]))
}
