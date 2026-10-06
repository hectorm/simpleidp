package simpleidp

// Reference material:
// OpenID Connect specifications index: https://openid.net/developers/specs/
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// OIDC Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
// OIDC RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt
// RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.txt

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type providerProcess struct {
	issuer       string
	idp          *identityProvider
	server       *http.Server
	serveDone    chan struct{}
	serveErrMu   sync.Mutex
	serveErr     error
	redirectless *http.Client
	http         *http.Client
}

var testSigningKeyB64 = sync.OnceValues(func() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
})

func startProvider(t *testing.T, config providerConfig) *providerProcess {
	t.Helper()

	signingKey, err := testSigningKeyB64()
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open listener: %v", err)
	}
	listenAddr := listener.Addr().String()
	issuer := "http://" + listenAddr
	if config.IssuerPath != "" {
		issuerPath := config.IssuerPath
		if !strings.HasPrefix(issuerPath, "/") {
			issuerPath = "/" + issuerPath
		}
		issuer += issuerPath
	}

	env := []string{
		"SIMPLE_IDP_LISTEN=" + listenAddr,
		"SIMPLE_IDP_ISSUER=" + issuer,
		"SIMPLE_IDP_TITLE=" + testTitle,
		"SIMPLE_IDP_KEY_B64=" + signingKey,
	}
	if config.EditProfile {
		env = append(env, "SIMPLE_IDP_EDIT_PROFILE=true")
	}
	if config.Logo != "" {
		env = append(env, "SIMPLE_IDP_LOGO="+config.Logo)
	}
	if config.Favicon != "" {
		env = append(env, "SIMPLE_IDP_FAVICON="+config.Favicon)
	}
	if config.AccentColor != "" {
		env = append(env, "SIMPLE_IDP_ACCENT_COLOR="+config.AccentColor)
	}
	if config.ColorScheme != "" {
		env = append(env, "SIMPLE_IDP_COLOR_SCHEME="+config.ColorScheme)
	}
	if config.Language != "" {
		env = append(env, "SIMPLE_IDP_LANGUAGE="+config.Language)
	}
	if config.AccessTokenTTL != 0 {
		env = append(env, "SIMPLE_IDP_ACCESS_TOKEN_TTL="+config.AccessTokenTTL.String())
	}
	if config.KeyID != "" {
		env = append(env, "SIMPLE_IDP_KEY_ID="+config.KeyID)
	}
	for _, client := range config.Clients {
		prefix := "SIMPLE_IDP_CLIENT_" + client.Label + "_"
		env = append(env,
			prefix+"ID="+client.ID,
			prefix+"REDIRECT_URL="+client.RedirectURL,
		)
		if client.Secret != "" {
			env = append(env, prefix+"SECRET="+client.Secret)
		}
		if client.Audience != "" {
			env = append(env, prefix+"AUDIENCE="+client.Audience)
		}
		if client.PostLogoutRedirectURL != "" {
			env = append(env, prefix+"POST_LOGOUT_REDIRECT_URL="+client.PostLogoutRedirectURL)
		}
		if client.BackchannelLogoutURI != "" {
			env = append(env, prefix+"BACKCHANNEL_LOGOUT_URI="+client.BackchannelLogoutURI)
		}
		if client.BackchannelLogoutSessionRequired {
			env = append(env, prefix+"BACKCHANNEL_LOGOUT_SESSION_REQUIRED=true")
		}
	}
	for _, user := range config.Users {
		prefix := "SIMPLE_IDP_USER_" + user.Label + "_"
		env = append(env,
			prefix+"USERNAME="+user.Username,
			prefix+"PASSWORD="+user.Password,
			prefix+"SUB="+user.Sub,
			prefix+"NAME="+user.Name,
			prefix+"EMAIL="+user.Email,
			prefix+"EMAIL_VERIFIED="+strconv.FormatBool(user.EmailVerified),
		)
		if user.TOTPSecret != "" {
			env = append(env, prefix+"TOTP_SECRET="+user.TOTPSecret)
		}
		if user.PreferredUsername != "" {
			env = append(env, prefix+"PREFERRED_USERNAME="+user.PreferredUsername)
		}
		if user.Profile != "" {
			env = append(env, prefix+"PROFILE="+user.Profile)
		}
		if user.Picture != "" {
			env = append(env, prefix+"PICTURE="+user.Picture)
		}
		if user.Locale != "" {
			env = append(env, prefix+"LOCALE="+user.Locale)
		}
		if len(user.Groups) > 0 {
			env = append(env, prefix+"GROUPS="+strings.Join(user.Groups, ","))
		}
		if len(user.Roles) > 0 {
			env = append(env, prefix+"ROLES="+strings.Join(user.Roles, ","))
		}
	}

	envMap := make(map[string]string, len(env))
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			envMap[key] = value
		}
	}

	listen, idp, err := newIdentityProvider(env, func(name string) string {
		return envMap[name]
	}, os.ReadFile)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("failed to create provider: %v", err)
	}
	srv := newServer(listen, idp)
	jar, err := cookiejar.New(nil)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("failed to create cookie jar: %v", err)
	}

	provider := &providerProcess{
		issuer:       strings.TrimRight(issuer, "/"),
		idp:          idp,
		server:       srv,
		serveDone:    make(chan struct{}),
		redirectless: newHTTPClient(false, jar),
		http:         newHTTPClient(true, jar),
	}

	go func() {
		err := srv.Serve(listener)
		provider.serveErrMu.Lock()
		provider.serveErr = err
		provider.serveErrMu.Unlock()
		close(provider.serveDone)
	}()

	t.Cleanup(func() {
		provider.stop(t)
	})
	waitForProviderReady(t, provider)

	return provider
}

func newIdentityProviderFromEnv(environ []string) (*identityProvider, error) {
	_, idp, err := newIdentityProvider(environ, func(name string) string {
		for _, item := range environ {
			key, value, _ := strings.Cut(item, "=")
			if key == name {
				return value
			}
		}
		return ""
	}, os.ReadFile)
	return idp, err
}

func waitForProviderReady(t *testing.T, provider *providerProcess) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var lastErr error

	for time.Now().Before(deadline) {
		select {
		case <-provider.serveDone:
			t.Fatalf("provider exited before it became ready: %v", provider.serveError())
		default:
		}

		resp, err := provider.http.Get(provider.endpoint("/.well-known/openid-configuration"))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("unexpected discovery status %s", resp.Status)
		} else {
			lastErr = err
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("provider did not become ready: %v", lastErr)
}

func (p *providerProcess) stop(t *testing.T) {
	t.Helper()

	p.http.CloseIdleConnections()
	p.redirectless.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("failed to stop provider: %v", err)
	}

	select {
	case <-p.serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for provider to stop")
	}

	if err := p.serveError(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("provider exited with error: %v", err)
	}
}

func (p *providerProcess) serveError() error {
	p.serveErrMu.Lock()
	defer p.serveErrMu.Unlock()
	return p.serveErr
}

func (p *providerProcess) endpoint(path string) string {
	return p.issuer + path
}

func (p *providerProcess) getAuthorize(t *testing.T, params url.Values) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, p.endpoint("/authorize")+"?"+params.Encode(), nil)
	if err != nil {
		t.Fatalf("failed to create authorize request: %v", err)
	}
	return p.do(t, p.redirectless, req)
}

func (p *providerProcess) postAuthorize(t *testing.T, params, body url.Values) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, p.endpoint("/authorize")+"?"+params.Encode(), strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatalf("failed to create authorize POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return p.do(t, p.redirectless, req)
}

func (p *providerProcess) postToken(t *testing.T, request tokenRequest) *http.Response {
	t.Helper()

	grantType := request.GrantType
	if grantType == "" {
		grantType = "authorization_code"
	}
	form := url.Values{
		"grant_type": {grantType},
	}
	if request.Code != "" {
		form.Set("code", request.Code)
	}
	if request.RefreshToken != "" {
		form.Set("refresh_token", request.RefreshToken)
	}
	if request.Scope != "" {
		form.Set("scope", request.Scope)
	}
	if request.ClientID != "" && (request.ClientSecret == "" || request.AuthMethod == authMethodClientSecretPost) {
		form.Set("client_id", request.ClientID)
	}
	if request.RedirectURI != "" {
		form.Set("redirect_uri", request.RedirectURI)
	}
	if request.CodeVerifier != "" {
		form.Set("code_verifier", request.CodeVerifier)
	}
	if request.ClientSecret != "" && request.AuthMethod == authMethodClientSecretPost {
		form.Set("client_secret", request.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, p.endpoint("/token"), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if request.ClientSecret != "" && request.AuthMethod != authMethodClientSecretPost {
		req.SetBasicAuth(url.QueryEscape(request.ClientID), url.QueryEscape(request.ClientSecret))
	}
	return p.do(t, p.redirectless, req)
}

func (p *providerProcess) postIntrospect(t *testing.T, request introspectionRequest) *http.Response {
	t.Helper()

	form := url.Values{}
	if request.Token != "" {
		form.Set("token", request.Token)
	}
	if request.TokenTypeHint != "" {
		form.Set("token_type_hint", request.TokenTypeHint)
	}
	if request.ClientID != "" && (request.ClientSecret == "" || request.AuthMethod == authMethodClientSecretPost) {
		form.Set("client_id", request.ClientID)
	}
	if request.ClientSecret != "" && request.AuthMethod == authMethodClientSecretPost {
		form.Set("client_secret", request.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, p.endpoint("/introspect"), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to create introspection request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if request.ClientSecret != "" && request.AuthMethod != authMethodClientSecretPost {
		req.SetBasicAuth(url.QueryEscape(request.ClientID), url.QueryEscape(request.ClientSecret))
	}
	return p.do(t, p.redirectless, req)
}

func (p *providerProcess) getUserInfoResponse(t *testing.T, accessToken string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, p.endpoint("/userinfo"), nil)
	if err != nil {
		t.Fatalf("failed to create userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return p.do(t, p.redirectless, req)
}

func (p *providerProcess) postUserInfo(t *testing.T, form url.Values, authorization string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, p.endpoint("/userinfo"), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to create userinfo POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return p.do(t, p.redirectless, req)
}

func (p *providerProcess) postFormURL(t *testing.T, target string, form url.Values, authorization string, followRedirects bool) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to create form POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	client := p.redirectless
	if followRedirects {
		client = p.http
	}
	return p.do(t, client, req)
}

func (p *providerProcess) postCrossSite(t *testing.T, target string, form url.Values) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to create cross-site POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Close = true
	return p.do(t, newHTTPClient(false, nil), req)
}

func (p *providerProcess) do(t *testing.T, client *http.Client, req *http.Request) *http.Response {
	t.Helper()

	resp, err := client.Do(req) // #nosec G704
	if err != nil {
		select {
		case <-p.serveDone:
			t.Fatalf("%s %s failed: %v (server error: %v)", req.Method, req.URL.String(), err, p.serveError())
		default:
			t.Fatalf("%s %s failed: %v", req.Method, req.URL.String(), err)
		}
	}
	return resp
}

func newHTTPClient(followRedirects bool, jar http.CookieJar) *http.Client {
	client := &http.Client{Timeout: 5 * time.Second, Jar: jar}
	if !followRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func newProviderBrowser(t *testing.T, provider *providerProcess) *providerProcess {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("failed to create browser cookie jar: %v", err)
	}
	browser := &providerProcess{
		issuer:       provider.issuer,
		idp:          provider.idp,
		redirectless: newHTTPClient(false, jar),
		http:         newHTTPClient(true, jar),
	}
	t.Cleanup(func() {
		browser.http.CloseIdleConnections()
		browser.redirectless.CloseIdleConnections()
	})
	return browser
}

func (p *providerProcess) copyCookiesFrom(t *testing.T, other *providerProcess) {
	t.Helper()

	issuerURL, err := url.Parse(p.endpoint("/"))
	if err != nil {
		t.Fatalf("failed to parse issuer URL: %v", err)
	}
	p.http.Jar.SetCookies(issuerURL, other.http.Jar.Cookies(issuerURL))
}

func fetchDiscovery(t *testing.T, provider *providerProcess) discoveryDocument {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/.well-known/openid-configuration"), nil)
	if err != nil {
		t.Fatalf("failed to create discovery request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	var document discoveryDocument
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("failed to decode discovery response: %v\nbody=%s", err, body)
	}
	return document
}

func requireInteractiveLogin(request authorizationRequest) authorizationRequest {
	for promptValue := range strings.FieldsSeq(request.Prompt) {
		if promptValue == "login" || promptValue == "select_account" || promptValue == "none" {
			return request
		}
	}
	if request.Prompt == "" {
		request.Prompt = "login"
	} else {
		request.Prompt += " login"
	}
	return request
}

func authorizeAndLogin(t *testing.T, provider *providerProcess, request authorizationRequest) authorizationResult {
	t.Helper()

	request = requireInteractiveLogin(request)
	params := authorizeParams(request)
	resp := provider.getAuthorize(t, params)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if !strings.Contains(string(body), "Sign in") || !strings.Contains(string(body), `name="username"`) {
		t.Fatalf("authorize page did not render login form:\n%s", body)
	}
	csrfToken := extractHiddenInputValue(t, body, "csrf_token")

	resp = provider.postAuthorize(t, params, url.Values{
		"username":   {testUsername},
		"password":   {testPassword},
		"csrf_token": {csrfToken},
	})

	code := expectAuthorizationCodeRedirect(t, resp, http.StatusSeeOther, request.RedirectURI, request.State, provider.issuer)
	return authorizationResult{
		Code:   code,
		State:  request.State,
		Issuer: provider.issuer,
	}
}

func authorizeAndLoginExpectPage(t *testing.T, provider *providerProcess, request authorizationRequest) []byte {
	t.Helper()

	request = requireInteractiveLogin(request)
	params := authorizeParams(request)
	resp := provider.getAuthorize(t, params)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if !strings.Contains(string(body), "Sign in") || !strings.Contains(string(body), `name="username"`) {
		t.Fatalf("authorize page did not render login form:\n%s", body)
	}
	csrfToken := extractHiddenInputValue(t, body, "csrf_token")

	resp = provider.postAuthorize(t, params, url.Values{
		"username":   {testUsername},
		"password":   {testPassword},
		"csrf_token": {csrfToken},
	})
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-login status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	return body
}

func authorize(t *testing.T, provider *providerProcess, request authorizationRequest) authorizationResult {
	t.Helper()

	params := authorizeParams(request)
	resp := provider.getAuthorize(t, params)

	for range 3 {
		switch resp.StatusCode {
		case http.StatusFound, http.StatusSeeOther:
			code := expectAuthorizationCodeRedirect(t, resp, resp.StatusCode, request.RedirectURI, request.State, provider.issuer)
			return authorizationResult{
				Code:   code,
				State:  request.State,
				Issuer: provider.issuer,
			}
		case http.StatusOK:
		default:
			body := readBody(t, resp)
			t.Fatalf("authorize status mismatch: got %s, want %d or redirect; body=%s", resp.Status, http.StatusOK, body)
		}

		body := readBody(t, resp)
		switch {
		case strings.Contains(string(body), "Sign in") && strings.Contains(string(body), `name="username"`):
			resp = submitLoginForm(t, provider, body, testUsername, testPassword)
		case strings.Contains(string(body), "Allow") && strings.Contains(string(body), `name="confirm"`):
			resp = submitConsentForm(t, provider, body, "yes")
		default:
			t.Fatalf("authorize flow did not render a supported interaction page:\n%s", body)
		}
	}

	t.Fatal("authorize flow did not complete after expected interaction steps")
	return authorizationResult{}
}

func authorizeAndExchange(t *testing.T, provider *providerProcess, authRequest authorizationRequest, tokenRequest tokenRequest) tokenResponse {
	t.Helper()

	authorization := authorize(t, provider, authRequest)
	if tokenRequest.Code == "" {
		tokenRequest.Code = authorization.Code
	}
	if tokenRequest.ClientID == "" {
		tokenRequest.ClientID = authRequest.ClientID
	}
	if tokenRequest.RedirectURI == "" {
		tokenRequest.RedirectURI = authRequest.RedirectURI
	}
	return exchangeAuthorizationCode(t, provider, tokenRequest)
}

func authorizeParams(request authorizationRequest) url.Values {
	params := url.Values{
		"client_id":             {request.ClientID},
		"redirect_uri":          {request.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {request.Scope},
		"code_challenge":        {pkceChallenge(request.Verifier)},
		"code_challenge_method": {"S256"},
	}
	if request.State != "" {
		params.Set("state", request.State)
	}
	if request.Nonce != "" {
		params.Set("nonce", request.Nonce)
	}
	if request.Prompt != "" {
		params.Set("prompt", request.Prompt)
	}
	return params
}

func exchangeAuthorizationCode(t *testing.T, provider *providerProcess, request tokenRequest) tokenResponse {
	t.Helper()

	resp := provider.postToken(t, request)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	assertTokenResponseHeaders(t, resp)

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("failed to decode token response: %v\nbody=%s", err, body)
	}
	return token
}

func exchangeRefreshToken(t *testing.T, provider *providerProcess, request tokenRequest) tokenResponse {
	t.Helper()

	request.GrantType = "refresh_token"
	resp := provider.postToken(t, request)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	assertTokenResponseHeaders(t, resp)

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("failed to decode token response: %v\nbody=%s", err, body)
	}
	return token
}

func exchangeClientCredentials(t *testing.T, provider *providerProcess, request tokenRequest) tokenResponse {
	t.Helper()

	request.GrantType = "client_credentials"
	resp := provider.postToken(t, request)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	assertTokenResponseHeaders(t, resp)

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatalf("failed to decode token response: %v\nbody=%s", err, body)
	}
	return token
}

func verifyIDToken(t *testing.T, provider *providerProcess, idToken string) idTokenClaims {
	t.Helper()

	jwks := fetchJWKS(t, provider)
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected a single jwk, got %#v", jwks.Keys)
	}
	header := decodeJWTHeader(t, idToken)
	if header.Alg != "RS256" {
		t.Fatalf("signing algorithm mismatch: got %q, want %q", header.Alg, "RS256")
	}
	if header.Kid == "" || header.Kid != jwks.Keys[0].KeyID {
		t.Fatalf("kid mismatch: got %q, want %q", header.Kid, jwks.Keys[0].KeyID)
	}
	publicKey := rsaPublicKeyFromJWK(t, jwks.Keys[0])

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid id token format: %q", idToken)
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode id token signature: %v", err)
	}

	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("failed to verify id token signature: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode id token payload: %v", err)
	}

	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to decode id token claims: %v\npayload=%s", err, payload)
	}
	return claims
}

func verifyAccessToken(t *testing.T, provider *providerProcess, accessToken string) accessTokenClaims {
	t.Helper()

	jwks := fetchJWKS(t, provider)
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected a single jwk, got %#v", jwks.Keys)
	}
	header := decodeJWTHeader(t, accessToken)
	if header.Alg != "RS256" {
		t.Fatalf("signing algorithm mismatch: got %q, want %q", header.Alg, "RS256")
	}
	if header.Kid == "" || header.Kid != jwks.Keys[0].KeyID {
		t.Fatalf("kid mismatch: got %q, want %q", header.Kid, jwks.Keys[0].KeyID)
	}
	publicKey := rsaPublicKeyFromJWK(t, jwks.Keys[0])

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid access token format: %q", accessToken)
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode access token signature: %v", err)
	}

	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("failed to verify access token signature: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode access token payload: %v", err)
	}

	var claims accessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to decode access token claims: %v\npayload=%s", err, payload)
	}
	return claims
}

func fetchJWKS(t *testing.T, provider *providerProcess) jwksDocument {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/jwks"), nil)
	if err != nil {
		t.Fatalf("failed to create jwks request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	var rawDocument struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &rawDocument); err != nil {
		t.Fatalf("failed to decode jwks response: %v\nbody=%s", err, body)
	}
	for _, key := range rawDocument.Keys {
		for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, present := key[name]; present {
				t.Fatalf("jwks must not contain private or symmetric key member %q", name)
			}
		}
	}

	var document jwksDocument
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("failed to decode jwks response: %v\nbody=%s", err, body)
	}
	return document
}

func rsaPublicKeyFromJWK(t *testing.T, key jwk) *rsa.PublicKey {
	t.Helper()

	if key.KeyType != "RSA" || key.Alg != "RS256" || key.Use != "sig" {
		t.Fatalf("unexpected jwk: %#v", key)
	}

	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		t.Fatalf("failed to decode jwk modulus: %v", err)
	}
	exponent, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		t.Fatalf("failed to decode jwk exponent: %v", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(new(big.Int).SetBytes(exponent).Int64()),
	}
}

func fetchUserInfo(t *testing.T, provider *providerProcess, accessToken string) userInfoClaims {
	t.Helper()

	resp := provider.getUserInfoResponse(t, accessToken)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	var claims userInfoClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("failed to decode userinfo response: %v\nbody=%s", err, body)
	}
	return claims
}

func introspectToken(t *testing.T, provider *providerProcess, request introspectionRequest) introspectionResponse {
	t.Helper()

	resp := provider.postIntrospect(t, request)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspection status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	var result introspectionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to decode introspection response: %v\nbody=%s", err, body)
	}
	return result
}

func (p *providerProcess) pendingTOTPCount(t *testing.T) int {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()
	return len(p.idp.pendingTOTPs)
}

func (p *providerProcess) expirePendingTOTPs(t *testing.T) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()
	for preAuthID, pending := range p.idp.pendingTOTPs {
		pending.createdAt = time.Now().Add(-loginActionTTL - time.Second)
		p.idp.pendingTOTPs[preAuthID] = pending
	}
}

func (p *providerProcess) validateTOTPAt(t *testing.T, code string, now time.Time, lastStep int64) (int64, bool) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()
	p.idp.lastTOTPSteps["ALICE"] = lastStep
	if !p.idp.validateTOTP("ALICE", code, now) {
		return 0, false
	}
	return p.idp.lastTOTPSteps["ALICE"], true
}

func (p *providerProcess) isThrottledAt(t *testing.T, now time.Time, failures int, lastFailure time.Time, maxDelay time.Duration) bool {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()
	p.idp.throttles["throttle-test"] = throttle{failures: failures, lastFailure: lastFailure}
	return p.idp.throttleWait("throttle-test", maxDelay, now) > 0
}

func (p *providerProcess) agePasswordThrottle(t *testing.T, failures int, age time.Duration) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()
	p.idp.throttles["password:ALICE"] = throttle{failures: failures, lastFailure: time.Now().Add(-age)}
}

func (p *providerProcess) ageTOTPThrottle(t *testing.T, failures int, age time.Duration) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()
	p.idp.throttles["totp:ALICE"] = throttle{failures: failures, lastFailure: time.Now().Add(-age)}
}

func (p *providerProcess) currentSessionCookie(t *testing.T) *http.Cookie {
	t.Helper()

	issuerURL, err := url.Parse(p.endpoint("/"))
	if err != nil {
		t.Fatalf("failed to parse issuer URL: %v", err)
	}
	for _, cookie := range p.http.Jar.Cookies(issuerURL) {
		if cookie.Name == p.idp.cookieName(sessionCookieBaseName) {
			return cookie
		}
	}
	t.Fatalf("session cookie %q not found", p.idp.cookieName(sessionCookieBaseName))
	return nil
}

func (p *providerProcess) currentSessionID(t *testing.T) string {
	t.Helper()
	return p.idp.sessionIDFromCookie(p.currentSessionCookie(t).Value)
}

func (p *providerProcess) expireSessionMax(t *testing.T) {
	t.Helper()
	p.ageSession(t, p.idp.sessionMaxTTL+time.Minute, 0)
}

func (p *providerProcess) expireSessionIdle(t *testing.T) {
	t.Helper()
	p.ageSession(t, p.idp.sessionIdleTTL+time.Minute, p.idp.sessionIdleTTL+time.Minute)
}

func (p *providerProcess) ageSession(t *testing.T, authenticatedAge, idleAge time.Duration) time.Time {
	t.Helper()

	sessionID := p.currentSessionID(t)

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()

	currentSession, ok := p.idp.sessions[sessionID]
	if !ok {
		t.Fatalf("session %q not found", sessionID)
	}
	now := time.Now()
	currentSession.authenticatedAt = now.Add(-authenticatedAge)
	currentSession.lastSeenAt = now.Add(-idleAge)
	p.idp.sessions[sessionID] = currentSession
	return currentSession.authenticatedAt
}

func (p *providerProcess) expireAuthorizationCode(t *testing.T, code string) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()

	pending, ok := p.idp.pendingCodes[code]
	if !ok {
		t.Fatalf("authorization code %q not found", code)
	}
	pending.createdAt = time.Now().Add(-10 * time.Minute)
	p.idp.pendingCodes[code] = pending
}

func (p *providerProcess) ageConsumedAuthorizationCode(t *testing.T, code string, age time.Duration) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()

	pending, ok := p.idp.pendingCodes[code]
	if !ok || pending.consumedAt.IsZero() {
		t.Fatalf("consumed authorization code %q not found", code)
	}
	pending.consumedAt = time.Now().Add(-age)
	pending.createdAt = pending.consumedAt
	p.idp.pendingCodes[code] = pending
}

func (p *providerProcess) accessTokenExpiry(t *testing.T, token string) time.Time {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()

	accessToken, ok := p.idp.accessTokens[token]
	if !ok {
		t.Fatalf("access token %q not found", token)
	}
	return accessToken.expiry
}

func (p *providerProcess) assertRefreshTokenIssueTime(t *testing.T, token string, earliest, latest time.Time) {
	t.Helper()

	p.idp.mu.Lock()
	stored, ok := p.idp.refreshTokens[token]
	p.idp.mu.Unlock()
	if !ok {
		t.Fatal("issued refresh token was not stored")
	}
	if stored.createdAt.Before(earliest) || stored.createdAt.After(latest) {
		t.Fatalf("refresh token issue time %s is outside exchange interval [%s, %s]", stored.createdAt, earliest, latest)
	}
}

func (p *providerProcess) expireAccessToken(t *testing.T, token string) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()

	accessToken, ok := p.idp.accessTokens[token]
	if !ok {
		t.Fatalf("access token %q not found", token)
	}
	accessToken.expiry = time.Now().Add(-time.Minute)
	p.idp.accessTokens[token] = accessToken
}

func (p *providerProcess) expireRefreshTokenMax(t *testing.T, refreshTokenValue string) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()

	storedRefreshToken, ok := p.idp.refreshTokens[refreshTokenValue]
	if !ok {
		t.Fatalf("refresh token %q not found", refreshTokenValue)
	}
	storedRefreshToken.sessionStartedAt = time.Now().Add(-p.idp.refreshTokenMaxTTL - time.Minute)
	storedRefreshToken.createdAt = time.Now()
	p.idp.refreshTokens[refreshTokenValue] = storedRefreshToken
}

func (p *providerProcess) expireRefreshTokenIdle(t *testing.T, refreshTokenValue string) {
	t.Helper()

	p.idp.mu.Lock()
	defer p.idp.mu.Unlock()

	storedRefreshToken, ok := p.idp.refreshTokens[refreshTokenValue]
	if !ok {
		t.Fatalf("refresh token %q not found", refreshTokenValue)
	}
	storedRefreshToken.createdAt = time.Now().Add(-p.idp.refreshTokenIdleTTL - time.Minute)
	p.idp.refreshTokens[refreshTokenValue] = storedRefreshToken
}

func expectJSONError(t *testing.T, resp *http.Response, status int) oauthErrorResponse {
	t.Helper()

	body := readBody(t, resp)
	if resp.StatusCode != status {
		t.Fatalf("status mismatch: got %s, want %d; body=%s", resp.Status, status, body)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		t.Fatalf("expected a JSON error response, got Content-Type %q", resp.Header.Get("Content-Type"))
	}

	var errResp oauthErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v\nbody=%s", err, body)
	}
	if errResp.Error == "" {
		t.Fatalf("expected a nonempty OAuth error code, got body=%s", body)
	}
	assertOAuthErrorText(t, errResp.Error, errResp.ErrorDescription)
	return errResp
}

func assertOAuthErrorText(t *testing.T, values ...string) {
	t.Helper()

	for _, value := range values {
		for _, char := range value {
			if char < 0x20 || char > 0x7e || char == '"' || char == '\\' {
				t.Fatalf("invalid character %U in OAuth error text %q", char, value)
			}
		}
	}
}

func expectRedirect(t *testing.T, resp *http.Response, status int) *url.URL {
	t.Helper()

	body := readBody(t, resp)
	if resp.StatusCode != status {
		t.Fatalf("redirect status mismatch: got %s, want %d; body=%s", resp.Status, status, body)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("expected redirect location header")
	}

	redirect, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location %q: %v", location, err)
	}
	return redirect
}

func expectAuthorizationCodeRedirect(t *testing.T, resp *http.Response, status int, redirectURI, state, issuer string) string {
	t.Helper()

	redirect := expectRedirect(t, resp, status)
	assertRedirectTarget(t, redirect, redirectURI)
	assertAuthorizationResponseMetadata(t, redirect, state, issuer)

	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatalf("expected authorization code in redirect, got %q", redirect.String())
	}
	for _, name := range []string{"error", "error_description", "error_uri", "access_token", "id_token", "refresh_token", "token_type"} {
		if redirect.Query().Has(name) {
			t.Fatalf("unexpected parameter %q in authorization code response %q", name, redirect.String())
		}
	}
	return code
}

func expectAuthorizationErrorRedirect(t *testing.T, resp *http.Response, status int, redirectURI, state, issuer, errorCode string) *url.URL {
	t.Helper()

	redirect := expectRedirect(t, resp, status)
	assertRedirectTarget(t, redirect, redirectURI)
	assertAuthorizationResponseMetadata(t, redirect, state, issuer)
	if got := redirect.Query().Get("error"); got != errorCode {
		t.Fatalf("error mismatch: got %q, want %q", got, errorCode)
	}
	assertOAuthErrorText(t, redirect.Query().Get("error"), redirect.Query().Get("error_description"))
	for _, name := range []string{"code", "access_token", "id_token", "refresh_token", "token_type"} {
		if redirect.Query().Has(name) {
			t.Fatalf("unexpected parameter %q in authorization error response %q", name, redirect.String())
		}
	}
	return redirect
}

func assertRedirectTarget(t *testing.T, redirect *url.URL, redirectURI string) {
	t.Helper()

	expected, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("failed to parse redirect uri: %v", err)
	}
	if got, want := redirectBase(redirect), redirectBase(expected); got != want {
		t.Fatalf("redirect destination mismatch: got %q, want %q", got, want)
	}
	if redirect.Fragment != expected.Fragment {
		t.Fatalf("redirect fragment mismatch: got %q, want %q", redirect.Fragment, expected.Fragment)
	}
	for key, want := range expected.Query() {
		if got := redirect.Query()[key]; !slices.Equal(got, want) {
			t.Fatalf("redirect query parameter %q mismatch: got %#v, want %#v", key, got, want)
		}
	}
}

func assertAuthorizationResponseMetadata(t *testing.T, redirect *url.URL, state, issuer string) {
	t.Helper()

	params := redirect.Query()
	for _, name := range []string{"code", "error", "error_description", "error_uri", "state", "iss"} {
		if len(params[name]) > 1 {
			t.Fatalf("duplicate authorization response parameter %q in %q", name, redirect.String())
		}
	}
	if got := params.Get("state"); got != state {
		t.Fatalf("state mismatch: got %q, want %q", got, state)
	}
	if got := params.Get("iss"); got != issuer {
		t.Fatalf("redirect issuer mismatch: got %q, want %q", got, issuer)
	}
}

func redirectBase(u *url.URL) string {
	copy := *u
	copy.RawQuery = ""
	copy.ForceQuery = false
	copy.Fragment = ""
	return copy.String()
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	return body
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pkceVerifier(seed string) string {
	sum := sha256.Sum256([]byte("pkce-verifier:" + seed))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func totpCodeAt(step int64) string {
	mac := hmac.New(sha1.New, []byte(testTOTPKey))
	_ = binary.Write(mac, binary.BigEndian, step)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:])&0x7fffffff)%1000000)
}

func currentTOTPCode() string {
	return totpCodeAt(time.Now().Unix() / totpPeriodSeconds)
}

func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func defaultSubject(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func extractFormAction(t *testing.T, body []byte) string {
	t.Helper()

	matches := regexp.MustCompile(`action="([^"]+)"`).FindSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("failed to extract form action from body:\n%s", body)
	}
	return html.UnescapeString(string(matches[1]))
}

func extractHiddenInputValue(t *testing.T, body []byte, name string) string {
	t.Helper()

	pattern := regexp.MustCompile(`(?s)<input[^>]*name="` + regexp.QuoteMeta(name) + `"[^>]*value="([^"]*)"|<input[^>]*value="([^"]*)"[^>]*name="` + regexp.QuoteMeta(name) + `"`)
	matches := pattern.FindSubmatch(body)
	if len(matches) != 3 {
		t.Fatalf("failed to extract hidden input %q from body:\n%s", name, body)
	}
	for _, match := range matches[1:] {
		if len(match) != 0 {
			return html.UnescapeString(string(match))
		}
	}
	t.Fatalf("failed to extract hidden input %q from body:\n%s", name, body)
	return ""
}

func extractHiddenInputs(t *testing.T, body []byte) url.Values {
	t.Helper()

	inputs := url.Values{}
	for _, match := range regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`).FindAllSubmatch(body, -1) {
		inputs.Add(html.UnescapeString(string(match[1])), html.UnescapeString(string(match[2])))
	}
	if len(inputs) == 0 {
		t.Fatalf("failed to extract hidden inputs from body:\n%s", body)
	}
	return inputs
}

func extractPageTitle(t *testing.T, body []byte) string {
	t.Helper()

	matches := regexp.MustCompile(`(?s)<h1 id="page-title" dir="auto" data-testid="page-title">(.*?)</h1>`).FindSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("failed to extract page title from body:\n%s", body)
	}
	return string(matches[1])
}

func expectPageLanguage(t *testing.T, body []byte, lang, dir string) {
	t.Helper()

	matches := regexp.MustCompile(`<html lang="([^"]*)" dir="([^"]*)">`).FindSubmatch(body)
	if len(matches) != 3 {
		t.Fatalf("failed to extract page language from body:\n%s", body)
	}
	if string(matches[1]) != lang || string(matches[2]) != dir {
		t.Fatalf("page language mismatch: got lang=%q dir=%q, want lang=%q dir=%q", matches[1], matches[2], lang, dir)
	}
}

func resolveProviderURL(t *testing.T, issuer, ref string) string {
	t.Helper()

	baseURL, err := url.Parse(issuer)
	if err != nil {
		t.Fatalf("failed to parse issuer %q: %v", issuer, err)
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		t.Fatalf("failed to parse form action %q: %v", ref, err)
	}
	return baseURL.ResolveReference(refURL).String()
}
