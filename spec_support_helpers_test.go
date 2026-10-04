package simpleidp

// Reference material:
// OpenID Connect specifications index: https://openid.net/developers/specs/
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// OIDC Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
// OIDC RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
// OIDC Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt
// RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.txt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type rpInitiatedLogoutFixture struct {
	provider   *providerProcess
	token      tokenResponse
	formBody   []byte
	formAction string
	csrfToken  string
}

func assertMediaType(t *testing.T, contentType, expected string) {
	t.Helper()

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != expected {
		t.Fatalf("content type mismatch: got %q, want %q", contentType, expected)
	}
}

func assertHeaderDirective(t *testing.T, header http.Header, name, expected string) {
	t.Helper()

	for _, value := range header.Values(name) {
		for directive := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), expected) {
				return
			}
		}
	}
	t.Fatalf("expected %s directive %q, got %#v", name, expected, header.Values(name))
}

func assertTokenResponseHeaders(t *testing.T, resp *http.Response) {
	t.Helper()

	assertMediaType(t, resp.Header.Get("Content-Type"), "application/json")
	assertHeaderDirective(t, resp.Header, "Cache-Control", "no-store")
}

var bearerChallengeAttributePattern = regexp.MustCompile(`^[ \t]*([!#$%&'*+.^_|~0-9A-Za-z\x60-]+)[ \t]*=[ \t]*("(?:[\t\x20-\x21\x23-\x5b\x5d-\x7e\x80-\x{10ffff}]|\\[\t\x20-\x7e\x80-\x{10ffff}])*"|[!#$%&'*+.^_|~0-9A-Za-z\x60-]+)[ \t]*(,|$)`)

func assertBearerChallenge(t *testing.T, header, errorCode string) map[string]string {
	t.Helper()

	scheme, remaining, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		t.Fatalf("expected a Bearer challenge, got %q", header)
	}
	attributes := map[string]string{}
	for {
		match := bearerChallengeAttributePattern.FindStringSubmatch(remaining)
		if match == nil {
			t.Fatalf("malformed Bearer challenge attributes in %q", header)
		}
		name, value := strings.ToLower(match[1]), match[2]
		if _, present := attributes[name]; present {
			t.Fatalf("duplicate Bearer challenge attribute %q in %q", name, header)
		}
		if name == "realm" && value[0] != '"' {
			t.Fatalf("expected a quoted realm in Bearer challenge %q", header)
		}
		if value[0] == '"' {
			value = value[1 : len(value)-1]
			var decoded strings.Builder
			for i := 0; i < len(value); i++ {
				if value[i] == '\\' {
					i++
				}
				decoded.WriteByte(value[i])
			}
			value = decoded.String()
		}
		attributes[name] = value
		remaining = remaining[len(match[0]):]
		if match[3] == "" {
			break
		}
	}
	if attributes["realm"] != "userinfo" || attributes["error"] != errorCode {
		t.Fatalf("unexpected Bearer challenge: got %q, want realm=userinfo and error=%q", header, errorCode)
	}
	assertOAuthErrorText(t, attributes["error"], attributes["error_description"], attributes["scope"])
	if errorCode == "" {
		for _, name := range []string{"error", "error_description", "error_uri"} {
			if _, present := attributes[name]; present {
				t.Fatalf("unexpected error information in unauthenticated challenge %q", header)
			}
		}
	}
	return attributes
}

func replaceJWTClaims(t *testing.T, provider *providerProcess, token string, claims map[string]any) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format: %q", token)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to encode JWT claims: %v", err)
	}
	signingInput := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(nil, provider.idp.privKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("failed to sign test JWT: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func decodeJWTHeader(t *testing.T, token string) jwtHeader {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format: %q", token)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode JWT header: %v", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to decode JWT header JSON: %v", err)
	}
	return header
}

func decodeJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode JWT claims: %v", err)
	}
	return decodeJSONMap(t, payload)
}

func tamperJWTSignature(t *testing.T, token string) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format: %q", token)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode JWT signature: %v", err)
	}
	if len(signature) == 0 {
		t.Fatal("JWT signature is empty")
	}
	signature[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(parts, ".")
}

func decodeJSONMap(t *testing.T, body []byte) map[string]any {
	t.Helper()

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to decode JSON object: %v\nbody=%s", err, body)
	}
	if payload == nil {
		t.Fatalf("expected a JSON object, got body=%s", body)
	}
	return payload
}

func fetchDiscoveryResponse(t *testing.T, provider *providerProcess) (*http.Response, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/.well-known/openid-configuration"), nil)
	if err != nil {
		t.Fatalf("failed to create discovery request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	return resp, readBody(t, resp)
}

func authorizeByPostExpectLoginPage(t *testing.T, provider *providerProcess, request authorizationRequest) []byte {
	t.Helper()

	params := authorizeParams(request)
	resp := submitResubmitForm(t, provider, expectResubmitForm(t, provider.postAuthorize(t, url.Values{}, params), params))
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize POST status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if !strings.Contains(string(body), "Sign in") || !strings.Contains(string(body), `name="username"`) {
		t.Fatalf("authorize POST did not render login form:\n%s", body)
	}
	return body
}

func submitLoginForm(t *testing.T, provider *providerProcess, formBody []byte, username, password string) *http.Response {
	t.Helper()

	form := extractHiddenInputs(t, formBody)
	form.Set("username", username)
	form.Set("password", password)
	return provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, formBody)), form, "", false)
}

func submitConsentForm(t *testing.T, provider *providerProcess, formBody []byte, confirm string) *http.Response {
	t.Helper()

	form := extractHiddenInputs(t, formBody)
	form.Set("confirm", confirm)
	return provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, formBody)), form, "", false)
}

func submitProfileForm(t *testing.T, provider *providerProcess, formBody []byte, name, username, email string) *http.Response {
	t.Helper()

	form := extractHiddenInputs(t, formBody)
	form.Set("name", name)
	form.Set("username", username)
	form.Set("email", email)
	return provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, formBody)), form, "", false)
}

func expectResubmitForm(t *testing.T, resp *http.Response, params url.Values) []byte {
	t.Helper()

	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resubmit status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if !strings.Contains(string(body), `data-testid="page-resubmit"`) {
		t.Fatalf("expected resubmit form, got body=%s", body)
	}
	if action := extractFormAction(t, body); strings.Contains(action, "?") {
		t.Fatalf("resubmit form action must not carry request parameters, got %q", action)
	}
	hidden := extractHiddenInputs(t, body)
	if hidden.Get(resubmitParam) == "" {
		t.Fatalf("resubmit form is missing the %s marker: %v", resubmitParam, hidden)
	}
	hidden.Del(resubmitParam)
	if got := hidden.Encode(); got != params.Encode() {
		t.Fatalf("resubmitted parameters mismatch: got %q, want %q", got, params.Encode())
	}
	nonce := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(resp.Header.Get("Content-Security-Policy"))
	if nonce == nil || !strings.Contains(string(body), `<script nonce="`+nonce[1]+`">HTMLFormElement.prototype.submit.call(document.forms[0])</script>`) {
		t.Fatalf("expected a nonce-allowed auto-submit script, got CSP %q; body=%s", resp.Header.Get("Content-Security-Policy"), body)
	}
	return body
}

func submitResubmitForm(t *testing.T, provider *providerProcess, formBody []byte) *http.Response {
	t.Helper()
	return provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, formBody)), extractHiddenInputs(t, formBody), "", false)
}

func newDefaultConfidentialAuthorizationRequest(verifier string) authorizationRequest {
	return authorizationRequest{
		ClientID:    webClientID,
		RedirectURI: webClientRedirect,
		Scope:       "openid profile email groups",
		State:       "state-" + verifier,
		Nonce:       "nonce-" + verifier,
		Verifier:    pkceVerifier(verifier),
	}
}

func fetchProfilePage(t *testing.T, provider *providerProcess) []byte {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, provider.endpoint(""), nil)
	if err != nil {
		t.Fatalf("failed to create profile request: %v", err)
	}

	resp := provider.do(t, provider.http, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile page status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	assertMediaType(t, resp.Header.Get("Content-Type"), "text/html")
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("profile cache control mismatch: got %q, want %q", got, "no-store")
	}
	if !strings.Contains(string(body), `data-testid="page-profile"`) {
		t.Fatalf("expected profile page, got body=%s", body)
	}
	return body
}

func fetchLoginForm(t *testing.T, provider *providerProcess) []byte {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/login"), nil)
	if err != nil {
		t.Fatalf("failed to create login request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login form status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if !strings.Contains(string(body), `data-testid="page-login"`) {
		t.Fatalf("expected login form, got body=%s", body)
	}
	return body
}

func fetchLogoutForm(t *testing.T, provider *providerProcess, params url.Values) []byte {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+params.Encode(), nil)
	if err != nil {
		t.Fatalf("failed to create logout request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout form status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}
	if !strings.Contains(string(body), `data-testid="page-logout"`) {
		t.Fatalf("expected logout confirmation form, got body=%s", body)
	}
	return body
}

func prepareRPInitiatedLogout(t *testing.T) rpInitiatedLogoutFixture {
	t.Helper()

	provider := startProvider(t, defaultProviderConfig())
	verifier := pkceVerifier("logout-flow-verifier")
	token := authorizeAndExchange(t, provider, authorizationRequest{
		ClientID:    webClientID,
		RedirectURI: webClientRedirect,
		Scope:       "openid profile email groups",
		State:       "logout-flow-state",
		Verifier:    verifier,
	}, tokenRequest{
		ClientID:     webClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: verifier,
	})

	body := fetchLogoutForm(t, provider, url.Values{
		"id_token_hint":            {token.IDToken},
		"post_logout_redirect_uri": {webClientPostLogoutRedirect},
		"state":                    {"logout-state"},
	})

	return rpInitiatedLogoutFixture{
		provider:   provider,
		token:      token,
		formBody:   body,
		formAction: resolveProviderURL(t, provider.issuer, extractFormAction(t, body)),
		csrfToken:  extractHiddenInputValue(t, body, "csrf_token"),
	}
}

func listenLocal(t *testing.T) (net.Listener, error) {
	t.Helper()
	return net.Listen("tcp", "127.0.0.1:0")
}

type backchannelLogoutReceiver struct {
	mu       sync.Mutex
	requests []backchannelLogoutRequest
	server   *http.Server
}

type backchannelLogoutRequest struct {
	contentType string
	rawToken    string
	form        url.Values
	rawQuery    string
}

func startBackchannelLogoutReceiver(t *testing.T) (*backchannelLogoutReceiver, string) {
	t.Helper()

	receiver := &backchannelLogoutReceiver{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			t.Errorf("failed to read back-channel logout request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		parsed, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("invalid back-channel logout form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receiver.mu.Lock()
		receiver.requests = append(receiver.requests, backchannelLogoutRequest{
			contentType: r.Header.Get("Content-Type"),
			rawToken:    parsed.Get("logout_token"),
			form:        parsed,
			rawQuery:    r.URL.RawQuery,
		})
		receiver.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	listener, err := listenLocal(t)
	if err != nil {
		t.Fatalf("failed to open listener for backchannel receiver: %v", err)
	}
	addr := listener.Addr().String()
	receiver.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = receiver.server.Serve(listener) }()
	t.Cleanup(func() { _ = receiver.server.Close() })

	return receiver, "http://" + addr + "/backchannel-logout"
}

func (r *backchannelLogoutReceiver) receivedRequests() []backchannelLogoutRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]backchannelLogoutRequest, len(r.requests))
	copy(cp, r.requests)
	return cp
}

func decodeLogoutToken(t *testing.T, rawToken string) logoutTokenClaims {
	t.Helper()

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid logout token format: %q", rawToken)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode logout token payload: %v", err)
	}

	var claims logoutTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to decode logout token claims: %v\npayload=%s", err, payload)
	}
	return claims
}

func verifyLogoutToken(t *testing.T, provider *providerProcess, rawToken string) logoutTokenClaims {
	t.Helper()

	jwks := fetchJWKS(t, provider)
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected a single jwk, got %#v", jwks.Keys)
	}
	header := decodeJWTHeader(t, rawToken)
	if header.Alg != "RS256" {
		t.Fatalf("signing algorithm mismatch: got %q, want %q", header.Alg, "RS256")
	}
	if header.Kid == "" || header.Kid != jwks.Keys[0].KeyID {
		t.Fatalf("kid mismatch: got %q, want %q", header.Kid, jwks.Keys[0].KeyID)
	}
	publicKey := rsaPublicKeyFromJWK(t, jwks.Keys[0])

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid logout token format: %q", rawToken)
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode logout token signature: %v", err)
	}

	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("failed to verify logout token signature: %v", err)
	}

	return decodeLogoutToken(t, rawToken)
}

func backchannelProviderConfig(backchannelLogoutURI string, sessionRequired bool) providerConfig {
	config := defaultProviderConfig()
	for i, c := range config.Clients {
		if c.ID == webClientID {
			config.Clients[i].BackchannelLogoutURI = backchannelLogoutURI
			config.Clients[i].BackchannelLogoutSessionRequired = sessionRequired
		}
	}
	return config
}

func performLogoutWithBackchannel(t *testing.T, provider *providerProcess) tokenResponse {
	t.Helper()

	verifier := pkceVerifier("backchannel-logout")
	token := authorizeAndExchange(t, provider, authorizationRequest{
		ClientID:    webClientID,
		RedirectURI: webClientRedirect,
		Scope:       "openid profile email",
		State:       "backchannel-state",
		Verifier:    verifier,
	}, tokenRequest{
		ClientID:     webClientID,
		ClientSecret: webClientSecret,
		CodeVerifier: verifier,
	})

	body := fetchLogoutForm(t, provider, url.Values{})
	resp := submitConsentForm(t, provider, body, "yes")
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-testid="page-logout-complete"`) {
		t.Fatalf("logout did not complete: got %s; body=%s", resp.Status, body)
	}
	return token
}
