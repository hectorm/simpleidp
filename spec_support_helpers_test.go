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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
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
	return payload
}

func fetchDiscoveryResponse(t *testing.T, provider *providerProcess) (*http.Response, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/.well-known/openid-configuration"), nil)
	if err != nil {
		t.Fatalf("failed to create discovery request: %v", err)
	}

	resp := provider.do(t, provider.http, req)
	return resp, readBody(t, resp)
}

func authorizeByPostExpectLoginPage(t *testing.T, provider *providerProcess, request authorizationRequest) []byte {
	t.Helper()

	resp := provider.postAuthorize(t, url.Values{}, authorizeParams(request))
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

	return provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, formBody)), url.Values{
		"username":   {username},
		"password":   {password},
		"csrf_token": {extractHiddenInputValue(t, formBody, "csrf_token")},
	}, "", false)
}

func submitConsentForm(t *testing.T, provider *providerProcess, formBody []byte, confirm string) *http.Response {
	t.Helper()

	return provider.postFormURL(t, resolveProviderURL(t, provider.issuer, extractFormAction(t, formBody)), url.Values{
		"confirm":    {confirm},
		"csrf_token": {extractHiddenInputValue(t, formBody, "csrf_token")},
	}, "", false)
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

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session")+"?"+url.Values{
		"id_token_hint":            {token.IDToken},
		"post_logout_redirect_uri": {webClientPostLogoutRedirect},
		"state":                    {"logout-state"},
	}.Encode(), nil)
	if err != nil {
		t.Fatalf("failed to create logout request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout form status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

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
}

func startBackchannelLogoutReceiver(t *testing.T) (*backchannelLogoutReceiver, string) {
	t.Helper()

	receiver := &backchannelLogoutReceiver{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		parsed, _ := url.ParseQuery(string(body))
		receiver.mu.Lock()
		receiver.requests = append(receiver.requests, backchannelLogoutRequest{
			contentType: r.Header.Get("Content-Type"),
			rawToken:    parsed.Get("logout_token"),
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

	req, err := http.NewRequest(http.MethodGet, provider.endpoint("/end-session"), nil)
	if err != nil {
		t.Fatalf("failed to create logout request: %v", err)
	}

	resp := provider.do(t, provider.redirectless, req)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout form status mismatch: got %s, want %d; body=%s", resp.Status, http.StatusOK, body)
	}

	_ = readBody(t, submitConsentForm(t, provider, body, "yes"))
	return token
}
