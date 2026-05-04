// Minimal OIDC Identity Provider that authenticates users via a login form against
// static credentials and completes the full OIDC Authorization Code flow with PKCE.
//
// Configuration is entirely through environment variables:
//
// SIMPLE_IDP_LISTEN   - listen address (default ":8227")
// SIMPLE_IDP_ISSUER   - issuer URL as seen by clients (required)
// SIMPLE_IDP_TITLE    - login page title (default: "Simple IdP")
// SIMPLE_IDP_KEY_ID   - JWKS key ID (default: "simple-idp")
// SIMPLE_IDP_KEY_FILE - PEM file for PKCS8 RSA private key; generated in memory if empty
// SIMPLE_IDP_KEY_B64  - base64-encoded PKCS8 RSA private key (alternative to KEY_FILE)
//
// Clients are configured with a label prefix (the label is arbitrary, used only for grouping):
//
// SIMPLE_IDP_CLIENT_<LABEL>_ID                                  - client ID
// SIMPLE_IDP_CLIENT_<LABEL>_SECRET                              - client secret (optional for loopback/native clients)
// SIMPLE_IDP_CLIENT_<LABEL>_REDIRECT_URL                        - allowed redirect URI
// SIMPLE_IDP_CLIENT_<LABEL>_POST_LOGOUT_REDIRECT_URL            - allowed post-logout redirect URI (optional)
// SIMPLE_IDP_CLIENT_<LABEL>_BACKCHANNEL_LOGOUT_URI              - back-channel logout URI (optional)
// SIMPLE_IDP_CLIENT_<LABEL>_BACKCHANNEL_LOGOUT_SESSION_REQUIRED - require "sid" in logout token (optional, default "false")
//
// Users are configured the same way:
//
// SIMPLE_IDP_USER_<LABEL>_USERNAME           - login username (required)
// SIMPLE_IDP_USER_<LABEL>_PASSWORD           - login password (required)
// SIMPLE_IDP_USER_<LABEL>_SUB                - "sub" claim (default: <USERNAME>)
// SIMPLE_IDP_USER_<LABEL>_NAME               - "name" claim (default: <USERNAME>)
// SIMPLE_IDP_USER_<LABEL>_PREFERRED_USERNAME - "preferred_username" claim (default: <USERNAME>)
// SIMPLE_IDP_USER_<LABEL>_EMAIL              - "email" claim (default: <USERNAME>@localhost)
// SIMPLE_IDP_USER_<LABEL>_EMAIL_VERIFIED     - "email_verified" claim (default: "true")
// SIMPLE_IDP_USER_<LABEL>_PROFILE            - "profile" claim (default: empty)
// SIMPLE_IDP_USER_<LABEL>_PICTURE            - "picture" claim (default: empty)
// SIMPLE_IDP_USER_<LABEL>_LOCALE             - "locale" claim (default: empty)
// SIMPLE_IDP_USER_<LABEL>_GROUPS             - comma-separated "groups" claim (default: empty)
//
// At least one client and one user must be configured.
package simpleidp

import (
	"compress/gzip"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

func New(environ []string, lookupEnv func(string) string, readFile func(string) ([]byte, error)) (string, *http.Server, error) {
	listen, provider, err := newIdentityProvider(environ, lookupEnv, readFile)
	if err != nil {
		return "", nil, err
	}
	return listen, newServer(listen, provider), nil
}

// -------------------------------------------------------------------------- //

const (
	codeTTL                      = time.Minute
	loginActionTTL               = 5 * time.Minute
	sessionIdleTTL               = 30 * time.Minute
	sessionMaxTTL                = 10 * time.Hour
	accessTokenTTL               = 5 * time.Minute
	refreshTokenIdleTTL          = 30 * time.Minute
	refreshTokenMaxTTL           = 10 * time.Hour
	maxFormBodyBytes             = 1 << 20
	sessionCookieBaseName        = "simple_idp_session"
	preAuthSessionCookieBaseName = "simple_idp_preauth_session"
)

type client struct {
	id                               string
	secret                           string
	isPublic                         bool
	redirectURL                      url.URL
	postLogoutRedirectURL            url.URL
	backchannelLogoutURI             url.URL
	backchannelLogoutSessionRequired bool
}

type user struct {
	username          string
	password          string
	sub               string
	name              string
	preferredUsername string
	email             string
	emailVerified     bool
	profile           string
	picture           string
	locale            string
	groups            []string
}

type session struct {
	username        string
	authenticatedAt time.Time
	lastSeenAt      time.Time
}

type accessToken struct {
	clientID string
	username string
	scope    string
	code     string
	expiry   time.Time
}

type refreshToken struct {
	clientID         string
	username         string
	scope            string
	code             string
	sessionID        string
	authenticatedAt  time.Time
	sessionStartedAt time.Time
	createdAt        time.Time
	consumedAt       time.Time
}

type pendingCode struct {
	clientID        string
	username        string
	redirectURI     url.URL
	codeChallenge   string
	nonce           string
	state           string
	scope           string
	sessionID       string
	consentRequired bool
	authenticatedAt time.Time
	createdAt       time.Time
	consumedAt      time.Time
}

type tokenHint struct {
	sub string
	aud string
}

type authorizeRequest struct {
	params          url.Values
	client          client
	redirectURI     url.URL
	scope           string
	state           string
	codeChallenge   string
	nonce           string
	consentRequired bool
}

type identityProvider struct {
	issuer        string
	base          string
	title         string
	keyID         string
	privKey       *rsa.PrivateKey
	csrfKey       []byte
	clients       map[string]client
	users         map[string]user
	sessions      map[string]session
	accessTokens  map[string]accessToken
	refreshTokens map[string]refreshToken
	pendingCodes  map[string]pendingCode
	mu            sync.Mutex
}

// -------------------------------------------------------------------------- //

func newIdentityProvider(environ []string, lookupEnv func(string) string, readFile func(string) ([]byte, error)) (string, *identityProvider, error) {
	listen := envOr(lookupEnv, "SIMPLE_IDP_LISTEN", ":8227")
	issuer, err := envRequired(lookupEnv, "SIMPLE_IDP_ISSUER")
	if err != nil {
		return "", nil, err
	}
	issuerURL, err := validateIssuerURL(issuer)
	if err != nil {
		return "", nil, fmt.Errorf("SIMPLE_IDP_ISSUER: %w", err)
	}
	issuerURL.Path = strings.TrimRight(issuerURL.Path, "/")
	issuer = issuerURL.String()

	clients, err := loadClients(environ, lookupEnv)
	if err != nil {
		return "", nil, err
	}
	users, err := loadUsers(environ, lookupEnv)
	if err != nil {
		return "", nil, err
	}

	title := envOr(lookupEnv, "SIMPLE_IDP_TITLE", "Simple IdP")
	keyID := envOr(lookupEnv, "SIMPLE_IDP_KEY_ID", "simple-idp")
	privKey, err := loadOrGenerateKey(lookupEnv, readFile)
	if err != nil {
		return "", nil, err
	}

	csrfKey := make([]byte, 32)
	if _, err := rand.Read(csrfKey); err != nil {
		return "", nil, fmt.Errorf("failed to generate CSRF key: %w", err)
	}

	return listen, &identityProvider{
		issuer:        issuer,
		base:          issuerURL.Path,
		title:         title,
		keyID:         keyID,
		privKey:       privKey,
		csrfKey:       csrfKey,
		clients:       clients,
		users:         users,
		sessions:      map[string]session{},
		accessTokens:  map[string]accessToken{},
		refreshTokens: map[string]refreshToken{},
		pendingCodes:  map[string]pendingCode{},
	}, nil
}

func newServer(listen string, provider *identityProvider) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+provider.base+"/.well-known/openid-configuration", provider.handleDiscovery)
	mux.HandleFunc("GET "+provider.base+"/authorize", provider.handleAuthorize)
	mux.HandleFunc("POST "+provider.base+"/authorize", provider.handleAuthorize)
	mux.HandleFunc("POST "+provider.base+"/token", provider.handleToken)
	mux.HandleFunc("GET "+provider.base+"/userinfo", provider.handleUserInfo)
	mux.HandleFunc("POST "+provider.base+"/userinfo", provider.handleUserInfo)
	mux.HandleFunc("GET "+provider.base+"/jwks", provider.handleJWKS)
	mux.HandleFunc("POST "+provider.base+"/introspect", provider.handleIntrospect)
	mux.HandleFunc("POST "+provider.base+"/revoke", provider.handleRevoke)
	mux.HandleFunc("GET "+provider.base+"/end-session", provider.handleEndSession)
	mux.HandleFunc("POST "+provider.base+"/end-session", provider.handleEndSession)
	mux.HandleFunc("GET "+provider.base+"/favicon.ico", provider.handleFavicon)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		mux.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func (p *identityProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := struct {
		Issuer                                     string   `json:"issuer"`
		AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
		TokenEndpoint                              string   `json:"token_endpoint"`
		UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
		JWKSURI                                    string   `json:"jwks_uri"`
		IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
		RevocationEndpoint                         string   `json:"revocation_endpoint"`
		EndSessionEndpoint                         string   `json:"end_session_endpoint"`
		ScopesSupported                            []string `json:"scopes_supported"`
		ResponseTypesSupported                     []string `json:"response_types_supported"`
		ResponseModesSupported                     []string `json:"response_modes_supported"`
		GrantTypesSupported                        []string `json:"grant_types_supported"`
		SubjectTypesSupported                      []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
		TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
		CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
		ClaimsSupported                            []string `json:"claims_supported"`
		PromptValuesSupported                      []string `json:"prompt_values_supported"`
		ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
		RequestParameterSupported                  bool     `json:"request_parameter_supported"`
		RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
		RequireRequestURIRegistration              bool     `json:"require_request_uri_registration"`
		AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
		BackchannelLogoutSupported                 bool     `json:"backchannel_logout_supported"`
		BackchannelLogoutSessionSupported          bool     `json:"backchannel_logout_session_supported"`
	}{
		Issuer:                            p.issuer,
		AuthorizationEndpoint:             p.issuer + "/authorize",
		TokenEndpoint:                     p.issuer + "/token",
		UserInfoEndpoint:                  p.issuer + "/userinfo",
		JWKSURI:                           p.issuer + "/jwks",
		IntrospectionEndpoint:             p.issuer + "/introspect",
		RevocationEndpoint:                p.issuer + "/revoke",
		EndSessionEndpoint:                p.issuer + "/end-session",
		ScopesSupported:                   []string{"openid", "profile", "email", "groups"},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "iat", "exp", "auth_time", "nonce", "sid", "email", "email_verified",
			"name", "preferred_username", "profile", "picture", "locale", "groups",
		},
		PromptValuesSupported:                      []string{"none", "login", "consent", "select_account"},
		ClaimsParameterSupported:                   false,
		RequestParameterSupported:                  false,
		RequestURIParameterSupported:               false,
		RequireRequestURIRegistration:              false,
		AuthorizationResponseIssParameterSupported: true,
		BackchannelLogoutSupported:                 true,
		BackchannelLogoutSessionSupported:          true,
	}
	writeJSON(w, http.StatusOK, doc)
}

func (p *identityProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := parseForm(w, r); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
	}

	params := r.URL.Query()
	if r.Method == http.MethodPost && len(params) == 0 {
		params = r.PostForm
	}

	if len(params["client_id"]) > 1 || len(params["redirect_uri"]) > 1 {
		http.Error(w, "Duplicate parameter", http.StatusBadRequest)
		return
	}

	clientID := params.Get("client_id")
	code := params.Get("code")
	scope := params.Get("scope")
	codeChallenge := params.Get("code_challenge")
	prompt := params.Get("prompt")
	idTokenHint := params.Get("id_token_hint")
	nonce := params.Get("nonce")
	state := params.Get("state")

	confirm, username, password := "", "", ""
	csrfToken := ""
	if r.Method == http.MethodPost {
		confirm = r.PostForm.Get("confirm")
		username = r.PostForm.Get("username")
		password = r.PostForm.Get("password")
		csrfToken = r.PostForm.Get("csrf_token")
	}

	client, ok := p.clients[clientID]
	redirectURI, err := url.Parse(params.Get("redirect_uri"))

	if !ok || err != nil || !isAllowedRedirectURL(client.redirectURL, *redirectURI, client.isPublic) {
		http.Error(w, "Unknown client or redirect URI", http.StatusBadRequest)
		return
	}
	if responseMode := params.Get("response_mode"); responseMode != "" && responseMode != "query" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost && (confirm != "" || username != "" || password != "") {
		ownerID := ""
		if confirm != "" {
			if id := p.readSession(r); id != "" {
				ownerID = "session:" + id
			}
		} else {
			if id := p.readPreAuthSession(r); id != "" {
				ownerID = "preauth:" + id
			}
		}
		if !p.validateCSRFToken(csrfToken, ownerID) {
			http.Error(w, "Invalid or expired session", http.StatusBadRequest)
			return
		}
	}

	if r.Method == http.MethodPost && confirm != "" {
		now := time.Now()
		p.mu.Lock()
		pendingCode, codeKnown := p.pendingCodes[code]
		if codeKnown && isPendingCodeExpired(pendingCode, now) {
			delete(p.pendingCodes, code)
			codeKnown = false
		}
		if codeKnown && (pendingCode.clientID != client.id || pendingCode.redirectURI != *redirectURI || !pendingCode.consumedAt.IsZero() || !pendingCode.consentRequired) {
			codeKnown = false
		}
		if codeKnown {
			switch confirm {
			case "yes":
				pendingCode.consentRequired = false
				pendingCode.createdAt = now
				p.pendingCodes[code] = pendingCode
			case "no":
				delete(p.pendingCodes, code)
			default:
				codeKnown = false
			}
		}
		p.mu.Unlock()

		if !codeKnown {
			redirectWithError(w, r, p.issuer, *redirectURI, pendingCode.state, "invalid_request", "Invalid consent request")
			return
		}
		if confirm == "no" {
			redirectWithError(w, r, p.issuer, *redirectURI, pendingCode.state, "access_denied", "End-user denied the request")
			return
		}
		redirectWithCode(w, r, p.issuer, *redirectURI, code, pendingCode.state)
		return
	}

	if errCode, errDesc := validateAuthorizeParams(params); errCode != "" {
		redirectWithError(w, r, p.issuer, *redirectURI, state, errCode, errDesc)
		return
	}
	if !hasUniqueParams(params) {
		redirectWithError(w, r, p.issuer, *redirectURI, state, "invalid_request", "Duplicate parameter")
		return
	}
	if scope, ok = filterScope(scope); !ok {
		redirectWithError(w, r, p.issuer, *redirectURI, state, "invalid_scope", "Scope must include 'openid'")
		return
	}
	consentRequired := hasPromptValue(prompt, "consent")

	maxAge, maxAgeRequested, err := parseMaxAge(params.Get("max_age"))
	if err != nil {
		redirectWithError(w, r, p.issuer, *redirectURI, state, "invalid_request", "Invalid max_age")
		return
	}

	var hintedUser tokenHint
	if idTokenHint != "" {
		var ok bool
		hintedUser, ok = p.resolveIDTokenHint(idTokenHint)
		if !ok || hintedUser.aud != client.id {
			redirectWithError(w, r, p.issuer, *redirectURI, state, "invalid_request", "Invalid id_token_hint")
			return
		}
	}

	authorization := authorizeRequest{
		params:          params,
		client:          client,
		redirectURI:     *redirectURI,
		scope:           scope,
		state:           state,
		codeChallenge:   codeChallenge,
		nonce:           nonce,
		consentRequired: consentRequired,
	}
	currentSession, sessionKnown := session{}, false
	if !hasPromptValue(prompt, "login") && !hasPromptValue(prompt, "select_account") {
		currentSession, sessionKnown = p.resumeSession(p.readSession(r))
		if sessionKnown && !p.canReuseSession(currentSession, hintedUser, maxAge, maxAgeRequested) {
			sessionKnown = false
		}
	}

	if prompt == "none" {
		if !sessionKnown {
			redirectWithError(w, r, p.issuer, *redirectURI, state, "login_required", "Authentication required")
			return
		}
		p.authorizeUser(w, r, authorization, currentSession.username, currentSession.authenticatedAt, p.readSession(r))
		return
	}

	if sessionKnown && (r.Method == http.MethodGet || (username == "" && password == "")) {
		p.authorizeUser(w, r, authorization, currentSession.username, currentSession.authenticatedAt, p.readSession(r))
		return
	}

	if r.Method == http.MethodGet || (username == "" && password == "") {
		p.renderLoginForm(w, r, authorization.params, "", "")
		return
	}
	authenticatedUser, userKnown := p.authenticateEndUser(username, password)
	if !userKnown {
		p.renderLoginForm(w, r, authorization.params, username, "Invalid username or password")
		return
	}
	if hintedUser.sub != "" && authenticatedUser.sub != hintedUser.sub {
		redirectWithError(w, r, p.issuer, *redirectURI, state, "login_required", "Authenticated user does not match id_token_hint")
		return
	}
	authenticatedAt := time.Now()
	sessionID := p.issueSession(w, authenticatedUser.username, authenticatedAt)
	p.clearPreAuthSession(w)
	p.authorizeUser(w, r, authorization, authenticatedUser.username, authenticatedAt, sessionID)
}

func (p *identityProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}

	if !hasUniqueParams(r.PostForm) {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Duplicate parameter")
		return
	}

	client, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}

	switch grantType := r.PostForm.Get("grant_type"); grantType {
	case "":
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Missing required parameter: grant_type")
	case "authorization_code":
		p.exchangeAuthorizationCode(w, r, client)
	case "refresh_token":
		p.exchangeRefreshToken(w, r, client)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type")
	}
}

func (p *identityProvider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	accessToken := ""
	if r.Method == http.MethodPost {
		if err := parseForm(w, r); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_request", error_description="Bad request"`)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !hasUniqueParams(r.PostForm) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_request", error_description="Duplicate parameter"`)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		accessToken = r.PostForm.Get("access_token")
	}

	if authorization != "" && accessToken != "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_request", error_description="Multiple access token methods are not allowed"`)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if authorization == "" && accessToken == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if authorization == "" && accessToken != "" {
		authorization = "Bearer " + accessToken
	}

	authFields := strings.Fields(authorization)
	if len(authFields) == 0 || !strings.EqualFold(authFields[0], "Bearer") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if len(authFields) != 2 || authFields[1] == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_request", error_description="Malformed bearer token"`)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, bearerToken, ok := p.resolveBearerToken(authFields[1])
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_token", error_description="The access token is invalid or expired"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, p.buildClaimsForScope(user, bearerToken.scope))
}

func (p *identityProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := &p.privKey.PublicKey
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": p.keyID,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	writeJSON(w, http.StatusOK, jwks)
}

func (p *identityProvider) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}
	if !hasUniqueParams(r.PostForm) {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Duplicate parameter")
		return
	}

	client, ok := p.authenticateProtectedResource(w, r)
	if !ok {
		return
	}

	token := r.PostForm.Get("token")
	if token == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Missing required parameter: token")
		return
	}
	p.mu.Lock()
	p.removeExpiredState()
	storedAccessToken, accessTokenKnown := p.accessTokens[token]
	storedRefreshToken, refreshTokenKnown := p.refreshTokens[token]
	p.mu.Unlock()

	writeActiveResponse := func(user user, clientID, scope string, expiry time.Time, tokenType string) {
		response := p.buildClaimsForScope(user, scope)
		response["active"] = true
		if tokenType != "" {
			response["token_type"] = tokenType
		}
		response["client_id"] = clientID
		response["scope"] = scope
		response["exp"] = expiry.Unix()
		response["iss"] = p.issuer
		writeJSON(w, http.StatusOK, response)
	}
	refreshTokenExpiry := func(token refreshToken) time.Time {
		idleExpiry := token.createdAt.Add(refreshTokenIdleTTL)
		maxExpiry := token.sessionStartedAt.Add(refreshTokenMaxTTL)
		if idleExpiry.Before(maxExpiry) {
			return idleExpiry
		}
		return maxExpiry
	}
	writeActiveAccessToken := func() bool {
		if !accessTokenKnown || storedAccessToken.clientID != client.id {
			return false
		}
		user := p.users[storedAccessToken.username]
		writeActiveResponse(user, storedAccessToken.clientID, storedAccessToken.scope, storedAccessToken.expiry, "Bearer")
		return true
	}
	writeActiveRefreshToken := func() bool {
		if !refreshTokenKnown || !storedRefreshToken.consumedAt.IsZero() || storedRefreshToken.clientID != client.id {
			return false
		}
		user := p.users[storedRefreshToken.username]
		writeActiveResponse(user, storedRefreshToken.clientID, storedRefreshToken.scope, refreshTokenExpiry(storedRefreshToken), "")
		return true
	}

	switch r.PostForm.Get("token_type_hint") {
	case "refresh_token":
		if writeActiveRefreshToken() || writeActiveAccessToken() {
			return
		}
	default:
		if writeActiveAccessToken() || writeActiveRefreshToken() {
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"active": false})
}

func (p *identityProvider) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}
	if !hasUniqueParams(r.PostForm) {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Duplicate parameter")
		return
	}

	client, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}

	token := r.PostForm.Get("token")
	if token == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Missing required parameter: token")
		return
	}
	tokenTypeHint := r.PostForm.Get("token_type_hint")

	revokeAccessToken := func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		stored, known := p.accessTokens[token]
		if !known || stored.clientID != client.id {
			return false
		}
		delete(p.accessTokens, token)
		return true
	}
	revokeRefreshToken := func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		stored, known := p.refreshTokens[token]
		if !known || stored.clientID != client.id {
			return false
		}
		for k, v := range p.refreshTokens {
			if v.code == stored.code {
				delete(p.refreshTokens, k)
			}
		}
		for k, v := range p.accessTokens {
			if v.code == stored.code {
				delete(p.accessTokens, k)
			}
		}
		return true
	}

	switch tokenTypeHint {
	case "refresh_token":
		if !revokeRefreshToken() {
			revokeAccessToken()
		}
	default:
		if !revokeAccessToken() {
			revokeRefreshToken()
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (p *identityProvider) handleEndSession(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := parseForm(w, r); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
	}

	params := r.URL.Query()
	if r.Method == http.MethodPost && len(params) == 0 {
		params = r.PostForm
	}
	if !hasUniqueParams(params) {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	clientID := params.Get("client_id")
	postLogoutRedirectURI := params.Get("post_logout_redirect_uri")
	state := params.Get("state")
	idTokenHint := params.Get("id_token_hint")

	confirm, csrfToken := "", ""
	if r.Method == http.MethodPost {
		confirm = r.PostForm.Get("confirm")
		csrfToken = r.PostForm.Get("csrf_token")
	}

	if idTokenHint != "" {
		hintedUser, ok := p.resolveIDTokenHint(idTokenHint)
		if !ok {
			http.Error(w, "Invalid id_token_hint", http.StatusBadRequest)
			return
		}
		if clientID == "" {
			clientID = hintedUser.aud
		} else if clientID != hintedUser.aud {
			http.Error(w, "Invalid id_token_hint", http.StatusBadRequest)
			return
		}
	}

	if postLogoutRedirectURI != "" {
		if clientID == "" {
			http.Error(w, "Missing client_id", http.StatusBadRequest)
			return
		}
		client, ok := p.clients[clientID]
		if !ok || postLogoutRedirectURI != client.postLogoutRedirectURL.String() {
			http.Error(w, "Unknown client or post-logout redirect URI", http.StatusBadRequest)
			return
		}
	}

	sessionID := p.readSession(r)
	currentSession, sessionKnown := p.resumeSession(sessionID)

	if !sessionKnown {
		p.renderLogoutComplete(w, r, clientID, postLogoutRedirectURI, state)
		return
	}

	if confirm == "" {
		p.renderLogoutForm(w, r, params, sessionID)
		return
	}

	if !p.validateCSRFToken(csrfToken, "session:"+sessionID) {
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}

	if confirm != "yes" {
		p.renderLogoutCanceled(w, r, clientID)
		return
	}

	logoutUsername := currentSession.username
	p.mu.Lock()
	affectedClientIDs := map[string]struct{}{}
	for tokenValue, accessToken := range p.accessTokens {
		if accessToken.username != logoutUsername {
			continue
		}
		if clientID != "" && accessToken.clientID != clientID {
			continue
		}
		affectedClientIDs[accessToken.clientID] = struct{}{}
		delete(p.accessTokens, tokenValue)
	}
	for codeValue, pendingCode := range p.pendingCodes {
		if pendingCode.username != logoutUsername {
			continue
		}
		if clientID != "" && pendingCode.clientID != clientID {
			continue
		}
		affectedClientIDs[pendingCode.clientID] = struct{}{}
		delete(p.pendingCodes, codeValue)
	}
	for tokenValue, refreshToken := range p.refreshTokens {
		if refreshToken.username != logoutUsername {
			continue
		}
		if clientID != "" && refreshToken.clientID != clientID {
			continue
		}
		affectedClientIDs[refreshToken.clientID] = struct{}{}
		delete(p.refreshTokens, tokenValue)
	}
	p.mu.Unlock()

	logoutUser := p.users[logoutUsername]
	for affectedClientID := range affectedClientIDs {
		affectedClient, ok := p.clients[affectedClientID]
		if !ok || affectedClient.backchannelLogoutURI.String() == "" {
			continue
		}
		p.sendBackchannelLogout(affectedClient, logoutUser, sessionID)
	}

	p.clearSession(w, sessionID)

	p.renderLogoutComplete(w, r, clientID, postLogoutRedirectURI, state)
}

func (p *identityProvider) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
	w.Header().Del("Pragma")
	_, _ = w.Write([]byte{
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0xb0, 0x00,
		0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
		0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
		0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
		0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff,
		0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
	})
}

// -------------------------------------------------------------------------- //

type formPageField struct {
	Type         string
	Name         string
	Label        string
	Value        string
	Autocomplete string
	Autofocus    bool
}

type formPageButton struct {
	Name  string
	Value string
	Label string
}

type formPageLink struct {
	Href   string
	Label  string
	TestID string
}

type formPage struct {
	Title       string
	Nonce       string
	Action      string
	Message     string
	Error       string
	DescribedBy string
	TestID      string
	Params      url.Values
	Fields      []formPageField
	Buttons     []formPageButton
	Links       []formPageLink
}

var formPageGzipPool = sync.Pool{New: func() any { return gzip.NewWriter(nil) }}
var formPageTemplate = template.Must(template.New("form-page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="color-scheme" content="light dark">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>{{.Title}}</title>
	<style nonce="{{.Nonce}}">
		:root {
			color-scheme: light dark;
			--color-bg: light-dark(oklch(96% 0 0), oklch(18% 0 0));
			--color-surface: light-dark(oklch(100% 0 0), oklch(23% 0 0));
			--color-shadow: light-dark(oklch(0% 0 0 / .08), oklch(0% 0 0 / .4));
			--color-text: light-dark(oklch(22% 0 0), oklch(92% 0 0));
			--color-text-muted: light-dark(oklch(37% 0.03 260), oklch(71% 0.01 286));
			--color-border: color-mix(in oklch, var(--color-text) 20%, transparent);
			--color-primary: light-dark(oklch(49% 0.19 264), oklch(54% 0.18 262));
			--color-primary-contrast: oklch(100% 0 0);
			--color-focus-ring: color-mix(in oklch, var(--color-primary) 25%, transparent);
			--color-error: light-dark(oklch(51% 0.19 28), oklch(71% 0.17 22));
			--color-error-bg: color-mix(in oklch, var(--color-error) 10%, var(--color-surface));
			--color-error-border: color-mix(in oklch, var(--color-error) 25%, var(--color-surface));
			--radius: 8px;
		}
		*, *::before, *::after {
			box-sizing: border-box;
			margin: 0;
			padding: 0;
		}
		body {
			display: flex;
			align-items: center;
			justify-content: center;
			min-height: 100dvh;
			padding: 1rem;
			font-family: system-ui, sans-serif;
			color: var(--color-text);
			background: var(--color-bg);
		}
		main {
			width: 100%;
			max-width: 400px;
			padding: 2.5rem 2rem;
			border-radius: calc(var(--radius) * 1.5);
			background: var(--color-surface);
			box-shadow: 0 2px 16px var(--color-shadow);
		}
		h1 {
			margin-bottom: 1.5rem;
			font-size: 1.25rem;
			font-weight: 600;
			text-align: center;
			color: var(--color-text-muted);
		}
		p {
			margin-bottom: 1rem;
			font-size: .95rem;
			text-align: center;
			color: var(--color-text-muted);
		}
		[role=alert] {
			margin-bottom: 1rem;
			padding: .75rem 1rem;
			border: 1px solid var(--color-error-border);
			border-radius: var(--radius);
			font-size: .875rem;
			color: var(--color-error);
			background: var(--color-error-bg);
		}
		form {
			display: grid;
			gap: 1rem;
			label {
				display: grid;
				gap: .25rem;
				font-size: .875rem;
				font-weight: 500;
				color: var(--color-text-muted);
			}
			input[type=text],
			input[type=password] {
				display: block;
				width: 100%;
				padding: .625rem .75rem;
				border: 1px solid var(--color-border);
				border-radius: var(--radius);
				font-size: 1rem;
				color: var(--color-text);
				background: var(--color-surface);
				transition: border-color .15s;
				&:focus-visible {
					border-color: var(--color-primary);
					outline: none;
					box-shadow: 0 0 0 3px var(--color-focus-ring);
				}
			}
		}
		ul {
			display: grid;
			gap: .75rem;
			list-style: none;
		}
		button, a {
			display: block;
			width: 100%;
			padding: .75rem;
			border: 1px solid transparent;
			border-radius: var(--radius);
			font-size: 1rem;
			font-weight: 500;
			text-align: center;
			text-decoration: none;
			cursor: pointer;
			transition: background .15s;
			&:focus-visible {
				outline: none;
				box-shadow: 0 0 0 3px var(--color-focus-ring);
			}
		}
		button {
			color: var(--color-primary-contrast);
			background: var(--color-primary);
			&:hover {
				background: color-mix(in oklch, var(--color-primary) 85%, light-dark(black, white));
			}
			&:active {
				background: color-mix(in oklch, var(--color-primary) 70%, light-dark(black, white));
			}
		}
		button[value=no], a {
			border-color: var(--color-border);
			color: var(--color-text);
			background: transparent;
			&:hover {
				background: color-mix(in oklch, var(--color-text) 8%, transparent);
			}
			&:active {
				background: color-mix(in oklch, var(--color-text) 14%, transparent);
			}
		}
	</style>
</head>
<body>
	<main aria-labelledby="page-title"{{if .TestID}} data-testid="{{.TestID}}"{{end}}>
		<h1 id="page-title" data-testid="page-title">{{.Title}}</h1>
		{{- if .Message}}
		<p id="form-description" data-testid="message">{{.Message}}</p>
		{{- end}}
		{{- if .Error}}
		<p id="form-error" role="alert" aria-live="assertive" data-testid="error">{{.Error}}</p>
		{{- end}}
		{{- if or .Fields .Buttons}}
		<form
			method="POST"
			action="{{.Action}}"
			{{- if .DescribedBy}}
			aria-describedby="{{.DescribedBy}}"
			{{- end}}
			data-testid="form"
		>
			{{- range $key, $values := .Params}}{{range $value := $values}}
			<input type="hidden" name="{{$key}}" value="{{$value}}">
			{{- end}}{{end}}
			{{- range .Fields}}
			<label for="{{.Name}}">{{.Label}}
				<input
					type="{{.Type}}"
					id="{{.Name}}"
					name="{{.Name}}"
					{{- if .Value}} value="{{.Value}}"{{end}}
					{{- if .Autocomplete}} autocomplete="{{.Autocomplete}}"{{end}}
					{{- if .Autofocus}} autofocus{{end}}
					data-testid="field-{{.Name}}"
					required
				>
			</label>
			{{- end}}
			<ul role="list" data-testid="actions">
				{{- range .Buttons}}
				<li>
					<button
						type="submit"
						{{- if .Name}}
						name="{{.Name}}"
						value="{{.Value}}"
						{{- end}}
						data-testid="submit{{if .Value}}-{{.Value}}{{end}}"
					>{{.Label}}</button>
				</li>
				{{- end}}
			</ul>
		</form>
		{{- end}}
		{{- if .Links}}
		<ul role="list" data-testid="links">
			{{- range .Links}}
			<li><a href="{{.Href}}"{{if .TestID}} data-testid="{{.TestID}}"{{end}}>{{.Label}}</a></li>
			{{- end}}
		</ul>
		{{- end}}
	</main>
</body>
</html>`))

func (p *identityProvider) renderFormPage(w http.ResponseWriter, r *http.Request, page formPage) {
	page.Nonce = rand.Text()
	switch {
	case page.Message != "" && page.Error != "":
		page.DescribedBy = "form-description form-error"
	case page.Message != "":
		page.DescribedBy = "form-description"
	case page.Error != "":
		page.DescribedBy = "form-error"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+page.Nonce+"'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Vary", "Accept-Encoding")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := formPageGzipPool.Get().(*gzip.Writer)
		gz.Reset(w)
		_ = formPageTemplate.Execute(gz, page)
		_ = gz.Close()
		formPageGzipPool.Put(gz)
	} else {
		_ = formPageTemplate.Execute(w, page)
	}
}

func (p *identityProvider) renderLoginForm(w http.ResponseWriter, r *http.Request, params url.Values, username, errorMsg string) {
	preAuthID := p.readPreAuthSession(r)
	if preAuthID == "" {
		preAuthID = p.issuePreAuthSession(w)
	}
	csrfToken := p.issueCSRFToken("preauth:" + preAuthID)
	p.renderFormPage(w, r, formPage{
		Title:  p.title,
		Action: p.base + "/authorize?" + filterFormParams(params, "username", "password", "code", "confirm").Encode(),
		Error:  errorMsg,
		TestID: "page-login",
		Params: url.Values{
			"csrf_token": {csrfToken},
		},
		Fields: []formPageField{
			{Type: "text", Name: "username", Label: "Username", Value: username, Autocomplete: "username", Autofocus: true},
			{Type: "password", Name: "password", Label: "Password", Autocomplete: "current-password"},
		},
		Buttons: []formPageButton{
			{Label: "Sign in"},
		},
	})
}

func (p *identityProvider) renderConsentForm(w http.ResponseWriter, r *http.Request, params url.Values, code, clientID, sessionID string) {
	csrfToken := p.issueCSRFToken("session:" + sessionID)
	consentParams := filterFormParams(params, "username", "password", "confirm")
	consentParams.Set("code", code)
	p.renderFormPage(w, r, formPage{
		Title:   p.title,
		Action:  p.base + "/authorize?" + consentParams.Encode(),
		Message: fmt.Sprintf("Allow %s to access these scopes: %s?", clientID, params.Get("scope")),
		TestID:  "page-consent",
		Params: url.Values{
			"csrf_token": {csrfToken},
		},
		Buttons: []formPageButton{
			{Name: "confirm", Value: "yes", Label: "Allow"},
			{Name: "confirm", Value: "no", Label: "Deny"},
		},
	})
}

func (p *identityProvider) renderLogoutForm(w http.ResponseWriter, r *http.Request, params url.Values, sessionID string) {
	csrfToken := p.issueCSRFToken("session:" + sessionID)
	p.renderFormPage(w, r, formPage{
		Title:   p.title,
		Action:  p.base + "/end-session?" + filterFormParams(params, "confirm", "csrf_token").Encode(),
		Message: "Log out of this identity provider?",
		TestID:  "page-logout",
		Params: url.Values{
			"csrf_token": {csrfToken},
		},
		Buttons: []formPageButton{
			{Name: "confirm", Value: "yes", Label: "Log out"},
			{Name: "confirm", Value: "no", Label: "Cancel"},
		},
	})
}

func (p *identityProvider) renderLogoutCanceled(w http.ResponseWriter, r *http.Request, clientID string) {
	var links []formPageLink
	if clientID != "" {
		if client, ok := p.clients[clientID]; ok {
			if returnURL := client.postLogoutRedirectURL.String(); returnURL != "" {
				links = append(links, formPageLink{Href: returnURL, Label: "Return to application", TestID: "return-link"})
			}
		}
	}
	p.renderFormPage(w, r, formPage{
		Title:   p.title,
		Message: "Logout canceled. You are still signed in.",
		TestID:  "page-logout-canceled",
		Links:   links,
	})
}

func (p *identityProvider) renderLogoutComplete(w http.ResponseWriter, r *http.Request, clientID, postLogoutRedirectURI, state string) {
	if postLogoutRedirectURI != "" {
		postLogoutRedirectURL := p.clients[clientID].postLogoutRedirectURL
		if state != "" {
			redirectQuery := postLogoutRedirectURL.Query()
			redirectQuery.Set("state", state)
			postLogoutRedirectURL.RawQuery = redirectQuery.Encode()
		}
		status := http.StatusFound
		if r.Method == http.MethodPost {
			status = http.StatusSeeOther
		}
		http.Redirect(w, r, postLogoutRedirectURL.String(), status)
		return
	}
	var links []formPageLink
	if clientID != "" {
		if client, ok := p.clients[clientID]; ok {
			if returnURL := client.postLogoutRedirectURL.String(); returnURL != "" {
				links = append(links, formPageLink{Href: returnURL, Label: "Return to application", TestID: "return-link"})
			}
		}
	}
	p.renderFormPage(w, r, formPage{
		Title:   p.title,
		Message: "You have been signed out.",
		TestID:  "page-logout-complete",
		Links:   links,
	})
}

// -------------------------------------------------------------------------- //

func (p *identityProvider) resolveIDTokenHint(token string) (tokenHint, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tokenHint{}, false
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return tokenHint{}, false
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return tokenHint{}, false
	}
	if header.Alg != "RS256" || header.Typ != "JWT" {
		return tokenHint{}, false
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return tokenHint{}, false
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&p.privKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		return tokenHint{}, false
	}

	var claims struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tokenHint{}, false
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return tokenHint{}, false
	}

	var aud string
	if err := json.Unmarshal(claims.Aud, &aud); err != nil {
		var auds []string
		if err := json.Unmarshal(claims.Aud, &auds); err != nil || len(auds) == 0 {
			return tokenHint{}, false
		}
		aud = auds[0]
	}

	if claims.Iss != p.issuer || claims.Sub == "" || aud == "" {
		return tokenHint{}, false
	}

	return tokenHint{sub: claims.Sub, aud: aud}, true
}

func (p *identityProvider) authorizeUser(w http.ResponseWriter, r *http.Request, authorization authorizeRequest, username string, authenticatedAt time.Time, sessionID string) {
	issuedCode := rand.Text()

	p.mu.Lock()
	p.pendingCodes[issuedCode] = pendingCode{
		clientID:        authorization.client.id,
		username:        username,
		redirectURI:     authorization.redirectURI,
		codeChallenge:   authorization.codeChallenge,
		nonce:           authorization.nonce,
		state:           authorization.state,
		scope:           authorization.scope,
		sessionID:       sessionID,
		consentRequired: authorization.consentRequired,
		authenticatedAt: authenticatedAt,
		createdAt:       time.Now(),
	}
	p.removeExpiredState()
	p.mu.Unlock()

	if authorization.consentRequired {
		p.renderConsentForm(w, r, authorization.params, issuedCode, authorization.client.id, sessionID)
		return
	}
	redirectWithCode(w, r, p.issuer, authorization.redirectURI, issuedCode, authorization.state)
}

func (p *identityProvider) exchangeAuthorizationCode(w http.ResponseWriter, r *http.Request, client client) {
	code := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	codeVerifier := r.PostForm.Get("code_verifier")

	if code == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Missing required parameter: code")
		return
	}
	p.mu.Lock()
	pendingCode, codeKnown := p.pendingCodes[code]
	codeExpired := codeKnown && isPendingCodeExpired(pendingCode, time.Now())
	codePendingConsent := codeKnown && pendingCode.consentRequired
	codeReused := codeKnown && !pendingCode.consumedAt.IsZero()
	if codeExpired {
		delete(p.pendingCodes, code)
	}
	p.mu.Unlock()

	if !codeKnown || codeExpired || codePendingConsent {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid, expired, or previously used authorization code")
		return
	}

	if pendingCode.clientID != client.id {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code was issued to a different client")
		return
	}

	if redirectURI != "" && redirectURI != pendingCode.redirectURI.String() {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Redirect URI does not match the one used in the authorization request")
		return
	}

	if codeVerifier == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Missing required parameter: code_verifier")
		return
	}
	if !isValidPKCEValue(codeVerifier) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid code_verifier")
		return
	}
	verifierHash := sha256.Sum256([]byte(codeVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])
	if subtle.ConstantTimeCompare([]byte(expectedChallenge), []byte(pendingCode.codeChallenge)) != 1 {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code verifier does not match code challenge")
		return
	}

	if codeReused {
		p.mu.Lock()
		for tokenValue, accessToken := range p.accessTokens {
			if accessToken.code == code {
				delete(p.accessTokens, tokenValue)
			}
		}
		for k, v := range p.refreshTokens {
			if v.code == code {
				delete(p.refreshTokens, k)
			}
		}
		delete(p.pendingCodes, code)
		p.mu.Unlock()
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid, expired, or previously used authorization code")
		return
	}

	user := p.users[pendingCode.username]
	accessTokenValue := rand.Text()
	refreshTokenValue := rand.Text()
	idToken, err := p.mintIDToken(user, client, pendingCode, accessTokenValue)
	if err != nil {
		http.Error(w, "Failed to mint ID token", http.StatusInternalServerError)
		return
	}

	issuedAt := time.Now()
	p.mu.Lock()
	if latest, ok := p.pendingCodes[code]; !ok || !latest.consumedAt.IsZero() {
		for tokenValue, accessToken := range p.accessTokens {
			if accessToken.code == code {
				delete(p.accessTokens, tokenValue)
			}
		}
		for k, v := range p.refreshTokens {
			if v.code == code {
				delete(p.refreshTokens, k)
			}
		}
		delete(p.pendingCodes, code)
		p.mu.Unlock()
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid, expired, or previously used authorization code")
		return
	}
	pendingCode.consumedAt = time.Now()
	p.pendingCodes[code] = pendingCode
	p.accessTokens[accessTokenValue] = accessToken{
		clientID: client.id,
		username: user.username,
		scope:    pendingCode.scope,
		code:     code,
		expiry:   issuedAt.Add(accessTokenTTL),
	}
	p.refreshTokens[refreshTokenValue] = refreshToken{
		clientID:         client.id,
		username:         user.username,
		scope:            pendingCode.scope,
		code:             code,
		sessionID:        pendingCode.sessionID,
		authenticatedAt:  pendingCode.authenticatedAt,
		sessionStartedAt: issuedAt,
		createdAt:        issuedAt,
	}
	p.removeExpiredState()
	p.mu.Unlock()

	response := map[string]any{
		"access_token":  accessTokenValue,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"scope":         pendingCode.scope,
		"id_token":      idToken,
		"refresh_token": refreshTokenValue,
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *identityProvider) exchangeRefreshToken(w http.ResponseWriter, r *http.Request, client client) {
	refreshTokenValue := r.PostForm.Get("refresh_token")
	if refreshTokenValue == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Missing required parameter: refresh_token")
		return
	}

	p.mu.Lock()
	storedRefreshToken, tokenKnown := p.refreshTokens[refreshTokenValue]
	tokenExpired := tokenKnown && isRefreshTokenExpired(storedRefreshToken, time.Now())
	tokenReused := tokenKnown && !storedRefreshToken.consumedAt.IsZero()
	if tokenExpired {
		delete(p.refreshTokens, refreshTokenValue)
	}
	p.mu.Unlock()

	if !tokenKnown || tokenExpired {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return
	}
	if storedRefreshToken.clientID != client.id {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token was issued to a different client")
		return
	}
	effectiveAccessScope, ok := validateRefreshScope(r.PostForm.Get("scope"), storedRefreshToken.scope)
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "Requested scope exceeds the original grant")
		return
	}

	if tokenReused {
		p.mu.Lock()
		for k, v := range p.refreshTokens {
			if v.code == storedRefreshToken.code {
				delete(p.refreshTokens, k)
			}
		}
		for k, v := range p.accessTokens {
			if v.code == storedRefreshToken.code {
				delete(p.accessTokens, k)
			}
		}
		p.mu.Unlock()
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return
	}

	user := p.users[storedRefreshToken.username]
	newAccessTokenValue := rand.Text()
	newRefreshTokenValue := rand.Text()

	idToken, err := p.mintIDToken(user, client, pendingCode{
		sessionID:       storedRefreshToken.sessionID,
		authenticatedAt: storedRefreshToken.authenticatedAt,
		scope:           effectiveAccessScope,
	}, newAccessTokenValue)
	if err != nil {
		http.Error(w, "Failed to mint ID token", http.StatusInternalServerError)
		return
	}

	issuedAt := time.Now()
	p.mu.Lock()
	if latest, ok := p.refreshTokens[refreshTokenValue]; !ok || !latest.consumedAt.IsZero() {
		for k, v := range p.refreshTokens {
			if v.code == storedRefreshToken.code {
				delete(p.refreshTokens, k)
			}
		}
		for k, v := range p.accessTokens {
			if v.code == storedRefreshToken.code {
				delete(p.accessTokens, k)
			}
		}
		p.mu.Unlock()
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return
	}
	storedRefreshToken.consumedAt = time.Now()
	p.refreshTokens[refreshTokenValue] = storedRefreshToken
	p.accessTokens[newAccessTokenValue] = accessToken{
		clientID: client.id,
		username: user.username,
		scope:    effectiveAccessScope,
		code:     storedRefreshToken.code,
		expiry:   issuedAt.Add(accessTokenTTL),
	}
	p.refreshTokens[newRefreshTokenValue] = refreshToken{
		clientID:         client.id,
		username:         storedRefreshToken.username,
		scope:            storedRefreshToken.scope,
		code:             storedRefreshToken.code,
		sessionID:        storedRefreshToken.sessionID,
		authenticatedAt:  storedRefreshToken.authenticatedAt,
		sessionStartedAt: storedRefreshToken.sessionStartedAt,
		createdAt:        issuedAt,
	}
	p.removeExpiredState()
	p.mu.Unlock()

	response := map[string]any{
		"access_token":  newAccessTokenValue,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"scope":         effectiveAccessScope,
		"refresh_token": newRefreshTokenValue,
		"id_token":      idToken,
	}
	writeJSON(w, http.StatusOK, response)
}

// -------------------------------------------------------------------------- //

func (p *identityProvider) cookieName(baseName string) string {
	prefix := ""
	if strings.HasPrefix(p.issuer, "https://") {
		prefix += "__"
		if p.base == "" {
			prefix += "Host-"
		}
		prefix += "Http-"
	}
	return prefix + baseName
}

func (p *identityProvider) newCookie(baseName string) *http.Cookie {
	path := p.base
	if path == "" {
		path = "/"
	}
	return &http.Cookie{ // #nosec G124
		Name:     p.cookieName(baseName),
		Path:     path,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(p.issuer, "https://"),
	}
}

func (p *identityProvider) readCookie(r *http.Request, baseName string) string {
	if cookie, err := r.Cookie(p.cookieName(baseName)); err == nil {
		return cookie.Value
	}
	return ""
}

func (p *identityProvider) readPreAuthSession(r *http.Request) string {
	return p.readCookie(r, preAuthSessionCookieBaseName)
}

func (p *identityProvider) issuePreAuthSession(w http.ResponseWriter) string {
	preAuthID := rand.Text()
	cookie := p.newCookie(preAuthSessionCookieBaseName) // #nosec G124
	cookie.Value = preAuthID
	cookie.MaxAge = int(loginActionTTL.Seconds())
	http.SetCookie(w, cookie)
	return preAuthID
}

func (p *identityProvider) clearPreAuthSession(w http.ResponseWriter) {
	cookie := p.newCookie(preAuthSessionCookieBaseName) // #nosec G124
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
}

func (p *identityProvider) readSession(r *http.Request) string {
	return p.readCookie(r, sessionCookieBaseName)
}

func (p *identityProvider) issueSession(w http.ResponseWriter, username string, authenticatedAt time.Time) string {
	sessionID := rand.Text()
	p.mu.Lock()
	p.sessions[sessionID] = session{username: username, authenticatedAt: authenticatedAt, lastSeenAt: authenticatedAt}
	p.removeExpiredState()
	p.mu.Unlock()
	cookie := p.newCookie(sessionCookieBaseName) // #nosec G124
	cookie.Value = sessionID
	http.SetCookie(w, cookie)
	return sessionID
}

func (p *identityProvider) clearSession(w http.ResponseWriter, sessionID string) {
	if sessionID != "" {
		p.mu.Lock()
		delete(p.sessions, sessionID)
		p.removeExpiredState()
		p.mu.Unlock()
	}
	cookie := p.newCookie(sessionCookieBaseName) // #nosec G124
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
}

func (p *identityProvider) resumeSession(sessionID string) (session, bool) {
	if sessionID == "" {
		return session{}, false
	}
	now := time.Now()
	p.mu.Lock()
	currentSession, ok := p.sessions[sessionID]
	if ok && isSessionExpired(currentSession, now) {
		delete(p.sessions, sessionID)
		ok = false
	}
	if ok {
		currentSession.lastSeenAt = now
		p.sessions[sessionID] = currentSession
	}
	p.removeExpiredState()
	p.mu.Unlock()
	if !ok {
		return session{}, false
	}
	return currentSession, true
}

func (p *identityProvider) canReuseSession(currentSession session, hintedUser tokenHint, maxAge time.Duration, maxAgeRequested bool) bool {
	currentUser, ok := p.users[currentSession.username]
	if !ok {
		return false
	}
	if hintedUser.sub != "" && currentUser.sub != hintedUser.sub {
		return false
	}
	if maxAgeRequested && time.Since(currentSession.authenticatedAt) > maxAge {
		return false
	}
	return true
}

// -------------------------------------------------------------------------- //

const (
	csrfNonceSize  = 16
	csrfExpirySize = 8
	csrfMACSize    = 32
	csrfTokenSize  = csrfNonceSize + csrfExpirySize + csrfMACSize
)

func (p *identityProvider) issueCSRFToken(ownerID string) string {
	payload := make([]byte, csrfTokenSize)
	nonce := payload[:csrfNonceSize]
	expiryBytes := payload[csrfNonceSize : csrfNonceSize+csrfExpirySize]
	sig := payload[csrfNonceSize+csrfExpirySize:]
	_, _ = rand.Read(nonce)
	expiry := max(time.Now().Add(loginActionTTL).Unix(), 0)
	binary.BigEndian.PutUint64(expiryBytes, uint64(expiry))
	mac := hmac.New(sha256.New, p.csrfKey)
	mac.Write([]byte(ownerID))
	mac.Write(nonce)
	mac.Write(expiryBytes)
	mac.Sum(sig[:0])
	return base64.RawURLEncoding.EncodeToString(payload)
}

func (p *identityProvider) validateCSRFToken(token, ownerID string) bool {
	if token == "" || ownerID == "" {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != csrfTokenSize {
		return false
	}
	nonce := decoded[:csrfNonceSize]
	expiryBytes := decoded[csrfNonceSize : csrfNonceSize+csrfExpirySize]
	sig := decoded[csrfNonceSize+csrfExpirySize:]
	expiryUint := binary.BigEndian.Uint64(expiryBytes)
	if expiryUint > uint64(math.MaxInt64) || time.Now().Unix() > int64(expiryUint) {
		return false
	}
	mac := hmac.New(sha256.New, p.csrfKey)
	mac.Write([]byte(ownerID))
	mac.Write(nonce)
	mac.Write(expiryBytes)
	return hmac.Equal(sig, mac.Sum(nil))
}

func (p *identityProvider) removeExpiredState() {
	now := time.Now()
	for k, v := range p.sessions {
		if isSessionExpired(v, now) {
			delete(p.sessions, k)
		}
	}
	for k, v := range p.pendingCodes {
		if isPendingCodeExpired(v, now) {
			delete(p.pendingCodes, k)
		}
	}
	for k, v := range p.accessTokens {
		if now.After(v.expiry) {
			delete(p.accessTokens, k)
		}
	}
	for k, v := range p.refreshTokens {
		if isRefreshTokenExpired(v, now) {
			delete(p.refreshTokens, k)
		}
	}
}

// -------------------------------------------------------------------------- //

func isSessionExpired(currentSession session, now time.Time) bool {
	return now.Sub(currentSession.lastSeenAt) > sessionIdleTTL || now.Sub(currentSession.authenticatedAt) > sessionMaxTTL
}

func isRefreshTokenExpired(token refreshToken, now time.Time) bool {
	return now.Sub(token.createdAt) > refreshTokenIdleTTL || now.Sub(token.sessionStartedAt) > refreshTokenMaxTTL
}

func isPendingCodeExpired(code pendingCode, now time.Time) bool {
	ttl := codeTTL
	if code.consentRequired {
		ttl = loginActionTTL
	}
	return now.Sub(code.createdAt) > ttl
}

func (p *identityProvider) authenticateEndUser(username, password string) (user, bool) {
	authenticatedUser, ok := p.users[username]
	if !ok || subtle.ConstantTimeCompare([]byte(password), []byte(authenticatedUser.password)) != 1 {
		return user{}, false
	}
	return authenticatedUser, true
}

func (p *identityProvider) authenticateClient(w http.ResponseWriter, r *http.Request) (client, bool) {
	clientID, clientSecret, err := parseClientCredentials(r)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Multiple client authentication mechanisms are not allowed")
		return client{}, false
	}
	c, ok := p.clients[clientID]
	if !ok {
		if _, _, ok := r.BasicAuth(); ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		}
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return client{}, false
	}
	if c.isPublic {
		if _, _, usedBasic := r.BasicAuth(); usedBasic || clientSecret != "" {
			writeTokenError(w, http.StatusBadRequest, "invalid_request", "Public clients must not send a client secret")
			return client{}, false
		}
		return c, true
	}
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(c.secret)) != 1 {
		if _, _, ok := r.BasicAuth(); ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		}
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return client{}, false
	}
	return c, true
}

func (p *identityProvider) authenticateProtectedResource(w http.ResponseWriter, r *http.Request) (client, bool) {
	c, ok := p.authenticateClient(w, r)
	if !ok {
		return client{}, false
	}
	if c.isPublic {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Protected resources must authenticate to the introspection endpoint")
		return client{}, false
	}
	return c, true
}

func (p *identityProvider) resolveBearerToken(token string) (user, accessToken, bool) {
	p.mu.Lock()
	storedAccessToken, tokenKnown := p.accessTokens[token]
	p.mu.Unlock()

	if !tokenKnown || time.Now().After(storedAccessToken.expiry) {
		return user{}, accessToken{}, false
	}

	return p.users[storedAccessToken.username], storedAccessToken, true
}

// -------------------------------------------------------------------------- //

func (p *identityProvider) mintIDToken(user user, client client, code pendingCode, accessToken string) (string, error) {
	now := time.Now().Unix()

	atHash := sha256.Sum256([]byte(accessToken))
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": p.keyID,
	}
	payload := map[string]any{
		"iss":       p.issuer,
		"sub":       user.sub,
		"aud":       client.id,
		"iat":       now,
		"exp":       now + int64(accessTokenTTL.Seconds()),
		"auth_time": code.authenticatedAt.Unix(),
		"at_hash":   base64.RawURLEncoding.EncodeToString(atHash[:len(atHash)/2]),
	}
	if code.nonce != "" {
		payload["nonce"] = code.nonce
	}
	if code.sessionID != "" {
		payload["sid"] = code.sessionID
	}
	for claim, value := range p.buildClaimsForScope(user, code.scope) {
		if claim != "sub" {
			payload[claim] = value
		}
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.privKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

func (p *identityProvider) mintLogoutToken(user user, client client, sessionID string) (string, error) {
	now := time.Now().Unix()

	header := map[string]string{
		"alg": "RS256",
		"typ": "logout+jwt",
		"kid": p.keyID,
	}
	payload := map[string]any{
		"iss": p.issuer,
		"sub": user.sub,
		"aud": client.id,
		"iat": now,
		"exp": now + 120,
		"jti": rand.Text(),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	if client.backchannelLogoutSessionRequired && sessionID != "" {
		payload["sid"] = sessionID
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.privKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

func (p *identityProvider) sendBackchannelLogout(client client, user user, sessionID string) {
	logoutToken, err := p.mintLogoutToken(user, client, sessionID)
	if err != nil {
		slog.Error("failed to mint logout token", "client_id", client.id, "error", err)
		return
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).PostForm(client.backchannelLogoutURI.String(), url.Values{
		"logout_token": {logoutToken},
	})
	if err != nil {
		slog.Error("back-channel logout request failed", "client_id", client.id, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		slog.Error("back-channel logout rejected", "client_id", client.id, "status", resp.Status)
	}
}

func (p *identityProvider) buildClaimsForScope(user user, scope string) map[string]any {
	claims := map[string]any{"sub": user.sub}
	for candidateScope := range strings.FieldsSeq(scope) {
		switch candidateScope {
		case "email":
			claims["email"] = user.email
			claims["email_verified"] = user.emailVerified
		case "profile":
			claims["name"] = user.name
			claims["preferred_username"] = user.preferredUsername
			if user.profile != "" {
				claims["profile"] = user.profile
			}
			if user.picture != "" {
				claims["picture"] = user.picture
			}
			if user.locale != "" {
				claims["locale"] = user.locale
			}
		case "groups":
			claims["groups"] = user.groups
		}
	}
	return claims
}

// -------------------------------------------------------------------------- //

func redirectWithError(w http.ResponseWriter, r *http.Request, issuer string, redirectURL url.URL, state, errorCode, errorDescription string) {
	redirectQuery := redirectURL.Query()
	redirectQuery.Set("error", errorCode)
	redirectQuery.Set("error_description", errorDescription)
	redirectQuery.Set("iss", issuer)
	if state != "" {
		redirectQuery.Set("state", state)
	}
	redirectURL.RawQuery = redirectQuery.Encode()
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	http.Redirect(w, r, redirectURL.String(), status) // #nosec G710
}

func redirectWithCode(w http.ResponseWriter, r *http.Request, issuer string, redirectURL url.URL, code, state string) {
	redirectQuery := redirectURL.Query()
	redirectQuery.Set("code", code)
	redirectQuery.Set("iss", issuer)
	if state != "" {
		redirectQuery.Set("state", state)
	}
	redirectURL.RawQuery = redirectQuery.Encode()
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	http.Redirect(w, r, redirectURL.String(), status) // #nosec G710
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeTokenError(w http.ResponseWriter, status int, errorCode, errorDescription string) {
	writeJSON(w, status, map[string]string{"error": errorCode, "error_description": errorDescription})
}

func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	return r.ParseForm()
}

func parseClientCredentials(r *http.Request) (clientID, clientSecret string, err error) {
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		if decoded, err := url.QueryUnescape(clientID); err == nil {
			clientID = decoded
		}
		if decoded, err := url.QueryUnescape(clientSecret); err == nil {
			clientSecret = decoded
		}
		if r.PostForm.Get("client_id") != "" || r.PostForm.Get("client_secret") != "" {
			return "", "", errors.New("multiple client authentication mechanisms are not allowed")
		}
		return clientID, clientSecret, nil
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"), nil
}

// -------------------------------------------------------------------------- //

func hasUniqueParams(params url.Values) bool {
	for _, values := range params {
		if len(values) > 1 {
			return false
		}
	}
	return true
}

func filterFormParams(params url.Values, skipped ...string) url.Values {
	filtered := url.Values{}
	for key, values := range params {
		skip := slices.Contains(skipped, key)
		if !skip {
			filtered[key] = values
		}
	}
	return filtered
}

func validateAuthorizeParams(params url.Values) (errorCode, errorDesc string) {
	if params.Get("request") != "" {
		return "request_not_supported", "Request parameter is not supported"
	}
	if params.Get("request_uri") != "" {
		return "request_uri_not_supported", "Request URI parameter is not supported"
	}
	for _, name := range []string{"response_type", "scope", "code_challenge", "code_challenge_method"} {
		if params.Get(name) == "" {
			return "invalid_request", "Missing required parameter: " + name
		}
	}
	if params.Get("response_type") != "code" {
		return "unsupported_response_type", "Only 'code' response type is supported"
	}
	if p := params.Get("prompt"); p != "" && !isValidPrompt(p) {
		return "invalid_request", "Invalid prompt value"
	}
	if !isValidPKCEValue(params.Get("code_challenge")) {
		return "invalid_request", "Invalid code_challenge"
	}
	if params.Get("code_challenge_method") != "S256" {
		return "invalid_request", "Only S256 code challenge method is supported"
	}
	return "", ""
}

func filterScope(scope string) (string, bool) {
	var kept []string
	for candidateScope := range strings.FieldsSeq(scope) {
		switch candidateScope {
		case "openid", "profile", "email", "groups":
			kept = append(kept, candidateScope)
		}
	}
	if !slices.Contains(kept, "openid") {
		return "", false
	}
	return strings.Join(kept, " "), true
}

func validateRefreshScope(requested, granted string) (string, bool) {
	if strings.TrimSpace(requested) == "" {
		return granted, true
	}
	grantedScopes := map[string]struct{}{}
	for candidateScope := range strings.FieldsSeq(granted) {
		grantedScopes[candidateScope] = struct{}{}
	}
	var kept []string
	for candidateScope := range strings.FieldsSeq(requested) {
		if _, ok := grantedScopes[candidateScope]; !ok {
			return "", false
		}
		if !slices.Contains(kept, candidateScope) {
			kept = append(kept, candidateScope)
		}
	}
	if len(kept) == 0 {
		return granted, true
	}
	return strings.Join(kept, " "), true
}

func hasPromptValue(prompt, want string) bool {
	for value := range strings.FieldsSeq(prompt) {
		if value == want {
			return true
		}
	}
	return false
}

func parseMaxAge(raw string) (time.Duration, bool, error) {
	if raw == "" {
		return 0, false, nil
	}
	maxAgeSeconds, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, false, err
	}
	return time.Duration(maxAgeSeconds) * time.Second, true, nil
}

func isValidPrompt(prompt string) bool {
	values := strings.Fields(prompt)
	if len(values) == 0 {
		return false
	}
	sawNone := false
	for _, value := range values {
		switch value {
		case "none":
			sawNone = true
		case "login", "consent", "select_account":
		default:
			return false
		}
	}
	return !sawNone || len(values) == 1
}

func isValidPKCEValue(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

func isLoopbackURL(u *url.URL) bool {
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isAllowedRedirectURL(redirectURL, redirectURI url.URL, allowLoopbackPort bool) bool {
	if redirectURL.Host != redirectURI.Host &&
		!(allowLoopbackPort && isLoopbackURL(&redirectURL) && isLoopbackURL(&redirectURI) &&
			redirectURL.Hostname() == redirectURI.Hostname()) {
		return false
	}
	return redirectURL.Scheme == redirectURI.Scheme &&
		redirectURL.User == nil && redirectURI.User == nil &&
		redirectURL.EscapedPath() == redirectURI.EscapedPath() &&
		redirectURL.ForceQuery == redirectURI.ForceQuery &&
		redirectURL.RawQuery == redirectURI.RawQuery &&
		redirectURL.Fragment == redirectURI.Fragment
}

func validateIssuerURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("not a valid URL: %w", err)
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("must be an absolute URL: %q", rawURL)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("must be http or https: %q", rawURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("must include a host: %q", rawURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("must not include user info: %q", rawURL)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("must not contain a fragment: %q", rawURL)
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("must not contain a query string: %q", rawURL)
	}
	return u, nil
}

func validateRedirectURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("not a valid URL: %w", err)
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("must be an absolute URL: %q", rawURL)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("must be http or https: %q", rawURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("must include a host: %q", rawURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("must not include user info: %q", rawURL)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("must not contain a fragment: %q", rawURL)
	}
	return u, nil
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

func isValidEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Name == "" && addr.Address == email && isASCII(email)
}

// -------------------------------------------------------------------------- //

func scanLabels(environ []string, prefix, suffix string) map[string]struct{} {
	labels := map[string]struct{}{}
	for _, env := range environ {
		key, _, ok := strings.Cut(env, "=")
		if !ok || !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
			continue
		}
		label := key[len(prefix) : len(key)-len(suffix)]
		if label != "" {
			labels[label] = struct{}{}
		}
	}
	return labels
}

func loadClients(environ []string, lookupEnv func(string) string) (map[string]client, error) {
	const prefix = "SIMPLE_IDP_CLIENT_"

	clients := map[string]client{}
	for label := range scanLabels(environ, prefix, "_ID") {
		id := lookupEnv(prefix + label + "_ID")
		secret := lookupEnv(prefix + label + "_SECRET")
		rawRedirectURL := lookupEnv(prefix + label + "_REDIRECT_URL")
		if id == "" || rawRedirectURL == "" {
			return nil, fmt.Errorf("incomplete client configuration for label %q", label)
		}
		if _, dup := clients[id]; dup {
			return nil, fmt.Errorf("duplicate client ID %q", id)
		}
		redirectURL, err := validateRedirectURL(rawRedirectURL)
		if err != nil {
			return nil, fmt.Errorf("client %q redirect URL: %w", label, err)
		}
		isPublic := secret == ""
		if isPublic && !isLoopbackURL(redirectURL) {
			return nil, fmt.Errorf("client %q: public clients (no secret) must use a loopback redirect URL", label)
		}
		var postLogoutRedirectURL url.URL
		if raw := lookupEnv(prefix + label + "_POST_LOGOUT_REDIRECT_URL"); raw != "" {
			parsed, err := validateRedirectURL(raw)
			if err != nil {
				return nil, fmt.Errorf("client %q post-logout redirect URL: %w", label, err)
			}
			postLogoutRedirectURL = *parsed
		}
		var backchannelLogoutURI url.URL
		if raw := lookupEnv(prefix + label + "_BACKCHANNEL_LOGOUT_URI"); raw != "" {
			parsed, err := url.Parse(raw)
			if err != nil || !parsed.IsAbs() || (parsed.Scheme != "https" && parsed.Scheme != "http") {
				return nil, fmt.Errorf("client %q backchannel logout URI: must be an absolute http or https URL", label)
			}
			backchannelLogoutURI = *parsed
		}
		backchannelLogoutSessionRequired := lookupEnv(prefix+label+"_BACKCHANNEL_LOGOUT_SESSION_REQUIRED") == "true"
		clients[id] = client{
			id:                               id,
			secret:                           secret,
			isPublic:                         isPublic,
			redirectURL:                      *redirectURL,
			postLogoutRedirectURL:            postLogoutRedirectURL,
			backchannelLogoutURI:             backchannelLogoutURI,
			backchannelLogoutSessionRequired: backchannelLogoutSessionRequired,
		}
		slog.LogAttrs(context.Background(), slog.LevelInfo, "registered client", slog.String("label", label), slog.String("client_id", id))
	}

	if len(clients) == 0 {
		return nil, errors.New("no clients configured (set SIMPLE_IDP_CLIENT_<LABEL>_ID/SECRET/REDIRECT_URL)")
	}

	return clients, nil
}

func loadUsers(environ []string, lookupEnv func(string) string) (map[string]user, error) {
	const prefix = "SIMPLE_IDP_USER_"

	users := map[string]user{}
	subs := map[string]struct{}{}

	for label := range scanLabels(environ, prefix, "_USERNAME") {
		username := envOr(lookupEnv, prefix+label+"_USERNAME", "")
		password := envOr(lookupEnv, prefix+label+"_PASSWORD", "")
		sub := envOr(lookupEnv, prefix+label+"_SUB", username)
		name := envOr(lookupEnv, prefix+label+"_NAME", username)
		preferredUsername := envOr(lookupEnv, prefix+label+"_PREFERRED_USERNAME", username)
		email := envOr(lookupEnv, prefix+label+"_EMAIL", username+"@localhost")
		emailVerified := envOr(lookupEnv, prefix+label+"_EMAIL_VERIFIED", "true") == "true"
		profile := envOr(lookupEnv, prefix+label+"_PROFILE", "")
		picture := envOr(lookupEnv, prefix+label+"_PICTURE", "")
		locale := envOr(lookupEnv, prefix+label+"_LOCALE", "")
		groups := envSplit(lookupEnv, prefix+label+"_GROUPS", ",")

		if username == "" || password == "" {
			return nil, fmt.Errorf("incomplete user configuration for label %q", label)
		}

		if _, dup := users[username]; dup {
			return nil, fmt.Errorf("duplicate username %q", username)
		}

		if len(sub) > 255 || !isASCII(sub) {
			return nil, fmt.Errorf("user %q: sub claim must not exceed 255 ASCII characters", label)
		}
		if _, dup := subs[sub]; dup {
			return nil, fmt.Errorf("duplicate sub claim %q", sub)
		}
		subs[sub] = struct{}{}

		if !isValidEmail(email) {
			return nil, fmt.Errorf("user %q: email must be a valid RFC 5322 addr-spec", label)
		}

		users[username] = user{
			username:          username,
			password:          password,
			sub:               sub,
			name:              name,
			preferredUsername: preferredUsername,
			email:             email,
			emailVerified:     emailVerified,
			profile:           profile,
			picture:           picture,
			locale:            locale,
			groups:            groups,
		}
		slog.LogAttrs(context.Background(), slog.LevelInfo, "registered user", slog.String("label", label), slog.String("username", username))
	}

	if len(users) == 0 {
		return nil, errors.New("no users configured (set SIMPLE_IDP_USER_<LABEL>_USERNAME/PASSWORD)")
	}

	return users, nil
}

func loadOrGenerateKey(lookupEnv func(string) string, readFile func(string) ([]byte, error)) (*rsa.PrivateKey, error) {
	if b64 := lookupEnv("SIMPLE_IDP_KEY_B64"); b64 != "" {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode SIMPLE_IDP_KEY_B64: %w", err)
		}
		return parseRSAPKCS8(der, "SIMPLE_IDP_KEY_B64")
	}

	if path := lookupEnv("SIMPLE_IDP_KEY_FILE"); path != "" {
		data, err := readFile(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %q: %w", path, err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM block found in key file %q", path)
		}
		return parseRSAPKCS8(block.Bytes, path)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	slog.Info("generated ephemeral RSA key")
	return key, nil
}

func parseRSAPKCS8(der []byte, source string) (*rsa.PrivateKey, error) {
	parsedKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key from %q: %w", source, err)
	}
	key, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key from %q is not RSA", source)
	}
	slog.LogAttrs(context.Background(), slog.LevelInfo, "loaded RSA key", slog.String("source", source))
	return key, nil
}

// -------------------------------------------------------------------------- //

func envOr(lookupEnv func(string) string, name, fallback string) string {
	if v := lookupEnv(name); v != "" {
		return v
	}
	return fallback
}

func envRequired(lookupEnv func(string) string, name string) (string, error) {
	v := lookupEnv(name)
	if v == "" {
		return "", fmt.Errorf("required environment variable not set: %s", name)
	}
	return v, nil
}

func envSplit(lookupEnv func(string) string, name, sep string) []string {
	if v := lookupEnv(name); v != "" {
		return strings.Split(v, sep)
	}
	return nil
}
