// Minimal OIDC Identity Provider that authenticates users via a login form against
// static credentials and completes the full OIDC Authorization Code flow with PKCE.
// Confidential clients can also use the client credentials grant, and access tokens
// are JWTs (RFC 9068) that APIs can validate against the JWKS endpoint.
//
// Configuration is entirely through environment variables:
//
// SIMPLE_IDP_LISTEN                 - listen address (default ":8227")
// SIMPLE_IDP_ISSUER                 - issuer URL as seen by clients (required)
// SIMPLE_IDP_TITLE                  - login page title (default: "Simple IdP")
// SIMPLE_IDP_LOGO                   - logo URL or data URI shown instead of the title (default: none)
// SIMPLE_IDP_FAVICON                - favicon URL or data URI (default: blank icon)
// SIMPLE_IDP_ACCENT_COLOR           - accent color for the pages (default: "oklch(49% 0.19 264)")
// SIMPLE_IDP_COLOR_SCHEME           - CSS color-scheme value for the pages (default: "light dark")
// SIMPLE_IDP_LANGUAGE               - language for every page (default: negotiated)
// SIMPLE_IDP_EDIT_PROFILE           - let users edit their profile, not persisted (default: "false")
// SIMPLE_IDP_SESSION_IDLE_TTL       - session idle timeout (default: "30m")
// SIMPLE_IDP_SESSION_MAX_TTL        - session maximum lifetime (default: "10h")
// SIMPLE_IDP_ACCESS_TOKEN_TTL       - access and ID token lifetime (default: "5m")
// SIMPLE_IDP_REFRESH_TOKEN_IDLE_TTL - refresh token idle timeout (default: "30m")
// SIMPLE_IDP_REFRESH_TOKEN_MAX_TTL  - refresh token maximum lifetime (default: "10h")
// SIMPLE_IDP_KEY_ID                 - JWKS key ID (default: "simpleidp")
// SIMPLE_IDP_KEY_FILE               - PEM file for PKCS8 RSA private key (generated in memory if empty)
// SIMPLE_IDP_KEY_B64                - base64-encoded PKCS8 RSA private key (alternative to KEY_FILE)
// SIMPLE_IDP_LOG_LEVEL              - log level: "debug", "info", "warn", or "error" (default: "info")
//
// Clients are configured with a label prefix (the label is arbitrary, used only for grouping):
//
// SIMPLE_IDP_CLIENT_<LABEL>_ID                                  - client ID
// SIMPLE_IDP_CLIENT_<LABEL>_SECRET                              - client secret (optional for loopback/native clients)
// SIMPLE_IDP_CLIENT_<LABEL>_AUDIENCE                            - "aud" claim of access tokens (default: client ID)
// SIMPLE_IDP_CLIENT_<LABEL>_REDIRECT_URL                        - allowed redirect URIs (whitespace-separated, optional with a secret)
// SIMPLE_IDP_CLIENT_<LABEL>_POST_LOGOUT_REDIRECT_URL            - allowed post-logout redirect URIs (whitespace-separated, optional)
// SIMPLE_IDP_CLIENT_<LABEL>_BACKCHANNEL_LOGOUT_URI              - back-channel logout URI (optional)
// SIMPLE_IDP_CLIENT_<LABEL>_BACKCHANNEL_LOGOUT_SESSION_REQUIRED - require "sid" in logout token (optional, default "false")
//
// Users are configured the same way:
//
// SIMPLE_IDP_USER_<LABEL>_USERNAME           - login username (required)
// SIMPLE_IDP_USER_<LABEL>_PASSWORD           - login password (required)
// SIMPLE_IDP_USER_<LABEL>_TOTP_SECRET        - base32 TOTP secret (default: empty)
// SIMPLE_IDP_USER_<LABEL>_SUB                - "sub" claim (default: hex SHA-256 of <LABEL>)
// SIMPLE_IDP_USER_<LABEL>_NAME               - "name" claim (default: <USERNAME>)
// SIMPLE_IDP_USER_<LABEL>_PREFERRED_USERNAME - "preferred_username" claim (default: <USERNAME>)
// SIMPLE_IDP_USER_<LABEL>_EMAIL              - "email" claim (default: <USERNAME>@localhost)
// SIMPLE_IDP_USER_<LABEL>_EMAIL_VERIFIED     - "email_verified" claim (default: "true")
// SIMPLE_IDP_USER_<LABEL>_PROFILE            - "profile" claim (default: empty)
// SIMPLE_IDP_USER_<LABEL>_PICTURE            - "picture" claim (default: empty)
// SIMPLE_IDP_USER_<LABEL>_LOCALE             - "locale" claim (default: empty)
// SIMPLE_IDP_USER_<LABEL>_GROUPS             - comma-separated "groups" claim (default: empty)
// SIMPLE_IDP_USER_<LABEL>_ROLES              - comma-separated "roles" claim (default: empty)
//
// At least one client and one user must be configured.
package simpleidp

import (
	"cmp"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"maps"
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
	"unicode/utf8"
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
	totpPeriodSeconds            = 30
	throttleFreeFailures         = 3
	throttleBaseDelay            = time.Second
	throttle1FAMaxDelay          = 15 * time.Minute
	throttle2FAMaxDelay          = 24 * time.Hour
	throttleTTL                  = 7 * 24 * time.Hour
	maxFormBodyBytes             = 1 << 20
	maxLogValueBytes             = 128
	maxPendingTOTPsPerUser       = 10
	sessionCookieBaseName        = "simple_idp_session"
	preAuthSessionCookieBaseName = "simple_idp_preauth_session"
	resubmitParam                = "resubmitted"
)

var (
	authorizeFormFields  = []string{"username", "password", "totp", "code", "confirm", "csrf_token"}
	endSessionFormFields = []string{"confirm", "csrf_token"}
	authorizeParamNames  = append([]string{
		"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state",
		"nonce", "display", "prompt", "max_age", "ui_locales", "claims_locales",
		"id_token_hint", "login_hint", "acr_values", "claims", "request", "request_uri", "registration",
		"code_challenge", "code_challenge_method",
	}, authorizeFormFields...)
	tokenParamNames = []string{
		"grant_type", "client_id", "client_secret", "code", "redirect_uri", "code_verifier", "refresh_token", "scope",
	}
)

type client struct {
	id                               string
	secret                           string
	isPublic                         bool
	audience                         string
	redirectURLs                     []string
	postLogoutRedirectURLs           []string
	backchannelLogoutURI             url.URL
	backchannelLogoutSessionRequired bool
}

type user struct {
	label             string
	username          string
	password          string
	totpSecret        []byte
	sub               string
	name              string
	preferredUsername string
	email             string
	emailVerified     bool
	profile           string
	picture           string
	locale            string
	groups            []string
	roles             []string
}

type session struct {
	userLabel       string
	cookieDigest    [sha256.Size]byte
	clientIDs       map[string]struct{}
	authenticatedAt time.Time
	lastSeenAt      time.Time
}

type accessToken struct {
	clientID  string
	userLabel string
	scope     string
	code      string
	sessionID string
	expiry    time.Time
}

type refreshToken struct {
	clientID         string
	userLabel        string
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
	userLabel       string
	redirectURI     string
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

type pendingTOTP struct {
	userLabel string
	createdAt time.Time
}

type throttle struct {
	failures    int
	lastFailure time.Time
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
	issuer              string
	base                string
	title               string
	logo                template.URL
	favicon             template.URL
	accentColor         template.CSS
	colorScheme         string
	languages           []language
	defaultLanguage     language
	editProfile         bool
	sessionIdleTTL      time.Duration
	sessionMaxTTL       time.Duration
	accessTokenTTL      time.Duration
	refreshTokenIdleTTL time.Duration
	refreshTokenMaxTTL  time.Duration
	keyID               string
	privKey             *rsa.PrivateKey
	csrfKey             []byte
	clients             map[string]client
	users               map[string]user
	sessions            map[string]session
	accessTokens        map[string]accessToken
	refreshTokens       map[string]refreshToken
	pendingCodes        map[string]pendingCode
	pendingTOTPs        map[string]pendingTOTP
	lastTOTPSteps       map[string]int64
	throttles           map[string]throttle
	mu                  sync.Mutex
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
	logo := template.URL(envOr(lookupEnv, "SIMPLE_IDP_LOGO", ""))                                   // #nosec G203
	favicon := template.URL(envOr(lookupEnv, "SIMPLE_IDP_FAVICON", ""))                             // #nosec G203
	accentColor := template.CSS(envOr(lookupEnv, "SIMPLE_IDP_ACCENT_COLOR", "oklch(49% 0.19 264)")) // #nosec G203
	colorScheme := envOr(lookupEnv, "SIMPLE_IDP_COLOR_SCHEME", "light dark")
	pageLanguages := languages
	defaultLanguage, _ := resolveLanguage(languages, "en")
	if tag := lookupEnv("SIMPLE_IDP_LANGUAGE"); tag != "" {
		lang, ok := resolveLanguage(languages, tag)
		if !ok {
			return "", nil, fmt.Errorf("SIMPLE_IDP_LANGUAGE: must be one of %s", strings.Join(languageTags(languages), ", "))
		}
		pageLanguages, defaultLanguage = []language{lang}, lang
	}
	editProfile := lookupEnv("SIMPLE_IDP_EDIT_PROFILE") == "true"
	sessionIdleTTL, err := envDuration(lookupEnv, "SIMPLE_IDP_SESSION_IDLE_TTL", 30*time.Minute)
	if err != nil {
		return "", nil, err
	}
	sessionMaxTTL, err := envDuration(lookupEnv, "SIMPLE_IDP_SESSION_MAX_TTL", 10*time.Hour)
	if err != nil {
		return "", nil, err
	}
	accessTokenTTL, err := envDuration(lookupEnv, "SIMPLE_IDP_ACCESS_TOKEN_TTL", 5*time.Minute)
	if err != nil {
		return "", nil, err
	}
	if accessTokenTTL%time.Second != 0 {
		return "", nil, errors.New("SIMPLE_IDP_ACCESS_TOKEN_TTL: must be a whole number of seconds")
	}
	refreshTokenIdleTTL, err := envDuration(lookupEnv, "SIMPLE_IDP_REFRESH_TOKEN_IDLE_TTL", 30*time.Minute)
	if err != nil {
		return "", nil, err
	}
	refreshTokenMaxTTL, err := envDuration(lookupEnv, "SIMPLE_IDP_REFRESH_TOKEN_MAX_TTL", 10*time.Hour)
	if err != nil {
		return "", nil, err
	}
	keyID := envOr(lookupEnv, "SIMPLE_IDP_KEY_ID", "simpleidp")
	privKey, err := loadOrGenerateKey(lookupEnv, readFile)
	if err != nil {
		return "", nil, err
	}

	csrfKey := make([]byte, 32)
	if _, err := rand.Read(csrfKey); err != nil {
		return "", nil, fmt.Errorf("failed to generate CSRF key: %w", err)
	}

	return listen, &identityProvider{
		issuer:              issuer,
		base:                issuerURL.Path,
		title:               title,
		logo:                logo,
		favicon:             favicon,
		accentColor:         accentColor,
		colorScheme:         colorScheme,
		languages:           pageLanguages,
		defaultLanguage:     defaultLanguage,
		editProfile:         editProfile,
		sessionIdleTTL:      sessionIdleTTL,
		sessionMaxTTL:       sessionMaxTTL,
		accessTokenTTL:      accessTokenTTL,
		refreshTokenIdleTTL: refreshTokenIdleTTL,
		refreshTokenMaxTTL:  refreshTokenMaxTTL,
		keyID:               keyID,
		privKey:             privKey,
		csrfKey:             csrfKey,
		clients:             clients,
		users:               users,
		sessions:            map[string]session{},
		accessTokens:        map[string]accessToken{},
		refreshTokens:       map[string]refreshToken{},
		pendingCodes:        map[string]pendingCode{},
		pendingTOTPs:        map[string]pendingTOTP{},
		lastTOTPSteps:       map[string]int64{},
		throttles:           map[string]throttle{},
	}, nil
}

func newServer(listen string, provider *identityProvider) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+provider.base+"/{$}", provider.handleProfile)
	if provider.editProfile {
		mux.HandleFunc("POST "+provider.base+"/{$}", provider.handleProfile)
	}
	mux.HandleFunc("GET "+provider.base+"/login", provider.handleLogin)
	mux.HandleFunc("POST "+provider.base+"/login", provider.handleLogin)
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

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

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

func (p *identityProvider) handleProfile(w http.ResponseWriter, r *http.Request) {
	sessionID := p.readSession(r)
	currentSession, sessionKnown := p.resumeSession(sessionID)
	if !sessionKnown {
		http.Redirect(w, r, p.base+"/login", http.StatusFound)
		return
	}
	profileUser, _ := p.lookupUser(currentSession.userLabel)
	if r.Method != http.MethodPost {
		p.renderProfilePage(w, r, profileUser, sessionID, msgNone)
		return
	}

	if err := parseForm(w, r); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if !hasUniqueParams(r.PostForm) {
		http.Error(w, "Duplicate parameter", http.StatusBadRequest)
		return
	}
	if !p.validateCSRFToken(r.PostForm.Get("csrf_token"), "session:"+sessionID) {
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}
	if !utf8.ValidString(r.PostForm.Get("username")) || !utf8.ValidString(r.PostForm.Get("name")) {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	profileUser.username = r.PostForm.Get("username")
	profileUser.name = r.PostForm.Get("name")
	profileUser.email = r.PostForm.Get("email")
	errorMsg := msgNone
	switch {
	case profileUser.username == "" || profileUser.name == "":
		errorMsg = msgUsernameAndNameRequired
	case !isValidEmail(profileUser.email):
		errorMsg = msgInvalidEmail
	case !p.updateUser(profileUser):
		errorMsg = msgUsernameTaken
	}
	if errorMsg != msgNone {
		p.renderProfilePage(w, r, profileUser, sessionID, errorMsg)
		return
	}
	http.Redirect(w, r, p.base+"/", http.StatusSeeOther)
}

func (p *identityProvider) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		if _, sessionKnown := p.resumeSession(p.readSession(r)); sessionKnown {
			http.Redirect(w, r, p.base+"/", http.StatusFound)
			return
		}
		p.renderLoginForm(w, r, p.base+"/login", nil, "", msgNone)
		return
	}

	if err := parseForm(w, r); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if !hasUniqueParams(r.PostForm) {
		http.Error(w, "Duplicate parameter", http.StatusBadRequest)
		return
	}
	preAuthID := p.readPreAuthSession(r)
	if preAuthID == "" || !p.validateCSRFToken(r.PostForm.Get("csrf_token"), "preauth:"+preAuthID) {
		slog.Warn("form submission rejected", "reason", "invalid or expired CSRF token")
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}

	authenticatedUser, ok := p.authenticateLogin(w, r, p.base+"/login", nil)
	if !ok {
		return
	}
	p.issueSession(w, authenticatedUser.label, time.Now(), p.readSession(r))
	p.clearPreAuthSession(w)
	http.Redirect(w, r, p.base+"/", http.StatusSeeOther)
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
		UILocalesSupported                         []string `json:"ui_locales_supported"`
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
		ScopesSupported:                   []string{"openid", "profile", "email", "groups", "roles"},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "iat", "exp", "auth_time", "nonce", "sid", "email", "email_verified",
			"name", "preferred_username", "profile", "picture", "locale", "groups", "roles",
		},
		PromptValuesSupported:                      []string{"none", "login", "consent", "select_account"},
		UILocalesSupported:                         languageTags(p.languages),
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
	resubmitted := params.Has(resubmitParam)
	params = filterFormParams(params, resubmitParam)

	if len(params["client_id"]) > 1 || len(params["redirect_uri"]) > 1 {
		http.Error(w, "Duplicate parameter", http.StatusBadRequest)
		return
	}

	clientID := params.Get("client_id")
	scope := params.Get("scope")
	codeChallenge := params.Get("code_challenge")
	prompt := params.Get("prompt")
	idTokenHint := params.Get("id_token_hint")
	nonce := params.Get("nonce")
	state := params.Get("state")

	code, confirm := "", ""
	csrfToken := ""
	credentialsSubmitted := false
	if r.Method == http.MethodPost {
		code = r.PostForm.Get("code")
		confirm = r.PostForm.Get("confirm")
		credentialsSubmitted = r.PostForm.Get("username") != "" || r.PostForm.Get("password") != "" || r.PostForm.Has("totp")
		csrfToken = r.PostForm.Get("csrf_token")
	}

	client, ok := p.clients[clientID]
	redirectURI, err := url.Parse(params.Get("redirect_uri"))

	if !ok || err != nil || !isAllowedRedirectURL(client.redirectURLs, params.Get("redirect_uri"), client.isPublic) {
		loggedRedirectURI := ""
		if err == nil {
			loggedRedirectURI = (&url.URL{Scheme: redirectURI.Scheme, Host: redirectURI.Host, Path: redirectURI.Path}).String()
		}
		slog.Warn("authorization request rejected", "reason", "unknown client or redirect URI", "client_id", logValue(clientID), "redirect_uri", logValue(loggedRedirectURI))
		http.Error(w, "Unknown client or redirect URI", http.StatusBadRequest)
		return
	}
	if responseMode := params.Get("response_mode"); responseMode != "" && responseMode != "query" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	sessionID := p.readSession(r)
	if r.Method == http.MethodPost && (confirm != "" || credentialsSubmitted) {
		ownerID := ""
		if confirm != "" {
			if sessionID != "" {
				ownerID = "session:" + sessionID
			}
		} else {
			if id := p.readPreAuthSession(r); id != "" {
				ownerID = "preauth:" + id
			}
		}
		if !p.validateCSRFToken(csrfToken, ownerID) {
			slog.Warn("form submission rejected", "reason", "invalid or expired CSRF token", "client_id", client.id)
			http.Error(w, "Invalid or expired session", http.StatusBadRequest)
			return
		}
	}

	if r.Method == http.MethodPost && confirm != "" {
		now := time.Now()
		p.mu.Lock()
		currentSession, sessionKnown := p.sessions[sessionID]
		pendingCode, codeKnown := p.pendingCodes[code]
		if codeKnown && p.isPendingCodeExpired(pendingCode, now) {
			delete(p.pendingCodes, code)
			codeKnown = false
		}
		if !sessionKnown || p.isSessionExpired(currentSession, now) || pendingCode.sessionID != sessionID {
			codeKnown = false
		}
		if codeKnown && (pendingCode.clientID != client.id || pendingCode.redirectURI != params.Get("redirect_uri") || !pendingCode.consumedAt.IsZero() || !pendingCode.consentRequired) {
			codeKnown = false
		}
		if codeKnown {
			switch confirm {
			case "yes":
				delete(p.pendingCodes, code)
				code = rand.Text()
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
			slog.Warn("consent rejected", "reason", "invalid or expired consent request", "client_id", client.id)
			redirectWithError(w, r, p.issuer, *redirectURI, state, "invalid_request", "Invalid consent request")
			return
		}
		if confirm == "no" {
			slog.Info("consent denied", "label", pendingCode.userLabel, "client_id", client.id)
			redirectWithError(w, r, p.issuer, *redirectURI, pendingCode.state, "access_denied", "End-user denied the request")
			return
		}
		slog.Info("consent granted", "label", pendingCode.userLabel, "client_id", client.id, "scope", pendingCode.scope)
		redirectWithCode(w, r, p.issuer, *redirectURI, code, pendingCode.state)
		return
	}

	if errCode, errDesc := validateAuthorizeParams(params); errCode != "" {
		redirectWithError(w, r, p.issuer, *redirectURI, state, errCode, errDesc)
		return
	}
	if !hasUniqueParams(params, authorizeParamNames...) || !hasUniqueParams(r.PostForm, authorizeFormFields...) {
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
	if r.Method == http.MethodPost && !resubmitted && !p.hasSessionCookie(r) && !credentialsSubmitted {
		p.renderResubmitForm(w, r, p.base+"/authorize", params, authorizeFormFields...)
		return
	}
	currentSession, sessionKnown := session{}, false
	if !hasPromptValue(prompt, "login") && !hasPromptValue(prompt, "select_account") {
		currentSession, sessionKnown = p.resumeSession(sessionID)
		if sessionKnown && !p.canReuseSession(currentSession, hintedUser, maxAge, maxAgeRequested) {
			slog.Debug("session not reused", "label", currentSession.userLabel, "client_id", client.id, "sid", sessionID)
			sessionKnown = false
		}
	}

	if hasPromptValue(prompt, "none") {
		if !sessionKnown {
			slog.Debug("sign-in required without interaction", "client_id", client.id)
			redirectWithError(w, r, p.issuer, *redirectURI, state, "login_required", "Authentication required")
			return
		}
		if client.isPublic {
			slog.Debug("interaction required for public client", "client_id", client.id)
			redirectWithError(w, r, p.issuer, *redirectURI, state, "interaction_required", "Public clients require end-user interaction")
			return
		}
		slog.Debug("reusing session", "label", currentSession.userLabel, "client_id", client.id, "sid", sessionID)
		p.authorizeUser(w, r, authorization, currentSession.userLabel, currentSession.authenticatedAt, sessionID)
		return
	}

	if sessionKnown && (r.Method == http.MethodGet || !credentialsSubmitted) {
		authorization.consentRequired = authorization.consentRequired || client.isPublic
		slog.Debug("reusing session", "label", currentSession.userLabel, "client_id", client.id, "sid", sessionID)
		p.authorizeUser(w, r, authorization, currentSession.userLabel, currentSession.authenticatedAt, sessionID)
		return
	}

	if r.Method == http.MethodGet || !credentialsSubmitted {
		p.renderLoginForm(w, r, p.base+"/authorize", authorization.params, "", msgNone)
		return
	}
	authenticatedUser, ok := p.authenticateLogin(w, r, p.base+"/authorize", authorization.params)
	if !ok {
		return
	}
	if hintedUser.sub != "" && authenticatedUser.sub != hintedUser.sub {
		slog.Warn("authenticated user does not match id_token_hint", "label", authenticatedUser.label, "client_id", client.id)
		redirectWithError(w, r, p.issuer, *redirectURI, state, "login_required", "Authenticated user does not match id_token_hint")
		return
	}
	authenticatedAt := time.Now()
	sessionID = p.issueSession(w, authenticatedUser.label, authenticatedAt, sessionID)
	p.clearPreAuthSession(w)
	p.authorizeUser(w, r, authorization, authenticatedUser.label, authenticatedAt, sessionID)
}

func (p *identityProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Malformed request body")
		return
	}

	if !hasUniqueParams(r.PostForm, tokenParamNames...) {
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
	case "client_credentials":
		p.exchangeClientCredentials(w, r, client)
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
	if !slices.Contains(strings.Fields(bearerToken.scope), "openid") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="insufficient_scope", error_description="The access token does not grant the openid scope", scope="openid"`)
		w.WriteHeader(http.StatusForbidden)
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

	writeActiveResponse := func(userLabel, clientID, scope string, expiry time.Time, tokenType string) {
		response := map[string]any{"sub": clientID}
		if user, ok := p.lookupUser(userLabel); ok {
			response = p.buildClaimsForScope(user, scope)
		}
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
		idleExpiry := token.createdAt.Add(p.refreshTokenIdleTTL)
		maxExpiry := token.sessionStartedAt.Add(p.refreshTokenMaxTTL)
		if idleExpiry.Before(maxExpiry) {
			return idleExpiry
		}
		return maxExpiry
	}
	writeActiveAccessToken := func() bool {
		if !accessTokenKnown || storedAccessToken.clientID != client.id {
			return false
		}
		writeActiveResponse(storedAccessToken.userLabel, storedAccessToken.clientID, storedAccessToken.scope, storedAccessToken.expiry, "Bearer")
		return true
	}
	writeActiveRefreshToken := func() bool {
		if !refreshTokenKnown || !storedRefreshToken.consumedAt.IsZero() || storedRefreshToken.clientID != client.id {
			return false
		}
		writeActiveResponse(storedRefreshToken.userLabel, storedRefreshToken.clientID, storedRefreshToken.scope, refreshTokenExpiry(storedRefreshToken), "")
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
		p.revokeGrant(stored.code)
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
	resubmitted := params.Has(resubmitParam)
	params = filterFormParams(params, resubmitParam)
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
			slog.Warn("logout request rejected", "reason", "invalid id_token_hint", "client_id", logValue(clientID))
			http.Error(w, "Invalid id_token_hint", http.StatusBadRequest)
			return
		}
		if clientID == "" {
			clientID = hintedUser.aud
		} else if clientID != hintedUser.aud {
			slog.Warn("logout request rejected", "reason", "id_token_hint issued to another client", "client_id", logValue(clientID))
			http.Error(w, "Invalid id_token_hint", http.StatusBadRequest)
			return
		}
	}

	if postLogoutRedirectURI != "" {
		if clientID == "" {
			slog.Warn("logout request rejected", "reason", "missing client_id")
			http.Error(w, "Missing client_id", http.StatusBadRequest)
			return
		}
		client, ok := p.clients[clientID]
		if _, matched := resolvePostLogoutRedirectURL(client.postLogoutRedirectURLs, postLogoutRedirectURI); !ok || !matched {
			slog.Warn("logout request rejected", "reason", "unknown client or post-logout redirect URI", "client_id", logValue(clientID))
			http.Error(w, "Unknown client or post-logout redirect URI", http.StatusBadRequest)
			return
		}
	}

	sessionID := p.readSession(r)
	if r.Method == http.MethodPost && !resubmitted && !p.hasSessionCookie(r) && confirm == "" {
		p.renderResubmitForm(w, r, p.base+"/end-session", params, endSessionFormFields...)
		return
	}
	_, sessionKnown := p.resumeSession(sessionID)
	if !sessionKnown {
		p.mu.Lock()
		_, sessionKnown = p.sessions[sessionID]
		p.mu.Unlock()
	}

	if !sessionKnown {
		slog.Debug("logout requested without a session", "client_id", logValue(clientID))
		p.renderLogoutComplete(w, r, clientID, postLogoutRedirectURI, state, params.Get("ui_locales"))
		return
	}

	if confirm == "" {
		slog.Debug("logout confirmation required", "client_id", logValue(clientID), "sid", sessionID)
		p.renderLogoutForm(w, r, params, sessionID)
		return
	}

	if !p.validateCSRFToken(csrfToken, "session:"+sessionID) {
		slog.Warn("form submission rejected", "reason", "invalid or expired CSRF token", "client_id", logValue(clientID))
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}

	if confirm != "yes" {
		slog.Info("logout canceled", "client_id", logValue(clientID), "sid", sessionID)
		p.renderLogoutCanceled(w, r, clientID, params.Get("ui_locales"))
		return
	}

	p.clearSession(w, sessionID)
	p.renderLogoutComplete(w, r, clientID, postLogoutRedirectURI, state, params.Get("ui_locales"))
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

type formPageDetail struct {
	Label string
	Value string
}

type formPageField struct {
	Type         string
	Name         string
	Label        string
	Value        string
	Autocomplete string
	Autofocus    bool
}

type formPageButton struct {
	Name   string
	Value  string
	Label  string
	Action string
}

type formPageLink struct {
	Href   string
	Label  string
	TestID string
}

type formPage struct {
	Lang        string
	Dir         string
	Title       string
	Logo        template.URL
	Favicon     template.URL
	AccentColor template.CSS
	ColorScheme string
	Nonce       string
	Action      string
	Message     string
	Error       string
	DescribedBy string
	TestID      string
	Params      url.Values
	Details     []formPageDetail
	Fields      []formPageField
	Buttons     []formPageButton
	Links       []formPageLink
	AutoSubmit  bool
}

var formPageGzipPool = sync.Pool{New: func() any { return gzip.NewWriter(nil) }}
var formPageTemplate = template.Must(template.New("form-page").Parse(`<!DOCTYPE html>
<html lang="{{.Lang}}" dir="{{.Dir}}">
<head>
	<meta charset="utf-8">
	<meta name="color-scheme" content="{{.ColorScheme}}">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>{{.Title}}</title>
	{{- if .Favicon}}
	<link rel="icon" href="{{.Favicon}}">
	{{- end}}
	<style nonce="{{.Nonce}}">
		:root {
			color-scheme: {{.ColorScheme}};
			--color-accent-base: {{.AccentColor}};
			--color-accent-light: oklch(from var(--color-accent-base) l c h);
			--color-accent-dark: oklch(from var(--color-accent-base) calc(l + .05) c h);
			--color-accent: light-dark(var(--color-accent-light), var(--color-accent-dark));
			--color-accent-contrast: light-dark(
				oklch(from var(--color-accent-light) clamp(0, (.6 - l) * 1000, 1) 0 0),
				oklch(from var(--color-accent-dark) clamp(0, (.6 - l) * 1000, 1) 0 0)
			);
			--color-bg: light-dark(oklch(96% 0 0), oklch(18% 0 0));
			--color-surface: light-dark(oklch(100% 0 0), oklch(23% 0 0));
			--color-shadow: light-dark(oklch(0% 0 0 / .08), oklch(0% 0 0 / .4));
			--color-text: light-dark(oklch(22% 0 0), oklch(92% 0 0));
			--color-text-muted: light-dark(
				oklch(from var(--color-accent-base) 37% calc(c * .16) h),
				oklch(from var(--color-accent-base) 71% calc(c * .05) h)
			);
			--color-border: color-mix(in oklch, var(--color-text) 20%, transparent);
			--color-focus-ring: color-mix(in oklch, var(--color-accent) 25%, transparent);
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
			img {
				display: block;
				max-width: 100%;
				max-height: 4rem;
				margin-inline: auto;
			}
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
		dl {
			display: grid;
			gap: 1rem;
			margin-bottom: 1.5rem;
			dt {
				font-size: .875rem;
				font-weight: 500;
				color: var(--color-text-muted);
			}
			dd {
				margin-top: .25rem;
				font-size: 1rem;
				overflow-wrap: anywhere;
			}
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
					border-color: var(--color-accent);
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
			color: var(--color-accent-contrast);
			background: var(--color-accent);
			&:hover {
				background: color-mix(in oklch, var(--color-accent) 85%, light-dark(black, white));
			}
			&:active {
				background: color-mix(in oklch, var(--color-accent) 70%, light-dark(black, white));
			}
		}
		button[value=no], button[formaction], a {
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
		<h1 id="page-title" dir="auto" data-testid="page-title">
			{{- if .Logo}}<img src="{{.Logo}}" alt="{{.Title}}" data-testid="logo">{{else}}{{.Title}}{{end -}}
		</h1>
		{{- if .Message}}
		<p id="form-description" data-testid="message">{{.Message}}</p>
		{{- end}}
		{{- if .Error}}
		<p id="form-error" role="alert" aria-live="assertive" data-testid="error">{{.Error}}</p>
		{{- end}}
		{{- if .Details}}
		<dl data-testid="details">
			{{- range .Details}}
			<div>
				<dt>{{.Label}}</dt>
				<dd><bdi>{{.Value}}</bdi></dd>
			</div>
			{{- end}}
		</dl>
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
					dir="auto"
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
						{{- if .Action}}
						formaction="{{.Action}}"
						formnovalidate
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
	{{- if .AutoSubmit}}
	<script nonce="{{.Nonce}}">HTMLFormElement.prototype.submit.call(document.forms[0])</script>
	{{- end}}
</body>
</html>`))

func (p *identityProvider) negotiateLanguage(r *http.Request, uiLocales string) language {
	for tag := range strings.FieldsSeq(uiLocales) {
		if lang, ok := resolveLanguage(p.languages, tag); ok {
			return lang
		}
	}
	best, bestWeight := p.defaultLanguage, 0.0
	for entry := range strings.SplitSeq(strings.Join(r.Header.Values("Accept-Language"), ","), ",") {
		tag, weightParam, _ := strings.Cut(entry, ";")
		weight := 1.0
		if value, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(weightParam)), "q="); ok {
			var err error
			if weight, err = strconv.ParseFloat(value, 64); err != nil {
				continue
			}
		}
		if lang, ok := resolveLanguage(p.languages, strings.TrimSpace(tag)); ok && weight > bestWeight {
			best, bestWeight = lang, weight
		}
	}
	return best
}

func (p *identityProvider) renderFormPage(w http.ResponseWriter, r *http.Request, lang language, page formPage) {
	page.Lang = lang.tag
	page.Dir = lang.dir
	page.Logo = p.logo
	page.Favicon = p.favicon
	page.AccentColor = p.accentColor
	page.ColorScheme = p.colorScheme
	page.Nonce = rand.Text()
	switch {
	case page.Message != "" && page.Error != "":
		page.DescribedBy = "form-description form-error"
	case page.Message != "":
		page.DescribedBy = "form-description"
	case page.Error != "":
		page.DescribedBy = "form-error"
	}
	scriptSrc := ""
	if page.AutoSubmit {
		scriptSrc = "; script-src 'nonce-" + page.Nonce + "'"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+page.Nonce+"'"+scriptSrc+"; img-src 'self' data: https: http:; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Vary", "Accept-Encoding, Accept-Language")
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

func (p *identityProvider) renderProfilePage(w http.ResponseWriter, r *http.Request, user user, sessionID string, errorMsg message) {
	lang := p.negotiateLanguage(r, "")
	csrfToken := p.issueCSRFToken("session:" + sessionID)
	page := formPage{
		Title:  p.title,
		Error:  lang.messages[errorMsg],
		TestID: "page-profile",
		Params: url.Values{
			"csrf_token": {csrfToken},
		},
	}
	if p.editProfile {
		page.Action = p.base + "/"
		page.Fields = []formPageField{
			{Type: "text", Name: "name", Label: lang.messages[msgName], Value: user.name, Autocomplete: "name"},
			{Type: "text", Name: "username", Label: lang.messages[msgUsername], Value: user.username, Autocomplete: "username"},
			{Type: "text", Name: "email", Label: lang.messages[msgEmail], Value: user.email, Autocomplete: "email"},
		}
		page.Buttons = []formPageButton{
			{Label: lang.messages[msgSave]},
			{Name: "confirm", Value: "yes", Label: lang.messages[msgLogOut], Action: p.base + "/end-session"},
		}
	} else {
		page.Action = p.base + "/end-session"
		page.Details = []formPageDetail{
			{Label: lang.messages[msgName], Value: user.name},
			{Label: lang.messages[msgUsername], Value: user.username},
			{Label: lang.messages[msgEmail], Value: user.email},
		}
		page.Buttons = []formPageButton{
			{Name: "confirm", Value: "yes", Label: lang.messages[msgLogOut]},
		}
	}
	p.renderFormPage(w, r, lang, page)
}

func (p *identityProvider) renderLoginForm(w http.ResponseWriter, r *http.Request, action string, params url.Values, username string, errorMsg message) {
	lang := p.negotiateLanguage(r, params.Get("ui_locales"))
	preAuthID := p.issuePreAuthSession(w, p.readPreAuthSession(r))
	loginParams := filterFormParams(params, authorizeFormFields...)
	loginParams.Set("csrf_token", p.issueCSRFToken("preauth:"+preAuthID))
	p.renderFormPage(w, r, lang, formPage{
		Title:  p.title,
		Action: action,
		Error:  lang.messages[errorMsg],
		TestID: "page-login",
		Params: loginParams,
		Fields: []formPageField{
			{Type: "text", Name: "username", Label: lang.messages[msgUsername], Value: username, Autocomplete: "username", Autofocus: true},
			{Type: "password", Name: "password", Label: lang.messages[msgPassword], Autocomplete: "current-password"},
		},
		Buttons: []formPageButton{
			{Label: lang.messages[msgSignIn]},
		},
	})
}

func (p *identityProvider) renderTOTPForm(w http.ResponseWriter, r *http.Request, action string, params url.Values, preAuthID string, errorMsg message) {
	lang := p.negotiateLanguage(r, params.Get("ui_locales"))
	p.issuePreAuthSession(w, preAuthID)
	totpParams := filterFormParams(params, authorizeFormFields...)
	totpParams.Set("csrf_token", p.issueCSRFToken("preauth:"+preAuthID))
	p.renderFormPage(w, r, lang, formPage{
		Title:   p.title,
		Action:  action,
		Message: lang.messages[msgEnterAuthenticationCode],
		Error:   lang.messages[errorMsg],
		TestID:  "page-totp",
		Params:  totpParams,
		Fields: []formPageField{
			{Type: "text", Name: "totp", Label: lang.messages[msgAuthenticationCode], Autocomplete: "one-time-code", Autofocus: true},
		},
		Buttons: []formPageButton{
			{Label: lang.messages[msgVerify]},
		},
	})
}

func (p *identityProvider) renderResubmitForm(w http.ResponseWriter, r *http.Request, action string, params url.Values, skipped ...string) {
	lang := p.negotiateLanguage(r, params.Get("ui_locales"))
	resubmitParams := filterFormParams(params, skipped...)
	resubmitParams.Set(resubmitParam, "1")
	p.renderFormPage(w, r, lang, formPage{
		Title:      p.title,
		Action:     action,
		TestID:     "page-resubmit",
		Params:     resubmitParams,
		Buttons:    []formPageButton{{Label: lang.messages[msgContinue]}},
		AutoSubmit: true,
	})
}

func (p *identityProvider) renderConsentForm(w http.ResponseWriter, r *http.Request, authorization authorizeRequest, code, sessionID string) {
	lang := p.negotiateLanguage(r, authorization.params.Get("ui_locales"))
	consentParams := filterFormParams(authorization.params, authorizeFormFields...)
	consentParams.Set("code", code)
	consentParams.Set("csrf_token", p.issueCSRFToken("session:"+sessionID))
	p.renderFormPage(w, r, lang, formPage{
		Title:   p.title,
		Action:  p.base + "/authorize",
		Message: fmt.Sprintf(lang.messages[msgConsentRequest], isolateText(authorization.client.id), isolateText(authorization.scope)),
		TestID:  "page-consent",
		Params:  consentParams,
		Details: []formPageDetail{
			{Label: lang.messages[msgRedirectURI], Value: authorization.redirectURI.String()},
		},
		Buttons: []formPageButton{
			{Name: "confirm", Value: "yes", Label: lang.messages[msgAllow]},
			{Name: "confirm", Value: "no", Label: lang.messages[msgDeny]},
		},
	})
}

func (p *identityProvider) renderLogoutForm(w http.ResponseWriter, r *http.Request, params url.Values, sessionID string) {
	lang := p.negotiateLanguage(r, params.Get("ui_locales"))
	logoutParams := filterFormParams(params, endSessionFormFields...)
	logoutParams.Set("csrf_token", p.issueCSRFToken("session:"+sessionID))
	p.renderFormPage(w, r, lang, formPage{
		Title:   p.title,
		Action:  p.base + "/end-session",
		Message: lang.messages[msgLogoutRequest],
		TestID:  "page-logout",
		Params:  logoutParams,
		Buttons: []formPageButton{
			{Name: "confirm", Value: "yes", Label: lang.messages[msgLogOut]},
			{Name: "confirm", Value: "no", Label: lang.messages[msgCancel]},
		},
	})
}

func (p *identityProvider) renderLogoutCanceled(w http.ResponseWriter, r *http.Request, clientID, uiLocales string) {
	lang := p.negotiateLanguage(r, uiLocales)
	var links []formPageLink
	if clientID != "" {
		if client, ok := p.clients[clientID]; ok {
			if len(client.postLogoutRedirectURLs) > 0 {
				returnURL := client.postLogoutRedirectURLs[0]
				links = append(links, formPageLink{Href: returnURL, Label: lang.messages[msgReturnToApplication], TestID: "return-link"})
			}
		}
	}
	p.renderFormPage(w, r, lang, formPage{
		Title:   p.title,
		Message: lang.messages[msgLogoutCanceled],
		TestID:  "page-logout-canceled",
		Links:   links,
	})
}

func (p *identityProvider) renderLogoutComplete(w http.ResponseWriter, r *http.Request, clientID, postLogoutRedirectURI, state, uiLocales string) {
	if postLogoutRedirectURI != "" {
		postLogoutRedirectURL, _ := resolvePostLogoutRedirectURL(p.clients[clientID].postLogoutRedirectURLs, postLogoutRedirectURI)
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
	lang := p.negotiateLanguage(r, uiLocales)
	var links []formPageLink
	if clientID != "" {
		if client, ok := p.clients[clientID]; ok {
			if len(client.postLogoutRedirectURLs) > 0 {
				returnURL := client.postLogoutRedirectURLs[0]
				links = append(links, formPageLink{Href: returnURL, Label: lang.messages[msgReturnToApplication], TestID: "return-link"})
			}
		}
	}
	p.renderFormPage(w, r, lang, formPage{
		Title:   p.title,
		Message: lang.messages[msgLogoutComplete],
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
		Iss string         `json:"iss"`
		Sub string         `json:"sub"`
		Aud jsontext.Value `json:"aud"`
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

func (p *identityProvider) authorizeUser(w http.ResponseWriter, r *http.Request, authorization authorizeRequest, userLabel string, authenticatedAt time.Time, sessionID string) {
	issuedCode := rand.Text()

	p.mu.Lock()
	currentSession, sessionKnown := p.sessions[sessionID]
	if !sessionKnown || p.isSessionExpired(currentSession, time.Now()) {
		p.mu.Unlock()
		slog.Debug("session expired before authorization", "client_id", authorization.client.id, "sid", sessionID)
		redirectWithError(w, r, p.issuer, authorization.redirectURI, authorization.state, "login_required", "Authentication required")
		return
	}
	p.pendingCodes[issuedCode] = pendingCode{
		clientID:        authorization.client.id,
		userLabel:       userLabel,
		redirectURI:     authorization.params.Get("redirect_uri"),
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
		slog.Debug("consent required", "label", userLabel, "client_id", authorization.client.id, "scope", authorization.scope)
		p.renderConsentForm(w, r, authorization, issuedCode, sessionID)
		return
	}
	slog.Info("authorization code issued", "label", userLabel, "client_id", authorization.client.id, "scope", authorization.scope)
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
	codeExpired := codeKnown && p.isPendingCodeExpired(pendingCode, time.Now())
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

	if redirectURI != "" && redirectURI != pendingCode.redirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Redirect URI does not match the one used in the authorization request")
		return
	}

	if codeVerifier == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Missing required parameter: code_verifier")
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
		p.revokeGrant(code)
		p.mu.Unlock()
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid, expired, or previously used authorization code")
		return
	}

	user, _ := p.lookupUser(pendingCode.userLabel)
	issuedAt := time.Now()
	accessTokenValue, err := p.mintAccessToken(client, user, pendingCode.scope, issuedAt)
	if err != nil {
		http.Error(w, "Failed to mint access token", http.StatusInternalServerError)
		return
	}
	refreshTokenValue := rand.Text()
	idToken, err := p.mintIDToken(user, client, pendingCode, accessTokenValue, issuedAt)
	if err != nil {
		http.Error(w, "Failed to mint ID token", http.StatusInternalServerError)
		return
	}

	p.mu.Lock()
	currentSession, sessionKnown := p.sessions[pendingCode.sessionID]
	sessionKnown = sessionKnown && !p.isSessionExpired(currentSession, time.Now())
	if latest, ok := p.pendingCodes[code]; !ok || !latest.consumedAt.IsZero() || !sessionKnown {
		p.revokeGrant(code)
		p.mu.Unlock()
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid, expired, or previously used authorization code")
		return
	}
	pendingCode.consumedAt = time.Now()
	p.pendingCodes[code] = pendingCode
	p.accessTokens[accessTokenValue] = accessToken{
		clientID:  client.id,
		userLabel: user.label,
		scope:     pendingCode.scope,
		code:      code,
		sessionID: pendingCode.sessionID,
		expiry:    issuedAt.Truncate(time.Second).Add(p.accessTokenTTL),
	}
	p.refreshTokens[refreshTokenValue] = refreshToken{
		clientID:         client.id,
		userLabel:        user.label,
		scope:            pendingCode.scope,
		code:             code,
		sessionID:        pendingCode.sessionID,
		authenticatedAt:  pendingCode.authenticatedAt,
		sessionStartedAt: issuedAt,
		createdAt:        issuedAt,
	}
	currentSession.clientIDs[client.id] = struct{}{}
	p.removeExpiredState()
	p.mu.Unlock()

	response := map[string]any{
		"access_token":  accessTokenValue,
		"token_type":    "Bearer",
		"expires_in":    int(p.accessTokenTTL.Seconds()),
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
	tokenReused := tokenKnown && !storedRefreshToken.consumedAt.IsZero()
	tokenExpired := tokenKnown && !tokenReused && p.isRefreshTokenExpired(storedRefreshToken, time.Now())
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
		p.revokeGrant(storedRefreshToken.code)
		p.mu.Unlock()
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return
	}

	user, _ := p.lookupUser(storedRefreshToken.userLabel)
	issuedAt := time.Now()
	newAccessTokenValue, err := p.mintAccessToken(client, user, effectiveAccessScope, issuedAt)
	if err != nil {
		http.Error(w, "Failed to mint access token", http.StatusInternalServerError)
		return
	}
	newRefreshTokenValue := rand.Text()

	idToken := ""
	if slices.Contains(strings.Fields(effectiveAccessScope), "openid") {
		idToken, err = p.mintIDToken(user, client, pendingCode{
			scope:           effectiveAccessScope,
			sessionID:       storedRefreshToken.sessionID,
			authenticatedAt: storedRefreshToken.authenticatedAt,
		}, newAccessTokenValue, issuedAt)
		if err != nil {
			http.Error(w, "Failed to mint ID token", http.StatusInternalServerError)
			return
		}
	}

	p.mu.Lock()
	if latest, ok := p.refreshTokens[refreshTokenValue]; !ok || !latest.consumedAt.IsZero() {
		p.revokeGrant(storedRefreshToken.code)
		p.mu.Unlock()
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired refresh token")
		return
	}
	storedRefreshToken.consumedAt = time.Now()
	p.refreshTokens[refreshTokenValue] = storedRefreshToken
	p.accessTokens[newAccessTokenValue] = accessToken{
		clientID:  client.id,
		userLabel: user.label,
		scope:     effectiveAccessScope,
		code:      storedRefreshToken.code,
		sessionID: storedRefreshToken.sessionID,
		expiry:    issuedAt.Truncate(time.Second).Add(p.accessTokenTTL),
	}
	p.refreshTokens[newRefreshTokenValue] = refreshToken{
		clientID:         client.id,
		userLabel:        storedRefreshToken.userLabel,
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
		"expires_in":    int(p.accessTokenTTL.Seconds()),
		"scope":         effectiveAccessScope,
		"refresh_token": newRefreshTokenValue,
	}
	if idToken != "" {
		response["id_token"] = idToken
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *identityProvider) exchangeClientCredentials(w http.ResponseWriter, r *http.Request, client client) {
	if client.isPublic {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Public clients cannot use the client credentials grant")
		return
	}
	scope := r.PostForm.Get("scope")
	if !isValidScope(scope) {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "Malformed scope")
		return
	}
	if slices.Contains(strings.Fields(scope), "openid") {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "The openid scope requires an end-user")
		return
	}

	issuedAt := time.Now()
	accessTokenValue, err := p.mintAccessToken(client, user{}, scope, issuedAt)
	if err != nil {
		http.Error(w, "Failed to mint access token", http.StatusInternalServerError)
		return
	}

	p.mu.Lock()
	p.accessTokens[accessTokenValue] = accessToken{
		clientID: client.id,
		scope:    scope,
		expiry:   issuedAt.Truncate(time.Second).Add(p.accessTokenTTL),
	}
	p.removeExpiredState()
	p.mu.Unlock()

	response := map[string]any{
		"access_token": accessTokenValue,
		"token_type":   "Bearer",
		"expires_in":   int(p.accessTokenTTL.Seconds()),
	}
	if scope != "" {
		response["scope"] = scope
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

func (p *identityProvider) issuePreAuthSession(w http.ResponseWriter, preAuthID string) string {
	if preAuthID == "" {
		preAuthID = rand.Text()
	}
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

func (p *identityProvider) hasSessionCookie(r *http.Request) bool {
	return p.readCookie(r, sessionCookieBaseName) != ""
}

func (p *identityProvider) readSession(r *http.Request) string {
	return p.sessionIDFromCookie(p.readCookie(r, sessionCookieBaseName))
}

func (p *identityProvider) issueSession(w http.ResponseWriter, userLabel string, authenticatedAt time.Time, sessionID string) string {
	cookie := p.newCookie(sessionCookieBaseName) // #nosec G124
	cookie.Value = rand.Text()
	cookieDigest := sha256.Sum256([]byte(cookie.Value))

	if sessionID != "" {
		p.mu.Lock()
		currentSession, sessionKnown := p.sessions[sessionID]
		if sessionKnown && currentSession.userLabel == userLabel && !p.isSessionExpired(currentSession, authenticatedAt) {
			currentSession.cookieDigest = cookieDigest
			currentSession.authenticatedAt = authenticatedAt
			currentSession.lastSeenAt = authenticatedAt
			p.sessions[sessionID] = currentSession
			p.mu.Unlock()
			http.SetCookie(w, cookie)
			slog.Info("user signed in", "label", userLabel, "sid", sessionID)
			return sessionID
		}
		p.mu.Unlock()
		p.clearSession(w, sessionID)
	}

	sessionID = rand.Text()
	p.mu.Lock()
	p.sessions[sessionID] = session{
		userLabel:       userLabel,
		cookieDigest:    cookieDigest,
		clientIDs:       map[string]struct{}{},
		authenticatedAt: authenticatedAt,
		lastSeenAt:      authenticatedAt,
	}
	p.removeExpiredState()
	p.mu.Unlock()
	http.SetCookie(w, cookie)
	slog.Info("user signed in", "label", userLabel, "sid", sessionID)
	return sessionID
}

func (p *identityProvider) clearSession(w http.ResponseWriter, sessionID string) {
	p.mu.Lock()
	currentSession, sessionKnown := p.sessions[sessionID]
	delete(p.sessions, sessionID)
	for k, v := range p.pendingCodes {
		if v.sessionID == sessionID {
			delete(p.pendingCodes, k)
		}
	}
	for k, v := range p.accessTokens {
		if v.sessionID == sessionID {
			delete(p.accessTokens, k)
		}
	}
	for k, v := range p.refreshTokens {
		if v.sessionID == sessionID {
			delete(p.refreshTokens, k)
		}
	}
	p.mu.Unlock()
	if sessionKnown {
		slog.Info("session ended", "label", currentSession.userLabel, "sid", sessionID)
	}
	cookie := p.newCookie(sessionCookieBaseName) // #nosec G124
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)

	logoutUser, _ := p.lookupUser(currentSession.userLabel)
	var wg sync.WaitGroup
	for clientID := range currentSession.clientIDs {
		client, ok := p.clients[clientID]
		if !ok || client.backchannelLogoutURI.String() == "" {
			continue
		}
		wg.Go(func() {
			p.sendBackchannelLogout(client, logoutUser, sessionID)
		})
	}
	wg.Wait()
}

func (p *identityProvider) resumeSession(sessionID string) (session, bool) {
	if sessionID == "" {
		return session{}, false
	}
	now := time.Now()
	p.mu.Lock()
	currentSession, ok := p.sessions[sessionID]
	if ok && p.isSessionExpired(currentSession, now) {
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
	currentUser, ok := p.lookupUser(currentSession.userLabel)
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

func (p *identityProvider) sessionIDFromCookie(value string) string {
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	p.mu.Lock()
	defer p.mu.Unlock()
	for sessionID, currentSession := range p.sessions {
		if subtle.ConstantTimeCompare(currentSession.cookieDigest[:], digest[:]) == 1 {
			return sessionID
		}
	}
	return ""
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

// -------------------------------------------------------------------------- //

func (p *identityProvider) revokeGrant(code string) {
	delete(p.pendingCodes, code)
	for k, v := range p.accessTokens {
		if subtle.ConstantTimeCompare([]byte(v.code), []byte(code)) == 1 {
			delete(p.accessTokens, k)
		}
	}
	for k, v := range p.refreshTokens {
		if subtle.ConstantTimeCompare([]byte(v.code), []byte(code)) == 1 {
			delete(p.refreshTokens, k)
		}
	}
}

func (p *identityProvider) removeExpiredState() {
	now := time.Now()
	for k, v := range p.sessions {
		if now.Sub(v.authenticatedAt) > p.sessionMaxTTL+p.refreshTokenMaxTTL+p.accessTokenTTL {
			delete(p.sessions, k)
		}
	}
	for k, v := range p.pendingCodes {
		if p.isPendingCodeExpired(v, now) {
			delete(p.pendingCodes, k)
		}
	}
	for k, v := range p.pendingTOTPs {
		if now.Sub(v.createdAt) > loginActionTTL {
			delete(p.pendingTOTPs, k)
		}
	}
	for k, v := range p.accessTokens {
		if now.After(v.expiry) {
			delete(p.accessTokens, k)
		}
	}
	for k, v := range p.refreshTokens {
		expired := p.isRefreshTokenExpired(v, now)
		if !v.consumedAt.IsZero() {
			expired = now.Sub(v.sessionStartedAt) > p.refreshTokenMaxTTL
		}
		if expired {
			delete(p.refreshTokens, k)
		}
	}
}

func (p *identityProvider) isSessionExpired(currentSession session, now time.Time) bool {
	return now.Sub(currentSession.lastSeenAt) > p.sessionIdleTTL || now.Sub(currentSession.authenticatedAt) > p.sessionMaxTTL
}

func (p *identityProvider) isRefreshTokenExpired(token refreshToken, now time.Time) bool {
	return now.Sub(token.createdAt) > p.refreshTokenIdleTTL || now.Sub(token.sessionStartedAt) > p.refreshTokenMaxTTL
}

func (p *identityProvider) isPendingCodeExpired(code pendingCode, now time.Time) bool {
	if !code.consumedAt.IsZero() {
		return now.Sub(code.consumedAt) > p.refreshTokenMaxTTL+p.accessTokenTTL
	}
	ttl := codeTTL
	if code.consentRequired {
		ttl = loginActionTTL
	}
	return now.Sub(code.createdAt) > ttl
}

// -------------------------------------------------------------------------- //

func (p *identityProvider) lookupUser(label string) (user, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	currentUser, ok := p.users[label]
	return currentUser, ok
}

func (p *identityProvider) updateUser(updatedUser user) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for label, otherUser := range p.users {
		if label != updatedUser.label && otherUser.username == updatedUser.username {
			return false
		}
	}
	p.users[updatedUser.label] = updatedUser
	return true
}

func (p *identityProvider) authenticateLogin(w http.ResponseWriter, r *http.Request, action string, params url.Values) (user, bool) {
	preAuthID := p.readPreAuthSession(r)
	if r.PostForm.Has("totp") {
		authenticatedUser, errorMsg, pending := p.authenticateTOTP(preAuthID, r.PostForm.Get("totp"))
		if !pending {
			p.renderLoginForm(w, r, action, params, "", errorMsg)
			return user{}, false
		}
		if errorMsg != msgNone {
			p.renderTOTPForm(w, r, action, params, preAuthID, errorMsg)
			return user{}, false
		}
		return authenticatedUser, true
	}

	username := r.PostForm.Get("username")
	authenticatedUser, errorMsg := p.authenticateEndUser(username, r.PostForm.Get("password"))
	if errorMsg != msgNone {
		p.renderLoginForm(w, r, action, params, username, errorMsg)
		return user{}, false
	}
	if authenticatedUser.totpSecret != nil {
		p.mu.Lock()
		delete(p.pendingTOTPs, preAuthID)
		p.removeExpiredState()
		var pendingIDs []string
		for id, pending := range p.pendingTOTPs {
			if pending.userLabel == authenticatedUser.label {
				pendingIDs = append(pendingIDs, id)
			}
		}
		if len(pendingIDs) >= maxPendingTOTPsPerUser {
			delete(p.pendingTOTPs, slices.MinFunc(pendingIDs, func(a, b string) int {
				return p.pendingTOTPs[a].createdAt.Compare(p.pendingTOTPs[b].createdAt)
			}))
		}
		preAuthID = rand.Text()
		p.pendingTOTPs[preAuthID] = pendingTOTP{userLabel: authenticatedUser.label, createdAt: time.Now()}
		p.mu.Unlock()
		slog.Debug("authentication code required", "label", authenticatedUser.label)
		p.renderTOTPForm(w, r, action, params, preAuthID, msgNone)
		return user{}, false
	}
	return authenticatedUser, true
}

func (p *identityProvider) authenticateEndUser(username, password string) (user, message) {
	p.mu.Lock()
	now := time.Now()
	for _, candidate := range p.users {
		if candidate.username != username {
			continue
		}
		throttleKey := "password:" + candidate.label
		if wait := p.throttleWait(throttleKey, throttle1FAMaxDelay, now); wait > 0 {
			p.mu.Unlock()
			slog.Warn("password attempt throttled", "username", logValue(username), "retry_after", wait.Round(time.Millisecond).String())
			return user{}, msgInvalidCredentials
		}
		if subtle.ConstantTimeCompare([]byte(password), []byte(candidate.password)) != 1 {
			p.recordFailedAttempt(throttleKey, now)
			failures := p.throttles[throttleKey].failures
			p.mu.Unlock()
			slog.Warn("password rejected", "username", logValue(username), "reason", "wrong password", "failures", failures)
			return user{}, msgInvalidCredentials
		}
		delete(p.throttles, throttleKey)
		p.mu.Unlock()
		slog.Info("password accepted", "label", candidate.label, "username", logValue(username))
		return candidate, msgNone
	}
	p.mu.Unlock()
	slog.Warn("password rejected", "username", logValue(username), "reason", "unknown username")
	return user{}, msgInvalidCredentials
}

func (p *identityProvider) authenticateTOTP(preAuthID, code string) (user, message, bool) {
	p.mu.Lock()
	now := time.Now()
	pending, ok := p.pendingTOTPs[preAuthID]
	if !ok {
		p.mu.Unlock()
		slog.Warn("authentication code rejected", "reason", "no pending authentication step")
		return user{}, msgSignInAgain, false
	}
	if now.Sub(pending.createdAt) > loginActionTTL {
		delete(p.pendingTOTPs, preAuthID)
		p.mu.Unlock()
		slog.Warn("authentication code rejected", "label", pending.userLabel, "reason", "authentication step expired")
		return user{}, msgSignInAgain, false
	}
	throttleKey := "totp:" + pending.userLabel
	if wait := p.throttleWait(throttleKey, throttle2FAMaxDelay, now); wait > 0 {
		p.mu.Unlock()
		slog.Warn("authentication code attempt throttled", "label", pending.userLabel, "retry_after", wait.Round(time.Millisecond).String())
		return user{}, msgTooManyAttempts, true
	}
	if !p.validateTOTP(pending.userLabel, code, now) {
		p.recordFailedAttempt(throttleKey, now)
		failures := p.throttles[throttleKey].failures
		p.mu.Unlock()
		slog.Warn("authentication code rejected", "label", pending.userLabel, "reason", "invalid, expired, or reused code", "failures", failures)
		return user{}, msgInvalidAuthenticationCode, true
	}
	delete(p.pendingTOTPs, preAuthID)
	delete(p.throttles, throttleKey)
	authenticatedUser := p.users[pending.userLabel]
	p.mu.Unlock()
	slog.Info("authentication code accepted", "label", pending.userLabel)
	return authenticatedUser, msgNone, true
}

func (p *identityProvider) validateTOTP(userLabel, code string, now time.Time) bool {
	secret := p.users[userLabel].totpSecret
	current := now.Unix() / totpPeriodSeconds
	lastStep := p.lastTOTPSteps[userLabel]
	for step := current - 3; step <= current+1; step++ {
		mac := hmac.New(sha1.New, secret)
		_ = binary.Write(mac, binary.BigEndian, step)
		sum := mac.Sum(nil)
		offset := sum[len(sum)-1] & 0x0f
		value := binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff
		if hmac.Equal([]byte(code), fmt.Appendf(nil, "%06d", value%1000000)) {
			if step <= lastStep {
				return false
			}
			if step >= current-1 {
				p.lastTOTPSteps[userLabel] = step
			}
		}
	}
	return p.lastTOTPSteps[userLabel] != lastStep
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
		slog.Warn("client secret rejected", "client_id", c.id)
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

func (p *identityProvider) throttleWait(key string, maxDelay time.Duration, now time.Time) time.Duration {
	attempts := p.throttles[key]
	if attempts.failures < throttleFreeFailures {
		return 0
	}
	delay := min(maxDelay, throttleBaseDelay<<min(attempts.failures-throttleFreeFailures, 20))
	return max(0, attempts.lastFailure.Add(delay).Sub(now))
}

func (p *identityProvider) recordFailedAttempt(key string, now time.Time) {
	attempts := p.throttles[key]
	if now.Sub(attempts.lastFailure) > throttleTTL {
		attempts.failures = 0
	}
	p.throttles[key] = throttle{failures: attempts.failures + 1, lastFailure: now}
}

func (p *identityProvider) resolveBearerToken(token string) (user, accessToken, bool) {
	p.mu.Lock()
	storedAccessToken, tokenKnown := p.accessTokens[token]
	p.mu.Unlock()

	if !tokenKnown || time.Now().After(storedAccessToken.expiry) {
		return user{}, accessToken{}, false
	}

	currentUser, _ := p.lookupUser(storedAccessToken.userLabel)
	return currentUser, storedAccessToken, true
}

// -------------------------------------------------------------------------- //

func (p *identityProvider) mintAccessToken(client client, user user, scope string, issuedAt time.Time) (string, error) {
	payload := map[string]any{
		"iss":       p.issuer,
		"sub":       client.id,
		"aud":       client.audience,
		"client_id": client.id,
		"iat":       issuedAt.Unix(),
		"exp":       issuedAt.Add(p.accessTokenTTL).Unix(),
		"jti":       rand.Text(),
	}
	if scope != "" {
		payload["scope"] = scope
	}
	if user.label != "" {
		maps.Copy(payload, p.buildClaimsForScope(user, scope))
	}

	return p.signJWT("at+jwt", payload)
}

func (p *identityProvider) mintIDToken(user user, client client, code pendingCode, accessToken string, issuedAt time.Time) (string, error) {
	atHash := sha256.Sum256([]byte(accessToken))
	payload := map[string]any{
		"iss":       p.issuer,
		"sub":       user.sub,
		"aud":       client.id,
		"iat":       issuedAt.Unix(),
		"exp":       issuedAt.Add(p.accessTokenTTL).Unix(),
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

	return p.signJWT("JWT", payload)
}

func (p *identityProvider) mintLogoutToken(user user, client client, sessionID string) (string, error) {
	if client.backchannelLogoutSessionRequired && sessionID == "" {
		return "", errors.New("client requires a session ID in logout tokens")
	}
	now := time.Now().Unix()

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
	if sessionID != "" {
		payload["sid"] = sessionID
	}

	return p.signJWT("logout+jwt", payload)
}

func (p *identityProvider) signJWT(typ string, payload map[string]any) (string, error) {
	header := map[string]string{
		"alg": "RS256",
		"typ": typ,
		"kid": p.keyID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

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

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := httpClient.PostForm(client.backchannelLogoutURI.String(), url.Values{
		"logout_token": {logoutToken},
	})
	if err != nil {
		slog.Error("back-channel logout request failed", "client_id", client.id, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		slog.Error("back-channel logout rejected", "client_id", client.id, "status", resp.Status)
		return
	}
	slog.Debug("back-channel logout delivered", "client_id", client.id, "status", resp.Status)
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
			claims["preferred_username"] = cmp.Or(user.preferredUsername, user.username)
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
		case "roles":
			claims["roles"] = user.roles
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
	_ = json.MarshalWrite(w, v, json.Deterministic(true))
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

func hasUniqueParams(params url.Values, names ...string) bool {
	for name, values := range params {
		if len(names) != 0 && !slices.Contains(names, name) {
			continue
		}
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
	if !utf8.ValidString(params.Get("nonce")) {
		return "invalid_request", "Invalid nonce"
	}
	return "", ""
}

func filterScope(scope string) (string, bool) {
	var kept []string
	for candidateScope := range strings.FieldsSeq(scope) {
		switch candidateScope {
		case "openid", "profile", "email", "groups", "roles":
			if !slices.Contains(kept, candidateScope) {
				kept = append(kept, candidateScope)
			}
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

func isValidScope(scope string) bool {
	if scope != strings.Join(strings.Fields(scope), " ") {
		return false
	}
	return !strings.ContainsFunc(scope, func(c rune) bool { return c < ' ' || c > '~' || c == '"' || c == '\\' })
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

func isAllowedRedirectURL(redirectURLs []string, rawRedirectURI string, allowLoopbackPort bool) bool {
	redirectURI, err := url.Parse(rawRedirectURI)
	for _, rawRedirectURL := range redirectURLs {
		if rawRedirectURL == rawRedirectURI {
			return true
		}
		if !allowLoopbackPort || err != nil {
			continue
		}
		redirectURL, err := url.Parse(rawRedirectURL)
		if err != nil || !isLoopbackURL(redirectURL) || !isLoopbackURL(redirectURI) ||
			redirectURI.User != nil || redirectURL.Hostname() != redirectURI.Hostname() {
			continue
		}
		if strings.Replace(rawRedirectURL, "://"+redirectURL.Host, "://"+redirectURI.Host, 1) == rawRedirectURI {
			return true
		}
	}
	return false
}

func resolvePostLogoutRedirectURL(postLogoutRedirectURLs []string, postLogoutRedirectURI string) (url.URL, bool) {
	for _, rawPostLogoutRedirectURL := range postLogoutRedirectURLs {
		if rawPostLogoutRedirectURL == postLogoutRedirectURI {
			postLogoutRedirectURL, err := url.Parse(rawPostLogoutRedirectURL)
			if err == nil {
				return *postLogoutRedirectURL, true
			}
		}
	}
	return url.URL{}, false
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

func validateRedirectURLs(rawURLs string) ([]string, error) {
	var redirectURLs []string
	for rawURL := range strings.FieldsSeq(rawURLs) {
		_, err := validateRedirectURL(rawURL)
		if err != nil {
			return nil, err
		}
		redirectURLs = append(redirectURLs, rawURL)
	}
	if len(redirectURLs) == 0 {
		return nil, errors.New("must include at least one URL")
	}
	return redirectURLs, nil
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
	if strings.Contains(rawURL, "#") {
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

func logValue(s string) string {
	return s[:min(len(s), maxLogValueBytes)]
}

// -------------------------------------------------------------------------- //

func scanLabels(environ []string, prefix string, suffixes ...string) map[string]struct{} {
	labels := map[string]struct{}{}
	var ambiguousLabels [][]string
	for _, env := range environ {
		key, _, ok := strings.Cut(env, "=")
		if !ok || !strings.HasPrefix(key, prefix) {
			continue
		}
		var matches []string
		for _, suffix := range suffixes {
			label, ok := strings.CutSuffix(key[len(prefix):], suffix)
			if ok && label != "" {
				matches = append(matches, label)
			}
		}
		switch len(matches) {
		case 0:
		case 1:
			labels[matches[0]] = struct{}{}
		default:
			ambiguousLabels = append(ambiguousLabels, matches)
		}
	}
	for _, matches := range ambiguousLabels {
		label := matches[0]
		known := false
		for _, candidate := range matches {
			if _, known = labels[candidate]; known {
				break
			}
			if len(candidate) < len(label) {
				label = candidate
			}
		}
		if !known {
			labels[label] = struct{}{}
		}
	}
	return labels
}

func loadClients(environ []string, lookupEnv func(string) string) (map[string]client, error) {
	const prefix = "SIMPLE_IDP_CLIENT_"

	labels := scanLabels(environ, prefix,
		"_ID",
		"_SECRET",
		"_AUDIENCE",
		"_REDIRECT_URL",
		"_POST_LOGOUT_REDIRECT_URL",
		"_BACKCHANNEL_LOGOUT_URI",
		"_BACKCHANNEL_LOGOUT_SESSION_REQUIRED",
	)

	clients := map[string]client{}
	for label := range labels {
		id := lookupEnv(prefix + label + "_ID")
		secret := lookupEnv(prefix + label + "_SECRET")
		audience := envOr(lookupEnv, prefix+label+"_AUDIENCE", id)
		rawRedirectURL := lookupEnv(prefix + label + "_REDIRECT_URL")
		if id == "" || (secret == "" && rawRedirectURL == "") {
			return nil, fmt.Errorf("incomplete client configuration for label %q", label)
		}
		if _, dup := clients[id]; dup {
			return nil, fmt.Errorf("duplicate client ID %q", id)
		}
		var redirectURLs []string
		var err error
		if rawRedirectURL != "" {
			redirectURLs, err = validateRedirectURLs(rawRedirectURL)
			if err != nil {
				return nil, fmt.Errorf("client %q redirect URL: %w", label, err)
			}
		}
		isPublic := secret == ""
		if isPublic {
			for _, rawURL := range redirectURLs {
				redirectURL, _ := url.Parse(rawURL)
				if !isLoopbackURL(redirectURL) {
					return nil, fmt.Errorf("client %q: public clients (no secret) must use loopback redirect URLs", label)
				}
			}
		}
		var postLogoutRedirectURLs []string
		if raw := lookupEnv(prefix + label + "_POST_LOGOUT_REDIRECT_URL"); raw != "" {
			postLogoutRedirectURLs, err = validateRedirectURLs(raw)
			if err != nil {
				return nil, fmt.Errorf("client %q post-logout redirect URL: %w", label, err)
			}
		}
		var backchannelLogoutURI url.URL
		if raw := lookupEnv(prefix + label + "_BACKCHANNEL_LOGOUT_URI"); raw != "" {
			parsed, err := validateRedirectURL(raw)
			if err != nil {
				return nil, fmt.Errorf("client %q backchannel logout URI: %w", label, err)
			}
			backchannelLogoutURI = *parsed
		}
		backchannelLogoutSessionRequired := lookupEnv(prefix+label+"_BACKCHANNEL_LOGOUT_SESSION_REQUIRED") == "true"
		clients[id] = client{
			id:                               id,
			secret:                           secret,
			isPublic:                         isPublic,
			audience:                         audience,
			redirectURLs:                     redirectURLs,
			postLogoutRedirectURLs:           postLogoutRedirectURLs,
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

	labels := scanLabels(environ, prefix,
		"_USERNAME",
		"_PASSWORD",
		"_TOTP_SECRET",
		"_SUB",
		"_NAME",
		"_PREFERRED_USERNAME",
		"_EMAIL",
		"_EMAIL_VERIFIED",
		"_PROFILE",
		"_PICTURE",
		"_LOCALE",
		"_GROUPS",
		"_ROLES",
	)

	users := map[string]user{}
	usernames := map[string]struct{}{}
	totpSecrets := map[string]struct{}{}
	subs := map[string]struct{}{}
	for label := range labels {
		username := envOr(lookupEnv, prefix+label+"_USERNAME", "")
		password := envOr(lookupEnv, prefix+label+"_PASSWORD", "")
		sub := envOr(lookupEnv, prefix+label+"_SUB", fmt.Sprintf("%x", sha256.Sum256([]byte(label))))
		name := envOr(lookupEnv, prefix+label+"_NAME", username)
		preferredUsername := envOr(lookupEnv, prefix+label+"_PREFERRED_USERNAME", "")
		email := envOr(lookupEnv, prefix+label+"_EMAIL", strings.ReplaceAll(url.PathEscape(username), "..", ".%2E")+"@localhost")
		emailVerified := envOr(lookupEnv, prefix+label+"_EMAIL_VERIFIED", "true") == "true"
		profile := envOr(lookupEnv, prefix+label+"_PROFILE", "")
		picture := envOr(lookupEnv, prefix+label+"_PICTURE", "")
		locale := envOr(lookupEnv, prefix+label+"_LOCALE", "")
		groups := envSplit(lookupEnv, prefix+label+"_GROUPS", ",")
		roles := envSplit(lookupEnv, prefix+label+"_ROLES", ",")

		if username == "" || password == "" {
			return nil, fmt.Errorf("incomplete user configuration for label %q", label)
		}

		if _, dup := usernames[username]; dup {
			return nil, fmt.Errorf("duplicate username %q", username)
		}
		usernames[username] = struct{}{}

		var totpSecret []byte
		if raw := envOr(lookupEnv, prefix+label+"_TOTP_SECRET", ""); raw != "" {
			secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(raw, "=")))
			if err != nil || len(secret) < 16 {
				return nil, fmt.Errorf("user %q: TOTP secret must be base32 and encode at least 128 bits", label)
			}
			hmacKey := string(secret)
			if len(secret) > sha1.BlockSize {
				sum := sha1.Sum(secret) // #nosec G401
				hmacKey = string(sum[:])
			}
			hmacKey = strings.TrimRight(hmacKey, "\x00")
			if _, dup := totpSecrets[hmacKey]; dup {
				return nil, fmt.Errorf("duplicate TOTP secret for user %q", label)
			}
			totpSecrets[hmacKey] = struct{}{}
			totpSecret = secret
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

		users[label] = user{
			label:             label,
			username:          username,
			password:          password,
			totpSecret:        totpSecret,
			sub:               sub,
			name:              name,
			preferredUsername: preferredUsername,
			email:             email,
			emailVerified:     emailVerified,
			profile:           profile,
			picture:           picture,
			locale:            locale,
			groups:            groups,
			roles:             roles,
		}
		slog.LogAttrs(context.Background(), slog.LevelInfo, "registered user", slog.String("label", label), slog.String("username", username), slog.Bool("totp", totpSecret != nil), slog.String("sub", sub))
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

	key, err := rsa.GenerateKey(rand.Reader, 3072)
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
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key from %q must be at least 2048 bits", source)
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

func envDuration(lookupEnv func(string) string, name string, fallback time.Duration) (time.Duration, error) {
	v := lookupEnv(name)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: must be a positive duration", name)
	}
	return d, nil
}

// -------------------------------------------------------------------------- //

type message int

const (
	msgNone message = iota
	msgName
	msgUsername
	msgEmail
	msgPassword
	msgAuthenticationCode
	msgRedirectURI
	msgSave
	msgSignIn
	msgVerify
	msgContinue
	msgAllow
	msgDeny
	msgLogOut
	msgCancel
	msgReturnToApplication
	msgEnterAuthenticationCode
	msgConsentRequest
	msgLogoutRequest
	msgLogoutCanceled
	msgLogoutComplete
	msgUsernameAndNameRequired
	msgInvalidEmail
	msgUsernameTaken
	msgInvalidCredentials
	msgSignInAgain
	msgTooManyAttempts
	msgInvalidAuthenticationCode
)

const (
	firstStrongIsolate    = "\u2068"
	popDirectionalIsolate = "\u2069"
)

type language struct {
	tag      string
	dir      string
	messages map[message]string
}

var languages = []language{
	{tag: "ar", dir: "rtl", messages: map[message]string{
		msgName:                      "الاسم",
		msgUsername:                  "اسم المستخدم",
		msgEmail:                     "البريد الإلكتروني",
		msgPassword:                  "كلمة المرور",
		msgAuthenticationCode:        "رمز المصادقة",
		msgRedirectURI:               "عنوان URI لإعادة التوجيه",
		msgSave:                      "حفظ",
		msgSignIn:                    "تسجيل الدخول",
		msgVerify:                    "تحقق",
		msgContinue:                  "متابعة",
		msgAllow:                     "السماح",
		msgDeny:                      "رفض",
		msgLogOut:                    "تسجيل الخروج",
		msgCancel:                    "إلغاء",
		msgReturnToApplication:       "العودة إلى التطبيق",
		msgEnterAuthenticationCode:   "أدخل الرمز من تطبيق المصادقة.",
		msgConsentRequest:            "هل تريد السماح للتطبيق %s بالوصول إلى هذه النطاقات: %s؟",
		msgLogoutRequest:             "هل تريد تسجيل الخروج من موفر الهوية هذا؟",
		msgLogoutCanceled:            "تم إلغاء تسجيل الخروج. لا تزال جلستك نشطة.",
		msgLogoutComplete:            "تم تسجيل خروجك.",
		msgUsernameAndNameRequired:   "اسم المستخدم والاسم مطلوبان",
		msgInvalidEmail:              "عنوان البريد الإلكتروني غير صالح",
		msgUsernameTaken:             "اسم المستخدم مستخدم بالفعل",
		msgInvalidCredentials:        "اسم المستخدم أو كلمة المرور غير صحيحة",
		msgSignInAgain:               "سجّل الدخول مرة أخرى للمتابعة",
		msgTooManyAttempts:           "محاولات فاشلة كثيرة جدًا، حاول مرة أخرى لاحقًا",
		msgInvalidAuthenticationCode: "رمز المصادقة غير صالح",
	}},
	{tag: "de", dir: "ltr", messages: map[message]string{
		msgName:                      "Name",
		msgUsername:                  "Benutzername",
		msgEmail:                     "E-Mail",
		msgPassword:                  "Passwort",
		msgAuthenticationCode:        "Authentifizierungscode",
		msgRedirectURI:               "Weiterleitungs-URI",
		msgSave:                      "Speichern",
		msgSignIn:                    "Anmelden",
		msgVerify:                    "Überprüfen",
		msgContinue:                  "Weiter",
		msgAllow:                     "Zulassen",
		msgDeny:                      "Ablehnen",
		msgLogOut:                    "Abmelden",
		msgCancel:                    "Abbrechen",
		msgReturnToApplication:       "Zurück zur Anwendung",
		msgEnterAuthenticationCode:   "Geben Sie den Code aus Ihrer Authentifizierungs-App ein.",
		msgConsentRequest:            "%s den Zugriff auf diese Bereiche erlauben: %s?",
		msgLogoutRequest:             "Von diesem Identitätsanbieter abmelden?",
		msgLogoutCanceled:            "Abmeldung abgebrochen. Sie sind weiterhin angemeldet.",
		msgLogoutComplete:            "Sie wurden abgemeldet.",
		msgUsernameAndNameRequired:   "Benutzername und Name sind erforderlich",
		msgInvalidEmail:              "Ungültige E-Mail-Adresse",
		msgUsernameTaken:             "Benutzername bereits vergeben",
		msgInvalidCredentials:        "Benutzername oder Passwort ungültig",
		msgSignInAgain:               "Melden Sie sich erneut an, um fortzufahren",
		msgTooManyAttempts:           "Zu viele Fehlversuche, versuchen Sie es später erneut",
		msgInvalidAuthenticationCode: "Ungültiger Authentifizierungscode",
	}},
	{tag: "en", dir: "ltr", messages: map[message]string{
		msgName:                      "Name",
		msgUsername:                  "Username",
		msgEmail:                     "Email",
		msgPassword:                  "Password",
		msgAuthenticationCode:        "Authentication code",
		msgRedirectURI:               "Redirect URI",
		msgSave:                      "Save",
		msgSignIn:                    "Sign in",
		msgVerify:                    "Verify",
		msgContinue:                  "Continue",
		msgAllow:                     "Allow",
		msgDeny:                      "Deny",
		msgLogOut:                    "Log out",
		msgCancel:                    "Cancel",
		msgReturnToApplication:       "Return to application",
		msgEnterAuthenticationCode:   "Enter the code from your authenticator app.",
		msgConsentRequest:            "Allow %s to access these scopes: %s?",
		msgLogoutRequest:             "Log out of this identity provider?",
		msgLogoutCanceled:            "Logout canceled. You are still signed in.",
		msgLogoutComplete:            "You have been signed out.",
		msgUsernameAndNameRequired:   "Username and name are required",
		msgInvalidEmail:              "Invalid email address",
		msgUsernameTaken:             "Username already taken",
		msgInvalidCredentials:        "Invalid username or password",
		msgSignInAgain:               "Sign in again to continue",
		msgTooManyAttempts:           "Too many failed attempts, try again later",
		msgInvalidAuthenticationCode: "Invalid authentication code",
	}},
	{tag: "es", dir: "ltr", messages: map[message]string{
		msgName:                      "Nombre",
		msgUsername:                  "Nombre de usuario",
		msgEmail:                     "Correo electrónico",
		msgPassword:                  "Contraseña",
		msgAuthenticationCode:        "Código de autenticación",
		msgRedirectURI:               "URI de redirección",
		msgSave:                      "Guardar",
		msgSignIn:                    "Iniciar sesión",
		msgVerify:                    "Verificar",
		msgContinue:                  "Continuar",
		msgAllow:                     "Permitir",
		msgDeny:                      "Denegar",
		msgLogOut:                    "Cerrar sesión",
		msgCancel:                    "Cancelar",
		msgReturnToApplication:       "Volver a la aplicación",
		msgEnterAuthenticationCode:   "Introduce el código de tu aplicación de autenticación.",
		msgConsentRequest:            "¿Permitir que %s acceda a estos ámbitos: %s?",
		msgLogoutRequest:             "¿Cerrar sesión en este proveedor de identidad?",
		msgLogoutCanceled:            "Cierre de sesión cancelado. Tu sesión sigue iniciada.",
		msgLogoutComplete:            "Se ha cerrado la sesión.",
		msgUsernameAndNameRequired:   "El nombre de usuario y el nombre son obligatorios",
		msgInvalidEmail:              "Correo electrónico no válido",
		msgUsernameTaken:             "El nombre de usuario ya está en uso",
		msgInvalidCredentials:        "Nombre de usuario o contraseña incorrectos",
		msgSignInAgain:               "Inicia sesión de nuevo para continuar",
		msgTooManyAttempts:           "Demasiados intentos fallidos, inténtalo de nuevo más tarde",
		msgInvalidAuthenticationCode: "Código de autenticación no válido",
	}},
	{tag: "fr", dir: "ltr", messages: map[message]string{
		msgName:                      "Nom",
		msgUsername:                  "Nom d’utilisateur",
		msgEmail:                     "E-mail",
		msgPassword:                  "Mot de passe",
		msgAuthenticationCode:        "Code d’authentification",
		msgRedirectURI:               "URI de redirection",
		msgSave:                      "Enregistrer",
		msgSignIn:                    "Se connecter",
		msgVerify:                    "Vérifier",
		msgContinue:                  "Continuer",
		msgAllow:                     "Autoriser",
		msgDeny:                      "Refuser",
		msgLogOut:                    "Se déconnecter",
		msgCancel:                    "Annuler",
		msgReturnToApplication:       "Retour à l’application",
		msgEnterAuthenticationCode:   "Saisissez le code de votre application d’authentification.",
		msgConsentRequest:            "Autoriser %s à accéder à ces étendues\u00a0: %s\u00a0?",
		msgLogoutRequest:             "Se déconnecter de ce fournisseur d’identité\u00a0?",
		msgLogoutCanceled:            "Déconnexion annulée. Votre session est toujours active.",
		msgLogoutComplete:            "Déconnexion effectuée.",
		msgUsernameAndNameRequired:   "Le nom d’utilisateur et le nom sont obligatoires",
		msgInvalidEmail:              "Adresse e-mail non valide",
		msgUsernameTaken:             "Ce nom d’utilisateur est déjà utilisé",
		msgInvalidCredentials:        "Nom d’utilisateur ou mot de passe incorrect",
		msgSignInAgain:               "Reconnectez-vous pour continuer",
		msgTooManyAttempts:           "Trop de tentatives infructueuses, réessayez plus tard",
		msgInvalidAuthenticationCode: "Code d’authentification non valide",
	}},
	{tag: "it", dir: "ltr", messages: map[message]string{
		msgName:                      "Nome",
		msgUsername:                  "Nome utente",
		msgEmail:                     "Email",
		msgPassword:                  "Password",
		msgAuthenticationCode:        "Codice di autenticazione",
		msgRedirectURI:               "URI di reindirizzamento",
		msgSave:                      "Salva",
		msgSignIn:                    "Accedi",
		msgVerify:                    "Verifica",
		msgContinue:                  "Continua",
		msgAllow:                     "Consenti",
		msgDeny:                      "Nega",
		msgLogOut:                    "Esci",
		msgCancel:                    "Annulla",
		msgReturnToApplication:       "Torna all’applicazione",
		msgEnterAuthenticationCode:   "Inserisci il codice della tua app di autenticazione.",
		msgConsentRequest:            "Consentire a %s di accedere a questi ambiti: %s?",
		msgLogoutRequest:             "Uscire da questo provider di identità?",
		msgLogoutCanceled:            "Disconnessione annullata. La tua sessione è ancora attiva.",
		msgLogoutComplete:            "Disconnessione effettuata.",
		msgUsernameAndNameRequired:   "Nome utente e nome sono obbligatori",
		msgInvalidEmail:              "Indirizzo email non valido",
		msgUsernameTaken:             "Nome utente già in uso",
		msgInvalidCredentials:        "Nome utente o password non validi",
		msgSignInAgain:               "Accedi di nuovo per continuare",
		msgTooManyAttempts:           "Troppi tentativi non riusciti, riprova più tardi",
		msgInvalidAuthenticationCode: "Codice di autenticazione non valido",
	}},
	{tag: "ja", dir: "ltr", messages: map[message]string{
		msgName:                      "名前",
		msgUsername:                  "ユーザー名",
		msgEmail:                     "メールアドレス",
		msgPassword:                  "パスワード",
		msgAuthenticationCode:        "認証コード",
		msgRedirectURI:               "リダイレクト URI",
		msgSave:                      "保存",
		msgSignIn:                    "ログイン",
		msgVerify:                    "確認",
		msgContinue:                  "続行",
		msgAllow:                     "許可",
		msgDeny:                      "拒否",
		msgLogOut:                    "ログアウト",
		msgCancel:                    "キャンセル",
		msgReturnToApplication:       "アプリケーションに戻る",
		msgEnterAuthenticationCode:   "認証アプリに表示されているコードを入力してください。",
		msgConsentRequest:            "%s にスコープ %s へのアクセスを許可しますか？",
		msgLogoutRequest:             "この ID プロバイダーからログアウトしますか？",
		msgLogoutCanceled:            "ログアウトをキャンセルしました。引き続きログインしています。",
		msgLogoutComplete:            "ログアウトしました。",
		msgUsernameAndNameRequired:   "ユーザー名と名前は必須です",
		msgInvalidEmail:              "メールアドレスが無効です",
		msgUsernameTaken:             "このユーザー名は既に使用されています",
		msgInvalidCredentials:        "ユーザー名またはパスワードが正しくありません",
		msgSignInAgain:               "続行するには再度ログインしてください",
		msgTooManyAttempts:           "失敗回数が多すぎるため、しばらくしてからもう一度お試しください",
		msgInvalidAuthenticationCode: "認証コードが無効です",
	}},
	{tag: "ko", dir: "ltr", messages: map[message]string{
		msgName:                      "이름",
		msgUsername:                  "사용자 이름",
		msgEmail:                     "이메일",
		msgPassword:                  "비밀번호",
		msgAuthenticationCode:        "인증 코드",
		msgRedirectURI:               "리디렉션 URI",
		msgSave:                      "저장",
		msgSignIn:                    "로그인",
		msgVerify:                    "확인",
		msgContinue:                  "계속",
		msgAllow:                     "허용",
		msgDeny:                      "거부",
		msgLogOut:                    "로그아웃",
		msgCancel:                    "취소",
		msgReturnToApplication:       "애플리케이션으로 돌아가기",
		msgEnterAuthenticationCode:   "인증 앱에 표시된 코드를 입력하세요.",
		msgConsentRequest:            "%s에 %s 범위에 대한 접근을 허용하시겠습니까?",
		msgLogoutRequest:             "이 ID 공급자에서 로그아웃하시겠습니까?",
		msgLogoutCanceled:            "로그아웃이 취소되었습니다. 계속 로그인된 상태입니다.",
		msgLogoutComplete:            "로그아웃되었습니다.",
		msgUsernameAndNameRequired:   "사용자 이름과 이름은 필수 항목입니다",
		msgInvalidEmail:              "유효하지 않은 이메일 주소입니다",
		msgUsernameTaken:             "이미 사용 중인 사용자 이름입니다",
		msgInvalidCredentials:        "사용자 이름 또는 비밀번호가 올바르지 않습니다",
		msgSignInAgain:               "계속하려면 다시 로그인하세요",
		msgTooManyAttempts:           "실패한 시도가 너무 많습니다. 잠시 후 다시 시도하세요",
		msgInvalidAuthenticationCode: "유효하지 않은 인증 코드입니다",
	}},
	{tag: "pt-BR", dir: "ltr", messages: map[message]string{
		msgName:                      "Nome",
		msgUsername:                  "Nome de usuário",
		msgEmail:                     "E-mail",
		msgPassword:                  "Senha",
		msgAuthenticationCode:        "Código de autenticação",
		msgRedirectURI:               "URI de redirecionamento",
		msgSave:                      "Salvar",
		msgSignIn:                    "Entrar",
		msgVerify:                    "Verificar",
		msgContinue:                  "Continuar",
		msgAllow:                     "Permitir",
		msgDeny:                      "Negar",
		msgLogOut:                    "Sair",
		msgCancel:                    "Cancelar",
		msgReturnToApplication:       "Voltar para o aplicativo",
		msgEnterAuthenticationCode:   "Digite o código do seu aplicativo autenticador.",
		msgConsentRequest:            "Permitir que %s acesse estes escopos: %s?",
		msgLogoutRequest:             "Sair deste provedor de identidade?",
		msgLogoutCanceled:            "Encerramento de sessão cancelado. Sua sessão continua ativa.",
		msgLogoutComplete:            "Sua sessão foi encerrada.",
		msgUsernameAndNameRequired:   "O nome de usuário e o nome são obrigatórios",
		msgInvalidEmail:              "Endereço de e-mail inválido",
		msgUsernameTaken:             "O nome de usuário já está em uso",
		msgInvalidCredentials:        "Nome de usuário ou senha incorretos",
		msgSignInAgain:               "Entre novamente para continuar",
		msgTooManyAttempts:           "Muitas tentativas malsucedidas, tente novamente mais tarde",
		msgInvalidAuthenticationCode: "Código de autenticação inválido",
	}},
	{tag: "pt-PT", dir: "ltr", messages: map[message]string{
		msgName:                      "Nome",
		msgUsername:                  "Nome de utilizador",
		msgEmail:                     "E-mail",
		msgPassword:                  "Palavra-passe",
		msgAuthenticationCode:        "Código de autenticação",
		msgRedirectURI:               "URI de redirecionamento",
		msgSave:                      "Guardar",
		msgSignIn:                    "Iniciar sessão",
		msgVerify:                    "Verificar",
		msgContinue:                  "Continuar",
		msgAllow:                     "Permitir",
		msgDeny:                      "Recusar",
		msgLogOut:                    "Terminar sessão",
		msgCancel:                    "Cancelar",
		msgReturnToApplication:       "Voltar à aplicação",
		msgEnterAuthenticationCode:   "Introduza o código da sua aplicação de autenticação.",
		msgConsentRequest:            "Permitir que %s aceda a estes âmbitos: %s?",
		msgLogoutRequest:             "Terminar sessão neste fornecedor de identidade?",
		msgLogoutCanceled:            "Fim de sessão cancelado. A sua sessão continua ativa.",
		msgLogoutComplete:            "A sua sessão foi terminada.",
		msgUsernameAndNameRequired:   "O nome de utilizador e o nome são obrigatórios",
		msgInvalidEmail:              "Endereço de e-mail inválido",
		msgUsernameTaken:             "O nome de utilizador já está em uso",
		msgInvalidCredentials:        "Nome de utilizador ou palavra-passe incorretos",
		msgSignInAgain:               "Inicie sessão novamente para continuar",
		msgTooManyAttempts:           "Demasiadas tentativas falhadas, tente novamente mais tarde",
		msgInvalidAuthenticationCode: "Código de autenticação inválido",
	}},
	{tag: "ru", dir: "ltr", messages: map[message]string{
		msgName:                      "Имя",
		msgUsername:                  "Имя пользователя",
		msgEmail:                     "Электронная почта",
		msgPassword:                  "Пароль",
		msgAuthenticationCode:        "Код аутентификации",
		msgRedirectURI:               "URI перенаправления",
		msgSave:                      "Сохранить",
		msgSignIn:                    "Войти",
		msgVerify:                    "Подтвердить",
		msgContinue:                  "Продолжить",
		msgAllow:                     "Разрешить",
		msgDeny:                      "Отклонить",
		msgLogOut:                    "Выйти",
		msgCancel:                    "Отмена",
		msgReturnToApplication:       "Вернуться в приложение",
		msgEnterAuthenticationCode:   "Введите код из приложения-аутентификатора.",
		msgConsentRequest:            "Разрешить %s доступ к этим областям: %s?",
		msgLogoutRequest:             "Выйти из этого поставщика удостоверений?",
		msgLogoutCanceled:            "Выход отменён. Вы по-прежнему в системе.",
		msgLogoutComplete:            "Вы вышли из системы.",
		msgUsernameAndNameRequired:   "Имя пользователя и имя обязательны",
		msgInvalidEmail:              "Неверный адрес электронной почты",
		msgUsernameTaken:             "Имя пользователя уже занято",
		msgInvalidCredentials:        "Неверное имя пользователя или пароль",
		msgSignInAgain:               "Войдите снова, чтобы продолжить",
		msgTooManyAttempts:           "Слишком много неудачных попыток, повторите попытку позже",
		msgInvalidAuthenticationCode: "Неверный код аутентификации",
	}},
	{tag: "zh-Hans", dir: "ltr", messages: map[message]string{
		msgName:                      "姓名",
		msgUsername:                  "用户名",
		msgEmail:                     "电子邮件",
		msgPassword:                  "密码",
		msgAuthenticationCode:        "验证码",
		msgRedirectURI:               "重定向 URI",
		msgSave:                      "保存",
		msgSignIn:                    "登录",
		msgVerify:                    "验证",
		msgContinue:                  "继续",
		msgAllow:                     "允许",
		msgDeny:                      "拒绝",
		msgLogOut:                    "退出登录",
		msgCancel:                    "取消",
		msgReturnToApplication:       "返回应用",
		msgEnterAuthenticationCode:   "请输入身份验证器应用中的验证码。",
		msgConsentRequest:            "允许 %s 访问以下权限范围：%s？",
		msgLogoutRequest:             "要从此身份提供商退出登录吗？",
		msgLogoutCanceled:            "已取消退出。您仍处于登录状态。",
		msgLogoutComplete:            "您已退出登录。",
		msgUsernameAndNameRequired:   "用户名和姓名为必填项",
		msgInvalidEmail:              "电子邮件地址无效",
		msgUsernameTaken:             "用户名已被占用",
		msgInvalidCredentials:        "用户名或密码错误",
		msgSignInAgain:               "请重新登录以继续",
		msgTooManyAttempts:           "失败次数过多，请稍后重试",
		msgInvalidAuthenticationCode: "验证码无效",
	}},
	{tag: "zh-Hant", dir: "ltr", messages: map[message]string{
		msgName:                      "姓名",
		msgUsername:                  "使用者名稱",
		msgEmail:                     "電子郵件",
		msgPassword:                  "密碼",
		msgAuthenticationCode:        "驗證碼",
		msgRedirectURI:               "重新導向 URI",
		msgSave:                      "儲存",
		msgSignIn:                    "登入",
		msgVerify:                    "驗證",
		msgContinue:                  "繼續",
		msgAllow:                     "允許",
		msgDeny:                      "拒絕",
		msgLogOut:                    "登出",
		msgCancel:                    "取消",
		msgReturnToApplication:       "返回應用程式",
		msgEnterAuthenticationCode:   "請輸入驗證器應用程式中的驗證碼。",
		msgConsentRequest:            "允許 %s 存取以下權限範圍：%s？",
		msgLogoutRequest:             "要從此身分識別提供者登出嗎？",
		msgLogoutCanceled:            "已取消登出。您仍處於登入狀態。",
		msgLogoutComplete:            "您已登出。",
		msgUsernameAndNameRequired:   "使用者名稱和姓名為必填欄位",
		msgInvalidEmail:              "電子郵件地址無效",
		msgUsernameTaken:             "使用者名稱已被使用",
		msgInvalidCredentials:        "使用者名稱或密碼錯誤",
		msgSignInAgain:               "請重新登入以繼續",
		msgTooManyAttempts:           "失敗次數過多，請稍後再試",
		msgInvalidAuthenticationCode: "驗證碼無效",
	}},
}

func resolveLanguage(languages []language, tag string) (language, bool) {
	primary, script, region := parseLanguageTag(tag)
	match, ok := language{}, false
	for _, lang := range languages {
		candidatePrimary, candidateScript, candidateRegion := parseLanguageTag(lang.tag)
		if primary != candidatePrimary || (script != "" && candidateScript != "" && script != candidateScript) {
			continue
		}
		if region != "" && region == candidateRegion {
			return lang, true
		}
		if !ok {
			match, ok = lang, true
		}
	}
	return match, ok
}

func parseLanguageTag(tag string) (primary, script, region string) {
	subtags := strings.Split(strings.ToLower(tag), "-")
	primary, subtags = subtags[0], subtags[1:]
	if len(subtags) > 0 && len(subtags[0]) == 4 && subtags[0][0] >= 'a' && subtags[0][0] <= 'z' {
		script, subtags = subtags[0], subtags[1:]
	}
	if len(subtags) > 0 && len(subtags[0]) == 2 {
		region = subtags[0]
	}
	switch {
	case primary == "zh" && script == "" && (region == "tw" || region == "hk" || region == "mo"):
		script = "hant"
	case primary == "pt" && region != "" && region != "br":
		region = "pt"
	}
	return primary, script, region
}

func languageTags(languages []language) []string {
	tags := make([]string, 0, len(languages))
	for _, lang := range languages {
		tags = append(tags, lang.tag)
	}
	return tags
}

func isolateText(s string) string {
	return firstStrongIsolate + s + popDirectionalIsolate
}
