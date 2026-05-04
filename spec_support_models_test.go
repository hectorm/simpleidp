package simpleidp

// Reference material:
// OpenID Connect specifications index: https://openid.net/developers/specs/
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// OIDC Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
// OIDC RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
// OIDC Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt
// RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.txt

const (
	testUsername          = "alice"
	testPassword          = "password"
	testSubject           = "alice-subject"
	testName              = "Alice Example"
	testPreferredUsername = "alice"
	testEmail             = "alice@example.com"
	testProfile           = "https://rp.example/alice"
	testPicture           = "https://rp.example/alice.png"
	testLocale            = "en-US"

	webClientID                 = "web-client"
	webClientSecret             = "web-secret"
	webClientRedirect           = "http://127.0.0.1/callback"
	webClientPostLogoutRedirect = "http://127.0.0.1/logout/callback"
	otherClientID               = "other-client"
	otherClientSecret           = "other-secret"
	otherClientRedirect         = "http://localhost/other/callback"
	nativeClientID              = "native-client"
	nativeClientRedirect        = "http://127.0.0.1/callback"

	authMethodClientSecretPost = "client_secret_post"
)

var testGroups = []string{"admins", "developers"}

type providerConfig struct {
	IssuerPath string
	Clients    []clientConfig
	Users      []userConfig
}

type clientConfig struct {
	Label                            string
	ID                               string
	Secret                           string
	RedirectURL                      string
	PostLogoutRedirectURL            string
	BackchannelLogoutURI             string
	BackchannelLogoutSessionRequired bool
}

type userConfig struct {
	Label         string
	Username      string
	Password      string
	Sub           string
	Name          string
	Email         string
	EmailVerified bool
	Profile       string
	Picture       string
	Locale        string
	Groups        []string
}

type authorizationRequest struct {
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Nonce       string
	Prompt      string
	Verifier    string
}

type authorizationResult struct {
	Code   string
	State  string
	Issuer string
}

type tokenRequest struct {
	ClientID     string
	ClientSecret string
	AuthMethod   string
	GrantType    string
	Code         string
	RefreshToken string
	Scope        string
	RedirectURI  string
	CodeVerifier string
}

type introspectionRequest struct {
	ClientID      string
	ClientSecret  string
	AuthMethod    string
	Token         string
	TokenTypeHint string
}

type discoveryDocument struct {
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
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type introspectionResponse struct {
	Active            bool     `json:"active"`
	Scope             string   `json:"scope"`
	ClientID          string   `json:"client_id"`
	TokenType         string   `json:"token_type"`
	Exp               int64    `json:"exp"`
	Iss               string   `json:"iss"`
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Profile           string   `json:"profile"`
	Picture           string   `json:"picture"`
	Locale            string   `json:"locale"`
	Groups            []string `json:"groups"`
}

type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyType string `json:"kty"`
	Alg     string `json:"alg"`
	Use     string `json:"use"`
	KeyID   string `json:"kid"`
	N       string `json:"n"`
	E       string `json:"e"`
}

type idTokenClaims struct {
	Iss               string   `json:"iss"`
	Sub               string   `json:"sub"`
	Aud               string   `json:"aud"`
	Exp               int64    `json:"exp"`
	Iat               int64    `json:"iat"`
	AuthTime          int64    `json:"auth_time"`
	Nonce             string   `json:"nonce"`
	Sid               string   `json:"sid"`
	AtHash            string   `json:"at_hash"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Profile           string   `json:"profile"`
	Picture           string   `json:"picture"`
	Locale            string   `json:"locale"`
	Groups            []string `json:"groups"`
}

type logoutTokenClaims struct {
	Iss    string         `json:"iss"`
	Sub    string         `json:"sub"`
	Aud    string         `json:"aud"`
	Iat    int64          `json:"iat"`
	Exp    int64          `json:"exp"`
	Jti    string         `json:"jti"`
	Sid    string         `json:"sid"`
	Nonce  string         `json:"nonce"`
	Events map[string]any `json:"events"`
}

type userInfoClaims struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Profile           string   `json:"profile"`
	Picture           string   `json:"picture"`
	Locale            string   `json:"locale"`
	Groups            []string `json:"groups"`
}

func defaultProviderConfig() providerConfig {
	return providerConfig{
		Clients: []clientConfig{
			{
				Label:                 "WEB",
				ID:                    webClientID,
				Secret:                webClientSecret,
				RedirectURL:           webClientRedirect,
				PostLogoutRedirectURL: webClientPostLogoutRedirect,
			},
			{
				Label:       "OTHER",
				ID:          otherClientID,
				Secret:      otherClientSecret,
				RedirectURL: otherClientRedirect,
			},
			{
				Label:       "NATIVE",
				ID:          nativeClientID,
				RedirectURL: nativeClientRedirect,
			},
		},
		Users: []userConfig{
			{
				Label:         "ALICE",
				Username:      testUsername,
				Password:      testPassword,
				Sub:           testSubject,
				Name:          testName,
				Email:         testEmail,
				EmailVerified: true,
				Profile:       testProfile,
				Picture:       testPicture,
				Locale:        testLocale,
				Groups:        testGroups,
			},
		},
	}
}
