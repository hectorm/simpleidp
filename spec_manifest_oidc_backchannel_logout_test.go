package simpleidp

// Reference material:
// OIDC Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html

import "testing"

var oidcBackChannelLogoutSections = []specSection{
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "1", Title: "Introduction", Notes: "Introductory material is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not test targets."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2", Title: "Back-Channel Logout", Applicable: true, Run: testBackChannelLogout},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.1", Title: "Indicating OP Support for Back-Channel Logout", Applicable: true, Run: testBackChannelLogoutDiscoveryMetadata},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.2", Title: "Indicating RP Support for Back-Channel Logout", Applicable: true, Notes: "Configured URIs must include a host and omit fragments; query parameters are retained. As provider policy, user info is also rejected. TLS is out of scope, so back-channel logout URIs may use http, including for public clients.", Run: testBackChannelLogoutClientRegistration},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.3", Title: "Remembering Logged-In RPs", Applicable: true, Run: testBackChannelLogoutRememberingRPs},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.4", Title: "Logout Token", Applicable: true, Run: testBackChannelLogoutToken},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.5", Title: "Back-Channel Logout Request", Applicable: true, Notes: "The product never retransmits failed notifications.", Run: testBackChannelLogoutRequest},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.6", Title: "Logout Token Validation", Applicable: true, Notes: "This section describes RP behavior; the signature, iss, aud, and sub of the logout tokens the product issues are validated against it, and their alg, iat, exp, events, nonce, and sid by section 2.4. As provider policy, signed JWTs include a kid identifying the published signing key.", Run: testBackChannelLogoutTokenValidation},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.7", Title: "Back-Channel Logout Actions", Applicable: true, Notes: "This section describes RP behavior; the product revokes the tokens of the logged-out session, and the offline_access scope is not implemented.", Run: testBackChannelLogout},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.8", Title: "Back-Channel Logout Response", Applicable: true, Notes: "This section describes RP behavior; the product completes logout regardless of the RP response and does not follow redirects.", Run: testBackChannelLogoutResponse},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "3", Title: "Implementation Considerations", Notes: "Required OP features are covered by the applicable sections above."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "4", Title: "Security Considerations", Applicable: true, Run: testBackChannelLogoutSecurity},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "4.1", Title: "Cross-JWT Confusion", Applicable: true, Notes: "Issued logout tokens use explicit typing and omit nonce; rejection of access and logout JWTs as ID token hints is also covered by OIDC Core 1.0 section 3.1.2.2 and OIDC RP-Initiated Logout 1.0 section 4.", Run: testBackChannelLogoutToken},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5", Title: "IANA Considerations", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.1", Title: "OAuth Dynamic Client Registration Metadata Registration", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.1.1", Title: "Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.2", Title: "OAuth Authorization Server Metadata Registry", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.2.1", Title: "Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.3", Title: "Media Type Registration", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.3.1", Title: "Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "6", Title: "References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "6.1", Title: "Normative References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "6.2", Title: "Informative References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "A", Title: "Acknowledgements", Notes: "Acknowledgements are not test targets."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "B", Title: "Notices", Notes: "Notices are not test targets."},
}

func TestOIDCBackChannelLogoutSections(t *testing.T) {
	runSpecSections(t, oidcBackChannelLogoutSections)
}
