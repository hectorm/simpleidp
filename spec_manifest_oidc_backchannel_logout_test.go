package simpleidp

// Reference material:
// OIDC Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html

import "testing"

var oidcBackChannelLogoutSections = []specSection{
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "1", Title: "Introduction", Notes: "Introductory material is not a direct integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a direct runtime integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not directly exercised by integration tests."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2", Title: "Back-Channel Logout", Applicable: true, Notes: "Covers the back-channel logout mechanism: logout token delivery and session termination propagation.", Run: testBackChannelLogout},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.1", Title: "Indicating OP Support for Back-Channel Logout", Applicable: true, Notes: "Covers discovery metadata advertising back-channel logout support.", Run: testBackChannelLogoutDiscoveryMetadata},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.2", Title: "Indicating RP Support for Back-Channel Logout", Applicable: true, Notes: "Covers client registration metadata for back-channel logout URI and session requirement.", Run: testBackChannelLogoutClientRegistration},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.3", Title: "Remembering Logged-In RPs", Applicable: true, Notes: "Covers tracking which RPs a user has logged into so the OP can notify them on logout.", Run: testBackChannelLogoutRememberingRPs},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.4", Title: "Logout Token", Applicable: true, Notes: "Covers logout token structure, required claims, and signing.", Run: testBackChannelLogoutToken},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.5", Title: "Back-Channel Logout Request", Applicable: true, Notes: "Covers the HTTP POST request the OP sends to the RP's back-channel logout URI.", Run: testBackChannelLogoutRequest},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.6", Title: "Logout Token Validation", Applicable: true, Notes: "Covers logout token validation requirements from the RP perspective; tested by verifying the token the OP produces is well-formed and verifiable.", Run: testBackChannelLogoutTokenValidation},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.7", Title: "Back-Channel Logout Actions", Applicable: true, Notes: "Covers OP-triggered session termination and token revocation after delivering the logout token.", Run: testBackChannelLogout},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "2.8", Title: "Back-Channel Logout Response", Applicable: true, Notes: "Covers OP handling of successful and failed RP responses, including HTTP 204 as a successful response.", Run: testBackChannelLogoutResponse},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "3", Title: "Implementation Considerations", Notes: "Implementation-consideration text is informational for this suite."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "4", Title: "Security Considerations", Applicable: true, Notes: "Covers security properties of the logout token.", Run: testBackChannelLogoutSecurity},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "4.1", Title: "Cross-JWT Confusion", Applicable: true, Notes: "Covers nonce omission and explicit logout+jwt typing to avoid confusion with ID Tokens.", Run: testBackChannelLogoutToken},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5", Title: "IANA Considerations", Notes: "IANA registration text is not a runtime integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.1", Title: "OAuth Dynamic Client Registration Metadata Registration", Notes: "IANA registry management is not a runtime integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.1.1", Title: "Registry Contents", Notes: "IANA registry contents are not a runtime integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.2", Title: "OAuth Authorization Server Metadata Registry", Notes: "IANA registry management is not a runtime integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.2.1", Title: "Registry Contents", Notes: "IANA registry contents are not a runtime integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.3", Title: "Media Type Registration", Notes: "Media type registration text is not a runtime integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "5.3.1", Title: "Registry Contents", Notes: "Media type registry contents are not a runtime integration-test target."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "6", Title: "References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "6.1", Title: "Normative References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "OIDC Back-Channel Logout 1.0", Section: "6.2", Title: "Informative References", Notes: "Reference sections are not runtime integration-test targets."},
}

func TestOIDCBackChannelLogoutSections(t *testing.T) {
	runSpecSections(t, oidcBackChannelLogoutSections)
}
