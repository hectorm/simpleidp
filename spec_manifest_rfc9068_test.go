package simpleidp

// Reference material:
// RFC 9068: https://www.rfc-editor.org/rfc/rfc9068.txt

import "testing"

var rfc9068Sections = []specSection{
	{Spec: "RFC 9068", Section: "1", Title: "Introduction", Notes: "Introductory material is not a direct integration-test target."},
	{Spec: "RFC 9068", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a direct runtime integration-test target."},
	{Spec: "RFC 9068", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are reflected by the executable sections below rather than tested independently."},
	{Spec: "RFC 9068", Section: "2", Title: "JWT Access Token Header and Data Structure", Notes: "Header and claim requirements are covered by the applicable subsections below."},
	{Spec: "RFC 9068", Section: "2.1", Title: "Header", Applicable: true, Run: testJWTAccessTokenHeader},
	{Spec: "RFC 9068", Section: "2.2", Title: "Data Structure", Applicable: true, Notes: "Covers access tokens issued to end-users; the client credentials case is covered by OAuth 2.1 section 4.2.", Run: testJWTAccessTokenDataStructure},
	{Spec: "RFC 9068", Section: "2.2.1", Title: "Authentication Information Claims", Notes: "The optional auth_time, acr, and amr claims are not included in access tokens."},
	{Spec: "RFC 9068", Section: "2.2.2", Title: "Identity Claims", Applicable: true, Run: testJWTAccessTokenIdentityClaims},
	{Spec: "RFC 9068", Section: "2.2.3", Title: "Authorization Claims", Applicable: true, Run: testJWTAccessTokenAuthorizationClaims},
	{Spec: "RFC 9068", Section: "2.2.3.1", Title: "Claims for Authorization Outside of Delegation Scenarios", Applicable: true, Notes: "The groups and roles claims follow the groups and roles scopes; entitlements are not implemented.", Run: testJWTAccessTokenGroupsClaim},
	{Spec: "RFC 9068", Section: "3", Title: "Requesting a JWT Access Token", Applicable: true, Notes: "The resource parameter is not supported; access tokens use the client's configured audience, which defaults to the client ID.", Run: testRequestingJWTAccessToken},
	{Spec: "RFC 9068", Section: "4", Title: "Validating JWT Access Tokens", Notes: "Validation is resource-server behavior; the typing and signing it relies on are covered by section 2.1."},
	{Spec: "RFC 9068", Section: "5", Title: "Security Considerations", Notes: "Explicit typing is covered by section 2.1; client IDs are server-configured, so clients cannot choose the sub of client credentials tokens."},
	{Spec: "RFC 9068", Section: "6", Title: "Privacy Considerations", Notes: "Access tokens only carry the claims of the granted scopes; encryption is not implemented."},
	{Spec: "RFC 9068", Section: "7", Title: "IANA Considerations", Notes: "IANA registration text is not a runtime integration-test target."},
	{Spec: "RFC 9068", Section: "7.1", Title: "Media Type Registration", Notes: "Registry management is not a runtime integration-test target."},
	{Spec: "RFC 9068", Section: "7.1.1", Title: "Registry Content", Notes: "Registry content is not a runtime integration-test target."},
	{Spec: "RFC 9068", Section: "7.2", Title: "Claims Registration", Notes: "Registry management is not a runtime integration-test target."},
	{Spec: "RFC 9068", Section: "7.2.1", Title: "Registry Content", Notes: "Registry content is not a runtime integration-test target."},
	{Spec: "RFC 9068", Section: "7.2.1.1", Title: "Roles", Notes: "Registry content is not a runtime integration-test target."},
	{Spec: "RFC 9068", Section: "7.2.1.2", Title: "Groups", Notes: "Registry content is not a runtime integration-test target."},
	{Spec: "RFC 9068", Section: "7.2.1.3", Title: "Entitlements", Notes: "Registry content is not a runtime integration-test target."},
	{Spec: "RFC 9068", Section: "8", Title: "References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "RFC 9068", Section: "8.1", Title: "Normative References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "RFC 9068", Section: "8.2", Title: "Informative References", Notes: "Reference sections are not runtime integration-test targets."},
}

func TestRFC9068Sections(t *testing.T) {
	runSpecSections(t, rfc9068Sections)
}
