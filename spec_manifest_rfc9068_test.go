package simpleidp

// Reference material:
// RFC 9068: https://www.rfc-editor.org/rfc/rfc9068.txt

import "testing"

var rfc9068Sections = []specSection{
	{Spec: "RFC 9068", Section: "1", Title: "Introduction", Notes: "Introductory material is not a test target."},
	{Spec: "RFC 9068", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a test target."},
	{Spec: "RFC 9068", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not test targets."},
	{Spec: "RFC 9068", Section: "2", Title: "JWT Access Token Header and Data Structure", Notes: "Covered by the applicable subsections below."},
	{Spec: "RFC 9068", Section: "2.1", Title: "Header", Applicable: true, Run: testJWTAccessTokenHeader},
	{Spec: "RFC 9068", Section: "2.2", Title: "Data Structure", Applicable: true, Notes: "Required claims are covered for authorization code, refresh, and client credentials tokens; client credentials subject and audience handling is also covered by OAuth 2.1 section 4.2.", Run: testJWTAccessTokenDataStructure},
	{Spec: "RFC 9068", Section: "2.2.1", Title: "Authentication Information Claims", Notes: "The optional auth_time, acr, and amr claims are not included in access tokens."},
	{Spec: "RFC 9068", Section: "2.2.2", Title: "Identity Claims", Applicable: true, Run: testJWTAccessTokenIdentityClaims},
	{Spec: "RFC 9068", Section: "2.2.3", Title: "Authorization Claims", Applicable: true, Run: testJWTAccessTokenAuthorizationClaims},
	{Spec: "RFC 9068", Section: "2.2.3.1", Title: "Claims for Authorization Outside of Delegation Scenarios", Applicable: true, Notes: "The groups and roles claims follow the groups and roles scopes and are plain string arrays rather than SCIM attribute objects; entitlements are not implemented.", Run: testJWTAccessTokenGroupsAndRolesClaims},
	{Spec: "RFC 9068", Section: "3", Title: "Requesting a JWT Access Token", Applicable: true, Notes: "The resource parameter is not implemented; the audience is configured per client and defaults to the client ID.", Run: testRequestingJWTAccessToken},
	{Spec: "RFC 9068", Section: "4", Title: "Validating JWT Access Tokens", Notes: "This section describes resource server behavior; the typing and signing it relies on are covered by section 2.1, and the issuer and jwks_uri metadata by OIDC Discovery 1.0 section 3; UserInfo does not check the audience."},
	{Spec: "RFC 9068", Section: "5", Title: "Security Considerations", Notes: "Explicit typing is covered by section 2.1 and per-client audiences by section 3; clients are operator-configured, so they cannot choose the sub of client credentials tokens."},
	{Spec: "RFC 9068", Section: "6", Title: "Privacy Considerations", Notes: "Optional identity and authorization claims follow the granted scopes, as covered by sections 2.2.2 and 2.2.3.1; encryption and pairwise subject identifiers are not implemented."},
	{Spec: "RFC 9068", Section: "7", Title: "IANA Considerations", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 9068", Section: "7.1", Title: "Media Type Registration", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 9068", Section: "7.1.1", Title: "Registry Content", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 9068", Section: "7.2", Title: "Claims Registration", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 9068", Section: "7.2.1", Title: "Registry Content", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 9068", Section: "7.2.1.1", Title: "Roles", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 9068", Section: "7.2.1.2", Title: "Groups", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 9068", Section: "7.2.1.3", Title: "Entitlements", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 9068", Section: "8", Title: "References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 9068", Section: "8.1", Title: "Normative References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 9068", Section: "8.2", Title: "Informative References", Notes: "Reference sections are not test targets."},
}

func TestRFC9068Sections(t *testing.T) {
	runSpecSections(t, rfc9068Sections)
}
