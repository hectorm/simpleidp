package simpleidp

// Reference material:
// RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.txt

import "testing"

var rfc7662Sections = []specSection{
	{Spec: "RFC 7662", Section: "1", Title: "Introduction", Notes: "Introductory material is not a test target."},
	{Spec: "RFC 7662", Section: "1.1", Title: "Notational Conventions", Notes: "Notation guidance is not a test target."},
	{Spec: "RFC 7662", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not test targets."},
	{Spec: "RFC 7662", Section: "2", Title: "Introspection Endpoint", Applicable: true, Notes: "TLS is out of scope.", Run: testIntrospectionEndpoint},
	{Spec: "RFC 7662", Section: "2.1", Title: "Introspection Request", Applicable: true, Notes: "Missing and empty token parameters are rejected. Protected-resource authentication failures, including registered public clients supplying only client_id, are covered by section 2.3.", Run: testIntrospectionRequest},
	{Spec: "RFC 7662", Section: "2.2", Title: "Introspection Response", Applicable: true, Notes: "As provider policy, active responses include exp: access-token expiration matches the signed JWT, and refresh-token expiration is the earlier idle or maximum lifetime limit.", Run: testIntrospectionResponse},
	{Spec: "RFC 7662", Section: "2.3", Title: "Error Response", Applicable: true, Run: testIntrospectionErrorResponse},
	{Spec: "RFC 7662", Section: "3", Title: "IANA Considerations", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7662", Section: "3.1", Title: "OAuth Token Introspection Response Registry", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7662", Section: "3.1.1", Title: "Registration Template", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7662", Section: "3.1.2", Title: "Initial Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7662", Section: "4", Title: "Security Considerations", Applicable: true, Notes: "Introspection checks the client a token was issued to, not its audience, and TLS is out of scope. Refresh tokens are inactive once consumed or past their idle or maximum lifetime. As provider policy, introspecting a consumed refresh token does not revoke its grant.", Run: testIntrospectionSecurityConsiderations},
	{Spec: "RFC 7662", Section: "5", Title: "Privacy Considerations", Applicable: true, Notes: "Only the confidential client a token was issued to can introspect it. As provider policy, active responses limit optional claims to that token's scopes; after a narrowed refresh, access tokens use the reduced scopes and refresh tokens retain the original grant scopes.", Run: testIntrospectionPrivacyConsiderations},
	{Spec: "RFC 7662", Section: "6", Title: "References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 7662", Section: "6.1", Title: "Normative References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 7662", Section: "6.2", Title: "Informative References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 7662", Section: "A", Title: "Use with Proof-of-Possession Tokens", Notes: "Proof-of-possession tokens are not implemented."},
}

func TestRFC7662Sections(t *testing.T) {
	runSpecSections(t, rfc7662Sections)
}
