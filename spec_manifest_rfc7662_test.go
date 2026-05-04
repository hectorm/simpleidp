package simpleidp

// Reference material:
// RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.txt

import "testing"

var rfc7662Sections = []specSection{
	{Spec: "RFC 7662", Section: "1", Title: "Introduction", Notes: "Introductory material is not a direct integration-test target."},
	{Spec: "RFC 7662", Section: "1.1", Title: "Notational Conventions", Notes: "Notation guidance is not a direct runtime integration-test target."},
	{Spec: "RFC 7662", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are reflected by the executable sections below rather than tested independently."},
	{Spec: "RFC 7662", Section: "2", Title: "Introspection Endpoint", Applicable: true, Notes: "Request/response/authentication semantics are covered; TLS and certificate validation are out of scope in the loopback harness.", Run: testIntrospectionEndpoint},
	{Spec: "RFC 7662", Section: "2.1", Title: "Introspection Request", Applicable: true, Run: testIntrospectionRequest},
	{Spec: "RFC 7662", Section: "2.2", Title: "Introspection Response", Applicable: true, Run: testIntrospectionResponse},
	{Spec: "RFC 7662", Section: "2.3", Title: "Error Response", Applicable: true, Run: testIntrospectionErrorResponse},
	{Spec: "RFC 7662", Section: "3", Title: "IANA Considerations", Notes: "IANA registration text is not a runtime integration-test target."},
	{Spec: "RFC 7662", Section: "3.1", Title: "OAuth Token Introspection Response Registry", Notes: "Registry management is not a runtime integration-test target."},
	{Spec: "RFC 7662", Section: "3.1.1", Title: "Registration Template", Notes: "Registration templates are not runtime integration-test targets."},
	{Spec: "RFC 7662", Section: "3.1.2", Title: "Initial Registry Contents", Notes: "Registry bootstrap text is not a runtime integration-test target."},
	{Spec: "RFC 7662", Section: "4", Title: "Security Considerations", Applicable: true, Notes: "Protected-resource authentication and inactive-token minimization are covered; TLS and certificate validation are out of scope in the loopback harness.", Run: testIntrospectionSecurityConsiderations},
	{Spec: "RFC 7662", Section: "5", Title: "Privacy Considerations", Applicable: true, Notes: "The suite exercises disclosure control by ensuring inactive or unauthorized introspection responses do not reveal protected-token details; omission or remapping of optional sensitive claims in active responses remains implementation-specific.", Run: testIntrospectionPrivacyConsiderations},
	{Spec: "RFC 7662", Section: "6", Title: "References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "RFC 7662", Section: "6.1", Title: "Normative References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "RFC 7662", Section: "6.2", Title: "Informative References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "RFC 7662", Section: "A", Title: "Use with Proof-of-Possession Tokens", Notes: "Proof-of-possession tokens are not implemented."},
}

func TestRFC7662Sections(t *testing.T) {
	runSpecSections(t, rfc7662Sections)
}
