package simpleidp

// Reference material:
// RFC 7009: https://www.rfc-editor.org/rfc/rfc7009.txt

import "testing"

var rfc7009Sections = []specSection{
	{Spec: "RFC 7009", Section: "1", Title: "Introduction", Notes: "Introductory material is not a direct integration-test target."},
	{Spec: "RFC 7009", Section: "1.1", Title: "Notational Conventions", Notes: "Notation guidance is not a direct runtime integration-test target."},
	{Spec: "RFC 7009", Section: "2", Title: "Token Revocation", Applicable: true, Notes: "Request and response semantics covered together; TLS is out of scope in the loopback harness.", Run: testRevocationEndpoint},
	{Spec: "RFC 7009", Section: "2.1", Title: "Revocation Request", Applicable: true, Run: testRevocationRequest},
	{Spec: "RFC 7009", Section: "2.2", Title: "Revocation Response", Applicable: true, Run: testRevocationResponse},
	{Spec: "RFC 7009", Section: "2.2.1", Title: "Error Response", Applicable: true, Run: testRevocationErrorResponse},
	{Spec: "RFC 7009", Section: "2.3", Title: "Cross-Origin Support", Notes: "Optional CORS and JSONP support for browser-based or legacy clients is not implemented."},
	{Spec: "RFC 7009", Section: "3", Title: "Implementation Note", Applicable: true, Run: testRevocationImplementationNote},
	{Spec: "RFC 7009", Section: "4", Title: "IANA Considerations", Notes: "IANA registration text is not a runtime integration-test target."},
	{Spec: "RFC 7009", Section: "4.1", Title: "OAuth Extensions Error Registration", Notes: "Registry management is not a runtime integration-test target."},
	{Spec: "RFC 7009", Section: "4.1.1", Title: "Unsupported Token Type Error", Notes: "Unknown token_type_hint values are ignored."},
	{Spec: "RFC 7009", Section: "4.1.2", Title: "OAuth Token Type Hints Registry", Notes: "Token type hint registry management is not a runtime integration-test target."},
	{Spec: "RFC 7009", Section: "4.1.2.1", Title: "Registration Template", Notes: "Registry registration templates are not runtime integration-test targets."},
	{Spec: "RFC 7009", Section: "4.1.2.2", Title: "Initial Registry Contents", Notes: "Registry bootstrap contents are not runtime integration-test targets."},
	{Spec: "RFC 7009", Section: "5", Title: "Security Considerations", Applicable: true, Run: testRevocationSecurityConsiderations},
	{Spec: "RFC 7009", Section: "6", Title: "Acknowledgements", Notes: "Acknowledgements are not a runtime integration-test target."},
	{Spec: "RFC 7009", Section: "7", Title: "References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "RFC 7009", Section: "7.1", Title: "Normative References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "RFC 7009", Section: "7.2", Title: "Informative References", Notes: "Reference sections are not runtime integration-test targets."},
}

func TestRFC7009Sections(t *testing.T) {
	runSpecSections(t, rfc7009Sections)
}
