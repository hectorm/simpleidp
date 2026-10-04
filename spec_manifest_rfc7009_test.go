package simpleidp

// Reference material:
// RFC 7009: https://www.rfc-editor.org/rfc/rfc7009.txt

import "testing"

var rfc7009Sections = []specSection{
	{Spec: "RFC 7009", Section: "1", Title: "Introduction", Notes: "Introductory material is not a test target."},
	{Spec: "RFC 7009", Section: "1.1", Title: "Requirements Language", Notes: "Notation guidance is not a test target."},
	{Spec: "RFC 7009", Section: "2", Title: "Token Revocation", Applicable: true, Notes: "TLS is out of scope.", Run: testRevocationEndpoint},
	{Spec: "RFC 7009", Section: "2.1", Title: "Revocation Request", Applicable: true, Run: testRevocationRequest},
	{Spec: "RFC 7009", Section: "2.2", Title: "Revocation Response", Applicable: true, Notes: "Revoking a refresh token also revokes the access tokens of its grant.", Run: testRevocationResponse},
	{Spec: "RFC 7009", Section: "2.2.1", Title: "Error Response", Applicable: true, Run: testRevocationErrorResponse},
	{Spec: "RFC 7009", Section: "2.3", Title: "Cross-Origin Support", Notes: "CORS and JSONP are not implemented."},
	{Spec: "RFC 7009", Section: "3", Title: "Implementation Note", Applicable: true, Run: testRevocationImplementationNote},
	{Spec: "RFC 7009", Section: "4", Title: "IANA Considerations", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7009", Section: "4.1", Title: "OAuth Extensions Error Registration", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7009", Section: "4.1.1", Title: "The \"unsupported_token_type\" Error Value", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7009", Section: "4.1.2", Title: "OAuth Token Type Hints Registry", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7009", Section: "4.1.2.1", Title: "Registration Template", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7009", Section: "4.1.2.2", Title: "Initial Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 7009", Section: "5", Title: "Security Considerations", Applicable: true, Notes: "Public-client requests with only client_id are covered by section 2.2; confidential-client authentication is covered by sections 2.1 and 2.2.1.", Run: testRevocationSecurityConsiderations},
	{Spec: "RFC 7009", Section: "6", Title: "Acknowledgements", Notes: "Acknowledgements are not test targets."},
	{Spec: "RFC 7009", Section: "7", Title: "References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 7009", Section: "7.1", Title: "Normative References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 7009", Section: "7.2", Title: "Informative References", Notes: "Reference sections are not test targets."},
}

func TestRFC7009Sections(t *testing.T) {
	runSpecSections(t, rfc7009Sections)
}
