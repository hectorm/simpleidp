package simpleidp

// Reference material:
// RFC 8414: https://www.rfc-editor.org/rfc/rfc8414.txt

import "testing"

var rfc8414Sections = []specSection{
	{Spec: "RFC 8414", Section: "1", Title: "Introduction", Notes: "Introductory material is not a test target."},
	{Spec: "RFC 8414", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a test target."},
	{Spec: "RFC 8414", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not test targets."},
	{Spec: "RFC 8414", Section: "2", Title: "Authorization Server Metadata", Applicable: true, Notes: "Dynamic client registration and JWT client authentication are not implemented, so registration_endpoint and the authentication signing algorithms are omitted. The service_documentation, op_policy_uri, and op_tos_uri values are not published. OpenID Provider metadata values are covered by OIDC Discovery 1.0 section 3.", Run: testAuthorizationServerMetadata},
	{Spec: "RFC 8414", Section: "2.1", Title: "Signed Authorization Server Metadata", Notes: "Signed metadata is not implemented."},
	{Spec: "RFC 8414", Section: "3", Title: "Obtaining Authorization Server Metadata", Applicable: true, Notes: "TLS is out of scope, so the metadata URL may use http. As OAuth 2.1 section 3.2 recommends for metadata URLs, the endpoint supports CORS.", Run: testObtainingAuthorizationServerMetadata},
	{Spec: "RFC 8414", Section: "3.1", Title: "Authorization Server Metadata Request", Applicable: true, Run: testAuthorizationServerMetadataRequest},
	{Spec: "RFC 8414", Section: "3.2", Title: "Authorization Server Metadata Response", Applicable: true, Run: testAuthorizationServerMetadataResponse},
	{Spec: "RFC 8414", Section: "3.3", Title: "Authorization Server Metadata Validation", Applicable: true, Run: testAuthorizationServerMetadataValidation},
	{Spec: "RFC 8414", Section: "4", Title: "String Operations", Notes: "This section describes client behavior. The exact issuer value it compares is covered by section 3.3."},
	{Spec: "RFC 8414", Section: "5", Title: "Compatibility Notes", Applicable: true, Notes: "For issuers with a path component, the OpenID configuration is only published at the location defined by OIDC Discovery 1.0 section 4.", Run: testAuthorizationServerMetadataCompatibility},
	{Spec: "RFC 8414", Section: "6", Title: "Security Considerations", Notes: "Covered by the applicable subsections below."},
	{Spec: "RFC 8414", Section: "6.1", Title: "TLS Requirements", Notes: "TLS is out of scope."},
	{Spec: "RFC 8414", Section: "6.2", Title: "Impersonation Attacks", Notes: "This section describes client behavior. The published issuer is covered by section 3.3, and TLS is out of scope."},
	{Spec: "RFC 8414", Section: "6.3", Title: "Publishing Metadata in a Standard Format", Notes: "Publication guidance is not a test target."},
	{Spec: "RFC 8414", Section: "6.4", Title: "Protected Resources", Notes: "This section describes client behavior."},
	{Spec: "RFC 8414", Section: "7", Title: "IANA Considerations", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 8414", Section: "7.1", Title: "OAuth Authorization Server Metadata Registry", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 8414", Section: "7.1.1", Title: "Registration Template", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 8414", Section: "7.1.2", Title: "Initial Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 8414", Section: "7.2", Title: "Updated Registration Instructions", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 8414", Section: "7.3", Title: "Well-Known URI Registry", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 8414", Section: "7.3.1", Title: "Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "RFC 8414", Section: "8", Title: "References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 8414", Section: "8.1", Title: "Normative References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 8414", Section: "8.2", Title: "Informative References", Notes: "Reference sections are not test targets."},
}

func TestRFC8414Sections(t *testing.T) {
	runSpecSections(t, rfc8414Sections)
}
