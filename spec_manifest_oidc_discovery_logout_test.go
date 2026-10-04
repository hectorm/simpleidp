package simpleidp

// Reference material:
// OIDC Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
// OIDC RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

import "testing"

var oidcDiscoverySections = []specSection{
	{Spec: "OIDC Discovery 1.0", Section: "1", Title: "Introduction", Notes: "Introductory material is not a test target."},
	{Spec: "OIDC Discovery 1.0", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a test target."},
	{Spec: "OIDC Discovery 1.0", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "2", Title: "OpenID Provider Issuer Discovery", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "2.1", Title: "Identifier Normalization", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "2.1.1", Title: "User Input Identifier Types", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "2.1.2", Title: "Normalization Steps", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2", Title: "Non-Normative Examples", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2.1", Title: "User Input using E-Mail Address Syntax", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2.2", Title: "User Input using URL Syntax", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2.3", Title: "User Input using Hostname and Port Syntax", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2.4", Title: "User Input using \"acct\" URI Syntax", Notes: "WebFinger issuer discovery is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "3", Title: "OpenID Provider Metadata", Applicable: true, Notes: "TLS is out of scope, so the issuer and endpoint URLs may use http; CORS is not implemented.", Run: testProviderMetadata},
	{Spec: "OIDC Discovery 1.0", Section: "4", Title: "Obtaining OpenID Provider Configuration Information", Notes: "Covered by the applicable subsections below; CORS is not implemented."},
	{Spec: "OIDC Discovery 1.0", Section: "4.1", Title: "OpenID Provider Configuration Request", Applicable: true, Run: testProviderConfigurationRequest},
	{Spec: "OIDC Discovery 1.0", Section: "4.2", Title: "OpenID Provider Configuration Response", Applicable: true, Run: testProviderConfigurationResponse},
	{Spec: "OIDC Discovery 1.0", Section: "4.3", Title: "OpenID Provider Configuration Validation", Applicable: true, Run: testProviderConfigurationValidation},
	{Spec: "OIDC Discovery 1.0", Section: "5", Title: "String Operations", Notes: "This section describes RP behavior; the product's string comparisons are covered by OIDC Core 1.0 section 14."},
	{Spec: "OIDC Discovery 1.0", Section: "6", Title: "Implementation Considerations", Notes: "Required OP features are covered by the applicable sections above."},
	{Spec: "OIDC Discovery 1.0", Section: "6.1", Title: "Compatibility Notes", Notes: "Compatibility notes are not test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "7", Title: "Security Considerations", Notes: "Covered by the applicable subsections below."},
	{Spec: "OIDC Discovery 1.0", Section: "7.1", Title: "TLS Requirements", Notes: "TLS is out of scope."},
	{Spec: "OIDC Discovery 1.0", Section: "7.2", Title: "Impersonation Attacks", Applicable: true, Notes: "This section describes RP behavior; the issuer values the product publishes are validated against it, and TLS is out of scope.", Run: testProviderConfigurationValidation},
	{Spec: "OIDC Discovery 1.0", Section: "8", Title: "IANA Considerations", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Discovery 1.0", Section: "8.1", Title: "Well-Known URI Registry", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Discovery 1.0", Section: "8.1.1", Title: "Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Discovery 1.0", Section: "8.2", Title: "OAuth Authorization Server Metadata Registry", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Discovery 1.0", Section: "8.2.1", Title: "Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC Discovery 1.0", Section: "9", Title: "References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "9.1", Title: "Normative References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "9.2", Title: "Informative References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "A", Title: "Acknowledgements", Notes: "Acknowledgements are not test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "B", Title: "Notices", Notes: "Notices are not test targets."},
}

var oidcRPInitiatedLogoutSections = []specSection{
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "1", Title: "Introduction", Notes: "Introductory material is not a test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not test targets."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "2", Title: "RP-Initiated Logout", Applicable: true, Notes: "Post-logout redirection is covered by sections 3 and 3.1, id_token_hint and client_id validation by section 4, and RP notification by OIDC Back-Channel Logout 1.0 section 2.3.", Run: testRPInitiatedLogout},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "2.1", Title: "OpenID Provider Discovery Metadata", Applicable: true, Notes: "TLS is out of scope, so the end_session_endpoint may use http.", Run: testLogoutDiscoveryMetadata},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "3", Title: "Redirection to RP After Logout", Applicable: true, Run: testLogoutRedirection},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "3.1", Title: "Client Registration Metadata", Applicable: true, Notes: "TLS is out of scope, so post-logout redirect URIs may use http, including for public clients.", Run: testLogoutClientRegistrationMetadata},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "4", Title: "Validation and Error Handling", Applicable: true, Notes: "As provider policy, invalid requests return HTTP 400 without redirection.", Run: testLogoutValidationAndErrorHandling},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "5", Title: "Implementation Considerations", Notes: "Required OP features are covered by the applicable sections above."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "6", Title: "Security Considerations", Applicable: true, Notes: "As provider policy, active browser sessions always require logout confirmation, even with a valid ID Token hint, and confirmation POSTs require CSRF protection. Canceled and invalid confirmations preserve the session.", Run: testLogoutSecurityConsiderations},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7", Title: "IANA Considerations", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7.1", Title: "OAuth Authorization Server Metadata Registry", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7.1.1", Title: "Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7.2", Title: "OAuth Dynamic Client Registration Metadata Registration", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7.2.1", Title: "Registry Contents", Notes: "IANA registration text is not a test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "8", Title: "References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "8.1", Title: "Normative References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "8.2", Title: "Informative References", Notes: "Reference sections are not test targets."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "A", Title: "Acknowledgements", Notes: "Acknowledgements are not test targets."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "B", Title: "Notices", Notes: "Notices are not test targets."},
}

func TestOIDCDiscoverySections(t *testing.T) {
	runSpecSections(t, oidcDiscoverySections)
}

func TestOIDCRPInitiatedLogoutSections(t *testing.T) {
	runSpecSections(t, oidcRPInitiatedLogoutSections)
}
