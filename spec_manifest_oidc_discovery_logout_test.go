package simpleidp

// Reference material:
// OIDC Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
// OIDC RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

import "testing"

var oidcDiscoverySections = []specSection{
	{Spec: "OIDC Discovery 1.0", Section: "1", Title: "Introduction", Notes: "Introductory material is not a direct integration-test target."},
	{Spec: "OIDC Discovery 1.0", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a direct runtime integration-test target."},
	{Spec: "OIDC Discovery 1.0", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not directly exercised by integration tests."},
	{Spec: "OIDC Discovery 1.0", Section: "2", Title: "OpenID Provider Issuer Discovery", Notes: "WebFinger-based issuer discovery is not implemented by this product."},
	{Spec: "OIDC Discovery 1.0", Section: "2.1", Title: "Identifier Normalization", Notes: "WebFinger-based issuer discovery is not implemented by this product."},
	{Spec: "OIDC Discovery 1.0", Section: "2.1.1", Title: "User Input Identifier Types", Notes: "WebFinger-based issuer discovery is not implemented by this product."},
	{Spec: "OIDC Discovery 1.0", Section: "2.1.2", Title: "Normalization Steps", Notes: "WebFinger-based issuer discovery is not implemented by this product."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2", Title: "Non-Normative Examples", Notes: "Non-normative examples are not integration-test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2.1", Title: "User Input using E-Mail Address Syntax", Notes: "Non-normative examples are not integration-test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2.2", Title: "User Input using URL Syntax", Notes: "Non-normative examples are not integration-test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2.3", Title: "User Input using Hostname and Port Syntax", Notes: "Non-normative examples are not integration-test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "2.2.4", Title: "User Input using \"acct\" URI Syntax", Notes: "Non-normative examples are not integration-test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "3", Title: "OpenID Provider Metadata", Applicable: true, Notes: "Metadata shape and issuer consistency are covered; the current product emits local http metadata, so the specification's https deployment requirement is not claimed as conformant here.", Run: testProviderMetadata},
	{Spec: "OIDC Discovery 1.0", Section: "4", Title: "Obtaining OpenID Provider Configuration Information", Notes: "Concrete configuration request, response, and validation behavior is covered by sections 4.1 through 4.3; the current product emits local http metadata, so the specification's https deployment requirement is not claimed as conformant here."},
	{Spec: "OIDC Discovery 1.0", Section: "4.1", Title: "OpenID Provider Configuration Request", Applicable: true, Notes: "Well-known path construction is covered; the current product emits local http metadata, so the specification's https deployment requirement is not claimed as conformant here.", Run: testProviderConfigurationRequest},
	{Spec: "OIDC Discovery 1.0", Section: "4.2", Title: "OpenID Provider Configuration Response", Applicable: true, Notes: "JSON response shape is covered; optional CORS behavior is not asserted, and the current product emits local http metadata instead of enforcing the specification's https deployment requirement.", Run: testProviderConfigurationResponse},
	{Spec: "OIDC Discovery 1.0", Section: "4.3", Title: "OpenID Provider Configuration Validation", Applicable: true, Notes: "Issuer consistency is covered; the current product emits local http metadata, so the specification's https deployment requirement is not claimed as conformant here.", Run: testProviderConfigurationValidation},
	{Spec: "OIDC Discovery 1.0", Section: "5", Title: "String Operations", Notes: "Unicode code point comparison rules govern RP-side metadata processing and are not a direct provider-side black-box integration-test target."},
	{Spec: "OIDC Discovery 1.0", Section: "6", Title: "Implementation Considerations", Notes: "Implementation-consideration text is informational for this suite."},
	{Spec: "OIDC Discovery 1.0", Section: "6.1", Title: "Compatibility Notes", Notes: "Compatibility notes are informational and not direct integration-test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "7", Title: "Security Considerations", Notes: "Only the impersonation defense is directly testable here; the product does not enforce the discovery specification's TLS/HTTPS deployment requirements in local deployments."},
	{Spec: "OIDC Discovery 1.0", Section: "7.1", Title: "TLS Requirements", Notes: "The product currently permits local http issuer and endpoint URLs, so this TLS/HTTPS requirement is not claimed as conformant here."},
	{Spec: "OIDC Discovery 1.0", Section: "7.2", Title: "Impersonation Attacks", Applicable: true, Run: testProviderConfigurationValidation},
	{Spec: "OIDC Discovery 1.0", Section: "8", Title: "IANA Considerations", Notes: "IANA registration text is not a runtime integration-test target."},
	{Spec: "OIDC Discovery 1.0", Section: "8.1", Title: "Well-Known URI Registry", Notes: "IANA registry management is not a runtime integration-test target."},
	{Spec: "OIDC Discovery 1.0", Section: "8.1.1", Title: "Registry Contents", Notes: "IANA registry contents are not a runtime integration-test target."},
	{Spec: "OIDC Discovery 1.0", Section: "8.2", Title: "OAuth Authorization Server Metadata Registry", Notes: "IANA registry management is not a runtime integration-test target."},
	{Spec: "OIDC Discovery 1.0", Section: "8.2.1", Title: "Registry Contents", Notes: "IANA registry contents are not a runtime integration-test target."},
	{Spec: "OIDC Discovery 1.0", Section: "9", Title: "References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "9.1", Title: "Normative References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "OIDC Discovery 1.0", Section: "9.2", Title: "Informative References", Notes: "Reference sections are not runtime integration-test targets."},
}

var oidcRPInitiatedLogoutSections = []specSection{
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "1", Title: "Introduction", Notes: "Introductory material is not a direct integration-test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "1.1", Title: "Requirements Notation and Conventions", Notes: "Notation guidance is not a direct runtime integration-test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "1.2", Title: "Terminology", Notes: "Terminology definitions are not directly exercised by integration tests."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "2", Title: "RP-Initiated Logout", Applicable: true, Notes: "This entry focuses on logout initiation, confirmation, and token revocation; post-logout redirect target and state handling are covered by section 3.", Run: testRPInitiatedLogout},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "2.1", Title: "OpenID Provider Discovery Metadata", Applicable: true, Notes: "The suite checks discovery metadata presence and endpoint construction; the current product emits local http metadata, so the specification's https deployment requirement is not claimed as conformant here.", Run: testLogoutDiscoveryMetadata},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "3", Title: "Redirection to RP After Logout", Applicable: true, Notes: "Exact redirect matching and state echo are covered; the current product allows local http redirect URIs, so the specification's https deployment guidance is not claimed as conformant here.", Run: testLogoutRedirection},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "3.1", Title: "Client Registration Metadata", Applicable: true, Notes: "Registered post-logout redirect URI matching is covered; the current product allows local http redirect URIs, so the specification's https deployment guidance is not claimed as conformant here.", Run: testLogoutClientRegistrationMetadata},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "4", Title: "Validation and Error Handling", Applicable: true, Run: testLogoutValidationAndErrorHandling},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "5", Title: "Implementation Considerations", Notes: "Implementation-consideration text is informational for this suite."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "6", Title: "Security Considerations", Applicable: true, Run: testLogoutSecurityConsiderations},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7", Title: "IANA Considerations", Notes: "IANA registration text is not a runtime integration-test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7.1", Title: "OAuth Authorization Server Metadata Registry", Notes: "IANA registry management is not a runtime integration-test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7.1.1", Title: "Registry Contents", Notes: "IANA registry contents are not a runtime integration-test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7.2", Title: "OAuth Dynamic Client Registration Metadata Registration", Notes: "IANA registry management is not a runtime integration-test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "7.2.1", Title: "Registry Contents", Notes: "IANA registry contents are not a runtime integration-test target."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "8", Title: "References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "8.1", Title: "Normative References", Notes: "Reference sections are not runtime integration-test targets."},
	{Spec: "OIDC RP-Initiated Logout 1.0", Section: "8.2", Title: "Informative References", Notes: "Reference sections are not runtime integration-test targets."},
}

func TestOIDCDiscoverySections(t *testing.T) {
	runSpecSections(t, oidcDiscoverySections)
}

func TestOIDCRPInitiatedLogoutSections(t *testing.T) {
	runSpecSections(t, oidcRPInitiatedLogoutSections)
}
