package simpleidp

// Reference material:
// RFC 6238: https://www.rfc-editor.org/rfc/rfc6238.txt

import "testing"

var rfc6238Sections = []specSection{
	{Spec: "RFC 6238", Section: "1", Title: "Introduction", Notes: "Introductory material is not a test target."},
	{Spec: "RFC 6238", Section: "1.1", Title: "Scope", Notes: "Introductory material is not a test target."},
	{Spec: "RFC 6238", Section: "1.2", Title: "Background", Notes: "Introductory material is not a test target."},
	{Spec: "RFC 6238", Section: "2", Title: "Notation and Terminology", Notes: "Notation guidance is not a test target."},
	{Spec: "RFC 6238", Section: "3", Title: "Algorithm Requirements", Applicable: true, Notes: "Secrets are configured per user in base32, must encode at least 128 bits, as HOTP requires, and must be unique; random key generation and key protection are operator concerns.", Run: testTOTPAlgorithmRequirements},
	{Spec: "RFC 6238", Section: "4", Title: "TOTP Algorithm", Notes: "Covered by the applicable subsections below."},
	{Spec: "RFC 6238", Section: "4.1", Title: "Notations", Notes: "The product uses the default 30-second time step and the Unix epoch as T0, as covered by section 4.2."},
	{Spec: "RFC 6238", Section: "4.2", Title: "Description", Applicable: true, Run: testTOTPDescription},
	{Spec: "RFC 6238", Section: "5", Title: "Security Considerations", Notes: "Covered by the applicable subsections below."},
	{Spec: "RFC 6238", Section: "5.1", Title: "General", Applicable: true, Notes: "Invalid codes are throttled per user across login sessions, as recommended for HOTP: after three failures, each further failure doubles the wait before the next attempt, from one second up to 24 hours. Key generation and storage are operator concerns, as secrets are configured through environment variables, and TLS is out of scope.", Run: testTOTPGeneralSecurityConsiderations},
	{Spec: "RFC 6238", Section: "5.2", Title: "Validation and Time-Step Size", Applicable: true, Notes: "The product accepts codes from the previous time step, as recommended, and rejects codes for time steps at or before the user's last accepted one, also checking the two time steps before the window so colliding codes stay rejected throughout their validity window.", Run: testTOTPValidationAndTimeStepSize},
	{Spec: "RFC 6238", Section: "6", Title: "Resynchronization", Notes: "The product also accepts codes from the next time step, as covered by section 5.2; clock drift is not recorded."},
	{Spec: "RFC 6238", Section: "7", Title: "Acknowledgements", Notes: "Acknowledgements are not test targets."},
	{Spec: "RFC 6238", Section: "8", Title: "References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 6238", Section: "8.1", Title: "Normative References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 6238", Section: "8.2", Title: "Informative References", Notes: "Reference sections are not test targets."},
	{Spec: "RFC 6238", Section: "A", Title: "TOTP Algorithm: Reference Implementation", Notes: "The reference implementation is not a test target."},
	{Spec: "RFC 6238", Section: "B", Title: "Test Vectors", Applicable: true, Notes: "Only the SHA-1 vectors apply, because the product implements HMAC-SHA-1 with six-digit codes, which are the last six digits of the eight-digit vectors.", Run: testTOTPTestVectors},
}

func TestRFC6238Sections(t *testing.T) {
	runSpecSections(t, rfc6238Sections)
}
