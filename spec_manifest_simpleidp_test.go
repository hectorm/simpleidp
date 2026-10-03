package simpleidp

// Reference material:
// Simple IdP: README.md

import "testing"

var simpleIdPSections = []specSection{
	{Spec: "Simple IdP", Section: "1", Title: "Profile", Notes: "Profile behavior is covered by the applicable subsections below."},
	{Spec: "Simple IdP", Section: "1.1", Title: "Profile Page", Applicable: true, Run: testProfilePage},
	{Spec: "Simple IdP", Section: "1.2", Title: "Profile Login", Applicable: true, Run: testProfileLogin},
	{Spec: "Simple IdP", Section: "1.3", Title: "Profile Update", Applicable: true, Run: testProfileUpdate},
	{Spec: "Simple IdP", Section: "1.4", Title: "Profile Logout", Applicable: true, Run: testProfileLogout},
}

func TestSimpleIdPSections(t *testing.T) {
	runSpecSections(t, simpleIdPSections)
}
