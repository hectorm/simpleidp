package simpleidp

// Reference material:
// OpenID Connect specifications index: https://openid.net/developers/specs/
// OIDC Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
// OIDC Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
// OIDC RP-Initiated Logout 1.0: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
// OIDC Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html
// OAuth 2.1 draft 15: https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-15.txt
// RFC 7662: https://www.rfc-editor.org/rfc/rfc7662.txt

import (
	"fmt"
	"strings"
	"testing"
)

var expectedOIDCCoreSections = []string{
	"1", "1.1", "1.2", "1.3",
	"2",
	"3", "3.1", "3.1.1", "3.1.2", "3.1.2.1", "3.1.2.2", "3.1.2.3", "3.1.2.4", "3.1.2.5", "3.1.2.6", "3.1.2.7", "3.1.3", "3.1.3.1", "3.1.3.2", "3.1.3.3", "3.1.3.4", "3.1.3.5", "3.1.3.6", "3.1.3.7", "3.1.3.8",
	"3.2", "3.2.1", "3.2.2", "3.2.2.1", "3.2.2.2", "3.2.2.3", "3.2.2.4", "3.2.2.5", "3.2.2.6", "3.2.2.7", "3.2.2.8", "3.2.2.9", "3.2.2.10", "3.2.2.11",
	"3.3", "3.3.1", "3.3.2", "3.3.2.1", "3.3.2.2", "3.3.2.3", "3.3.2.4", "3.3.2.5", "3.3.2.6", "3.3.2.7", "3.3.2.8", "3.3.2.9", "3.3.2.10", "3.3.2.11", "3.3.2.12", "3.3.3", "3.3.3.1", "3.3.3.2", "3.3.3.3", "3.3.3.4", "3.3.3.5", "3.3.3.6", "3.3.3.7", "3.3.3.8", "3.3.3.9",
	"4",
	"5", "5.1", "5.1.1", "5.1.2", "5.2", "5.3", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.4", "5.5", "5.5.1", "5.5.1.1", "5.5.2", "5.6", "5.6.1", "5.6.2", "5.6.2.1", "5.6.2.2", "5.7",
	"6", "6.1", "6.1.1", "6.2", "6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.3", "6.3.1", "6.3.2", "6.3.3",
	"7", "7.1", "7.2", "7.2.1", "7.3", "7.4", "7.5",
	"8", "8.1",
	"9",
	"10", "10.1", "10.1.1", "10.2", "10.2.1",
	"11",
	"12", "12.1", "12.2", "12.3",
	"13", "13.1", "13.2", "13.3",
	"14",
	"15", "15.1", "15.2", "15.3", "15.4", "15.5", "15.5.1", "15.5.2", "15.5.3", "15.6", "15.7",
	"16", "16.1", "16.2", "16.3", "16.4", "16.5", "16.6", "16.7", "16.8", "16.9", "16.10", "16.11", "16.12", "16.13", "16.14", "16.15", "16.16", "16.17", "16.18", "16.19", "16.20", "16.21", "16.22", "16.23",
	"17", "17.1", "17.2", "17.3", "17.4",
	"18", "18.1", "18.1.1", "18.2", "18.2.1", "18.3", "18.3.1", "18.4", "18.4.1",
	"19", "19.1", "19.2",
}

var expectedOAuth21Sections = []string{
	"1", "1.1", "1.2", "1.3", "1.3.1", "1.3.2", "1.3.3", "1.4", "1.4.1", "1.4.2", "1.4.3", "1.5", "1.6", "1.7", "1.8", "1.9",
	"2", "2.1", "2.2", "2.3", "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.3.5", "2.3.6", "2.4", "2.4.1", "2.4.2", "2.5",
	"3", "3.1", "3.2", "3.2.1", "3.2.2", "3.2.3", "3.2.4",
	"4", "4.1", "4.1.1", "4.1.2", "4.1.3", "4.2", "4.2.1", "4.3", "4.3.1", "4.3.2", "4.3.3", "4.4",
	"5", "5.1", "5.1.1", "5.1.2", "5.2", "5.3", "5.3.1", "5.3.2",
	"6", "6.1", "6.1.1", "6.1.2", "6.2", "6.3", "6.4", "6.5",
	"7", "7.1", "7.1.1", "7.1.2", "7.1.3", "7.1.4", "7.2", "7.3", "7.3.1", "7.3.2", "7.4", "7.5", "7.5.1", "7.5.2", "7.5.3", "7.6", "7.7", "7.8", "7.9", "7.10", "7.11", "7.12", "7.12.1", "7.12.2", "7.13", "7.14", "7.14.1", "7.14.2",
	"8", "8.1", "8.1.1", "8.1.2", "8.2", "8.3", "8.4", "8.4.1", "8.4.2", "8.4.3", "8.5", "8.5.1", "8.5.2", "8.5.3", "8.5.4",
	"9",
	"10", "10.1", "10.2",
	"11", "12", "12.1", "12.2",
}

var expectedOIDCDiscoverySections = []string{
	"1", "1.1", "1.2",
	"2", "2.1", "2.1.1", "2.1.2", "2.2", "2.2.1", "2.2.2", "2.2.3", "2.2.4",
	"3",
	"4", "4.1", "4.2", "4.3",
	"5",
	"6", "6.1",
	"7", "7.1", "7.2",
	"8", "8.1", "8.1.1", "8.2", "8.2.1",
	"9", "9.1", "9.2",
}

var expectedOIDCRPInitiatedLogoutSections = []string{
	"1", "1.1", "1.2",
	"2", "2.1",
	"3", "3.1",
	"4",
	"5",
	"6",
	"7", "7.1", "7.1.1", "7.2", "7.2.1",
	"8", "8.1", "8.2",
}

var expectedOIDCBackChannelLogoutSections = []string{
	"1", "1.1", "1.2",
	"2", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8",
	"3",
	"4", "4.1",
	"5", "5.1", "5.1.1", "5.2", "5.2.1", "5.3", "5.3.1",
	"6", "6.1", "6.2",
}

var expectedRFC7662Sections = []string{
	"1", "1.1", "1.2",
	"2", "2.1", "2.2", "2.3",
	"3", "3.1", "3.1.1", "3.1.2",
	"4",
	"5",
	"6", "6.1", "6.2",
	"A",
}

var expectedRFC7009Sections = []string{
	"1", "1.1",
	"2", "2.1", "2.2", "2.2.1", "2.3",
	"3",
	"4", "4.1", "4.1.1", "4.1.2", "4.1.2.1", "4.1.2.2",
	"5",
	"6",
	"7", "7.1", "7.2",
}

type specSection struct {
	Spec       string
	Section    string
	Title      string
	Applicable bool
	Notes      string
	Run        func(*testing.T)
}

func (s specSection) Name() string {
	title := strings.NewReplacer(
		" ", "_",
		"\"", "",
		"'", "",
		",", "",
		":", "",
		";", "",
		"(", "",
		")", "",
		"/", "_",
		"-", "_",
	).Replace(s.Title)
	return fmt.Sprintf("%s_%s", s.Section, title)
}

func runSpecSections(t *testing.T, sections []specSection) {
	t.Helper()

	for _, section := range sections {
		if !section.Applicable {
			continue
		}
		if section.Run == nil {
			t.Fatalf("missing test implementation for %s %s", section.Spec, section.Name())
		}
		t.Run(section.Name(), func(t *testing.T) {
			section.Run(t)
		})
	}
}

func allSpecSections() []specSection {
	var sections []specSection
	sections = append(sections, oidcCoreSections...)
	sections = append(sections, oidcDiscoverySections...)
	sections = append(sections, oidcRPInitiatedLogoutSections...)
	sections = append(sections, oidcBackChannelLogoutSections...)
	sections = append(sections, oauth21Sections...)
	sections = append(sections, rfc7662Sections...)
	sections = append(sections, rfc7009Sections...)
	return sections
}

func assertExactManifestSections(t *testing.T, spec string, expected []string, actual map[string]struct{}) {
	t.Helper()

	expectedSet := make(map[string]struct{}, len(expected))
	for _, section := range expected {
		expectedSet[section] = struct{}{}
		if _, ok := actual[section]; !ok {
			t.Fatalf("missing manifest entry for %s:%s", spec, section)
		}
	}
	for section := range actual {
		if _, ok := expectedSet[section]; !ok {
			t.Fatalf("unexpected manifest entry for %s:%s", spec, section)
		}
	}
}

func TestSpecCoverageManifest(t *testing.T) {
	type summary struct {
		applicable int
		documented int
	}

	seen := map[string]struct{}{}
	sectionsBySpec := map[string]map[string]struct{}{}
	summaries := map[string]summary{}

	for _, section := range allSpecSections() {
		key := section.Spec + ":" + section.Section
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate manifest entry for %s", key)
		}
		seen[key] = struct{}{}
		if sectionsBySpec[section.Spec] == nil {
			sectionsBySpec[section.Spec] = map[string]struct{}{}
		}
		sectionsBySpec[section.Spec][section.Section] = struct{}{}

		current := summaries[section.Spec]
		switch {
		case section.Applicable:
			current.applicable++
			if section.Run == nil {
				t.Fatalf("manifest entry %s is applicable but has no test implementation", key)
			}
		default:
			current.documented++
			if section.Notes == "" {
				t.Fatalf("manifest entry %s is out of scope but has no rationale", key)
			}
		}
		summaries[section.Spec] = current
	}

	for _, spec := range []string{
		"OIDC Core 1.0",
		"OIDC Discovery 1.0",
		"OIDC RP-Initiated Logout 1.0",
		"OIDC Back-Channel Logout 1.0",
		"OAuth 2.1",
		"RFC 7662",
		"RFC 7009",
	} {
		summary := summaries[spec]
		t.Logf("%s: %d applicable sections, %d documented out-of-scope sections", spec, summary.applicable, summary.documented)
	}

	assertExactManifestSections(t, "OIDC Core 1.0", expectedOIDCCoreSections, sectionsBySpec["OIDC Core 1.0"])
	assertExactManifestSections(t, "OIDC Discovery 1.0", expectedOIDCDiscoverySections, sectionsBySpec["OIDC Discovery 1.0"])
	assertExactManifestSections(t, "OIDC RP-Initiated Logout 1.0", expectedOIDCRPInitiatedLogoutSections, sectionsBySpec["OIDC RP-Initiated Logout 1.0"])
	assertExactManifestSections(t, "OIDC Back-Channel Logout 1.0", expectedOIDCBackChannelLogoutSections, sectionsBySpec["OIDC Back-Channel Logout 1.0"])
	assertExactManifestSections(t, "OAuth 2.1", expectedOAuth21Sections, sectionsBySpec["OAuth 2.1"])
	assertExactManifestSections(t, "RFC 7662", expectedRFC7662Sections, sectionsBySpec["RFC 7662"])
	assertExactManifestSections(t, "RFC 7009", expectedRFC7009Sections, sectionsBySpec["RFC 7009"])
}
