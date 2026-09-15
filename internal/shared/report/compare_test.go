package report

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
)

func TestCompareClassifiesFindingsAndObservations(t *testing.T) {
	before := comparisonReport([]models.VulnResult{
		comparisonFinding("rule.resolved", "https://example.test/resolved", constants.SeverityHigh, "resolved", "same"),
		comparisonFinding("rule.worsened", "https://example.test/worse", constants.SeverityLow, "worse", "same"),
		comparisonFinding("rule.improved", "https://example.test/improved", constants.SeverityHigh, "improved", "same"),
		comparisonFinding("rule.evidence", "https://example.test/evidence", constants.SeverityMedium, "evidence", "before"),
		comparisonFinding("rule.display", "https://example.test/display", constants.SeverityMedium, "before title", "same"),
		comparisonFinding("rule.unchanged", "https://example.test/unchanged", constants.SeverityInfo, "same", "same"),
	}, []Observation{{Key: "changed", Value: "before"}, {Key: "removed", Value: "gone"}, {Key: "repeat", Value: "one"}, {Key: "repeat", Value: "two"}})
	after := comparisonReport([]models.VulnResult{
		comparisonFinding("rule.added", "https://example.test/added", constants.SeverityCritical, "added", "same"),
		comparisonFinding("rule.worsened", "HTTPS://EXAMPLE.test:443/worse", constants.SeverityHigh, "worse", "same"),
		comparisonFinding("rule.improved", "https://example.test/improved", constants.SeverityLow, "improved", "same"),
		comparisonFinding("rule.evidence", "https://example.test/evidence", constants.SeverityMedium, "evidence", "after"),
		comparisonFinding("rule.display", "https://example.test/display", constants.SeverityMedium, "after title", "same"),
		comparisonFinding("rule.unchanged", "https://example.test/unchanged", constants.SeverityInfo, "same", "same"),
	}, []Observation{{Key: "added", Value: "new"}, {Key: "changed", Value: "after"}, {Key: "repeat", Value: "two"}, {Key: "repeat", Value: "three"}})

	got, err := Compare(before, after, false)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if got.SchemaVersion != ComparisonSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, ComparisonSchemaVersion)
	}
	if got.Before.Audit.Target != "https://example.test/" || got.After.Audit.Target != "https://example.test/" {
		t.Errorf("metadata target = %q / %q, want canonical target", got.Before.Audit.Target, got.After.Audit.Target)
	}
	if ids := findingIDs(got.Findings.Added); !reflect.DeepEqual(ids, []string{"rule.added"}) {
		t.Errorf("added = %v, want rule.added", ids)
	}
	if gotID, wantID := got.Findings.Added[0].ID, FindingID("rule.added", "https://example.test/added"); gotID != wantID {
		t.Errorf("comparison trusted input ID %q, want derived ID %q", gotID, wantID)
	}
	if ids := findingIDs(got.Findings.Resolved); !reflect.DeepEqual(ids, []string{"rule.resolved"}) {
		t.Errorf("resolved = %v, want rule.resolved", ids)
	}
	if len(got.Findings.Unchanged) != 1 || got.Findings.Unchanged[0].RuleID != "rule.unchanged" {
		t.Errorf("unchanged = %#v", got.Findings.Unchanged)
	}
	changes := changesByRule(got.Findings.Changed)
	for rule, want := range map[string]struct {
		worsened bool
		improved bool
		evidence bool
		display  bool
	}{
		"rule.worsened": {worsened: true},
		"rule.improved": {improved: true},
		"rule.evidence": {evidence: true},
		"rule.display":  {display: true},
	} {
		change, ok := changes[rule]
		if !ok {
			t.Errorf("missing %s change", rule)
			continue
		}
		if change.SeverityWorsened != want.worsened || change.SeverityImproved != want.improved || change.EvidenceChanged != want.evidence || change.DisplayChanged != want.display {
			t.Errorf("%s change flags = %#v", rule, change)
		}
	}

	if got, want := observationPairs(got.Observations.Added), []string{"added=new"}; !reflect.DeepEqual(got, want) {
		t.Errorf("added observations = %v, want %v", got, want)
	}
	if got, want := observationPairs(got.Observations.Removed), []string{"removed=gone"}; !reflect.DeepEqual(got, want) {
		t.Errorf("removed observations = %v, want %v", got, want)
	}
	if len(got.Observations.Changed) != 2 || got.Observations.Changed[0].Key != "changed" || got.Observations.Changed[1].Key != "repeat" {
		t.Errorf("changed observations = %#v", got.Observations.Changed)
	}
	if got, want := observationPairs(got.Observations.Unchanged), []string{"repeat=two"}; !reflect.DeepEqual(got, want) {
		t.Errorf("unchanged observations = %v, want %v", got, want)
	}
}

func TestCompareRejectsIncompatibleAndAmbiguousInputs(t *testing.T) {
	base := comparisonReport([]models.VulnResult{comparisonFinding("rule.one", "https://example.test/one", constants.SeverityLow, "one", "evidence")}, nil)

	tests := []struct {
		name   string
		before Report
		after  Report
		allow  bool
		want   error
	}{
		{name: "kind", before: base, after: Report{Audit: AuditInfo{Kind: "other", Target: base.Audit.Target}}, want: ErrKindMismatch},
		{name: "target", before: base, after: Report{Audit: AuditInfo{Kind: base.Audit.Kind, Target: "https://other.test/"}}, want: ErrTargetMismatch},
		{name: "target allowed", before: base, after: Report{Audit: AuditInfo{Kind: base.Audit.Kind, Target: "https://other.test/"}}, allow: true},
		{name: "duplicate", before: comparisonReport([]models.VulnResult{
			comparisonFinding("rule.one", "https://example.test/one", constants.SeverityLow, "one", "a"),
			comparisonFinding("rule.one", "HTTPS://EXAMPLE.test:443/one", constants.SeverityHigh, "two", "b"),
		}, nil), after: base, want: ErrDuplicateFindingIdentity},
		{name: "empty rule", before: comparisonReport([]models.VulnResult{{Resource: "https://example.test/one"}}, nil), after: base, want: ErrInvalidFindingIdentity},
		{name: "empty resource", before: comparisonReport([]models.VulnResult{{RuleID: "rule.one"}}, nil), after: base, want: ErrInvalidFindingIdentity},
		{name: "whitespace resource", before: comparisonReport([]models.VulnResult{{RuleID: "rule.one", Resource: " \t\n "}}, nil), after: base, want: ErrInvalidFindingIdentity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compare(test.before, test.after, test.allow)
			if !errors.Is(err, test.want) {
				t.Fatalf("Compare error = %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestCompareRejectsInvalidFindingSeverity(t *testing.T) {
	base := comparisonReport(nil, nil)
	for _, test := range []struct {
		name     string
		severity constants.Severity
		want     error
	}{
		{name: "typo", severity: constants.Severity("URGENT"), want: ErrInvalidReport},
		{name: "none", severity: constants.SeverityNone, want: ErrInvalidReport},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := comparisonReport([]models.VulnResult{comparisonFinding("rule.invalid", "https://example.test/invalid", test.severity, "invalid", "evidence")}, nil)
			_, err := Compare(base, invalid, false)
			if !errors.Is(err, test.want) || !strings.Contains(err.Error(), "after finding 0") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("Compare error = %v, want contextual errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestCompareCanonicalizesLowercaseSeverityForRegressionPolicy(t *testing.T) {
	before := comparisonReport(nil, nil)
	after := comparisonReport([]models.VulnResult{comparisonFinding("rule.lowercase", "https://example.test/lowercase", constants.Severity("low"), "added", "evidence")}, nil)
	comparison, err := Compare(before, after, false)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if got := comparison.Findings.Added[0].Severity; got != constants.SeverityLow {
		t.Errorf("added severity = %q, want canonical %q", got, constants.SeverityLow)
	}
	if !comparison.HasRegressionAt(constants.SeverityLow) {
		t.Error("canonical lowercase LOW added finding must trigger LOW threshold")
	}
}

func TestCompareIsDeterministicAndDoesNotMutateInputs(t *testing.T) {
	before := comparisonReport([]models.VulnResult{
		comparisonFinding("rule.b", "HTTPS://EXAMPLE.test:443/b", constants.SeverityLow, "b", "same"),
		comparisonFinding("rule.a", "https://example.test/a", constants.SeverityLow, "a", "same"),
	}, []Observation{{Key: "key", Value: "b"}, {Key: "key", Value: "a"}})
	after := comparisonReport([]models.VulnResult{
		comparisonFinding("rule.c", "https://example.test/c", constants.SeverityLow, "c", "same"),
		comparisonFinding("rule.b", "https://example.test/b", constants.SeverityHigh, "b", "same"),
	}, []Observation{{Key: "key", Value: "c"}, {Key: "key", Value: "a"}})
	beforeCopy, afterCopy := cloneReport(before), cloneReport(after)

	first, err := Compare(before, after, false)
	if err != nil {
		t.Fatalf("first Compare: %v", err)
	}
	if !reflect.DeepEqual(before, beforeCopy) || !reflect.DeepEqual(after, afterCopy) {
		t.Fatal("Compare mutated its inputs")
	}
	before.Findings[0], before.Findings[1] = before.Findings[1], before.Findings[0]
	after.Findings[0], after.Findings[1] = after.Findings[1], after.Findings[0]
	before.Observations[0], before.Observations[1] = before.Observations[1], before.Observations[0]
	after.Observations[0], after.Observations[1] = after.Observations[1], after.Observations[0]
	second, err := Compare(before, after, false)
	if err != nil {
		t.Fatalf("second Compare: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("comparison differs after input permutation\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestComparisonHasRegressionAt(t *testing.T) {
	before := comparisonReport([]models.VulnResult{
		comparisonFinding("rule.worse", "https://example.test/worse", constants.SeverityLow, "worse", "same"),
		comparisonFinding("rule.better", "https://example.test/better", constants.SeverityCritical, "better", "same"),
	}, nil)
	after := comparisonReport([]models.VulnResult{
		comparisonFinding("rule.added", "https://example.test/added", constants.SeverityMedium, "added", "same"),
		comparisonFinding("rule.worse", "https://example.test/worse", constants.SeverityHigh, "worse", "same"),
		comparisonFinding("rule.better", "https://example.test/better", constants.SeverityLow, "better", "same"),
	}, nil)
	comparison, err := Compare(before, after, false)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	for _, test := range []struct {
		threshold constants.Severity
		want      bool
	}{
		{constants.SeverityNone, false},
		{constants.SeverityInfo, true},
		{constants.SeverityLow, true},
		{constants.SeverityMedium, true},
		{constants.SeverityHigh, true},
		{constants.SeverityCritical, false},
	} {
		if got := comparison.HasRegressionAt(test.threshold); got != test.want {
			t.Errorf("HasRegressionAt(%s) = %t, want %t", test.threshold, got, test.want)
		}
	}

	regressionFreeAfter := comparisonReport([]models.VulnResult{
		comparisonFinding("rule.worse", "https://example.test/worse", constants.SeverityInfo, "worse", "different evidence"),
		comparisonFinding("rule.better", "https://example.test/better", constants.SeverityLow, "better", "same"),
	}, nil)
	resolvedOnly, err := Compare(before, regressionFreeAfter, false)
	if err != nil {
		t.Fatalf("reversed Compare: %v", err)
	}
	if resolvedOnly.HasRegressionAt(constants.SeverityInfo) {
		t.Error("resolutions and improvements must not be regressions")
	}
}

func comparisonReport(findings []models.VulnResult, observations []Observation) Report {
	return Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolInfo{Name: "raxuiscli", Version: "test"},
		Audit:         AuditInfo{Kind: "web", Target: "https://example.test/", StartedAt: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)},
		Findings:      findings,
		Observations:  observations,
	}
}

func comparisonFinding(rule, resource string, severity constants.Severity, title, evidence string) models.VulnResult {
	return models.VulnResult{ID: "untrusted-input-id", RuleID: rule, Resource: resource, Severity: severity, Title: title, Status: "open", Evidence: evidence, Remediation: "fix"}
}

func findingIDs(findings []models.VulnResult) []string {
	result := make([]string, len(findings))
	for index, finding := range findings {
		result[index] = finding.RuleID
	}
	return result
}

func changesByRule(changes []FindingChange) map[string]FindingChange {
	result := make(map[string]FindingChange, len(changes))
	for _, change := range changes {
		result[change.After.RuleID] = change
	}
	return result
}

func observationPairs(observations []Observation) []string {
	result := make([]string, len(observations))
	for index, observation := range observations {
		result[index] = observation.Key + "=" + observation.Value
	}
	return result
}

func cloneReport(value Report) Report {
	clone := value
	clone.Findings = append([]models.VulnResult(nil), value.Findings...)
	clone.Observations = append([]Observation(nil), value.Observations...)
	clone.Errors = append([]ReportError(nil), value.Errors...)
	return clone
}
