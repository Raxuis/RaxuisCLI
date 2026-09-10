package report

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
)

// ComparisonSchemaVersion is the version of the comparison JSON envelope.
const ComparisonSchemaVersion = 1

var (
	// ErrInvalidFindingIdentity marks a finding without a stable comparison key.
	ErrInvalidFindingIdentity = errors.New("invalid finding identity")
	// ErrDuplicateFindingIdentity marks multiple findings with the same rule and
	// canonical resource in one report. Pairing such findings would be ambiguous.
	ErrDuplicateFindingIdentity = errors.New("duplicate finding identity")
)

// Comparison is the versioned, deterministic difference between two reports.
// Before and After retain the execution metadata needed by CLI and TUI clients;
// findings and observations contain only their classified differences.
type Comparison struct {
	SchemaVersion int                   `json:"schema_version"`
	Before        ComparisonMetadata    `json:"before"`
	After         ComparisonMetadata    `json:"after"`
	Findings      FindingComparison     `json:"findings"`
	Observations  ObservationComparison `json:"observations"`
}

// ComparisonMetadata is the source metadata carried with a comparison.
type ComparisonMetadata struct {
	Tool  ToolInfo  `json:"tool"`
	Audit AuditInfo `json:"audit"`
}

// FindingComparison classifies findings by their stable identity.
type FindingComparison struct {
	Added     []models.VulnResult `json:"added"`
	Resolved  []models.VulnResult `json:"resolved"`
	Changed   []FindingChange     `json:"changed"`
	Unchanged []models.VulnResult `json:"unchanged"`
}

// FindingChange records a matched finding whose content changed.
type FindingChange struct {
	Before           models.VulnResult `json:"before"`
	After            models.VulnResult `json:"after"`
	SeverityWorsened bool              `json:"severity_worsened"`
	SeverityImproved bool              `json:"severity_improved"`
	EvidenceChanged  bool              `json:"evidence_changed"`
	DisplayChanged   bool              `json:"display_changed"`
}

// ObservationComparison classifies observations by key and value. Repeated
// keys are matched deterministically: identical values first, then remaining
// values in lexical order.
type ObservationComparison struct {
	Added     []Observation       `json:"added"`
	Removed   []Observation       `json:"removed"`
	Changed   []ObservationChange `json:"changed"`
	Unchanged []Observation       `json:"unchanged"`
}

// ObservationChange records an observation with a stable key and a changed
// value.
type ObservationChange struct {
	Key    string `json:"key"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Compare validates and deterministically compares two report snapshots. It
// never mutates either input, and derives identities from RuleID and canonical
// Resource instead of trusting persisted IDs.
func Compare(before, after Report, allowTargetMismatch bool) (Comparison, error) {
	if err := ValidateComparisonInputs(before, after, allowTargetMismatch); err != nil {
		return Comparison{}, err
	}
	beforeFindings, err := comparisonFindingMap(before.Findings, "before")
	if err != nil {
		return Comparison{}, err
	}
	afterFindings, err := comparisonFindingMap(after.Findings, "after")
	if err != nil {
		return Comparison{}, err
	}

	result := Comparison{
		SchemaVersion: ComparisonSchemaVersion,
		Before:        comparisonMetadata(before),
		After:         comparisonMetadata(after),
		Findings: FindingComparison{
			Added:     make([]models.VulnResult, 0),
			Resolved:  make([]models.VulnResult, 0),
			Changed:   make([]FindingChange, 0),
			Unchanged: make([]models.VulnResult, 0),
		},
		Observations: compareObservations(before.Observations, after.Observations),
	}

	for identity, beforeFinding := range beforeFindings {
		afterFinding, exists := afterFindings[identity]
		if !exists {
			result.Findings.Resolved = append(result.Findings.Resolved, beforeFinding)
			continue
		}
		if findingContentEqual(beforeFinding, afterFinding) {
			result.Findings.Unchanged = append(result.Findings.Unchanged, afterFinding)
			continue
		}
		change := FindingChange{
			Before:          beforeFinding,
			After:           afterFinding,
			EvidenceChanged: beforeFinding.Evidence != afterFinding.Evidence,
			DisplayChanged:  findingDisplayChanged(beforeFinding, afterFinding),
		}
		change.SeverityWorsened = afterFinding.Severity.Rank() > beforeFinding.Severity.Rank()
		change.SeverityImproved = afterFinding.Severity.Rank() < beforeFinding.Severity.Rank()
		result.Findings.Changed = append(result.Findings.Changed, change)
	}
	for identity, afterFinding := range afterFindings {
		if _, exists := beforeFindings[identity]; !exists {
			result.Findings.Added = append(result.Findings.Added, afterFinding)
		}
	}

	sortFindings(result.Findings.Added)
	sortFindings(result.Findings.Resolved)
	sortFindings(result.Findings.Unchanged)
	sort.Slice(result.Findings.Changed, func(i, j int) bool {
		return findingLess(result.Findings.Changed[i].After, result.Findings.Changed[j].After)
	})
	return result, nil
}

// CompareReports is an explicit alias for Compare for callers that prefer a
// descriptive operation name.
func CompareReports(before, after Report, allowTargetMismatch bool) (Comparison, error) {
	return Compare(before, after, allowTargetMismatch)
}

// HasRegressionAt reports whether an added or severity-worsened finding meets
// threshold. Resolutions, severity improvements, evidence changes, and display
// changes do not affect this policy decision.
func (comparison Comparison) HasRegressionAt(threshold constants.Severity) bool {
	if threshold == constants.SeverityNone {
		return false
	}
	for _, finding := range comparison.Findings.Added {
		if finding.Severity.MeetsThreshold(threshold) {
			return true
		}
	}
	for _, change := range comparison.Findings.Changed {
		if change.SeverityWorsened && change.After.Severity.MeetsThreshold(threshold) {
			return true
		}
	}
	return false
}

func comparisonFindingMap(findings []models.VulnResult, side string) (map[string]models.VulnResult, error) {
	result := make(map[string]models.VulnResult, len(findings))
	for index, finding := range findings {
		normalized, identity, err := normalizeComparisonFinding(finding)
		if err != nil {
			return nil, fmt.Errorf("%w: %s finding %d: %v", ErrInvalidFindingIdentity, side, index, err)
		}
		if _, exists := result[identity]; exists {
			return nil, fmt.Errorf("%w: %s finding %d (%s)", ErrDuplicateFindingIdentity, side, index, identity)
		}
		result[identity] = normalized
	}
	return result, nil
}

func normalizeComparisonFinding(finding models.VulnResult) (models.VulnResult, string, error) {
	// NormalizeFinding copies its value argument, so comparison cannot mutate an
	// input report while canonicalizing resource and presentation fields.
	normalized := NormalizeFinding(finding)
	normalized.RuleID = strings.TrimSpace(normalized.RuleID)
	normalized.Resource = CanonicalizeResource(normalized.Resource)
	normalized.URL = normalized.Resource
	if normalized.RuleID == "" || normalized.Resource == "" {
		return models.VulnResult{}, "", errors.New("rule_id and resource are required")
	}
	if severity, err := constants.ParseSeverity(string(normalized.Severity)); err == nil {
		normalized.Severity = severity
	}
	normalized.ID = FindingID(normalized.RuleID, normalized.Resource)
	return normalized, normalized.RuleID + "\n" + normalized.Resource, nil
}

func comparisonMetadata(value Report) ComparisonMetadata {
	metadata := ComparisonMetadata{Tool: value.Tool, Audit: value.Audit}
	metadata.Audit.Target = CanonicalizeResource(metadata.Audit.Target)
	metadata.Audit.StartedAt = metadata.Audit.StartedAt.UTC()
	return metadata
}

func findingContentEqual(left, right models.VulnResult) bool {
	return left.RuleID == right.RuleID &&
		left.Title == right.Title &&
		left.Type == right.Type &&
		left.Severity == right.Severity &&
		left.Status == right.Status &&
		left.Resource == right.Resource &&
		left.Parameter == right.Parameter &&
		left.Payload == right.Payload &&
		left.Evidence == right.Evidence &&
		left.Description == right.Description &&
		left.Remediation == right.Remediation
}

func findingDisplayChanged(left, right models.VulnResult) bool {
	return left.Title != right.Title ||
		left.Type != right.Type ||
		left.Status != right.Status ||
		left.Parameter != right.Parameter ||
		left.Payload != right.Payload ||
		left.Description != right.Description ||
		left.Remediation != right.Remediation
}

func findingLess(left, right models.VulnResult) bool {
	leftIdentity := left.RuleID + "\n" + left.Resource
	rightIdentity := right.RuleID + "\n" + right.Resource
	if leftIdentity != rightIdentity {
		return leftIdentity < rightIdentity
	}
	return left.ID < right.ID
}

func compareObservations(before, after []Observation) ObservationComparison {
	beforeGroups := observationGroups(before)
	afterGroups := observationGroups(after)
	keys := make(map[string]struct{}, len(beforeGroups)+len(afterGroups))
	for key := range beforeGroups {
		keys[key] = struct{}{}
	}
	for key := range afterGroups {
		keys[key] = struct{}{}
	}
	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	result := ObservationComparison{
		Added:     make([]Observation, 0),
		Removed:   make([]Observation, 0),
		Changed:   make([]ObservationChange, 0),
		Unchanged: make([]Observation, 0),
	}
	for _, key := range sortedKeys {
		remainingBefore, remainingAfter := matchIdenticalObservations(beforeGroups[key], afterGroups[key], &result.Unchanged)
		shared := len(remainingBefore)
		if len(remainingAfter) < shared {
			shared = len(remainingAfter)
		}
		for index := 0; index < shared; index++ {
			result.Changed = append(result.Changed, ObservationChange{Key: key, Before: remainingBefore[index].Value, After: remainingAfter[index].Value})
		}
		result.Removed = append(result.Removed, remainingBefore[shared:]...)
		result.Added = append(result.Added, remainingAfter[shared:]...)
	}
	return result
}

func observationGroups(observations []Observation) map[string][]Observation {
	groups := make(map[string][]Observation)
	for _, observation := range observations {
		groups[observation.Key] = append(groups[observation.Key], Observation{Key: observation.Key, Value: observation.Value})
	}
	for key := range groups {
		sort.SliceStable(groups[key], func(i, j int) bool { return groups[key][i].Value < groups[key][j].Value })
	}
	return groups
}

func matchIdenticalObservations(before, after []Observation, unchanged *[]Observation) ([]Observation, []Observation) {
	remainingBefore := make([]Observation, 0, len(before))
	remainingAfter := make([]Observation, 0, len(after))
	beforeIndex, afterIndex := 0, 0
	for beforeIndex < len(before) && afterIndex < len(after) {
		if before[beforeIndex].Value == after[afterIndex].Value {
			*unchanged = append(*unchanged, before[beforeIndex])
			beforeIndex++
			afterIndex++
			continue
		}
		if before[beforeIndex].Value < after[afterIndex].Value {
			remainingBefore = append(remainingBefore, before[beforeIndex])
			beforeIndex++
			continue
		}
		remainingAfter = append(remainingAfter, after[afterIndex])
		afterIndex++
	}
	remainingBefore = append(remainingBefore, before[beforeIndex:]...)
	remainingAfter = append(remainingAfter, after[afterIndex:]...)
	return remainingBefore, remainingAfter
}
