// Package report defines the versioned, persisted audit-report contract.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"raxuiscli/internal/shared/models"
)

// SchemaVersion is the current public JSON report schema version.
const SchemaVersion = 1

// Report is the versioned envelope persisted by audit commands.
type Report struct {
	SchemaVersion int                 `json:"schema_version"`
	Tool          ToolInfo            `json:"tool"`
	Audit         AuditInfo           `json:"audit"`
	Findings      []models.VulnResult `json:"findings"`
	Observations  []Observation       `json:"observations"`
	Errors        []ReportError       `json:"errors"`
}

// ToolInfo identifies the executable that produced a report.
type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// AuditInfo identifies an audit execution and its target.
type AuditInfo struct {
	ID        string        `json:"id"`
	Kind      string        `json:"kind"`
	Target    string        `json:"target"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Status    string        `json:"status"`
}

// Observation is a non-finding fact collected during an audit.
type Observation struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ReportError records a redacted, partial-failure message.
type ReportError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewReport constructs a schema-v1 report, redacting sensitive data and sorting
// all collections for deterministic persistence.
func NewReport(tool ToolInfo, audit AuditInfo, findings []models.VulnResult, observations []Observation, errors []ReportError) Report {
	audit.Target = CanonicalizeResource(audit.Target)
	audit.StartedAt = audit.StartedAt.UTC()
	if audit.ID == "" {
		audit.ID = AuditID(audit.Kind, audit.Target, audit.StartedAt)
	}

	normalizedFindings := make([]models.VulnResult, len(findings))
	for i, finding := range findings {
		normalizedFindings[i] = NormalizeFinding(finding)
	}
	sortFindings(normalizedFindings)

	normalizedObservations := make([]Observation, len(observations))
	for i, observation := range observations {
		normalizedObservations[i] = Observation{
			Key:   RedactString(observation.Key),
			Value: RedactString(observation.Value),
		}
	}
	sort.SliceStable(normalizedObservations, func(i, j int) bool {
		if normalizedObservations[i].Key != normalizedObservations[j].Key {
			return normalizedObservations[i].Key < normalizedObservations[j].Key
		}
		return normalizedObservations[i].Value < normalizedObservations[j].Value
	})

	normalizedErrors := make([]ReportError, len(errors))
	for i, reportError := range errors {
		normalizedErrors[i] = ReportError{
			Code:    RedactString(reportError.Code),
			Message: RedactString(reportError.Message),
		}
	}
	sort.SliceStable(normalizedErrors, func(i, j int) bool {
		if normalizedErrors[i].Code != normalizedErrors[j].Code {
			return normalizedErrors[i].Code < normalizedErrors[j].Code
		}
		return normalizedErrors[i].Message < normalizedErrors[j].Message
	})

	return Report{
		SchemaVersion: SchemaVersion,
		Tool:          tool,
		Audit:         audit,
		Findings:      normalizedFindings,
		Observations:  normalizedObservations,
		Errors:        normalizedErrors,
	}
}

// NormalizeFinding adapts a legacy VulnResult to the stable report finding
// contract without changing the caller's value.
func NormalizeFinding(finding models.VulnResult) models.VulnResult {
	resource := finding.Resource
	if resource == "" {
		resource = finding.URL
	}
	resource = CanonicalizeResource(resource)
	finding.Resource = resource
	// Preserve the legacy field for existing display callers while ensuring it is
	// safe whenever a finding escapes in a report.
	finding.URL = resource
	if finding.Title == "" && finding.Type != "" {
		finding.Title = finding.Type.Description()
	}
	if finding.RuleID != "" {
		finding.ID = FindingID(finding.RuleID, resource)
	}
	finding.Parameter = RedactString(finding.Parameter)
	finding.Payload = RedactString(finding.Payload)
	finding.Evidence = RedactString(finding.Evidence)
	finding.Description = RedactString(finding.Description)
	finding.Remediation = RedactString(finding.Remediation)
	return finding
}

// FindingID derives a stable finding identity from its stable rule and canonical
// resource. Display fields intentionally play no part in this value.
func FindingID(ruleID, resource string) string {
	input := ruleID + "\n" + CanonicalizeResource(resource)
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// AuditID derives a repeatable ID for a particular audit execution.
func AuditID(kind, target string, startedAt time.Time) string {
	input := strings.Join([]string{kind, CanonicalizeResource(target), startedAt.UTC().Format(time.RFC3339Nano)}, "\n")
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func sortFindings(findings []models.VulnResult) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		for _, pair := range [][2]string{
			{left.ID, right.ID},
			{left.RuleID, right.RuleID},
			{left.Resource, right.Resource},
			{left.Status, right.Status},
			{left.Title, right.Title},
			{string(left.Severity), string(right.Severity)},
			{left.Evidence, right.Evidence},
		} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return false
	})
}
