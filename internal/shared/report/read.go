package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"raxuiscli/internal/shared/constants"
)

const (
	maxReportBytes = int64(16 << 20)
	maxJSONDepth   = 128
)

var (
	// ErrInvalidReport marks malformed reports and schema-v1 contract failures.
	ErrInvalidReport = errors.New("invalid report")
	// ErrUnsupportedSchema marks a well-formed report using an unknown schema.
	ErrUnsupportedSchema = errors.New("unsupported report schema")
	// ErrTargetMismatch marks reports that describe different canonical targets.
	ErrTargetMismatch = errors.New("report targets do not match")
	// ErrKindMismatch marks reports produced by different audit kinds.
	ErrKindMismatch = errors.New("report kinds do not match")
)

// Read decodes, validates, redacts, and deterministically normalizes one
// persisted report. Unknown additive fields are accepted for forward
// compatibility; fields required by schema v1 must remain present.
func Read(reader io.Reader) (Report, error) {
	if reader == nil {
		return Report{}, invalidReport("document", "reader is nil")
	}

	contents, err := io.ReadAll(io.LimitReader(reader, maxReportBytes+1))
	if err != nil {
		return Report{}, fmt.Errorf("%w: read JSON: %v", ErrInvalidReport, err)
	}
	if int64(len(contents)) > maxReportBytes {
		return Report{}, invalidReport("document", fmt.Sprintf("exceeds %d-byte limit", maxReportBytes))
	}
	if err := rejectDuplicateJSONKeys(contents); err != nil {
		return Report{}, err
	}

	document := json.RawMessage(contents)
	root, err := decodeObject(document, "document")
	if err != nil {
		return Report{}, err
	}
	if err := validateSchemaV1(root); err != nil {
		return Report{}, err
	}

	var decoded Report
	if err := json.Unmarshal(document, &decoded); err != nil {
		return Report{}, fmt.Errorf("%w: decode schema v1: %v", ErrInvalidReport, err)
	}
	for index := range decoded.Findings {
		severity, _ := constants.ParseSeverity(string(decoded.Findings[index].Severity))
		decoded.Findings[index].Severity = severity
	}

	// IDs are derived data. Recompute them after canonicalization instead of
	// trusting stale or tampered values stored in the input document.
	decoded.Audit.ID = ""
	normalized := NewReport(decoded.Tool, decoded.Audit, decoded.Findings, decoded.Observations, decoded.Errors)
	return normalized, nil
}

// ReadFile opens and reads one persisted report while retaining filesystem
// errors for errors.Is/errors.As callers.
func ReadFile(filename string) (Report, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Report{}, fmt.Errorf("read report %q: %w", filename, err)
	}
	loaded, readErr := Read(file)
	closeErr := file.Close()
	if readErr != nil {
		return Report{}, fmt.Errorf("read report %q: %w", filename, readErr)
	}
	if closeErr != nil {
		return Report{}, fmt.Errorf("read report %q: close: %w", filename, closeErr)
	}
	return loaded, nil
}

// ValidateComparisonInputs enforces the compatibility rules shared by report
// comparison callers. Audit kinds must always match; target mismatches require
// an explicit opt-in.
func ValidateComparisonInputs(before, after Report, allowTargetMismatch bool) error {
	if before.Audit.Kind != after.Audit.Kind {
		return fmt.Errorf("%w: %q and %q", ErrKindMismatch, before.Audit.Kind, after.Audit.Kind)
	}
	beforeTarget := CanonicalizeResource(before.Audit.Target)
	afterTarget := CanonicalizeResource(after.Audit.Target)
	if !allowTargetMismatch && beforeTarget != afterTarget {
		return fmt.Errorf("%w: %q and %q", ErrTargetMismatch, beforeTarget, afterTarget)
	}
	return nil
}

func validateSchemaV1(root map[string]json.RawMessage) error {
	schemaRaw, err := requiredField(root, "schema_version", "schema_version")
	if err != nil {
		return err
	}
	var schemaVersion int
	if err := json.Unmarshal(schemaRaw, &schemaVersion); err != nil {
		return invalidReport("schema_version", "must be an integer")
	}
	if schemaVersion != SchemaVersion {
		return fmt.Errorf("%w: got %d, support %d", ErrUnsupportedSchema, schemaVersion, SchemaVersion)
	}

	toolRaw, err := requiredField(root, "tool", "tool")
	if err != nil {
		return err
	}
	tool, err := decodeObject(toolRaw, "tool")
	if err != nil {
		return err
	}
	for _, name := range []string{"name", "version", "commit", "go_version", "platform"} {
		if _, err := requiredString(tool, name, "tool."+name, true); err != nil {
			return err
		}
	}

	auditRaw, err := requiredField(root, "audit", "audit")
	if err != nil {
		return err
	}
	audit, err := decodeObject(auditRaw, "audit")
	if err != nil {
		return err
	}
	for _, name := range []string{"id", "kind", "target", "started_at", "status"} {
		if _, err := requiredString(audit, name, "audit."+name, true); err != nil {
			return err
		}
	}
	durationRaw, err := requiredField(audit, "duration", "audit.duration")
	if err != nil {
		return err
	}
	var duration int64
	if err := json.Unmarshal(durationRaw, &duration); err != nil || duration < 0 {
		return invalidReport("audit.duration", "must be a non-negative integer")
	}

	findingsRaw, err := requiredField(root, "findings", "findings")
	if err != nil {
		return err
	}
	findings, err := decodeArray(findingsRaw, "findings")
	if err != nil {
		return err
	}
	for index, rawFinding := range findings {
		path := fmt.Sprintf("findings[%d]", index)
		finding, err := decodeObject(rawFinding, path)
		if err != nil {
			return err
		}
		for _, name := range []string{"id", "rule_id", "title", "severity", "status", "resource", "evidence", "remediation"} {
			value, err := requiredString(finding, name, path+"."+name, name != "evidence" && name != "remediation")
			if err != nil {
				return err
			}
			if name == "severity" {
				severity, severityErr := constants.ParseSeverity(value)
				if severityErr != nil || severity == constants.SeverityNone {
					return invalidReport(path+".severity", "must be INFO, LOW, MEDIUM, HIGH, or CRITICAL")
				}
			}
		}
	}

	observationsRaw, err := requiredField(root, "observations", "observations")
	if err != nil {
		return err
	}
	observations, err := decodeArray(observationsRaw, "observations")
	if err != nil {
		return err
	}
	for index, rawObservation := range observations {
		path := fmt.Sprintf("observations[%d]", index)
		observation, err := decodeObject(rawObservation, path)
		if err != nil {
			return err
		}
		if _, err := requiredString(observation, "key", path+".key", true); err != nil {
			return err
		}
		if _, err := requiredString(observation, "value", path+".value", false); err != nil {
			return err
		}
	}

	errorsRaw, err := requiredField(root, "errors", "errors")
	if err != nil {
		return err
	}
	reportErrors, err := decodeArray(errorsRaw, "errors")
	if err != nil {
		return err
	}
	for index, rawError := range reportErrors {
		path := fmt.Sprintf("errors[%d]", index)
		reportError, err := decodeObject(rawError, path)
		if err != nil {
			return err
		}
		if _, err := requiredString(reportError, "code", path+".code", true); err != nil {
			return err
		}
		if _, err := requiredString(reportError, "message", path+".message", false); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return invalidReport("document", "contains more than one JSON value")
		}
		return fmt.Errorf("%w: decode trailing JSON: %v", ErrInvalidReport, err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return invalidReport("document", fmt.Sprintf("exceeds maximum JSON depth %d", maxJSONDepth))
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: decode JSON: %v", ErrInvalidReport, err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%w: decode object key: %v", ErrInvalidReport, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return invalidReport("document", "contains a non-string object key")
			}
			if _, exists := seen[key]; exists {
				return invalidReport("document", "contains a duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return invalidReport("document", "contains an unexpected JSON delimiter")
	}

	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("%w: decode closing delimiter: %v", ErrInvalidReport, err)
	}
	return nil
}

func decodeObject(raw json.RawMessage, path string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, invalidReport(path, "must be an object")
	}
	return object, nil
}

func decodeArray(raw json.RawMessage, path string) ([]json.RawMessage, error) {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, invalidReport(path, "must be an array")
	}
	return values, nil
}

func requiredField(object map[string]json.RawMessage, name, path string) (json.RawMessage, error) {
	raw, exists := object[name]
	if !exists || len(raw) == 0 || string(raw) == "null" {
		return nil, invalidReport(path, "is required")
	}
	return raw, nil
}

func requiredString(object map[string]json.RawMessage, name, path string, nonEmpty bool) (string, error) {
	raw, err := requiredField(object, name, path)
	if err != nil {
		return "", err
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", invalidReport(path, "must be a string")
	}
	if nonEmpty && strings.TrimSpace(value) == "" {
		return "", invalidReport(path, "must not be empty")
	}
	return value, nil
}

func invalidReport(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidReport, path, reason)
}
