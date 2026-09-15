package models

import "github.com/Raxuis/RaxuisCLI/internal/shared/constants"

// VulnResult represents a vulnerability finding
type VulnResult struct {
	// ID is derived from RuleID and Resource when the result is included in a report.
	ID          string             `json:"id,omitempty"`
	RuleID      string             `json:"rule_id,omitempty"`
	Title       string             `json:"title,omitempty"`
	Type        constants.VulnType `json:"type,omitempty"`
	Severity    constants.Severity `json:"severity,omitempty"`
	Status      string             `json:"status,omitempty"`
	Resource    string             `json:"resource,omitempty"`
	URL         string             `json:"-"`
	Parameter   string             `json:"parameter,omitempty"`
	Payload     string             `json:"payload,omitempty"`
	Evidence    string             `json:"evidence,omitempty"`
	Description string             `json:"description,omitempty"`
	Remediation string             `json:"remediation,omitempty"`
}

// CORSResult holds CORS test results with additional fields
type CORSResult struct {
	VulnResult
	AllowOrigin      string
	AllowCredentials bool
	AllowMethods     string
	AllowHeaders     string
	ExposeHeaders    string
}

// RaceResult holds race condition test results
type RaceResult struct {
	VulnResult
	Responses    []int // status codes
	Inconsistent bool
	SuccessCount int
}

// GraphQLSchema represents introspection result
type GraphQLSchema struct {
	Types     []string
	Queries   []string
	Mutations []string
}
