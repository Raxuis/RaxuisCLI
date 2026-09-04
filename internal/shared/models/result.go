package models

import "raxuiscli/internal/shared/constants"

// VulnResult represents a vulnerability finding
type VulnResult struct {
	Type        constants.VulnType
	Severity    constants.Severity
	URL         string
	Parameter   string
	Payload     string
	Evidence    string
	Description string
	Remediation string
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
