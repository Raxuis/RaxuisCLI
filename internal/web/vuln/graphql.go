package vuln

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"raxuiscli/internal/shared/payloads"
)

// TestGraphQL tests for GraphQL security issues
func TestGraphQL(opts GraphQLOptions, resultChan chan<- VulnResult) {
	client := createClient(opts.ScanOptions)

	// Test introspection
	introspectionQueries := []struct {
		name  string
		query string
	}{
		{"simple", payloads.GraphQLQueries["introspection_simple"]},
		{"full", payloads.GraphQLQueries["introspection_full"]},
		{"query_type", payloads.GraphQLQueries["query_type"]},
		{"mutation_type", payloads.GraphQLQueries["mutation_type"]},
	}

	for _, iq := range introspectionQueries {
		req, err := http.NewRequest("POST", opts.URL, strings.NewReader(iq.query))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		// Check if introspection is enabled
		if strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "__type") {
			if strings.Contains(bodyStr, "queryType") || strings.Contains(bodyStr, "fields") {
				severity := SeverityMedium
				if strings.Contains(bodyStr, "mutation") || strings.Contains(bodyStr, "Mutation") {
					severity = SeverityHigh
				}

				resultChan <- VulnResult{
					Type:        VulnGraphQL,
					Severity:    severity,
					URL:         opts.URL,
					Parameter:   "Introspection",
					Payload:     iq.name,
					Evidence:    "Introspection query successful - schema exposed",
					Description: "GraphQL introspection is enabled. Attackers can enumerate the entire API schema.",
					Remediation: "Disable introspection in production. Use allowlists for permitted queries.",
				}
				break
			}
		}

		// Check for sensitive type names in schema
		bodyLower := strings.ToLower(bodyStr)
		for _, sensitive := range payloads.SensitiveTypeNames {
			if strings.Contains(bodyLower, sensitive) {
				resultChan <- VulnResult{
					Type:        VulnGraphQL,
					Severity:    SeverityMedium,
					URL:         opts.URL,
					Parameter:   "Schema",
					Payload:     iq.name,
					Evidence:    fmt.Sprintf("Sensitive field found: %s", sensitive),
					Description: "GraphQL schema exposes potentially sensitive field names.",
					Remediation: "Review schema for sensitive data exposure. Implement proper authorization.",
				}
			}
		}
	}

	// Test field suggestions (typo-based enumeration)
	suggestionQuery := payloads.GraphQLSuggestionQuery
	req, _ := http.NewRequest("POST", opts.URL, strings.NewReader(suggestionQuery))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if strings.Contains(string(body), "Did you mean") || strings.Contains(string(body), "suggestions") {
			resultChan <- VulnResult{
				Type:        VulnGraphQL,
				Severity:    SeverityLow,
				URL:         opts.URL,
				Parameter:   "Field Suggestions",
				Payload:     suggestionQuery,
				Evidence:    "Server provides field suggestions on typos",
				Description: "GraphQL server suggests field names. This aids enumeration even without introspection.",
				Remediation: "Disable field suggestions in production GraphQL configuration.",
			}
		}
	}

	// Test for batching/DoS if enabled
	if opts.DoS {
		// Test query batching
		batchQuery := payloads.GraphQLBatchQuery
		req, _ := http.NewRequest("POST", opts.URL, strings.NewReader(batchQuery))
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if strings.Contains(string(body), "[") && strings.Count(string(body), "__typename") >= 2 {
				resultChan <- VulnResult{
					Type:        VulnGraphQL,
					Severity:    SeverityMedium,
					URL:         opts.URL,
					Parameter:   "Batching",
					Payload:     "Array batch query",
					Evidence:    "Multiple responses returned for batched queries",
					Description: "GraphQL batching is enabled. This may allow DoS via query multiplication.",
					Remediation: "Limit batch size. Implement query cost analysis and rate limiting.",
				}
			}
		}

		// Test deeply nested query
		nestedQuery := payloads.GraphQLNestedQuery
		req, _ = http.NewRequest("POST", opts.URL, strings.NewReader(nestedQuery))
		req.Header.Set("Content-Type", "application/json")

		start := time.Now()
		resp, err = client.Do(req)
		elapsed := time.Since(start)

		if err == nil {
			resp.Body.Close()
			if elapsed > 3*time.Second {
				resultChan <- VulnResult{
					Type:        VulnGraphQL,
					Severity:    SeverityHigh,
					URL:         opts.URL,
					Parameter:   "Query Depth",
					Payload:     "Nested introspection",
					Evidence:    fmt.Sprintf("Slow response: %v for nested query", elapsed),
					Description: "GraphQL server is vulnerable to DoS via deeply nested queries.",
					Remediation: "Implement query depth limiting. Set maximum query complexity.",
				}
			}
		}
	}
}
