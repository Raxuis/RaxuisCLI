package vuln

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"raxuiscli/internal/shared/payloads"
)

// TestXXE tests for XML External Entity vulnerabilities
func TestXXE(opts XXEOptions, resultChan chan<- VulnResult) {
	client := createClient(opts.ScanOptions)

	xxePayloads := payloads.GetXXEPayloads(opts.PayloadType)

	for _, payload := range xxePayloads {
		// Replace callback placeholder if provided
		testPayload := payload
		if opts.OOBCallback != "" {
			testPayload = strings.ReplaceAll(payload, "CALLBACK", opts.OOBCallback)
		} else {
			// Skip OOB payloads if no callback provided
			if strings.Contains(payload, "CALLBACK") {
				continue
			}
		}

		req, err := http.NewRequest("POST", opts.URL, strings.NewReader(testPayload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/xml")
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

		// Check for file disclosure indicators
		for _, indicator := range payloads.XXESuccessIndicators {
			if strings.Contains(bodyStr, indicator.Pattern) {
				severity := SeverityCritical
				if strings.Contains(indicator.Description, "base64") {
					severity = SeverityHigh
				}
				resultChan <- VulnResult{
					Type:        VulnXXE,
					Severity:    severity,
					URL:         opts.URL,
					Parameter:   "XML body",
					Payload:     truncate(testPayload, 100),
					Evidence:    fmt.Sprintf("Pattern found: %s", indicator.Pattern),
					Description: indicator.Description,
					Remediation: "Disable external entity processing. Use defused XML parsers. Set DTD processing to prohibited.",
				}
				break
			}
		}

		// Check for error-based XXE indicators
		for _, errInd := range payloads.XXEErrorIndicators {
			if strings.Contains(bodyStr, errInd) {
				resultChan <- VulnResult{
					Type:        VulnXXE,
					Severity:    SeverityMedium,
					URL:         opts.URL,
					Parameter:   "XML body",
					Payload:     truncate(testPayload, 100),
					Evidence:    fmt.Sprintf("XML error: %s", errInd),
					Description: "XML parsing error exposed. The server processes XML and may be vulnerable to XXE.",
					Remediation: "Disable external entity processing. Configure XML parser securely.",
				}
				break
			}
		}
	}
}
