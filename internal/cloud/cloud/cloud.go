package cloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudProvider represents a cloud provider
type CloudProvider string

const (
	AWS   CloudProvider = "aws"
	Azure CloudProvider = "azure"
	GCP   CloudProvider = "gcp"
)

// S3BucketResult holds S3 bucket enumeration result
type S3BucketResult struct {
	Name        string
	Exists      bool
	Public      bool
	ListAllowed bool
	Region      string
	Error       error
}

// AzureBlobResult holds Azure blob enumeration result
type AzureBlobResult struct {
	Account     string
	Container   string
	Exists      bool
	Public      bool
	ListAllowed bool
	Error       error
}

// GCPBucketResult holds GCP bucket enumeration result
type GCPBucketResult struct {
	Name        string
	Exists      bool
	Public      bool
	ListAllowed bool
	Error       error
}

// EnumOptions holds enumeration options
type EnumOptions struct {
	Provider CloudProvider
	Target   string
	Wordlist []string
	Timeout  int
	Threads  int
}

// URL builders and metadata service base URLs, factored out as overridable
// vars so tests can point them at a local httptest server instead of real
// cloud provider hosts. They default to today's real endpoints and are not
// otherwise configurable from the CLI.
var (
	s3RegionURL        = func(name, region string) string { return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", name, region) }
	s3VirtualHostedURL = func(name string) string { return fmt.Sprintf("https://%s.s3.amazonaws.com/", name) }
	azureBlobURL       = func(account, container string) string {
		return fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", account, container)
	}
	azureAccountURL = func(account string) string { return fmt.Sprintf("https://%s.blob.core.windows.net/", account) }
	gcpBucketURL    = func(name string) string { return fmt.Sprintf("https://storage.googleapis.com/%s/", name) }

	awsMetadataBaseURL   = "http://169.254.169.254"
	gcpMetadataBaseURL   = "http://169.254.169.254"
	azureMetadataBaseURL = "http://169.254.169.254"
)

// Common bucket/storage name mutations
var CommonMutations = []string{
	"",
	"-dev",
	"-prod",
	"-staging",
	"-test",
	"-backup",
	"-backups",
	"-data",
	"-files",
	"-assets",
	"-static",
	"-media",
	"-uploads",
	"-public",
	"-private",
	"-internal",
	"-logs",
	"-archive",
	"-db",
	"-database",
	"-sql",
	"-config",
	"-configs",
	"-secrets",
	"-keys",
	"-api",
	"-web",
	"-app",
	"-mobile",
	"-cdn",
}

// CheckS3Bucket checks if an S3 bucket exists and is accessible
func CheckS3Bucket(name string, timeout int) S3BucketResult {
	result := S3BucketResult{Name: name}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try different region endpoints
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}

	for _, region := range regions {
		url := s3RegionURL(name, region)

		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case 200:
			result.Exists = true
			result.Public = true
			result.ListAllowed = true
			result.Region = region
			return result
		case 403:
			result.Exists = true
			result.Region = region
			return result
		case 301:
			// Redirect to correct region
			if loc := resp.Header.Get("Location"); loc != "" {
				result.Exists = true
				// Extract region from redirect
				if strings.Contains(loc, "s3.") {
					parts := strings.Split(loc, "s3.")
					if len(parts) > 1 {
						regionPart := strings.Split(parts[1], ".")[0]
						result.Region = regionPart
					}
				}
			}
		case 404:
			continue
		}
	}

	// Try virtual hosted style
	url := s3VirtualHostedURL(name)
	resp, err := client.Get(url)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			result.Exists = true
			if resp.StatusCode == 200 {
				result.Public = true
				result.ListAllowed = true
			}
		}
	}

	return result
}

// CheckAzureBlob checks Azure blob storage
func CheckAzureBlob(account, container string, timeout int) AzureBlobResult {
	result := AzureBlobResult{
		Account:   account,
		Container: container,
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Check blob storage
	url := azureBlobURL(account, container)

	resp, err := client.Get(url)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		result.Exists = true
		result.Public = true
		result.ListAllowed = true
	case 403:
		result.Exists = true
	case 404:
		// Container doesn't exist, but account might
		// Check if account exists
		accountURL := azureAccountURL(account)
		if accResp, err := client.Get(accountURL); err == nil {
			accResp.Body.Close()
			if accResp.StatusCode != 404 {
				// Account exists
				result.Exists = false
			}
		}
	}

	return result
}

// CheckGCPBucket checks GCP storage bucket
func CheckGCPBucket(name string, timeout int) GCPBucketResult {
	result := GCPBucketResult{Name: name}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	url := gcpBucketURL(name)

	resp, err := client.Get(url)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		result.Exists = true
		result.Public = true
		result.ListAllowed = true
	case 403:
		result.Exists = true
	}

	return result
}

// EnumerateS3 enumerates S3 buckets for a company
func EnumerateS3(company string, mutations []string, timeout int) []S3BucketResult {
	var results []S3BucketResult

	if mutations == nil {
		mutations = CommonMutations
	}

	for _, mutation := range mutations {
		name := strings.ToLower(company + mutation)
		name = strings.ReplaceAll(name, " ", "-")

		result := CheckS3Bucket(name, timeout)
		if result.Exists {
			results = append(results, result)
		}
	}

	return results
}

// EnumerateAzure enumerates Azure storage accounts
func EnumerateAzure(company string, mutations []string, timeout int) []AzureBlobResult {
	var results []AzureBlobResult

	if mutations == nil {
		mutations = CommonMutations
	}

	containers := []string{"$root", "data", "files", "backup", "logs", "public", "private"}

	for _, mutation := range mutations {
		account := strings.ToLower(company + mutation)
		account = strings.ReplaceAll(account, "-", "")
		account = strings.ReplaceAll(account, " ", "")

		// Azure storage account names are 3-24 chars, alphanumeric only
		if len(account) > 24 {
			account = account[:24]
		}
		if len(account) < 3 {
			continue
		}

		for _, container := range containers {
			result := CheckAzureBlob(account, container, timeout)
			if result.Exists {
				results = append(results, result)
			}
		}
	}

	return results
}

// EnumerateGCP enumerates GCP buckets
func EnumerateGCP(company string, mutations []string, timeout int) []GCPBucketResult {
	var results []GCPBucketResult

	if mutations == nil {
		mutations = CommonMutations
	}

	for _, mutation := range mutations {
		name := strings.ToLower(company + mutation)
		name = strings.ReplaceAll(name, " ", "-")

		result := CheckGCPBucket(name, timeout)
		if result.Exists {
			results = append(results, result)
		}
	}

	return results
}

// CheckAWSMetadata checks for AWS metadata service access
func CheckAWSMetadata(timeout int) (map[string]interface{}, error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// IMDSv1
	url := awsMetadataBaseURL + "/latest/meta-data/"

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("metadata service not accessible: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	result := map[string]interface{}{
		"accessible": true,
		"version":    "IMDSv1",
		"endpoints":  strings.Split(string(body), "\n"),
	}

	// Try to get instance identity
	idURL := awsMetadataBaseURL + "/latest/dynamic/instance-identity/document"
	if idResp, err := client.Get(idURL); err == nil {
		defer idResp.Body.Close()
		if idBody, err := io.ReadAll(idResp.Body); err == nil {
			var identity map[string]interface{}
			if json.Unmarshal(idBody, &identity) == nil {
				result["identity"] = identity
			}
		}
	}

	// Try to get credentials
	credsURL := awsMetadataBaseURL + "/latest/meta-data/iam/security-credentials/"
	if credsResp, err := client.Get(credsURL); err == nil {
		defer credsResp.Body.Close()
		if credsBody, err := io.ReadAll(credsResp.Body); err == nil {
			roles := strings.Split(string(credsBody), "\n")
			result["iam_roles"] = roles
		}
	}

	return result, nil
}

// CheckGCPMetadata checks for GCP metadata service access
func CheckGCPMetadata(timeout int) (map[string]interface{}, error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, _ := http.NewRequest("GET", gcpMetadataBaseURL+"/computeMetadata/v1/", nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metadata service not accessible: %v", err)
	}
	defer resp.Body.Close()

	result := map[string]interface{}{
		"accessible": true,
	}

	// Get project info
	projReq, _ := http.NewRequest("GET", gcpMetadataBaseURL+"/computeMetadata/v1/project/project-id", nil)
	projReq.Header.Set("Metadata-Flavor", "Google")
	if projResp, err := client.Do(projReq); err == nil {
		defer projResp.Body.Close()
		if projBody, err := io.ReadAll(projResp.Body); err == nil {
			result["project_id"] = string(projBody)
		}
	}

	// Get service account
	saReq, _ := http.NewRequest("GET", gcpMetadataBaseURL+"/computeMetadata/v1/instance/service-accounts/", nil)
	saReq.Header.Set("Metadata-Flavor", "Google")
	if saResp, err := client.Do(saReq); err == nil {
		defer saResp.Body.Close()
		if saBody, err := io.ReadAll(saResp.Body); err == nil {
			result["service_accounts"] = strings.Split(string(saBody), "\n")
		}
	}

	return result, nil
}

// CheckAzureMetadata checks for Azure metadata service access
func CheckAzureMetadata(timeout int) (map[string]interface{}, error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	req, _ := http.NewRequest("GET", azureMetadataBaseURL+"/metadata/instance?api-version=2021-02-01", nil)
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metadata service not accessible: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return map[string]interface{}{"accessible": true, "raw": string(body)}, nil
	}

	result["accessible"] = true
	return result, nil
}

// DisplayS3Results displays S3 enumeration results
func DisplayS3Results(results []S3BucketResult) {
	fmt.Fprintln(stdoutW, "\n[AWS S3] Bucket Enumeration Results")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(results) == 0 {
		fmt.Fprintln(stdoutW, "No buckets found")
		return
	}

	for _, r := range results {
		status := "PRIVATE"
		if r.Public {
			status = "PUBLIC"
		}
		if r.ListAllowed {
			status = "PUBLIC (LISTABLE)"
		}

		fmt.Fprintf(stdoutW, "  %-40s [%s] Region: %s\n", r.Name, status, r.Region)
	}

	fmt.Fprintf(stdoutW, "\nTotal: %d buckets found\n", len(results))
}

// DisplayAzureResults displays Azure enumeration results
func DisplayAzureResults(results []AzureBlobResult) {
	fmt.Fprintln(stdoutW, "\n[Azure Blob] Storage Enumeration Results")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(results) == 0 {
		fmt.Fprintln(stdoutW, "No storage containers found")
		return
	}

	for _, r := range results {
		status := "PRIVATE"
		if r.Public {
			status = "PUBLIC"
		}
		if r.ListAllowed {
			status = "PUBLIC (LISTABLE)"
		}

		fmt.Fprintf(stdoutW, "  %s/%s [%s]\n", r.Account, r.Container, status)
	}

	fmt.Fprintf(stdoutW, "\nTotal: %d containers found\n", len(results))
}

// DisplayGCPResults displays GCP enumeration results
func DisplayGCPResults(results []GCPBucketResult) {
	fmt.Fprintln(stdoutW, "\n[GCP Storage] Bucket Enumeration Results")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(results) == 0 {
		fmt.Fprintln(stdoutW, "No buckets found")
		return
	}

	for _, r := range results {
		status := "PRIVATE"
		if r.Public {
			status = "PUBLIC"
		}
		if r.ListAllowed {
			status = "PUBLIC (LISTABLE)"
		}

		fmt.Fprintf(stdoutW, "  %-40s [%s]\n", r.Name, status)
	}

	fmt.Fprintf(stdoutW, "\nTotal: %d buckets found\n", len(results))
}

// DisplayMetadata displays cloud metadata results
func DisplayMetadata(provider string, metadata map[string]interface{}) {
	fmt.Fprintf(stdoutW, "\n[%s] Cloud Metadata\n", strings.ToUpper(provider))
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if accessible, ok := metadata["accessible"].(bool); ok && accessible {
		fmt.Fprintln(stdoutW, "[!] METADATA SERVICE ACCESSIBLE")
		fmt.Fprintln(stdoutW)

		for key, value := range metadata {
			if key == "accessible" {
				continue
			}
			fmt.Fprintf(stdoutW, "  %s: %v\n", key, value)
		}
	} else {
		fmt.Fprintln(stdoutW, "Metadata service not accessible")
	}

	fmt.Fprintln(stdoutW)
}
