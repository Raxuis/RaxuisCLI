package cloud

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func captureCloudStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	stdoutW = w
	fn()
	w.Close()
	os.Stdout = orig
	stdoutW = orig
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// withOverride swaps a package var for the duration of the test and restores it after.
func withOverride[T any](t *testing.T, target *T, value T) {
	t.Helper()
	orig := *target
	*target = value
	t.Cleanup(func() { *target = orig })
}

func TestCheckS3BucketPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	withOverride(t, &s3RegionURL, func(name, region string) string { return srv.URL })
	withOverride(t, &s3VirtualHostedURL, func(name string) string { return srv.URL })

	result := CheckS3Bucket("mybucket", 5)
	if !result.Exists || !result.Public || !result.ListAllowed {
		t.Errorf("CheckS3Bucket on a 200 response = %+v, want Exists/Public/ListAllowed all true", result)
	}
}

func TestCheckS3BucketPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	withOverride(t, &s3RegionURL, func(name, region string) string { return srv.URL })

	result := CheckS3Bucket("mybucket", 5)
	if !result.Exists || result.Public {
		t.Errorf("CheckS3Bucket on a 403 response = %+v, want Exists=true Public=false", result)
	}
}

func TestCheckS3BucketNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	withOverride(t, &s3RegionURL, func(name, region string) string { return srv.URL })
	withOverride(t, &s3VirtualHostedURL, func(name string) string { return srv.URL })

	result := CheckS3Bucket("mybucket", 5)
	if result.Exists {
		t.Errorf("CheckS3Bucket on all-404 responses should report Exists=false, got %+v", result)
	}
}

func TestCheckAzureBlobPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	withOverride(t, &azureBlobURL, func(account, container string) string { return srv.URL })

	result := CheckAzureBlob("myaccount", "mycontainer", 5)
	if !result.Exists || !result.Public {
		t.Errorf("CheckAzureBlob on a 200 response = %+v, want Exists/Public true", result)
	}
}

func TestCheckAzureBlobPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	withOverride(t, &azureBlobURL, func(account, container string) string { return srv.URL })

	result := CheckAzureBlob("myaccount", "mycontainer", 5)
	if !result.Exists || result.Public {
		t.Errorf("CheckAzureBlob on a 403 response = %+v, want Exists=true Public=false", result)
	}
}

func TestCheckAzureBlobNotFoundChecksAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	withOverride(t, &azureBlobURL, func(account, container string) string { return srv.URL })
	withOverride(t, &azureAccountURL, func(account string) string { return srv.URL })

	result := CheckAzureBlob("myaccount", "mycontainer", 5)
	if result.Exists {
		t.Errorf("CheckAzureBlob(404) with account URL also 404 should report Exists=false, got %+v", result)
	}
}

func TestCheckAzureBlobConnectionError(t *testing.T) {
	withOverride(t, &azureBlobURL, func(account, container string) string { return "http://127.0.0.1:1" })

	result := CheckAzureBlob("myaccount", "mycontainer", 1)
	if result.Error == nil {
		t.Error("CheckAzureBlob against an unreachable host should set Error")
	}
}

func TestCheckGCPBucketPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	withOverride(t, &gcpBucketURL, func(name string) string { return srv.URL })

	result := CheckGCPBucket("mybucket", 5)
	if !result.Exists || !result.Public {
		t.Errorf("CheckGCPBucket on a 200 response = %+v, want Exists/Public true", result)
	}
}

func TestCheckGCPBucketConnectionError(t *testing.T) {
	withOverride(t, &gcpBucketURL, func(name string) string { return "http://127.0.0.1:1" })

	result := CheckGCPBucket("mybucket", 1)
	if result.Error == nil {
		t.Error("CheckGCPBucket against an unreachable host should set Error")
	}
}

func TestEnumerateS3FindsMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // Exists=true, Public=false
	}))
	defer srv.Close()

	withOverride(t, &s3RegionURL, func(name, region string) string { return srv.URL })

	results := EnumerateS3("acme", []string{"", "-dev"}, 5)
	if len(results) != 2 {
		t.Fatalf("EnumerateS3 = %d results, want 2 (one per mutation)", len(results))
	}
	if results[0].Name != "acme" || results[1].Name != "acme-dev" {
		t.Errorf("EnumerateS3 names = %q, %q, want acme, acme-dev", results[0].Name, results[1].Name)
	}
}

func TestEnumerateS3DefaultMutations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	withOverride(t, &s3RegionURL, func(name, region string) string { return srv.URL })
	withOverride(t, &s3VirtualHostedURL, func(name string) string { return srv.URL })

	// nil mutations should fall back to CommonMutations without panicking.
	results := EnumerateS3("acme", nil, 5)
	if len(results) != 0 {
		t.Errorf("EnumerateS3 with all-404 responses should find nothing, got %d", len(results))
	}
}

func TestEnumerateAzureAccountLengthConstraints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	withOverride(t, &azureBlobURL, func(account, container string) string { return srv.URL })

	// "ab" (2 chars) is below Azure's 3-char minimum and should be skipped
	// entirely (no request made, no results for that mutation).
	results := EnumerateAzure("ab", []string{""}, 5)
	if len(results) != 0 {
		t.Errorf("EnumerateAzure with a too-short account name should produce no results, got %d", len(results))
	}
}

func TestEnumerateGCPFindsMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withOverride(t, &gcpBucketURL, func(name string) string { return srv.URL })

	results := EnumerateGCP("acme", []string{""}, 5)
	if len(results) != 1 || !results[0].Public {
		t.Errorf("EnumerateGCP = %+v, want one public result", results)
	}
}

func TestCheckAWSMetadataAccessible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/meta-data/":
			w.Write([]byte("ami-id\nhostname\n"))
		case "/latest/dynamic/instance-identity/document":
			w.Write([]byte(`{"region":"us-east-1"}`))
		case "/latest/meta-data/iam/security-credentials/":
			w.Write([]byte("my-role\n"))
		}
	}))
	defer srv.Close()

	withOverride(t, &awsMetadataBaseURL, srv.URL)

	result, err := CheckAWSMetadata(5)
	if err != nil {
		t.Fatalf("CheckAWSMetadata returned error: %v", err)
	}
	if result["accessible"] != true {
		t.Error("expected accessible=true")
	}
	if result["version"] != "IMDSv1" {
		t.Errorf("version = %v, want IMDSv1", result["version"])
	}
	if _, ok := result["identity"]; !ok {
		t.Error("expected identity to be populated from the instance-identity document")
	}
	if _, ok := result["iam_roles"]; !ok {
		t.Error("expected iam_roles to be populated")
	}
}

func TestCheckAWSMetadataInaccessible(t *testing.T) {
	withOverride(t, &awsMetadataBaseURL, "http://127.0.0.1:1")

	_, err := CheckAWSMetadata(1)
	if err == nil {
		t.Error("CheckAWSMetadata against an unreachable host should return an error")
	}
}

func TestCheckGCPMetadataAccessible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/computeMetadata/v1/project/project-id":
			w.Write([]byte("my-project"))
		case "/computeMetadata/v1/instance/service-accounts/":
			w.Write([]byte("default/\n"))
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	withOverride(t, &gcpMetadataBaseURL, srv.URL)

	result, err := CheckGCPMetadata(5)
	if err != nil {
		t.Fatalf("CheckGCPMetadata returned error: %v", err)
	}
	if result["accessible"] != true {
		t.Error("expected accessible=true")
	}
	if result["project_id"] != "my-project" {
		t.Errorf("project_id = %v, want my-project", result["project_id"])
	}
}

func TestCheckGCPMetadataInaccessible(t *testing.T) {
	withOverride(t, &gcpMetadataBaseURL, "http://127.0.0.1:1")

	_, err := CheckGCPMetadata(1)
	if err == nil {
		t.Error("CheckGCPMetadata against an unreachable host should return an error")
	}
}

func TestCheckAzureMetadataAccessibleJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"compute":{"vmId":"abc123"}}`))
	}))
	defer srv.Close()

	withOverride(t, &azureMetadataBaseURL, srv.URL)

	result, err := CheckAzureMetadata(5)
	if err != nil {
		t.Fatalf("CheckAzureMetadata returned error: %v", err)
	}
	if result["accessible"] != true {
		t.Error("expected accessible=true")
	}
	compute, ok := result["compute"].(map[string]interface{})
	if !ok || compute["vmId"] != "abc123" {
		t.Errorf("expected parsed compute.vmId=abc123, got %v", result["compute"])
	}
}

func TestCheckAzureMetadataNonJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	withOverride(t, &azureMetadataBaseURL, srv.URL)

	result, err := CheckAzureMetadata(5)
	if err != nil {
		t.Fatalf("CheckAzureMetadata returned error: %v", err)
	}
	if result["accessible"] != true || result["raw"] != "not json" {
		t.Errorf("expected fallback raw body result, got %v", result)
	}
}

func TestCheckAzureMetadataInaccessible(t *testing.T) {
	withOverride(t, &azureMetadataBaseURL, "http://127.0.0.1:1")

	_, err := CheckAzureMetadata(1)
	if err == nil {
		t.Error("CheckAzureMetadata against an unreachable host should return an error")
	}
}

func TestDisplayS3Results(t *testing.T) {
	out := captureCloudStdout(t, func() {
		DisplayS3Results([]S3BucketResult{{Name: "acme-backup", Public: true, ListAllowed: true, Region: "us-east-1"}})
	})
	for _, want := range []string{"acme-backup", "LISTABLE", "us-east-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayS3Results output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDisplayS3ResultsEmpty(t *testing.T) {
	out := captureCloudStdout(t, func() { DisplayS3Results(nil) })
	if !strings.Contains(out, "No buckets found") {
		t.Errorf("DisplayS3Results(nil) should report no buckets, got %q", out)
	}
}

func TestDisplayAzureResults(t *testing.T) {
	out := captureCloudStdout(t, func() {
		DisplayAzureResults([]AzureBlobResult{{Account: "acme", Container: "data", Public: true}})
	})
	if !strings.Contains(out, "acme/data") {
		t.Errorf("DisplayAzureResults output missing account/container; got:\n%s", out)
	}
}

func TestDisplayGCPResults(t *testing.T) {
	out := captureCloudStdout(t, func() {
		DisplayGCPResults([]GCPBucketResult{{Name: "acme-bucket"}})
	})
	if !strings.Contains(out, "acme-bucket") || !strings.Contains(out, "PRIVATE") {
		t.Errorf("DisplayGCPResults output wrong; got:\n%s", out)
	}
}

func TestDisplayMetadataAccessible(t *testing.T) {
	out := captureCloudStdout(t, func() {
		DisplayMetadata("aws", map[string]interface{}{"accessible": true, "version": "IMDSv1"})
	})
	if !strings.Contains(out, "ACCESSIBLE") || !strings.Contains(out, "IMDSv1") {
		t.Errorf("DisplayMetadata output wrong; got:\n%s", out)
	}
}

func TestDisplayMetadataInaccessible(t *testing.T) {
	out := captureCloudStdout(t, func() {
		DisplayMetadata("gcp", map[string]interface{}{})
	})
	if !strings.Contains(out, "not accessible") {
		t.Errorf("DisplayMetadata with no accessible key should report not accessible; got:\n%s", out)
	}
}

func TestCommonMutationsNotEmpty(t *testing.T) {
	if len(CommonMutations) == 0 {
		t.Error("CommonMutations should not be empty")
	}
}
