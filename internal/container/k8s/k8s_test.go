package k8s

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureK8sStdout(t *testing.T, fn func()) string {
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

func withK8sRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := rootPrefix
	rootPrefix = dir
	t.Cleanup(func() { rootPrefix = orig })
	return dir
}

func writeSAFile(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, "var/run/secrets/kubernetes.io/serviceaccount")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
}

func TestDetectK8sInCluster(t *testing.T) {
	root := withK8sRoot(t)
	writeSAFile(t, root, "token", "eyJhbGciOiJSUzI1NiJ9.fake.token")
	writeSAFile(t, root, "namespace", "default")
	writeSAFile(t, root, "ca.crt", "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")

	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")

	info := DetectK8s()
	if !info.InCluster {
		t.Error("DetectK8s should report InCluster=true when the token file exists")
	}
	if info.Namespace != "default" {
		t.Errorf("Namespace = %q, want default", info.Namespace)
	}
	if info.CACert == "" {
		t.Error("CACert should be populated when ca.crt exists")
	}
	if info.APIServer != "https://10.0.0.1:6443" {
		t.Errorf("APIServer = %q, want https://10.0.0.1:6443", info.APIServer)
	}
}

func TestDetectK8sDefaultPort(t *testing.T) {
	withK8sRoot(t)
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	info := DetectK8s()
	if info.APIServer != "https://10.0.0.1:443" {
		t.Errorf("APIServer = %q, want default port 443", info.APIServer)
	}
}

func TestDetectK8sNotInCluster(t *testing.T) {
	withK8sRoot(t)
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	info := DetectK8s()
	if info.InCluster {
		t.Error("DetectK8s in an empty sandbox should report InCluster=false")
	}
	if info.APIServer != "" {
		t.Errorf("APIServer = %q, want empty with no KUBERNETES_SERVICE_HOST", info.APIServer)
	}
}

func TestCheckAPIAccessNotInCluster(t *testing.T) {
	rbac := CheckAPIAccess(&K8sInfo{InCluster: false})
	if len(rbac) != 0 {
		t.Errorf("CheckAPIAccess with InCluster=false should return nothing, got %v", rbac)
	}
}

func TestCheckAPIAccessAllowedEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if strings.Contains(r.URL.Path, "secrets") || strings.Contains(r.URL.Path, "pods") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	info := &K8sInfo{InCluster: true, Token: "test-token", APIServer: srv.URL, Namespace: "default"}
	rbac := CheckAPIAccess(info)

	found := map[string]bool{}
	for _, r := range rbac {
		found[r.Resources[0]] = true
	}
	if !found["secrets"] || !found["pods"] {
		t.Errorf("CheckAPIAccess should report access to secrets and pods, got %+v", rbac)
	}
	if found["nodes"] {
		t.Error("CheckAPIAccess should not report access to nodes (403 in this test)")
	}
}

func TestListSecretsNotInCluster(t *testing.T) {
	_, err := ListSecrets(&K8sInfo{InCluster: false}, "default")
	if err == nil {
		t.Error("ListSecrets with InCluster=false should return an error")
	}
}

func TestListSecretsSuccess(t *testing.T) {
	body := `{"items":[{"metadata":{"name":"db-creds","namespace":"default"},"type":"Opaque","data":{"password":"xxx","username":"yyy"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	info := &K8sInfo{InCluster: true, Token: "test-token", APIServer: srv.URL, Namespace: "default"}
	secrets, err := ListSecrets(info, "")
	if err != nil {
		t.Fatalf("ListSecrets returned error: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Name != "db-creds" {
		t.Fatalf("ListSecrets = %+v, want a single db-creds secret", secrets)
	}
	if len(secrets[0].Keys) != 2 {
		t.Errorf("secret Keys = %v, want 2 entries", secrets[0].Keys)
	}
}

func TestListSecretsAccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	info := &K8sInfo{InCluster: true, Token: "test-token", APIServer: srv.URL, Namespace: "default"}
	_, err := ListSecrets(info, "")
	if err == nil {
		t.Error("ListSecrets on a 403 response should return an error")
	}
}

func TestListSecretsInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	info := &K8sInfo{InCluster: true, Token: "test-token", APIServer: srv.URL, Namespace: "default"}
	_, err := ListSecrets(info, "")
	if err == nil {
		t.Error("ListSecrets with an invalid JSON body should return an error")
	}
}

func TestCheckPrivilegeEscalationAnonymousAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	info := &K8sInfo{InCluster: true, Token: "", APIServer: srv.URL}
	vulns := CheckPrivilegeEscalation(info)

	found := false
	for _, v := range vulns {
		if v.Name == "Anonymous Authentication" {
			found = true
		}
	}
	if !found {
		t.Errorf("CheckPrivilegeEscalation should flag anonymous auth when /api/v1 returns 200, got %+v", vulns)
	}
}

func TestCheckPrivilegeEscalationSecretAndPodAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	info := &K8sInfo{InCluster: true, Token: "test-token", APIServer: srv.URL, Namespace: "default"}
	vulns := CheckPrivilegeEscalation(info)

	names := map[string]bool{}
	for _, v := range vulns {
		names[v.Name] = true
	}
	if !names["Secret Access"] || !names["Pod Listing"] || !names["Node Access"] {
		t.Errorf("CheckPrivilegeEscalation = %+v, want Secret Access, Pod Listing and Node Access flagged", vulns)
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"secrets (namespace)"}, "secrets") {
		t.Error("contains should match a substring")
	}
	if contains([]string{"pods"}, "nodes") {
		t.Error("contains should not match an absent substring")
	}
}

func TestGenerateKubectlCommands(t *testing.T) {
	cmds := GenerateKubectlCommands(&K8sInfo{Namespace: "default"})
	if len(cmds) == 0 {
		t.Fatal("GenerateKubectlCommands should return a non-empty list")
	}
	found := false
	for _, c := range cmds {
		if strings.Contains(c, "kubectl get secrets -n default") {
			found = true
		}
	}
	if !found {
		t.Error("GenerateKubectlCommands should include the namespace-scoped secrets command")
	}
}

func TestDisplayK8sInfoNotInCluster(t *testing.T) {
	out := captureK8sStdout(t, func() { DisplayK8sInfo(&K8sInfo{InCluster: false}) })
	if !strings.Contains(out, "Not running inside Kubernetes") {
		t.Errorf("DisplayK8sInfo(not in cluster) output wrong; got:\n%s", out)
	}
}

func TestDisplayK8sInfoInCluster(t *testing.T) {
	info := &K8sInfo{
		InCluster: true,
		Namespace: "default",
		APIServer: "https://10.0.0.1:443",
		Token:     "eyJhbGciOiJSUzI1NiJ9fakefakefakefaketoken",
	}
	out := captureK8sStdout(t, func() { DisplayK8sInfo(info) })
	for _, want := range []string{"Kubernetes cluster", "default", "10.0.0.1", "..."} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayK8sInfo output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDisplaySecretsEmpty(t *testing.T) {
	out := captureK8sStdout(t, func() { DisplaySecrets(nil) })
	if !strings.Contains(out, "No accessible secrets found") {
		t.Errorf("DisplaySecrets(nil) output wrong; got:\n%s", out)
	}
}

func TestDisplaySecretsWithData(t *testing.T) {
	secrets := []SecretEntry{{Name: "db-creds", Namespace: "default", Type: "Opaque", Keys: []string{"password", "username"}}}
	out := captureK8sStdout(t, func() { DisplaySecrets(secrets) })
	if !strings.Contains(out, "db-creds") || !strings.Contains(out, "password") {
		t.Errorf("DisplaySecrets output wrong; got:\n%s", out)
	}
}

func TestDisplayVulnerabilitiesEmpty(t *testing.T) {
	out := captureK8sStdout(t, func() { DisplayVulnerabilities(nil) })
	if !strings.Contains(out, "No vulnerabilities found") {
		t.Errorf("DisplayVulnerabilities(nil) output wrong; got:\n%s", out)
	}
}

func TestDisplayVulnerabilitiesWithFindings(t *testing.T) {
	vulns := []K8sVulnerability{{Name: "Anonymous Authentication", Description: "desc", Severity: "HIGH", Exploitable: true, Details: "details"}}
	out := captureK8sStdout(t, func() { DisplayVulnerabilities(vulns) })
	if !strings.Contains(out, "HIGH") || !strings.Contains(out, "Anonymous Authentication") {
		t.Errorf("DisplayVulnerabilities output wrong; got:\n%s", out)
	}
}

func TestDisplayRBACEmpty(t *testing.T) {
	out := captureK8sStdout(t, func() { DisplayRBAC(nil) })
	if !strings.Contains(out, "No accessible resources found") {
		t.Errorf("DisplayRBAC(nil) output wrong; got:\n%s", out)
	}
}

func TestDisplayRBACWithData(t *testing.T) {
	rbac := []RBACInfo{{Resources: []string{"pods"}, Verbs: []string{"get", "list"}, Allowed: true}}
	out := captureK8sStdout(t, func() { DisplayRBAC(rbac) })
	if !strings.Contains(out, "pods") {
		t.Errorf("DisplayRBAC output wrong; got:\n%s", out)
	}
}
