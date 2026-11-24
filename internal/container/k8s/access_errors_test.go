package k8s

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIAccessErrorsAreNotDeniedPermissions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		wantErr     bool
		wantAllowed int
	}{
		{"allowed", http.StatusOK, `{"kind":"List","items":[]}`, false, 9},
		{"forbidden is a completed RBAC check", http.StatusForbidden, `{"kind":"Status","reason":"Forbidden"}`, false, 0},
		{"unauthorized token", http.StatusUnauthorized, `{"kind":"Status","reason":"Unauthorized"}`, true, 0},
		{"unavailable API", http.StatusServiceUnavailable, `unavailable`, true, 0},
		{"malformed JSON", http.StatusOK, `{`, true, 0},
		{"unrelated JSON", http.StatusOK, `{"login":true}`, true, 0},
		{"redirect is not permission", http.StatusFound, ``, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Errorf("missing bearer token")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			results, err := CheckAPIAccessWithError(&K8sInfo{InCluster: true, Token: "test-token", APIServer: srv.URL, Namespace: "default"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, wantErr=%v", err, tc.wantErr)
			}
			if len(results) != tc.wantAllowed {
				t.Fatalf("allowed=%d, want=%d", len(results), tc.wantAllowed)
			}
		})
	}
}

func TestAPIAccessRefusedAndMalformedAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := "http://" + listener.Addr().String()
	listener.Close()
	for _, url := range []string{address, "://broken"} {
		results, err := CheckAPIAccessWithError(&K8sInfo{InCluster: true, Token: "test-token", APIServer: url, Namespace: "default"})
		if err == nil || len(results) != 0 {
			t.Fatalf("url=%q results=%v err=%v", url, results, err)
		}
	}
}

func TestAPIAccessPreservesPartialResultsAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pods") {
			_, _ = w.Write([]byte(`{"kind":"PodList","items":[]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	results, err := CheckAPIAccessWithError(&K8sInfo{InCluster: true, Token: "test-token", APIServer: srv.URL, Namespace: "default"})
	if err == nil || len(results) != 2 {
		t.Fatalf("partial results=%v err=%v", results, err)
	}
}

func TestAPIClientsUseClusterCAForEveryProbe(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"kind":"List","items":[]}`))
	}))
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "cluster-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	info := &K8sInfo{InCluster: true, Token: "test-token\n", Namespace: "default", APIServer: srv.URL, CACert: caPath}
	if _, err := CheckAPIAccessWithError(info); err != nil {
		t.Fatalf("RBAC trusted CA: %v", err)
	}
	if _, err := ListSecrets(info, ""); err != nil {
		t.Fatalf("secrets trusted CA: %v", err)
	}
	if _, err := CheckPrivilegeEscalationWithError(info); err != nil {
		t.Fatalf("privilege probes trusted CA: %v", err)
	}
	info.CACert = ""
	if _, err := CheckAPIAccessWithError(info); err == nil {
		t.Fatal("untrusted RBAC certificate accepted")
	}
	if _, err := ListSecrets(info, ""); err == nil {
		t.Fatal("untrusted secrets certificate accepted")
	}
	if _, err := CheckPrivilegeEscalationWithError(info); err == nil {
		t.Fatal("untrusted privilege probe certificate accepted")
	}
}

func TestDetectK8sFormatsIPv6APIServer(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "2001:db8::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	if got := DetectK8s().APIServer; got != "https://[2001:db8::1]:6443" {
		t.Fatalf("API server=%q", got)
	}
}

func TestAnonymousProbeRequiresKubernetesDiscoveryResponse(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		status               int
		body                 string
		wantErr, wantFinding bool
	}{
		{"discovery", 200, `{"kind":"APIResourceList","groupVersion":"v1","resources":[]}`, false, true},
		{"HTML login page", 200, `<html>login</html>`, true, false},
		{"unavailable", 503, `unavailable`, true, false},
		{"denied", 403, ``, false, false},
		{"unauthenticated", 401, ``, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1" {
					if r.Header.Get("Authorization") != "" {
						t.Error("anonymous probe sent authorization")
					}
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
					return
				}
				w.WriteHeader(http.StatusForbidden)
			}))
			defer server.Close()
			findings, err := CheckPrivilegeEscalationWithError(&K8sInfo{InCluster: true, Token: "fixture", Namespace: "default", APIServer: server.URL})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
			found := false
			for _, f := range findings {
				if f.Name == "Anonymous Authentication" {
					found = true
				}
			}
			if found != tc.wantFinding {
				t.Fatalf("anonymous finding=%v want=%v", found, tc.wantFinding)
			}
		})
	}
}
