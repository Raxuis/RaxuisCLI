package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// K8sInfo holds Kubernetes cluster information
type K8sInfo struct {
	InCluster      bool
	ServiceAccount string
	Namespace      string
	Token          string
	APIServer      string
	CACert         string
}

// SecretEntry represents a Kubernetes secret
type SecretEntry struct {
	Name      string
	Namespace string
	Type      string
	Keys      []string
}

// PodInfo represents pod information
type PodInfo struct {
	Name       string
	Namespace  string
	Status     string
	IP         string
	Node       string
	Containers []string
}

// RBACInfo represents RBAC permissions
type RBACInfo struct {
	Verbs     []string
	Resources []string
	Allowed   bool
}

// K8sVulnerability represents a Kubernetes vulnerability
type K8sVulnerability struct {
	Name        string
	Description string
	Severity    string
	Exploitable bool
	Details     string
}

// rootPrefix lets tests sandbox the service-account file reads under a
// t.TempDir() instead of the real machine's filesystem. Empty (the
// default) preserves real behavior exactly - production code never sets
// this.
var rootPrefix string

// DetectK8s detects if running inside Kubernetes
func DetectK8s() *K8sInfo {
	info := &K8sInfo{}

	// Check for service account token
	tokenPath := rootPrefix + "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if data, err := os.ReadFile(tokenPath); err == nil {
		info.InCluster = true
		info.Token = string(data)
	}

	// Get namespace
	nsPath := rootPrefix + "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	if data, err := os.ReadFile(nsPath); err == nil {
		info.Namespace = string(data)
	}

	// Get CA cert path
	caPath := rootPrefix + "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	if _, err := os.Stat(caPath); err == nil {
		info.CACert = caPath
	}

	// Get API server from environment
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if port == "" {
			port = "443"
		}
		info.APIServer = "https://" + net.JoinHostPort(strings.Trim(host, "[]"), port)
	}

	return info
}

// newAPIClient keeps all Kubernetes probes on the same certificate trust policy.
func newAPIClient(info *K8sInfo, timeout time.Duration) (*http.Client, error) {
	if info == nil {
		return nil, fmt.Errorf("kubernetes cluster information is required")
	}
	apiURL, err := url.Parse(info.APIServer)
	if err != nil || apiURL.Host == "" || (apiURL.Scheme != "http" && apiURL.Scheme != "https") {
		return nil, fmt.Errorf("invalid Kubernetes API server address %q", info.APIServer)
	}
	transport := &http.Transport{}
	if info.CACert != "" {
		pem, err := os.ReadFile(info.CACert)
		if err != nil {
			return nil, fmt.Errorf("reading Kubernetes CA certificate: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("invalid Kubernetes CA certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, nil
}

func readAPIResponse(body io.Reader) ([]byte, error) {
	const maxResponseSize = 16 << 20
	data, err := io.ReadAll(io.LimitReader(body, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseSize {
		return nil, fmt.Errorf("kubernetes API response exceeds %d bytes", maxResponseSize)
	}
	return data, nil
}

// CheckAPIAccess preserves the original allowed-resource view. Call
// CheckAPIAccessWithError when execution failures must be distinguished from denial.
func CheckAPIAccess(info *K8sInfo) []RBACInfo {
	rbac, _ := CheckAPIAccessWithError(info)
	return rbac
}

// CheckAPIAccessWithError lists allowed resources and reports incomplete probes.
// HTTP 403 is an expected permission denial; authentication, transport and
// malformed API responses are operational errors, including partial failures.
func CheckAPIAccessWithError(info *K8sInfo) ([]RBACInfo, error) {
	var rbac []RBACInfo
	if info == nil || !info.InCluster || strings.TrimSpace(info.Token) == "" {
		return rbac, fmt.Errorf("not in cluster or no token")
	}
	client, err := newAPIClient(info, 5*time.Second)
	if err != nil {
		return rbac, err
	}
	defer client.CloseIdleConnections()
	endpoints := []struct{ path, resource string }{
		{"/api/v1/namespaces", "namespaces"}, {"/api/v1/pods", "pods"},
		{"/api/v1/secrets", "secrets"}, {"/api/v1/configmaps", "configmaps"},
		{"/api/v1/services", "services"}, {"/api/v1/nodes", "nodes"},
		{"/apis/rbac.authorization.k8s.io/v1/clusterroles", "clusterroles"},
		{"/api/v1/namespaces/" + url.PathEscape(strings.TrimSpace(info.Namespace)) + "/pods", "pods (namespace)"},
		{"/api/v1/namespaces/" + url.PathEscape(strings.TrimSpace(info.Namespace)) + "/secrets", "secrets (namespace)"},
	}
	var failures []error
	for _, ep := range endpoints {
		req, err := http.NewRequest(http.MethodGet, strings.TrimRight(info.APIServer, "/")+ep.path, nil)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", ep.resource, err))
			continue
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(info.Token))
		resp, err := client.Do(req)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", ep.resource, err))
			continue
		}
		if resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			failures = append(failures, fmt.Errorf("%s: Kubernetes API returned HTTP %d", ep.resource, resp.StatusCode))
			continue
		}
		// A login page or a proxy's successful response is not a Kubernetes list.
		body, readErr := readAPIResponse(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			failures = append(failures, fmt.Errorf("%s: reading API response: %w", ep.resource, readErr))
			continue
		}
		var list struct {
			Items []json.RawMessage `json:"items"`
		}
		decodeErr := json.Unmarshal(body, &list)
		if decodeErr != nil || list.Items == nil {
			failures = append(failures, fmt.Errorf("%s: malformed Kubernetes list response", ep.resource))
			continue
		}
		rbac = append(rbac, RBACInfo{Resources: []string{ep.resource}, Verbs: []string{"get", "list"}, Allowed: true})
	}
	return rbac, errors.Join(failures...)
}

// ListSecrets lists accessible secrets
func ListSecrets(info *K8sInfo, namespace string) ([]SecretEntry, error) {
	var secrets []SecretEntry

	if info == nil || !info.InCluster || strings.TrimSpace(info.Token) == "" {
		return secrets, fmt.Errorf("not in cluster or no token")
	}

	if namespace == "" {
		namespace = strings.TrimSpace(info.Namespace)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", info.APIServer, namespace)

	client, err := newAPIClient(info, 10*time.Second)
	if err != nil {
		return secrets, err
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return secrets, err
	}

	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(info.Token))

	resp, err := client.Do(req)
	if err != nil {
		return secrets, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return secrets, fmt.Errorf("access denied: %d", resp.StatusCode)
	}

	body, err := readAPIResponse(resp.Body)
	if err != nil {
		return secrets, err
	}

	var result struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Type string            `json:"type"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return secrets, err
	}

	for _, item := range result.Items {
		var keys []string
		for k := range item.Data {
			keys = append(keys, k)
		}

		secrets = append(secrets, SecretEntry{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Type:      item.Type,
			Keys:      keys,
		})
	}

	return secrets, nil
}

// CheckPrivilegeEscalation checks for privilege escalation paths
func CheckPrivilegeEscalation(info *K8sInfo) []K8sVulnerability {
	vulns, _ := CheckPrivilegeEscalationWithError(info)
	return vulns
}

// CheckPrivilegeEscalationWithError reports incomplete API checks along with findings.
func CheckPrivilegeEscalationWithError(info *K8sInfo) ([]K8sVulnerability, error) {
	var vulns []K8sVulnerability
	if info == nil {
		return vulns, fmt.Errorf("kubernetes cluster information is required")
	}
	var failures []error

	// Check for anonymous auth
	client, err := newAPIClient(info, 5*time.Second)
	if err != nil {
		return vulns, err
	}
	defer client.CloseIdleConnections()
	accessible, probeErr := anonymousAPIAccess(client, info.APIServer)
	if probeErr != nil {
		failures = append(failures, fmt.Errorf("checking anonymous API access: %w", probeErr))
	} else if accessible {
		vulns = append(vulns, K8sVulnerability{
			Name: "Anonymous Authentication", Description: "Kubernetes API allows anonymous access", Severity: "HIGH", Exploitable: true, Details: "Can access API without authentication",
		})
	}

	// Check for overly permissive service account
	rbac, accessErr := CheckAPIAccessWithError(info)
	if accessErr != nil {
		failures = append(failures, accessErr)
	}
	for _, r := range rbac {
		if contains(r.Resources, "secrets") && r.Allowed {
			vulns = append(vulns, K8sVulnerability{
				Name:        "Secret Access",
				Description: "Service account can read secrets",
				Severity:    "HIGH",
				Exploitable: true,
				Details:     "Can extract sensitive data from secrets",
			})
		}

		if contains(r.Resources, "pods") && r.Allowed {
			vulns = append(vulns, K8sVulnerability{
				Name:        "Pod Listing",
				Description: "Service account can list pods",
				Severity:    "MEDIUM",
				Exploitable: false,
				Details:     "Can enumerate running workloads",
			})
		}
	}

	// Check for node access
	for _, r := range rbac {
		if contains(r.Resources, "nodes") && r.Allowed {
			vulns = append(vulns, K8sVulnerability{
				Name:        "Node Access",
				Description: "Service account can access node information",
				Severity:    "HIGH",
				Exploitable: true,
				Details:     "May be able to access node-level secrets",
			})
		}
	}

	return vulns, errors.Join(failures...)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}

// GenerateKubectlCommands generates useful kubectl commands
func GenerateKubectlCommands(info *K8sInfo) []string {
	cmds := []string{
		"# Useful kubectl commands for pentesting",
		"",
		"# List all namespaces",
		"kubectl get namespaces",
		"",
		"# List all pods in all namespaces",
		"kubectl get pods --all-namespaces",
		"",
		"# List all secrets",
		fmt.Sprintf("kubectl get secrets -n %s", info.Namespace),
		"",
		"# Get a specific secret",
		fmt.Sprintf("kubectl get secret <name> -n %s -o yaml", info.Namespace),
		"",
		"# Decode secret",
		"kubectl get secret <name> -o jsonpath='{.data}' | base64 -d",
		"",
		"# Get service account permissions",
		"kubectl auth can-i --list",
		"",
		"# Execute command in pod",
		"kubectl exec -it <pod-name> -- /bin/sh",
		"",
		"# Port forward",
		"kubectl port-forward <pod-name> 8080:80",
		"",
		"# Get cluster info",
		"kubectl cluster-info",
	}

	return cmds
}

// DisplayK8sInfo displays Kubernetes info
func DisplayK8sInfo(info *K8sInfo) {
	fmt.Fprintln(stdoutW, "\n[KUBERNETES DETECTION]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if !info.InCluster {
		fmt.Fprintln(stdoutW, "Not running inside Kubernetes")
		return
	}

	fmt.Fprintln(stdoutW, "Running inside Kubernetes cluster!")
	fmt.Fprintf(stdoutW, "Namespace:   %s\n", info.Namespace)
	fmt.Fprintf(stdoutW, "API Server:  %s\n", info.APIServer)

	if info.Token != "" {
		fmt.Fprintf(stdoutW, "Token:       %s...%s (%d chars)\n",
			info.Token[:20], info.Token[len(info.Token)-10:], len(info.Token))
	}

	fmt.Fprintln(stdoutW)
}

// DisplaySecrets displays Kubernetes secrets
func DisplaySecrets(secrets []SecretEntry) {
	fmt.Fprintln(stdoutW, "\n[KUBERNETES SECRETS]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(secrets) == 0 {
		fmt.Fprintln(stdoutW, "No accessible secrets found")
		return
	}

	fmt.Fprintf(stdoutW, "Found: %d secrets\n\n", len(secrets))

	for _, s := range secrets {
		fmt.Fprintf(stdoutW, "  %s/%s [%s]\n", s.Namespace, s.Name, s.Type)
		fmt.Fprintf(stdoutW, "    Keys: %s\n", strings.Join(s.Keys, ", "))
	}

	fmt.Fprintln(stdoutW)
}

// DisplayVulnerabilities displays K8s vulnerabilities
func DisplayVulnerabilities(vulns []K8sVulnerability) {
	fmt.Fprintln(stdoutW, "\n[KUBERNETES VULNERABILITIES]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(vulns) == 0 {
		fmt.Fprintln(stdoutW, "No vulnerabilities found")
		return
	}

	exploitable := 0
	for _, v := range vulns {
		if v.Exploitable {
			exploitable++
		}
	}

	fmt.Fprintf(stdoutW, "Found: %d issues (%d exploitable)\n\n", len(vulns), exploitable)

	for _, v := range vulns {
		fmt.Fprintf(stdoutW, "[%s] %s\n", v.Severity, v.Name)
		fmt.Fprintf(stdoutW, "  %s\n", v.Description)
		if v.Details != "" {
			fmt.Fprintf(stdoutW, "  Details: %s\n", v.Details)
		}
		fmt.Fprintln(stdoutW)
	}
}

// DisplayRBAC displays RBAC permissions
func DisplayRBAC(rbac []RBACInfo) {
	fmt.Fprintln(stdoutW, "\n[KUBERNETES RBAC]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(rbac) == 0 {
		fmt.Fprintln(stdoutW, "No accessible resources found")
		return
	}

	fmt.Fprintln(stdoutW, "Accessible resources:")
	for _, r := range rbac {
		fmt.Fprintf(stdoutW, "  %s: %v\n", r.Resources[0], r.Verbs)
	}

	fmt.Fprintln(stdoutW)
}

func anonymousAPIAccess(client *http.Client, server string) (bool, error) {
	response, err := client.Get(strings.TrimRight(server, "/") + "/api/v1")
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	case http.StatusOK:
		body, err := readAPIResponse(response.Body)
		if err != nil {
			return false, err
		}
		var discovery struct {
			Kind      string            `json:"kind"`
			Resources []json.RawMessage `json:"resources"`
		}
		if err := json.Unmarshal(body, &discovery); err != nil || discovery.Kind != "APIResourceList" || discovery.Resources == nil {
			return false, fmt.Errorf("malformed Kubernetes discovery response")
		}
		return true, nil
	default:
		return false, fmt.Errorf("kubernetes discovery returned HTTP %d", response.StatusCode)
	}
}
