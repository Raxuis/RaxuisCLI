package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		info.APIServer = fmt.Sprintf("https://%s:%s", host, port)
	}

	return info
}

// CheckAPIAccess checks what API access is available
func CheckAPIAccess(info *K8sInfo) []RBACInfo {
	var rbac []RBACInfo

	if !info.InCluster || info.Token == "" {
		return rbac
	}

	// Try common API endpoints
	endpoints := []struct {
		path     string
		resource string
	}{
		{"/api/v1/namespaces", "namespaces"},
		{"/api/v1/pods", "pods"},
		{"/api/v1/secrets", "secrets"},
		{"/api/v1/configmaps", "configmaps"},
		{"/api/v1/services", "services"},
		{"/api/v1/nodes", "nodes"},
		{"/apis/rbac.authorization.k8s.io/v1/clusterroles", "clusterroles"},
		{"/api/v1/namespaces/" + info.Namespace + "/pods", "pods (namespace)"},
		{"/api/v1/namespaces/" + info.Namespace + "/secrets", "secrets (namespace)"},
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: nil, // Skip TLS verification for testing
		},
	}

	for _, ep := range endpoints {
		url := info.APIServer + ep.path

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Authorization", "Bearer "+info.Token)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		rbacInfo := RBACInfo{
			Resources: []string{ep.resource},
			Verbs:     []string{"get", "list"},
			Allowed:   resp.StatusCode == 200,
		}

		if resp.StatusCode == 200 {
			rbac = append(rbac, rbacInfo)
		}
	}

	return rbac
}

// ListSecrets lists accessible secrets
func ListSecrets(info *K8sInfo, namespace string) ([]SecretEntry, error) {
	var secrets []SecretEntry

	if !info.InCluster || info.Token == "" {
		return secrets, fmt.Errorf("not in cluster or no token")
	}

	if namespace == "" {
		namespace = info.Namespace
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", info.APIServer, namespace)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: nil,
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return secrets, err
	}

	req.Header.Set("Authorization", "Bearer "+info.Token)

	resp, err := client.Do(req)
	if err != nil {
		return secrets, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return secrets, fmt.Errorf("access denied: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
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
	var vulns []K8sVulnerability

	// Check for anonymous auth
	client := &http.Client{Timeout: 5 * time.Second}
	if resp, err := client.Get(info.APIServer + "/api/v1"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			vulns = append(vulns, K8sVulnerability{
				Name:        "Anonymous Authentication",
				Description: "Kubernetes API allows anonymous access",
				Severity:    "HIGH",
				Exploitable: true,
				Details:     "Can access API without authentication",
			})
		}
	}

	// Check for overly permissive service account
	rbac := CheckAPIAccess(info)
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

	return vulns
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
	fmt.Println("\n[KUBERNETES DETECTION]")
	fmt.Println(strings.Repeat("=", 60))

	if !info.InCluster {
		fmt.Println("Not running inside Kubernetes")
		return
	}

	fmt.Println("Running inside Kubernetes cluster!")
	fmt.Printf("Namespace:   %s\n", info.Namespace)
	fmt.Printf("API Server:  %s\n", info.APIServer)

	if info.Token != "" {
		fmt.Printf("Token:       %s...%s (%d chars)\n",
			info.Token[:20], info.Token[len(info.Token)-10:], len(info.Token))
	}

	fmt.Println()
}

// DisplaySecrets displays Kubernetes secrets
func DisplaySecrets(secrets []SecretEntry) {
	fmt.Println("\n[KUBERNETES SECRETS]")
	fmt.Println(strings.Repeat("=", 60))

	if len(secrets) == 0 {
		fmt.Println("No accessible secrets found")
		return
	}

	fmt.Printf("Found: %d secrets\n\n", len(secrets))

	for _, s := range secrets {
		fmt.Printf("  %s/%s [%s]\n", s.Namespace, s.Name, s.Type)
		fmt.Printf("    Keys: %s\n", strings.Join(s.Keys, ", "))
	}

	fmt.Println()
}

// DisplayVulnerabilities displays K8s vulnerabilities
func DisplayVulnerabilities(vulns []K8sVulnerability) {
	fmt.Println("\n[KUBERNETES VULNERABILITIES]")
	fmt.Println(strings.Repeat("=", 60))

	if len(vulns) == 0 {
		fmt.Println("No vulnerabilities found")
		return
	}

	exploitable := 0
	for _, v := range vulns {
		if v.Exploitable {
			exploitable++
		}
	}

	fmt.Printf("Found: %d issues (%d exploitable)\n\n", len(vulns), exploitable)

	for _, v := range vulns {
		fmt.Printf("[%s] %s\n", v.Severity, v.Name)
		fmt.Printf("  %s\n", v.Description)
		if v.Details != "" {
			fmt.Printf("  Details: %s\n", v.Details)
		}
		fmt.Println()
	}
}

// DisplayRBAC displays RBAC permissions
func DisplayRBAC(rbac []RBACInfo) {
	fmt.Println("\n[KUBERNETES RBAC]")
	fmt.Println(strings.Repeat("=", 60))

	if len(rbac) == 0 {
		fmt.Println("No accessible resources found")
		return
	}

	fmt.Println("Accessible resources:")
	for _, r := range rbac {
		fmt.Printf("  %s: %v\n", r.Resources[0], r.Verbs)
	}

	fmt.Println()
}
