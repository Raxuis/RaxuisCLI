package container

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// ContainerType represents the type of container runtime
type ContainerType string

const (
	Docker     ContainerType = "docker"
	Containerd ContainerType = "containerd"
	Podman     ContainerType = "podman"
	CRI        ContainerType = "cri-o"
	Unknown    ContainerType = "unknown"
)

// EscapeVector represents a container escape technique
type EscapeVector struct {
	Name        string
	Description string
	CVE         string
	Exploitable bool
	Details     string
	Mitigation  string
}

// ContainerInfo holds information about the container environment
type ContainerInfo struct {
	IsContainer   bool
	ContainerType ContainerType
	ContainerID   string
	Hostname      string
	Privileged    bool
	Capabilities  []string
	Mounts        []MountInfo
	Environment   map[string]string
}

// MountInfo holds mount point information
type MountInfo struct {
	Source      string
	Destination string
	Type        string
	Options     []string
	Writable    bool
}

// SecretFinding represents a discovered secret
type SecretFinding struct {
	Path    string
	Type    string
	Content string
}

// rootPrefix lets tests sandbox every absolute filesystem path this package
// probes (/.dockerenv, /proc/..., /dev/..., etc.) under a t.TempDir()
// instead of the real machine's filesystem. Empty (the default) preserves
// real behavior exactly - production code never sets this.
var rootPrefix string

func rootPath(p string) string {
	return rootPrefix + p
}

// DetectContainer detects if running inside a container
func DetectContainer() *ContainerInfo {
	info := &ContainerInfo{
		Environment: make(map[string]string),
	}

	// Check /.dockerenv
	if _, err := os.Stat(rootPath("/.dockerenv")); err == nil {
		info.IsContainer = true
		info.ContainerType = Docker
	}

	// Check /run/.containerenv (Podman)
	if _, err := os.Stat(rootPath("/run/.containerenv")); err == nil {
		info.IsContainer = true
		info.ContainerType = Podman
	}

	// Check cgroup
	if data, err := os.ReadFile(rootPath("/proc/1/cgroup")); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") {
			info.IsContainer = true
			info.ContainerType = Docker
			// Extract container ID
			re := regexp.MustCompile(`docker/([a-f0-9]{64})`)
			if matches := re.FindStringSubmatch(content); len(matches) > 1 {
				info.ContainerID = matches[1][:12]
			}
		} else if strings.Contains(content, "kubepods") {
			info.IsContainer = true
			info.ContainerType = Containerd
		} else if strings.Contains(content, "containerd") {
			info.IsContainer = true
			info.ContainerType = Containerd
		}
	}

	// Check for container-specific environment variables
	containerEnvVars := []string{
		"KUBERNETES_SERVICE_HOST",
		"DOCKER_HOST",
		"container",
	}
	for _, env := range containerEnvVars {
		if val := os.Getenv(env); val != "" {
			info.IsContainer = true
			info.Environment[env] = val
		}
	}

	// Get hostname
	info.Hostname, _ = os.Hostname()

	// Check if privileged
	info.Privileged = isPrivileged()

	// Get capabilities
	info.Capabilities = getCapabilities()

	// Get mounts
	info.Mounts = getMounts()

	return info
}

// isPrivileged checks if container is running in privileged mode
func isPrivileged() bool {
	// Check for /dev access
	if _, err := os.Stat(rootPath("/dev/sda")); err == nil {
		return true
	}

	// Check capabilities
	if data, err := os.ReadFile(rootPath("/proc/self/status")); err == nil {
		content := string(data)
		// CapEff: ffffffffffffffff indicates all capabilities
		if strings.Contains(content, "CapEff:\tffffffffffffffff") {
			return true
		}
	}

	// Check if we can access host devices
	if _, err := os.Stat(rootPath("/dev/kmsg")); err == nil {
		return true
	}

	return false
}

// getCapabilities gets container capabilities
func getCapabilities() []string {
	var caps []string

	if runtime.GOOS != "linux" {
		return caps
	}

	// Parse /proc/self/status for capabilities
	data, err := os.ReadFile(rootPath("/proc/self/status"))
	if err != nil {
		return caps
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Cap") {
			parts := strings.SplitN(line, ":\t", 2)
			if len(parts) == 2 {
				caps = append(caps, fmt.Sprintf("%s: %s", parts[0], parts[1]))
			}
		}
	}

	return caps
}

// getMounts gets mount information
func getMounts() []MountInfo {
	var mounts []MountInfo

	file, err := os.Open(rootPath("/proc/self/mounts"))
	if err != nil {
		return mounts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 4 {
			continue
		}

		mount := MountInfo{
			Source:      parts[0],
			Destination: parts[1],
			Type:        parts[2],
			Options:     strings.Split(parts[3], ","),
		}

		// Check if writable
		for _, opt := range mount.Options {
			if opt == "rw" {
				mount.Writable = true
				break
			}
		}

		mounts = append(mounts, mount)
	}

	return mounts
}

// CheckEscapeVectors checks for container escape vulnerabilities
func CheckEscapeVectors() []EscapeVector {
	var vectors []EscapeVector

	// Check privileged mode
	if isPrivileged() {
		vectors = append(vectors, EscapeVector{
			Name:        "Privileged Container",
			Description: "Container running with --privileged flag",
			Exploitable: true,
			Details:     "Full host access available",
			Mitigation:  "Remove --privileged flag, use specific capabilities instead",
		})
	}

	// Check Docker socket mount
	if _, err := os.Stat(rootPath("/var/run/docker.sock")); err == nil {
		vectors = append(vectors, EscapeVector{
			Name:        "Docker Socket Mount",
			Description: "Docker socket is mounted inside container",
			Exploitable: true,
			Details:     "Can create containers on host: docker run -v /:/host alpine chroot /host",
			Mitigation:  "Remove docker.sock mount",
		})
	}

	// Check /proc/sys writable (CVE-2019-5736)
	if f, err := os.OpenFile(rootPath("/proc/sys/kernel/core_pattern"), os.O_WRONLY, 0); err == nil {
		f.Close()
		vectors = append(vectors, EscapeVector{
			Name:        "Writable /proc/sys",
			Description: "Can write to /proc/sys/kernel/core_pattern",
			CVE:         "CVE-2019-5736",
			Exploitable: true,
			Details:     "Can overwrite core_pattern to execute arbitrary commands",
			Mitigation:  "Use read-only /proc, drop CAP_SYS_ADMIN",
		})
	}

	// Check host PID namespace
	if data, err := os.ReadFile(rootPath("/proc/1/cmdline")); err == nil {
		if !strings.Contains(string(data), "init") && !strings.Contains(string(data), "systemd") {
			// Likely in container's own PID namespace
		} else {
			vectors = append(vectors, EscapeVector{
				Name:        "Host PID Namespace",
				Description: "Container shares PID namespace with host",
				Exploitable: true,
				Details:     "Can see and potentially interact with host processes",
				Mitigation:  "Remove --pid=host flag",
			})
		}
	}

	// Check host network
	if data, err := os.ReadFile(rootPath("/proc/net/route")); err == nil {
		if strings.Contains(string(data), "eth0") || strings.Contains(string(data), "ens") {
			// Could be host network
			vectors = append(vectors, EscapeVector{
				Name:        "Possible Host Network",
				Description: "Container may share network namespace with host",
				Exploitable: false,
				Details:     "Check network interfaces for host network access",
				Mitigation:  "Remove --network=host flag",
			})
		}
	}

	// Check sensitive mount paths
	sensitivePaths := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/root/.ssh",
		"/var/log",
		"/etc/kubernetes",
	}

	for _, path := range sensitivePaths {
		if _, err := os.Stat(rootPath(path)); err == nil {
			vectors = append(vectors, EscapeVector{
				Name:        fmt.Sprintf("Sensitive Mount: %s", path),
				Description: "Sensitive host path is mounted",
				Exploitable: true,
				Details:     fmt.Sprintf("Can access: %s", path),
				Mitigation:  "Remove volume mount",
			})
		}
	}

	// Check CAP_SYS_ADMIN
	if hasCapability("cap_sys_admin") {
		vectors = append(vectors, EscapeVector{
			Name:        "CAP_SYS_ADMIN",
			Description: "Container has CAP_SYS_ADMIN capability",
			Exploitable: true,
			Details:     "Can mount filesystems and perform privileged operations",
			Mitigation:  "Drop CAP_SYS_ADMIN capability",
		})
	}

	// Check CAP_NET_ADMIN
	if hasCapability("cap_net_admin") {
		vectors = append(vectors, EscapeVector{
			Name:        "CAP_NET_ADMIN",
			Description: "Container has CAP_NET_ADMIN capability",
			Exploitable: false,
			Details:     "Can perform network administration tasks",
			Mitigation:  "Drop CAP_NET_ADMIN if not needed",
		})
	}

	return vectors
}

// capshOutput runs `capsh --print` to list capabilities. Overridable by
// tests so they don't depend on capsh being installed on the test machine.
var capshOutput = func() (string, error) {
	out, err := exec.Command("capsh", "--print").Output()
	return string(out), err
}

// hasCapability checks if a capability is present
func hasCapability(cap string) bool {
	out, err := capshOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(out), cap)
}

// ScanSecrets scans for secrets in container
func ScanSecrets() []SecretFinding {
	var findings []SecretFinding

	// Common secret locations
	secretPaths := []string{
		"/run/secrets",
		"/var/run/secrets",
		"/etc/kubernetes/secrets",
		"/var/secrets",
	}

	for _, basePath := range secretPaths {
		_ = filepath.Walk(rootPath(basePath), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			// Determine secret type
			secretType := "unknown"
			content := string(data)

			if strings.Contains(path, "token") {
				secretType = "token"
			} else if strings.Contains(path, "password") || strings.Contains(path, "passwd") {
				secretType = "password"
			} else if strings.Contains(path, "key") || strings.Contains(path, "secret") {
				secretType = "key"
			} else if strings.HasPrefix(content, "-----BEGIN") {
				secretType = "certificate/key"
			}

			findings = append(findings, SecretFinding{
				Path:    path,
				Type:    secretType,
				Content: truncateSecret(content),
			})

			return nil
		})
	}

	// Check environment variables for secrets
	secretEnvPatterns := []string{"PASSWORD", "SECRET", "KEY", "TOKEN", "API_KEY", "CREDENTIAL"}
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		for _, pattern := range secretEnvPatterns {
			if strings.Contains(strings.ToUpper(parts[0]), pattern) {
				findings = append(findings, SecretFinding{
					Path:    "ENV:" + parts[0],
					Type:    "environment",
					Content: truncateSecret(parts[1]),
				})
				break
			}
		}
	}

	return findings
}

func truncateSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 50 {
		return s[:20] + "..." + s[len(s)-10:]
	}
	return s
}

// DisplayContainerInfo displays container information
func DisplayContainerInfo(info *ContainerInfo) {
	fmt.Fprintln(stdoutW, "\n[CONTAINER DETECTION]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if !info.IsContainer {
		fmt.Fprintln(stdoutW, "Not running inside a container")
		return
	}

	fmt.Fprintf(stdoutW, "Container Type:  %s\n", info.ContainerType)
	fmt.Fprintf(stdoutW, "Container ID:    %s\n", info.ContainerID)
	fmt.Fprintf(stdoutW, "Hostname:        %s\n", info.Hostname)
	fmt.Fprintf(stdoutW, "Privileged:      %v\n", info.Privileged)

	if len(info.Capabilities) > 0 {
		fmt.Fprintln(stdoutW, "\nCapabilities:")
		for _, cap := range info.Capabilities {
			fmt.Fprintf(stdoutW, "  %s\n", cap)
		}
	}

	if len(info.Environment) > 0 {
		fmt.Fprintln(stdoutW, "\nContainer Environment Variables:")
		for k, v := range info.Environment {
			fmt.Fprintf(stdoutW, "  %s=%s\n", k, v)
		}
	}

	fmt.Fprintln(stdoutW)
}

// DisplayEscapeVectors displays escape vectors
func DisplayEscapeVectors(vectors []EscapeVector) {
	fmt.Fprintln(stdoutW, "\n[CONTAINER ESCAPE VECTORS]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(vectors) == 0 {
		fmt.Fprintln(stdoutW, "No obvious escape vectors found")
		return
	}

	exploitable := 0
	for _, v := range vectors {
		if v.Exploitable {
			exploitable++
		}
	}

	fmt.Fprintf(stdoutW, "Found: %d vectors (%d exploitable)\n\n", len(vectors), exploitable)

	for _, v := range vectors {
		status := "INFO"
		if v.Exploitable {
			status = "VULNERABLE"
		}

		fmt.Fprintf(stdoutW, "[%s] %s\n", status, v.Name)
		fmt.Fprintf(stdoutW, "  %s\n", v.Description)
		if v.CVE != "" {
			fmt.Fprintf(stdoutW, "  CVE: %s\n", v.CVE)
		}
		if v.Details != "" {
			fmt.Fprintf(stdoutW, "  Details: %s\n", v.Details)
		}
		fmt.Fprintln(stdoutW)
	}
}

// DisplaySecrets displays found secrets
func DisplaySecrets(findings []SecretFinding) {
	fmt.Fprintln(stdoutW, "\n[CONTAINER SECRETS]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(findings) == 0 {
		fmt.Fprintln(stdoutW, "No secrets found")
		return
	}

	fmt.Fprintf(stdoutW, "Found: %d secrets\n\n", len(findings))

	for _, f := range findings {
		fmt.Fprintf(stdoutW, "  [%s] %s\n", f.Type, f.Path)
		fmt.Fprintf(stdoutW, "    Value: %s\n", f.Content)
	}

	fmt.Fprintln(stdoutW)
}
