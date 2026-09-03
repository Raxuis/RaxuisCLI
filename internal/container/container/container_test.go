package container

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureContainerStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// withRoot sandboxes every absolute path this package touches under a fresh
// t.TempDir() and restores rootPrefix afterward.
func withRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := rootPrefix
	rootPrefix = dir
	t.Cleanup(func() { rootPrefix = orig })
	return dir
}

func writeAt(t *testing.T, root, relPath, content string) {
	t.Helper()
	full := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatalf("failed to mkdir for %s: %v", relPath, err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", relPath, err)
	}
}

func TestDetectContainerDockerenv(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/.dockerenv", "")

	info := DetectContainer()
	if !info.IsContainer || info.ContainerType != Docker {
		t.Errorf("DetectContainer with /.dockerenv = %+v, want IsContainer=true Type=docker", info)
	}
}

func TestDetectContainerPodman(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/run/.containerenv", "")

	info := DetectContainer()
	if !info.IsContainer || info.ContainerType != Podman {
		t.Errorf("DetectContainer with /run/.containerenv = %+v, want IsContainer=true Type=podman", info)
	}
}

func TestDetectContainerCgroupDocker(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/proc/1/cgroup", "0::/docker/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n")

	info := DetectContainer()
	if !info.IsContainer || info.ContainerType != Docker {
		t.Errorf("DetectContainer with docker cgroup = %+v, want IsContainer=true Type=docker", info)
	}
	if info.ContainerID != "abcdef012345" {
		t.Errorf("ContainerID = %q, want the first 12 hex chars", info.ContainerID)
	}
}

func TestDetectContainerCgroupKubepods(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/proc/1/cgroup", "0::/kubepods/besteffort/pod123/container456\n")

	info := DetectContainer()
	if !info.IsContainer || info.ContainerType != Containerd {
		t.Errorf("DetectContainer with kubepods cgroup = %+v, want IsContainer=true Type=containerd", info)
	}
}

func TestDetectContainerEnvVar(t *testing.T) {
	withRoot(t)
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")

	info := DetectContainer()
	if !info.IsContainer {
		t.Error("DetectContainer should detect KUBERNETES_SERVICE_HOST env var")
	}
	if info.Environment["KUBERNETES_SERVICE_HOST"] != "10.0.0.1" {
		t.Errorf("Environment[KUBERNETES_SERVICE_HOST] = %q, want 10.0.0.1", info.Environment["KUBERNETES_SERVICE_HOST"])
	}
}

func TestDetectContainerNotAContainer(t *testing.T) {
	withRoot(t) // empty sandbox: none of the container markers exist
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("container", "")

	info := DetectContainer()
	if info.IsContainer {
		t.Errorf("DetectContainer in an empty sandbox with no container env vars should report false, got %+v", info)
	}
}

func TestIsPrivilegedViaDevSda(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/dev/sda", "")

	if !isPrivileged() {
		t.Error("isPrivileged should return true when /dev/sda exists")
	}
}

func TestIsPrivilegedViaCapEff(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/proc/self/status", "Name:\tgo\nCapEff:\tffffffffffffffff\n")

	if !isPrivileged() {
		t.Error("isPrivileged should return true when CapEff is all-ones")
	}
}

func TestIsPrivilegedFalse(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/proc/self/status", "Name:\tgo\nCapEff:\t0000000000000000\n")

	if isPrivileged() {
		t.Error("isPrivileged should return false with a restricted CapEff and no /dev/sda or /dev/kmsg")
	}
}

func TestGetMountsParsesEntries(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/proc/self/mounts", "overlay / overlay rw,relatime 0 0\ntmpfs /dev tmpfs ro,nosuid 0 0\n")

	mounts := getMounts()
	if len(mounts) != 2 {
		t.Fatalf("getMounts() = %d entries, want 2", len(mounts))
	}
	if mounts[0].Destination != "/" || !mounts[0].Writable {
		t.Errorf("mounts[0] = %+v, want Destination=/ Writable=true", mounts[0])
	}
	if mounts[1].Writable {
		t.Errorf("mounts[1] = %+v, want Writable=false (ro)", mounts[1])
	}
}

func TestGetMountsMissingFile(t *testing.T) {
	withRoot(t)
	if mounts := getMounts(); mounts != nil {
		t.Errorf("getMounts() with no /proc/self/mounts should return nil, got %v", mounts)
	}
}

func TestCheckEscapeVectorsDockerSocket(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/var/run/docker.sock", "")

	vectors := CheckEscapeVectors()
	found := false
	for _, v := range vectors {
		if v.Name == "Docker Socket Mount" {
			found = true
		}
	}
	if !found {
		t.Errorf("CheckEscapeVectors should flag a mounted docker.sock, got %+v", vectors)
	}
}

func TestCheckEscapeVectorsSensitiveMount(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/etc/shadow", "root:!:19000:0:99999:7:::")

	vectors := CheckEscapeVectors()
	found := false
	for _, v := range vectors {
		if strings.Contains(v.Name, "/etc/shadow") {
			found = true
		}
	}
	if !found {
		t.Errorf("CheckEscapeVectors should flag an accessible /etc/shadow, got %+v", vectors)
	}
}

func TestCheckEscapeVectorsClean(t *testing.T) {
	withRoot(t) // nothing present at all
	vectors := CheckEscapeVectors()
	for _, v := range vectors {
		if v.Name == "Docker Socket Mount" || strings.Contains(v.Name, "Sensitive Mount") {
			t.Errorf("unexpected vector %q in an empty sandbox", v.Name)
		}
	}
}

func TestHasCapabilityOverride(t *testing.T) {
	orig := capshOutput
	defer func() { capshOutput = orig }()

	capshOutput = func() (string, error) { return "Current: = cap_sys_admin+eip", nil }
	if !hasCapability("cap_sys_admin") {
		t.Error("hasCapability should detect cap_sys_admin in the capsh output")
	}
	if hasCapability("cap_net_admin") {
		t.Error("hasCapability should not report a capability absent from the output")
	}
}

func TestHasCapabilityCommandError(t *testing.T) {
	orig := capshOutput
	defer func() { capshOutput = orig }()

	capshOutput = func() (string, error) { return "", errCapshMissing }
	if hasCapability("cap_sys_admin") {
		t.Error("hasCapability should return false when the capsh command fails")
	}
}

var errCapshMissing = &capshError{}

type capshError struct{}

func (*capshError) Error() string { return "capsh: command not found" }

func TestScanSecretsFindsFileAndEnv(t *testing.T) {
	root := withRoot(t)
	writeAt(t, root, "/run/secrets/db_password", "hunter2hunter2hunter2hunter2hunter2hunter2hunter2")
	t.Setenv("MY_API_KEY", "sk-1234567890")

	findings := ScanSecrets()

	var foundFile, foundEnv bool
	for _, f := range findings {
		if strings.Contains(f.Path, "db_password") {
			foundFile = true
			if f.Type != "password" {
				t.Errorf("db_password finding Type = %q, want password", f.Type)
			}
		}
		if f.Path == "ENV:MY_API_KEY" {
			foundEnv = true
		}
	}
	if !foundFile {
		t.Errorf("ScanSecrets should find the db_password file, got %+v", findings)
	}
	if !foundEnv {
		t.Errorf("ScanSecrets should find the MY_API_KEY env var, got %+v", findings)
	}
}

func TestTruncateSecret(t *testing.T) {
	short := "short-secret"
	if got := truncateSecret(short); got != short {
		t.Errorf("truncateSecret(short) = %q, want unchanged %q", got, short)
	}

	long := strings.Repeat("a", 60)
	got := truncateSecret(long)
	if len(got) >= len(long) {
		t.Errorf("truncateSecret(long) should shorten the string, got len %d", len(got))
	}
	if !strings.Contains(got, "...") {
		t.Errorf("truncateSecret(long) = %q, want it to contain ...", got)
	}
}

func TestDisplayContainerInfoNotContainer(t *testing.T) {
	out := captureContainerStdout(t, func() {
		DisplayContainerInfo(&ContainerInfo{IsContainer: false})
	})
	if !strings.Contains(out, "Not running inside a container") {
		t.Errorf("DisplayContainerInfo(not a container) output wrong; got:\n%s", out)
	}
}

func TestDisplayContainerInfoFull(t *testing.T) {
	info := &ContainerInfo{
		IsContainer:   true,
		ContainerType: Docker,
		ContainerID:   "abc123",
		Hostname:      "myhost",
		Privileged:    true,
		Capabilities:  []string{"CapEff: ffffffffffffffff"},
		Environment:   map[string]string{"container": "docker"},
	}
	out := captureContainerStdout(t, func() {
		DisplayContainerInfo(info)
	})
	for _, want := range []string{"docker", "abc123", "myhost", "CapEff", "container=docker"} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayContainerInfo output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDisplayEscapeVectorsEmpty(t *testing.T) {
	out := captureContainerStdout(t, func() { DisplayEscapeVectors(nil) })
	if !strings.Contains(out, "No obvious escape vectors found") {
		t.Errorf("DisplayEscapeVectors(nil) output wrong; got:\n%s", out)
	}
}

func TestDisplayEscapeVectorsWithFindings(t *testing.T) {
	vectors := []EscapeVector{
		{Name: "Privileged Container", Description: "desc", CVE: "CVE-2019-5736", Exploitable: true, Details: "details"},
		{Name: "Possible Host Network", Description: "desc2", Exploitable: false},
	}
	out := captureContainerStdout(t, func() { DisplayEscapeVectors(vectors) })
	for _, want := range []string{"VULNERABLE", "Privileged Container", "CVE-2019-5736", "INFO", "Possible Host Network"} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayEscapeVectors output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDisplaySecretsEmpty(t *testing.T) {
	out := captureContainerStdout(t, func() { DisplaySecrets(nil) })
	if !strings.Contains(out, "No secrets found") {
		t.Errorf("DisplaySecrets(nil) output wrong; got:\n%s", out)
	}
}

func TestDisplaySecretsWithFindings(t *testing.T) {
	findings := []SecretFinding{{Path: "/run/secrets/token", Type: "token", Content: "abc123"}}
	out := captureContainerStdout(t, func() { DisplaySecrets(findings) })
	if !strings.Contains(out, "token") || !strings.Contains(out, "abc123") {
		t.Errorf("DisplaySecrets output wrong; got:\n%s", out)
	}
}
