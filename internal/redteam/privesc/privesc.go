package privesc

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

// CheckResult holds the result of a privilege escalation check
type CheckResult struct {
	Category    string
	Name        string
	Description string
	Vulnerable  bool
	Details     []string
	Severity    string // "critical", "high", "medium", "low", "info"
}

// SystemInfo holds system information
type SystemInfo struct {
	OS           string
	Kernel       string
	Architecture string
	Hostname     string
	CurrentUser  string
	Groups       []string
	Path         string
	Shell        string
}

// Options holds privesc check options
type Options struct {
	Thorough bool
	Category string // "all", "suid", "sudo", "capabilities", "cron", "writable", "passwords"
}

// GetSystemInfo collects system information
func GetSystemInfo() SystemInfo {
	info := SystemInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	// Hostname
	info.Hostname, _ = os.Hostname()

	// Current user
	info.CurrentUser = os.Getenv("USER")
	if info.CurrentUser == "" {
		info.CurrentUser = os.Getenv("USERNAME")
	}

	// Shell
	info.Shell = os.Getenv("SHELL")

	// Path
	info.Path = os.Getenv("PATH")

	// Kernel version (Linux)
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/version"); err == nil {
			info.Kernel = strings.TrimSpace(string(data))
		}
	} else if runtime.GOOS == "darwin" {
		if out, err := exec.Command("uname", "-r").Output(); err == nil {
			info.Kernel = strings.TrimSpace(string(out))
		}
	}

	// Groups
	if out, err := exec.Command("id", "-Gn").Output(); err == nil {
		info.Groups = strings.Fields(strings.TrimSpace(string(out)))
	}

	return info
}

// RunAllChecks performs all privilege escalation checks
func RunAllChecks(opts Options) []CheckResult {
	var results []CheckResult

	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		results = append(results, CheckResult{
			Category:    "system",
			Name:        "OS Not Supported",
			Description: "This tool currently only supports Linux and macOS",
			Vulnerable:  false,
			Severity:    "info",
		})
		return results
	}

	// Run checks based on category
	switch opts.Category {
	case "suid":
		results = append(results, CheckSUID()...)
	case "sudo":
		results = append(results, CheckSudo()...)
	case "capabilities":
		results = append(results, CheckCapabilities()...)
	case "cron":
		results = append(results, CheckCron()...)
	case "writable":
		results = append(results, CheckWritablePaths()...)
	case "passwords":
		results = append(results, CheckPasswordFiles()...)
	default: // "all"
		results = append(results, CheckSUID()...)
		results = append(results, CheckSudo()...)
		results = append(results, CheckCapabilities()...)
		results = append(results, CheckCron()...)
		results = append(results, CheckWritablePaths()...)
		results = append(results, CheckPasswordFiles()...)
		results = append(results, CheckSSHKeys()...)
		results = append(results, CheckDockerSocket()...)
		results = append(results, CheckKernelExploits()...)
	}

	return results
}

// CheckSUID finds SUID/SGID binaries
func CheckSUID() []CheckResult {
	var results []CheckResult
	result := CheckResult{
		Category:    "SUID/SGID",
		Name:        "SUID Binaries",
		Description: "Binaries with SUID bit set that may be exploitable",
		Severity:    "high",
	}

	// Known exploitable SUID binaries
	exploitable := map[string]string{
		"nmap":       "nmap --interactive",
		"vim":        "vim -c ':!/bin/sh'",
		"vim.basic":  "vim.basic -c ':!/bin/sh'",
		"vim.tiny":   "vim.tiny -c ':!/bin/sh'",
		"find":       "find . -exec /bin/sh \\; -quit",
		"bash":       "bash -p",
		"sh":         "sh -p",
		"less":       "less /etc/passwd, then !/bin/sh",
		"more":       "more /etc/passwd, then !/bin/sh",
		"nano":       "nano can edit sensitive files",
		"cp":         "cp /bin/sh /tmp/sh; chmod +s /tmp/sh",
		"mv":         "mv /bin/sh /tmp/",
		"perl":       "perl -e 'exec \"/bin/sh\";'",
		"python":     "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
		"python3":    "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
		"ruby":       "ruby -e 'exec \"/bin/sh\"'",
		"lua":        "lua -e 'os.execute(\"/bin/sh\")'",
		"awk":        "awk 'BEGIN {system(\"/bin/sh\")}'",
		"tcpdump":    "tcpdump -n -i lo -G1 -w /dev/null -z ./shell.sh",
		"tar":        "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
		"zip":        "zip /tmp/test.zip /etc/passwd -T --unzip-command=\"sh -c /bin/sh\"",
		"man":        "man man, then !/bin/sh",
		"wget":       "wget can download malicious files",
		"curl":       "curl can download malicious files",
		"git":        "PAGER='sh -c \"exec sh 0<&1\"' git -p help",
		"env":        "env /bin/sh -p",
		"docker":     "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
		"strace":     "strace -o /dev/null /bin/sh",
		"ltrace":     "ltrace -b -L /bin/sh",
		"systemctl":  "systemctl can manipulate services",
		"journalctl": "journalctl, then !/bin/sh",
		"ftp":        "ftp, then !/bin/sh",
		"gdb":        "gdb -q --nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
		"php":        "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'",
	}

	// Find SUID binaries
	searchPaths := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"}

	for _, searchPath := range searchPaths {
		_ = filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}

			// Check for SUID bit
			mode := info.Mode()
			if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
				name := filepath.Base(path)
				detail := fmt.Sprintf("%s (mode: %s)", path, mode.String())

				if exploit, ok := exploitable[name]; ok {
					result.Vulnerable = true
					detail = fmt.Sprintf("EXPLOITABLE: %s | Method: %s", path, exploit)
				}

				result.Details = append(result.Details, detail)
			}

			return nil
		})
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "No SUID binaries found in common paths")
	}

	results = append(results, result)
	return results
}

// CheckSudo checks sudo configuration
func CheckSudo() []CheckResult {
	var results []CheckResult

	result := CheckResult{
		Category:    "Sudo",
		Name:        "Sudo Configuration",
		Description: "Checking sudo permissions for current user",
		Severity:    "critical",
	}

	// Check sudo -l
	cmd := exec.Command("sudo", "-l")
	output, err := cmd.CombinedOutput()

	if err != nil {
		result.Details = append(result.Details, "Cannot run sudo -l (may require password)")
	} else {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Check for dangerous sudo permissions
			if strings.Contains(line, "NOPASSWD") {
				result.Vulnerable = true
				result.Details = append(result.Details, "NOPASSWD: "+line)
			} else if strings.Contains(line, "(ALL)") || strings.Contains(line, "(root)") {
				result.Vulnerable = true
				result.Details = append(result.Details, line)
			} else if strings.Contains(line, "/bin/sh") || strings.Contains(line, "/bin/bash") {
				result.Vulnerable = true
				result.Details = append(result.Details, "Shell access: "+line)
			}
		}
	}

	// Check for sudo version CVE
	versionCmd := exec.Command("sudo", "--version")
	versionOut, _ := versionCmd.Output()
	if len(versionOut) > 0 {
		versionLine := strings.Split(string(versionOut), "\n")[0]
		result.Details = append(result.Details, "Version: "+versionLine)

		// Check for known vulnerable versions
		if strings.Contains(versionLine, "1.8.") {
			result.Details = append(result.Details, "Warning: Older sudo version, check for CVEs")
		}
	}

	results = append(results, result)
	return results
}

// CheckCapabilities checks Linux capabilities
func CheckCapabilities() []CheckResult {
	var results []CheckResult

	if runtime.GOOS != "linux" {
		return results
	}

	result := CheckResult{
		Category:    "Capabilities",
		Name:        "Linux Capabilities",
		Description: "Binaries with dangerous capabilities",
		Severity:    "high",
	}

	// Dangerous capabilities
	dangerous := map[string]string{
		"cap_setuid":          "Can set UID - potential privesc",
		"cap_setgid":          "Can set GID - potential privesc",
		"cap_dac_override":    "Bypasses file permission checks",
		"cap_dac_read_search": "Can read any file",
		"cap_sys_admin":       "Many privileges - very dangerous",
		"cap_sys_ptrace":      "Can trace processes - code injection",
		"cap_net_admin":       "Network admin - can sniff traffic",
		"cap_net_raw":         "Raw sockets - can sniff traffic",
	}

	// Use getcap to find capabilities
	cmd := exec.Command("getcap", "-r", "/")
	output, _ := cmd.CombinedOutput()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" || strings.Contains(line, "Operation not permitted") {
			continue
		}

		for cap, desc := range dangerous {
			if strings.Contains(strings.ToLower(line), cap) {
				result.Vulnerable = true
				result.Details = append(result.Details, fmt.Sprintf("%s - %s", line, desc))
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "No dangerous capabilities found")
	}

	results = append(results, result)
	return results
}

// CheckCron checks cron jobs for vulnerabilities
func CheckCron() []CheckResult {
	var results []CheckResult

	result := CheckResult{
		Category:    "Cron",
		Name:        "Cron Jobs",
		Description: "Checking cron jobs for misconfigurations",
		Severity:    "medium",
	}

	cronPaths := []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/var/spool/cron",
		"/var/spool/cron/crontabs",
	}

	// Check system crontab
	if data, err := os.ReadFile("/etc/crontab"); err == nil {
		result.Details = append(result.Details, "=== /etc/crontab ===")
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				result.Details = append(result.Details, line)
			}
		}
	}

	// Check cron.d directory
	for _, cronPath := range cronPaths {
		if info, err := os.Stat(cronPath); err == nil && info.IsDir() {
			_ = filepath.Walk(cronPath, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				// Check if writable by current user
				if info.Mode()&0002 != 0 {
					result.Vulnerable = true
					result.Details = append(result.Details, fmt.Sprintf("WRITABLE: %s", path))
				}

				return nil
			})
		}
	}

	results = append(results, result)
	return results
}

// CheckWritablePaths checks for writable paths in PATH
func CheckWritablePaths() []CheckResult {
	var results []CheckResult

	result := CheckResult{
		Category:    "Writable Paths",
		Name:        "PATH Hijacking",
		Description: "Writable directories in PATH",
		Severity:    "high",
	}

	pathEnv := os.Getenv("PATH")
	paths := strings.Split(pathEnv, ":")

	for _, p := range paths {
		if p == "" {
			continue
		}

		// Check if path exists and is writable
		if info, err := os.Stat(p); err == nil {
			// Try to create a temp file to test writability
			testFile := filepath.Join(p, ".privesc_test")
			if f, err := os.Create(testFile); err == nil {
				f.Close()
				os.Remove(testFile)
				result.Vulnerable = true
				result.Details = append(result.Details, fmt.Sprintf("WRITABLE: %s (mode: %s)", p, info.Mode().String()))
			}
		}
	}

	// Check world-writable directories
	worldWritable := []string{"/tmp", "/var/tmp", "/dev/shm"}
	for _, dir := range worldWritable {
		if info, err := os.Stat(dir); err == nil {
			if info.Mode()&0002 != 0 {
				result.Details = append(result.Details, fmt.Sprintf("World-writable: %s", dir))
			}
		}
	}

	if len(result.Details) == 0 {
		result.Details = append(result.Details, "No writable paths found in PATH")
	}

	results = append(results, result)
	return results
}

// CheckPasswordFiles checks for password-related files
func CheckPasswordFiles() []CheckResult {
	var results []CheckResult

	result := CheckResult{
		Category:    "Passwords",
		Name:        "Password Files",
		Description: "Checking for readable password files and hashes",
		Severity:    "critical",
	}

	// Check /etc/shadow readability
	if _, err := os.ReadFile("/etc/shadow"); err == nil {
		result.Vulnerable = true
		result.Details = append(result.Details, "CRITICAL: /etc/shadow is readable!")
	}

	// Check for password in common files
	passwordFiles := []string{
		"/etc/passwd",
		".bash_history",
		".mysql_history",
		".psql_history",
		"/var/log/auth.log",
		"/home/*/.bash_history",
	}

	for _, pf := range passwordFiles {
		if matches, _ := filepath.Glob(pf); len(matches) > 0 {
			for _, match := range matches {
				if data, err := os.ReadFile(match); err == nil {
					// Look for password patterns
					content := string(data)
					if containsPasswordPattern(content) {
						result.Vulnerable = true
						result.Details = append(result.Details, fmt.Sprintf("Potential passwords in: %s", match))
					}
				}
			}
		}
	}

	// Check for .netrc, .pgpass, etc.
	homeDir, _ := os.UserHomeDir()
	sensitiveFiles := []string{".netrc", ".pgpass", ".my.cnf", ".git-credentials"}
	for _, sf := range sensitiveFiles {
		path := filepath.Join(homeDir, sf)
		if _, err := os.Stat(path); err == nil {
			result.Details = append(result.Details, fmt.Sprintf("Found: %s", path))
		}
	}

	results = append(results, result)
	return results
}

// CheckSSHKeys checks for SSH private keys
func CheckSSHKeys() []CheckResult {
	var results []CheckResult

	result := CheckResult{
		Category:    "SSH",
		Name:        "SSH Keys",
		Description: "Checking for accessible SSH private keys",
		Severity:    "high",
	}

	sshDirs := []string{
		"/root/.ssh",
		"/home/*/.ssh",
	}

	for _, pattern := range sshDirs {
		matches, _ := filepath.Glob(pattern)
		for _, sshDir := range matches {
			_ = filepath.Walk(sshDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				// Check for private key files
				name := info.Name()
				if name == "id_rsa" || name == "id_dsa" || name == "id_ecdsa" || name == "id_ed25519" {
					if _, err := os.ReadFile(path); err == nil {
						result.Vulnerable = true
						result.Details = append(result.Details, fmt.Sprintf("Readable private key: %s", path))
					}
				}

				return nil
			})
		}
	}

	results = append(results, result)
	return results
}

// CheckDockerSocket checks for Docker socket access
func CheckDockerSocket() []CheckResult {
	var results []CheckResult

	result := CheckResult{
		Category:    "Docker",
		Name:        "Docker Socket",
		Description: "Checking Docker socket access",
		Severity:    "critical",
	}

	// Check if user is in docker group
	if out, err := exec.Command("id", "-Gn").Output(); err == nil {
		if strings.Contains(string(out), "docker") {
			result.Vulnerable = true
			result.Details = append(result.Details, "User is in docker group - can escalate to root")
		}
	}

	// Check Docker socket
	if info, err := os.Stat("/var/run/docker.sock"); err == nil {
		result.Details = append(result.Details, fmt.Sprintf("Docker socket exists (mode: %s)", info.Mode().String()))

		// Check if readable/writable
		if f, err := os.OpenFile("/var/run/docker.sock", os.O_RDWR, 0); err == nil {
			f.Close()
			result.Vulnerable = true
			result.Details = append(result.Details, "Docker socket is accessible - can escalate to root")
			result.Details = append(result.Details, "Exploit: docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
		}
	}

	results = append(results, result)
	return results
}

// CheckKernelExploits checks for known kernel exploits
func CheckKernelExploits() []CheckResult {
	var results []CheckResult

	result := CheckResult{
		Category:    "Kernel",
		Name:        "Kernel Exploits",
		Description: "Checking for known kernel vulnerabilities",
		Severity:    "critical",
	}

	// Get kernel version
	var kernelVersion string
	if data, err := os.ReadFile("/proc/version"); err == nil {
		kernelVersion = string(data)
	} else if out, err := exec.Command("uname", "-r").Output(); err == nil {
		kernelVersion = string(out)
	}

	result.Details = append(result.Details, "Kernel: "+strings.TrimSpace(kernelVersion))

	// Known vulnerable versions (simplified)
	vulnerabilities := map[string]string{
		"4.4.0": "CVE-2016-5195 (Dirty COW)",
		"3.":    "Multiple vulnerabilities, consider updating",
		"2.6.":  "Very old kernel, many exploits available",
		"4.8":   "CVE-2016-8655",
		"4.10":  "CVE-2017-6074",
	}

	for pattern, vuln := range vulnerabilities {
		if strings.Contains(kernelVersion, pattern) {
			result.Vulnerable = true
			result.Details = append(result.Details, fmt.Sprintf("Potential: %s", vuln))
		}
	}

	results = append(results, result)
	return results
}

// containsPasswordPattern checks if content contains password patterns
func containsPasswordPattern(content string) bool {
	patterns := []string{
		`(?i)password\s*[=:]\s*\S+`,
		`(?i)passwd\s*[=:]\s*\S+`,
		`(?i)pwd\s*[=:]\s*\S+`,
		`(?i)secret\s*[=:]\s*\S+`,
		`mysql.*-p\S+`,
		`ssh.*-i\s+\S+`,
	}

	for _, p := range patterns {
		if matched, _ := regexp.MatchString(p, content); matched {
			return true
		}
	}
	return false
}

// DisplayResults displays all check results
func DisplayResults(results []CheckResult, showAll bool) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("  PRIVILEGE ESCALATION CHECK RESULTS")
	fmt.Println(strings.Repeat("=", 70))

	// Count vulnerabilities
	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}

	fmt.Printf("\nVulnerabilities found: %d\n", vulnCount)
	fmt.Println()

	// Group by category
	categories := make(map[string][]CheckResult)
	for _, r := range results {
		categories[r.Category] = append(categories[r.Category], r)
	}

	for category, checks := range categories {
		fmt.Printf("\n[%s]\n", category)
		fmt.Println(strings.Repeat("-", 50))

		for _, check := range checks {
			status := "OK"
			if check.Vulnerable {
				status = "VULNERABLE"
			}

			severityColor := ""
			switch check.Severity {
			case "critical":
				severityColor = "CRITICAL"
			case "high":
				severityColor = "HIGH"
			case "medium":
				severityColor = "MEDIUM"
			default:
				severityColor = "INFO"
			}

			fmt.Printf("  %s [%s] - %s\n", check.Name, severityColor, status)

			if showAll || check.Vulnerable {
				for _, detail := range check.Details {
					fmt.Printf("    > %s\n", detail)
				}
			}
		}
	}

	fmt.Println()
}

// DisplaySystemInfo displays system information
func DisplaySystemInfo(info SystemInfo) {
	fmt.Println("\n[SYSTEM INFORMATION]")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("  OS:           %s\n", info.OS)
	fmt.Printf("  Architecture: %s\n", info.Architecture)
	fmt.Printf("  Hostname:     %s\n", info.Hostname)
	fmt.Printf("  User:         %s\n", info.CurrentUser)
	fmt.Printf("  Groups:       %s\n", strings.Join(info.Groups, ", "))
	fmt.Printf("  Shell:        %s\n", info.Shell)
	if info.Kernel != "" {
		kernelShort := info.Kernel
		if len(kernelShort) > 60 {
			kernelShort = kernelShort[:60] + "..."
		}
		fmt.Printf("  Kernel:       %s\n", kernelShort)
	}
}

// ScanFile scans a single file for sensitive information
func ScanFile(path string) []string {
	var findings []string

	file, err := os.Open(path)
	if err != nil {
		return findings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if containsPasswordPattern(line) {
			findings = append(findings, fmt.Sprintf("Line %d: %s", lineNum, truncate(line, 80)))
		}
	}

	return findings
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
