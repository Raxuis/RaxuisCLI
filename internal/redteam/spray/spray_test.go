package spray

import (
	"net"
	"strconv"
	"testing"
)

// fakeLDAP accepts binds and replies success only when the request's simple-auth
// password equals validPass, otherwise invalidCredentials (49).
func fakeLDAP(t *testing.T, validPass string) (host string, port int, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				code := byte(49)
				if extractBindPassword(buf[:n]) == validPass {
					code = 0
				}
				// LDAPMessage { msgID 1, bindResponse { resultCode, "", "" } }
				c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00})
			}(c)
		}
	}()

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pi, _ := strconv.Atoi(p)
	return h, pi, func() { ln.Close() }
}

// extractBindPassword returns the last simple-auth (context tag 0x80) value.
func extractBindPassword(req []byte) string {
	for i := len(req) - 1; i >= 0; i-- {
		if req[i] == 0x80 && i+1 < len(req) {
			plen := int(req[i+1])
			if i+2+plen <= len(req) {
				return string(req[i+2 : i+2+plen])
			}
		}
	}
	return ""
}

func TestRunFindsValidCredential(t *testing.T) {
	host, port, done := fakeLDAP(t, "Winter2025!")
	defer done()

	res := Run(Options{
		Targets:     []Target{{Host: host, Port: port, TLS: false}},
		Users:       []string{"alice", "bob"},
		Passwords:   []string{"WrongPass", "Winter2025!"},
		Domain:      "corp.local",
		Timeout:     3,
		Concurrency: 5,
	})

	// Round 1 (WrongPass): 2 attempts, 0 hits. Round 2 (Winter2025!): 2 hits.
	if len(res.Valid) != 2 {
		t.Fatalf("expected 2 valid creds, got %d (%v)", len(res.Valid), res.Valid)
	}
	if res.Attempts != 4 {
		t.Errorf("expected 4 attempts, got %d", res.Attempts)
	}
	if res.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", res.Errors)
	}
	for _, h := range res.Valid {
		if h.Password != "Winter2025!" {
			t.Errorf("hit with wrong password: %+v", h)
		}
	}
}

func TestRunSkipsFoundUsers(t *testing.T) {
	host, port, done := fakeLDAP(t, "P@ss")
	defer done()

	// Both passwords are valid on the fake server, so without skip logic each
	// user would be reported twice. With skip-on-success, once each.
	res := Run(Options{
		Targets:     []Target{{Host: host, Port: port}},
		Users:       []string{"alice"},
		Passwords:   []string{"P@ss", "P@ss"},
		Domain:      "corp.local",
		Timeout:     3,
		Concurrency: 1,
	})
	if len(res.Valid) != 1 {
		t.Errorf("expected 1 hit (found users skipped in later rounds), got %d", len(res.Valid))
	}
}

func TestRunCountsConnectionErrors(t *testing.T) {
	// Port 1 is closed -> connection error, no hit, counted as error.
	res := Run(Options{
		Targets:     []Target{{Host: "127.0.0.1", Port: 1}},
		Users:       []string{"alice"},
		Passwords:   []string{"x"},
		Domain:      "corp.local",
		Timeout:     1,
		Concurrency: 1,
	})
	if len(res.Valid) != 0 {
		t.Errorf("expected 0 valid on closed port, got %d", len(res.Valid))
	}
	if res.Errors == 0 {
		t.Error("expected connection error to be counted")
	}
}

func TestOnHitCallback(t *testing.T) {
	host, port, done := fakeLDAP(t, "hit")
	defer done()

	var got []Hit
	Run(Options{
		Targets:     []Target{{Host: host, Port: port}},
		Users:       []string{"alice"},
		Passwords:   []string{"hit"},
		Domain:      "corp.local",
		Timeout:     3,
		Concurrency: 1,
		OnHit:       func(h Hit) { got = append(got, h) },
	})
	if len(got) != 1 || got[0].User != "alice" {
		t.Errorf("OnHit not invoked correctly: %v", got)
	}
}

func TestParseScanTargets(t *testing.T) {
	js := []byte(`{"hosts":[
		{"ip":"10.0.0.5","open_ports":[
			{"port":389,"service":"ldap","tag":"ad"},
			{"port":636,"service":"ldaps","tag":"ad"},
			{"port":445,"service":"smb","tag":"ad"},
			{"port":80,"service":"http","tag":"web"}]},
		{"ip":"10.0.0.6","open_ports":[
			{"port":3268,"service":"ldap","tag":"ad"}]}]}`)

	targets, err := ParseScanTargets(js)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 389 + 636 on .5, 3268 on .6; 445 and 80 excluded.
	if len(targets) != 3 {
		t.Fatalf("expected 3 LDAP targets, got %d: %v", len(targets), targets)
	}
	var has636TLS bool
	for _, tg := range targets {
		if tg.Port == 636 && tg.TLS {
			has636TLS = true
		}
		if tg.Port == 445 || tg.Port == 80 {
			t.Errorf("non-LDAP port leaked into targets: %d", tg.Port)
		}
	}
	if !has636TLS {
		t.Error("port 636 should be marked TLS")
	}
}

func TestParseScanTargetsEmpty(t *testing.T) {
	if _, err := ParseScanTargets([]byte(`{"hosts":[{"ip":"10.0.0.9","open_ports":[{"port":22,"service":"ssh","tag":"recon"}]}]}`)); err == nil {
		t.Error("expected error when no ad-tagged LDAP targets are present")
	}
}

func TestStopOnSuccessHaltsSpray(t *testing.T) {
	host, port, done := fakeLDAP(t, "P@ss") // every user matches when password is P@ss
	defer done()

	res := Run(Options{
		Targets:       []Target{{Host: host, Port: port}},
		Users:         []string{"alice", "bob", "carol"},
		Passwords:     []string{"P@ss"},
		Domain:        "corp.local",
		Timeout:       3,
		Concurrency:   1,
		StopOnSuccess: true,
	})
	if len(res.Valid) != 1 {
		t.Errorf("StopOnSuccess should yield exactly 1 hit, got %d", len(res.Valid))
	}
}

func TestOnRoundStartFires(t *testing.T) {
	host, port, done := fakeLDAP(t, "none") // no password matches, so all rounds run
	defer done()

	var seen []int
	Run(Options{
		Targets:      []Target{{Host: host, Port: port}},
		Users:        []string{"alice"},
		Passwords:    []string{"a", "b", "c"},
		Domain:       "corp.local",
		Timeout:      3,
		Concurrency:  1,
		OnRoundStart: func(round, total int, _ string) { seen = append(seen, round) },
	})
	if len(seen) != 3 || seen[0] != 1 || seen[2] != 3 {
		t.Errorf("OnRoundStart should fire for rounds 1,2,3; got %v", seen)
	}
}
