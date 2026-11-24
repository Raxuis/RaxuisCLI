package ldap

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ldapFixture exchanges exactly one short-form BER bind message over loopback.
// It verifies the real client's wire request; it implements neither AD nor search.
func ldapFixture(t *testing.T, requestHex string, response []byte) (LDAPOptions, <-chan error) {
	t.Helper()
	want, err := hex.DecodeString(requestHex)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		header := make([]byte, 2)
		if _, err = io.ReadFull(conn, header); err != nil {
			done <- err
			return
		}
		if header[0] != 0x30 || header[1] >= 128 {
			done <- fmt.Errorf("unexpected BER header: %x", header)
			return
		}
		body := make([]byte, int(header[1]))
		if _, err = io.ReadFull(conn, body); err != nil {
			done <- err
			return
		}
		request := append(header, body...)
		if !bytes.Equal(request, want) {
			done <- fmt.Errorf("bind request = %x, want %x", request, want)
			return
		}
		_, err = conn.Write(response)
		done <- err
	}()
	return LDAPOptions{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Timeout: 2}, done
}

func awaitLDAPFixture(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("LDAP fixture: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("LDAP fixture did not finish")
	}
}

func TestBindLocalFixture(t *testing.T) {
	// LDAPv3 bind: message 1, DN "user@example.test", simple password "secret".
	const request = "3023020101601e020103041175736572406578616d706c652e746573748006736563726574"
	for _, tt := range []struct {
		name      string
		response  []byte
		wantError string
	}{
		{"success", []byte{0x30, 12, 2, 1, 1, 0x61, 7, 0x0a, 1, 0, 4, 0, 4, 0}, ""},
		{"invalid credentials", []byte{0x30, 12, 2, 1, 1, 0x61, 7, 0x0a, 1, 49, 4, 0, 4, 0}, "invalid credentials"},
		{"unwilling", []byte{0x30, 12, 2, 1, 1, 0x61, 7, 0x0a, 1, 53, 4, 0, 4, 0}, "code: 53"},
		{"malformed", []byte("not LDAP"), "unparseable"},
		{"disconnect", nil, "bind read failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts, done := ldapFixture(t, request, tt.response)
			conn, err := Connect(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			err = conn.Bind("user", "secret", "example.test")
			awaitLDAPFixture(t, done)
			if tt.wantError == "" {
				if err != nil || !conn.bound {
					t.Fatalf("bind did not succeed: bound=%v, err=%v", conn.bound, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantError) || conn.bound {
				t.Fatalf("bind = bound %v, err %v; want %q and unbound", conn.bound, err, tt.wantError)
			}
		})
	}
}

func TestAnonymousBindLocalFixture(t *testing.T) {
	for _, tt := range []struct {
		name    string
		code    byte
		allowed bool
	}{
		{"accepted", 0, true}, {"rejected", 49, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts, done := ldapFixture(t, "300c020101600702010304008000", []byte{0x30, 12, 2, 1, 1, 0x61, 7, 0x0a, 1, tt.code, 4, 0, 4, 0})
			allowed, err := CheckAnonymousBind(opts.Host, opts.Port, opts.Timeout)
			awaitLDAPFixture(t, done)
			if allowed != tt.allowed || (err == nil) != tt.allowed {
				t.Fatalf("anonymous bind = %v, %v; allowed=%v", allowed, err, tt.allowed)
			}
		})
	}
}

func TestEnumerateUsersDoesNotReportEmptySuccess(t *testing.T) {
	users, err := EnumerateUsers(LDAPOptions{Host: "127.0.0.1", Port: 0, Timeout: 1}, "(objectClass=user)")
	if err == nil || len(users) != 0 || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("unsupported search = %+v, %v", users, err)
	}
}
