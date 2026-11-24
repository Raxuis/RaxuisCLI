package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/shared/catalog"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

func TestPublicCLI(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "raxuiscli")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	build := exec.Command("go", "build", "-o", executable, ".")
	if data, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, data)
	}
	run := func(args ...string) ([]byte, []byte, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, executable, args...)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		if ctx.Err() != nil {
			t.Fatalf("command timed out: %v", args)
		}
		code := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		return stdout.Bytes(), stderr.Bytes(), code
	}
	t.Run("all command help", func(t *testing.T) {
		for _, entry := range catalog.All() {
			args := append(strings.Fields(entry.Path)[1:], "--help")
			stdout, stderr, code := run(args...)
			if code != 0 || len(stdout) == 0 || len(stderr) != 0 {
				t.Errorf("%s: exit=%d stdout=%q stderr=%q", entry.Path, code, stdout, stderr)
			}
		}
	})
	t.Run("operational failures", func(t *testing.T) {
		cases := [][]string{
			{"pwgen", "--length", "-1"},
			{"pwgen", "--length", "0"},
			{"pwgen", "generate", "--length", "100001"},
			{"pwgen", "generate", "--count", "0"},
			{"pwgen", "generate", "--count", "-1"},
			{"keygen", "aes", "--bits", "7"},
			{"keygen", "ecdsa", "--curve", "invalid"},
			{"keygen", "cert"},
			{"keygen", "random", "--length", "-1"},
			{"jwt", "decode", "invalid"},
			{"jwt", "verify"},
			{"jwt", "forge", "--payload", "{"},
			{"cookie", "flask", "invalid"},
			{"fuzz", "dir"},
			{"http", "get"},
			{"http", "get", "http://127.0.0.1:0"},
			{"todo", "complete", "invalid"},
			{"audit", "dns", "https://example.test"},
			{"audit", "tls", "example.test:65536"},
			{"audit", "web", "ftp://example.test"},
			{"audit", "all", "ftp://example.test"},
		}
		for _, args := range cases {
			stdout, stderr, code := run(args...)
			if code != 1 || len(stderr) == 0 || len(stdout) != 0 {
				t.Errorf("%v: exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
			}
		}
	})
	t.Run("password generation is scriptable", func(t *testing.T) {
		for _, path := range [][]string{{"pwgen"}, {"pwgen", "generate"}} {
			args := append(append([]string{}, path...), "--output=json", "--length=24", "--count=2", "--no-symbols", "--no-numbers")
			stdout, stderr, code := run(args...)
			var value struct {
				Passwords []string `json:"passwords"`
			}
			if code != 0 || len(stderr) != 0 || json.Unmarshal(stdout, &value) != nil || len(value.Passwords) != 2 {
				t.Fatalf("%v: exit=%d stdout=%s stderr=%s", args, code, stdout, stderr)
			}
			for _, password := range value.Passwords {
				if len(password) != 24 || strings.IndexFunc(password, func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') }) >= 0 {
					t.Fatalf("unexpected password: %q", password)
				}
			}
			stdout, stderr, code = run(append(append([]string{}, path...), "--length=20")...)
			if code != 0 || len(stderr) != 0 || !strings.HasPrefix(string(stdout), "Password 1: ") || strings.Contains(string(stdout), "clipboard?") {
				t.Fatalf("non-interactive generation: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		}
	})
	t.Run("offline utility results", func(t *testing.T) {
		cases := []struct {
			args []string
			want string
		}{
			{[]string{"encode", "hello", "--format=base64"}, "aGVsbG8="},
			{[]string{"encode", "decode", "aGVsbG8=", "--format=base64"}, "hello"},
			{[]string{"encode", "hello", "--format=hex"}, "68656c6c6f"},
			{[]string{"encode", "hello world", "--format=url"}, "hello+world"},
			{[]string{"hash", "hello", "--algo=md5"}, "5d41402abc4b2a76b9719d911017c592"},
			{[]string{"hash", "hello", "--algo=sha256"}, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
			{[]string{"cipher", "caesar", "Hello", "--shift=3"}, "Khoor"},
			{[]string{"cipher", "rot13", "Hello"}, "Uryyb"},
			{[]string{"cipher", "atbash", "Hello"}, "Svool"},
			{[]string{"hashid", "5d41402abc4b2a76b9719d911017c592"}, "MD5"},
		}
		for _, tc := range cases {
			stdout, stderr, code := run(tc.args...)
			if code != 0 || len(stderr) != 0 || !strings.Contains(string(stdout), tc.want) {
				t.Errorf("%v: exit=%d stdout=%q stderr=%q; want %q", tc.args, code, stdout, stderr, tc.want)
			}
		}
	})
	t.Run("offline JSON output", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "input.txt")
		if err := os.WriteFile(input, []byte("hello world\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"version"},
			{"doctor"},
			{"keygen", "aes"},
			{"keygen", "random"},
			{"keygen", "ed25519"},
			{"cipher", "detect", "hello"},
			{"cookie", "decode", "session=abc"},
			{"cookie", "bulk", "session=abc", "user=def"},
			{"vuln", "payloads", "xss"},
			{"jwt", "forge", "--payload", `{"sub":"local-demo"}`, "--secret=fixture-key"},
			{"encode", "hello"},
			{"encode", "decode", "aGVsbG8=", "--format=base64"},
			{"encode", "rot-brute", "uryyb"},
			{"hash", "hello"},
			{"hash", input, "--file", "--algo=sha256"},
			{"hash", "identify", "5d41402abc4b2a76b9719d911017c592"},
			{"hashid", "5d41402abc4b2a76b9719d911017c592"},
			{"cipher", "caesar", "hello", "--shift=3"},
			{"cipher", "rot13", "hello"},
			{"cipher", "atbash", "hello"},
			{"cipher", "freq", "hello"},
			{"cookie", "analyze", "session=abc; HttpOnly; Secure"},
			{"cookie", "sensitive", "user=admin"},
			{"metadata", input},
			{"entropy", input},
			{"strings", input, "--min=8"},
		} {
			stdout, stderr, code := run(append([]string{"--output=json"}, args...)...)
			if code != 0 || len(stderr) != 0 || !json.Valid(stdout) {
				t.Errorf("%v: exit=%d stdout=%s stderr=%s", args, code, stdout, stderr)
			}
		}
	})

	t.Run("global file output and overwrite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hash.json")
		args := []string{"--output=json", "--output-file", path, "hash", "hello", "--algo=sha256"}
		stdout, stderr, code := run(args...)
		if code != 0 || len(stdout) != 0 || len(stderr) != 0 {
			t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		data, err := os.ReadFile(path)
		var value struct {
			Hash string `json:"hash"`
		}
		if err != nil || json.Unmarshal(data, &value) != nil || value.Hash != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
			t.Fatalf("file=%s error=%v", data, err)
		}
		_, stderr, code = run(args...)
		after, readErr := os.ReadFile(path)
		if code != 1 || len(stderr) == 0 || readErr != nil || !bytes.Equal(data, after) {
			t.Fatalf("overwrite protection: exit=%d error=%v stderr=%s", code, readErr, stderr)
		}
		stdout, stderr, code = run(append(args, "--force")...)
		if code != 0 || len(stdout) != 0 || len(stderr) != 0 {
			t.Fatalf("forced replacement: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})
	t.Run("unsupported format cannot run file deletion", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keep.txt")
		if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := run("--output=json", "files", "shred", path, "--yes")
		data, err := os.ReadFile(path)
		if code != 1 || len(stdout) != 0 || !strings.Contains(string(stderr), "does not support") || err != nil || string(data) != "keep" {
			t.Fatalf("exit=%d stdout=%s stderr=%s file=%q err=%v", code, stdout, stderr, data, err)
		}
	})
	t.Run("file encryption round trip", func(t *testing.T) {
		dir := t.TempDir()
		plain, encrypted, decrypted := filepath.Join(dir, "plain.txt"), filepath.Join(dir, "encrypted.bin"), filepath.Join(dir, "decrypted.txt")
		content := []byte("local CLI round trip\n")
		if err := os.WriteFile(plain, content, 0600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"files", "encrypt", plain, "--password", "local-test-passphrase", "--out", encrypted},
			{"files", "decrypt", encrypted, "--password", "local-test-passphrase", "--out", decrypted},
		} {
			stdout, stderr, code := run(args...)
			if code != 0 {
				t.Fatalf("%v: exit=%d stdout=%s stderr=%s", args, code, stdout, stderr)
			}
		}
		data, err := os.ReadFile(decrypted)
		if err != nil || !bytes.Equal(data, content) {
			t.Fatalf("decrypted=%q err=%v", data, err)
		}
	})
	t.Run("file dry run preserves inputs", func(t *testing.T) {
		dir := t.TempDir()
		input := filepath.Join(dir, "input.txt")
		content := []byte("must survive the dry run")
		if err := os.WriteFile(input, content, 0600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"files", "encrypt", input, "--password=test", "--out", filepath.Join(dir, "encrypted")},
			{"files", "compress", input, "--out", filepath.Join(dir, "archive.zip")},
			{"files", "find", dir, "--exec", "invalid-command-that-must-not-run"},
			{"files", "shred", input, "--yes"},
		} {
			stdout, stderr, code := run(append(args, "--dry-run")...)
			if code != 0 {
				t.Errorf("%v: exit=%d stdout=%s stderr=%s", args, code, stdout, stderr)
			}
			data, err := os.ReadFile(input)
			if err != nil || !bytes.Equal(data, content) {
				t.Fatalf("dry run changed input: %q, %v", data, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Errorf("dry run created files: %v, %v", entries, err)
			}
		}
	})
	t.Run("HTTP methods use requested method", func(t *testing.T) {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"} {
			t.Run(method, func(t *testing.T) {
				seen := make(chan string, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Method; w.WriteHeader(http.StatusNoContent) }))
				defer server.Close()
				stdout, stderr, code := run("--output=json", "http", strings.ToLower(method), server.URL)
				var value struct {
					StatusCode int `json:"status_code"`
				}
				if code != 0 || json.Unmarshal(stdout, &value) != nil || value.StatusCode != 204 {
					t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout, stderr)
				}
				select {
				case got := <-seen:
					if got != method {
						t.Fatalf("method=%s want=%s", got, method)
					}
				default:
					t.Fatal("no request received")
				}
			})
		}
	})
	t.Run("combined local HTTP report", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		defer server.Close()
		stdout, stderr, code := run("--output=json", "audit", "all", server.URL)
		if code != 0 {
			t.Fatalf("exit=%d stderr=%s", code, stderr)
		}
		value, err := report.Read(bytes.NewReader(stdout))
		if err != nil || value.Audit.Kind != "all" || value.Audit.Status != "complete" {
			t.Fatalf("report=%s err=%v", stdout, err)
		}
		skipped := 0
		for _, item := range value.Observations {
			if item.Key == "combined.dns.status" || item.Key == "combined.tls.status" {
				if item.Value != "skipped" {
					t.Fatal(item)
				}
				skipped++
			}
		}
		if skipped != 2 {
			t.Fatalf("expected two skipped stages: %+v", value.Observations)
		}
	})
	t.Run("demo report and policy exit", func(t *testing.T) {
		for _, expected := range []int{0, 2} {
			args := []string{"--output=json", "demo", "web"}
			if expected == 2 {
				args = append(args, "--fail-on=high")
			}
			stdout, stderr, code := run(args...)
			if code != expected {
				t.Fatalf("exit=%d stderr=%s", code, stderr)
			}
			value, err := report.Read(bytes.NewReader(stdout))
			if err != nil || value.Audit.Status == "partial" || len(value.Findings) == 0 {
				t.Fatalf("invalid demo report: %v\n%s", err, stdout)
			}
		}
	})
}
