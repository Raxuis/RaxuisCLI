package main

import (
	"bytes"
	"context"
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
		}
		for _, args := range cases {
			stdout, stderr, code := run(args...)
			if code != 1 || len(stderr) == 0 || len(stdout) != 0 {
				t.Errorf("%v: exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
			}
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
