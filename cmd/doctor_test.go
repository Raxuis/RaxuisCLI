package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
)

func TestDoctorEmptyPathJSON(t *testing.T) {
	t.Setenv("PATH", "")
	var stdout bytes.Buffer
	output.Set(&stdout)
	output.SetFormat("json")
	t.Cleanup(func() { output.Set(nil); output.SetFormat("") })
	command := newDoctorCommand()
	command.SetArgs(nil)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var result struct {
		OS           string `json:"os"`
		Arch         string `json:"arch"`
		GoVersion    string `json:"go_version"`
		DockerDaemon string `json:"docker_daemon"`
		Tools        []struct {
			Name      string `json:"name"`
			Installed bool   `json:"installed"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if result.OS != runtime.GOOS || result.Arch != runtime.GOARCH || result.GoVersion != runtime.Version() {
		t.Fatalf("runtime information = %+v", result)
	}
	if result.DockerDaemon != "not_checked" {
		t.Fatalf("daemon incorrectly inferred: %q", result.DockerDaemon)
	}
	if len(result.Tools) < 4 {
		t.Fatalf("missing optional tool diagnostics: %+v", result.Tools)
	}
	for _, tool := range result.Tools {
		if tool.Installed {
			t.Errorf("empty PATH reported installed tool %s", tool.Name)
		}
	}
}

func TestDoctorLooksUpToolsWithoutExecutingThem(t *testing.T) {
	directory := t.TempDir()
	executable := "docker"
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	// Deliberately not executable machine code: discovering it must not run it.
	if err := os.WriteFile(filepath.Join(directory, executable), []byte("this must never execute"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	var stdout bytes.Buffer
	output.Set(&stdout)
	output.SetFormat("json")
	t.Cleanup(func() { output.Set(nil); output.SetFormat("") })
	command := newDoctorCommand()
	command.SetArgs(nil)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var result struct {
		DockerDaemon string `json:"docker_daemon"`
		Tools        []struct {
			Name      string `json:"name"`
			Installed bool   `json:"installed"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range result.Tools {
		if tool.Name == "docker" {
			found = tool.Installed
		}
	}
	if !found || result.DockerDaemon != "not_checked" {
		t.Fatalf("installed docker must not imply a running daemon: %+v", result)
	}
}

type doctorFailWriter struct{ err error }

func (w doctorFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDoctorPropagatesOutputFailure(t *testing.T) {
	sentinel := errors.New("doctor output failure")
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			output.Set(doctorFailWriter{sentinel})
			output.SetFormat(format)
			t.Cleanup(func() { output.Set(nil); output.SetFormat("") })
			command := newDoctorCommand()
			command.SetArgs(nil)
			command.SetErr(&bytes.Buffer{})
			if err := command.Execute(); !errors.Is(err, sentinel) {
				t.Fatalf("output error = %v, want sentinel", err)
			}
		})
	}
}

func TestDoctorTextAndArguments(t *testing.T) {
	t.Setenv("PATH", "")
	var stdout bytes.Buffer
	output.Set(&stdout)
	output.SetFormat("text")
	t.Cleanup(func() { output.Set(nil); output.SetFormat("") })
	command := newDoctorCommand()
	command.SetArgs(nil)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{runtime.GOOS, runtime.GOARCH, runtime.Version(), "not checked", "docker", "missing", "Terminal"} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Errorf("text output lacks %q: %q", fragment, stdout.String())
		}
	}
	command = newDoctorCommand()
	command.SetArgs([]string{"unexpected"})
	command.SetErr(&bytes.Buffer{})
	if err := command.Execute(); err == nil {
		t.Fatal("doctor accepted an argument")
	}
}
