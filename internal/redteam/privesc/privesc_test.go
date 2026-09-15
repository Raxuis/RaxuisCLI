package privesc

import (
	"testing"
)

func TestGetSystemInfo(t *testing.T) {
	info := GetSystemInfo()
	if info.Hostname == "" {
		t.Errorf("GetSystemInfo().Hostname empty")
	}
	if info.CurrentUser == "" {
		t.Errorf("GetSystemInfo().CurrentUser empty")
	}
	if info.OS == "" {
		t.Errorf("GetSystemInfo().OS empty")
	}
}

func TestCheckSUID(t *testing.T) {
	results := CheckSUID()
	if results == nil {
		t.Errorf("CheckSUID() returned nil")
	}
}

func TestCheckSudo(t *testing.T) {
	results := CheckSudo()
	if results == nil {
		t.Errorf("CheckSudo() returned nil")
	}
}

func TestCheckCapabilities(t *testing.T) {
	results := CheckCapabilities()
	if results == nil {
		t.Errorf("CheckCapabilities() returned nil")
	}
}

func TestCheckCron(t *testing.T) {
	results := CheckCron()
	if results == nil {
		t.Errorf("CheckCron() returned nil")
	}
}

func TestCheckWritablePaths(t *testing.T) {
	results := CheckWritablePaths()
	if results == nil {
		t.Errorf("CheckWritablePaths() returned nil")
	}
}

func TestCheckPasswordFiles(t *testing.T) {
	results := CheckPasswordFiles()
	if results == nil {
		t.Errorf("CheckPasswordFiles() returned nil")
	}
}

func TestCheckSSHKeys(t *testing.T) {
	results := CheckSSHKeys()
	if results == nil {
		t.Errorf("CheckSSHKeys() returned nil")
	}
}

func TestCheckDockerSocket(t *testing.T) {
	results := CheckDockerSocket()
	if results == nil {
		t.Errorf("CheckDockerSocket() returned nil")
	}
}

func TestRunAllChecks(t *testing.T) {
	opts := Options{}
	results := RunAllChecks(opts)
	if results == nil {
		t.Errorf("RunAllChecks() returned nil")
	}
	if len(results) == 0 {
		t.Errorf("RunAllChecks() returned empty results")
	}
}
