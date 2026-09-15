package persist

import (
	"strings"
	"testing"
)

func TestListTechniques(t *testing.T) {
	techniques := ListTechniques()
	if len(techniques) == 0 {
		t.Errorf("ListTechniques() returned empty list")
	}
}

func TestListAllTechniques(t *testing.T) {
	techniques := ListAllTechniques()
	if len(techniques) == 0 {
		t.Errorf("ListAllTechniques() returned empty list")
	}
}

func TestGenerateCronPersistence(t *testing.T) {
	cmd := GenerateCronPersistence("/tmp/beacon.sh", "* * * * *")
	if cmd == "" {
		t.Errorf("GenerateCronPersistence() returned empty string")
	}
	if !strings.Contains(cmd, "cron") && !strings.Contains(cmd, "/tmp/beacon.sh") {
		t.Errorf("GenerateCronPersistence() missing cron or command reference: %q", cmd)
	}
}

func TestGenerateSystemdService(t *testing.T) {
	cmd := GenerateSystemdService("beacon", "/tmp/beacon.sh", "Persistence Service")
	if cmd == "" {
		t.Errorf("GenerateSystemdService() returned empty string")
	}
	if !strings.Contains(cmd, "beacon") || !strings.Contains(cmd, "/tmp/beacon.sh") {
		t.Errorf("GenerateSystemdService() missing service or command: %q", cmd)
	}
}

func TestGenerateLaunchdPlist(t *testing.T) {
	plist := GenerateLaunchdPlist("com.example.beacon", "/tmp/beacon.sh", true)
	if plist == "" {
		t.Errorf("GenerateLaunchdPlist() returned empty string")
	}
	if !strings.Contains(plist, "com.example.beacon") || !strings.Contains(plist, "/tmp/beacon.sh") {
		t.Errorf("GenerateLaunchdPlist() missing label or command: %q", plist)
	}
}
