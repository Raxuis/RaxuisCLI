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

func TestGenerateCronPersist(t *testing.T) {
	cmd := GenerateCronPersist("* * * * * /tmp/beacon.sh")
	if cmd == "" {
		t.Errorf("GenerateCronPersist() returned empty string")
	}
	if !strings.Contains(cmd, "crontab") && !strings.Contains(cmd, "cron") {
		t.Errorf("GenerateCronPersist() missing cron reference: %q", cmd)
	}
}

func TestGenerateSSHPersist(t *testing.T) {
	cmd := GenerateSSHPersist("authorized_keys", "ssh-rsa AAAA...")
	if cmd == "" {
		t.Errorf("GenerateSSHPersist() returned empty string")
	}
}

func TestGetPersistPath(t *testing.T) {
	path := GetPersistPath()
	if path == "" {
		t.Errorf("GetPersistPath() returned empty string")
	}
}
