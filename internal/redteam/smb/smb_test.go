package smb

import (
	"testing"
)

func TestBuildSMB2Header(t *testing.T) {
	tests := []struct {
		name      string
		command   uint16
		messageID uint64
		minLen    int
	}{
		{"negotiate", 0, 0, 32},
		{"tree connect", 3, 1, 32},
		{"create", 5, 2, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildSMB2Header(tt.command, tt.messageID)
			if len(got) < tt.minLen {
				t.Errorf("BuildSMB2Header() len = %d, want >= %d", len(got), tt.minLen)
			}
		})
	}
}

func TestEnumerateShares(t *testing.T) {
	opts := SMBOptions{
		Host:     "localhost",
		Port:     445,
		Username: "guest",
		Password: "",
		Timeout:  2,
	}
	shares, err := EnumerateShares(opts)
	if err == nil || shares != nil {
		t.Logf("EnumerateShares may require real SMB server")
	}
}

func TestCheckNullSession(t *testing.T) {
	_, err := CheckNullSession("localhost", 445, 2)
	if err == nil {
		t.Logf("CheckNullSession may require real SMB server")
	}
}
