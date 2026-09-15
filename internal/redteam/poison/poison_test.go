package poison

import (
	"strings"
	"testing"
)

func TestGenerateResponderCommand(t *testing.T) {
	cmd := GenerateResponderCommand("eth0", map[string]bool{})
	if cmd == "" {
		t.Errorf("GenerateResponderCommand() returned empty string")
	}
	if !strings.Contains(cmd, "responder") {
		t.Errorf("GenerateResponderCommand() missing 'responder': %q", cmd)
	}
}

func TestGenerateBettercapCommand(t *testing.T) {
	cmd := GenerateBettercapCommand("eth0", []string{"arp"})
	if cmd == "" {
		t.Errorf("GenerateBettercapCommand() returned empty string")
	}
	if !strings.Contains(cmd, "bettercap") {
		t.Errorf("GenerateBettercapCommand() missing 'bettercap': %q", cmd)
	}
}

func TestGetARPPoisonCommand(t *testing.T) {
	cmds := GetARPPoisonCommand("192.168.1.100", "192.168.1.1", "eth0")
	if len(cmds) == 0 {
		t.Errorf("GetARPPoisonCommand() returned empty")
	}
	found := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "arpspoof") || strings.Contains(cmd, "ettercap") || strings.Contains(cmd, "bettercap") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetARPPoisonCommand() no poison tools found")
	}
}

func TestGetDHCPPoisonInfo(t *testing.T) {
	info := GetDHCPPoisonInfo()
	if len(info) == 0 {
		t.Errorf("GetDHCPPoisonInfo() returned empty")
	}
}

func TestBuildLLMNRResponse(t *testing.T) {
	txnID := []byte{0x12, 0x34}
	resp := BuildLLMNRResponse(txnID, "target.local", "192.168.1.100")
	if len(resp) == 0 {
		t.Errorf("BuildLLMNRResponse() returned empty response")
	}
}

func TestAnalyzeNetwork(t *testing.T) {
	findings := AnalyzeNetwork("lo", 1)
	if findings == nil {
		t.Errorf("AnalyzeNetwork() returned nil")
	}
}
