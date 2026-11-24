package network

import (
	"context"
	"testing"
)

func TestReconTargetValidation(t *testing.T) {
	for _, tc := range []struct {
		input, host string
		port        int
	}{
		{"example.test", "example.test", 0}, {"example.test:443", "example.test", 443}, {"2001:db8::1", "2001:db8::1", 0}, {"[2001:db8::1]:443", "2001:db8::1", 443},
	} {
		h, p, e := parseReconTarget(tc.input)
		if e != nil || h != tc.host || p != tc.port {
			t.Errorf("%q: (%q,%d,%v)", tc.input, h, p, e)
		}
	}
	for _, input := range []string{"", ":443", "example.test:0", "example.test:65536", "example.test:bad", "https://example.test"} {
		if _, _, e := parseReconTarget(input); e == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestScanHonorsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanCmd.SetContext(ctx)
	defer scanCmd.SetContext(context.Background())
	oldNoDiscovery, oldNoBanner, oldPorts := scanNoDiscovery, scanNoBanner, scanPorts
	scanNoDiscovery = true
	scanNoBanner = true
	scanPorts = "1"
	defer func() { scanNoDiscovery = oldNoDiscovery; scanNoBanner = oldNoBanner; scanPorts = oldPorts }()
	if err := scanCmd.RunE(scanCmd, []string{"127.0.0.1"}); err == nil {
		t.Fatal("canceled scan succeeded")
	}
}
