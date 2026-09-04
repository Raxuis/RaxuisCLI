package ports

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestParsePortRangeSingle(t *testing.T) {
	got, err := parsePortRange("80")
	if err != nil {
		t.Fatalf("parsePortRange returned error: %v", err)
	}
	if len(got) != 1 || got[0] != 80 {
		t.Errorf("parsePortRange(80) = %v, want [80]", got)
	}
}

func TestParsePortRangeRange(t *testing.T) {
	got, err := parsePortRange("20-22")
	if err != nil {
		t.Fatalf("parsePortRange returned error: %v", err)
	}
	want := []int{20, 21, 22}
	if len(got) != len(want) {
		t.Fatalf("parsePortRange(20-22) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parsePortRange(20-22)[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestParsePortRangeCommaList(t *testing.T) {
	got, err := parsePortRange("22,80,443")
	if err != nil {
		t.Fatalf("parsePortRange returned error: %v", err)
	}
	want := []int{22, 80, 443}
	if len(got) != len(want) {
		t.Fatalf("parsePortRange(22,80,443) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %d, want %d", i, got[i], want[i])
		}
	}
}

func TestParsePortRangeMixed(t *testing.T) {
	got, err := parsePortRange("22,80-82,443")
	if err != nil {
		t.Fatalf("parsePortRange returned error: %v", err)
	}
	want := []int{22, 80, 81, 82, 443}
	if len(got) != len(want) {
		t.Fatalf("parsePortRange(22,80-82,443) = %v, want %v", got, want)
	}
}

func TestParsePortRangeErrors(t *testing.T) {
	tests := []string{
		"notaport",
		"0",
		"70000",
		"1-notaport",
		"1-2-3",
		"70000-70001",
		"1000-1",
		"a,b",
	}
	for _, in := range tests {
		if _, err := parsePortRange(in); err == nil {
			t.Errorf("parsePortRange(%q) should return an error", in)
		}
	}
}

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{0, false},
		{1, true},
		{65535, true},
		{65536, false},
		{-1, false},
	}
	for _, tt := range tests {
		if got := isValidPort(tt.port); got != tt.want {
			t.Errorf("isValidPort(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestExpandPresetRanges(t *testing.T) {
	tests := []struct {
		input      string
		wantPreset bool
	}{
		{"common", true},
		{"web", true},
		{"database", true},
		{"dev", true},
		{"system", true},
		{"all", true},
		{"extended", true},
		{"COMMON", true}, // case-insensitive
		{"22,80,443", false},
	}

	for _, tt := range tests {
		got := expandPresetRanges(tt.input)
		if tt.wantPreset && got == tt.input {
			t.Errorf("expandPresetRanges(%q) did not expand the preset, got %q", tt.input, got)
		}
		if !tt.wantPreset && got != tt.input {
			t.Errorf("expandPresetRanges(%q) = %q, want unchanged %q", tt.input, got, tt.input)
		}
	}
}

func TestGetServiceName(t *testing.T) {
	if got := getServiceName(80); got != "(HTTP)" {
		t.Errorf("getServiceName(80) = %q, want (HTTP)", got)
	}
	if got := getServiceName(65000); got != "" {
		t.Errorf("getServiceName(65000) = %q, want empty string for unknown port", got)
	}
}

func TestScanTCPOpenAndClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ps := &PortScanner{timeout: 2 * time.Second, scanType: "tcp"}

	if status := ps.scanTCP(ln.Addr().String()); status != "open" {
		t.Errorf("scanTCP against a listening port = %q, want open", status)
	}

	// Grab an address, then close the listener so nothing is listening there.
	closedAddr := ln.Addr().String()
	ln.Close()
	if status := ps.scanTCP(closedAddr); status != "closed" {
		t.Errorf("scanTCP against a closed port = %q, want closed", status)
	}
}

func TestScanPortDispatchesByType(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ps := &PortScanner{host: host, timeout: 2 * time.Second, scanType: "tcp"}
	result := ps.scanPort(port)
	if result.Status != "open" {
		t.Errorf("scanPort(tcp) status = %q, want open", result.Status)
	}
	if result.Port != port {
		t.Errorf("scanPort result.Port = %d, want %d", result.Port, port)
	}
}

func TestScanPortsPopulatesResults(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	openPort, _ := strconv.Atoi(portStr)

	ps := &PortScanner{host: host, timeout: 500 * time.Millisecond, scanType: "tcp"}
	ps.scanPorts([]int{openPort})

	if len(ps.results) != 1 {
		t.Fatalf("expected 1 open port result, got %d: %v", len(ps.results), ps.results)
	}
	if ps.results[0].Port != openPort {
		t.Errorf("result port = %d, want %d", ps.results[0].Port, openPort)
	}
}

func TestScanEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())

	// Scan() prints to stdout and doesn't return anything, so this just
	// exercises the full parse -> scan -> display pipeline without panicking.
	Scan(Options{Host: host, PortRange: portStr, Timeout: 2, ScanType: "tcp"})
}

func TestScanInvalidPortRange(t *testing.T) {
	// Should print an error and return, not panic.
	Scan(Options{Host: "127.0.0.1", PortRange: "not-a-port", Timeout: 1, ScanType: "tcp"})
}
