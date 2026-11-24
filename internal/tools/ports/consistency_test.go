package ports

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
)

func TestParsePortRangeDeduplicates(t *testing.T) {
	got, err := parsePortRange(" 80 , 79-80 , 80 ")
	if err != nil || !reflect.DeepEqual(got, []int{80, 79}) {
		t.Fatalf("got %v, %v", got, err)
	}
}
func TestScanResultsSilentAndNormalized(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var output bytes.Buffer
	old := stdoutW
	stdoutW = &output
	defer func() { stdoutW = old }()
	results, err := ScanResults(Options{Host: " 127.0.0.1 ", PortRange: port + "," + port, Timeout: 1, ScanType: "tcp"})
	if err != nil || len(results) != 1 {
		t.Fatalf("got %v, %v", results, err)
	}
	if output.Len() != 0 {
		t.Fatalf("machine readable scan printed %q", output.String())
	}
}
func TestScanResultsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanResultsContext(ctx, Options{Host: "127.0.0.1", PortRange: "1-65535", Timeout: 30})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}
func TestScanResultsRejectsInvalidHostAndType(t *testing.T) {
	for _, opts := range []Options{{Host: "", PortRange: "80"}, {Host: "http://localhost", PortRange: "80"}, {Host: "localhost", PortRange: "80", ScanType: "sctp"}} {
		if _, err := ScanResults(opts); err == nil {
			t.Errorf("accepted %+v", opts)
		}
	}
}

func TestScanResultsIPv6(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	results, err := ScanResults(Options{Host: "[::1]", PortRange: port, Timeout: 1})
	if err != nil || len(results) != 1 || results[0].Status != "open" {
		t.Fatalf("results = %v, %v", results, err)
	}
}
func TestScanResultsUDPReportsAmbiguousPort(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	results, err := ScanResults(Options{Host: "127.0.0.1", PortRange: port, Timeout: 1, ScanType: "udp"})
	if err != nil || len(results) != 1 || results[0].Status != "open|filtered" {
		t.Fatalf("results = %v, %v", results, err)
	}
}
func TestScanResultsUDPCancellationInterruptsRead(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		var buf [1]byte
		_, _, err := conn.ReadFrom(buf[:])
		if err == nil {
			cancel()
		}
	}()
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	_, err = ScanResultsContext(ctx, Options{Host: "127.0.0.1", PortRange: port, Timeout: 30, ScanType: "udp"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}
