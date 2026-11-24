package recon

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestParsePortsRejectsMalformedOrOutOfRange(t *testing.T) {
	for _, spec := range []string{"80junk", "0", "65536", "0-2", "1-65536", "80,", "22-20"} {
		if got, err := ParsePorts(spec); err == nil {
			t.Errorf("ParsePorts(%q) = %v without error", spec, got)
		}
	}
}

func TestReconMultipleStableUniqueOrder(t *testing.T) {
	results := ReconMultiple(ReconOptions{Host: "127.0.0.1", Ports: []int{0, 0, -1}, Timeout: 1})
	var ports []int
	for _, result := range results {
		ports = append(ports, result.Port)
		if result.Error == nil {
			t.Error("invalid port should have error")
		}
	}
	if !reflect.DeepEqual(ports, []int{-1, 0}) {
		t.Fatalf("ports = %v", ports)
	}
}

func TestBannerGrabHonorsReadTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-done
	}()
	start := time.Now()
	result := BannerGrab("127.0.0.1", listenerPort(t, ln.Addr().String()), 1, false)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("1s timeout took %s", elapsed)
	}
}

func TestBannerGrabCancellationInterruptsRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		cancel()
	}()
	result := BannerGrabContext(ctx, "127.0.0.1", listenerPort(t, ln.Addr().String()), 30, false)
	if !errors.Is(result.Error, context.Canceled) {
		t.Fatalf("error = %v", result.Error)
	}
}

func TestBannerGrabPropagatesCallerDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-done
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := BannerGrabContext(ctx, "127.0.0.1", listenerPort(t, ln.Addr().String()), 30, false)
	if !errors.Is(result.Error, context.DeadlineExceeded) {
		t.Fatalf("error = %v", result.Error)
	}
}
