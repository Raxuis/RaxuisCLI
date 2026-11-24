package scan

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestRunLoopbackOpenClosedAndDoesNotMutateTargets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	targets := []string{"localhost", "127.0.0.1"}
	original := append([]string(nil), targets...)
	result := Run(Options{Targets: targets, Ports: []int{closedPort, openPort, openPort}, SkipDiscovery: true, Timeout: 1})
	if !reflect.DeepEqual(targets, original) {
		t.Errorf("mutated caller targets: %v", targets)
	}
	for _, host := range result.Hosts {
		if len(host.OpenPorts) != 1 || host.OpenPorts[0].Port != openPort {
			t.Errorf("ports = %v", host.OpenPorts)
		}
	}
}
func TestRunCancellationInterruptsJitter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := RunContext(ctx, Options{Targets: []string{"127.0.0.1"}, Ports: []int{80}, SkipDiscovery: true, Jitter: time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation delayed")
	}
}
func TestParseTargetsNormalizesAndRejectsURLs(t *testing.T) {
	got, err := ParseTargets("LOCALHOST,localhost,[::1],::1")
	if err != nil || !reflect.DeepEqual(got, []string{"localhost", "::1"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, spec := range []string{"http://localhost", "localhost:80", "bad host"} {
		if _, err := ParseTargets(spec); err == nil {
			t.Errorf("accepted %q", spec)
		}
	}
}

func TestRunDiscoversLoopbackHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	result, err := RunContext(context.Background(), Options{Targets: []string{"127.0.0.1"}, DiscoveryPorts: []int{port}, Ports: []int{port}, Timeout: 1})
	if err != nil || result.AliveHosts != 1 || len(result.Hosts) != 1 || len(result.Hosts[0].OpenPorts) != 1 {
		t.Fatalf("result = %+v, %v", result, err)
	}
}
func TestRunCancellationInterruptsBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		first, err := ln.Accept()
		if err != nil {
			return
		}
		first.Close()
		second, err := ln.Accept()
		if err != nil {
			return
		}
		defer second.Close()
		cancel()
	}()
	_, err = RunContext(ctx, Options{Targets: []string{"127.0.0.1"}, Ports: []int{ln.Addr().(*net.TCPAddr).Port}, SkipDiscovery: true, Banner: true, Timeout: 30})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}
