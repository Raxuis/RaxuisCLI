// Package netutil provides the common input and execution contract for network probes.
package netutil

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ParsePorts accepts comma-separated ports and ascending ranges, preserving first occurrence.
func ParsePorts(spec string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)
	for _, part := range strings.Split(spec, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid port range: %q", part)
		}
		start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
		if err != nil || !ValidPort(start) {
			return nil, fmt.Errorf("invalid port: %q (expected 1-65535)", part)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil || !ValidPort(end) || end < start {
				return nil, fmt.Errorf("invalid port range: %q (expected ascending ports in 1-65535)", part)
			}
		}
		for p := start; p <= end; p++ {
			if !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}
	return ports, nil
}

func ValidPort(port int) bool { return port >= 1 && port <= 65535 }

// NormalizeHost accepts a hostname or IP literal, including bracketed IPv6.
func NormalizeHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	// IPv6 interface zones are valid dial targets.
	if ip, _, ok := strings.Cut(host, "%"); ok && net.ParseIP(ip) != nil && strings.Contains(ip, ":") && !strings.ContainsAny(host, " /\\\t\r\n") {
		return host, nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("invalid host: %q", host)
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid host: %q", host)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", fmt.Errorf("invalid host: %q", host)
			}
		}
	}
	return host, nil
}

// Timeout uses the same bounded default for all TCP probe entry points.
func Timeout(seconds int) time.Duration {
	if seconds <= 0 {
		return 2 * time.Second
	}
	maxSeconds := (1<<63 - 1) / int64(time.Second)
	if int64(seconds) > maxSeconds {
		return time.Duration(1<<63 - 1)
	}
	return time.Duration(seconds) * time.Second
}

// UniquePorts returns a sorted copy without duplicate probes.
func UniquePorts(ports []int) []int {
	out := append([]int(nil), ports...)
	sort.Ints(out)
	return compact(out)
}
func compact(ports []int) []int {
	var out []int
	for _, p := range ports {
		if len(out) == 0 || p != out[len(out)-1] {
			out = append(out, p)
		}
	}
	return out
}

// ForEach bounds both active probes and goroutines and stops scheduling on cancellation.
func ForEach[T any](ctx context.Context, items []T, concurrency int, probe func(T)) {
	if concurrency <= 0 {
		concurrency = 100
	}
	if concurrency > len(items) {
		concurrency = len(items)
	}
	jobs := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() == nil {
					probe(item)
				}
			}
		}()
	}
	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- item:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
}

// Dial performs a context-aware connection with the caller's probe timeout.
func Dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = Timeout(0)
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, address)
}
