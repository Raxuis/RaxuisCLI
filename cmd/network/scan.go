package network

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/network/recon"
	"github.com/Raxuis/RaxuisCLI/internal/network/scan"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"

	"github.com/spf13/cobra"
)

var (
	scanPorts       string
	scanFull        bool
	scanConcurrency int
	scanTimeout     int
	scanJitter      string
	scanNoDiscovery bool
	scanNoBanner    bool
)

type openPortOut struct {
	Port     int    `json:"port"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
	TLS      bool   `json:"tls"`
	Tag      string `json:"tag,omitempty"`
	NextStep string `json:"next_step,omitempty"`
}

type hostOut struct {
	IP        string        `json:"ip"`
	Hostname  string        `json:"hostname,omitempty"`
	OpenPorts []openPortOut `json:"open_ports"`
}

var scanCmd = &cobra.Command{
	Use:   "scan [targets]",
	Short: "Concurrent host & service discovery (attack-surface mapper)",
	Long: `Map the attack surface of a network: discover live hosts, scan their TCP
services, and tag interesting ones with the raxuiscli command to run next.

Targets may be a single IP or hostname, a comma-separated list, or an IPv4
CIDR (e.g. 10.10.10.0/24). Only run this against networks you are authorized
to test (pentest engagement, CTF, or your own lab).

Examples:
  raxuiscli scan 10.10.10.0/24                       # curated top ports
  raxuiscli scan 10.10.10.5 --ports 1-1024           # custom range
  raxuiscli scan 10.10.10.0/24 --jitter 200ms -c 50  # low & slow
  raxuiscli scan 192.168.1.10 --full --no-discovery  # all 65535 ports
  raxuiscli --output=json scan 10.0.0.0/24 > surface.json`,
	Args: cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		targets, err := scan.ParseTargets(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		ports, err := resolveScanPorts()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		var jitter time.Duration
		if scanJitter != "" {
			jitter, err = time.ParseDuration(scanJitter)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid --jitter %q: %v\n", scanJitter, err)
				os.Exit(1)
			}
		}

		if !output.JSON() {
			fmt.Printf("Scanning %d target(s) across %d ports (concurrency %d)...\n",
				len(targets), len(ports), scanConcurrency)
		}

		result := scan.Run(scan.Options{
			Targets:       targets,
			Ports:         ports,
			Concurrency:   scanConcurrency,
			Timeout:       scanTimeout,
			Jitter:        jitter,
			SkipDiscovery: scanNoDiscovery,
			Banner:        !scanNoBanner,
		})

		hosts := make([]hostOut, 0, len(result.Hosts))
		for _, h := range result.Hosts {
			ports := make([]openPortOut, 0, len(h.OpenPorts))
			for _, p := range h.OpenPorts {
				ports = append(ports, openPortOut{
					Port: p.Port, Service: p.Service, Version: p.Version,
					Banner: p.Banner, TLS: p.TLS, Tag: p.Tag, NextStep: p.NextStep,
				})
			}
			hosts = append(hosts, hostOut{IP: h.IP, Hostname: h.Hostname, OpenPorts: ports})
		}

		payload := map[string]any{
			"targets":     result.Targets,
			"alive_hosts": result.AliveHosts,
			"duration_ms": result.Duration.Milliseconds(),
			"hosts":       hosts,
		}
		_ = output.Emit(payload, func(w io.Writer) { renderScan(w, result) })
	},
}

func resolveScanPorts() ([]int, error) {
	switch {
	case scanFull:
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	case scanPorts != "":
		if scanPorts == "common" {
			return recon.GetCommonPorts(), nil
		}
		return recon.ParsePorts(scanPorts)
	default:
		return scan.DefaultTopPorts, nil
	}
}

func renderScan(w io.Writer, r *scan.Result) {
	openHosts := 0
	for _, h := range r.Hosts {
		if len(h.OpenPorts) == 0 {
			continue
		}
		openHosts++

		title := h.IP
		if h.Hostname != "" {
			title = fmt.Sprintf("%s   %s", h.IP, h.Hostname)
		}
		fmt.Fprintf(w, "\n%s\n", title)
		for _, p := range h.OpenPorts {
			svc := p.Service
			if p.Version != "" {
				svc = fmt.Sprintf("%s %s", p.Service, p.Version)
			}
			line := fmt.Sprintf("  %-9s %-14s", fmt.Sprintf("%d/tcp", p.Port), svc)
			if p.NextStep != "" {
				line += " " + p.NextStep
			}
			fmt.Fprintln(w, line)
		}
	}

	fmt.Fprintf(w, "\n%s\n", "----------------------------------------")
	fmt.Fprintf(w, "%d/%d hosts alive, %d with open ports  (%.1fs)\n",
		r.AliveHosts, r.Targets, openHosts, r.Duration.Seconds())
}

func init() {
	cmd.RootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanPorts, "ports", "p", "", "Ports to scan: list/range (e.g. 22,80,443 or 1-1024), or 'common' (default: curated top ports)")
	scanCmd.Flags().BoolVar(&scanFull, "full", false, "Scan all 65535 TCP ports (overrides --ports)")
	scanCmd.Flags().IntVarP(&scanConcurrency, "concurrency", "c", 100, "Maximum concurrent connections")
	scanCmd.Flags().IntVarP(&scanTimeout, "timeout", "t", 2, "Per-connection timeout in seconds")
	scanCmd.Flags().StringVar(&scanJitter, "jitter", "", "Random delay before each connection (e.g. 200ms) for low & slow scans")
	scanCmd.Flags().BoolVar(&scanNoDiscovery, "no-discovery", false, "Skip host-liveness probing; scan every target directly")
	scanCmd.Flags().BoolVar(&scanNoBanner, "no-banner", false, "Skip banner grabbing (faster, quieter, port-based service names only)")
}
