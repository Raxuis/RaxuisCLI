package network

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"raxuiscli/cmd"
	"raxuiscli/internal/network/recon"

	"github.com/spf13/cobra"
)

var reconPorts string
var reconTimeout int
var reconTLS bool

var reconCmd = &cobra.Command{
	Use:   "recon [host:port | host]",
	Short: "Banner grabbing and service detection",
	Long: `Perform service reconnaissance through banner grabbing and fingerprinting.

Connects to services and attempts to identify them through banner analysis.
Supports automatic TLS detection for secure services.

Examples:
  raxuiscli recon example.com:22            # Single port
  raxuiscli recon example.com:80            # HTTP banner grab
  raxuiscli recon example.com --ports 21,22,80,443  # Multiple ports
  raxuiscli recon example.com --ports 1-1024 # Port range
  raxuiscli recon example.com --ports common # Common ports`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// Parse target (host:port or just host)
		host, port := parseTarget(target)

		var ports []int
		var err error

		if port > 0 {
			// Single port specified in target
			ports = []int{port}
		} else if reconPorts != "" {
			// Ports specified via flag
			if reconPorts == "common" {
				ports = recon.GetCommonPorts()
			} else {
				ports, err = recon.ParsePorts(reconPorts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error parsing ports: %v\n", err)
					os.Exit(1)
				}
			}
		} else {
			// Default: common ports
			ports = recon.GetCommonPorts()
		}

		if len(ports) == 1 {
			// Single port - detailed view
			result := recon.BannerGrab(host, ports[0], reconTimeout, reconTLS)
			recon.DisplayResult(result)
		} else {
			// Multiple ports - summary view
			fmt.Printf("Scanning %s with %d ports...\n", host, len(ports))
			opts := recon.ReconOptions{
				Host:    host,
				Ports:   ports,
				Timeout: reconTimeout,
				TLS:     reconTLS,
			}
			results := recon.ReconMultiple(opts)
			recon.DisplayResults(results)
		}
	},
}

// parseTarget extracts host and optional port from target string
func parseTarget(target string) (string, int) {
	// Check for host:port format
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err == nil && port > 0 && port <= 65535 {
				return parts[0], port
			}
		}
	}
	return target, 0
}

func init() {
	cmd.RootCmd.AddCommand(reconCmd)

	reconCmd.Flags().StringVarP(&reconPorts, "ports", "p", "", "Ports to scan (e.g., 80,443 or 1-1024 or 'common')")
	reconCmd.Flags().IntVarP(&reconTimeout, "timeout", "t", 5, "Connection timeout in seconds")
	reconCmd.Flags().BoolVar(&reconTLS, "tls", false, "Force TLS connection")
}
