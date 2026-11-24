package network

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/network/recon"
	"github.com/Raxuis/RaxuisCLI/internal/shared/netutil"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"

	"github.com/spf13/cobra"
)

type serviceOut struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol,omitempty"`
	Banner     string `json:"banner,omitempty"`
	Service    string `json:"service,omitempty"`
	Version    string `json:"version,omitempty"`
	TLS        bool   `json:"tls"`
	TLSVersion string `json:"tls_version,omitempty"`
	ResponseMS int64  `json:"response_ms"`
	Error      string `json:"error,omitempty"`
}

func serviceView(r recon.ServiceResult) serviceOut {
	return serviceOut{
		Host:       r.Host,
		Port:       r.Port,
		Protocol:   r.Protocol,
		Banner:     r.Banner,
		Service:    r.Service,
		Version:    r.Version,
		TLS:        r.TLS,
		TLSVersion: r.TLSVersion,
		ResponseMS: r.ResponseTime.Milliseconds(),
		Error:      errString(r.Error),
	}
}

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
	RunE: func(cmd *cobra.Command, args []string) error {
		if reconTimeout < 0 {
			return fmt.Errorf("timeout must be nonnegative")
		}
		target := args[0]

		// Parse target (host:port or just host)
		host, port, parseErr := parseReconTarget(target)
		if parseErr != nil {
			return parseErr
		}

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
					return fmt.Errorf("error parsing ports: %v", err)
				}
			}
		} else {
			// Default: common ports
			ports = recon.GetCommonPorts()
		}

		if len(ports) == 1 {
			// Single port - detailed view
			result := recon.BannerGrabContext(cmd.Context(), host, ports[0], reconTimeout, reconTLS)
			if result.Error != nil {
				return result.Error
			}
			return output.Emit(serviceView(result), func(_ io.Writer) {
				recon.DisplayResult(result)
			})
		} else {
			// Multiple ports - summary view
			if !output.JSON() {
				fmt.Fprintf(output.Std, "Scanning %s with %d ports...\n", host, len(ports))
			}
			opts := recon.ReconOptions{
				Host:    host,
				Ports:   ports,
				Timeout: reconTimeout,
				TLS:     reconTLS,
			}
			results := recon.ReconMultipleContext(cmd.Context(), opts)
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			failures := 0
			views := make([]serviceOut, 0, len(results))
			for _, r := range results {
				if r.Error != nil {
					failures++
				}
				views = append(views, serviceView(r))
			}
			if err := output.Emit(map[string]any{"host": host, "results": views}, func(_ io.Writer) { recon.DisplayResults(results) }); err != nil {
				return err
			}
			if failures == len(results) {
				return fmt.Errorf("reconnaissance failed for all %d ports", failures)
			}
			return nil
		}
	},
}

// parseReconTarget accepts a hostname or IP with an optional explicit port.
func parseReconTarget(target string) (string, int, error) {
	target = strings.TrimSpace(target)
	if strings.Contains(target, ":") && net.ParseIP(target) == nil {
		host, portText, err := net.SplitHostPort(target)
		if err != nil {
			return "", 0, fmt.Errorf("invalid target %q: %w", target, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || !netutil.ValidPort(port) {
			return "", 0, fmt.Errorf("invalid target port %q", portText)
		}
		host, err = netutil.NormalizeHost(host)
		return host, port, err
	}
	host, err := netutil.NormalizeHost(target)
	return host, 0, err
}

func init() {
	cmd.RootCmd.AddCommand(reconCmd)

	reconCmd.Flags().StringVarP(&reconPorts, "ports", "p", "", "Ports to scan (e.g., 80,443 or 1-1024 or 'common')")
	reconCmd.Flags().IntVarP(&reconTimeout, "timeout", "t", 5, "Connection timeout in seconds")
	reconCmd.Flags().BoolVar(&reconTLS, "tls", false, "Force TLS connection")
}
