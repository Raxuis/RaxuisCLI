package redteam

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/pivot"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var pivotLocal string
var pivotRemote string
var pivotUsername string
var pivotPassword string

var pivotCmd = &cobra.Command{
	Use:   "pivot",
	Short: "Network pivoting and proxying",
	Long: `Network pivoting toolkit for creating proxies and port forwards.

Create SOCKS5 proxies, TCP port forwards, and reverse tunnels
for lateral movement and network pivoting.

Examples:
  raxuiscli pivot socks5 --listen :1080           # SOCKS5 proxy
  raxuiscli pivot forward --local :8080 --remote internal:80
  raxuiscli pivot test --remote 10.0.0.1:445      # Test connectivity`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var pivotSocks5Cmd = &cobra.Command{
	Use:   "socks5",
	Short: "Start SOCKS5 proxy",
	Long: `Start a SOCKS5 proxy server for network pivoting.

Traffic can be routed through this proxy to access internal networks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if pivotLocal == "" {
			pivotLocal = ":1080"
		}

		auth := pivotUsername != "" && pivotPassword != ""
		pivot.DisplayProxyInfo(pivot.SOCKS5Proxy, pivotLocal, auth)

		server := pivot.NewSOCKS5Server(pivotLocal, pivotUsername, pivotPassword)

		fmt.Fprintf(output.Std, "Starting SOCKS5 proxy on %s...\n", pivotLocal)

		if err := server.Start(); err != nil {
			return err
		}

		fmt.Fprintln(output.Std, "Proxy started. Press Ctrl+C to stop.")
		fmt.Fprintln(output.Std, "\nUsage examples:")
		fmt.Fprintf(output.Std, "  curl --socks5 %s http://target\n", pivotLocal)
		fmt.Fprintf(output.Std, "  proxychains -q <command>\n")

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Fprintln(output.Std, "\nStopping proxy...")
		_ = server.Stop()
		return nil
	},
}

var pivotForwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "TCP port forwarding",
	Long: `Create a TCP port forward to access remote services.

Forwards local traffic to a remote destination.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if pivotLocal == "" || pivotRemote == "" {
			return fmt.Errorf("both --local and --remote are required")
		}

		pivot.DisplayForwardInfo(pivotLocal, pivotRemote)

		forward := pivot.NewPortForward(pivotLocal, pivotRemote)

		fmt.Fprintf(output.Std, "Starting port forward: %s -> %s\n", pivotLocal, pivotRemote)

		if err := forward.Start(); err != nil {
			return err
		}

		fmt.Fprintln(output.Std, "Port forward started. Press Ctrl+C to stop.")

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Fprintln(output.Std, "\nStopping forward...")
		_ = forward.Stop()
		return nil
	},
}

var pivotTestTimeout int

var pivotTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test remote connectivity",
	Long:  `Test if a remote address is reachable.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if pivotRemote == "" {
			return fmt.Errorf("--remote is required")
		}

		fmt.Fprintf(output.Std, "Testing connectivity to %s...\n", pivotRemote)

		err := pivot.TestConnectivity(pivotRemote, pivotTestTimeout)
		if err != nil {
			return fmt.Errorf("[-] Connection failed: %v", err)
		}

		fmt.Fprintln(output.Std, "[+] Connection successful!")
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(pivotCmd)

	// SOCKS5 subcommand
	pivotCmd.AddCommand(pivotSocks5Cmd)
	pivotSocks5Cmd.Flags().StringVarP(&pivotLocal, "listen", "l", ":1080", "Listen address")
	pivotSocks5Cmd.Flags().StringVarP(&pivotUsername, "user", "u", "", "Username for auth")
	pivotSocks5Cmd.Flags().StringVarP(&pivotPassword, "pass", "p", "", "Password for auth")

	// Forward subcommand
	pivotCmd.AddCommand(pivotForwardCmd)
	pivotForwardCmd.Flags().StringVarP(&pivotLocal, "local", "l", "", "Local address (e.g., :8080)")
	pivotForwardCmd.Flags().StringVarP(&pivotRemote, "remote", "r", "", "Remote address (e.g., internal:80)")

	// Test subcommand
	pivotCmd.AddCommand(pivotTestCmd)
	pivotTestCmd.Flags().StringVarP(&pivotRemote, "remote", "r", "", "Remote address to test")
	pivotTestCmd.Flags().IntVarP(&pivotTestTimeout, "timeout", "t", 5, "Timeout in seconds")
}
