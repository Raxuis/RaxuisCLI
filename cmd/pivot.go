package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"raxuiscli/internal/pivot"
	"syscall"

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
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var pivotSocks5Cmd = &cobra.Command{
	Use:   "socks5",
	Short: "Start SOCKS5 proxy",
	Long: `Start a SOCKS5 proxy server for network pivoting.

Traffic can be routed through this proxy to access internal networks.`,
	Run: func(cmd *cobra.Command, args []string) {
		if pivotLocal == "" {
			pivotLocal = ":1080"
		}

		auth := pivotUsername != "" && pivotPassword != ""
		pivot.DisplayProxyInfo(pivot.SOCKS5Proxy, pivotLocal, auth)

		server := pivot.NewSOCKS5Server(pivotLocal, pivotUsername, pivotPassword)

		fmt.Printf("Starting SOCKS5 proxy on %s...\n", pivotLocal)

		if err := server.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Proxy started. Press Ctrl+C to stop.")
		fmt.Println("\nUsage examples:")
		fmt.Printf("  curl --socks5 %s http://target\n", pivotLocal)
		fmt.Printf("  proxychains -q <command>\n")

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\nStopping proxy...")
		server.Stop()
	},
}

var pivotForwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "TCP port forwarding",
	Long: `Create a TCP port forward to access remote services.

Forwards local traffic to a remote destination.`,
	Run: func(cmd *cobra.Command, args []string) {
		if pivotLocal == "" || pivotRemote == "" {
			fmt.Fprintln(os.Stderr, "Error: both --local and --remote are required")
			os.Exit(1)
		}

		pivot.DisplayForwardInfo(pivotLocal, pivotRemote)

		forward := pivot.NewPortForward(pivotLocal, pivotRemote)

		fmt.Printf("Starting port forward: %s -> %s\n", pivotLocal, pivotRemote)

		if err := forward.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Port forward started. Press Ctrl+C to stop.")

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\nStopping forward...")
		forward.Stop()
	},
}

var pivotTestTimeout int

var pivotTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test remote connectivity",
	Long:  `Test if a remote address is reachable.`,
	Run: func(cmd *cobra.Command, args []string) {
		if pivotRemote == "" {
			fmt.Fprintln(os.Stderr, "Error: --remote is required")
			os.Exit(1)
		}

		fmt.Printf("Testing connectivity to %s...\n", pivotRemote)

		err := pivot.TestConnectivity(pivotRemote, pivotTestTimeout)
		if err != nil {
			fmt.Printf("[-] Connection failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[+] Connection successful!")
	},
}

func init() {
	rootCmd.AddCommand(pivotCmd)

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
