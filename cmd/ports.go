package cmd

import (
	"raxuiscli/internal/ports"

	"github.com/spf13/cobra"
)

var portsHost string
var portsPortRange string
var portsTimeout int
var portsScanType string

var portsCmd = &cobra.Command{
	Use:   "ports",
	Short: "Check open ports on a host",
	Long:  "Check for open ports on a specified host using various scanning techniques",
	Run: func(cmd *cobra.Command, args []string) {
		options := ports.Options{
			Host:      portsHost,
			PortRange: portsPortRange,
			Timeout:   portsTimeout,
			ScanType:  "tcp", // Default scan type
		}

		ports.Scan(options)
	},
}

func init() {
	rootCmd.AddCommand(portsCmd)
	portsCmd.PersistentFlags().StringVar(&portsHost, "host", "localhost", "Target host to scan")
	portsCmd.PersistentFlags().StringVar(&portsPortRange, "port-range", "1-65535", "Port range to scan (e.g., 1-1000)")
	portsCmd.PersistentFlags().IntVar(&portsTimeout, "timeout", 5, "Timeout in seconds for each port scan")
	portsCmd.PersistentFlags().StringVar(&portsScanType, "scan-type", "tcp", "Type of scan to perform (tcp/udp)")
}
