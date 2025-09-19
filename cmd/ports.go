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
			ScanType:  portsScanType,
		}

		ports.Scan(options)
	},
}

func init() {
	rootCmd.AddCommand(portsCmd)
	portsCmd.PersistentFlags().StringVarP(&portsHost, "host", "H", "localhost", "Target host to scan")
	portsCmd.PersistentFlags().StringVarP(&portsPortRange, "port-range", "p", "1-1024", "Port range to scan (e.g., 1-65535)")
	portsCmd.PersistentFlags().IntVarP(&portsTimeout, "timeout", "t", 5, "Timeout in seconds for each port scan")
	portsCmd.PersistentFlags().StringVarP(&portsScanType, "scan-type", "s", "tcp", "Type of scan (tcp/udp)")
}
