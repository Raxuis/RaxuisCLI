package tools

import (
	"raxuiscli/cmd"
	"raxuiscli/internal/tools/ports"

	"github.com/spf13/cobra"
)

var portsHost string
var portsPortRange string
var portsTimeout int
var portsScanType string

var portsCmd = &cobra.Command{
	Use:   "ports",
	Short: "Check open ports on a host",
	Long: `Check for open ports on a specified host using various scanning techniques.

Preset port ranges:
  common   - Common services (21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,8080)
  web      - Web services (80,443,8000,8080,8443,8888,9000,9090)
  dev      - Development ports (3000,3001,4000,5000,8000,8080,8888,9000)
  database - Database ports (1433,3306,5432,6379,27017)
  system   - System ports (21,22,23,25,53,80,135,139,443,445)
  extended - Extended range (1-10000)
  all      - All ports (1-65535)

Examples:
  raxuiscli ports -H localhost -p dev
  raxuiscli ports -H example.com -p 3000
  raxuiscli ports -H 192.168.1.1 -p 1-1024
  raxuiscli ports -H localhost -p 22,80,443,3000`,
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
	cmd.RootCmd.AddCommand(portsCmd)
	portsCmd.PersistentFlags().StringVarP(&portsHost, "host", "H", "localhost", "Target host to scan")
	portsCmd.PersistentFlags().StringVarP(&portsPortRange, "port-range", "p", "common", "Port range to scan (e.g., 1-65535, common, dev, web)")
	portsCmd.PersistentFlags().IntVarP(&portsTimeout, "timeout", "t", 5, "Timeout in seconds for each port scan")
	portsCmd.PersistentFlags().StringVarP(&portsScanType, "scan-type", "s", "tcp", "Type of scan (tcp/udp)")
}
