package redteam

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/kerberos"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var kerbDomain string
var kerbDC string

var kerberosCmd = &cobra.Command{
	Use:   "kerberos",
	Short: "Kerberos attack helpers",
	Long: `Kerberos attack toolkit for Active Directory environments.

Generate commands and format hashes for Kerberoasting, AS-REP roasting,
golden tickets, and silver tickets.

Examples:
  raxuiscli kerberos roast -d corp.local --dc dc01.corp.local
  raxuiscli kerberos asrep -d corp.local --dc dc01.corp.local
  raxuiscli kerberos parse '$krb5tgs$23$*user...'
  raxuiscli kerberos golden -d corp.local --sid S-1-5-... --hash <krbtgt>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var kerbRoastCmd = &cobra.Command{
	Use:   "roast",
	Short: "Kerberoasting commands",
	Long:  `Generate Kerberoasting commands for various tools.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if kerbDomain == "" {
			kerbDomain = "<domain>"
		}
		if kerbDC == "" {
			kerbDC = "<dc>"
		}

		kerberos.DisplayKerberoastHelp(kerbDomain, kerbDC)
		return nil
	},
}

var kerbASREPCmd = &cobra.Command{
	Use:   "asrep",
	Short: "AS-REP Roasting commands",
	Long:  `Generate AS-REP Roasting commands for various tools.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if kerbDomain == "" {
			kerbDomain = "<domain>"
		}
		if kerbDC == "" {
			kerbDC = "<dc>"
		}

		kerberos.DisplayASREPHelp(kerbDomain, kerbDC)
		return nil
	},
}

var kerbParseCmd = &cobra.Command{
	Use:   "parse [hash]",
	Short: "Parse Kerberos hash",
	Long:  `Parse a Kerberos hash and display information.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := args[0]

		ticket, err := kerberos.ParseHashcatOutput(hash)
		if err != nil {
			return fmt.Errorf("error parsing hash: %v", err)
		}

		kerberos.DisplayTicket(ticket)
		return nil
	},
}

var kerbGoldenSID string
var kerbGoldenHash string
var kerbGoldenUser string

var kerbGoldenCmd = &cobra.Command{
	Use:   "golden",
	Short: "Golden ticket commands",
	Long:  `Generate golden ticket commands for various tools.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if kerbDomain == "" || kerbGoldenSID == "" || kerbGoldenHash == "" {
			return fmt.Errorf("--domain, --sid, and --hash are required")
		}

		if kerbGoldenUser == "" {
			kerbGoldenUser = "Administrator"
		}

		fmt.Fprintln(output.Std, "\n[GOLDEN TICKET COMMANDS]")
		fmt.Fprintln(output.Std, "========================")

		tools := []string{"impacket", "mimikatz", "rubeus"}
		for _, tool := range tools {
			cmd := kerberos.GenerateGoldenTicketCommand(
				kerbDomain, kerbGoldenSID, kerbGoldenHash, kerbGoldenUser, tool)
			fmt.Fprintf(output.Std, "\n%s:\n  %s\n", tool, cmd)
		}

		fmt.Fprintln(output.Std)
		return nil
	},
}

var kerbSilverSPN string
var kerbSilverHash string
var kerbSilverUser string
var kerbSilverSID string

var kerbSilverCmd = &cobra.Command{
	Use:   "silver",
	Short: "Silver ticket commands",
	Long:  `Generate silver ticket commands for various tools.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if kerbDomain == "" || kerbSilverSID == "" || kerbSilverHash == "" || kerbSilverSPN == "" {
			return fmt.Errorf("--domain, --sid, --hash, and --spn are required")
		}

		if kerbSilverUser == "" {
			kerbSilverUser = "Administrator"
		}

		fmt.Fprintln(output.Std, "\n[SILVER TICKET COMMANDS]")
		fmt.Fprintln(output.Std, "========================")

		tools := []string{"impacket", "mimikatz"}
		for _, tool := range tools {
			cmd := kerberos.GenerateSilverTicketCommand(
				kerbDomain, kerbSilverSID, kerbSilverHash, kerbSilverSPN, kerbSilverUser, tool)
			fmt.Fprintf(output.Std, "\n%s:\n  %s\n", tool, cmd)
		}

		fmt.Fprintln(output.Std)
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(kerberosCmd)

	// Global flags
	kerberosCmd.PersistentFlags().StringVarP(&kerbDomain, "domain", "d", "", "Domain name")
	kerberosCmd.PersistentFlags().StringVar(&kerbDC, "dc", "", "Domain controller")

	// Roast subcommand
	kerberosCmd.AddCommand(kerbRoastCmd)

	// AS-REP subcommand
	kerberosCmd.AddCommand(kerbASREPCmd)

	// Parse subcommand
	kerberosCmd.AddCommand(kerbParseCmd)

	// Golden ticket subcommand
	kerberosCmd.AddCommand(kerbGoldenCmd)
	kerbGoldenCmd.Flags().StringVar(&kerbGoldenSID, "sid", "", "Domain SID")
	kerbGoldenCmd.Flags().StringVar(&kerbGoldenHash, "hash", "", "KRBTGT NT hash")
	kerbGoldenCmd.Flags().StringVarP(&kerbGoldenUser, "user", "u", "Administrator", "Username to impersonate")

	// Silver ticket subcommand
	kerberosCmd.AddCommand(kerbSilverCmd)
	kerbSilverCmd.Flags().StringVar(&kerbSilverSID, "sid", "", "Domain SID")
	kerbSilverCmd.Flags().StringVar(&kerbSilverHash, "hash", "", "Service account NT hash")
	kerbSilverCmd.Flags().StringVar(&kerbSilverSPN, "spn", "", "Service Principal Name")
	kerbSilverCmd.Flags().StringVarP(&kerbSilverUser, "user", "u", "Administrator", "Username to impersonate")
}
