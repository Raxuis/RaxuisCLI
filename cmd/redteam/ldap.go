package redteam

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/ldap"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var ldapPort int
var ldapUser string
var ldapPass string
var ldapDomain string
var ldapTLS bool
var ldapTimeout int
var ldapShowAll bool

var ldapCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Active Directory LDAP enumeration",
	Long: `LDAP enumeration toolkit for Active Directory reconnaissance.

Connectivity and simple-bind authentication checks are available through ldap test.
LDAP search and AD enumeration are not implemented; enum and users return explicit
errors without connecting.

Examples:
  raxuiscli ldap test dc.corp.local
  raxuiscli ldap test dc.corp.local -u user -p pass -d corp.local`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var ldapEnumCmd = &cobra.Command{
	Use:   "enum [host]",
	Short: "Full AD enumeration",
	Long:  `Active Directory enumeration is not implemented. This command returns an explicit error without connecting.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := ldap.LDAPOptions{
			Host:     args[0],
			Port:     ldapPort,
			Username: ldapUser,
			Password: ldapPass,
			Domain:   ldapDomain,
			UseTLS:   ldapTLS,
			Timeout:  ldapTimeout,
		}

		_, err := ldap.EnumerateUsers(opts, "")
		return err
	},
}

var ldapUsersCmd = &cobra.Command{
	Use:   "users [host]",
	Short: "Enumerate AD users",
	Long:  `LDAP user enumeration is not implemented. This command returns an explicit error without connecting.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := ldap.LDAPOptions{
			Host:     args[0],
			Port:     ldapPort,
			Username: ldapUser,
			Password: ldapPass,
			Domain:   ldapDomain,
			UseTLS:   ldapTLS,
			Timeout:  ldapTimeout,
		}

		_, err := ldap.EnumerateUsers(opts, "")
		return err
	},
}

var ldapTestCmd = &cobra.Command{
	Use:   "test [host]",
	Short: "Test LDAP connectivity",
	Long:  `Test LDAP connectivity and authentication.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		host := args[0]

		fmt.Fprintf(output.Std, "Testing connection to %s:%d...\n", host, ldapPort)

		// Test TCP connection
		if err := ldap.TestConnection(host, ldapPort, ldapTimeout); err != nil {
			return fmt.Errorf("TCP connection failed: %v", err)
		}
		fmt.Fprintln(output.Std, "[+] TCP connection successful")

		// Test anonymous bind
		anon, err := ldap.CheckAnonymousBind(host, ldapPort, ldapTimeout)
		if anon {
			fmt.Fprintln(output.Std, "[+] Anonymous bind: ALLOWED (potential vulnerability)")
		} else {
			fmt.Fprintf(output.Std, "[-] Anonymous bind: NOT ALLOWED (%v)\n", err)
		}

		// Test authentication if credentials provided
		if ldapUser != "" && ldapPass != "" {
			opts := ldap.LDAPOptions{
				Host:     host,
				Port:     ldapPort,
				Username: ldapUser,
				Password: ldapPass,
				Domain:   ldapDomain,
				UseTLS:   ldapTLS,
				Timeout:  ldapTimeout,
			}

			conn, err := ldap.Connect(opts)
			if err != nil {
				return fmt.Errorf("connection failed: %v", err)
			}
			defer conn.Close()

			err = conn.Bind(ldapUser, ldapPass, ldapDomain)
			if err != nil {
				return fmt.Errorf("[-] Authentication failed: %v", err)
			}
			fmt.Fprintln(output.Std, "[+] Authentication successful!")
		}
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(ldapCmd)

	// Global LDAP flags
	ldapCmd.PersistentFlags().IntVarP(&ldapPort, "port", "P", 389, "LDAP port (389 or 636 for LDAPS)")
	ldapCmd.PersistentFlags().StringVarP(&ldapUser, "user", "u", "", "Username for authentication")
	ldapCmd.PersistentFlags().StringVarP(&ldapPass, "pass", "p", "", "Password for authentication")
	ldapCmd.PersistentFlags().StringVarP(&ldapDomain, "domain", "d", "", "Domain name")
	ldapCmd.PersistentFlags().BoolVar(&ldapTLS, "tls", false, "Use TLS (LDAPS)")
	ldapCmd.PersistentFlags().IntVarP(&ldapTimeout, "timeout", "t", 10, "Connection timeout")
	ldapCmd.PersistentFlags().BoolVar(&ldapShowAll, "all", false, "Show all details")

	// Subcommands
	ldapCmd.AddCommand(ldapEnumCmd)
	ldapCmd.AddCommand(ldapUsersCmd)
	ldapCmd.AddCommand(ldapTestCmd)
}
