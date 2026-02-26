package cmd

import (
	"fmt"
	"os"
	"raxuiscli/internal/redteam/ldap"

	"github.com/spf13/cobra"
)

var ldapHost string
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

Enumerate users, computers, groups, and GPOs from Active Directory.
Identify potentially vulnerable configurations like Kerberoastable accounts,
AS-REP roastable users, and unconstrained delegation.

Examples:
  raxuiscli ldap enum dc.corp.local -u user -p pass -d corp.local
  raxuiscli ldap users dc.corp.local -u user -p pass
  raxuiscli ldap computers dc.corp.local -u user -p pass
  raxuiscli ldap groups dc.corp.local -u user -p pass`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var ldapEnumCmd = &cobra.Command{
	Use:   "enum [host]",
	Short: "Full AD enumeration",
	Long: `Perform comprehensive Active Directory enumeration.

Enumerates users, computers, groups, and identifies:
- Kerberoastable accounts (users with SPNs)
- AS-REP roastable users (no pre-auth required)
- Unconstrained delegation
- Admin accounts`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		opts := ldap.LDAPOptions{
			Host:     args[0],
			Port:     ldapPort,
			Username: ldapUser,
			Password: ldapPass,
			Domain:   ldapDomain,
			UseTLS:   ldapTLS,
			Timeout:  ldapTimeout,
		}

		// Test connection first
		fmt.Printf("Connecting to %s:%d...\n", opts.Host, opts.Port)

		if err := ldap.TestConnection(opts.Host, opts.Port, opts.Timeout); err != nil {
			fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Connection successful!")

		// Check anonymous bind
		anon, _ := ldap.CheckAnonymousBind(opts.Host, opts.Port, opts.Timeout)
		if anon {
			fmt.Println("WARNING: Anonymous bind is allowed!")
		}

		// Enumerate users
		users, err := ldap.EnumerateUsers(opts, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "User enumeration failed: %v\n", err)
		} else {
			ldap.DisplayUsers(users, ldapShowAll)

			// Show security findings
			if kerberoastable := ldap.FindKerberoastable(users); len(kerberoastable) > 0 {
				fmt.Printf("\n[!] Kerberoastable accounts: %d\n", len(kerberoastable))
				for _, u := range kerberoastable {
					fmt.Printf("    %s (SPNs: %v)\n", u.SAMAccountName, u.ServicePrincipal)
				}
			}

			if asrep := ldap.FindASREPRoastable(users); len(asrep) > 0 {
				fmt.Printf("\n[!] AS-REP Roastable accounts: %d\n", len(asrep))
				for _, u := range asrep {
					fmt.Printf("    %s\n", u.SAMAccountName)
				}
			}
		}
	},
}

var ldapUsersCmd = &cobra.Command{
	Use:   "users [host]",
	Short: "Enumerate AD users",
	Long:  `Enumerate Active Directory users and their attributes.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		opts := ldap.LDAPOptions{
			Host:     args[0],
			Port:     ldapPort,
			Username: ldapUser,
			Password: ldapPass,
			Domain:   ldapDomain,
			UseTLS:   ldapTLS,
			Timeout:  ldapTimeout,
		}

		users, err := ldap.EnumerateUsers(opts, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		ldap.DisplayUsers(users, ldapShowAll)
	},
}

var ldapTestCmd = &cobra.Command{
	Use:   "test [host]",
	Short: "Test LDAP connectivity",
	Long:  `Test LDAP connectivity and authentication.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]

		fmt.Printf("Testing connection to %s:%d...\n", host, ldapPort)

		// Test TCP connection
		if err := ldap.TestConnection(host, ldapPort, ldapTimeout); err != nil {
			fmt.Fprintf(os.Stderr, "TCP connection failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] TCP connection successful")

		// Test anonymous bind
		anon, err := ldap.CheckAnonymousBind(host, ldapPort, ldapTimeout)
		if anon {
			fmt.Println("[+] Anonymous bind: ALLOWED (potential vulnerability)")
		} else {
			fmt.Printf("[-] Anonymous bind: NOT ALLOWED (%v)\n", err)
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
				fmt.Fprintf(os.Stderr, "Connection failed: %v\n", err)
				os.Exit(1)
			}
			defer conn.Close()

			err = conn.Bind(ldapUser, ldapPass, ldapDomain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Authentication failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] Authentication successful!")
		}
	},
}

func init() {
	rootCmd.AddCommand(ldapCmd)

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
