package tools

import (
	"fmt"
	"raxuiscli/cmd"
	"raxuiscli/internal/tools/pwgen"
	"strings"

	"github.com/spf13/cobra"
)

var pwgenCmd = &cobra.Command{
	Use:   "pwgen",
	Short: "Generate secure passwords",
	Long:  "Generate cryptographically secure passwords with various options",
}

var pwgenLength int
var pwgenNoSymbols bool
var pwgenNoNumbers bool
var pwgenCount int

var pwgenGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate password(s)",
	Run: func(cmd *cobra.Command, args []string) {
		options := pwgen.Options{
			Length:    pwgenLength,
			NoSymbols: pwgenNoSymbols,
			NoNumbers: pwgenNoNumbers,
		}

		if pwgenLength > 100000 {
			fmt.Println("Maximum password length is 100000 characters.")
			return
		}

		var lastPassword string

		for i := 0; i < pwgenCount; i++ {
			password, err := pwgen.Generate(options)
			if err != nil {
				fmt.Printf("Error generating password: %v\n", err)
				return
			}

			fmt.Printf("Password %d: %s\n", i+1, password)
			lastPassword = password
		}

		if pwgenCount == 1 {
			fmt.Print("Copy this password to clipboard? (y/N): ")
		} else {
			fmt.Print("Copy the last password to clipboard? (y/N): ")
		}

		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			return
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" {
			err := pwgen.CopyToClipboard(lastPassword)
			if err != nil {
				fmt.Printf("Error copying to clipboard: %v\n", err)
			} else {
				fmt.Println("Password copied to clipboard!")

				if err := pwgen.VerifyClipboard(lastPassword); err != nil {
					fmt.Printf("Warning: %v\n", err)
				} else {
					fmt.Println("Copy verified successfully")
				}
			}
		}
	},
}

func init() {
	cmd.RootCmd.AddCommand(pwgenCmd)
	pwgenCmd.AddCommand(pwgenGenerateCmd)

	pwgenCmd.PersistentFlags().IntVarP(&pwgenLength, "length", "l", 16, "Password length")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenNoSymbols, "no-symbols", false, "Exclude symbols")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenNoNumbers, "no-numbers", false, "Exclude numbers")
	pwgenCmd.PersistentFlags().IntVar(&pwgenCount, "count", 1, "Number of passwords to generate")
}
