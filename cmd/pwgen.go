package cmd

import (
	"fmt"
	"raxuiscli/internal/pwgen"

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

		for i := 0; i < pwgenCount; i++ {
			password, err := pwgen.Generate(options)
			if err != nil {
				fmt.Printf("Error generating password: %v\n", err)
				return
			}
			fmt.Println(password)
		}
	},
}

func init() {
	rootCmd.AddCommand(pwgenCmd)
	pwgenCmd.AddCommand(pwgenGenerateCmd)

	pwgenCmd.PersistentFlags().IntVar(&pwgenLength, "length", 16, "Password length")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenNoSymbols, "no-symbols", false, "Exclude symbols")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenNoNumbers, "no-numbers", false, "Exclude numbers")
	pwgenCmd.PersistentFlags().IntVar(&pwgenCount, "count", 1, "Number of passwords to generate")
}
