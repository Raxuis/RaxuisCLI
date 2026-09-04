package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// RootCmd is exported so subpackages can add their commands
var RootCmd = &cobra.Command{
	Use:   "raxuiscli",
	Short: "A powerful CLI toolkit",
	Long:  `RaxuisCLI is a collection of the most used commands by @Raxuis.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to RaxuisCLI! Use --help to see available commands.")
	},
}

func Execute() error {
	return RootCmd.Execute()
}

func init() {
	RootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
}
