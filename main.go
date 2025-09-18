package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	var name string

	var rootCmd = &cobra.Command{
		Use:   "mycli",
		Short: "A simple greeting CLI",
		Long:  "This CLI prints a greeting message to the user",
		Run: func(cmd *cobra.Command, args []string) {
			if name == "" {
				fmt.Println("Hello, World!")
			} else {
				fmt.Printf("Hello, %s!\n", name)
			}
		},
	}

	rootCmd.Flags().StringVarP(&name, "name", "n", "", "Your name")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
