package cmd

import (
	"fmt"
	"raxuiscli/internal/pwgen"
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
			fmt.Println("La longueur maximale du mot de passe est de 100000 caractères.")
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

		// Demander si l'utilisateur veut copier le dernier mot de passe
		if pwgenCount == 1 {
			fmt.Print("Voulez-vous copier ce mot de passe dans le presse-papiers ? (y/N): ")
		} else {
			fmt.Print("Voulez-vous copier le dernier mot de passe dans le presse-papiers ? (y/N): ")
		}

		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			return
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" || response == "oui" {
			err := pwgen.CopyToClipboard(lastPassword)
			if err != nil {
				fmt.Printf("Erreur lors de la copie dans le presse-papiers: %v\n", err)
			} else {
				fmt.Println("Mot de passe copié dans le presse-papiers!")

				// Optionnel : vérifier que la copie a bien fonctionné
				if err := pwgen.VerifyClipboard(lastPassword); err != nil {
					fmt.Printf("Attention: %v\n", err)
				} else {
					fmt.Println("✓ Copie vérifiée avec succès")
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(pwgenCmd)
	pwgenCmd.AddCommand(pwgenGenerateCmd)

	pwgenCmd.PersistentFlags().IntVarP(&pwgenLength, "length", "l", 16, "Password length")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenNoSymbols, "no-symbols", false, "Exclude symbols")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenNoNumbers, "no-numbers", false, "Exclude numbers")
	pwgenCmd.PersistentFlags().IntVar(&pwgenCount, "count", 1, "Number of passwords to generate")
}
