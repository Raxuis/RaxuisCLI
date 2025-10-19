package cmd

import (
	"fmt"
	"raxuiscli/internal/translate"
	"strings"

	"github.com/spf13/cobra"
)

var translateCmd = &cobra.Command{
	Use:   "translate",
	Short: "Traduire du texte entre différentes langues",
	Long:  "Traduire du texte en utilisant différents services de traduction (DeepL, LibreTranslate, etc.)",
}

var (
	translateSource   string
	translateTarget   string
	translateProvider string
	translateApiKey   string
)

var translateTextCmd = &cobra.Command{
	Use:   "text [texte à traduire]",
	Short: "Traduire un texte",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		text := strings.Join(args, " ")

		options := translate.Options{
			Source:   translateSource,
			Target:   translateTarget,
			Provider: translateProvider,
			ApiKey:   translateApiKey,
		}

		result, err := translate.Translate(text, options)
		if err != nil {
			fmt.Printf("Erreur lors de la traduction: %v\n", err)
			return
		}

		fmt.Printf("\n📝 Texte original (%s):\n%s\n\n", translateSource, text)
		fmt.Printf("🌐 Traduction (%s):\n%s\n\n", translateTarget, result.TranslatedText)

		if result.DetectedLanguage != "" && translateSource == "auto" {
			fmt.Printf("ℹ️  Langue détectée: %s\n", result.DetectedLanguage)
		}

		// Demander si l'utilisateur veut copier la traduction
		fmt.Print("Voulez-vous copier la traduction dans le presse-papiers ? (y/N): ")

		var response string
		_, err = fmt.Scanln(&response)
		if err != nil {
			return
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" || response == "oui" {
			err := translate.CopyToClipboard(result.TranslatedText)
			if err != nil {
				fmt.Printf("Erreur lors de la copie: %v\n", err)
			} else {
				fmt.Println("✅ Traduction copiée dans le presse-papiers!")
			}
		}
	},
}

var translateListLanguagesCmd = &cobra.Command{
	Use:   "languages",
	Short: "Lister les langues disponibles",
	Run: func(cmd *cobra.Command, args []string) {
		options := translate.Options{
			Provider: translateProvider,
			ApiKey:   translateApiKey,
		}

		languages, err := translate.ListLanguages(options)
		if err != nil {
			fmt.Printf("Erreur lors de la récupération des langues: %v\n", err)
			return
		}

		fmt.Printf("\n🌍 Langues disponibles pour %s:\n\n", translateProvider)
		for code, name := range languages {
			fmt.Printf("  %s: %s\n", code, name)
		}
		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(translateCmd)
	translateCmd.AddCommand(translateTextCmd)
	translateCmd.AddCommand(translateListLanguagesCmd)

	// Flags pour la traduction de texte
	translateTextCmd.Flags().StringVarP(&translateSource, "source", "s", "auto", "Langue source (auto pour détection automatique)")
	translateTextCmd.Flags().StringVarP(&translateTarget, "target", "t", "en", "Langue cible")
	translateTextCmd.Flags().StringVar(&translateProvider, "provider", "libretranslate", "Service de traduction (libretranslate, deepl)")
	translateTextCmd.Flags().StringVar(&translateApiKey, "api-key", "", "Clé API (si nécessaire)")

	// Flags pour lister les langues
	translateListLanguagesCmd.Flags().StringVar(&translateProvider, "provider", "libretranslate", "Service de traduction")
	translateListLanguagesCmd.Flags().StringVar(&translateApiKey, "api-key", "", "Clé API (si nécessaire)")
}
