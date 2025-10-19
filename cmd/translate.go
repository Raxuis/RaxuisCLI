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

var translateFileCmd = &cobra.Command{
	Use:   "file [chemin du fichier]",
	Short: "Traduire le contenu d'un fichier",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		options := translate.Options{
			Source:   translateSource,
			Target:   translateTarget,
			Provider: translateProvider,
			ApiKey:   translateApiKey,
		}

		result, err := translate.TranslateFile(filePath, options)
		if err != nil {
			fmt.Printf("Erreur lors de la traduction du fichier: %v\n", err)
			return
		}

		fmt.Printf("\n✅ Fichier traduit avec succès!\n")
		fmt.Printf("📄 Fichier original: %s\n", filePath)
		fmt.Printf("📝 Fichier traduit: %s\n\n", result.OutputPath)

		if result.DetectedLanguage != "" && translateSource == "auto" {
			fmt.Printf("ℹ️  Langue détectée: %s\n\n", result.DetectedLanguage)
		}

		// Aperçu du contenu traduit
		if len(result.TranslatedText) > 200 {
			fmt.Printf("Aperçu: %s...\n", result.TranslatedText[:200])
		} else {
			fmt.Printf("Contenu: %s\n", result.TranslatedText)
		}
	},
}

var translateBatchCmd = &cobra.Command{
	Use:   "batch [texte1] [texte2] [...]",
	Short: "Traduire plusieurs textes en une seule commande",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		options := translate.Options{
			Source:   translateSource,
			Target:   translateTarget,
			Provider: translateProvider,
			ApiKey:   translateApiKey,
		}

		fmt.Printf("\n🔄 Traduction de %d texte(s)...\n\n", len(args))

		for i, text := range args {
			result, err := translate.Translate(text, options)
			if err != nil {
				fmt.Printf("❌ Erreur texte %d: %v\n", i+1, err)
				continue
			}

			fmt.Printf("─────────────────────────────────────\n")
			fmt.Printf("📝 Texte %d (%s): %s\n", i+1, translateSource, text)
			fmt.Printf("🌐 Traduction (%s): %s\n", translateTarget, result.TranslatedText)
			if result.DetectedLanguage != "" && translateSource == "auto" {
				fmt.Printf("ℹ️  Langue détectée: %s\n", result.DetectedLanguage)
			}
			fmt.Println()
		}
	},
}

var translateInteractiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Mode interactif pour traduire en continu",
	Run: func(cmd *cobra.Command, args []string) {
		options := translate.Options{
			Source:   translateSource,
			Target:   translateTarget,
			Provider: translateProvider,
			ApiKey:   translateApiKey,
		}

		fmt.Printf("\n🌐 Mode interactif de traduction\n")
		fmt.Printf("📌 %s → %s | Provider: %s\n", translateSource, translateTarget, translateProvider)
		fmt.Println("💡 Tapez 'quit', 'exit' ou 'q' pour quitter")
		fmt.Println("💡 Tapez 'swap' pour inverser les langues")
		fmt.Println("─────────────────────────────────────\n")

		for {
			fmt.Print("Texte à traduire: ")
			var input string
			_, err := fmt.Scanln(&input)
			if err != nil {
				continue
			}

			input = strings.TrimSpace(input)

			// Commandes spéciales
			switch strings.ToLower(input) {
			case "quit", "exit", "q":
				fmt.Println("\n👋 Au revoir!")
				return
			case "swap":
				options.Source, options.Target = options.Target, options.Source
				fmt.Printf("🔄 Langues inversées: %s → %s\n\n", options.Source, options.Target)
				continue
			case "":
				continue
			}

			result, err := translate.Translate(input, options)
			if err != nil {
				fmt.Printf("❌ Erreur: %v\n\n", err)
				continue
			}

			fmt.Printf("→ %s\n", result.TranslatedText)
			if result.DetectedLanguage != "" && options.Source == "auto" {
				fmt.Printf("  (langue détectée: %s)\n", result.DetectedLanguage)
			}
			fmt.Println()
		}
	},
}

var translateHistoryLimit int

var translateHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Afficher l'historique des traductions",
	Run: func(cmd *cobra.Command, args []string) {
		history, err := translate.GetHistory(translateHistoryLimit)
		if err != nil {
			fmt.Printf("Erreur lors de la récupération de l'historique: %v\n", err)
			return
		}

		if len(history) == 0 {
			fmt.Println("\n📭 Aucune traduction dans l'historique")
			return
		}

		fmt.Printf("\n📚 Historique des traductions (%d entrées)\n\n", len(history))

		for i, entry := range history {
			fmt.Printf("─────────────────────────────────────\n")
			fmt.Printf("🕐 %s\n", entry.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Printf("📌 %s → %s | %s\n", entry.SourceLang, entry.TargetLang, entry.Provider)

			if entry.DetectedLanguage != "" {
				fmt.Printf("🔍 Langue détectée: %s\n", entry.DetectedLanguage)
			}

			// Limiter l'affichage pour les textes longs
			original := entry.OriginalText
			translated := entry.TranslatedText

			if len(original) > 100 {
				original = original[:100] + "..."
			}
			if len(translated) > 100 {
				translated = translated[:100] + "..."
			}

			fmt.Printf("\n📝 Original: %s\n", original)
			fmt.Printf("🌐 Traduit: %s\n", translated)

			if i < len(history)-1 {
				fmt.Println()
			}
		}
		fmt.Println("\n─────────────────────────────────────")
	},
}

var translateHistoryClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Effacer l'historique des traductions",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print("⚠️  Êtes-vous sûr de vouloir effacer l'historique ? (y/N): ")

		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			return
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response == "y" || response == "yes" || response == "oui" {
			if err := translate.ClearHistory(); err != nil {
				fmt.Printf("❌ Erreur lors de l'effacement: %v\n", err)
			} else {
				fmt.Println("✅ Historique effacé avec succès!")
			}
		} else {
			fmt.Println("❌ Annulé")
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
	translateCmd.AddCommand(translateFileCmd)
	translateCmd.AddCommand(translateBatchCmd)
	translateCmd.AddCommand(translateInteractiveCmd)
	translateCmd.AddCommand(translateListLanguagesCmd)
	translateCmd.AddCommand(translateHistoryCmd)
	translateHistoryCmd.AddCommand(translateHistoryClearCmd)

	// Flags globaux pour toutes les commandes de traduction
	translateCmd.PersistentFlags().StringVarP(&translateSource, "source", "s", "auto", "Langue source (auto pour détection automatique)")
	translateCmd.PersistentFlags().StringVarP(&translateTarget, "target", "t", "en", "Langue cible")
	translateCmd.PersistentFlags().StringVar(&translateProvider, "provider", "libretranslate", "Service de traduction (libretranslate, deepl)")
	translateCmd.PersistentFlags().StringVar(&translateApiKey, "api-key", "", "Clé API (si nécessaire)")

	translateHistoryCmd.Flags().IntVarP(&translateHistoryLimit, "limit", "l", 10, "Nombre d'entrées à afficher")
}
