package cmd

import (
	"fmt"
	"raxuiscli/internal/templates"

	"github.com/spf13/cobra"
)

var templatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "Generate files from project templates",
	Long:  "Generate files from predefined project templates to kickstart your development.",
	Run: func(cmd *cobra.Command, args []string) {
		err := cmd.Help()
		if err != nil {
			return
		}
	},
}

var generateCmd = &cobra.Command{
	Use:   "generate [project-type]",
	Short: "Generate template files for a specific project type",
	Long:  "Generate template files like .gitignore, README.md, .dockerignore for specific project types (nextjs, node, go, rust).",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		projectType := args[0]

		// Récupérer les flags
		outputDir, _ := cmd.Flags().GetString("output")
		files, _ := cmd.Flags().GetStringSlice("files")
		force, _ := cmd.Flags().GetBool("force")
		projectName, _ := cmd.Flags().GetString("name")

		generator := templates.NewGenerator()

		config := templates.GenerateConfig{
			ProjectType: projectType,
			OutputDir:   outputDir,
			Files:       files,
			Force:       force,
			ProjectName: projectName,
		}

		if err := generator.Generate(config); err != nil {
			fmt.Printf("Error generating templates: %v\n", err)
			return
		}

		fmt.Printf("Templates generated successfully for %s project!\n", projectType)
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available project types and template files",
	Long:  "Display all available project types and their supported template files.",
	Run: func(cmd *cobra.Command, args []string) {
		template, _ := cmd.Flags().GetString("template")
		generator := templates.NewGenerator()
		generator.ListAvailable(templates.ListOption{TemplateName: template})
	},
}

func init() {
	rootCmd.AddCommand(templatesCmd)
	templatesCmd.AddCommand(generateCmd)
	templatesCmd.AddCommand(listCmd)

	// Flags pour la commande generate
	generateCmd.Flags().StringP("output", "o", ".", "Output directory for generated files")
	generateCmd.Flags().StringSliceP("files", "f", []string{}, "Specific files to generate (default: all)")
	generateCmd.Flags().BoolP("force", "", false, "Overwrite existing files")
	generateCmd.Flags().StringP("name", "n", "", "Project name for template customization")

	// Flags pour la commande list
	listCmd.Flags().StringP("template", "t", "", "Filter output by specific template name")
}
