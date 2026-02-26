package cmd

import (
	"raxuiscli/internal/container"

	"github.com/spf13/cobra"
)

var containerCmd = &cobra.Command{
	Use:   "container",
	Short: "Container security assessment",
	Long: `Container security toolkit for Docker/Kubernetes environments.

Detect container environment, check for escape vectors, and find secrets.

Examples:
  raxuiscli container detect                 # Detect container environment
  raxuiscli container escape                 # Check escape vectors
  raxuiscli container secrets                # Find secrets
  raxuiscli container check                  # Full assessment`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var containerDetectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Detect container environment",
	Long:  `Detect if running inside a container and gather information.`,
	Run: func(cmd *cobra.Command, args []string) {
		info := container.DetectContainer()
		container.DisplayContainerInfo(info)
	},
}

var containerEscapeCmd = &cobra.Command{
	Use:   "escape",
	Short: "Check container escape vectors",
	Long:  `Check for potential container escape vulnerabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		vectors := container.CheckEscapeVectors()
		container.DisplayEscapeVectors(vectors)
	},
}

var containerSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Find container secrets",
	Long:  `Scan for secrets in container environment.`,
	Run: func(cmd *cobra.Command, args []string) {
		findings := container.ScanSecrets()
		container.DisplaySecrets(findings)
	},
}

var containerCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Full container security check",
	Long:  `Perform a complete container security assessment.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Detect container
		info := container.DetectContainer()
		container.DisplayContainerInfo(info)

		if !info.IsContainer {
			return
		}

		// Check escape vectors
		vectors := container.CheckEscapeVectors()
		container.DisplayEscapeVectors(vectors)

		// Find secrets
		findings := container.ScanSecrets()
		container.DisplaySecrets(findings)
	},
}

func init() {
	rootCmd.AddCommand(containerCmd)

	containerCmd.AddCommand(containerDetectCmd)
	containerCmd.AddCommand(containerEscapeCmd)
	containerCmd.AddCommand(containerSecretsCmd)
	containerCmd.AddCommand(containerCheckCmd)
}
