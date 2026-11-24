package container

import (
	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/container/container"

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
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var containerDetectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Detect container environment",
	Long:  `Detect if running inside a container and gather information.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := container.DetectContainer()
		container.DisplayContainerInfo(info)
		return nil
	},
}

var containerEscapeCmd = &cobra.Command{
	Use:   "escape",
	Short: "Check container escape vectors",
	Long:  `Check for potential container escape vulnerabilities.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vectors := container.CheckEscapeVectors()
		container.DisplayEscapeVectors(vectors)
		return nil
	},
}

var containerSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Find container secrets",
	Long:  `Scan for secrets in container environment.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		findings := container.ScanSecrets()
		container.DisplaySecrets(findings)
		return nil
	},
}

var containerCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Full container security check",
	Long:  `Perform a complete container security assessment.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Detect container
		info := container.DetectContainer()
		container.DisplayContainerInfo(info)

		if !info.IsContainer {
			return nil
		}

		// Check escape vectors
		vectors := container.CheckEscapeVectors()
		container.DisplayEscapeVectors(vectors)

		// Find secrets
		findings := container.ScanSecrets()
		container.DisplaySecrets(findings)
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(containerCmd)

	containerCmd.AddCommand(containerDetectCmd)
	containerCmd.AddCommand(containerEscapeCmd)
	containerCmd.AddCommand(containerSecretsCmd)
	containerCmd.AddCommand(containerCheckCmd)
}
