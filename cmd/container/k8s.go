package container

import (
	"errors"
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/container/k8s"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var k8sNamespace string

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Kubernetes security assessment",
	Long: `Kubernetes security toolkit for cluster enumeration and attack.

Detect Kubernetes environment, enumerate permissions, find secrets,
and check for privilege escalation paths.

Examples:
  raxuiscli k8s detect                       # Detect K8s environment
  raxuiscli k8s enum                         # Enumerate accessible resources
  raxuiscli k8s secrets                      # List accessible secrets
  raxuiscli k8s privesc                      # Check privilege escalation
  raxuiscli k8s commands                     # Show useful kubectl commands`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var k8sDetectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Detect Kubernetes environment",
	Long:  `Detect if running inside Kubernetes and gather cluster info.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := k8s.DetectK8s()
		k8s.DisplayK8sInfo(info)
		return nil
	},
}

var k8sEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate accessible resources",
	Long:  `Enumerate what Kubernetes resources are accessible with current token.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := k8s.DetectK8s()
		if !info.InCluster {
			return fmt.Errorf("not running inside Kubernetes")
		}

		k8s.DisplayK8sInfo(info)

		rbac, err := k8s.CheckAPIAccessWithError(info)
		k8s.DisplayRBAC(rbac)
		return err
	},
}

var k8sSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "List accessible secrets",
	Long:  `List Kubernetes secrets accessible with current service account.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := k8s.DetectK8s()
		if !info.InCluster {
			return fmt.Errorf("not running inside Kubernetes")
		}

		secrets, err := k8s.ListSecrets(info, k8sNamespace)
		if err != nil {
			return err
		}

		k8s.DisplaySecrets(secrets)
		return nil
	},
}

var k8sPrivescCmd = &cobra.Command{
	Use:   "privesc",
	Short: "Check privilege escalation paths",
	Long:  `Check for privilege escalation vulnerabilities in the cluster.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := k8s.DetectK8s()
		if !info.InCluster {
			return fmt.Errorf("not running inside Kubernetes")
		}

		vulns, err := k8s.CheckPrivilegeEscalationWithError(info)
		k8s.DisplayVulnerabilities(vulns)
		return err
	},
}

var k8sCommandsCmd = &cobra.Command{
	Use:   "commands",
	Short: "Show useful kubectl commands",
	Long:  `Display useful kubectl commands for pentesting.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := k8s.DetectK8s()

		if info.Namespace == "" {
			info.Namespace = "default"
		}

		fmt.Fprintln(output.Std, "\n[USEFUL KUBECTL COMMANDS]")
		fmt.Fprintln(output.Std, "=========================")

		for _, line := range k8s.GenerateKubectlCommands(info) {
			fmt.Fprintln(output.Std, line)
		}
		return nil
	},
}

var k8sCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Full Kubernetes security check",
	Long:  `Perform a complete Kubernetes security assessment.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := k8s.DetectK8s()
		k8s.DisplayK8sInfo(info)

		if !info.InCluster {
			return nil
		}

		// Check RBAC
		rbac, accessErr := k8s.CheckAPIAccessWithError(info)
		k8s.DisplayRBAC(rbac)

		// Check secrets
		secrets, secretErr := k8s.ListSecrets(info, "")
		if secretErr == nil {
			k8s.DisplaySecrets(secrets)
		}

		// Check privesc
		vulns, vulnerabilityErr := k8s.CheckPrivilegeEscalationWithError(info)
		k8s.DisplayVulnerabilities(vulns)
		return errors.Join(accessErr, secretErr, vulnerabilityErr)
	},
}

func init() {
	cmd.RootCmd.AddCommand(k8sCmd)

	// Global flags
	k8sCmd.PersistentFlags().StringVarP(&k8sNamespace, "namespace", "n", "", "Kubernetes namespace")

	// Subcommands
	k8sCmd.AddCommand(k8sDetectCmd)
	k8sCmd.AddCommand(k8sEnumCmd)
	k8sCmd.AddCommand(k8sSecretsCmd)
	k8sCmd.AddCommand(k8sPrivescCmd)
	k8sCmd.AddCommand(k8sCommandsCmd)
	k8sCmd.AddCommand(k8sCheckCmd)
}
