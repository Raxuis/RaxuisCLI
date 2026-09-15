package container

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/container/k8s"

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
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var k8sDetectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Detect Kubernetes environment",
	Long:  `Detect if running inside Kubernetes and gather cluster info.`,
	Run: func(cmd *cobra.Command, args []string) {
		info := k8s.DetectK8s()
		k8s.DisplayK8sInfo(info)
	},
}

var k8sEnumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate accessible resources",
	Long:  `Enumerate what Kubernetes resources are accessible with current token.`,
	Run: func(cmd *cobra.Command, args []string) {
		info := k8s.DetectK8s()
		if !info.InCluster {
			fmt.Println("Not running inside Kubernetes")
			return
		}

		k8s.DisplayK8sInfo(info)

		rbac := k8s.CheckAPIAccess(info)
		k8s.DisplayRBAC(rbac)
	},
}

var k8sSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "List accessible secrets",
	Long:  `List Kubernetes secrets accessible with current service account.`,
	Run: func(cmd *cobra.Command, args []string) {
		info := k8s.DetectK8s()
		if !info.InCluster {
			fmt.Println("Not running inside Kubernetes")
			return
		}

		secrets, err := k8s.ListSecrets(info, k8sNamespace)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		k8s.DisplaySecrets(secrets)
	},
}

var k8sPrivescCmd = &cobra.Command{
	Use:   "privesc",
	Short: "Check privilege escalation paths",
	Long:  `Check for privilege escalation vulnerabilities in the cluster.`,
	Run: func(cmd *cobra.Command, args []string) {
		info := k8s.DetectK8s()
		if !info.InCluster {
			fmt.Println("Not running inside Kubernetes")
			return
		}

		vulns := k8s.CheckPrivilegeEscalation(info)
		k8s.DisplayVulnerabilities(vulns)
	},
}

var k8sCommandsCmd = &cobra.Command{
	Use:   "commands",
	Short: "Show useful kubectl commands",
	Long:  `Display useful kubectl commands for pentesting.`,
	Run: func(cmd *cobra.Command, args []string) {
		info := k8s.DetectK8s()

		if info.Namespace == "" {
			info.Namespace = "default"
		}

		fmt.Println("\n[USEFUL KUBECTL COMMANDS]")
		fmt.Println("=========================")

		for _, line := range k8s.GenerateKubectlCommands(info) {
			fmt.Println(line)
		}
	},
}

var k8sCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Full Kubernetes security check",
	Long:  `Perform a complete Kubernetes security assessment.`,
	Run: func(cmd *cobra.Command, args []string) {
		info := k8s.DetectK8s()
		k8s.DisplayK8sInfo(info)

		if !info.InCluster {
			return
		}

		// Check RBAC
		rbac := k8s.CheckAPIAccess(info)
		k8s.DisplayRBAC(rbac)

		// Check secrets
		if secrets, err := k8s.ListSecrets(info, ""); err == nil {
			k8s.DisplaySecrets(secrets)
		}

		// Check privesc
		vulns := k8s.CheckPrivilegeEscalation(info)
		k8s.DisplayVulnerabilities(vulns)
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
