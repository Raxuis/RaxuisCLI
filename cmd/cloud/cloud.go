package cloud

import (
	"errors"
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/cloud/cloud"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var cloudTimeout int
var cloudThreads int

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Cloud infrastructure enumeration",
	Long: `Cloud enumeration toolkit for AWS, Azure, and GCP.

Enumerate public cloud resources like S3 buckets, Azure blob storage,
and GCP storage buckets. Also detect cloud metadata services.

Examples:
  raxuiscli cloud aws s3 companyname       # Enumerate S3 buckets
  raxuiscli cloud azure blob companyname   # Enumerate Azure blobs
  raxuiscli cloud gcp bucket companyname   # Enumerate GCP buckets
  raxuiscli cloud metadata aws             # Check AWS metadata`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

// AWS commands
var cloudAwsCmd = &cobra.Command{
	Use:   "aws",
	Short: "AWS enumeration",
	Long:  `AWS cloud resource enumeration.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var cloudAwsS3Cmd = &cobra.Command{
	Use:   "s3 [company]",
	Short: "Enumerate S3 buckets",
	Long: `Enumerate S3 buckets for a company by trying common naming patterns.

Tries various mutations like company-dev, company-backup, etc.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		company := args[0]

		fmt.Fprintf(output.Std, "Enumerating S3 buckets for '%s'...\n", company)

		results := cloud.EnumerateS3(company, nil, cloudTimeout)
		cloud.DisplayS3Results(results)
		var failures []error
		for _, result := range results {
			if result.Error != nil {
				failures = append(failures, result.Error)
			}
		}
		if len(results) > 0 && len(failures) == len(results) {
			return fmt.Errorf("S3 enumeration failed: %w", errors.Join(failures...))
		}
		return nil
	},
}

var cloudAwsMetaCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Check AWS metadata service",
	Long:  `Check if AWS instance metadata service is accessible (SSRF/IMDSv1).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(output.Std, "Checking AWS metadata service...")

		metadata, err := cloud.CheckAWSMetadata(cloudTimeout)
		if err != nil {
			return err
		}

		cloud.DisplayMetadata("aws", metadata)
		return nil
	},
}

// Azure commands
var cloudAzureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Azure enumeration",
	Long:  `Azure cloud resource enumeration.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var cloudAzureBlobCmd = &cobra.Command{
	Use:   "blob [company]",
	Short: "Enumerate Azure blob storage",
	Long: `Enumerate Azure blob storage accounts for a company.

Tries various mutations and common container names.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		company := args[0]

		fmt.Fprintf(output.Std, "Enumerating Azure blob storage for '%s'...\n", company)

		results := cloud.EnumerateAzure(company, nil, cloudTimeout)
		cloud.DisplayAzureResults(results)
		var failures []error
		for _, result := range results {
			if result.Error != nil {
				failures = append(failures, result.Error)
			}
		}
		if len(results) > 0 && len(failures) == len(results) {
			return fmt.Errorf("azure enumeration failed: %w", errors.Join(failures...))
		}
		return nil
	},
}

var cloudAzureMetaCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Check Azure metadata service",
	Long:  `Check if Azure instance metadata service is accessible.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(output.Std, "Checking Azure metadata service...")

		metadata, err := cloud.CheckAzureMetadata(cloudTimeout)
		if err != nil {
			return err
		}

		cloud.DisplayMetadata("azure", metadata)
		return nil
	},
}

// GCP commands
var cloudGcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "GCP enumeration",
	Long:  `GCP cloud resource enumeration.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var cloudGcpBucketCmd = &cobra.Command{
	Use:   "bucket [company]",
	Short: "Enumerate GCP storage buckets",
	Long: `Enumerate GCP storage buckets for a company.

Tries various naming patterns and mutations.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		company := args[0]

		fmt.Fprintf(output.Std, "Enumerating GCP buckets for '%s'...\n", company)

		results := cloud.EnumerateGCP(company, nil, cloudTimeout)
		cloud.DisplayGCPResults(results)
		var failures []error
		for _, result := range results {
			if result.Error != nil {
				failures = append(failures, result.Error)
			}
		}
		if len(results) > 0 && len(failures) == len(results) {
			return fmt.Errorf("GCP enumeration failed: %w", errors.Join(failures...))
		}
		return nil
	},
}

var cloudGcpMetaCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Check GCP metadata service",
	Long:  `Check if GCP instance metadata service is accessible.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(output.Std, "Checking GCP metadata service...")

		metadata, err := cloud.CheckGCPMetadata(cloudTimeout)
		if err != nil {
			return err
		}

		cloud.DisplayMetadata("gcp", metadata)
		return nil
	},
}

// Metadata check all
var cloudMetadataCmd = &cobra.Command{
	Use:   "metadata [provider]",
	Short: "Check cloud metadata service",
	Long: `Check cloud metadata service accessibility.

Useful for SSRF detection and cloud instance enumeration.
Provider can be: aws, azure, gcp, or all.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		provider := args[0]

		switch provider {
		case "aws":
			metadata, err := cloud.CheckAWSMetadata(cloudTimeout)
			if err != nil {
				return fmt.Errorf("AWS metadata: %w", err)
			} else {
				cloud.DisplayMetadata("aws", metadata)
			}
		case "azure":
			metadata, err := cloud.CheckAzureMetadata(cloudTimeout)
			if err != nil {
				return fmt.Errorf("azure metadata: %w", err)
			} else {
				cloud.DisplayMetadata("azure", metadata)
			}
		case "gcp":
			metadata, err := cloud.CheckGCPMetadata(cloudTimeout)
			if err != nil {
				return fmt.Errorf("GCP metadata: %w", err)
			} else {
				cloud.DisplayMetadata("gcp", metadata)
			}
		case "all":
			fmt.Fprintln(output.Std, "Checking all cloud metadata services...")
			var failures []error
			successes := 0
			if metadata, err := cloud.CheckAWSMetadata(cloudTimeout); err == nil {
				successes++
				cloud.DisplayMetadata("aws", metadata)
			} else {
				failures = append(failures, fmt.Errorf("aws metadata: %w", err))
			}
			if metadata, err := cloud.CheckAzureMetadata(cloudTimeout); err == nil {
				successes++
				cloud.DisplayMetadata("azure", metadata)
			} else {
				failures = append(failures, fmt.Errorf("azure metadata: %w", err))
			}
			if metadata, err := cloud.CheckGCPMetadata(cloudTimeout); err == nil {
				successes++
				cloud.DisplayMetadata("gcp", metadata)
			} else {
				failures = append(failures, fmt.Errorf("gcp metadata: %w", err))
			}
			if successes == 0 {
				return errors.Join(failures...)
			}
		default:
			return fmt.Errorf("unknown provider: %s", provider)
		}
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(cloudCmd)

	// Global flags
	cloudCmd.PersistentFlags().IntVarP(&cloudTimeout, "timeout", "t", 5, "Request timeout")
	cloudCmd.PersistentFlags().IntVar(&cloudThreads, "threads", 10, "Number of threads")

	// AWS subcommands
	cloudCmd.AddCommand(cloudAwsCmd)
	cloudAwsCmd.AddCommand(cloudAwsS3Cmd)
	cloudAwsCmd.AddCommand(cloudAwsMetaCmd)

	// Azure subcommands
	cloudCmd.AddCommand(cloudAzureCmd)
	cloudAzureCmd.AddCommand(cloudAzureBlobCmd)
	cloudAzureCmd.AddCommand(cloudAzureMetaCmd)

	// GCP subcommands
	cloudCmd.AddCommand(cloudGcpCmd)
	cloudGcpCmd.AddCommand(cloudGcpBucketCmd)
	cloudGcpCmd.AddCommand(cloudGcpMetaCmd)

	// Direct metadata command
	cloudCmd.AddCommand(cloudMetadataCmd)
}
