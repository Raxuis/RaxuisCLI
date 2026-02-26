package cmd

import (
	"fmt"
	"os"
	"raxuiscli/internal/cloud"

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
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// AWS commands
var cloudAwsCmd = &cobra.Command{
	Use:   "aws",
	Short: "AWS enumeration",
	Long:  `AWS cloud resource enumeration.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var cloudAwsS3Cmd = &cobra.Command{
	Use:   "s3 [company]",
	Short: "Enumerate S3 buckets",
	Long: `Enumerate S3 buckets for a company by trying common naming patterns.

Tries various mutations like company-dev, company-backup, etc.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		company := args[0]

		fmt.Printf("Enumerating S3 buckets for '%s'...\n", company)

		results := cloud.EnumerateS3(company, nil, cloudTimeout)
		cloud.DisplayS3Results(results)
	},
}

var cloudAwsMetaCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Check AWS metadata service",
	Long:  `Check if AWS instance metadata service is accessible (SSRF/IMDSv1).`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Checking AWS metadata service...")

		metadata, err := cloud.CheckAWSMetadata(cloudTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		cloud.DisplayMetadata("aws", metadata)
	},
}

// Azure commands
var cloudAzureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Azure enumeration",
	Long:  `Azure cloud resource enumeration.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var cloudAzureBlobCmd = &cobra.Command{
	Use:   "blob [company]",
	Short: "Enumerate Azure blob storage",
	Long: `Enumerate Azure blob storage accounts for a company.

Tries various mutations and common container names.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		company := args[0]

		fmt.Printf("Enumerating Azure blob storage for '%s'...\n", company)

		results := cloud.EnumerateAzure(company, nil, cloudTimeout)
		cloud.DisplayAzureResults(results)
	},
}

var cloudAzureMetaCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Check Azure metadata service",
	Long:  `Check if Azure instance metadata service is accessible.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Checking Azure metadata service...")

		metadata, err := cloud.CheckAzureMetadata(cloudTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		cloud.DisplayMetadata("azure", metadata)
	},
}

// GCP commands
var cloudGcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "GCP enumeration",
	Long:  `GCP cloud resource enumeration.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var cloudGcpBucketCmd = &cobra.Command{
	Use:   "bucket [company]",
	Short: "Enumerate GCP storage buckets",
	Long: `Enumerate GCP storage buckets for a company.

Tries various naming patterns and mutations.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		company := args[0]

		fmt.Printf("Enumerating GCP buckets for '%s'...\n", company)

		results := cloud.EnumerateGCP(company, nil, cloudTimeout)
		cloud.DisplayGCPResults(results)
	},
}

var cloudGcpMetaCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Check GCP metadata service",
	Long:  `Check if GCP instance metadata service is accessible.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Checking GCP metadata service...")

		metadata, err := cloud.CheckGCPMetadata(cloudTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		cloud.DisplayMetadata("gcp", metadata)
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
	Run: func(cmd *cobra.Command, args []string) {
		provider := args[0]

		switch provider {
		case "aws":
			metadata, err := cloud.CheckAWSMetadata(cloudTimeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "AWS Error: %v\n", err)
			} else {
				cloud.DisplayMetadata("aws", metadata)
			}
		case "azure":
			metadata, err := cloud.CheckAzureMetadata(cloudTimeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Azure Error: %v\n", err)
			} else {
				cloud.DisplayMetadata("azure", metadata)
			}
		case "gcp":
			metadata, err := cloud.CheckGCPMetadata(cloudTimeout)
			if err != nil {
				fmt.Fprintf(os.Stderr, "GCP Error: %v\n", err)
			} else {
				cloud.DisplayMetadata("gcp", metadata)
			}
		case "all":
			fmt.Println("Checking all cloud metadata services...")
			if metadata, err := cloud.CheckAWSMetadata(cloudTimeout); err == nil {
				cloud.DisplayMetadata("aws", metadata)
			}
			if metadata, err := cloud.CheckAzureMetadata(cloudTimeout); err == nil {
				cloud.DisplayMetadata("azure", metadata)
			}
			if metadata, err := cloud.CheckGCPMetadata(cloudTimeout); err == nil {
				cloud.DisplayMetadata("gcp", metadata)
			}
		default:
			fmt.Fprintf(os.Stderr, "Unknown provider: %s\n", provider)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(cloudCmd)

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
