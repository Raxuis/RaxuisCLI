package tools

import (
	"fmt"
	"os"

	"raxuiscli/cmd"

	"raxuiscli/internal/tools/files"

	"github.com/spf13/cobra"
)

var filesCmd = &cobra.Command{
	Use:   "files",
	Short: "File operations",
	Long:  `Perform various file operations such as encryption, decryption, compression, and more.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := cmd.Help()
		if err != nil {
			fmt.Println("Error displaying help:", err)
			return
		}
	},
}

var filesEncryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt a file",
	Long:  `Encrypt a file using a specified encryption algorithm.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		algo, _ := cmd.Flags().GetString("algo")
		password, _ := cmd.Flags().GetString("password")
		keyFile, _ := cmd.Flags().GetString("key-file")
		out, _ := cmd.Flags().GetString("out")
		overwrite, _ := cmd.Flags().GetBool("overwrite")
		armor, _ := cmd.Flags().GetBool("armor")
		salt, _ := cmd.Flags().GetBool("salt")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if verbose {
			fmt.Printf("Encrypting file: %s with algorithm: %s\n", args[0], algo)
		}

		opts := files.EncryptOptions{
			Algorithm:  algo,
			Password:   password,
			KeyFile:    keyFile,
			OutputPath: out,
			Overwrite:  overwrite,
			Armor:      armor,
			Salt:       salt,
		}

		if err := files.Encrypt(args[0], opts); err != nil {
			_, err2 := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if err2 != nil {
				return
			}
			os.Exit(1)
		}
	},
}

var filesDecryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt a file",
	Long:  `Decrypt a file using a specified decryption algorithm.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		algo, _ := cmd.Flags().GetString("algo")
		password, _ := cmd.Flags().GetString("password")
		keyFile, _ := cmd.Flags().GetString("key-file")
		out, _ := cmd.Flags().GetString("out")
		overwrite, _ := cmd.Flags().GetBool("overwrite")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if verbose {
			fmt.Printf("Decrypting file: %s with algorithm: %s\n", args[0], algo)
		}

		opts := files.DecryptOptions{
			Algorithm:  algo,
			Password:   password,
			KeyFile:    keyFile,
			OutputPath: out,
			Overwrite:  overwrite,
		}

		if err := files.Decrypt(args[0], opts); err != nil {
			_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if err != nil {
				return
			}
			os.Exit(1)
		}
	},
}

var filesShredCmd = &cobra.Command{
	Use:   "shred [file...]",
	Short: "Securely delete files",
	Long:  `Securely delete files by overwriting them multiple times.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		passes, _ := cmd.Flags().GetInt("passes")
		random, _ := cmd.Flags().GetBool("random")
		zero, _ := cmd.Flags().GetBool("zero")
		recursive, _ := cmd.Flags().GetBool("recursive")
		force, _ := cmd.Flags().GetBool("force")
		yes, _ := cmd.Flags().GetBool("yes")

		if yes {
			force = true
		}

		opts := files.ShredOptions{
			Passes:    passes,
			Random:    random,
			Zero:      zero,
			Recursive: recursive,
			Force:     force,
		}

		if err := files.Shred(args, opts); err != nil {
			_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if err != nil {
				return
			}
			os.Exit(1)
		}
	},
}

var filesChecksumCmd = &cobra.Command{
	Use:   "checksum [file...]",
	Short: "Calculate file checksums",
	Long:  `Calculate and verify file checksums using various algorithms.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		algo, _ := cmd.Flags().GetString("algo")
		verify, _ := cmd.Flags().GetString("verify")
		output, _ := cmd.Flags().GetString("output")
		recursive, _ := cmd.Flags().GetBool("recursive")
		relative, _ := cmd.Flags().GetBool("relative")

		opts := files.ChecksumOptions{
			Algorithm: algo,
			Verify:    verify,
			Output:    output,
			Recursive: recursive,
			Relative:  relative,
		}

		if err := files.Checksum(args, opts); err != nil {
			_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if err != nil {
				return
			}
			os.Exit(1)
		}
	},
}

var filesFindCmd = &cobra.Command{
	Use:   "find [path...]",
	Short: "Find files",
	Long:  `Find files based on various criteria like name, content, size, and modification time.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name, _ := cmd.Flags().GetString("name")
		contains, _ := cmd.Flags().GetString("contains")
		regex, _ := cmd.Flags().GetBool("regex")
		size, _ := cmd.Flags().GetString("size")
		mtime, _ := cmd.Flags().GetString("mtime")
		exec, _ := cmd.Flags().GetString("exec")

		opts := files.FindOptions{
			Name:     name,
			Contains: contains,
			Regex:    regex,
			Size:     size,
			Mtime:    mtime,
			Exec:     exec,
		}

		if err := files.Find(args, opts); err != nil {
			_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if err != nil {
				return
			}
			os.Exit(1)
		}
	},
}

var filesCompressCmd = &cobra.Command{
	Use:   "compress [files...]",
	Short: "Compress files",
	Long:  `Compress files into an archive using various formats.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		out, _ := cmd.Flags().GetString("out")
		password, _ := cmd.Flags().GetString("password")
		overwrite, _ := cmd.Flags().GetBool("overwrite")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if verbose {
			fmt.Printf("Compressing files to %s format\n", format)
			fmt.Printf("Output: %s\n", out)
		}

		opts := files.CompressOptions{
			Format:    format,
			Output:    out,
			Password:  password,
			Overwrite: overwrite,
		}

		if err := files.Compress(args, opts); err != nil {
			_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if err != nil {
				return
			}
			os.Exit(1)
		}
	},
}

var filesExtractCmd = &cobra.Command{
	Use:   "extract [archive]",
	Short: "Extract archive",
	Long:  `Extract files from an archive.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		stripComponents, _ := cmd.Flags().GetInt("strip-components")
		password, _ := cmd.Flags().GetString("password")
		overwrite, _ := cmd.Flags().GetBool("overwrite")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if verbose {
			fmt.Printf("Extracting archive: %s\n", args[0])
			fmt.Printf("Format: %s, Strip components: %d\n", format, stripComponents)
		}

		opts := files.ExtractOptions{
			Format:          format,
			StripComponents: stripComponents,
			Password:        password,
			Overwrite:       overwrite,
		}

		if err := files.Extract(args[0], opts); err != nil {
			_, err := fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if err != nil {
				return
			}
			os.Exit(1)
		}
	},
}

func init() {
	cmd.RootCmd.AddCommand(filesCmd)

	filesCmd.AddCommand(filesEncryptCmd)
	filesCmd.AddCommand(filesDecryptCmd)
	filesCmd.AddCommand(filesShredCmd)
	filesCmd.AddCommand(filesChecksumCmd)
	filesCmd.AddCommand(filesFindCmd)
	filesCmd.AddCommand(filesCompressCmd)
	filesCmd.AddCommand(filesExtractCmd)

	filesEncryptCmd.Flags().String("algo", "aes256", "Encryption algorithm (aes256|chacha20|rsa)")
	filesEncryptCmd.Flags().String("password", "", "Passphrase for encryption")
	filesEncryptCmd.Flags().String("key-file", "", "Path to key material")
	filesEncryptCmd.Flags().String("out", "", "Output file path")
	filesEncryptCmd.Flags().Bool("overwrite", false, "Overwrite the original file in place")
	filesEncryptCmd.Flags().Bool("armor", false, "ASCII-armored output")
	filesEncryptCmd.Flags().Bool("salt", true, "Use salt (use --no-salt to disable)")

	filesDecryptCmd.Flags().String("algo", "aes256", "Decryption algorithm (aes256|chacha20|rsa)")
	filesDecryptCmd.Flags().String("password", "", "Passphrase for decryption")
	filesDecryptCmd.Flags().String("key-file", "", "Path to key material")
	filesDecryptCmd.Flags().String("out", "", "Output file path")
	filesDecryptCmd.Flags().Bool("overwrite", false, "Overwrite the original file in place")

	filesShredCmd.Flags().Int("passes", 3, "Number of overwrite passes")
	filesShredCmd.Flags().Bool("random", false, "Use random data instead of fixed patterns")
	filesShredCmd.Flags().Bool("zero", false, "Final overwrite with zeros")
	filesShredCmd.Flags().Bool("recursive", false, "Shred directories recursively")
	filesShredCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	filesChecksumCmd.Flags().String("algo", "sha256", "Hashing algorithm (md5|sha1|sha256|sha512|blake2)")
	filesChecksumCmd.Flags().String("verify", "", "Verify checksums from a manifest file")
	filesChecksumCmd.Flags().String("output", "", "Write checksums to a file")
	filesChecksumCmd.Flags().Bool("recursive", false, "Walk directories")
	filesChecksumCmd.Flags().Bool("relative", false, "Store relative paths in manifest")

	filesFindCmd.Flags().String("name", "", "Glob pattern for file names")
	filesFindCmd.Flags().String("contains", "", "Search file contents")
	filesFindCmd.Flags().Bool("regex", false, "Treat --contains as regex")
	filesFindCmd.Flags().String("size", "", "Filter by file size (e.g., >10M, <1K)")
	filesFindCmd.Flags().String("mtime", "", "Modified time filter (e.g., -7d, +1h)")
	filesFindCmd.Flags().String("exec", "", "Run command for each match")

	filesCompressCmd.Flags().String("format", "zip", "Archive format (zip|tar|gz|bz2|xz)")
	filesCompressCmd.Flags().String("out", "", "Output archive name")
	filesCompressCmd.Flags().String("password", "", "Password for protected archives")
	filesCompressCmd.Flags().Bool("overwrite", false, "Replace existing files")

	filesExtractCmd.Flags().String("format", "", "Archive format (auto-detect if empty)")
	filesExtractCmd.Flags().Int("strip-components", 0, "Strip directory levels when extracting")
	filesExtractCmd.Flags().String("password", "", "Password for protected archives")
	filesExtractCmd.Flags().Bool("overwrite", false, "Replace existing files")

	commands := []*cobra.Command{
		filesEncryptCmd, filesDecryptCmd, filesShredCmd,
		filesChecksumCmd, filesFindCmd, filesCompressCmd, filesExtractCmd,
	}

	for _, cmd := range commands {
		cmd.Flags().Bool("quiet", false, "Suppress normal output")
		cmd.Flags().Bool("verbose", false, "Print extra logs")
		cmd.Flags().Bool("dry-run", false, "Simulate actions")
		cmd.Flags().Bool("yes", false, "Skip confirmations")
	}
}
