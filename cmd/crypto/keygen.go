package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"raxuiscli/internal/crypto/keygen"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate cryptographic keys and certificates",
	Long: `Generate RSA, ECDSA, Ed25519 keys, SSH keys, and self-signed certificates.

Examples:
  raxuiscli keygen rsa --bits 4096
  raxuiscli keygen ssh --type ed25519
  raxuiscli keygen cert --cn example.com`,
}

var keygenRSACmd = &cobra.Command{
	Use:   "rsa",
	Short: "Generate RSA key pair",
	Long: `Generate an RSA key pair.

Examples:
  raxuiscli keygen rsa
  raxuiscli keygen rsa --bits 4096
  raxuiscli keygen rsa --bits 2048 --out key.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		bits, _ := cmd.Flags().GetInt("bits")
		outFile, _ := cmd.Flags().GetString("out")
		pubFile, _ := cmd.Flags().GetString("pub")

		kp, err := keygen.GenerateRSAKeyPair(bits)
		if err != nil {
			fmt.Printf("Error generating RSA key: %v\n", err)
			return
		}

		keygen.DisplayKeyPair(kp)

		if outFile != "" {
			if pubFile == "" {
				pubFile = outFile + ".pub"
			}
			if err := keygen.SaveKeyPair(kp, outFile, pubFile); err != nil {
				fmt.Printf("Error saving keys: %v\n", err)
				return
			}
			fmt.Printf("\nPrivate key saved to: %s\n", outFile)
			fmt.Printf("Public key saved to:  %s\n", pubFile)
		}
	},
}

var keygenECDSACmd = &cobra.Command{
	Use:   "ecdsa",
	Short: "Generate ECDSA key pair",
	Long: `Generate an ECDSA key pair.

Supported curves: P256, P384, P521

Examples:
  raxuiscli keygen ecdsa
  raxuiscli keygen ecdsa --curve P384
  raxuiscli keygen ecdsa --curve P521 --out key.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		curve, _ := cmd.Flags().GetString("curve")
		outFile, _ := cmd.Flags().GetString("out")
		pubFile, _ := cmd.Flags().GetString("pub")

		kp, err := keygen.GenerateECDSAKeyPair(curve)
		if err != nil {
			fmt.Printf("Error generating ECDSA key: %v\n", err)
			return
		}

		keygen.DisplayKeyPair(kp)

		if outFile != "" {
			if pubFile == "" {
				pubFile = outFile + ".pub"
			}
			if err := keygen.SaveKeyPair(kp, outFile, pubFile); err != nil {
				fmt.Printf("Error saving keys: %v\n", err)
				return
			}
			fmt.Printf("\nPrivate key saved to: %s\n", outFile)
			fmt.Printf("Public key saved to:  %s\n", pubFile)
		}
	},
}

var keygenEd25519Cmd = &cobra.Command{
	Use:   "ed25519",
	Short: "Generate Ed25519 key pair",
	Long: `Generate an Ed25519 key pair.

Ed25519 is a modern, secure, and fast algorithm.

Examples:
  raxuiscli keygen ed25519
  raxuiscli keygen ed25519 --out key.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		outFile, _ := cmd.Flags().GetString("out")
		pubFile, _ := cmd.Flags().GetString("pub")

		kp, err := keygen.GenerateEd25519KeyPair()
		if err != nil {
			fmt.Printf("Error generating Ed25519 key: %v\n", err)
			return
		}

		keygen.DisplayKeyPair(kp)

		if outFile != "" {
			if pubFile == "" {
				pubFile = outFile + ".pub"
			}
			if err := keygen.SaveKeyPair(kp, outFile, pubFile); err != nil {
				fmt.Printf("Error saving keys: %v\n", err)
				return
			}
			fmt.Printf("\nPrivate key saved to: %s\n", outFile)
			fmt.Printf("Public key saved to:  %s\n", pubFile)
		}
	},
}

var keygenSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Generate SSH key pair",
	Long: `Generate an SSH key pair.

Supported types: rsa, ecdsa, ed25519

Examples:
  raxuiscli keygen ssh
  raxuiscli keygen ssh --type ed25519
  raxuiscli keygen ssh --type rsa --bits 4096
  raxuiscli keygen ssh --type ed25519 --out id_ed25519`,
	Run: func(cmd *cobra.Command, args []string) {
		keyType, _ := cmd.Flags().GetString("type")
		bits, _ := cmd.Flags().GetInt("bits")
		outFile, _ := cmd.Flags().GetString("out")

		kp, err := keygen.GenerateSSHKeyPair(keyType, bits)
		if err != nil {
			fmt.Printf("Error generating SSH key: %v\n", err)
			return
		}

		keygen.DisplayKeyPair(kp)

		if outFile != "" {
			pubFile := outFile + ".pub"
			if err := keygen.SaveKeyPair(kp, outFile, pubFile); err != nil {
				fmt.Printf("Error saving keys: %v\n", err)
				return
			}
			fmt.Printf("\nPrivate key saved to: %s\n", outFile)
			fmt.Printf("Public key saved to:  %s\n", pubFile)
		}
	},
}

var keygenCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Generate self-signed certificate",
	Long: `Generate a self-signed X.509 certificate.

Examples:
  raxuiscli keygen cert --cn example.com
  raxuiscli keygen cert --cn test.local --days 365
  raxuiscli keygen cert --cn mysite.com --days 730 --out cert.pem --key key.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		cn, _ := cmd.Flags().GetString("cn")
		days, _ := cmd.Flags().GetInt("days")
		bits, _ := cmd.Flags().GetInt("bits")
		certFile, _ := cmd.Flags().GetString("out")
		keyFile, _ := cmd.Flags().GetString("key")

		if cn == "" {
			fmt.Println("Please provide a Common Name with --cn")
			return
		}

		cert, err := keygen.GenerateSelfSignedCert(cn, days, bits)
		if err != nil {
			fmt.Printf("Error generating certificate: %v\n", err)
			return
		}

		keygen.DisplayCertificate(cert)

		if certFile != "" {
			if keyFile == "" {
				keyFile = strings.TrimSuffix(certFile, ".pem") + ".key"
			}
			if err := keygen.SaveCertificate(cert, certFile, keyFile); err != nil {
				fmt.Printf("Error saving certificate: %v\n", err)
				return
			}
			fmt.Printf("\nCertificate saved to: %s\n", certFile)
			fmt.Printf("Private key saved to: %s\n", keyFile)
		}
	},
}

var keygenAESCmd = &cobra.Command{
	Use:   "aes",
	Short: "Generate AES key",
	Long: `Generate a random AES key.

Supported sizes: 128, 192, 256 bits

Examples:
  raxuiscli keygen aes
  raxuiscli keygen aes --bits 256
  raxuiscli keygen aes --bits 128`,
	Run: func(cmd *cobra.Command, args []string) {
		bits, _ := cmd.Flags().GetInt("bits")

		hexKey, _, err := keygen.GenerateAESKey(bits)
		if err != nil {
			fmt.Printf("Error generating AES key: %v\n", err)
			return
		}

		keygen.DisplayAESKey(hexKey, bits)
	},
}

var keygenRandomCmd = &cobra.Command{
	Use:   "random",
	Short: "Generate random bytes",
	Long: `Generate random bytes (useful for secrets, IVs, etc).

Examples:
  raxuiscli keygen random
  raxuiscli keygen random --length 32
  raxuiscli keygen random --length 16`,
	Run: func(cmd *cobra.Command, args []string) {
		length, _ := cmd.Flags().GetInt("length")

		hexBytes, _, err := keygen.GenerateRandomBytes(length)
		if err != nil {
			fmt.Printf("Error generating random bytes: %v\n", err)
			return
		}

		fmt.Println("\n[RANDOM BYTES GENERATED]")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Length: %d bytes\n", length)
		fmt.Printf("Hex:    %s\n", hexBytes)
	},
}

func init() {
	rootCmd.AddCommand(keygenCmd)

	// RSA command
	keygenCmd.AddCommand(keygenRSACmd)
	keygenRSACmd.Flags().Int("bits", 2048, "Key size in bits (1024, 2048, 4096)")
	keygenRSACmd.Flags().StringP("out", "o", "", "Output file for private key")
	keygenRSACmd.Flags().String("pub", "", "Output file for public key")

	// ECDSA command
	keygenCmd.AddCommand(keygenECDSACmd)
	keygenECDSACmd.Flags().String("curve", "P256", "Elliptic curve (P256, P384, P521)")
	keygenECDSACmd.Flags().StringP("out", "o", "", "Output file for private key")
	keygenECDSACmd.Flags().String("pub", "", "Output file for public key")

	// Ed25519 command
	keygenCmd.AddCommand(keygenEd25519Cmd)
	keygenEd25519Cmd.Flags().StringP("out", "o", "", "Output file for private key")
	keygenEd25519Cmd.Flags().String("pub", "", "Output file for public key")

	// SSH command
	keygenCmd.AddCommand(keygenSSHCmd)
	keygenSSHCmd.Flags().StringP("type", "t", "ed25519", "Key type (rsa, ecdsa, ed25519)")
	keygenSSHCmd.Flags().Int("bits", 4096, "Key size (for RSA/ECDSA)")
	keygenSSHCmd.Flags().StringP("out", "o", "", "Output file for private key")

	// Certificate command
	keygenCmd.AddCommand(keygenCertCmd)
	keygenCertCmd.Flags().String("cn", "", "Common Name (required)")
	keygenCertCmd.Flags().Int("days", 365, "Validity in days")
	keygenCertCmd.Flags().Int("bits", 2048, "RSA key size")
	keygenCertCmd.Flags().StringP("out", "o", "", "Output file for certificate")
	keygenCertCmd.Flags().String("key", "", "Output file for private key")

	// AES command
	keygenCmd.AddCommand(keygenAESCmd)
	keygenAESCmd.Flags().Int("bits", 256, "Key size (128, 192, 256)")

	// Random command
	keygenCmd.AddCommand(keygenRandomCmd)
	keygenRandomCmd.Flags().IntP("length", "l", 32, "Number of bytes to generate")
}
