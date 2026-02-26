package crypto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"raxuiscli/cmd"
	"strings"

	"github.com/spf13/cobra"

	"raxuiscli/internal/crypto/jwt"
)

var jwtCmd = &cobra.Command{
	Use:   "jwt",
	Short: "JWT token operations (decode, forge, crack, attack)",
	Long: `Work with JSON Web Tokens (JWT).

Decode, verify, forge, and attack JWT tokens.`,
}

var jwtDecodeCmd = &cobra.Command{
	Use:   "decode [token]",
	Short: "Decode JWT without verification",
	Long: `Decode and display JWT header and payload without verifying signature.

Examples:
  raxuiscli jwt decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  raxuiscli jwt decode -f token.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")
		checkVulns, _ := cmd.Flags().GetBool("check")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			fmt.Println("Please provide a JWT token or use -f for file input")
			return
		}

		decoded, err := jwt.DecodeJWT(token)
		if err != nil {
			fmt.Printf("Error decoding JWT: %v\n", err)
			return
		}

		jwt.DisplayJWT(decoded)

		if checkVulns {
			vulns := jwt.CheckVulnerabilities(decoded)
			jwt.DisplayVulnerabilities(vulns)
		}
	},
}

var jwtVerifyCmd = &cobra.Command{
	Use:   "verify [token]",
	Short: "Verify JWT signature",
	Long: `Verify JWT signature with the provided secret.

Examples:
  raxuiscli jwt verify "eyJ..." --secret "mysecret"
  raxuiscli jwt verify "eyJ..." --secret-file secret.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		secret, _ := cmd.Flags().GetString("secret")
		secretFile, _ := cmd.Flags().GetString("secret-file")
		file, _ := cmd.Flags().GetString("file")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			fmt.Println("Please provide a JWT token")
			return
		}

		if secretFile != "" {
			data, err := os.ReadFile(secretFile)
			if err != nil {
				fmt.Printf("Error reading secret file: %v\n", err)
				return
			}
			secret = strings.TrimSpace(string(data))
		}

		if secret == "" {
			fmt.Println("Please provide a secret with --secret or --secret-file")
			return
		}

		verified, err := jwt.VerifyJWT(token, secret)
		if err != nil {
			fmt.Printf("Error verifying JWT: %v\n", err)
			return
		}

		jwt.DisplayJWT(verified)

		fmt.Println("[VERIFICATION RESULT]")
		fmt.Println(strings.Repeat("=", 60))
		if verified.Valid {
			fmt.Println("Signature: VALID")
		} else {
			fmt.Println("Signature: INVALID")
		}
	},
}

var jwtForgeCmd = &cobra.Command{
	Use:   "forge",
	Short: "Create a new JWT token",
	Long: `Forge a new JWT token with custom payload.

Examples:
  raxuiscli jwt forge --payload '{"sub":"admin","admin":true}' --secret "key"
  raxuiscli jwt forge --payload '{"user":"test"}' --algorithm HS512 --secret "key"
  raxuiscli jwt forge --payload '{}' --algorithm none`,
	Run: func(cmd *cobra.Command, args []string) {
		payloadStr, _ := cmd.Flags().GetString("payload")
		secret, _ := cmd.Flags().GetString("secret")
		algorithm, _ := cmd.Flags().GetString("algorithm")

		if payloadStr == "" {
			fmt.Println("Please provide a payload with --payload")
			return
		}

		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
			fmt.Printf("Error parsing payload JSON: %v\n", err)
			return
		}

		token, err := jwt.ForgeJWT(payload, secret, algorithm)
		if err != nil {
			fmt.Printf("Error forging JWT: %v\n", err)
			return
		}

		fmt.Println("\n[JWT FORGED]")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Algorithm: %s\n", algorithm)
		fmt.Printf("Token: %s\n", token)

		// Also decode and show it
		decoded, _ := jwt.DecodeJWT(token)
		if decoded != nil {
			fmt.Println("\n[Decoded Payload]")
			payloadJSON, _ := json.MarshalIndent(decoded.Payload, "", "  ")
			fmt.Println(string(payloadJSON))
		}
	},
}

var jwtCrackCmd = &cobra.Command{
	Use:   "crack [token]",
	Short: "Brute force JWT secret",
	Long: `Attempt to crack JWT secret using a wordlist.

Examples:
  raxuiscli jwt crack "eyJ..." --wordlist secrets.txt
  raxuiscli jwt crack "eyJ..." --common`,
	Run: func(cmd *cobra.Command, args []string) {
		wordlist, _ := cmd.Flags().GetString("wordlist")
		useCommon, _ := cmd.Flags().GetBool("common")
		file, _ := cmd.Flags().GetString("file")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			fmt.Println("Please provide a JWT token")
			return
		}

		var secrets []string

		if useCommon {
			secrets = jwt.CommonSecrets()
			fmt.Printf("Using %d common secrets...\n", len(secrets))
		}

		if wordlist != "" {
			f, err := os.Open(wordlist)
			if err != nil {
				fmt.Printf("Error opening wordlist: %v\n", err)
				return
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				secrets = append(secrets, scanner.Text())
			}
			fmt.Printf("Loaded %d secrets from wordlist\n", len(secrets))
		}

		if len(secrets) == 0 {
			fmt.Println("Please provide --wordlist or --common flag")
			return
		}

		fmt.Println("\n[JWT CRACKING]")
		fmt.Println(strings.Repeat("=", 60))

		decoded, err := jwt.DecodeJWT(token)
		if err != nil {
			fmt.Printf("Error decoding JWT: %v\n", err)
			return
		}
		fmt.Printf("Algorithm: %s\n", decoded.Algorithm)
		fmt.Printf("Trying %d secrets...\n\n", len(secrets))

		secret, found := jwt.CrackJWT(token, secrets)

		if found {
			fmt.Printf("SECRET FOUND: %s\n", secret)
			fmt.Println("\nYou can now forge tokens with:")
			fmt.Printf("  raxuiscli jwt forge --payload '{...}' --secret '%s'\n", secret)
		} else {
			fmt.Println("Secret not found in wordlist")
		}
	},
}

var jwtNoneCmd = &cobra.Command{
	Use:   "none-attack [token]",
	Short: "Exploit algorithm 'none' vulnerability",
	Long: `Generate JWT tokens with 'none' algorithm to bypass signature verification.

This attack works on vulnerable implementations that accept algorithm:none.

Examples:
  raxuiscli jwt none-attack "eyJ..."`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			fmt.Println("Please provide a JWT token")
			return
		}

		tokens, err := jwt.NoneAttack(token)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Println("\n[NONE ATTACK TOKENS]")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println("Generated tokens with 'none' algorithm variations:")
		fmt.Println("Test each token to see if the target accepts unsigned JWTs.\n")

		for i, t := range tokens {
			fmt.Printf("[%d] %s\n\n", i+1, t)
		}
	},
}

var jwtCheckCmd = &cobra.Command{
	Use:   "check [token]",
	Short: "Check JWT for vulnerabilities",
	Long: `Analyze JWT for common security issues.

Checks for:
- Algorithm 'none' vulnerability
- Missing expiration
- Weak algorithms
- Sensitive data exposure
- JKU/X5U header injection
- KID header injection

Examples:
  raxuiscli jwt check "eyJ..."`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			fmt.Println("Please provide a JWT token")
			return
		}

		decoded, err := jwt.DecodeJWT(token)
		if err != nil {
			fmt.Printf("Error decoding JWT: %v\n", err)
			return
		}

		jwt.DisplayJWT(decoded)

		vulns := jwt.CheckVulnerabilities(decoded)
		jwt.DisplayVulnerabilities(vulns)
	},
}

func init() {
	cmd.RootCmd.AddCommand(jwtCmd)

	// Decode command
	jwtCmd.AddCommand(jwtDecodeCmd)
	jwtDecodeCmd.Flags().StringP("file", "f", "", "Read token from file")
	jwtDecodeCmd.Flags().BoolP("check", "c", false, "Check for vulnerabilities")

	// Verify command
	jwtCmd.AddCommand(jwtVerifyCmd)
	jwtVerifyCmd.Flags().StringP("file", "f", "", "Read token from file")
	jwtVerifyCmd.Flags().StringP("secret", "s", "", "Secret key for verification")
	jwtVerifyCmd.Flags().String("secret-file", "", "Read secret from file")

	// Forge command
	jwtCmd.AddCommand(jwtForgeCmd)
	jwtForgeCmd.Flags().StringP("payload", "p", "", "JSON payload")
	jwtForgeCmd.Flags().StringP("secret", "s", "", "Secret key")
	jwtForgeCmd.Flags().StringP("algorithm", "a", "HS256", "Algorithm (HS256, HS384, HS512, none)")

	// Crack command
	jwtCmd.AddCommand(jwtCrackCmd)
	jwtCrackCmd.Flags().StringP("file", "f", "", "Read token from file")
	jwtCrackCmd.Flags().StringP("wordlist", "w", "", "Wordlist file")
	jwtCrackCmd.Flags().Bool("common", false, "Use common secrets list")

	// None attack command
	jwtCmd.AddCommand(jwtNoneCmd)
	jwtNoneCmd.Flags().StringP("file", "f", "", "Read token from file")

	// Check command
	jwtCmd.AddCommand(jwtCheckCmd)
	jwtCheckCmd.Flags().StringP("file", "f", "", "Read token from file")
}
