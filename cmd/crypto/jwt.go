package crypto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/internal/crypto/jwt"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		file, _ := cmd.Flags().GetString("file")
		checkVulns, _ := cmd.Flags().GetBool("check")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			return fmt.Errorf("please provide a JWT token or use -f for file input")
		}

		decoded, err := jwt.DecodeJWT(token)
		if err != nil {
			return fmt.Errorf("decoding JWT: %w", err)
		}

		payload := map[string]any{
			"algorithm": decoded.Algorithm,
			"header":    decoded.Header,
			"payload":   decoded.Payload,
			"signature": decoded.Signature,
		}

		var vulns []jwt.VulnerabilityCheck
		if checkVulns {
			vulns = jwt.CheckVulnerabilities(decoded)
			view := make([]map[string]any, 0, len(vulns))
			for _, v := range vulns {
				view = append(view, map[string]any{
					"name":        v.Name,
					"vulnerable":  v.Vulnerable,
					"description": v.Description,
					"severity":    v.Severity,
				})
			}
			payload["vulnerabilities"] = view
		}

		return output.Emit(payload, func(_ io.Writer) {
			jwt.DisplayJWT(decoded)
			if checkVulns {
				jwt.DisplayVulnerabilities(vulns)
			}
		})
	},
}

var jwtVerifyCmd = &cobra.Command{
	Use:   "verify [token]",
	Short: "Verify JWT signature",
	Long: `Verify JWT signature with the provided secret.

Examples:
  raxuiscli jwt verify "eyJ..." --secret "mysecret"
  raxuiscli jwt verify "eyJ..." --secret-file secret.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		secret, _ := cmd.Flags().GetString("secret")
		secretFile, _ := cmd.Flags().GetString("secret-file")
		file, _ := cmd.Flags().GetString("file")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			return fmt.Errorf("please provide a JWT token")
		}

		if secretFile != "" {
			data, err := os.ReadFile(secretFile)
			if err != nil {
				return fmt.Errorf("reading secret file: %w", err)
			}
			secret = strings.TrimSpace(string(data))
		}

		if secret == "" {
			return fmt.Errorf("please provide a secret with --secret or --secret-file")
		}

		verified, err := jwt.VerifyJWT(token, secret)
		if err != nil {
			return fmt.Errorf("verifying JWT: %w", err)
		}

		return output.Emit(map[string]any{
			"algorithm": verified.Algorithm,
			"header":    verified.Header,
			"payload":   verified.Payload,
			"valid":     verified.Valid,
		}, func(_ io.Writer) {
			jwt.DisplayJWT(verified)
			fmt.Println("[VERIFICATION RESULT]")
			fmt.Println(strings.Repeat("=", 60))
			if verified.Valid {
				fmt.Println("Signature: VALID")
			} else {
				fmt.Println("Signature: INVALID")
			}
		})
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
	RunE: func(cmd *cobra.Command, args []string) error {
		payloadStr, _ := cmd.Flags().GetString("payload")
		secret, _ := cmd.Flags().GetString("secret")
		algorithm, _ := cmd.Flags().GetString("algorithm")

		if payloadStr == "" {
			return fmt.Errorf("please provide a payload with --payload")
		}

		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
			return fmt.Errorf("parsing payload JSON: %w", err)
		}

		token, err := jwt.ForgeJWT(payload, secret, algorithm)
		if err != nil {
			return fmt.Errorf("forging JWT: %w", err)
		}

		decoded, _ := jwt.DecodeJWT(token)
		forgePayload := map[string]any{
			"algorithm": algorithm,
			"token":     token,
		}
		if decoded != nil {
			forgePayload["payload"] = decoded.Payload
		}
		return output.Emit(forgePayload, func(_ io.Writer) {
			fmt.Println("\n[JWT FORGED]")
			fmt.Println(strings.Repeat("=", 60))
			fmt.Printf("Algorithm: %s\n", algorithm)
			fmt.Printf("Token: %s\n", token)
			if decoded != nil {
				fmt.Println("\n[Decoded Payload]")
				payloadJSON, _ := json.MarshalIndent(decoded.Payload, "", "  ")
				fmt.Println(string(payloadJSON))
			}
		})
	},
}

var jwtCrackCmd = &cobra.Command{
	Use:   "crack [token]",
	Short: "Brute force JWT secret",
	Long: `Attempt to crack JWT secret using a wordlist.

Examples:
  raxuiscli jwt crack "eyJ..." --wordlist secrets.txt
  raxuiscli jwt crack "eyJ..." --common`,
	RunE: func(cmd *cobra.Command, args []string) error {
		wordlist, _ := cmd.Flags().GetString("wordlist")
		useCommon, _ := cmd.Flags().GetBool("common")
		file, _ := cmd.Flags().GetString("file")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			return fmt.Errorf("please provide a JWT token")
		}

		var secrets []string

		if useCommon {
			secrets = jwt.CommonSecrets()
			if !output.JSON() {
				fmt.Printf("Using %d common secrets...\n", len(secrets))
			}
		}

		if wordlist != "" {
			f, err := os.Open(wordlist)
			if err != nil {
				return fmt.Errorf("opening wordlist: %w", err)
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				secrets = append(secrets, scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("reading wordlist: %w", err)
			}
			if !output.JSON() {
				fmt.Printf("Loaded %d secrets from wordlist\n", len(secrets))
			}
		}

		if len(secrets) == 0 {
			return fmt.Errorf("please provide --wordlist or --common flag")
		}

		if !output.JSON() {
			fmt.Println("\n[JWT CRACKING]")
			fmt.Println(strings.Repeat("=", 60))
		}

		decoded, err := jwt.DecodeJWT(token)
		if err != nil {
			return fmt.Errorf("decoding JWT: %w", err)
		}
		if !output.JSON() {
			fmt.Printf("Algorithm: %s\n", decoded.Algorithm)
			fmt.Printf("Trying %d secrets...\n\n", len(secrets))
		}

		secret, found := jwt.CrackJWT(token, secrets)

		crackPayload := map[string]any{
			"algorithm": decoded.Algorithm,
			"found":     found,
		}
		if found {
			crackPayload["secret"] = secret
		}
		return output.Emit(crackPayload, func(_ io.Writer) {
			if found {
				fmt.Printf("SECRET FOUND: %s\n", secret)
				fmt.Println("\nYou can now forge tokens with:")
				fmt.Printf("  raxuiscli jwt forge --payload '{...}' --secret '%s'\n", secret)
			} else {
				fmt.Println("Secret not found in wordlist")
			}
		})
	},
}

var jwtNoneCmd = &cobra.Command{
	Use:   "none-attack [token]",
	Short: "Exploit algorithm 'none' vulnerability",
	Long: `Generate JWT tokens with 'none' algorithm to bypass signature verification.

This attack works on vulnerable implementations that accept algorithm:none.

Examples:
  raxuiscli jwt none-attack "eyJ..."`,
	RunE: func(cmd *cobra.Command, args []string) error {
		file, _ := cmd.Flags().GetString("file")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			return fmt.Errorf("please provide a JWT token")
		}

		tokens, err := jwt.NoneAttack(token)
		if err != nil {
			return err
		}

		return output.Emit(map[string]any{"tokens": tokens}, func(_ io.Writer) {
			fmt.Println("\n[NONE ATTACK TOKENS]")
			fmt.Println(strings.Repeat("=", 60))
			fmt.Println("Generated tokens with 'none' algorithm variations:")
			fmt.Println("Test each token to see if the target accepts unsigned JWTs.")
			for i, t := range tokens {
				fmt.Printf("[%d] %s\n\n", i+1, t)
			}
		})
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
	RunE: func(cmd *cobra.Command, args []string) error {
		file, _ := cmd.Flags().GetString("file")

		var token string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}
			token = strings.TrimSpace(string(data))
		} else if len(args) > 0 {
			token = args[0]
		} else {
			return fmt.Errorf("please provide a JWT token")
		}

		decoded, err := jwt.DecodeJWT(token)
		if err != nil {
			return fmt.Errorf("decoding JWT: %w", err)
		}

		vulns := jwt.CheckVulnerabilities(decoded)
		vulnView := make([]map[string]any, 0, len(vulns))
		for _, v := range vulns {
			vulnView = append(vulnView, map[string]any{
				"name":        v.Name,
				"vulnerable":  v.Vulnerable,
				"description": v.Description,
				"severity":    v.Severity,
			})
		}
		return output.Emit(map[string]any{
			"algorithm":       decoded.Algorithm,
			"header":          decoded.Header,
			"payload":         decoded.Payload,
			"vulnerabilities": vulnView,
		}, func(_ io.Writer) {
			jwt.DisplayJWT(decoded)
			jwt.DisplayVulnerabilities(vulns)
		})
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
