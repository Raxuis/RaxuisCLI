package jwt

import (
	"strings"
	"testing"
	"time"
)

func TestForgeAndVerifyRoundTrip(t *testing.T) {
	algos := []string{"HS256", "HS384", "HS512"}
	payload := map[string]interface{}{"sub": "user1", "admin": false}

	for _, algo := range algos {
		token, err := ForgeJWT(payload, "s3cret", algo)
		if err != nil {
			t.Fatalf("ForgeJWT(%s) returned error: %v", algo, err)
		}

		decoded, err := VerifyJWT(token, "s3cret")
		if err != nil {
			t.Fatalf("VerifyJWT(%s) returned error: %v", algo, err)
		}
		if !decoded.Valid {
			t.Errorf("VerifyJWT(%s) with correct secret should be valid", algo)
		}
		if decoded.Algorithm != algo {
			t.Errorf("Algorithm = %q, want %q", decoded.Algorithm, algo)
		}
		if decoded.Payload["sub"] != "user1" {
			t.Errorf("Payload[sub] = %v, want user1", decoded.Payload["sub"])
		}
	}
}

func TestForgeJWTDefaultAlgorithm(t *testing.T) {
	token, err := ForgeJWT(map[string]interface{}{"a": 1}, "secret", "")
	if err != nil {
		t.Fatalf("ForgeJWT returned error: %v", err)
	}
	decoded, err := DecodeJWT(token)
	if err != nil {
		t.Fatalf("DecodeJWT returned error: %v", err)
	}
	if decoded.Algorithm != "HS256" {
		t.Errorf("default algorithm = %q, want HS256", decoded.Algorithm)
	}
}

func TestForgeJWTUnsupportedAlgorithm(t *testing.T) {
	_, err := ForgeJWT(map[string]interface{}{}, "secret", "HS999")
	if err == nil {
		t.Error("ForgeJWT with unsupported algorithm should return an error")
	}
}

func TestForgeJWTNoneAlgorithm(t *testing.T) {
	token, err := ForgeJWT(map[string]interface{}{"admin": true}, "", "none")
	if err != nil {
		t.Fatalf("ForgeJWT(none) returned error: %v", err)
	}
	if !strings.HasSuffix(token, ".") {
		t.Errorf("none-algorithm token should end with an empty signature segment: %q", token)
	}
}

func TestVerifyJWTTamperedSignatureIsInvalid(t *testing.T) {
	token, err := ForgeJWT(map[string]interface{}{"sub": "user1"}, "secret", "HS256")
	if err != nil {
		t.Fatalf("ForgeJWT returned error: %v", err)
	}

	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + parts[1] + ".invalidsignature"

	decoded, err := VerifyJWT(tampered, "secret")
	if err != nil {
		t.Fatalf("VerifyJWT returned error: %v", err)
	}
	if decoded.Valid {
		t.Error("VerifyJWT with tampered signature should not be valid")
	}
}

func TestVerifyJWTWrongSecretIsInvalid(t *testing.T) {
	token, _ := ForgeJWT(map[string]interface{}{"sub": "user1"}, "correct-secret", "HS256")

	decoded, err := VerifyJWT(token, "wrong-secret")
	if err != nil {
		t.Fatalf("VerifyJWT returned error: %v", err)
	}
	if decoded.Valid {
		t.Error("VerifyJWT with wrong secret should not be valid")
	}
}

func TestVerifyJWTNoneAlgorithm(t *testing.T) {
	token, _ := ForgeJWT(map[string]interface{}{"admin": true}, "", "none")

	decoded, err := VerifyJWT(token, "anything")
	if err != nil {
		t.Fatalf("VerifyJWT(none) returned error: %v", err)
	}
	if !decoded.Valid {
		t.Error("none-algorithm token with empty signature should be considered valid")
	}
}

func TestVerifyJWTUnsupportedAlgorithm(t *testing.T) {
	// Manually build a token with an unsupported algorithm header.
	token, err := ForgeJWT(map[string]interface{}{}, "secret", "none")
	if err != nil {
		t.Fatalf("ForgeJWT returned error: %v", err)
	}
	// Swap header manually to an unsupported alg by forging with a custom algorithm
	// through the header directly isn't exposed, so instead exercise the default
	// branch via a hand-crafted header/payload.
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	parts := strings.Split(token, ".")
	crafted := header + "." + parts[1] + "." + parts[2]

	_, err = VerifyJWT(crafted, "secret")
	if err == nil {
		t.Error("VerifyJWT with unsupported algorithm should return an error")
	}
}

func TestDecodeJWTInvalidFormat(t *testing.T) {
	_, err := DecodeJWT("not.a.valid.jwt.token")
	if err == nil {
		t.Error("DecodeJWT with wrong number of parts should return an error")
	}

	_, err = DecodeJWT("onlyonepart")
	if err == nil {
		t.Error("DecodeJWT with a single part should return an error")
	}
}

func TestDecodeJWTInvalidBase64Header(t *testing.T) {
	_, err := DecodeJWT("!!!not-base64!!!.eyJhIjoxfQ.sig")
	if err == nil {
		t.Error("DecodeJWT with invalid base64 header should return an error")
	}
}

func TestDecodeJWTInvalidJSONPayload(t *testing.T) {
	badPayload := base64URLEncode([]byte("not json"))
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	token := header + "." + badPayload + ".sig"

	_, err := DecodeJWT(token)
	if err == nil {
		t.Error("DecodeJWT with invalid JSON payload should return an error")
	}
}

func TestBase64URLDecodePaddingVariants(t *testing.T) {
	// Payloads of different lengths force base64URLDecode through each padding branch.
	payloads := []map[string]interface{}{
		{"a": 1},
		{"ab": 12},
		{"abc": 123},
		{"abcd": 1234},
	}

	for _, p := range payloads {
		token, err := ForgeJWT(p, "secret", "HS256")
		if err != nil {
			t.Fatalf("ForgeJWT returned error: %v", err)
		}
		decoded, err := DecodeJWT(token)
		if err != nil {
			t.Fatalf("DecodeJWT returned error for payload %v: %v", p, err)
		}
		if len(decoded.Payload) != len(p) {
			t.Errorf("decoded payload length = %d, want %d", len(decoded.Payload), len(p))
		}
	}
}

func TestNoneAttackGeneratesVariations(t *testing.T) {
	token, _ := ForgeJWT(map[string]interface{}{"admin": false}, "secret", "HS256")

	variations, err := NoneAttack(token)
	if err != nil {
		t.Fatalf("NoneAttack returned error: %v", err)
	}
	if len(variations) == 0 {
		t.Fatal("NoneAttack should return at least one variation")
	}

	for _, v := range variations {
		decoded, err := DecodeJWT(v)
		if err != nil {
			t.Fatalf("NoneAttack produced an undecodable token %q: %v", v, err)
		}
		alg := strings.ToLower(decoded.Algorithm)
		if alg != "none" {
			t.Errorf("NoneAttack variation algorithm = %q, want a case variant of none", decoded.Algorithm)
		}
	}
}

func TestNoneAttackInvalidToken(t *testing.T) {
	_, err := NoneAttack("invalid")
	if err == nil {
		t.Error("NoneAttack on an invalid token should return an error")
	}
}

func TestCrackJWTFindsSecret(t *testing.T) {
	token, _ := ForgeJWT(map[string]interface{}{"sub": "u"}, "correct-horse", "HS256")

	wordlist := []string{"wrong1", "wrong2", "correct-horse", "wrong3"}
	secret, found := CrackJWT(token, wordlist)
	if !found {
		t.Fatal("CrackJWT should have found the secret in the wordlist")
	}
	if secret != "correct-horse" {
		t.Errorf("CrackJWT secret = %q, want %q", secret, "correct-horse")
	}
}

func TestCrackJWTNotFound(t *testing.T) {
	token, _ := ForgeJWT(map[string]interface{}{"sub": "u"}, "actual-secret", "HS256")

	_, found := CrackJWT(token, []string{"a", "b", "c"})
	if found {
		t.Error("CrackJWT should not find the secret when it isn't in the wordlist")
	}
}

func TestCrackJWTInvalidToken(t *testing.T) {
	_, found := CrackJWT("not-a-jwt", []string{"a"})
	if found {
		t.Error("CrackJWT on an invalid token should not report found")
	}
}

func TestCrackJWTSkipsUnsupportedAlgorithm(t *testing.T) {
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(`{"sub":"u"}`))
	token := header + "." + payload + ".sig"

	_, found := CrackJWT(token, []string{"a", "b"})
	if found {
		t.Error("CrackJWT should not find a match for an unsupported algorithm")
	}
}

func TestCrackJWTHS384AndHS512(t *testing.T) {
	for _, algo := range []string{"HS384", "HS512"} {
		token, _ := ForgeJWT(map[string]interface{}{"sub": "u"}, "the-secret", algo)
		secret, found := CrackJWT(token, []string{"nope", "the-secret"})
		if !found || secret != "the-secret" {
			t.Errorf("CrackJWT(%s) = (%q, %v), want (the-secret, true)", algo, secret, found)
		}
	}
}

func TestCheckVulnerabilitiesNoneAlgorithm(t *testing.T) {
	jwt := &JWT{Algorithm: "none", Payload: map[string]interface{}{}, Header: map[string]interface{}{}}
	checks := CheckVulnerabilities(jwt)

	if !hasCheck(checks, "Algorithm None") {
		t.Error("expected an 'Algorithm None' vulnerability check")
	}
}

func TestCheckVulnerabilitiesMissingExpiration(t *testing.T) {
	jwt := &JWT{Algorithm: "HS256", Payload: map[string]interface{}{}, Header: map[string]interface{}{}}
	checks := CheckVulnerabilities(jwt)

	if !hasCheck(checks, "Missing Expiration") {
		t.Error("expected a 'Missing Expiration' vulnerability check")
	}
}

func TestCheckVulnerabilitiesExpiredToken(t *testing.T) {
	past := float64(time.Now().Add(-time.Hour).Unix())
	jwt := &JWT{
		Algorithm: "HS256",
		Payload:   map[string]interface{}{"exp": past},
		Header:    map[string]interface{}{},
	}
	checks := CheckVulnerabilities(jwt)

	if !hasCheck(checks, "Expired Token") {
		t.Error("expected an 'Expired Token' vulnerability check")
	}
	if hasCheck(checks, "Missing Expiration") {
		t.Error("did not expect a 'Missing Expiration' check when exp is present")
	}
}

func TestCheckVulnerabilitiesNotExpiredToken(t *testing.T) {
	future := float64(time.Now().Add(time.Hour).Unix())
	jwt := &JWT{
		Algorithm: "HS256",
		Payload:   map[string]interface{}{"exp": future},
		Header:    map[string]interface{}{},
	}
	checks := CheckVulnerabilities(jwt)

	if hasCheck(checks, "Expired Token") {
		t.Error("did not expect an 'Expired Token' check for a future exp claim")
	}
}

func TestCheckVulnerabilitiesSensitiveData(t *testing.T) {
	jwt := &JWT{
		Algorithm: "HS256",
		Payload:   map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix()), "password": "hunter2"},
		Header:    map[string]interface{}{},
	}
	checks := CheckVulnerabilities(jwt)

	if !hasCheck(checks, "Sensitive Data in Payload") {
		t.Error("expected a 'Sensitive Data in Payload' vulnerability check")
	}
}

func TestCheckVulnerabilitiesKidInjection(t *testing.T) {
	jwt := &JWT{
		Algorithm: "HS256",
		Payload:   map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())},
		Header:    map[string]interface{}{"kid": "../../etc/passwd"},
	}
	checks := CheckVulnerabilities(jwt)

	if !hasCheck(checks, "Potential KID Injection") {
		t.Error("expected a 'Potential KID Injection' vulnerability check")
	}
}

func TestCheckVulnerabilitiesKidNotSuspicious(t *testing.T) {
	jwt := &JWT{
		Algorithm: "HS256",
		Payload:   map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())},
		Header:    map[string]interface{}{"kid": "key-1"},
	}
	checks := CheckVulnerabilities(jwt)

	if hasCheck(checks, "Potential KID Injection") {
		t.Error("did not expect a KID injection check for a benign kid value")
	}
}

func TestCheckVulnerabilitiesJKUAndX5U(t *testing.T) {
	jwt := &JWT{
		Algorithm: "HS256",
		Payload:   map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())},
		Header:    map[string]interface{}{"jku": "https://evil.com/keys", "x5u": "https://evil.com/cert"},
	}
	checks := CheckVulnerabilities(jwt)

	if !hasCheck(checks, "JKU Header Present") {
		t.Error("expected a 'JKU Header Present' vulnerability check")
	}
	if !hasCheck(checks, "X5U Header Present") {
		t.Error("expected an 'X5U Header Present' vulnerability check")
	}
}

func hasCheck(checks []VulnerabilityCheck, name string) bool {
	for _, c := range checks {
		if c.Name == name {
			return true
		}
	}
	return false
}

func TestGetClaimTime(t *testing.T) {
	ts := float64(1700000000)
	jwt := &JWT{Payload: map[string]interface{}{"iat": ts}}

	got := GetClaimTime(jwt, "iat")
	want := time.Unix(1700000000, 0).Format(time.RFC3339)
	if got != want {
		t.Errorf("GetClaimTime = %q, want %q", got, want)
	}
}

func TestGetClaimTimeMissingClaim(t *testing.T) {
	jwt := &JWT{Payload: map[string]interface{}{}}
	if got := GetClaimTime(jwt, "exp"); got != "" {
		t.Errorf("GetClaimTime for missing claim = %q, want empty string", got)
	}
}

func TestGetClaimTimeWrongType(t *testing.T) {
	jwt := &JWT{Payload: map[string]interface{}{"exp": "not-a-number"}}
	if got := GetClaimTime(jwt, "exp"); got != "" {
		t.Errorf("GetClaimTime for non-numeric claim = %q, want empty string", got)
	}
}

func TestCommonSecretsNonEmpty(t *testing.T) {
	secrets := CommonSecrets()
	if len(secrets) == 0 {
		t.Fatal("CommonSecrets should return a non-empty list")
	}
	for _, s := range secrets {
		if s == "" {
			t.Error("CommonSecrets should not contain empty entries")
		}
	}
}

func TestCrackJWTAgainstCommonSecrets(t *testing.T) {
	token, _ := ForgeJWT(map[string]interface{}{"sub": "u"}, "password", "HS256")

	secret, found := CrackJWT(token, CommonSecrets())
	if !found || secret != "password" {
		t.Errorf("CrackJWT against CommonSecrets = (%q, %v), want (password, true)", secret, found)
	}
}

// Display* functions only print to stdout; exercised here for coverage and to
// make sure they don't panic on both short and long field values.
func TestDisplayFunctionsDoNotPanic(t *testing.T) {
	token, _ := ForgeJWT(map[string]interface{}{
		"sub": "user1",
		"iat": float64(time.Now().Unix()),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"nbf": float64(time.Now().Unix()),
	}, "secret", "HS256")

	decoded, err := DecodeJWT(token)
	if err != nil {
		t.Fatalf("DecodeJWT returned error: %v", err)
	}

	DisplayJWT(decoded)

	checks := CheckVulnerabilities(decoded)
	DisplayVulnerabilities(checks)
	DisplayVulnerabilities(nil)

	// Long signature branch
	decoded.Signature = strings.Repeat("a", 100)
	DisplayJWT(decoded)
}
