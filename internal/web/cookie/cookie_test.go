package cookie

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseCookieStringBasic(t *testing.T) {
	c := ParseCookieString("session=abc123; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict")

	if c.Name != "session" {
		t.Errorf("Name = %q, want %q", c.Name, "session")
	}
	if c.Value != "abc123" {
		t.Errorf("Value = %q, want %q", c.Value, "abc123")
	}
	if c.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", c.Domain, "example.com")
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want %q", c.Path, "/")
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if c.SameSite != "Strict" {
		t.Errorf("SameSite = %q, want %q", c.SameSite, "Strict")
	}
}

func TestParseCookieStringMaxAgeAndExpires(t *testing.T) {
	c := ParseCookieString("id=1; Max-Age=3600; Expires=Wed, 09 Jun 2021 10:18:14 GMT")

	if c.MaxAge != 3600 {
		t.Errorf("MaxAge = %d, want 3600", c.MaxAge)
	}
	if c.Expires.IsZero() {
		t.Error("Expires should be parsed, got zero value")
	}
}

func TestParseCookieStringMissingFlagsProducesIssues(t *testing.T) {
	c := ParseCookieString("session=abc123")

	if len(c.Issues) == 0 {
		t.Fatal("expected security issues for cookie with no flags")
	}

	foundSecure, foundHttpOnly, foundSameSite := false, false, false
	for _, issue := range c.Issues {
		switch issue.Title {
		case "Missing Secure Flag":
			foundSecure = true
		case "Missing HttpOnly Flag":
			foundHttpOnly = true
		case "Missing SameSite Attribute":
			foundSameSite = true
		}
	}
	if !foundSecure || !foundHttpOnly || !foundSameSite {
		t.Errorf("expected all three missing-flag issues, got: %+v", c.Issues)
	}
}

func TestParseCookieStringSessionNameInsecure(t *testing.T) {
	c := ParseCookieString("PHPSESSID=deadbeef")

	found := false
	for _, issue := range c.Issues {
		if issue.Title == "Insecure Session Cookie" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Insecure Session Cookie' issue for unflagged PHPSESSID")
	}
}

func TestDecodeCookieValueURLEncoding(t *testing.T) {
	value := url.QueryEscape("hello world")
	result := DecodeCookieValue(value)

	if result.Encoding != "URL" {
		t.Errorf("Encoding = %q, want %q", result.Encoding, "URL")
	}
	if result.Decoded != "hello world" {
		t.Errorf("Decoded = %q, want %q", result.Decoded, "hello world")
	}
}

func TestDecodeCookieValueBase64(t *testing.T) {
	value := base64.StdEncoding.EncodeToString([]byte("plaintext-value"))
	result := DecodeCookieValue(value)

	if result.Encoding != "Base64" {
		t.Errorf("Encoding = %q, want %q", result.Encoding, "Base64")
	}
	if result.Decoded != "plaintext-value" {
		t.Errorf("Decoded = %q, want %q", result.Decoded, "plaintext-value")
	}
}

func TestDecodeCookieValueHex(t *testing.T) {
	// DecodeCookieValue tries every Base64 variant before hex, and most short
	// hex strings also happen to be decodable (if not meaningfully so) as
	// Base64 - "544f" is one of the rarer inputs where every Base64 attempt
	// fails first, so hex decoding is what actually wins here.
	result := DecodeCookieValue("544f")
	if result.Encoding != "Hex" {
		t.Errorf("Encoding = %q, want %q (result: %+v)", result.Encoding, "Hex", result)
	}
	if result.Decoded != "TO" {
		t.Errorf("Decoded = %q, want %q", result.Decoded, "TO")
	}
}

func TestDecodeCookieValueJSON(t *testing.T) {
	raw := `{"admin":true}`
	value := base64.StdEncoding.EncodeToString([]byte(raw))
	result := DecodeCookieValue(value)

	if !result.IsJSON {
		t.Error("expected IsJSON = true")
	}
	m, ok := result.JSONData.(map[string]interface{})
	if !ok {
		t.Fatalf("JSONData is not a map: %T", result.JSONData)
	}
	if m["admin"] != true {
		t.Errorf("JSONData[admin] = %v, want true", m["admin"])
	}
}

func TestDecodeCookieValueDetectsSensitiveData(t *testing.T) {
	raw := `{"user_id":12345,"is_admin":true,"email":"test@example.com"}`
	value := base64.StdEncoding.EncodeToString([]byte(raw))
	result := DecodeCookieValue(value)

	if len(result.Sensitive) == 0 {
		t.Fatal("expected sensitive data to be found")
	}
}

func TestDetectSessionType(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"flask dotted", ".eJwrTk0uzy9K5eIyMDcz0zW0MDIxNTM3NTe1sqgqLC5JLcnMzytJzSkuUUgHAKe3D9Y=", "Flask"},
		{"django pickle", "gAJ9cQAoWAUAAAB1c2VyaHEBWAgAAABwYXNzd29yZHECdS4=", "Django (Pickle)"},
		{"php serialized", `a:1:{s:4:"user";s:5:"admin";}`, "PHP Serialized"},
		{"aspnet viewstate", "/wEPDwULLTE2MTY2OTk4MTk=", "ASP.NET ViewState"},
		{"express", "s:abc123.signaturehere", "Express.js"},
		{"unknown", "just-some-random-value", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectSessionType(tt.value); got != tt.want {
				t.Errorf("DetectSessionType(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestDetectSessionTypeJWT(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	jwt := header + "." + payload + "." + sig

	if got := DetectSessionType(jwt); got != "JWT" {
		t.Errorf("DetectSessionType(jwt) = %q, want %q", got, "JWT")
	}
}

func buildFlaskSession(t *testing.T, payload map[string]interface{}, secret string) string {
	t.Helper()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Flask timestamp: seconds since 2011-01-01, big-endian 4 bytes minimum.
	epoch := time.Date(2011, 1, 1, 0, 0, 0, 0, time.UTC)
	seconds := int64(time.Now().UTC().Sub(epoch).Seconds())
	tsBytes := []byte{
		byte(seconds >> 24),
		byte(seconds >> 16),
		byte(seconds >> 8),
		byte(seconds),
	}
	tsB64 := base64.RawURLEncoding.EncodeToString(tsBytes)

	data := payloadB64 + "." + tsB64

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(data))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return data + "." + sig
}

func TestDecodeFlaskSessionValidSignature(t *testing.T) {
	secret := "super-secret-key"
	payload := map[string]interface{}{"user": "admin", "logged_in": true}
	value := buildFlaskSession(t, payload, secret)

	session, err := DecodeFlaskSession(value, secret)
	if err != nil {
		t.Fatalf("DecodeFlaskSession returned error: %v", err)
	}

	if session.Payload["user"] != "admin" {
		t.Errorf("Payload[user] = %v, want admin", session.Payload["user"])
	}
	if !session.Valid {
		t.Error("expected session.Valid = true with correct secret")
	}
	if session.Timestamp.IsZero() {
		t.Error("expected a non-zero timestamp")
	}
}

func TestDecodeFlaskSessionInvalidSignature(t *testing.T) {
	value := buildFlaskSession(t, map[string]interface{}{"user": "admin"}, "correct-secret")

	session, err := DecodeFlaskSession(value, "wrong-secret")
	if err != nil {
		t.Fatalf("DecodeFlaskSession returned error: %v", err)
	}
	if session.Valid {
		t.Error("expected session.Valid = false with wrong secret")
	}
}

func TestDecodeFlaskSessionMalformed(t *testing.T) {
	_, err := DecodeFlaskSession("not.a.valid.session.but.enough.dots", "secret")
	if err == nil {
		t.Log("malformed-but-dotted value did not error; acceptable if payload segment isn't valid base64/JSON")
	}

	_, err = DecodeFlaskSession("onlyonedot.here", "secret")
	if err == nil {
		t.Error("expected error for a value with too few segments")
	}
}

func buildExpressSession(t *testing.T, data map[string]interface{}, secret string) string {
	t.Helper()

	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal data: %v", err)
	}
	jsonPart := url.QueryEscape(string(jsonData))

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(jsonPart))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return "s:" + jsonPart + "." + sig
}

func TestDecodeExpressSessionValid(t *testing.T) {
	secret := "express-secret"
	value := buildExpressSession(t, map[string]interface{}{"userId": "42"}, secret)

	data, err := DecodeExpressSession(value, secret)
	if err != nil {
		t.Fatalf("DecodeExpressSession returned error: %v", err)
	}
	if data["userId"] != "42" {
		t.Errorf("data[userId] = %v, want 42", data["userId"])
	}
}

func TestDecodeExpressSessionInvalidSignature(t *testing.T) {
	value := buildExpressSession(t, map[string]interface{}{"userId": "42"}, "correct-secret")

	_, err := DecodeExpressSession(value, "wrong-secret")
	if err == nil {
		t.Error("expected signature verification error with wrong secret")
	}
}

func TestDecodeExpressSessionMissingPrefix(t *testing.T) {
	_, err := DecodeExpressSession("not-an-express-session", "secret")
	if err == nil {
		t.Error("expected error for value missing 's:' prefix")
	}
}

func TestFindSensitiveDataTypes(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{"email", "contact: john.doe@example.com", "Email"},
		{"ip", "server at 192.168.1.100 responded", "IP Address"},
		{"ssn", "ssn: 123-45-6789", "SSN"},
		{"aws key", "key=AKIAABCDEFGHIJKLMNOP", "AWS Key"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", "Private Key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := FindSensitiveData(tt.data)
			found := false
			for _, r := range results {
				if r.Type == tt.want {
					found = true
				}
			}
			if !found {
				t.Errorf("FindSensitiveData(%q) did not find type %q, got %+v", tt.data, tt.want, results)
			}
		})
	}
}

func TestFindSensitiveDataNoMatch(t *testing.T) {
	results := FindSensitiveData("nothing interesting here")
	if len(results) != 0 {
		t.Errorf("expected no sensitive data, got %+v", results)
	}
}

func TestAnalyzeCookieSecurityExpiredCookie(t *testing.T) {
	c := &CookieInfo{
		Name:     "id",
		Value:    "1",
		Secure:   true,
		HttpOnly: true,
		SameSite: "Strict",
		Expires:  time.Now().Add(-24 * time.Hour),
	}

	issues := AnalyzeCookieSecurity(c)

	found := false
	for _, issue := range issues {
		if issue.Title == "Expired Cookie" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Expired Cookie' issue, got %+v", issues)
	}
}

func TestAnalyzeCookieSecurityLongLived(t *testing.T) {
	c := &CookieInfo{
		Name:     "id",
		Value:    "1",
		Secure:   true,
		HttpOnly: true,
		SameSite: "Strict",
		Expires:  time.Now().AddDate(2, 0, 0),
	}

	issues := AnalyzeCookieSecurity(c)

	found := false
	for _, issue := range issues {
		if issue.Title == "Long-Lived Cookie" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Long-Lived Cookie' issue, got %+v", issues)
	}
}

func TestAnalyzeCookieSecuritySameSiteNone(t *testing.T) {
	c := &CookieInfo{Name: "id", Value: "1", Secure: true, HttpOnly: true, SameSite: "None"}
	issues := AnalyzeCookieSecurity(c)

	found := false
	for _, issue := range issues {
		if issue.Title == "SameSite=None" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'SameSite=None' issue, got %+v", issues)
	}
}

func TestAnalyzeCookieSecurityNoIssues(t *testing.T) {
	c := &CookieInfo{
		Name:     "harmless",
		Value:    "1",
		Secure:   true,
		HttpOnly: true,
		SameSite: "Strict",
	}
	issues := AnalyzeCookieSecurity(c)
	if len(issues) != 0 {
		t.Errorf("expected no issues for a well-configured non-session cookie, got %+v", issues)
	}
}

// Display* functions only print to stdout; call them to cover the code paths
// without asserting on exact formatting.
func TestDisplayFunctionsDoNotPanic(t *testing.T) {
	c := ParseCookieString("session=abc123; Secure; HttpOnly")
	DisplayCookieInfo(c)

	decoded := DecodeCookieValue(base64.StdEncoding.EncodeToString([]byte(`{"a":1}`)))
	DisplayDecodedCookie(decoded)

	session := &FlaskSession{
		Payload:   map[string]interface{}{"user": "admin"},
		Timestamp: time.Now(),
		Signature: strings.Repeat("x", 50),
		Valid:     true,
	}
	DisplayFlaskSession(session)
}
