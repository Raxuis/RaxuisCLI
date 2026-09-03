package cipher

import "testing"

func TestXOREncryptRoundTrip(t *testing.T) {
	data := []byte("Hello, World!")
	key := []byte("secret")

	encrypted := XOREncrypt(data, key)
	decrypted := XOREncrypt(encrypted, key)

	if string(decrypted) != string(data) {
		t.Errorf("XOREncrypt round trip failed: got %q, want %q", decrypted, data)
	}
}

func TestXOREncryptEmptyKey(t *testing.T) {
	data := []byte("unchanged")
	result := XOREncrypt(data, nil)

	if string(result) != string(data) {
		t.Errorf("XOREncrypt with empty key should return data unchanged: got %q, want %q", result, data)
	}
}

func TestXORBruteForceFindsSingleByteKey(t *testing.T) {
	plaintext := "the quick brown fox jumps over the lazy dog"
	key := byte(0x42)
	encrypted := XOREncrypt([]byte(plaintext), []byte{key})

	results := XORBruteForce(encrypted)
	if len(results) != 256 {
		t.Fatalf("expected 256 results, got %d", len(results))
	}

	best := results[0]
	if string(best.Result) != plaintext {
		t.Errorf("best XOR brute force result = %q, want %q", best.Result, plaintext)
	}
}

func TestVigenereRoundTrip(t *testing.T) {
	tests := []struct {
		plaintext string
		key       string
	}{
		{"HELLO WORLD", "KEY"},
		{"attackatdawn", "lemon"},
		{"Mixed Case Text", "Secret"},
	}

	for _, tt := range tests {
		encrypted := VigenereEncrypt(tt.plaintext, tt.key)
		decrypted := VigenereDecrypt(encrypted, tt.key)

		if decrypted != tt.plaintext {
			t.Errorf("Vigenere round trip failed for key %q: got %q, want %q", tt.key, decrypted, tt.plaintext)
		}
	}
}

func TestVigenereEncryptEmptyKey(t *testing.T) {
	text := "unchanged"
	if got := VigenereEncrypt(text, ""); got != text {
		t.Errorf("VigenereEncrypt with empty key = %q, want %q", got, text)
	}
}

func TestVigenereEncryptKnownVector(t *testing.T) {
	// Classic textbook example
	got := VigenereEncrypt("ATTACKATDAWN", "LEMON")
	want := "LXFOPVEFRNHR"

	if got != want {
		t.Errorf("VigenereEncrypt(ATTACKATDAWN, LEMON) = %q, want %q", got, want)
	}
}

func TestCaesarDecryptAndROT13(t *testing.T) {
	plaintext := "HELLO WORLD"
	encrypted := CaesarDecrypt(plaintext, -3) // shift by -3 to encrypt with shift 3
	decrypted := CaesarDecrypt(encrypted, 3)

	if decrypted != plaintext {
		t.Errorf("Caesar round trip failed: got %q, want %q", decrypted, plaintext)
	}

	rot13Encoded := CaesarDecrypt(plaintext, -13)
	rot13Decoded := ROT13(rot13Encoded)
	if rot13Decoded != plaintext {
		t.Errorf("ROT13 round trip failed: got %q, want %q", rot13Decoded, plaintext)
	}
}

func TestROT13SelfInverse(t *testing.T) {
	text := "The Quick Brown Fox"
	if got := ROT13(ROT13(text)); got != text {
		t.Errorf("ROT13 applied twice should return original: got %q, want %q", got, text)
	}
}

func TestAtbashSelfInverse(t *testing.T) {
	text := "HELLO WORLD"
	if got := AtbashDecrypt(AtbashDecrypt(text)); got != text {
		t.Errorf("Atbash applied twice should return original: got %q, want %q", got, text)
	}
}

func TestAtbashKnownVector(t *testing.T) {
	got := AtbashDecrypt("ABCZ")
	want := "ZYXA"
	if got != want {
		t.Errorf("AtbashDecrypt(ABCZ) = %q, want %q", got, want)
	}
}

func TestCaesarBruteForceIncludesCorrectShift(t *testing.T) {
	plaintext := "the quick brown fox jumps over the lazy dog"
	shift := 7
	encrypted := CaesarDecrypt(plaintext, -shift)

	results := CaesarBruteForce(encrypted)
	if len(results) != 26 {
		t.Fatalf("expected 26 results, got %d", len(results))
	}

	found := false
	for _, r := range results {
		if r.Text == plaintext {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CaesarBruteForce did not include correct plaintext %q among results", plaintext)
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		data []byte
		want bool
	}{
		{[]byte("hello world"), true},
		{[]byte("line1\nline2\ttab"), true},
		{[]byte{0x00, 0x01, 0x02}, false},
		{[]byte{0xff}, false},
		{[]byte(""), true},
	}

	for _, tt := range tests {
		if got := IsPrintable(tt.data); got != tt.want {
			t.Errorf("IsPrintable(%v) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

func TestAnalyzeFrequency(t *testing.T) {
	results := AnalyzeFrequency("aaabbc")
	if len(results) != 3 {
		t.Fatalf("expected 3 distinct characters, got %d", len(results))
	}

	// Results are sorted by count descending, so 'a' (count 3) should be first
	if results[0].Char != 'a' || results[0].Count != 3 {
		t.Errorf("top frequency char = %c (count %d), want a (count 3)", results[0].Char, results[0].Count)
	}
}

func TestVigenereCrackShortTextReturnsEmpty(t *testing.T) {
	results := VigenereCrack("short")
	if len(results) != 0 {
		t.Errorf("VigenereCrack on text < 20 letters should return no results, got %d", len(results))
	}
}

func TestDetectCipherTypeBase64(t *testing.T) {
	got := DetectCipherType("SGVsbG8gV29ybGQ=")
	want := "Possibly Base64 encoded"
	if got != want {
		t.Errorf("DetectCipherType(base64) = %q, want %q", got, want)
	}
}
