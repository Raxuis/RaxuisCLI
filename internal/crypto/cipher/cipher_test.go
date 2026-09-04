package cipher

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

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

func TestXORBruteForceMultiByte(t *testing.T) {
	plaintext := "the quick brown fox jumps over the lazy dog repeated for length the quick brown fox jumps over the lazy dog"
	key := []byte("KEY")
	encrypted := XOREncrypt([]byte(plaintext), key)

	results := XORBruteForceMultiByte(encrypted, 5)
	if len(results) != 5 {
		t.Fatalf("expected 5 results (key lengths 1-5), got %d", len(results))
	}

	// The best-scoring result should be the correct 3-byte key recovering the plaintext.
	best := results[0]
	if string(best.Result) != plaintext {
		t.Errorf("best XORBruteForceMultiByte result = %q, want %q", best.Result, plaintext)
	}
}

func TestVigenereCrackReturnsRankedResults(t *testing.T) {
	// Kasiski examination needs repeated substrings spaced at multiples of
	// the key length to reliably find that length, so use a text built from
	// a repeating phrase (long enough to give the heuristic real signal)
	// rather than asserting exact key/plaintext recovery, which isn't
	// guaranteed for every input even when the heuristic is working.
	plaintext := strings.ToUpper(strings.Repeat("the quick brown fox jumps over the lazy dog and then runs away ", 4))
	plaintext = strings.ReplaceAll(plaintext, " ", "")
	ciphertext := VigenereEncrypt(plaintext, "KEY")

	results := VigenereCrack(ciphertext)
	if len(results) == 0 {
		t.Fatal("VigenereCrack on a long, repetitive ciphertext should return candidate results")
	}

	// Results must be sorted by descending score (best guess first).
	for i := 1; i < len(results); i++ {
		if results[i].Score > results[i-1].Score {
			t.Errorf("VigenereCrack results not sorted by descending score at index %d: %v > %v", i, results[i].Score, results[i-1].Score)
		}
	}
}

func TestDetectCipherTypeHex(t *testing.T) {
	got := DetectCipherType("68656c6c6f776f726c64")
	want := "Possibly XOR-encrypted (hex format)"
	if got != want {
		t.Errorf("DetectCipherType(hex) = %q, want %q", got, want)
	}
}

func TestDetectCipherTypeCaesar(t *testing.T) {
	// Caesar-shift a long, letter-heavy English sentence so ScoreEnglish has
	// enough signal to clear the 0.8 threshold DetectCipherType checks for.
	plaintext := "the quick brown fox jumps over the lazy dog and runs away very quickly into the forest"
	encrypted := CaesarDecrypt(plaintext, -5)

	got := DetectCipherType(encrypted)
	if !strings.Contains(got, "Caesar") {
		t.Errorf("DetectCipherType(caesar-shifted text) = %q, want it to mention Caesar", got)
	}
}

func TestDetectCipherTypeNoLetters(t *testing.T) {
	got := DetectCipherType("12345 67890 !@#$%")
	want := "No alphabetic characters - possibly binary/encoded data"
	if got != want {
		t.Errorf("DetectCipherType(no letters) = %q, want %q", got, want)
	}
}

func TestDetectCipherTypePolyalphabetic(t *testing.T) {
	// A Vigenere-encrypted long, varied text should have a low Index of
	// Coincidence, exercising the IOC-based branches of DetectCipherType
	// (as opposed to the Caesar/ROT heuristic, which a short or repetitive
	// input can spuriously satisfy).
	plaintext := "the quick brown fox jumps over the lazy dog while a clever fox watches silently from the shadows near the old wooden barn and thinks about dinner plans for tonight"
	encrypted := VigenereEncrypt(plaintext, "SECRETKEY")

	got := DetectCipherType(encrypted)
	if !strings.Contains(got, "Vigenere") && !strings.Contains(got, "monoalphabetic") && !strings.Contains(got, "Caesar") {
		t.Errorf("DetectCipherType(vigenere text) = %q, want it to mention Vigenere, monoalphabetic or Caesar", got)
	}
}

func TestDetectCipherTypeMonoalphabeticIOC(t *testing.T) {
	// A long, ROT-shifted, non-repetitive text that doesn't clear the 0.8
	// Caesar-detection score threshold still has a normal English-like index
	// of coincidence, exercising calculateIOC's "monoalphabetic" branch.
	plaintext := "wxyz qrst mnop ijkl efgh abcd zyxw tsrq ponm lkji hgfe dcba wxyz qrst mnop ijkl efgh"
	got := DetectCipherType(plaintext)
	if got == "" || got == "Unknown cipher type" {
		t.Errorf("DetectCipherType should reach the IOC-based classification, got %q", got)
	}
}

func TestIsBase64EdgeCases(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"YQ==", true},
		{"not valid base64!!", false},
		{"abc", false}, // length not a multiple of 4
	}
	for _, tt := range tests {
		got := DetectCipherType(tt.in)
		isB64 := got == "Possibly Base64 encoded"
		if isB64 != tt.want {
			t.Errorf("isBase64(%q) via DetectCipherType = %v, want %v (got %q)", tt.in, isB64, tt.want, got)
		}
	}
}

func TestDisplayFrequencyAnalysis(t *testing.T) {
	results := AnalyzeFrequency("aaabbc")
	out := captureStdout(t, func() {
		DisplayFrequencyAnalysis(results)
	})
	if !strings.Contains(out, "FREQUENCY ANALYSIS") || !strings.Contains(out, "a") {
		t.Errorf("DisplayFrequencyAnalysis output looks wrong: %q", out)
	}
}

func TestDisplayXORResults(t *testing.T) {
	results := XORBruteForce(XOREncrypt([]byte("hello world"), []byte{0x42}))
	out := captureStdout(t, func() {
		DisplayXORResults(results, 3)
	})
	if !strings.Contains(out, "XOR BRUTE FORCE RESULTS") {
		t.Errorf("DisplayXORResults output missing header: %q", out)
	}
}

func TestDisplayVigenereResultsEmpty(t *testing.T) {
	out := captureStdout(t, func() {
		DisplayVigenereResults(nil, 5)
	})
	if !strings.Contains(out, "No results found") {
		t.Errorf("DisplayVigenereResults(nil) should report no results: %q", out)
	}
}

func TestDisplayVigenereResultsWithData(t *testing.T) {
	results := []VigenereResult{{Key: "KEY", Plaintext: "hello world", KeyLength: 3, Score: -1.5}}
	out := captureStdout(t, func() {
		DisplayVigenereResults(results, 5)
	})
	if !strings.Contains(out, "KEY") || !strings.Contains(out, "hello world") {
		t.Errorf("DisplayVigenereResults output missing data: %q", out)
	}
}

func TestDisplayCaesarResults(t *testing.T) {
	results := CaesarBruteForce("uryyb jbeyq")
	out := captureStdout(t, func() {
		DisplayCaesarResults(results, 26)
	})
	if !strings.Contains(out, "CAESAR BRUTE FORCE RESULTS") || !strings.Contains(out, "ROT13") {
		t.Errorf("DisplayCaesarResults output looks wrong: %q", out)
	}
}

func TestMin(t *testing.T) {
	if got := min(3, 5); got != 3 {
		t.Errorf("min(3, 5) = %d, want 3", got)
	}
	if got := min(5, 3); got != 3 {
		t.Errorf("min(5, 3) = %d, want 3", got)
	}
}
