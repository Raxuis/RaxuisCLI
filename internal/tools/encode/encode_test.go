package encode

import "testing"

func TestEncodeDecodeRoundTrip(t *testing.T) {
	input := "Hello, World! 123"

	formats := []Format{FormatBase64, FormatBase32, FormatHex, FormatURL, FormatHTML, FormatROT13}

	for _, format := range formats {
		opts := Options{Format: format}

		encoded, err := Encode(input, opts)
		if err != nil {
			t.Fatalf("Encode(%s) returned error: %v", format, err)
		}

		decoded, err := Decode(encoded, opts)
		if err != nil {
			t.Fatalf("Decode(%s) returned error: %v", format, err)
		}

		if decoded != input {
			t.Errorf("%s round trip failed: got %q, want %q", format, decoded, input)
		}
	}
}

func TestEncodeDecodeROTN(t *testing.T) {
	input := "Hello World"
	opts := Options{Format: FormatROTN, Shift: 5}

	encoded, err := Encode(input, opts)
	if err != nil {
		t.Fatalf("Encode(rotn) returned error: %v", err)
	}

	decoded, err := Decode(encoded, opts)
	if err != nil {
		t.Fatalf("Decode(rotn) returned error: %v", err)
	}

	if decoded != input {
		t.Errorf("ROTN round trip failed: got %q, want %q", decoded, input)
	}
}

func TestEncodeUnsupportedFormat(t *testing.T) {
	_, err := Encode("test", Options{Format: "bogus"})
	if err == nil {
		t.Error("Encode with unsupported format should return an error")
	}
}

func TestDecodeUnsupportedFormat(t *testing.T) {
	_, err := Decode("test", Options{Format: "bogus"})
	if err == nil {
		t.Error("Decode with unsupported format should return an error")
	}
}

func TestDecodeInvalidBase64(t *testing.T) {
	_, err := Decode("not valid base64!!!", Options{Format: FormatBase64})
	if err == nil {
		t.Error("Decode with invalid base64 should return an error")
	}
}

func TestDecodeHexWithPrefixAndSeparators(t *testing.T) {
	tests := []string{
		"68656c6c6f",
		"0x68656c6c6f",
		"68:65:6c:6c:6f",
		"68 65 6c 6c 6f",
	}

	for _, hexInput := range tests {
		decoded, err := Decode(hexInput, Options{Format: FormatHex})
		if err != nil {
			t.Fatalf("Decode(hex, %q) returned error: %v", hexInput, err)
		}
		if decoded != "hello" {
			t.Errorf("Decode(hex, %q) = %q, want %q", hexInput, decoded, "hello")
		}
	}
}

func TestEncodeAllReturnsAllFormats(t *testing.T) {
	results := EncodeAll("test")
	expectedKeys := []string{"base64", "base32", "hex", "url", "html", "rot13"}

	for _, key := range expectedKeys {
		if _, ok := results[key]; !ok {
			t.Errorf("EncodeAll result missing key %q", key)
		}
	}
}

func TestBruteForceROTIncludesOriginalShift(t *testing.T) {
	plaintext := "hello"
	shift := 9
	encoded, _ := Encode(plaintext, Options{Format: FormatROTN, Shift: shift})

	results := BruteForceROT(encoded)
	if len(results) != 25 {
		t.Fatalf("expected 25 results (shifts 1-25), got %d", len(results))
	}

	decodeShift := 26 - shift
	if results[decodeShift] != plaintext {
		t.Errorf("BruteForceROT[%d] = %q, want %q", decodeShift, results[decodeShift], plaintext)
	}
}

func TestGetSupportedFormats(t *testing.T) {
	formats := GetSupportedFormats()
	if len(formats) != 7 {
		t.Errorf("expected 7 supported formats, got %d", len(formats))
	}
}
