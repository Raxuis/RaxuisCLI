package pwgen

import "testing"

func TestGenerateLength(t *testing.T) {
	pw, err := Generate(Options{Length: 16})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(pw) != 16 {
		t.Errorf("Generate(Length: 16) produced password of length %d, want 16", len(pw))
	}
}

func TestGenerateZeroLength(t *testing.T) {
	pw, err := Generate(Options{Length: 0})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if pw != "" {
		t.Errorf("Generate(Length: 0) = %q, want empty string", pw)
	}
}

func TestGenerateNoSymbols(t *testing.T) {
	pw, err := Generate(Options{Length: 200, NoSymbols: true})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	for _, c := range pw {
		if isInCharset(byte(c), symbols) {
			t.Errorf("Generate(NoSymbols: true) produced a symbol character %q in %q", c, pw)
			break
		}
	}
}

func TestGenerateNoNumbers(t *testing.T) {
	pw, err := Generate(Options{Length: 200, NoNumbers: true})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	for _, c := range pw {
		if isInCharset(byte(c), numbers) {
			t.Errorf("Generate(NoNumbers: true) produced a digit character %q in %q", c, pw)
			break
		}
	}
}

func TestGenerateNoSymbolsNoNumbers(t *testing.T) {
	pw, err := Generate(Options{Length: 200, NoSymbols: true, NoNumbers: true})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	for _, c := range pw {
		if !isInCharset(byte(c), letters) {
			t.Errorf("Generate(NoSymbols, NoNumbers) produced a non-letter character %q in %q", c, pw)
			break
		}
	}
}

func TestGenerateIsRandom(t *testing.T) {
	a, err := Generate(Options{Length: 32})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	b, err := Generate(Options{Length: 32})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if a == b {
		t.Error("two 32-char Generate() calls produced the same password - randomness looks broken")
	}
}

func isInCharset(b byte, charset string) bool {
	for i := 0; i < len(charset); i++ {
		if charset[i] == b {
			return true
		}
	}
	return false
}
