package cipher

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
)

// English letter frequencies (percentage)
var EnglishFreq = map[rune]float64{
	'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
	'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
	'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
	'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
	'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
	'z': 0.074,
}

// FrequencyResult holds frequency analysis results
type FrequencyResult struct {
	Char      rune
	Count     int
	Frequency float64
}

// XORResult holds XOR operation results
type XORResult struct {
	Key       []byte
	KeyString string
	Result    []byte
	Printable bool
	Score     float64
}

// VigenereResult holds Vigenere crack results
type VigenereResult struct {
	Key           string
	Plaintext     string
	KeyLength     int
	Score         float64
	KasiskiSpaces []int
}

// XOREncrypt performs XOR encryption/decryption
func XOREncrypt(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return result
}

// XORBruteForce attempts to brute force single-byte XOR key
func XORBruteForce(data []byte) []XORResult {
	var results []XORResult

	for key := 0; key <= 255; key++ {
		keyByte := byte(key)
		decrypted := XOREncrypt(data, []byte{keyByte})

		score := ScoreEnglish(decrypted)
		printable := IsPrintable(decrypted)

		results = append(results, XORResult{
			Key:       []byte{keyByte},
			KeyString: fmt.Sprintf("0x%02x", keyByte),
			Result:    decrypted,
			Printable: printable,
			Score:     score,
		})
	}

	// Sort by score (higher is better)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

// XORBruteForceMultiByte attempts multi-byte XOR key brute force
func XORBruteForceMultiByte(data []byte, maxKeyLen int) []XORResult {
	var results []XORResult

	for keyLen := 1; keyLen <= maxKeyLen; keyLen++ {
		// For each key length, find the best key byte for each position
		key := make([]byte, keyLen)

		for pos := 0; pos < keyLen; pos++ {
			// Extract bytes at this position
			var posBytes []byte
			for i := pos; i < len(data); i += keyLen {
				posBytes = append(posBytes, data[i])
			}

			// Find best single-byte key for these bytes
			bestScore := -1.0
			bestKey := byte(0)
			for k := 0; k <= 255; k++ {
				decrypted := XOREncrypt(posBytes, []byte{byte(k)})
				score := ScoreEnglish(decrypted)
				if score > bestScore {
					bestScore = score
					bestKey = byte(k)
				}
			}
			key[pos] = bestKey
		}

		decrypted := XOREncrypt(data, key)
		score := ScoreEnglish(decrypted)

		results = append(results, XORResult{
			Key:       key,
			KeyString: fmt.Sprintf("%q (hex: %x)", string(key), key),
			Result:    decrypted,
			Printable: IsPrintable(decrypted),
			Score:     score,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

// VigenereEncrypt encrypts using Vigenere cipher
func VigenereEncrypt(plaintext, key string) string {
	if len(key) == 0 {
		return plaintext
	}

	key = strings.ToUpper(key)
	var result strings.Builder
	keyIndex := 0

	for _, char := range plaintext {
		if unicode.IsLetter(char) {
			base := 'A'
			if unicode.IsLower(char) {
				base = 'a'
			}
			shift := int(key[keyIndex%len(key)] - 'A')
			encrypted := rune((int(unicode.ToUpper(char)-'A')+shift)%26) + base
			result.WriteRune(encrypted)
			keyIndex++
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// VigenereDecrypt decrypts using Vigenere cipher
func VigenereDecrypt(ciphertext, key string) string {
	if len(key) == 0 {
		return ciphertext
	}

	key = strings.ToUpper(key)
	var result strings.Builder
	keyIndex := 0

	for _, char := range ciphertext {
		if unicode.IsLetter(char) {
			base := 'A'
			if unicode.IsLower(char) {
				base = 'a'
			}
			shift := int(key[keyIndex%len(key)] - 'A')
			decrypted := rune((int(unicode.ToUpper(char)-'A')-shift+26)%26) + base
			result.WriteRune(decrypted)
			keyIndex++
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// VigenereCrack attempts to crack Vigenere cipher using Kasiski examination
func VigenereCrack(ciphertext string) []VigenereResult {
	var results []VigenereResult

	// Clean text - letters only
	cleanText := ""
	for _, c := range strings.ToUpper(ciphertext) {
		if unicode.IsLetter(c) {
			cleanText += string(c)
		}
	}

	if len(cleanText) < 20 {
		return results
	}

	// Find likely key lengths using Kasiski
	keyLengths := kasiskiExamination(cleanText)

	// Try each likely key length
	for _, keyLen := range keyLengths {
		if keyLen < 1 || keyLen > 20 {
			continue
		}

		key := crackVigenereKey(cleanText, keyLen)
		plaintext := VigenereDecrypt(ciphertext, key)
		score := ScoreEnglish([]byte(plaintext))

		results = append(results, VigenereResult{
			Key:           key,
			Plaintext:     plaintext,
			KeyLength:     keyLen,
			Score:         score,
			KasiskiSpaces: keyLengths,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

// kasiskiExamination finds likely key lengths
func kasiskiExamination(text string) []int {
	distances := make(map[int]int)

	// Find repeated sequences of length 3+
	for seqLen := 3; seqLen <= 5; seqLen++ {
		for i := 0; i <= len(text)-seqLen; i++ {
			seq := text[i : i+seqLen]
			for j := i + seqLen; j <= len(text)-seqLen; j++ {
				if text[j:j+seqLen] == seq {
					dist := j - i
					// Find factors of distance
					for f := 2; f <= min(dist, 20); f++ {
						if dist%f == 0 {
							distances[f]++
						}
					}
				}
			}
		}
	}

	// Sort by frequency
	type kv struct {
		Key   int
		Value int
	}
	var sorted []kv
	for k, v := range distances {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	var result []int
	for i := 0; i < min(5, len(sorted)); i++ {
		result = append(result, sorted[i].Key)
	}

	// Add common key lengths if not found
	if len(result) == 0 {
		result = []int{3, 4, 5, 6, 7}
	}

	return result
}

// crackVigenereKey cracks Vigenere key of known length
func crackVigenereKey(text string, keyLen int) string {
	key := make([]byte, keyLen)

	for i := 0; i < keyLen; i++ {
		// Extract every keyLen-th character starting at position i
		var subset string
		for j := i; j < len(text); j += keyLen {
			subset += string(text[j])
		}

		// Find the shift that produces best frequency match
		bestShift := 0
		bestScore := -math.MaxFloat64

		for shift := 0; shift < 26; shift++ {
			// Decrypt subset with this shift
			var decrypted string
			for _, c := range subset {
				decrypted += string(rune((int(c-'A')-shift+26)%26) + 'A')
			}

			score := frequencyMatchScore(decrypted)
			if score > bestScore {
				bestScore = score
				bestShift = shift
			}
		}

		key[i] = byte('A' + bestShift)
	}

	return string(key)
}

// frequencyMatchScore calculates how well text matches English frequencies
func frequencyMatchScore(text string) float64 {
	if len(text) == 0 {
		return 0
	}

	// Count frequencies
	counts := make(map[rune]int)
	total := 0
	for _, c := range text {
		if unicode.IsLetter(c) {
			counts[unicode.ToLower(c)]++
			total++
		}
	}

	if total == 0 {
		return 0
	}

	// Calculate chi-squared distance from English
	score := 0.0
	for char, expected := range EnglishFreq {
		observed := float64(counts[char]) / float64(total) * 100
		diff := observed - expected
		score -= diff * diff / expected
	}

	return score
}

// AnalyzeFrequency performs frequency analysis on text
func AnalyzeFrequency(text string) []FrequencyResult {
	counts := make(map[rune]int)
	total := 0

	for _, c := range text {
		if unicode.IsLetter(c) {
			counts[unicode.ToLower(c)]++
			total++
		}
	}

	var results []FrequencyResult
	for char, count := range counts {
		freq := float64(count) / float64(total) * 100
		results = append(results, FrequencyResult{
			Char:      char,
			Count:     count,
			Frequency: freq,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Count > results[j].Count
	})

	return results
}

// CaesarDecrypt decrypts Caesar cipher with given shift
func CaesarDecrypt(text string, shift int) string {
	var result strings.Builder

	for _, char := range text {
		if unicode.IsLetter(char) {
			base := 'A'
			if unicode.IsLower(char) {
				base = 'a'
			}
			decrypted := rune((int(unicode.ToUpper(char)-'A')-shift+26)%26) + base
			result.WriteRune(decrypted)
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// CaesarBruteForce tries all 26 shifts
func CaesarBruteForce(text string) []struct {
	Shift int
	Text  string
	Score float64
} {
	var results []struct {
		Shift int
		Text  string
		Score float64
	}

	for shift := 0; shift < 26; shift++ {
		decrypted := CaesarDecrypt(text, shift)
		score := ScoreEnglish([]byte(decrypted))
		results = append(results, struct {
			Shift int
			Text  string
			Score float64
		}{shift, decrypted, score})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

// ROT13 applies ROT13
func ROT13(text string) string {
	return CaesarDecrypt(text, 13)
}

// AtbashDecrypt decrypts Atbash cipher
func AtbashDecrypt(text string) string {
	var result strings.Builder

	for _, char := range text {
		if unicode.IsLetter(char) {
			base := 'A'
			if unicode.IsLower(char) {
				base = 'a'
			}
			// A->Z, B->Y, etc.
			decrypted := rune(25-int(unicode.ToUpper(char)-'A')) + base
			result.WriteRune(decrypted)
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// DetectCipherType attempts to detect the type of cipher
func DetectCipherType(text string) string {
	// Check if it's hex
	isHex := true
	for _, c := range text {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ' ') {
			isHex = false
			break
		}
	}
	if isHex && len(strings.ReplaceAll(text, " ", ""))%2 == 0 {
		return "Possibly XOR-encrypted (hex format)"
	}

	// Check if it's Base64
	if isBase64(text) {
		return "Possibly Base64 encoded"
	}

	// Count letters only
	letterCount := 0
	for _, c := range text {
		if unicode.IsLetter(c) {
			letterCount++
		}
	}

	if letterCount == 0 {
		return "No alphabetic characters - possibly binary/encoded data"
	}

	// Frequency analysis
	freq := AnalyzeFrequency(text)
	if len(freq) == 0 {
		return "Unknown"
	}

	// Check for Caesar/ROT13 (single letter shift)
	topChar := freq[0].Char
	expectedTop := []rune{'e', 't', 'a', 'o', 'i', 'n'}

	for _, expected := range expectedTop {
		shift := (int(topChar) - int(expected) + 26) % 26
		if shift != 0 {
			decrypted := CaesarDecrypt(text, shift)
			score := ScoreEnglish([]byte(decrypted))
			if score > 0.8 {
				return fmt.Sprintf("Likely Caesar cipher (shift %d or ROT%d)", shift, shift)
			}
		}
	}

	// Check Index of Coincidence for Vigenere
	ioc := calculateIOC(text)
	if ioc < 0.050 {
		return "Likely polyalphabetic cipher (Vigenere)"
	} else if ioc > 0.060 {
		return "Likely monoalphabetic substitution"
	}

	return "Unknown cipher type"
}

// calculateIOC calculates Index of Coincidence
func calculateIOC(text string) float64 {
	counts := make(map[rune]int)
	total := 0

	for _, c := range strings.ToUpper(text) {
		if c >= 'A' && c <= 'Z' {
			counts[c]++
			total++
		}
	}

	if total < 2 {
		return 0
	}

	sum := 0.0
	for _, count := range counts {
		sum += float64(count * (count - 1))
	}

	return sum / float64(total*(total-1))
}

// isBase64 checks if text looks like Base64
func isBase64(text string) bool {
	text = strings.TrimSpace(text)
	if len(text) == 0 || len(text)%4 != 0 {
		return false
	}

	for _, c := range text {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// ScoreEnglish scores how likely text is English
func ScoreEnglish(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	score := 0.0
	letterCount := 0
	spaceCount := 0

	for _, b := range data {
		c := rune(b)
		if c >= 'a' && c <= 'z' {
			score += EnglishFreq[c]
			letterCount++
		} else if c >= 'A' && c <= 'Z' {
			score += EnglishFreq[unicode.ToLower(c)]
			letterCount++
		} else if c == ' ' {
			score += 13.0 // Space is very common
			spaceCount++
		} else if c == '.' || c == ',' || c == '!' || c == '?' || c == '\'' || c == '"' {
			score += 1.0
		} else if c < 32 || c > 126 {
			score -= 10.0 // Penalize non-printable
		}
	}

	// Normalize
	if letterCount > 0 {
		score /= float64(len(data))
	}

	// Bonus for reasonable space ratio
	if len(data) > 10 {
		spaceRatio := float64(spaceCount) / float64(len(data))
		if spaceRatio > 0.1 && spaceRatio < 0.25 {
			score *= 1.5
		}
	}

	return score
}

// IsPrintable checks if data contains only printable ASCII
func IsPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			if b != '\n' && b != '\r' && b != '\t' {
				return false
			}
		}
	}
	return true
}

// DisplayFrequencyAnalysis displays frequency analysis results
func DisplayFrequencyAnalysis(results []FrequencyResult) {
	fmt.Println("\n[FREQUENCY ANALYSIS]")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\n%-6s %-8s %-10s %s\n", "CHAR", "COUNT", "FREQ %", "BAR")
	fmt.Println(strings.Repeat("-", 60))

	for _, r := range results {
		barLen := int(r.Frequency / 2)
		bar := strings.Repeat("█", barLen)

		// Compare to English
		expectedFreq := EnglishFreq[r.Char]
		diff := r.Frequency - expectedFreq
		diffStr := ""
		if diff > 0 {
			diffStr = fmt.Sprintf(" (+%.1f)", diff)
		} else if diff < 0 {
			diffStr = fmt.Sprintf(" (%.1f)", diff)
		}

		fmt.Printf("%-6c %-8d %-10.2f %s%s\n", r.Char, r.Count, r.Frequency, bar, diffStr)
	}

	fmt.Println()
}

// DisplayXORResults displays XOR brute force results
func DisplayXORResults(results []XORResult, maxResults int) {
	fmt.Println("\n[XOR BRUTE FORCE RESULTS]")
	fmt.Println(strings.Repeat("=", 60))

	count := 0
	for _, r := range results {
		if count >= maxResults {
			break
		}

		if !r.Printable && count > 3 {
			continue
		}

		fmt.Printf("\nKey: %s (score: %.2f)\n", r.KeyString, r.Score)

		// Show preview of result
		preview := string(r.Result)
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		// Make non-printable visible
		preview = strings.Map(func(r rune) rune {
			if r < 32 || r > 126 {
				return '.'
			}
			return r
		}, preview)

		fmt.Printf("Result: %s\n", preview)
		count++
	}

	fmt.Println()
}

// DisplayVigenereResults displays Vigenere crack results
func DisplayVigenereResults(results []VigenereResult, maxResults int) {
	fmt.Println("\n[VIGENERE CRACK RESULTS]")
	fmt.Println(strings.Repeat("=", 60))

	if len(results) == 0 {
		fmt.Println("No results found. Text may be too short or not Vigenere encrypted.")
		return
	}

	count := 0
	for _, r := range results {
		if count >= maxResults {
			break
		}

		fmt.Printf("\nKey: %s (length: %d, score: %.2f)\n", r.Key, r.KeyLength, r.Score)

		preview := r.Plaintext
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		fmt.Printf("Plaintext: %s\n", preview)
		count++
	}

	fmt.Println()
}

// DisplayCaesarResults displays Caesar brute force results
func DisplayCaesarResults(results []struct {
	Shift int
	Text  string
	Score float64
}, maxResults int) {
	fmt.Println("\n[CAESAR BRUTE FORCE RESULTS]")
	fmt.Println(strings.Repeat("=", 60))

	for i, r := range results {
		if i >= maxResults {
			break
		}

		rotName := ""
		if r.Shift == 13 {
			rotName = " (ROT13)"
		}

		preview := r.Text
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}

		fmt.Printf("\nShift %2d%s (score: %.2f): %s\n", r.Shift, rotName, r.Score, preview)
	}

	fmt.Println()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
