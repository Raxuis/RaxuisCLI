package files

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestGlobToRegex(t *testing.T) {
	pattern := globToRegex("*.txt")
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("globToRegex(*.txt) produced an invalid regex %q: %v", pattern, err)
	}
	if !re.MatchString("file.txt") {
		t.Errorf("globToRegex(*.txt) should match file.txt")
	}
	if re.MatchString("file.go") {
		t.Errorf("globToRegex(*.txt) should not match file.go")
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"100", 100, false},
		{"10K", 10 * 1024, false},
		{"5M", 5 * 1024 * 1024, false},
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"1T", 1024 * 1024 * 1024 * 1024, false},
		{"", 0, true},
		{"10X", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := parseSize(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseSize(%q) should return an error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSize(%q) returned error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseSize(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseSizeFilter(t *testing.T) {
	f, err := parseSizeFilter(">10")
	if err != nil {
		t.Fatalf("parseSizeFilter(>10) returned error: %v", err)
	}
	if !f(20) || f(5) {
		t.Error("parseSizeFilter(>10) predicate incorrect")
	}

	f, err = parseSizeFilter("<10")
	if err != nil {
		t.Fatalf("parseSizeFilter(<10) returned error: %v", err)
	}
	if !f(5) || f(20) {
		t.Error("parseSizeFilter(<10) predicate incorrect")
	}

	f, err = parseSizeFilter("=10")
	if err != nil {
		t.Fatalf("parseSizeFilter(=10) returned error: %v", err)
	}
	if !f(10) || f(11) {
		t.Error("parseSizeFilter(=10) predicate incorrect")
	}

	if _, err := parseSizeFilter("~10"); err == nil {
		t.Error("parseSizeFilter with an invalid operator should return an error")
	}

	f, err = parseSizeFilter("")
	if err != nil || f != nil {
		t.Error("parseSizeFilter(\"\") should return a nil filter and no error")
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"30s", 30 * time.Second, false},
		{"5m", 5 * time.Minute, false},
		{"2h", 2 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"", 0, true},
		{"5x", 0, true},
		{"abcd", 0, true},
	}
	for _, tt := range tests {
		got, err := parseDuration(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseDuration(%q) should return an error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDuration(%q) returned error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseTimeFilter(t *testing.T) {
	f, err := parseTimeFilter("-1h")
	if err != nil {
		t.Fatalf("parseTimeFilter(-1h) returned error: %v", err)
	}
	if !f(time.Now()) {
		t.Error("parseTimeFilter(-1h) should match a file modified now (within the last hour)")
	}
	if f(time.Now().Add(-48 * time.Hour)) {
		t.Error("parseTimeFilter(-1h) should not match a file modified 48h ago")
	}

	f, err = parseTimeFilter("+1h")
	if err != nil {
		t.Fatalf("parseTimeFilter(+1h) returned error: %v", err)
	}
	if f(time.Now()) {
		t.Error("parseTimeFilter(+1h) should not match a file modified now")
	}
	if !f(time.Now().Add(-48 * time.Hour)) {
		t.Error("parseTimeFilter(+1h) should match a file modified 48h ago")
	}

	if _, err := parseTimeFilter("1h"); err == nil {
		t.Error("parseTimeFilter without a +/- prefix should return an error")
	}

	f, err = parseTimeFilter("")
	if err != nil || f != nil {
		t.Error("parseTimeFilter(\"\") should return a nil filter and no error")
	}
}

func TestFindByName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "match.txt", "content")
	writeFile(t, dir, "nomatch.go", "content")

	out := captureShredStdout(t, func() {
		if err := Find([]string{dir}, FindOptions{Name: "*.txt"}); err != nil {
			t.Fatalf("Find returned error: %v", err)
		}
	})

	if !containsAll(out, "match.txt") {
		t.Errorf("Find(Name: *.txt) output missing match.txt; got %q", out)
	}
}

func TestFindByContains(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "hello world")
	writeFile(t, dir, "b.txt", "goodbye")

	out := captureShredStdout(t, func() {
		if err := Find([]string{dir}, FindOptions{Contains: "hello"}); err != nil {
			t.Fatalf("Find returned error: %v", err)
		}
	})

	if !containsAll(out, "a.txt") || containsAll(out, "b.txt") {
		t.Errorf("Find(Contains: hello) output wrong; got %q", out)
	}
}

func TestFindByContainsRegex(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "version 1.2.3")

	out := captureShredStdout(t, func() {
		if err := Find([]string{dir}, FindOptions{Contains: `\d+\.\d+\.\d+`, Regex: true}); err != nil {
			t.Fatalf("Find returned error: %v", err)
		}
	})
	if !containsAll(out, "a.txt") {
		t.Errorf("Find(Contains regex) output missing a.txt; got %q", out)
	}
}

func TestFindBySize(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "small.txt", "x")
	writeFile(t, dir, "big.txt", string(make([]byte, 1000)))

	out := captureShredStdout(t, func() {
		if err := Find([]string{dir}, FindOptions{Size: ">100"}); err != nil {
			t.Fatalf("Find returned error: %v", err)
		}
	})
	if !containsAll(out, "big.txt") || containsAll(out, "small.txt") {
		t.Errorf("Find(Size: >100) output wrong; got %q", out)
	}
}

func TestFindNoMatches(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "content")

	out := captureShredStdout(t, func() {
		if err := Find([]string{dir}, FindOptions{Name: "*.nonexistent"}); err != nil {
			t.Fatalf("Find returned error: %v", err)
		}
	})
	if !containsAll(out, "No files found") {
		t.Errorf("Find with no matches should report that; got %q", out)
	}
}

func TestFindInvalidSizeFilter(t *testing.T) {
	dir := t.TempDir()
	if err := Find([]string{dir}, FindOptions{Size: "bogus"}); err == nil {
		t.Error("Find with an invalid Size filter should return an error")
	}
}

func TestFindInvalidNamePattern(t *testing.T) {
	dir := t.TempDir()
	// An unbalanced glob that becomes an invalid regex isn't easy to produce
	// via globToRegex (it escapes everything first), so instead verify a
	// bad Contains regex is rejected.
	if err := Find([]string{dir}, FindOptions{Contains: "(unclosed", Regex: true}); err == nil {
		t.Error("Find with an invalid regex Contains pattern should return an error")
	}
}

func TestExecuteCommandSuccess(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "a.txt", "x")

	if err := executeCommand("true {}", path); err != nil {
		t.Errorf("executeCommand(true) returned error: %v", err)
	}
}

func TestExecuteCommandFailure(t *testing.T) {
	if err := executeCommand("this-command-does-not-exist-anywhere", "x"); err == nil {
		t.Error("executeCommand with a nonexistent command should return an error")
	}
}

func TestExecuteCommandEmpty(t *testing.T) {
	if err := executeCommand("", "x"); err == nil {
		t.Error("executeCommand with an empty command should return an error")
	}
}

func TestFindWithExec(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "content")

	captureShredStdout(t, func() {
		if err := Find([]string{dir}, FindOptions{Name: "*.txt", Exec: "true {}"}); err != nil {
			t.Fatalf("Find with Exec returned error: %v", err)
		}
	})
}

func containsAll(haystack string, needle string) bool {
	return strings.Contains(haystack, needle)
}
