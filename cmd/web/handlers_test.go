package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/Raxuis/RaxuisCLI/internal/web/fuzz"
	"github.com/spf13/cobra"
)

func TestCookiesEmitOnlyJSON(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command *cobra.Command
		args    []string
	}{
		{"decode name pair", cookieDecodeCmd, []string{"session=abc123"}},
		{"analyze", cookieAnalyzeCmd, []string{"session=abc; Secure; HttpOnly"}},
		{"express", cookieExpressCmd, []string{`s:%7B%22user%22%3A%22admin%22%7D.signature`}},
		{"bulk", cookieBulkCmd, []string{"session=abc", "user=admin"}},
		{"detect", cookieDetectCmd, []string{"abc"}},
		{"sensitive", cookieSensitiveCmd, []string{"user=admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			output.Set(&b)
			output.SetFormat("json")
			defer output.Set(nil)
			defer output.SetFormat("text")
			if err := tc.command.RunE(tc.command, tc.args); err != nil {
				t.Fatal(err)
			}
			if !json.Valid(b.Bytes()) {
				t.Fatalf("not JSON: %s", b.String())
			}
		})
	}
}

func TestCookieAndPayloadErrorsReturnToCaller(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command *cobra.Command
		args    []string
	}{
		{"missing cookie", cookieDecodeCmd, nil},
		{"invalid cookie", cookieAnalyzeCmd, []string{"bad"}},
		{"invalid bulk", cookieBulkCmd, []string{"bad"}},
		{"invalid flask", cookieFlaskCmd, []string{"bad"}},
		{"unknown payload", vulnPayloadsCmd, []string{"bad"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.command.RunE(tc.command, tc.args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFuzzerDrainsResultsBeforeEmittingJSON(t *testing.T) {
	var b bytes.Buffer
	output.Set(&b)
	output.SetFormat("json")
	defer output.Set(nil)
	defer output.SetFormat("text")
	const count = 101
	if err := runFuzzer(fuzz.FuzzOptions{Words: make([]string, count)}, func(_ fuzz.FuzzOptions, results chan<- fuzz.FuzzResult, done chan<- bool) {
		for i := 0; i < count; i++ {
			results <- fuzz.FuzzResult{Input: fmt.Sprint(i), StatusCode: 200}
		}
		done <- true
	}); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Found   int               `json:"found"`
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(b.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Found != count || len(result.Results) != count {
		t.Fatalf("lost fuzz results: found=%d results=%d want=%d", result.Found, len(result.Results), count)
	}
}
