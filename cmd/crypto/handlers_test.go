package crypto

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

func TestGeneratedKeysAreStructuredJSON(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command *cobra.Command
		flags   map[string]string
		args    []string
		field   string
	}{
		{name: "aes", command: keygenAESCmd, flags: map[string]string{"bits": "128"}, field: "hex"},
		{name: "random", command: keygenRandomCmd, flags: map[string]string{"length": "16"}, field: "hex"},
		{name: "ed25519 saved", command: keygenEd25519Cmd, flags: map[string]string{"out": filepath.Join(t.TempDir(), "key.pem")}, field: "private_key"},
		{name: "caesar brute", command: cipherCaesarCmd, flags: map[string]string{"brute": "true", "top": "3"}, args: []string{"khoor"}, field: "results"},
		{name: "xor brute", command: cipherXORBruteCmd, flags: map[string]string{"max-key-len": "1", "top": "2"}, args: []string{"hello"}, field: "results"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			output.Set(&b)
			output.SetFormat("json")
			defer output.Set(nil)
			defer output.SetFormat("text")
			for name, value := range tc.flags {
				flag := tc.command.Flags().Lookup(name)
				old := flag.Value.String()
				if err := tc.command.Flags().Set(name, value); err != nil {
					t.Fatal(err)
				}
				defer tc.command.Flags().Set(name, old)
			}
			if err := tc.command.RunE(tc.command, tc.args); err != nil {
				t.Fatal(err)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(b.Bytes(), &got); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, b.String())
			}
			if len(got[tc.field]) == 0 {
				t.Fatalf("missing %s: %s", tc.field, b.String())
			}
			if path := tc.flags["out"]; path != "" {
				if _, err := os.Stat(path); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCryptoFailuresReturnErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command *cobra.Command
		flags   map[string]string
		args    []string
	}{
		{name: "invalid AES size", command: keygenAESCmd, flags: map[string]string{"bits": "7"}},
		{name: "negative random length", command: keygenRandomCmd, flags: map[string]string{"length": "-1"}},
		{name: "missing XOR key", command: cipherXORCmd, args: []string{"hello"}},
		{name: "missing cipher input", command: cipherROT13Cmd},
		{name: "missing cipher file", command: cipherFreqCmd, flags: map[string]string{"file": filepath.Join(t.TempDir(), "missing")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range tc.flags {
				flag := tc.command.Flags().Lookup(name)
				old := flag.Value.String()
				tc.command.Flags().Set(name, value)
				defer tc.command.Flags().Set(name, old)
			}
			if err := tc.command.RunE(tc.command, tc.args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
