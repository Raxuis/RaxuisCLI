package tools

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
)

func TestFileFailureReturnsErrorAndDryRunDoesNotAct(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	var b bytes.Buffer
	output.Set(&b)
	defer output.Set(nil)
	filesEncryptCmd.SetOut(&b)
	defer filesEncryptCmd.SetOut(nil)
	if err := filesEncryptCmd.RunE(filesEncryptCmd, []string{path}); err == nil {
		t.Fatal("missing file succeeded")
	}
	if err := filesEncryptCmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatal(err)
	}
	defer filesEncryptCmd.Flags().Set("dry-run", "false")
	if err := filesEncryptCmd.RunE(filesEncryptCmd, []string{path}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b.Bytes(), []byte("Dry run:")) {
		t.Fatalf("dry run output: %q", b.String())
	}
}

func TestHexdumpRejectsMissingFileAndInvalidOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if err := hexdumpCmd.RunE(hexdumpCmd, []string{path}); err == nil {
		t.Fatal("missing file succeeded")
	}
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	old := hexdumpOffset
	hexdumpOffset = -1
	defer func() { hexdumpOffset = old }()
	if err := hexdumpCmd.RunE(hexdumpCmd, []string{path}); err == nil {
		t.Fatal("negative offset succeeded")
	}
}

func TestFileOptionsDoNotShadowRootOutputFlags(t *testing.T) {
	for _, name := range []string{"quiet", "verbose", "force", "output"} {
		if flag := filesChecksumCmd.LocalNonPersistentFlags().Lookup(name); flag != nil {
			t.Fatalf("checksum shadows --%s", name)
		}
	}
	if filesChecksumCmd.Flags().Lookup("manifest-output") == nil {
		t.Fatal("missing --manifest-output")
	}
}
