package cmd_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"raxuiscli/cmd"
	_ "raxuiscli/cmd/audit"
	_ "raxuiscli/cmd/cloud"
	_ "raxuiscli/cmd/container"
	_ "raxuiscli/cmd/crypto"
	_ "raxuiscli/cmd/network"
	_ "raxuiscli/cmd/redteam"
	_ "raxuiscli/cmd/tools"
	_ "raxuiscli/cmd/web"
	"raxuiscli/internal/shared/catalog"
)

func TestCatalogMatchesVisibleCommandTree(t *testing.T) {
	t.Parallel()

	want := visibleCommands(cmd.RootCmd)
	got := make(map[string]catalog.Entry, len(catalog.All()))
	var duplicates []string
	for _, entry := range catalog.All() {
		if _, exists := got[entry.Path]; exists {
			duplicates = append(duplicates, entry.Path)
		}
		got[entry.Path] = entry
	}

	var missing, stale, summaryMismatch []string
	for path, command := range want {
		entry, exists := got[path]
		if !exists {
			missing = append(missing, fmt.Sprintf("%s | %s", path, command.Short))
			continue
		}
		if entry.Summary != command.Short {
			summaryMismatch = append(summaryMismatch, fmt.Sprintf("%s: catalog=%q cobra=%q", path, entry.Summary, command.Short))
		}
	}
	for path := range got {
		if _, exists := want[path]; !exists {
			stale = append(stale, path)
		}
	}
	for _, values := range [][]string{missing, stale, duplicates, summaryMismatch} {
		sort.Strings(values)
	}
	if len(missing)+len(stale)+len(duplicates)+len(summaryMismatch) != 0 {
		t.Fatalf("catalog/tree mismatch\nmissing:\n  %s\nstale:\n  %s\nduplicates:\n  %s\nsummary mismatch:\n  %s",
			strings.Join(missing, "\n  "), strings.Join(stale, "\n  "),
			strings.Join(duplicates, "\n  "), strings.Join(summaryMismatch, "\n  "))
	}
}

func visibleCommands(root *cobra.Command) map[string]*cobra.Command {
	result := make(map[string]*cobra.Command)
	var visit func(*cobra.Command)
	visit = func(command *cobra.Command) {
		// Cobra generates help and completion commands at runtime. They are not
		// product commands and therefore deliberately have no catalog metadata.
		if command.Hidden || command.Name() == "help" || command.Name() == "completion" {
			return
		}
		result[command.CommandPath()] = command
		for _, child := range command.Commands() {
			visit(child)
		}
	}
	visit(root)
	return result
}
