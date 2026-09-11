// Command gen updates the delimited command-catalog sections in project docs.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"raxuiscli/internal/shared/catalog"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	items := catalog.All()
	readme, err := catalog.RenderReadmeStatus(items)
	if err != nil {
		fatal(err)
	}
	roadmap, err := catalog.RenderRoadmapStatus(items)
	if err != nil {
		fatal(err)
	}
	readmeUpdate, err := prepare(filepath.Join(*root, "README.md"), readme)
	if err != nil {
		fatal(err)
	}
	roadmapUpdate, err := prepare(filepath.Join(*root, "ROADMAP.md"), roadmap)
	if err != nil {
		fatal(err)
	}
	for _, update := range []documentUpdate{readmeUpdate, roadmapUpdate} {
		if err := update.write(); err != nil {
			fatal(err)
		}
	}
}

type documentUpdate struct {
	path   string
	before []byte
	after  []byte
	mode   os.FileMode
}

func prepare(path, generated string) (documentUpdate, error) {
	before, err := os.ReadFile(path)
	if err != nil {
		return documentUpdate{}, fmt.Errorf("read %s: %w", path, err)
	}
	after, err := catalog.ReplaceGeneratedBlock(string(before), generated)
	if err != nil {
		return documentUpdate{}, fmt.Errorf("update %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return documentUpdate{}, fmt.Errorf("stat %s: %w", path, err)
	}
	return documentUpdate{path: path, before: before, after: []byte(after), mode: info.Mode().Perm()}, nil
}

func (update documentUpdate) write() error {
	if bytes.Equal(update.before, update.after) {
		return nil
	}
	if err := os.WriteFile(update.path, update.after, update.mode); err != nil {
		return fmt.Errorf("write %s: %w", update.path, err)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
