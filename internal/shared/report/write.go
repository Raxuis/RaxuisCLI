package report

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Renderer writes a report to an output stream. render.Renderer satisfies this
// interface without report depending on a presentation package.
type Renderer interface {
	Render(io.Writer, Report) error
}

// ErrDestinationExists indicates that an output path would be replaced without
// explicit permission.
var ErrDestinationExists = errors.New("output destination already exists")

var (
	linkFile               = os.Link
	publishReplace         = replaceFile
	beforeNoReplacePublish func(string)
)

// WriteFile renders value to a sibling temporary file and publishes it only
// after rendering, syncing, and closing succeed. Existing paths require force.
func WriteFile(path string, value Report, renderer Renderer, force bool) error {
	if renderer == nil {
		return errors.New("report renderer is nil")
	}
	exists, err := destinationExists(path)
	if err != nil {
		return err
	}
	if exists && !force {
		return fmt.Errorf("%w: %s", ErrDestinationExists, path)
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create output temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporaryPath != "" {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := renderer.Render(temporary, value); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("render report: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync output temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output temporary file: %w", err)
	}

	if force {
		if err := publishReplace(temporaryPath, path); err != nil {
			return fmt.Errorf("publish output replacement: %w", err)
		}
	} else {
		if beforeNoReplacePublish != nil {
			beforeNoReplacePublish(path)
		}
		if err := linkFile(temporaryPath, path); err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("%w: %s", ErrDestinationExists, path)
			}
			return fmt.Errorf("publish output file without replacement: %w", err)
		}
		if err := os.Remove(temporaryPath); err != nil {
			return fmt.Errorf("remove published output temporary file: %w", err)
		}
	}
	temporaryPath = ""

	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}

func destinationExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect output destination: %w", err)
	}
	if info.IsDir() {
		return false, fmt.Errorf("output destination is a directory: %s", path)
	}
	return true, nil
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}
