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

var renameFile = os.Rename

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

	exists, err = destinationExists(path)
	if err != nil {
		return err
	}
	if exists && !force {
		return fmt.Errorf("%w: %s", ErrDestinationExists, path)
	}
	if exists {
		if err := replaceExistingFile(temporaryPath, path); err != nil {
			return err
		}
	} else if err := renameFile(temporaryPath, path); err != nil {
		return fmt.Errorf("publish output file: %w", err)
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

func replaceExistingFile(temporaryPath, destination string) error {
	backupPath, err := reserveBackupPath(destination)
	if err != nil {
		return err
	}

	if err := renameFile(destination, backupPath); err != nil {
		return fmt.Errorf("prepare output replacement: %w", err)
	}
	if err := renameFile(temporaryPath, destination); err != nil {
		restoreErr := renameFile(backupPath, destination)
		if restoreErr != nil {
			return fmt.Errorf("publish output replacement: %w; restore original from %s: %v", err, backupPath, restoreErr)
		}
		return fmt.Errorf("publish output replacement: %w", err)
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("remove replaced output backup: %w", err)
	}
	return nil
}

func reserveBackupPath(destination string) (string, error) {
	backup, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+".backup-")
	if err != nil {
		return "", fmt.Errorf("create output backup placeholder: %w", err)
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("close output backup placeholder: %w", err)
	}
	if err := os.Remove(backupPath); err != nil {
		return "", fmt.Errorf("prepare output backup path: %w", err)
	}
	return backupPath, nil
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
