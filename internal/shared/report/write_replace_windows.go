//go:build windows

package report

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// replaceFile uses MoveFileExW with MOVEFILE_REPLACE_EXISTING. This is a
// single replacement operation, unlike moving the destination aside before
// publishing the file.
func replaceFile(temporaryPath, destination string) error {
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return fmt.Errorf("encode temporary output path: %w", err)
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return fmt.Errorf("encode output destination path: %w", err)
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING)
}
