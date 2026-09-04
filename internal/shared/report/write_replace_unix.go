//go:build !windows

package report

import "os"

// replaceFile is a single rename operation. POSIX rename atomically replaces
// an existing non-directory destination without an observable missing-path
// interval.
func replaceFile(temporaryPath, destination string) error {
	return os.Rename(temporaryPath, destination)
}
