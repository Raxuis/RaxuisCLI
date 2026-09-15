// Package output centralizes where command text output is written, so the root
// command can point every command at one writer (for redirection, capture, or
// embedding) without each package hard-coding os.Stdout.
package output

import (
	"io"
	"os"
	"sync"
)

var (
	mu     sync.RWMutex
	target io.Writer = os.Stdout
)

// Set points subsequent writes at w. A nil w resets to os.Stdout.
func Set(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	if w == nil {
		w = os.Stdout
	}
	target = w
}

type forwarder struct{}

func (forwarder) Write(p []byte) (int, error) {
	mu.RLock()
	w := target
	mu.RUnlock()
	return w.Write(p)
}

// Std always writes to the current target set by Set.
var Std io.Writer = forwarder{}
