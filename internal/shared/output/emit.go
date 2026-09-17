package output

import (
	"encoding/json"
	"io"
	"strings"
)

var format = "text"

// SetFormat records the active output format (typically from the root --output
// flag). It is set once per invocation in the root PersistentPreRunE, alongside
// Set. An empty value resets to text.
func SetFormat(f string) {
	mu.Lock()
	defer mu.Unlock()
	f = strings.ToLower(strings.TrimSpace(f))
	if f == "" {
		f = "text"
	}
	format = f
}

// FormatName returns the active output format.
func FormatName() string {
	mu.RLock()
	defer mu.RUnlock()
	return format
}

// JSON reports whether machine-readable JSON output is requested.
func JSON() bool {
	return FormatName() == "json"
}

// Emit writes payload as indented JSON when --output=json is active; otherwise
// it calls text to produce the human-readable output. Both paths write to Std,
// so command output stays redirectable and capturable.
func Emit(payload any, text func(w io.Writer)) error {
	if JSON() {
		encoded, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		_, err = Std.Write(append(encoded, '\n'))
		return err
	}
	text(Std)
	return nil
}
