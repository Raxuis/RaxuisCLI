package output

import (
	"bytes"
	"os"
	"testing"
)

func TestForwarderFollowsTarget(t *testing.T) {
	t.Cleanup(func() { Set(nil) })

	var buf bytes.Buffer
	Set(&buf)
	if _, err := Std.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if buf.String() != "hello" {
		t.Fatalf("target = %q, want hello", buf.String())
	}

	var other bytes.Buffer
	Set(&other)
	_, _ = Std.Write([]byte("world"))
	if buf.String() != "hello" || other.String() != "world" {
		t.Fatalf("Set did not switch target: buf=%q other=%q", buf.String(), other.String())
	}
}

func TestSetNilResetsToStdout(t *testing.T) {
	Set(&bytes.Buffer{})
	Set(nil)
	mu.RLock()
	defer mu.RUnlock()
	if target != os.Stdout {
		t.Fatal("Set(nil) did not reset target to os.Stdout")
	}
}
