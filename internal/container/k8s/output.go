package k8s

import (
	"io"
	"os"
)

var stdoutW io.Writer = os.Stdout
