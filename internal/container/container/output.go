package container

import (
	"io"
	"os"
)

var stdoutW io.Writer = os.Stdout
