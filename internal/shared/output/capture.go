package output

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
)

type Capture struct {
	buffer      *bytes.Buffer
	quiet       bool
	outputFile  string
	force       bool
	multiWriter io.Writer
	mu          sync.Mutex
}

func NewCapture(outputFile string, quiet, force bool) *Capture {
	c := &Capture{
		buffer:     &bytes.Buffer{},
		quiet:      quiet,
		outputFile: outputFile,
		force:      force,
	}

	writers := []io.Writer{c.buffer}
	if !quiet {
		writers = append(writers, os.Stdout)
	}
	c.multiWriter = io.MultiWriter(writers...)
	return c
}

func (c *Capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.multiWriter.Write(p)
}

func (c *Capture) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.outputFile == "" {
		return nil
	}

	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if !c.force {
		flags = os.O_CREATE | os.O_WRONLY | os.O_EXCL
	}

	f, err := os.OpenFile(c.outputFile, flags, 0644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("output file already exists: %s (use --force to overwrite)", c.outputFile)
		}
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()

	_, err = f.Write(c.buffer.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	if !c.quiet {
		fmt.Fprintf(os.Stderr, "Output saved to: %s\n", c.outputFile)
	}
	return nil
}

func (c *Capture) Buffer() *bytes.Buffer {
	return c.buffer
}

func (c *Capture) String() string {
	return c.buffer.String()
}
