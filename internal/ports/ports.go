package ports

import "fmt"

type Options struct {
	Host      string
	PortRange string
	Timeout   int
	ScanType  string
}

func Scan(opts Options) {
	fmt.Println("Scanning ports...")
	fmt.Printf("Host: %s\n", opts.Host)
	fmt.Printf("Port Range: %s\n", opts.PortRange)
	fmt.Printf("Timeout: %d seconds\n", opts.Timeout)
	fmt.Printf("Scan Type: %s\n", opts.ScanType)
}
