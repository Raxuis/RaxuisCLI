package main

import (
	"log"

	"RaxuisCLI/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
