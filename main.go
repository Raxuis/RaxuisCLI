package main

import (
	"log"

	"raxuiscli/cmd"

	_ "raxuiscli/cmd/cloud"
	_ "raxuiscli/cmd/container"
	_ "raxuiscli/cmd/crypto"
	_ "raxuiscli/cmd/network"
	_ "raxuiscli/cmd/redteam"
	_ "raxuiscli/cmd/tools"
	_ "raxuiscli/cmd/web"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
