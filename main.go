package main

import (
	"os"

	"raxuiscli/cmd"

	_ "raxuiscli/cmd/audit"
	_ "raxuiscli/cmd/cloud"
	_ "raxuiscli/cmd/container"
	_ "raxuiscli/cmd/crypto"
	_ "raxuiscli/cmd/network"
	_ "raxuiscli/cmd/redteam"
	_ "raxuiscli/cmd/tools"
	_ "raxuiscli/cmd/web"
)

func main() {
	os.Exit(cmd.Execute())
}
