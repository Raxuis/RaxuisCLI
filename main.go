package main

import (
	"os"

	"github.com/Raxuis/RaxuisCLI/cmd"

	_ "github.com/Raxuis/RaxuisCLI/cmd/audit"
	_ "github.com/Raxuis/RaxuisCLI/cmd/cloud"
	_ "github.com/Raxuis/RaxuisCLI/cmd/container"
	_ "github.com/Raxuis/RaxuisCLI/cmd/crypto"
	_ "github.com/Raxuis/RaxuisCLI/cmd/interactive"
	_ "github.com/Raxuis/RaxuisCLI/cmd/network"
	_ "github.com/Raxuis/RaxuisCLI/cmd/redteam"
	_ "github.com/Raxuis/RaxuisCLI/cmd/tools"
	_ "github.com/Raxuis/RaxuisCLI/cmd/web"
)

func main() {
	os.Exit(cmd.Execute())
}
