package tools

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/Raxuis/RaxuisCLI/internal/tools/pwgen"
	"github.com/charmbracelet/x/term"

	"github.com/spf13/cobra"
)

var pwgenCmd = &cobra.Command{
	Use:   "pwgen",
	Short: "Generate secure passwords",
	Long:  "Generate cryptographically secure passwords with various options",
	Args:  cobra.NoArgs,
	RunE:  runPasswordGeneration,
}

var pwgenLength int
var pwgenNoSymbols bool
var pwgenNoNumbers bool
var pwgenCount int

var pwgenGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate password(s)",
	Args:  cobra.NoArgs,
	RunE:  runPasswordGeneration,
}

func runPasswordGeneration(command *cobra.Command, _ []string) error {
	if pwgenLength < 1 || pwgenLength > 100000 {
		return fmt.Errorf("password length must be between 1 and 100000")
	}
	if pwgenCount < 1 {
		return fmt.Errorf("password count must be positive")
	}
	options := pwgen.Options{Length: pwgenLength, NoSymbols: pwgenNoSymbols, NoNumbers: pwgenNoNumbers}
	passwords := make([]string, 0)
	for i := 0; i < pwgenCount; i++ {
		password, err := pwgen.Generate(options)
		if err != nil {
			return fmt.Errorf("generating password: %w", err)
		}
		passwords = append(passwords, password)
	}
	if err := output.Emit(map[string]any{"passwords": passwords}, func(w io.Writer) {
		for i, password := range passwords {
			fmt.Fprintf(w, "Password %d: %s\n", i+1, password)
		}
	}); err != nil {
		return err
	}
	in, inOK := command.InOrStdin().(*os.File)
	out, outOK := command.OutOrStdout().(*os.File)
	if output.JSON() || !inOK || !outOK || !term.IsTerminal(in.Fd()) || !term.IsTerminal(out.Fd()) {
		return nil
	}
	fmt.Fprint(out, "Copy the last password to clipboard? (y/N): ")
	var response string
	if _, err := fmt.Fscanln(in, &response); err != nil {
		return nil
	}
	response = strings.ToLower(strings.TrimSpace(response))
	if response == "y" || response == "yes" {
		password := passwords[len(passwords)-1]
		if err := pwgen.CopyToClipboard(password); err != nil {
			return fmt.Errorf("copying password: %w", err)
		}
		if err := pwgen.VerifyClipboard(password); err != nil {
			return fmt.Errorf("verifying clipboard: %w", err)
		}
		fmt.Fprintln(out, "Password copied to clipboard!")
	}
	return nil
}

func init() {
	cmd.RootCmd.AddCommand(pwgenCmd)
	pwgenCmd.AddCommand(pwgenGenerateCmd)

	pwgenCmd.PersistentFlags().IntVarP(&pwgenLength, "length", "l", 16, "Password length")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenNoSymbols, "no-symbols", false, "Exclude symbols")
	pwgenCmd.PersistentFlags().BoolVar(&pwgenNoNumbers, "no-numbers", false, "Exclude numbers")
	pwgenCmd.PersistentFlags().IntVar(&pwgenCount, "count", 1, "Number of passwords to generate")
}
