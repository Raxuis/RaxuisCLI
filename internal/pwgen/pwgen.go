package pwgen

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os/exec"
	"runtime"
	"strings"
)

type Options struct {
	Length    int
	NoSymbols bool
	NoNumbers bool
}

const (
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers = "0123456789"
	symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
)

func Generate(opts Options) (string, error) {
	charset := letters

	if !opts.NoNumbers {
		charset += numbers
	}

	if !opts.NoSymbols {
		charset += symbols
	}

	password := make([]byte, opts.Length)

	for i := range password {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("error generating random number: %w", err)
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return string(password), nil
}

func CopyToClipboard(text string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin": // macOS
		cmd = exec.Command("pbcopy")
	case "linux":
		// Essai avec xclip d'abord, puis xsel comme fallback
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return fmt.Errorf("aucun utilitaire de presse-papiers trouvé (xclip ou xsel requis sur Linux)")
		}
	case "windows":
		cmd = exec.Command("clip")
	default:
		return fmt.Errorf("système d'exploitation non supporté: %s", runtime.GOOS)
	}

	cmd.Stdin = strings.NewReader(text)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("erreur lors de la copie dans le presse-papiers: %w", err)
	}

	return nil
}

func VerifyClipboard(expectedText string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin": // macOS
		cmd = exec.Command("pbpaste")
	case "linux":
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard", "-out")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--output")
		} else {
			return fmt.Errorf("aucun utilitaire de presse-papiers trouvé pour la vérification")
		}
	case "windows":
		// Sur Windows, PowerShell pour lire le presse-papiers
		cmd = exec.Command("powershell", "-command", "Get-Clipboard")
	default:
		return fmt.Errorf("vérification non supportée sur: %s", runtime.GOOS)
	}

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("erreur lors de la lecture du presse-papiers: %w", err)
	}

	clipboardContent := strings.TrimSpace(string(output))
	if clipboardContent != expectedText {
		return fmt.Errorf("le contenu du presse-papiers ne correspond pas au texte original")
	}

	return nil
}
