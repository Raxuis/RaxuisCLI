package translate

import (
	"fmt"
	"os/exec"
	"raxuiscli/internal/translate/providers"
	"runtime"
	"strings"
)

type Options struct {
	Source   string
	Target   string
	Provider string
	ApiKey   string
}

type Result struct {
	TranslatedText   string
	DetectedLanguage string
}

type Provider interface {
	Translate(text string, source, target string) (*Result, error)
	ListLanguages() (map[string]string, error)
}

func Translate(text string, opts Options) (*Result, error) {
	provider, err := getProvider(opts)
	if err != nil {
		return nil, err
	}

	return provider.Translate(text, opts.Source, opts.Target)
}

func ListLanguages(opts Options) (map[string]string, error) {
	provider, err := getProvider(opts)
	if err != nil {
		return nil, err
	}

	return provider.ListLanguages()
}

func getProvider(opts Options) (Provider, error) {
	switch strings.ToLower(opts.Provider) {
	case "libretranslate":
		return providers.NewLibreTranslate(opts.ApiKey), nil
	case "deepl":
		if opts.ApiKey == "" {
			return nil, fmt.Errorf("une clé API est requise pour DeepL")
		}
		return providers.NewDeepL(opts.ApiKey), nil
	default:
		return nil, fmt.Errorf("provider non supporté: %s (disponibles: libretranslate, deepl)", opts.Provider)
	}
}

func CopyToClipboard(text string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
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
		return fmt.Errorf("erreur lors de la copie: %w", err)
	}

	return nil
}
