package translate

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"raxuiscli/internal/translate/providers"
	"raxuiscli/internal/translate/types"
	"runtime"
	"strings"
	"time"
)

type Options struct {
	Source   string
	Target   string
	Provider string
	ApiKey   string
}

type HistoryEntry struct {
	Timestamp        time.Time `json:"timestamp"`
	OriginalText     string    `json:"original_text"`
	TranslatedText   string    `json:"translated_text"`
	SourceLang       string    `json:"source_lang"`
	TargetLang       string    `json:"target_lang"`
	DetectedLanguage string    `json:"detected_language,omitempty"`
	Provider         string    `json:"provider"`
}

type Provider interface {
	Translate(text string, source, target string) (*types.Result, error)
	ListLanguages() (map[string]string, error)
}

func Translate(text string, opts Options) (*types.Result, error) {
	provider, err := getProvider(opts)
	if err != nil {
		return nil, err
	}

	result, err := provider.Translate(text, opts.Source, opts.Target)
	if err != nil {
		return nil, err
	}

	// Sauvegarder dans l'historique
	_ = saveToHistory(text, result.TranslatedText, opts.Source, opts.Target, result.DetectedLanguage, opts.Provider)

	return result, nil
}

func TranslateFile(filePath string, opts Options) (*types.Result, error) {
	// Lire le fichier
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture du fichier: %w", err)
	}

	// Traduire le contenu
	provider, err := getProvider(opts)
	if err != nil {
		return nil, err
	}

	result, err := provider.Translate(string(content), opts.Source, opts.Target)
	if err != nil {
		return nil, err
	}

	// Créer le nom du fichier de sortie
	ext := filepath.Ext(filePath)
	nameWithoutExt := strings.TrimSuffix(filepath.Base(filePath), ext)
	dir := filepath.Dir(filePath)
	outputPath := filepath.Join(dir, fmt.Sprintf("%s_%s%s", nameWithoutExt, opts.Target, ext))

	// Écrire le fichier traduit
	err = os.WriteFile(outputPath, []byte(result.TranslatedText), 0644)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'écriture du fichier traduit: %w", err)
	}

	result.OutputPath = outputPath

	// Sauvegarder dans l'historique
	_ = saveToHistory(string(content), result.TranslatedText, opts.Source, opts.Target, result.DetectedLanguage, opts.Provider)

	return result, nil
}

func ListLanguages(opts Options) (map[string]string, error) {
	provider, err := getProvider(opts)
	if err != nil {
		return nil, err
	}

	return provider.ListLanguages()
}

func GetHistory(limit int) ([]HistoryEntry, error) {
	historyPath := getHistoryPath()

	data, err := os.ReadFile(historyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []HistoryEntry{}, nil
		}
		return nil, fmt.Errorf("erreur lors de la lecture de l'historique: %w", err)
	}

	var history []HistoryEntry
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("erreur lors du décodage de l'historique: %w", err)
	}

	// Retourner les dernières entrées
	if limit > 0 && len(history) > limit {
		return history[len(history)-limit:], nil
	}

	return history, nil
}

func ClearHistory() error {
	historyPath := getHistoryPath()
	return os.Remove(historyPath)
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

func saveToHistory(original, translated, source, target, detected, provider string) error {
	historyPath := getHistoryPath()

	// Créer le dossier si nécessaire
	if err := os.MkdirAll(filepath.Dir(historyPath), 0755); err != nil {
		return err
	}

	// Lire l'historique existant
	var history []HistoryEntry
	if data, err := os.ReadFile(historyPath); err == nil {
		_ = json.Unmarshal(data, &history)
	}

	// Ajouter la nouvelle entrée
	entry := HistoryEntry{
		Timestamp:        time.Now(),
		OriginalText:     original,
		TranslatedText:   translated,
		SourceLang:       source,
		TargetLang:       target,
		DetectedLanguage: detected,
		Provider:         provider,
	}
	history = append(history, entry)

	// Limiter à 1000 entrées
	if len(history) > 1000 {
		history = history[len(history)-1000:]
	}

	// Sauvegarder
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(historyPath, data, 0644)
}

func getHistoryPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".raxuiscli", "translate_history.json")
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
