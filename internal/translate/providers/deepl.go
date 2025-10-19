package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"raxuiscli/internal/translate/types"
	"strings"
)

type DeepL struct {
	apiKey  string
	baseURL string
}

func NewDeepL(apiKey string) *DeepL {
	// Utiliser l'API gratuite si la clé finit par :fx
	baseURL := "https://api.deepl.com/v2"
	if strings.HasSuffix(apiKey, ":fx") {
		baseURL = "https://api-free.deepl.com/v2"
	}

	return &DeepL{
		apiKey:  apiKey,
		baseURL: baseURL,
	}
}

type deeplTranslation struct {
	DetectedSourceLanguage string `json:"detected_source_language"`
	Text                   string `json:"text"`
}

type deeplResponse struct {
	Translations []deeplTranslation `json:"translations"`
}

type deeplLanguage struct {
	Language string `json:"language"`
	Name     string `json:"name"`
}

func (d *DeepL) Translate(text string, source, target string) (*types.Result, error) {
	// Préparer les paramètres
	data := url.Values{}
	data.Set("text", text)
	data.Set("target_lang", strings.ToUpper(target))

	if source != "auto" && source != "" {
		data.Set("source_lang", strings.ToUpper(source))
	}

	// Créer la requête
	req, err := http.NewRequest("POST", d.baseURL+"/translate", bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création de la requête: %w", err)
	}

	req.Header.Set("Authorization", "DeepL-Auth-Key "+d.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Exécuter la requête
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la requête API: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("erreur lors de la fermeture du corps de la réponse: %v\n", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("erreur API DeepL (%d): %s", resp.StatusCode, string(body))
	}

	var deeplResp deeplResponse
	if err := json.NewDecoder(resp.Body).Decode(&deeplResp); err != nil {
		return nil, fmt.Errorf("erreur lors du décodage de la réponse: %w", err)
	}

	if len(deeplResp.Translations) == 0 {
		return nil, fmt.Errorf("aucune traduction retournée")
	}

	translation := deeplResp.Translations[0]
	result := &types.Result{
		TranslatedText:   translation.Text,
		DetectedLanguage: strings.ToLower(translation.DetectedSourceLanguage),
	}

	return result, nil
}

func (d *DeepL) ListLanguages() (map[string]string, error) {
	req, err := http.NewRequest("GET", d.baseURL+"/languages?type=target", nil)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création de la requête: %w", err)
	}

	req.Header.Set("Authorization", "DeepL-Auth-Key "+d.apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la récupération des langues: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("erreur lors de la fermeture du corps de la réponse: %v\n", err)
		}
	}(resp.Body)

	var languages []deeplLanguage
	if err := json.NewDecoder(resp.Body).Decode(&languages); err != nil {
		return nil, fmt.Errorf("erreur lors du décodage des langues: %w", err)
	}

	result := make(map[string]string)
	for _, lang := range languages {
		result[strings.ToLower(lang.Language)] = lang.Name
	}

	return result, nil
}
