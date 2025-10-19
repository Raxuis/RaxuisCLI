package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type LibreTranslate struct {
	apiKey  string
	baseURL string
}

func NewLibreTranslate(apiKey string) *LibreTranslate {
	return &LibreTranslate{
		apiKey:  apiKey,
		baseURL: "https://libretranslate.com/translate",
	}
}

type libreTranslateRequest struct {
	Q      string `json:"q"`
	Source string `json:"source"`
	Target string `json:"target"`
	Format string `json:"format"`
	ApiKey string `json:"api_key,omitempty"`
}

type libreTranslateResponse struct {
	TranslatedText   string `json:"translatedText"`
	DetectedLanguage struct {
		Confidence float64 `json:"confidence"`
		Language   string  `json:"language"`
	} `json:"detectedLanguage,omitempty"`
}

type libreLanguage struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

func (lt *LibreTranslate) Translate(text string, source, target string) (*Result, error) {
	reqBody := libreTranslateRequest{
		Q:      text,
		Source: source,
		Target: target,
		Format: "text",
		ApiKey: lt.apiKey,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création de la requête: %w", err)
	}

	resp, err := http.Post(lt.baseURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la requête API: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Erreur lors de la fermeture du corps de la réponse: %v\n", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("erreur API (%d): %s", resp.StatusCode, string(body))
	}

	var translateResp libreTranslateResponse
	if err := json.NewDecoder(resp.Body).Decode(&translateResp); err != nil {
		return nil, fmt.Errorf("erreur lors du décodage de la réponse: %w", err)
	}

	result := &Result{
		TranslatedText: translateResp.TranslatedText,
	}

	if translateResp.DetectedLanguage.Language != "" {
		result.DetectedLanguage = translateResp.DetectedLanguage.Language
	}

	return result, nil
}

func (lt *LibreTranslate) ListLanguages() (map[string]string, error) {
	resp, err := http.Get("https://libretranslate.com/languages")
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la récupération des langues: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Erreur lors de la fermeture du corps de la réponse: %v\n", err)
		}
	}(resp.Body)

	var languages []libreLanguage
	if err := json.NewDecoder(resp.Body).Decode(&languages); err != nil {
		return nil, fmt.Errorf("erreur lors du décodage des langues: %w", err)
	}

	result := make(map[string]string)
	for _, lang := range languages {
		result[lang.Code] = lang.Name
	}

	return result, nil
}

type Result struct {
	TranslatedText   string
	DetectedLanguage string
}
