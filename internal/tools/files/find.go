package files

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type FindOptions struct {
	Name     string
	Contains string
	Regex    bool
	Size     string
	Mtime    string
	Exec     string
}

type FileMatch struct {
	Path    string
	Info    os.FileInfo
	Matches bool
	Reason  string
}

// Find recherche des fichiers selon des critères
func Find(paths []string, opts FindOptions) error {
	var namePattern *regexp.Regexp
	var contentPattern *regexp.Regexp
	var err error

	// Compiler les patterns
	if opts.Name != "" {
		pattern := globToRegex(opts.Name)
		namePattern, err = regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid name pattern: %w", err)
		}
	}

	if opts.Contains != "" {
		if opts.Regex {
			contentPattern, err = regexp.Compile(opts.Contains)
			if err != nil {
				return fmt.Errorf("invalid regex pattern: %w", err)
			}
		}
	}

	// Parser les filtres de taille et temps
	sizeFilter, err := parseSizeFilter(opts.Size)
	if err != nil {
		return err
	}

	mtimeFilter, err := parseTimeFilter(opts.Mtime)
	if err != nil {
		return err
	}

	matches := make([]string, 0)

	// Rechercher dans chaque chemin
	for _, path := range paths {
		err := filepath.Walk(path, func(currentPath string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue même en cas d'erreur
			}

			// Appliquer les filtres
			if !matchesFilters(currentPath, info, namePattern, contentPattern, sizeFilter, mtimeFilter, opts) {
				return nil
			}

			matches = append(matches, currentPath)
			fmt.Println(currentPath)

			// Exécuter une commande si spécifiée
			if opts.Exec != "" {
				if err := executeCommand(opts.Exec, currentPath); err != nil {
					_, err := fmt.Fprintf(os.Stderr, "Error executing command for %s: %v\n", currentPath, err)
					if err != nil {
						return err
					}
				}
			}

			return nil
		})

		if err != nil {
			return err
		}
	}

	if len(matches) == 0 {
		fmt.Println("No files found matching the criteria")
	} else {
		fmt.Printf("\nFound %d file(s)\n", len(matches))
	}

	return nil
}

// matchesFilters vérifie si un fichier correspond aux filtres
func matchesFilters(path string, info os.FileInfo, namePattern, contentPattern *regexp.Regexp,
	sizeFilter func(int64) bool, mtimeFilter func(time.Time) bool, opts FindOptions) bool {
	// Filtre par nom
	if namePattern != nil {
		basename := filepath.Base(path)
		if !namePattern.MatchString(basename) {
			return false
		}
	}

	// Filtre par taille
	if sizeFilter != nil && !info.IsDir() {
		if !sizeFilter(info.Size()) {
			return false
		}
	}

	// Filtre par modification time
	if mtimeFilter != nil {
		if !mtimeFilter(info.ModTime()) {
			return false
		}
	}

	// Filtre par contenu (seulement pour les fichiers réguliers)
	if opts.Contains != "" && !info.IsDir() {
		if contentPattern != nil {
			if !searchFileRegex(path, contentPattern) {
				return false
			}
		} else {
			if !searchFileString(path, opts.Contains) {
				return false
			}
		}
	}

	return true
}

// searchFileString recherche une chaîne dans un fichier
func searchFileString(path string, searchStr string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing file %s: %v\n", path, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), searchStr) {
			return true
		}
	}

	return false
}

// searchFileRegex recherche avec une regex dans un fichier
func searchFileRegex(path string, pattern *regexp.Regexp) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing file %s: %v\n", path, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if pattern.MatchString(scanner.Text()) {
			return true
		}
	}

	return false
}

// globToRegex convertit un pattern glob en regex
func globToRegex(pattern string) string {
	pattern = regexp.QuoteMeta(pattern)
	pattern = strings.ReplaceAll(pattern, `\*`, ".*")
	pattern = strings.ReplaceAll(pattern, `\?`, ".")
	return "^" + pattern + "$"
}

// parseSizeFilter parse un filtre de taille (ex: >10M, <1K)
func parseSizeFilter(sizeStr string) (func(int64) bool, error) {
	if sizeStr == "" {
		return nil, nil
	}

	var op string
	var valueStr string

	if strings.HasPrefix(sizeStr, ">") {
		op = ">"
		valueStr = strings.TrimPrefix(sizeStr, ">")
	} else if strings.HasPrefix(sizeStr, "<") {
		op = "<"
		valueStr = strings.TrimPrefix(sizeStr, "<")
	} else if strings.HasPrefix(sizeStr, "=") {
		op = "="
		valueStr = strings.TrimPrefix(sizeStr, "=")
	} else {
		return nil, fmt.Errorf("invalid size filter: %s (use >, <, or =)", sizeStr)
	}

	size, err := parseSize(valueStr)
	if err != nil {
		return nil, err
	}

	return func(fileSize int64) bool {
		switch op {
		case ">":
			return fileSize > size
		case "<":
			return fileSize < size
		case "=":
			return fileSize == size
		default:
			return false
		}
	}, nil
}

// parseSize parse une taille avec unité (10M, 1K, etc.)
func parseSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(sizeStr)
	if sizeStr == "" {
		return 0, fmt.Errorf("empty size")
	}

	multiplier := int64(1)
	numStr := sizeStr

	lastChar := strings.ToUpper(string(sizeStr[len(sizeStr)-1]))
	if lastChar >= "A" && lastChar <= "Z" {
		numStr = sizeStr[:len(sizeStr)-1]
		switch lastChar {
		case "K":
			multiplier = 1024
		case "M":
			multiplier = 1024 * 1024
		case "G":
			multiplier = 1024 * 1024 * 1024
		case "T":
			multiplier = 1024 * 1024 * 1024 * 1024
		default:
			return 0, fmt.Errorf("unknown size unit: %s", lastChar)
		}
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size number: %w", err)
	}

	return num * multiplier, nil
}

// parseTimeFilter parse un filtre de temps (ex: -7d, +1h)
func parseTimeFilter(timeStr string) (func(time.Time) bool, error) {
	if timeStr == "" {
		return nil, nil
	}

	var op string
	var valueStr string

	if strings.HasPrefix(timeStr, "+") {
		op = "+"
		valueStr = strings.TrimPrefix(timeStr, "+")
	} else if strings.HasPrefix(timeStr, "-") {
		op = "-"
		valueStr = strings.TrimPrefix(timeStr, "-")
	} else {
		return nil, fmt.Errorf("invalid time filter: %s (use + or -)", timeStr)
	}

	duration, err := parseDuration(valueStr)
	if err != nil {
		return nil, err
	}

	threshold := time.Now().Add(-duration)

	return func(modTime time.Time) bool {
		if op == "-" {
			// -7d = modifié dans les derniers 7 jours (plus récent que threshold)
			return modTime.After(threshold)
		} else {
			// +7d = modifié il y a plus de 7 jours (plus vieux que threshold)
			return modTime.Before(threshold)
		}
	}, nil
}

// parseDuration parse une durée (7d, 1h, 30m)
func parseDuration(durStr string) (time.Duration, error) {
	durStr = strings.TrimSpace(durStr)
	if durStr == "" {
		return 0, fmt.Errorf("empty duration")
	}

	lastChar := string(durStr[len(durStr)-1])
	numStr := durStr[:len(durStr)-1]

	num, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, fmt.Errorf("invalid duration number: %w", err)
	}

	var multiplier time.Duration
	switch lastChar {
	case "s":
		multiplier = time.Second
	case "m":
		multiplier = time.Minute
	case "h":
		multiplier = time.Hour
	case "d":
		multiplier = 24 * time.Hour
	case "w":
		multiplier = 7 * 24 * time.Hour
	default:
		return 0, fmt.Errorf("unknown duration unit: %s", lastChar)
	}

	return time.Duration(num) * multiplier, nil
}

// executeCommand exécute une commande pour un fichier trouvé
func executeCommand(cmdStr string, filePath string) error {
	// Remplacer {} par le chemin du fichier
	cmdStr = strings.ReplaceAll(cmdStr, "{}", filePath)

	// Parser la commande
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
