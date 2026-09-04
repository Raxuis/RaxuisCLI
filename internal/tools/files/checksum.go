package files

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/blake2b"
)

type ChecksumOptions struct {
	Algorithm string
	Verify    string
	Output    string
	Recursive bool
	Relative  bool
}

type ChecksumResult struct {
	Path     string
	Checksum string
	Error    error
}

// Checksum calcule les checksums de fichiers
func Checksum(paths []string, opts ChecksumOptions) error {
	if opts.Verify != "" {
		return verifyChecksums(opts.Verify)
	}

	results := make([]ChecksumResult, 0)

	for _, path := range paths {
		if err := processPath(path, opts, &results); err != nil {
			return err
		}
	}

	// Afficher ou sauvegarder les résultats
	if opts.Output != "" {
		return saveChecksums(results, opts.Output)
	}

	for _, result := range results {
		if result.Error != nil {
			_, err := fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", result.Path, result.Error)
			if err != nil {
				return err
			}
		} else {
			fmt.Printf("%s  %s\n", result.Checksum, result.Path)
		}
	}

	return nil
}

// processPath traite un chemin (fichier ou répertoire)
func processPath(path string, opts ChecksumOptions, results *[]ChecksumResult) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		if !opts.Recursive {
			return fmt.Errorf("%s is a directory (use --recursive)", path)
		}
		return walkDirectory(path, opts, results)
	}

	checksum, err := calculateChecksum(path, opts.Algorithm)
	displayPath := path
	if opts.Relative {
		if relPath, err := filepath.Rel(".", path); err == nil {
			displayPath = relPath
		}
	}

	*results = append(*results, ChecksumResult{
		Path:     displayPath,
		Checksum: checksum,
		Error:    err,
	})

	return nil
}

// walkDirectory parcourt un répertoire récursivement
func walkDirectory(dirPath string, opts ChecksumOptions, results *[]ChecksumResult) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			checksum, err := calculateChecksum(path, opts.Algorithm)
			displayPath := path
			if opts.Relative {
				if relPath, err := filepath.Rel(".", path); err == nil {
					displayPath = relPath
				}
			}

			*results = append(*results, ChecksumResult{
				Path:     displayPath,
				Checksum: checksum,
				Error:    err,
			})
		}

		return nil
	})
}

// calculateChecksum calcule le checksum d'un fichier
func calculateChecksum(path string, algorithm string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing file %s: %v\n", path, err)
		}
	}(file)

	var h hash.Hash
	switch algorithm {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	case "blake2":
		h, err = blake2b.New256(nil)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// saveChecksums sauvegarde les checksums dans un fichier
func saveChecksums(results []ChecksumResult, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing file %s: %v\n", outputPath, err)
		}
	}(file)

	writer := bufio.NewWriter(file)
	defer func(writer *bufio.Writer) {
		err := writer.Flush()
		if err != nil {
			fmt.Printf("Error flushing to file %s: %v\n", outputPath, err)
		}
	}(writer)

	for _, result := range results {
		if result.Error == nil {
			_, err := fmt.Fprintf(writer, "%s  %s\n", result.Checksum, result.Path)
			if err != nil {
				return err
			}
		}
	}

	fmt.Printf("Checksums saved to: %s\n", outputPath)
	return nil
}

// verifyChecksums vérifie les checksums depuis un fichier manifest
func verifyChecksums(manifestPath string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing file %s: %v\n", manifestPath, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	lineNum := 0
	verified := 0
	failed := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format attendu: "checksum  filepath"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			_, err := fmt.Fprintf(os.Stderr, "Invalid format at line %d\n", lineNum)
			if err != nil {
				return err
			}
			continue
		}

		expectedChecksum := parts[0]
		filePath := strings.Join(parts[1:], " ")

		// Déterminer l'algorithme basé sur la longueur du checksum
		algorithm := detectAlgorithm(expectedChecksum)
		if algorithm == "" {
			_, err := fmt.Fprintf(os.Stderr, "Cannot detect algorithm for %s\n", filePath)
			if err != nil {
				return err
			}
			failed++
			continue
		}

		// Calculer le checksum actuel
		actualChecksum, err := calculateChecksum(filePath, algorithm)
		if err != nil {
			_, err := fmt.Fprintf(os.Stderr, "%s: FAILED (cannot read file)\n", filePath)
			if err != nil {
				return err
			}
			failed++
			continue
		}

		// Comparer
		if actualChecksum == expectedChecksum {
			fmt.Printf("%s: OK\n", filePath)
			verified++
		} else {
			fmt.Printf("%s: FAILED\n", filePath)
			failed++
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	fmt.Printf("\nTotal: %d verified, %d failed\n", verified, failed)

	if failed > 0 {
		return fmt.Errorf("%d file(s) failed verification", failed)
	}

	return nil
}

// detectAlgorithm détecte l'algorithme basé sur la longueur du checksum
func detectAlgorithm(checksum string) string {
	switch len(checksum) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256" // ou blake2
	case 128:
		return "sha512"
	default:
		return ""
	}
}
