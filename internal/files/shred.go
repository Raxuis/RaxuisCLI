package files

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type ShredOptions struct {
	Passes    int
	Random    bool
	Zero      bool
	Recursive bool
	Force     bool
}

// Shred supprime de manière sécurisée un ou plusieurs fichiers
func Shred(paths []string, opts ShredOptions) error {
	for _, path := range paths {
		if err := shredPath(path, opts); err != nil {
			return fmt.Errorf("error shredding %s: %w", path, err)
		}
	}
	return nil
}

// shredPath supprime un chemin (fichier ou répertoire)
func shredPath(path string, opts ShredOptions) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		if !opts.Recursive {
			return fmt.Errorf("%s is a directory (use --recursive)", path)
		}
		return shredDirectory(path, opts)
	}

	return shredFile(path, opts)
}

// shredDirectory supprime récursivement un répertoire
func shredDirectory(dirPath string, opts ShredOptions) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}

	// Shred tous les fichiers et sous-répertoires
	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry.Name())
		if err := shredPath(fullPath, opts); err != nil {
			return err
		}
	}

	// Supprimer le répertoire vide
	return os.Remove(dirPath)
}

// shredFile supprime un fichier de manière sécurisée
func shredFile(path string, opts ShredOptions) error {
	// Confirmation si nécessaire
	if !opts.Force {
		fmt.Printf("Shred file %s? (y/N): ", path)
		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			return err
		}
		if response != "y" && response != "Y" {
			fmt.Println("Skipped.")
			return nil
		}
	}

	// Ouvrir le fichier
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Error closing file %s: %v\n", path, err)
		}
	}(file)

	// Obtenir la taille du fichier
	info, err := file.Stat()
	if err != nil {
		return err
	}
	size := info.Size()

	// Effectuer les passes d'écrasement
	for i := 0; i < opts.Passes; i++ {
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}

		if opts.Random {
			// Écraser avec des données aléatoires
			if err := overwriteRandom(file, size); err != nil {
				return err
			}
		} else {
			// Écraser avec un pattern fixe
			pattern := byte(i % 256)
			if err := overwritePattern(file, size, pattern); err != nil {
				return err
			}
		}

		if err := file.Sync(); err != nil {
			return err
		}

		fmt.Printf("Pass %d/%d completed for %s\n", i+1, opts.Passes, path)
	}

	// Passe finale avec des zéros si demandé
	if opts.Zero {
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		if err := overwritePattern(file, size, 0); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		fmt.Printf("Final zero pass completed for %s\n", path)
	}

	err = file.Close()
	if err != nil {
		return err
	}

	// Supprimer le fichier
	if err := os.Remove(path); err != nil {
		return err
	}

	fmt.Printf("Successfully shredded: %s\n", path)
	return nil
}

// overwriteRandom écrase le fichier avec des données aléatoires
func overwriteRandom(file *os.File, size int64) error {
	const bufSize = 1024 * 1024 // 1MB buffer
	buf := make([]byte, bufSize)

	remaining := size
	for remaining > 0 {
		toWrite := bufSize
		if remaining < int64(bufSize) {
			toWrite = int(remaining)
		}

		if _, err := io.ReadFull(rand.Reader, buf[:toWrite]); err != nil {
			return err
		}

		if _, err := file.Write(buf[:toWrite]); err != nil {
			return err
		}

		remaining -= int64(toWrite)
	}

	return nil
}

// overwritePattern écrase le fichier avec un pattern fixe
func overwritePattern(file *os.File, size int64, pattern byte) error {
	const bufSize = 1024 * 1024 // 1MB buffer
	buf := make([]byte, bufSize)
	for i := range buf {
		buf[i] = pattern
	}

	remaining := size
	for remaining > 0 {
		toWrite := bufSize
		if remaining < int64(bufSize) {
			toWrite = int(remaining)
		}

		if _, err := file.Write(buf[:toWrite]); err != nil {
			return err
		}

		remaining -= int64(toWrite)
	}

	return nil
}
