package files

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

type CompressOptions struct {
	Format    string
	Output    string
	Password  string
	Overwrite bool
}

type ExtractOptions struct {
	Format          string
	StripComponents int
	Password        string
	Overwrite       bool
}

// Compress compresse des fichiers dans une archive
func Compress(paths []string, opts CompressOptions) error {
	if opts.Output == "" {
		return fmt.Errorf("output file is required")
	}

	// Vérifier si le fichier existe
	if !opts.Overwrite {
		if _, err := os.Stat(opts.Output); err == nil {
			return fmt.Errorf("output file already exists: %s", opts.Output)
		}
	}

	switch opts.Format {
	case "zip":
		return compressZip(paths, opts)
	case "tar":
		return compressTar(paths, opts, "")
	case "gz", "gzip":
		return compressTar(paths, opts, "gzip")
	case "bz2", "bzip2":
		return compressTar(paths, opts, "bzip2")
	case "xz":
		return compressTar(paths, opts, "xz")
	default:
		return fmt.Errorf("unsupported format: %s", opts.Format)
	}
}

// Extract extrait une archive
func Extract(archivePath string, opts ExtractOptions) error {
	// Détecter le format automatiquement si non spécifié
	format := opts.Format
	if format == "" {
		format = detectFormat(archivePath)
	}

	switch format {
	case "zip":
		return extractZip(archivePath, opts)
	case "tar":
		return extractTar(archivePath, opts, "")
	case "gz", "gzip", "tar.gz", "tgz":
		return extractTar(archivePath, opts, "gzip")
	case "bz2", "bzip2", "tar.bz2", "tbz2":
		return extractTar(archivePath, opts, "bzip2")
	case "xz", "tar.xz", "txz":
		return extractTar(archivePath, opts, "xz")
	default:
		return fmt.Errorf("unsupported or unknown format: %s", format)
	}
}

// compressZip crée une archive ZIP
func compressZip(paths []string, opts CompressOptions) error {
	file, err := os.Create(opts.Output)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing file: %v\n", err)
		}
	}(file)

	zipWriter := zip.NewWriter(file)
	defer func(zipWriter *zip.Writer) {
		err := zipWriter.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing zip writer: %v\n", err)
		}
	}(zipWriter)

	for _, path := range paths {
		if err := addToZip(zipWriter, path, ""); err != nil {
			return err
		}
	}

	fmt.Fprintf(stdoutW, "Created ZIP archive: %s\n", opts.Output)
	return nil
}

// addToZip ajoute un fichier ou répertoire à une archive ZIP
func addToZip(zipWriter *zip.Writer, path string, baseInZip string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			fullPath := filepath.Join(path, entry.Name())
			zipPath := filepath.Join(baseInZip, info.Name(), entry.Name())
			if err := addToZip(zipWriter, fullPath, zipPath); err != nil {
				return err
			}
		}
		return nil
	}

	// Ajouter le fichier
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing file: %v\n", err)
		}
	}(file)

	zipPath := filepath.Join(baseInZip, info.Name())
	if baseInZip == "" {
		zipPath = info.Name()
	}

	writer, err := zipWriter.Create(zipPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	return err
}

// extractZip extrait une archive ZIP
func extractZip(archivePath string, opts ExtractOptions) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer func(reader *zip.ReadCloser) {
		err := reader.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing zip reader: %v\n", err)
		}
	}(reader)

	for _, file := range reader.File {
		// Appliquer strip-components
		extractPath := file.Name
		if opts.StripComponents > 0 {
			parts := strings.Split(file.Name, string(os.PathSeparator))
			if len(parts) <= opts.StripComponents {
				continue
			}
			extractPath = filepath.Join(parts[opts.StripComponents:]...)
		}

		if file.FileInfo().IsDir() {
			err := os.MkdirAll(extractPath, file.Mode())
			if err != nil {
				return err
			}
			continue
		}

		// Vérifier si le fichier existe
		if !opts.Overwrite {
			if _, err := os.Stat(extractPath); err == nil {
				fmt.Fprintf(stdoutW, "Skipping existing file: %s\n", extractPath)
				continue
			}
		}

		// Créer les répertoires parents
		if err := os.MkdirAll(filepath.Dir(extractPath), 0755); err != nil {
			return err
		}

		// Extraire le fichier
		if err := extractZipFile(file, extractPath); err != nil {
			return err
		}

		fmt.Fprintf(stdoutW, "Extracted: %s\n", extractPath)
	}

	fmt.Fprintln(stdoutW, "Extraction complete")
	return nil
}

// extractZipFile extrait un fichier individuel d'une archive ZIP
func extractZipFile(file *zip.File, destPath string) error {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer func(reader io.ReadCloser) {
		err := reader.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing file: %v\n", err)
		}
	}(reader)

	writer, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
	if err != nil {
		return err
	}
	defer func(writer *os.File) {
		err := writer.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing file: %v\n", err)
		}
	}(writer)

	_, err = io.Copy(writer, reader)
	return err
}

// compressTar crée une archive TAR (avec compression optionnelle)
func compressTar(paths []string, opts CompressOptions, compression string) error {
	file, err := os.Create(opts.Output)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing file: %v\n", err)
		}
	}(file)

	var writer io.Writer = file

	// Ajouter la compression
	if compression == "gzip" {
		gzWriter := gzip.NewWriter(file)
		defer func(gzWriter *gzip.Writer) {
			err := gzWriter.Close()
			if err != nil {
				fmt.Fprintf(stdoutW, "Error closing gzip writer: %v\n", err)
			}
		}(gzWriter)
		writer = gzWriter
	} else if compression == "xz" {
		xzWriter, err := xz.NewWriter(file)
		if err != nil {
			return err
		}
		defer func(xzWriter *xz.Writer) {
			err := xzWriter.Close()
			if err != nil {
				fmt.Fprintf(stdoutW, "Error closing xz writer: %v\n", err)
			}
		}(xzWriter)
		writer = xzWriter
	}

	tarWriter := tar.NewWriter(writer)
	defer func(tarWriter *tar.Writer) {
		err := tarWriter.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing tar writer: %v\n", err)
		}
	}(tarWriter)

	for _, path := range paths {
		if err := addToTar(tarWriter, path, ""); err != nil {
			return err
		}
	}

	fmt.Fprintf(stdoutW, "Created TAR archive: %s\n", opts.Output)
	return nil
}

// addToTar ajoute un fichier ou répertoire à une archive TAR
func addToTar(tarWriter *tar.Writer, path string, baseInTar string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}

	if baseInTar != "" {
		header.Name = filepath.Join(baseInTar, info.Name())
	} else {
		header.Name = info.Name()
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return err
	}

	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			fullPath := filepath.Join(path, entry.Name())
			tarPath := filepath.Join(header.Name)
			if err := addToTar(tarWriter, fullPath, tarPath); err != nil {
				return err
			}
		}
		return nil
	}

	// Ajouter le contenu du fichier
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing file: %v\n", err)
		}
	}(file)

	_, err = io.Copy(tarWriter, file)
	return err
}

// extractTar extrait une archive TAR (avec décompression optionnelle)
func extractTar(archivePath string, opts ExtractOptions, compression string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing file: %v\n", err)
		}
	}(file)

	var reader io.Reader = file

	// Ajouter la décompression
	if compression == "gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer func(gzReader *gzip.Reader) {
			err := gzReader.Close()
			if err != nil {
				fmt.Fprintf(stdoutW, "Error closing gzip reader: %v\n", err)
			}
		}(gzReader)
		reader = gzReader
	} else if compression == "bzip2" {
		reader = bzip2.NewReader(file)
	} else if compression == "xz" {
		xzReader, err := xz.NewReader(file)
		if err != nil {
			return err
		}
		reader = xzReader
	}

	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Appliquer strip-components
		extractPath := header.Name
		if opts.StripComponents > 0 {
			parts := strings.Split(header.Name, string(os.PathSeparator))
			if len(parts) <= opts.StripComponents {
				continue
			}
			extractPath = filepath.Join(parts[opts.StripComponents:]...)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(extractPath, os.FileMode(header.Mode)); err != nil {
				return err
			}

		case tar.TypeReg:
			// Vérifier si le fichier existe
			if !opts.Overwrite {
				if _, err := os.Stat(extractPath); err == nil {
					fmt.Fprintf(stdoutW, "Skipping existing file: %s\n", extractPath)
					continue
				}
			}

			// Créer les répertoires parents
			if err := os.MkdirAll(filepath.Dir(extractPath), 0755); err != nil {
				return err
			}

			// Extraire le fichier
			outFile, err := os.OpenFile(extractPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				err := outFile.Close()
				if err != nil {
					return err
				}
				return err
			}
			err = outFile.Close()
			if err != nil {
				return err
			}

			fmt.Fprintf(stdoutW, "Extracted: %s\n", extractPath)
		}
	}

	fmt.Fprintln(stdoutW, "Extraction complete")
	return nil
}

// detectFormat détecte le format d'une archive basé sur son extension
func detectFormat(path string) string {
	lower := strings.ToLower(path)

	if strings.HasSuffix(lower, ".zip") {
		return "zip"
	} else if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return "tar.gz"
	} else if strings.HasSuffix(lower, ".tar.bz2") || strings.HasSuffix(lower, ".tbz2") {
		return "tar.bz2"
	} else if strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".txz") {
		return "tar.xz"
	} else if strings.HasSuffix(lower, ".tar") {
		return "tar"
	} else if strings.HasSuffix(lower, ".gz") {
		return "gzip"
	} else if strings.HasSuffix(lower, ".bz2") {
		return "bzip2"
	} else if strings.HasSuffix(lower, ".xz") {
		return "xz"
	}

	return ""
}
