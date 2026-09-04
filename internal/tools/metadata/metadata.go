package metadata

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileType represents the detected file type
type FileType string

const (
	TypeUnknown FileType = "unknown"
	TypeJPEG    FileType = "jpeg"
	TypePNG     FileType = "png"
	TypeGIF     FileType = "gif"
	TypePDF     FileType = "pdf"
	TypeDOCX    FileType = "docx"
	TypeXLSX    FileType = "xlsx"
	TypePPTX    FileType = "pptx"
	TypeZIP     FileType = "zip"
)

// Metadata holds extracted metadata
type Metadata struct {
	FileType   FileType
	FileName   string
	FileSize   int64
	ModTime    time.Time
	Properties map[string]string
	ExifData   map[string]string
	Errors     []string
}

// Extract extracts metadata from a file
func Extract(path string) (*Metadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("error getting file info: %w", err)
	}

	meta := &Metadata{
		FileName:   filepath.Base(path),
		FileSize:   info.Size(),
		ModTime:    info.ModTime(),
		Properties: make(map[string]string),
		ExifData:   make(map[string]string),
		Errors:     []string{},
	}

	// Detect file type
	meta.FileType = detectFileType(path, file)

	// Reset file position
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	// Extract type-specific metadata
	switch meta.FileType {
	case TypeJPEG:
		extractJPEGMetadata(file, meta)
	case TypePNG:
		extractPNGMetadata(file, meta)
	case TypePDF:
		extractPDFMetadata(file, meta)
	case TypeDOCX, TypeXLSX, TypePPTX:
		extractOfficeMetadata(path, meta)
	default:
		meta.Properties["note"] = "Limited metadata extraction for this file type"
	}

	// Add basic file properties
	meta.Properties["file_name"] = meta.FileName
	meta.Properties["file_size"] = fmt.Sprintf("%d bytes", meta.FileSize)
	meta.Properties["modified"] = meta.ModTime.Format(time.RFC3339)
	meta.Properties["file_type"] = string(meta.FileType)

	return meta, nil
}

// detectFileType detects the file type based on magic bytes and extension
func detectFileType(path string, file *os.File) FileType {
	// Read magic bytes
	magic := make([]byte, 16)
	n, err := file.Read(magic)
	if err != nil || n < 4 {
		return TypeUnknown
	}

	// Check magic bytes
	switch {
	case bytes.HasPrefix(magic, []byte{0xFF, 0xD8, 0xFF}):
		return TypeJPEG
	case bytes.HasPrefix(magic, []byte{0x89, 0x50, 0x4E, 0x47}):
		return TypePNG
	case bytes.HasPrefix(magic, []byte{0x47, 0x49, 0x46, 0x38}):
		return TypeGIF
	case bytes.HasPrefix(magic, []byte{0x25, 0x50, 0x44, 0x46}):
		return TypePDF
	case bytes.HasPrefix(magic, []byte{0x50, 0x4B, 0x03, 0x04}):
		// ZIP-based format, check extension
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".docx":
			return TypeDOCX
		case ".xlsx":
			return TypeXLSX
		case ".pptx":
			return TypePPTX
		default:
			return TypeZIP
		}
	}

	// Fall back to extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".jpg", ".jpeg":
		return TypeJPEG
	case ".png":
		return TypePNG
	case ".gif":
		return TypeGIF
	case ".pdf":
		return TypePDF
	case ".docx":
		return TypeDOCX
	case ".xlsx":
		return TypeXLSX
	case ".pptx":
		return TypePPTX
	}

	return TypeUnknown
}

// extractJPEGMetadata extracts EXIF data from JPEG files
func extractJPEGMetadata(file *os.File, meta *Metadata) {
	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		meta.Errors = append(meta.Errors, "Failed to read JPEG header")
		return
	}

	// Read file content
	data, err := io.ReadAll(file)
	if err != nil {
		meta.Errors = append(meta.Errors, "Failed to read file")
		return
	}

	// Look for EXIF marker (APP1)
	exifMarker := []byte{0xFF, 0xE1}
	idx := bytes.Index(data, exifMarker)
	if idx == -1 {
		meta.Properties["exif"] = "No EXIF data found"
		return
	}

	// Skip marker and get length
	if idx+4 >= len(data) {
		return
	}

	// Check for "Exif" header
	exifHeader := data[idx+4:]
	if len(exifHeader) < 6 {
		return
	}

	if string(exifHeader[:4]) == "Exif" {
		meta.ExifData["exif_present"] = "true"

		// Basic EXIF parsing - look for common tags
		parseBasicExif(data[idx:], meta)
	}
}

// parseBasicExif does basic EXIF parsing
func parseBasicExif(data []byte, meta *Metadata) {
	// Look for common strings in EXIF data
	dataStr := string(data)

	// Try to find camera make/model (often ASCII in EXIF)
	// This is a simplified approach
	if idx := strings.Index(dataStr, "NIKON"); idx != -1 {
		meta.ExifData["make"] = "NIKON"
	} else if idx := strings.Index(dataStr, "Canon"); idx != -1 {
		meta.ExifData["make"] = "Canon"
	} else if idx := strings.Index(dataStr, "Apple"); idx != -1 {
		meta.ExifData["make"] = "Apple"
	} else if idx := strings.Index(dataStr, "SONY"); idx != -1 {
		meta.ExifData["make"] = "SONY"
	} else if idx := strings.Index(dataStr, "samsung"); idx != -1 {
		meta.ExifData["make"] = "Samsung"
	}

	// Look for software
	if idx := strings.Index(dataStr, "Adobe"); idx != -1 {
		meta.ExifData["software"] = "Adobe"
	} else if idx := strings.Index(dataStr, "GIMP"); idx != -1 {
		meta.ExifData["software"] = "GIMP"
	}
}

// extractPNGMetadata extracts metadata from PNG files
func extractPNGMetadata(file *os.File, meta *Metadata) {
	_, err := file.Seek(8, io.SeekStart) // Skip PNG signature
	if err != nil {
		meta.Errors = append(meta.Errors, "Failed to read PNG header")
		return
	}

	// Read chunks
	for {
		// Read chunk length and type
		var length uint32
		if err := binary.Read(file, binary.BigEndian, &length); err != nil {
			break
		}

		chunkType := make([]byte, 4)
		if _, err := file.Read(chunkType); err != nil {
			break
		}

		chunkName := string(chunkType)

		// Handle specific chunks
		switch chunkName {
		case "IHDR":
			// Image header
			var width, height uint32
			binary.Read(file, binary.BigEndian, &width)
			binary.Read(file, binary.BigEndian, &height)
			meta.Properties["width"] = fmt.Sprintf("%d", width)
			meta.Properties["height"] = fmt.Sprintf("%d", height)

			bitDepth := make([]byte, 1)
			file.Read(bitDepth)
			meta.Properties["bit_depth"] = fmt.Sprintf("%d", bitDepth[0])

			colorType := make([]byte, 1)
			file.Read(colorType)
			meta.Properties["color_type"] = fmt.Sprintf("%d", colorType[0])

			// Skip rest of IHDR
			file.Seek(int64(length-10+4), io.SeekCurrent) // +4 for CRC

		case "tEXt", "iTXt":
			// Text chunks may contain metadata
			textData := make([]byte, length)
			file.Read(textData)

			// Split on null byte
			parts := bytes.SplitN(textData, []byte{0}, 2)
			if len(parts) >= 2 {
				key := string(parts[0])
				value := string(parts[1])
				meta.Properties[key] = value
			}

			// Skip CRC
			file.Seek(4, io.SeekCurrent)

		case "IEND":
			break

		default:
			// Skip chunk data and CRC
			file.Seek(int64(length+4), io.SeekCurrent)
		}

		if chunkName == "IEND" {
			break
		}
	}
}

// extractPDFMetadata extracts metadata from PDF files
func extractPDFMetadata(file *os.File, meta *Metadata) {
	// Read entire file for simple parsing
	data, err := io.ReadAll(file)
	if err != nil {
		meta.Errors = append(meta.Errors, "Failed to read PDF")
		return
	}

	content := string(data)

	// Look for /Info dictionary
	infoIdx := strings.Index(content, "/Info")
	if infoIdx != -1 {
		meta.Properties["info_dict"] = "present"
	}

	// Look for common metadata fields
	fields := []string{"/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer", "/CreationDate", "/ModDate"}

	for _, field := range fields {
		if idx := strings.Index(content, field); idx != -1 {
			// Try to extract value (simplified)
			afterField := content[idx+len(field):]
			if len(afterField) > 0 {
				// Look for parentheses or angle brackets
				if afterField[0] == '(' {
					endIdx := strings.Index(afterField, ")")
					if endIdx > 1 {
						value := afterField[1:endIdx]
						key := strings.TrimPrefix(field, "/")
						meta.Properties[strings.ToLower(key)] = value
					}
				}
			}
		}
	}

	// Get PDF version
	if len(content) > 8 && strings.HasPrefix(content, "%PDF-") {
		version := content[5:8]
		meta.Properties["pdf_version"] = version
	}
}

// OfficeCoreMeta represents core.xml structure
type OfficeCoreMeta struct {
	XMLName        xml.Name `xml:"coreProperties"`
	Creator        string   `xml:"creator"`
	LastModifiedBy string   `xml:"lastModifiedBy"`
	Created        string   `xml:"created"`
	Modified       string   `xml:"modified"`
	Title          string   `xml:"title"`
	Subject        string   `xml:"subject"`
	Keywords       string   `xml:"keywords"`
	Description    string   `xml:"description"`
	Revision       string   `xml:"revision"`
}

// OfficeAppMeta represents app.xml structure
type OfficeAppMeta struct {
	XMLName     xml.Name `xml:"Properties"`
	Application string   `xml:"Application"`
	AppVersion  string   `xml:"AppVersion"`
	Company     string   `xml:"Company"`
	Template    string   `xml:"Template"`
	TotalTime   string   `xml:"TotalTime"`
	Pages       string   `xml:"Pages"`
	Words       string   `xml:"Words"`
	Characters  string   `xml:"Characters"`
}

// extractOfficeMetadata extracts metadata from Office Open XML files
func extractOfficeMetadata(path string, meta *Metadata) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		meta.Errors = append(meta.Errors, "Failed to open as ZIP")
		return
	}
	defer reader.Close()

	for _, file := range reader.File {
		switch file.Name {
		case "docProps/core.xml":
			extractCoreXML(file, meta)
		case "docProps/app.xml":
			extractAppXML(file, meta)
		}
	}
}

func extractCoreXML(file *zip.File, meta *Metadata) {
	rc, err := file.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return
	}

	var core OfficeCoreMeta
	if err := xml.Unmarshal(data, &core); err != nil {
		// Try to extract manually as the namespace can vary
		content := string(data)

		extractXMLTag(content, "creator", meta.Properties)
		extractXMLTag(content, "lastModifiedBy", meta.Properties)
		extractXMLTag(content, "created", meta.Properties)
		extractXMLTag(content, "modified", meta.Properties)
		extractXMLTag(content, "title", meta.Properties)
		extractXMLTag(content, "subject", meta.Properties)
		extractXMLTag(content, "keywords", meta.Properties)
		extractXMLTag(content, "description", meta.Properties)
		extractXMLTag(content, "revision", meta.Properties)
		return
	}

	if core.Creator != "" {
		meta.Properties["creator"] = core.Creator
	}
	if core.LastModifiedBy != "" {
		meta.Properties["last_modified_by"] = core.LastModifiedBy
	}
	if core.Created != "" {
		meta.Properties["created"] = core.Created
	}
	if core.Modified != "" {
		meta.Properties["modified"] = core.Modified
	}
	if core.Title != "" {
		meta.Properties["title"] = core.Title
	}
	if core.Subject != "" {
		meta.Properties["subject"] = core.Subject
	}
	if core.Keywords != "" {
		meta.Properties["keywords"] = core.Keywords
	}
	if core.Revision != "" {
		meta.Properties["revision"] = core.Revision
	}
}

func extractAppXML(file *zip.File, meta *Metadata) {
	rc, err := file.Open()
	if err != nil {
		return
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return
	}

	var app OfficeAppMeta
	if err := xml.Unmarshal(data, &app); err != nil {
		content := string(data)
		extractXMLTag(content, "Application", meta.Properties)
		extractXMLTag(content, "AppVersion", meta.Properties)
		extractXMLTag(content, "Company", meta.Properties)
		extractXMLTag(content, "TotalTime", meta.Properties)
		extractXMLTag(content, "Pages", meta.Properties)
		extractXMLTag(content, "Words", meta.Properties)
		return
	}

	if app.Application != "" {
		meta.Properties["application"] = app.Application
	}
	if app.AppVersion != "" {
		meta.Properties["app_version"] = app.AppVersion
	}
	if app.Company != "" {
		meta.Properties["company"] = app.Company
	}
	if app.TotalTime != "" {
		meta.Properties["total_time"] = app.TotalTime + " minutes"
	}
	if app.Pages != "" {
		meta.Properties["pages"] = app.Pages
	}
	if app.Words != "" {
		meta.Properties["words"] = app.Words
	}
	if app.Characters != "" {
		meta.Properties["characters"] = app.Characters
	}
}

func extractXMLTag(content, tag string, props map[string]string) {
	// Simple XML tag extraction
	startTag := "<" + tag
	endTag := "</" + tag + ">"

	start := strings.Index(content, startTag)
	if start == -1 {
		// Try with namespace prefix
		start = strings.Index(content, ":"+tag)
		if start == -1 {
			return
		}
		// Find the actual start of the tag
		for i := start - 1; i >= 0; i-- {
			if content[i] == '<' {
				start = i
				break
			}
		}
	}

	// Find closing of opening tag
	closeStart := strings.Index(content[start:], ">")
	if closeStart == -1 {
		return
	}

	valueStart := start + closeStart + 1
	end := strings.Index(content[valueStart:], endTag)
	if end == -1 {
		// Try with namespace
		for _, ns := range []string{"dc:", "cp:", "dcterms:", ""} {
			endTagNs := "</" + ns + tag + ">"
			end = strings.Index(content[valueStart:], endTagNs)
			if end != -1 {
				break
			}
		}
		if end == -1 {
			return
		}
	}

	value := strings.TrimSpace(content[valueStart : valueStart+end])
	if value != "" {
		props[strings.ToLower(tag)] = value
	}
}

// Strip removes metadata from a file (creates a clean copy)
func Strip(inputPath, outputPath string) error {
	// For now, just copy the file and note that stripping requires format-specific handling
	// Full implementation would require rewriting files without metadata

	input, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, input, 0644)
}
