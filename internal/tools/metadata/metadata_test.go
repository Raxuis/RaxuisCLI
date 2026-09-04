package metadata

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	return path
}

func TestDetectFileTypeMagicBytes(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name  string
		magic []byte
		want  FileType
	}{
		{"a.bin", []byte{0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0}, TypeJPEG},
		{"b.bin", []byte{0x89, 0x50, 0x4E, 0x47, 0, 0, 0, 0}, TypePNG},
		{"c.bin", []byte{0x47, 0x49, 0x46, 0x38, 0, 0, 0, 0}, TypeGIF},
		{"d.bin", []byte{0x25, 0x50, 0x44, 0x46, 0, 0, 0, 0}, TypePDF},
	}
	for _, tt := range tests {
		path := writeFile(t, dir, tt.name, tt.magic)
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("failed to open %s: %v", path, err)
		}
		got := detectFileType(path, f)
		f.Close()
		if got != tt.want {
			t.Errorf("detectFileType(%s) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestDetectFileTypeZipExtensions(t *testing.T) {
	dir := t.TempDir()
	zipMagic := []byte{0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0}

	tests := []struct {
		name string
		want FileType
	}{
		{"a.docx", TypeDOCX},
		{"b.xlsx", TypeXLSX},
		{"c.pptx", TypePPTX},
		{"d.zip", TypeZIP},
	}
	for _, tt := range tests {
		path := writeFile(t, dir, tt.name, zipMagic)
		f, _ := os.Open(path)
		got := detectFileType(path, f)
		f.Close()
		if got != tt.want {
			t.Errorf("detectFileType(%s) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestDetectFileTypeExtensionFallback(t *testing.T) {
	dir := t.TempDir()
	// No recognizable magic bytes, so it should fall back to the extension.
	path := writeFile(t, dir, "photo.jpg", []byte("not really a jpeg"))
	f, _ := os.Open(path)
	got := detectFileType(path, f)
	f.Close()
	if got != TypeJPEG {
		t.Errorf("detectFileType with .jpg extension fallback = %q, want %q", got, TypeJPEG)
	}
}

func TestDetectFileTypeUnknown(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "mystery.xyz", []byte("random bytes"))
	f, _ := os.Open(path)
	got := detectFileType(path, f)
	f.Close()
	if got != TypeUnknown {
		t.Errorf("detectFileType(unknown) = %q, want %q", got, TypeUnknown)
	}
}

func TestDetectFileTypeTooShort(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "tiny.bin", []byte{0x01, 0x02})
	f, _ := os.Open(path)
	got := detectFileType(path, f)
	f.Close()
	if got != TypeUnknown {
		t.Errorf("detectFileType on a too-short file = %q, want %q", got, TypeUnknown)
	}
}

func TestExtractMissingFile(t *testing.T) {
	if _, err := Extract("/nonexistent/file"); err == nil {
		t.Error("Extract on a missing file should return an error")
	}
}

func TestExtractUnknownType(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "data.bin", []byte("just some bytes"))

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.FileType != TypeUnknown {
		t.Errorf("FileType = %q, want %q", meta.FileType, TypeUnknown)
	}
	if meta.Properties["note"] == "" {
		t.Error("expected a note about limited metadata extraction")
	}
	if meta.Properties["file_name"] != "data.bin" {
		t.Errorf("file_name = %q, want data.bin", meta.Properties["file_name"])
	}
}

func TestExtractJPEGWithExif(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8, 0xFF}) // JPEG magic
	buf.Write([]byte{0xFF, 0xE1})       // APP1/EXIF marker
	buf.Write([]byte{0x00, 0x20})       // length (arbitrary)
	buf.WriteString("Exif\x00\x00")
	buf.WriteString("padding NIKON camera data Adobe processed")

	path := writeFile(t, dir, "photo.jpg", buf.Bytes())
	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.FileType != TypeJPEG {
		t.Fatalf("FileType = %q, want %q", meta.FileType, TypeJPEG)
	}
	if meta.ExifData["exif_present"] != "true" {
		t.Error("expected exif_present=true")
	}
	if meta.ExifData["make"] != "NIKON" {
		t.Errorf("make = %q, want NIKON", meta.ExifData["make"])
	}
	if meta.ExifData["software"] != "Adobe" {
		t.Errorf("software = %q, want Adobe", meta.ExifData["software"])
	}
}

func TestExtractJPEGWithoutExif(t *testing.T) {
	dir := t.TempDir()
	data := append([]byte{0xFF, 0xD8, 0xFF}, []byte("no exif marker here at all")...)
	path := writeFile(t, dir, "plain.jpg", data)

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.Properties["exif"] != "No EXIF data found" {
		t.Errorf("exif property = %q, want %q", meta.Properties["exif"], "No EXIF data found")
	}
}

func TestParseBasicExifAllMakes(t *testing.T) {
	makes := map[string]string{
		"NIKON":   "NIKON",
		"Canon":   "Canon",
		"Apple":   "Apple",
		"SONY":    "SONY",
		"samsung": "Samsung",
	}
	for needle, want := range makes {
		meta := &Metadata{ExifData: make(map[string]string)}
		parseBasicExif([]byte("junk "+needle+" junk"), meta)
		if meta.ExifData["make"] != want {
			t.Errorf("parseBasicExif(%q) make = %q, want %q", needle, meta.ExifData["make"], want)
		}
	}
}

func TestParseBasicExifSoftwareGIMP(t *testing.T) {
	meta := &Metadata{ExifData: make(map[string]string)}
	parseBasicExif([]byte("some data GIMP some more"), meta)
	if meta.ExifData["software"] != "GIMP" {
		t.Errorf("software = %q, want GIMP", meta.ExifData["software"])
	}
}

func buildPNG(t *testing.T, textKey, textValue string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}) // signature

	// IHDR chunk: length=13, "IHDR", width(4) height(4) bitdepth(1) colortype(1) + 3 filler bytes, then CRC(4)
	ihdrData := new(bytes.Buffer)
	binary.Write(ihdrData, binary.BigEndian, uint32(100)) // width
	binary.Write(ihdrData, binary.BigEndian, uint32(200)) // height
	ihdrData.WriteByte(8)                                 // bit depth
	ihdrData.WriteByte(6)                                 // color type
	ihdrData.Write([]byte{0, 0, 0})                       // compression, filter, interlace

	binary.Write(&buf, binary.BigEndian, uint32(13))
	buf.WriteString("IHDR")
	buf.Write(ihdrData.Bytes())
	buf.Write([]byte{0, 0, 0, 0}) // fake CRC

	if textKey != "" {
		textData := []byte(textKey + "\x00" + textValue)
		binary.Write(&buf, binary.BigEndian, uint32(len(textData)))
		buf.WriteString("tEXt")
		buf.Write(textData)
		buf.Write([]byte{0, 0, 0, 0}) // fake CRC
	}

	binary.Write(&buf, binary.BigEndian, uint32(0))
	buf.WriteString("IEND")
	buf.Write([]byte{0, 0, 0, 0})

	return buf.Bytes()
}

func TestExtractPNGMetadata(t *testing.T) {
	dir := t.TempDir()
	data := buildPNG(t, "Comment", "made with RaxuisCLI tests")
	path := writeFile(t, dir, "image.png", data)

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.FileType != TypePNG {
		t.Fatalf("FileType = %q, want %q", meta.FileType, TypePNG)
	}
	if meta.Properties["width"] != "100" || meta.Properties["height"] != "200" {
		t.Errorf("width/height = %q/%q, want 100/200", meta.Properties["width"], meta.Properties["height"])
	}
	if meta.Properties["bit_depth"] != "8" {
		t.Errorf("bit_depth = %q, want 8", meta.Properties["bit_depth"])
	}
	if meta.Properties["Comment"] != "made with RaxuisCLI tests" {
		t.Errorf("tEXt chunk Comment = %q, want %q", meta.Properties["Comment"], "made with RaxuisCLI tests")
	}
}

func TestExtractPNGNoTextChunk(t *testing.T) {
	dir := t.TempDir()
	data := buildPNG(t, "", "")
	path := writeFile(t, dir, "image.png", data)

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.Properties["width"] != "100" {
		t.Errorf("width = %q, want 100", meta.Properties["width"])
	}
}

func TestExtractPDFMetadata(t *testing.T) {
	dir := t.TempDir()
	// extractPDFMetadata expects the value's opening paren to immediately
	// follow the field name (no space), matching how it indexes afterField[0].
	content := "%PDF-1.4\n" +
		"1 0 obj << /Type /Catalog >> endobj\n" +
		"/Info 5 0 R\n" +
		"5 0 obj << /Title(Test Document) /Author(Jane Doe) /Subject(Testing) >> endobj\n"
	path := writeFile(t, dir, "doc.pdf", []byte(content))

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.FileType != TypePDF {
		t.Fatalf("FileType = %q, want %q", meta.FileType, TypePDF)
	}
	if meta.Properties["info_dict"] != "present" {
		t.Error("expected info_dict=present")
	}
	if meta.Properties["title"] != "Test Document" {
		t.Errorf("title = %q, want %q", meta.Properties["title"], "Test Document")
	}
	if meta.Properties["author"] != "Jane Doe" {
		t.Errorf("author = %q, want %q", meta.Properties["author"], "Jane Doe")
	}
	if meta.Properties["pdf_version"] != "1.4" {
		t.Errorf("pdf_version = %q, want %q", meta.Properties["pdf_version"], "1.4")
	}
}

func TestExtractPDFNoInfo(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "doc.pdf", []byte("%PDF-1.7\nno metadata fields here"))

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if _, ok := meta.Properties["info_dict"]; ok {
		t.Error("expected no info_dict property when /Info is absent")
	}
	if meta.Properties["pdf_version"] != "1.7" {
		t.Errorf("pdf_version = %q, want %q", meta.Properties["pdf_version"], "1.7")
	}
}

func buildDocx(t *testing.T, coreXML, appXML string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "doc.docx")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create docx: %v", err)
	}
	zw := zip.NewWriter(f)

	w, _ := zw.Create("docProps/core.xml")
	w.Write([]byte(coreXML))

	w, _ = zw.Create("docProps/app.xml")
	w.Write([]byte(appXML))

	zw.Close()
	f.Close()
	return path
}

func TestExtractOfficeMetadataWellFormedXML(t *testing.T) {
	coreXML := `<coreProperties><creator>Alice</creator><lastModifiedBy>Bob</lastModifiedBy><title>Report</title></coreProperties>`
	appXML := `<Properties><Application>Microsoft Word</Application><Pages>3</Pages></Properties>`
	path := buildDocx(t, coreXML, appXML)

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.FileType != TypeDOCX {
		t.Fatalf("FileType = %q, want %q", meta.FileType, TypeDOCX)
	}
	if meta.Properties["creator"] != "Alice" {
		t.Errorf("creator = %q, want Alice", meta.Properties["creator"])
	}
	if meta.Properties["application"] != "Microsoft Word" {
		t.Errorf("application = %q, want %q", meta.Properties["application"], "Microsoft Word")
	}
	if meta.Properties["pages"] != "3" {
		t.Errorf("pages = %q, want 3", meta.Properties["pages"])
	}
}

func TestExtractOfficeMetadataFallbackManualParse(t *testing.T) {
	// Missing the closing root tag makes xml.Unmarshal fail, forcing the
	// manual extractXMLTag fallback path - which should still find the
	// well-formed inner tags via substring search.
	coreXML := `<coreProperties><creator>Carol</creator><title>Untitled</title>`
	appXML := `<Properties><Application>PowerPoint</Application>`
	path := buildDocx(t, coreXML, appXML)

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.Properties["creator"] != "Carol" {
		t.Errorf("creator (fallback parse) = %q, want Carol", meta.Properties["creator"])
	}
	if meta.Properties["application"] != "PowerPoint" {
		t.Errorf("application (fallback parse) = %q, want PowerPoint", meta.Properties["application"])
	}
}

func TestExtractOfficeMetadataNamespacedTags(t *testing.T) {
	// Malformed (missing root close) + namespaced inner tags, exercising the
	// extractXMLTag namespace-prefix fallback search.
	coreXML := `<cp:coreProperties xmlns:cp="x" xmlns:dc="y"><dc:creator>Dana</dc:creator>`
	path := buildDocx(t, coreXML, `<Properties></Properties>`)

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if meta.Properties["creator"] != "Dana" {
		t.Errorf("creator (namespaced fallback) = %q, want Dana", meta.Properties["creator"])
	}
}

func TestExtractOfficeMetadataNotAZip(t *testing.T) {
	dir := t.TempDir()
	// ZIP magic bytes but invalid ZIP structure so zip.OpenReader fails.
	path := writeFile(t, dir, "bad.docx", []byte{0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0})

	meta, err := Extract(path)
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if len(meta.Errors) == 0 {
		t.Error("expected an error to be recorded for an invalid ZIP/docx")
	}
}

func TestStrip(t *testing.T) {
	dir := t.TempDir()
	inPath := writeFile(t, dir, "in.txt", []byte("file content"))
	outPath := filepath.Join(dir, "out.txt")

	if err := Strip(inPath, outPath); err != nil {
		t.Fatalf("Strip returned error: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read stripped output: %v", err)
	}
	if string(got) != "file content" {
		t.Errorf("Strip output content = %q, want %q", got, "file content")
	}
}

func TestStripMissingInput(t *testing.T) {
	dir := t.TempDir()
	if err := Strip("/nonexistent/file", filepath.Join(dir, "out.txt")); err == nil {
		t.Error("Strip on a missing input file should return an error")
	}
}
