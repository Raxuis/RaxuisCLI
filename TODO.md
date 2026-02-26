# RaxuisCLI - Task Tracking

## Phase 1: Cleanup

### 1.1 Remove translate module
- [x] Delete `cmd/translate.go`
- [x] Delete `internal/translate/` folder (translate.go, types/, providers/)

### 1.2 Remove unused code
- [x] Delete `pkg/config/config.go` (empty and unused)

### 1.3 Francisation (CANCELLED - Keep English)
- [x] ~~Franciser cmd/root.go~~ - Kept in English as requested
- [x] ~~Franciser cmd/files.go~~ - Kept in English as requested
- [x] ~~Franciser cmd/pwgen.go~~ - Kept in English as requested
- [x] ~~Franciser cmd/ports.go~~ - Kept in English as requested
- [x] ~~Franciser cmd/todo.go~~ - Kept in English as requested

---

## Phase 2: Encoding/Hash Features

### 2.1 `encode` command
- [x] Create `cmd/encode.go`
- [x] Create `internal/encode/encode.go`
- [x] Implement base64 encoding/decoding
- [x] Implement base32 encoding/decoding
- [x] Implement hex encoding/decoding
- [x] Implement URL encoding/decoding
- [x] Implement HTML entities encoding/decoding
- [x] Implement ROT13 cipher
- [x] Implement ROT-N cipher with --shift flag
- [x] Add `encode decode` subcommand
- [x] Add `encode rot-brute` subcommand

```
raxuiscli encode [text] --format [format]
raxuiscli encode decode [text] --format [format]
raxuiscli encode rot-brute [text]
```

### 2.2 `hash` command
- [x] Create `cmd/hash.go`
- [x] Create `internal/hash/hash.go`
- [x] Implement MD5 hashing
- [x] Implement SHA1 hashing
- [x] Implement SHA256 hashing
- [x] Implement SHA512 hashing
- [x] Implement BLAKE2 hashing
- [x] Add `hash identify` subcommand
- [x] Add `hash crack` subcommand with wordlist support
- [x] Support both text and file input

```
raxuiscli hash [file|text] --algo [algo]
raxuiscli hash crack [hash] --wordlist [file] --algo [algo]
raxuiscli hash identify [hash]
```

---

## Phase 3: File Analysis Features

### 3.1 `hexdump` command
- [x] Create `cmd/hexdump.go`
- [x] Create `internal/hexdump/hexdump.go`
- [x] Implement hex + ASCII display (xxd style)
- [x] Add --offset flag for starting position
- [x] Add --length flag for byte limit
- [x] Add colorization for different byte types
- [x] Add --columns flag for bytes per line

```
raxuiscli hexdump [file] --offset [N] --length [N]
```

### 3.2 `strings` command
- [x] Create `cmd/strings.go`
- [x] Create `internal/strings/strings.go`
- [x] Implement ASCII string extraction
- [x] Implement Unicode (UTF-16) string extraction
- [x] Add --min flag for minimum length
- [x] Add --encoding flag (ascii|unicode|all)
- [x] Add --offset flag to show file offsets

```
raxuiscli strings [file] --min [N] --encoding [ascii|unicode]
```

### 3.3 `entropy` command
- [x] Create `cmd/entropy.go`
- [x] Create `internal/entropy/entropy.go`
- [x] Implement global entropy calculation
- [x] Implement per-block entropy analysis
- [x] Add ASCII visualization bar chart
- [x] Add entropy interpretation (low=text, high=encrypted)
- [x] Add colorized output

```
raxuiscli entropy [file] --block-size [N]
```

### 3.4 `metadata` command
- [x] Create `cmd/metadata.go`
- [x] Create `internal/metadata/metadata.go`
- [x] Implement JPEG/EXIF extraction
- [x] Implement PNG metadata extraction
- [x] Implement PDF metadata extraction
- [x] Implement Office (DOCX/XLSX/PPTX) metadata extraction
- [x] Add `metadata strip` subcommand (basic implementation)

```
raxuiscli metadata [file]
raxuiscli metadata strip [file]
```

---

## Phase 4: Refactoring (Future)

### 4.1 Consolidation checksum → hash
- [ ] Review `files checksum` vs `hash` command overlap
- [ ] Consider merging or clarifying usage differences
- [ ] Keep `files checksum` for file verification (different use case)

---

## Build & Testing

### Build Commands
```bash
go build -o bin/raxuiscli .
go test ./...
./bin/raxuiscli --help
```

### Manual Tests
```bash
# Encode tests
raxuiscli encode "Hello World" --format base64
raxuiscli encode decode "SGVsbG8gV29ybGQ=" --format base64
raxuiscli encode "secret" --format rot13
raxuiscli encode rot-brute "frperg"

# Hash tests
raxuiscli hash "password"
raxuiscli hash "password" --algo md5
raxuiscli hash identify "5d41402abc4b2a76b9719d911017c592"
raxuiscli hash crack "5d41402abc4b2a76b9719d911017c592" --algo md5 --wordlist wordlist.txt

# Hexdump tests
raxuiscli hexdump /bin/ls --length 256
raxuiscli hexdump /bin/ls --offset 1024 --length 128

# Strings tests
raxuiscli strings /bin/ls --min 8
raxuiscli strings /bin/ls --offset

# Entropy tests
raxuiscli entropy /bin/ls
raxuiscli entropy /bin/ls --block-size 4096

# Metadata tests
raxuiscli metadata image.jpg
raxuiscli metadata document.pdf
raxuiscli metadata report.docx
```

---

## Summary

| Phase | Feature | Status |
|-------|---------|--------|
| 1.1 | Remove translate | ✅ Done |
| 1.2 | Remove unused config | ✅ Done |
| 1.3 | Francisation | ❌ Cancelled |
| 2.1 | encode command | ✅ Done |
| 2.2 | hash command | ✅ Done |
| 3.1 | hexdump command | ✅ Done |
| 3.2 | strings command | ✅ Done |
| 3.3 | entropy command | ✅ Done |
| 3.4 | metadata command | ✅ Done |
| 4.1 | checksum consolidation | 📋 Future |
