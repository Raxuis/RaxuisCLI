.PHONY: build clean install test run-todo run-weather run-organize

# Build the application
build:
	go build -o bin/raxuiscli .

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o bin/raxuiscli-linux-amd64 .
	GOOS=windows GOARCH=amd64 go build -o bin/raxuiscli-windows-amd64.exe .
	GOOS=darwin GOARCH=amd64 go build -o bin/raxuiscli-darwin-amd64 .

# Clean build artifacts
clean:
	rm -rf bin/

# Install to system (requires GOPATH/bin in PATH)
install:
	go install .

# Run tests
test:
	go test ./...

# Development helpers
run-todo:
	go run . todo --help

run-ports:
	go run . ports --help

run-pwgen:
	go run . pwgen --help

# Initialize go mod
init:
	go mod init raxuiscli
	go mod tidy

# Download dependencies
deps:
	go mod download
	go mod tidy