.PHONY: build build-all clean install test test-race cover lint tidy run help

BINARY      := raxuiscli
PKG         := raxuiscli/cmd
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X $(PKG).version=$(VERSION) \
	-X $(PKG).commit=$(COMMIT) \
	-X $(PKG).date=$(DATE)

## build: build the binary into bin/
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

## build-all: cross-compile for linux, windows and darwin
build-all:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-windows-amd64.exe .
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-darwin-arm64 .

## clean: remove build artifacts
clean:
	rm -rf bin/ dist/ coverage.txt coverage.html

## install: install the binary with version metadata
install:
	go install -trimpath -ldflags "$(LDFLAGS)" .

## test: run the test suite
test:
	go test ./...

## test-race: run the test suite with the race detector
test-race:
	go test -race ./...

## cover: run tests with coverage and write coverage.html
cover:
	go test -covermode=atomic -coverprofile=coverage.txt ./...
	go tool cover -html=coverage.txt -o coverage.html
	go tool cover -func=coverage.txt | tail -1

## lint: run golangci-lint (install: https://golangci-lint.run/usage/install/)
lint:
	golangci-lint run ./...

## tidy: sync go.mod / go.sum
tidy:
	go mod tidy

## run: build and run (use ARGS="..." to pass flags)
run: build
	./bin/$(BINARY) $(ARGS)

## help: list available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
