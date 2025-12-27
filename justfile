# go-roast justfile

# Variables
version := "1.0.0"
binary := "roast"
build_dir := "build"
ldflags := "-s -w -X main.version=" + version

# Default task - show available commands
default:
    @just --list

# Clean build directory
clean:
    rm -rf {{build_dir}}
    mkdir -p {{build_dir}}

# Run tests
test:
    go test -v ./...

# Run tests with coverage
test-coverage:
    go test -cover ./...

# Build for current platform
build:
    go build -ldflags "{{ldflags}}" -o {{binary}} ./cmd/roast

# Build all platforms
build-all: clean build-macos-arm build-macos-amd64 build-windows build-linux-amd64 build-linux-arm64
    @echo "✓ Built all platforms"
    @ls -lh {{build_dir}}

# macOS ARM64 (Apple Silicon)
build-macos-arm:
    @echo "Building for macOS ARM64..."
    GOOS=darwin GOARCH=arm64 go build -ldflags "{{ldflags}}" -o {{build_dir}}/{{binary}}-darwin-arm64 ./cmd/roast
    @echo "✓ {{build_dir}}/{{binary}}-darwin-arm64"

# macOS AMD64 (Intel)
build-macos-amd64:
    @echo "Building for macOS AMD64..."
    GOOS=darwin GOARCH=amd64 go build -ldflags "{{ldflags}}" -o {{build_dir}}/{{binary}}-darwin-amd64 ./cmd/roast
    @echo "✓ {{build_dir}}/{{binary}}-darwin-amd64"

# Windows AMD64
build-windows:
    @echo "Building for Windows AMD64..."
    GOOS=windows GOARCH=amd64 go build -ldflags "{{ldflags}}" -o {{build_dir}}/{{binary}}-windows-amd64.exe ./cmd/roast
    @echo "✓ {{build_dir}}/{{binary}}-windows-amd64.exe"

# Linux AMD64
build-linux-amd64:
    @echo "Building for Linux AMD64..."
    GOOS=linux GOARCH=amd64 go build -ldflags "{{ldflags}}" -o {{build_dir}}/{{binary}}-linux-amd64 ./cmd/roast
    @echo "✓ {{build_dir}}/{{binary}}-linux-amd64"

# Linux ARM64
build-linux-arm64:
    @echo "Building for Linux ARM64..."
    GOOS=linux GOARCH=arm64 go build -ldflags "{{ldflags}}" -o {{build_dir}}/{{binary}}-linux-arm64 ./cmd/roast
    @echo "✓ {{build_dir}}/{{binary}}-linux-arm64"

# Install locally
install:
    go install -ldflags "{{ldflags}}" ./cmd/roast

# Create release archives
release: build-all
    @echo "Creating release archives..."
    cd {{build_dir}} && tar -czf {{binary}}-darwin-arm64.tar.gz {{binary}}-darwin-arm64
    cd {{build_dir}} && tar -czf {{binary}}-darwin-amd64.tar.gz {{binary}}-darwin-amd64
    cd {{build_dir}} && tar -czf {{binary}}-linux-amd64.tar.gz {{binary}}-linux-amd64
    cd {{build_dir}} && tar -czf {{binary}}-linux-arm64.tar.gz {{binary}}-linux-arm64
    cd {{build_dir}} && zip -q {{binary}}-windows-amd64.zip {{binary}}-windows-amd64.exe
    @echo "✓ Release archives created"
    @ls -lh {{build_dir}}/*.{tar.gz,zip}

# Generate checksums for releases
checksums:
    cd {{build_dir}} && shasum -a 256 *.{tar.gz,zip} > SHA256SUMS
    @echo "✓ Checksums generated"
    @cat {{build_dir}}/SHA256SUMS

# Test MCP server locally
test-mcp:
    @echo "Testing MCP server initialization..."
    @echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | ./{{binary}} mcp | jq .

# Test decode with sample domain
test-decode:
    @echo "Testing decode command..."
    @echo "c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro" | ./{{binary}} decode -o json | jq .

# Test extract with sample text
test-extract:
    @echo "Testing extract command..."
    @echo "Found: c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro" | ./{{binary}} extract --decode -o json | jq .

# Run all functional tests
test-all: test test-decode test-extract test-mcp
    @echo "✓ All tests passed"

# Development build with race detector
dev:
    go build -race -ldflags "{{ldflags}}" -o {{binary}}-dev ./cmd/roast

# Format code
fmt:
    go fmt ./...

# Lint code
lint:
    golangci-lint run ./...

# Update dependencies
deps:
    go mod tidy
    go mod download

# Show build info
info:
    @echo "Version: {{version}}"
    @echo "Binary: {{binary}}"
    @echo "Build dir: {{build_dir}}"
    @echo "Go version: $(go version)"
    @echo "Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"
