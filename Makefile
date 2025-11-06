.PHONY: build test clean clean-all

build:
	@echo "🔨 Building KODOK..."
	@go build -o kodok cmd/kodok/main.go

test:
	@echo "🧪 Running tests..."
	@go test ./... -v

clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -f kodok
	@rm -f kodok.exe

clean-all: clean
	@echo "🧹 Cleaning all generated files..."
	@rm -f *.json
	@rm -f *.txt
	@rm -rf results/
	@rm -rf output/
	@rm -f *.log
	@rm -f *.out
	@rm -f coverage.txt

run:
	@go run cmd/kodok/main.go

deps:
	@echo "📦 Downloading dependencies..."
	@go mod download
	@go mod tidy

dev:
	@echo "🚀 Starting development build..."
	@go run cmd/kodok/main.go -u https://example.com -v

# Install dependencies for development
setup:
	@echo "⚙️  Setting up development environment..."
	@go mod download
	@go mod verify

# Build for release
release: clean
	@echo "🏷️  Building release binaries..."
	@GOOS=linux GOARCH=amd64 go build -o dist/kodok-linux-amd64 cmd/kodok/main.go
	@GOOS=darwin GOARCH=amd64 go build -o dist/kodok-darwin-amd64 cmd/kodok/main.go
	@GOOS=windows GOARCH=amd64 go build -o dist/kodok-windows-amd64.exe cmd/kodok/main.go
	@echo "✅ Release binaries built in dist/"

.PHONY: help
help:
	@echo "🐸 KODOK - Available targets:"
	@echo "  build     - Build the binary"
	@echo "  test      - Run tests"
	@echo "  clean     - Remove build artifacts"
	@echo "  clean-all - Remove all generated files"
	@echo "  run       - Run directly with go run"
	@echo "  deps      - Download dependencies"
	@echo "  dev       - Run development build"
	@echo "  setup     - Setup development environment"
	@echo "  release   - Build release binaries for multiple platforms"
	@echo "  help      - Show this help message"