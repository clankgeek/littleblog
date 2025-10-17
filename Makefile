# Variables
BINARY_NAME=littleblog
BUILD_DIR=build
BUILD_ID := $(shell date +%Y%m%d%H%M%S)
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildID=${BUILD_ID} -s -w"
PLATFORMS=linux/386 linux/amd64 linux/arm linux/arm64 darwin/amd64 darwin/arm64 windows/386 windows/amd64

# Debian package variables
DEB_VERSION=$(shell echo $(VERSION) | sed 's/^v//')
DEB_ARCH=amd64
DEB_NAME=$(BINARY_NAME)_$(DEB_VERSION)_$(DEB_ARCH)
DEB_DIR=$(BUILD_DIR)/debian/$(DEB_NAME)

# Go parameters
GOCMD=CGO_ENABLED=1 go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

.PHONY: all build clean test test-unit test-integration test-bench deps help run example deb deb-clean

# Default target
all: help

# Build the project
build:
	@echo "🔨 Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	@echo "✅ Dependencies installed"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)
	rm -rf static/*
	rm -f coverage.out coverage.html
	rm -f test-report.html benchmark_results.txt
	rm -f *.prof
	@echo "✅ Clean complete"

# Run tests
test: test-unit

# Run unit tests only
test-unit:
	@echo "🧪 Running unit tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo "📊 Test coverage:"
	$(GOCMD) tool cover -func=coverage.out

# Run integration tests (requires -tags integration)
test-integration:
	@echo "🔧 Running integration tests..."
	$(GOTEST) -v -race -tags=integration ./...

# Run all tests (unit + integration)
test-all: test-unit test-integration

# Run benchmarks
test-bench:
	@echo "⚡ Running benchmarks..."
	$(GOTEST) -v -bench=. -benchmem ./...

# Generate test coverage report
coverage: test-unit
	@echo "📊 Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report: coverage.html"

# Run comprehensive test suite
test-suite:
	@chmod +x test.sh
	@./test.sh all

# Run CI test pipeline
test-ci:
	@chmod +x test.sh
	@./test.sh ci

# Run security tests
test-security:
	@chmod +x test.sh
	@./test.sh security

# Run lint checks
lint:
	@echo "🔍 Running lint checks..."
	@$(GOCMD) vet ./...
	@$(GOCMD) fmt ./...
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; fi

# Run with custom config
run: build
	@echo "🏃 Running $(BINARY_NAME)..."
	@if [ -f "littleblog.yaml" ]; then \
		./$(BUILD_DIR)/$(BINARY_NAME) -config littleblog.yaml; \
	else \
		echo "❌ Configuration file 'littleblog.yaml' not found"; \
		echo "💡 Run 'make example' to create one"; \
		exit 1; \
	fi

# Create example configuration
example: build
	@echo "📝 Creating example configuration..."
	./$(BUILD_DIR)/$(BINARY_NAME) -example
	@echo "✅ Example configuration created: littleblog.yaml"
	@echo "💡 Edit the file before running 'make run'"

# Build Debian package for linux/amd64
deb: deps
	@echo "📦 Building Debian package..."
	@echo "Version: $(DEB_VERSION)"
	
	# Build binary for linux/amd64
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	
	# Create debian package structure
	@mkdir -p $(DEB_DIR)/DEBIAN
	@mkdir -p $(DEB_DIR)/usr/local/bin
	@mkdir -p $(DEB_DIR)/etc/littleblog
	@mkdir -p $(DEB_DIR)/etc/systemd/system
	@mkdir -p $(DEB_DIR)/usr/share/doc/littleblog
	
	# Copy binary
	@cp $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(DEB_DIR)/usr/local/bin/$(BINARY_NAME)
	@chmod +x $(DEB_DIR)/usr/local/bin/$(BINARY_NAME)
	
	# Create example config if exists
	@if [ -f "littleblog.yaml" ]; then \
		cp littleblog.yaml $(DEB_DIR)/etc/littleblog/littleblog.yaml.example; \
	fi
	
	# Create systemd service
	@echo '[Unit]' > $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'Description=littleblog - Reverse Proxy with ACME' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'After=network.target' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo '' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo '[Service]' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'Type=simple' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'User=root' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'WorkingDirectory=/etc/littleblog' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'ExecStart=/usr/local/bin/littleblog -config /etc/littleblog/littleblog.yaml' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'Restart=always' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'RestartSec=5' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'StandardOutput=journal' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'StandardError=journal' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo '' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo '[Install]' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	@echo 'WantedBy=multi-user.target' >> $(DEB_DIR)/etc/systemd/system/littleblog.service
	
	# Create control file
	@echo 'Package: $(BINARY_NAME)' > $(DEB_DIR)/DEBIAN/control
	@echo 'Version: $(DEB_VERSION)' >> $(DEB_DIR)/DEBIAN/control
	@echo 'Section: web' >> $(DEB_DIR)/DEBIAN/control
	@echo 'Priority: optional' >> $(DEB_DIR)/DEBIAN/control
	@echo 'Architecture: $(DEB_ARCH)' >> $(DEB_DIR)/DEBIAN/control
	@echo 'Maintainer: Your Name <your.email@example.com>' >> $(DEB_DIR)/DEBIAN/control
	@echo 'Description: Reverse Proxy with automatic ACME/Let'\''s Encrypt support' >> $(DEB_DIR)/DEBIAN/control
	@echo ' A lightweight reverse proxy with automatic SSL certificate management' >> $(DEB_DIR)/DEBIAN/control
	@echo ' using ACME protocol and Let'\''s Encrypt.' >> $(DEB_DIR)/DEBIAN/control
	
	# Create postinst script
	@echo '#!/bin/bash' > $(DEB_DIR)/DEBIAN/postinst
	@echo 'set -e' >> $(DEB_DIR)/DEBIAN/postinst
	@echo 'systemctl daemon-reload' >> $(DEB_DIR)/DEBIAN/postinst
	@echo 'echo "✅ littleblog installed successfully"' >> $(DEB_DIR)/DEBIAN/postinst
	@echo 'echo "📝 Edit /etc/littleblog/littleblog.yaml.example and rename it to littleblog.yaml"' >> $(DEB_DIR)/DEBIAN/postinst
	@echo 'echo "🚀 Then run: systemctl enable littleblog && systemctl start littleblog"' >> $(DEB_DIR)/DEBIAN/postinst
	@chmod +x $(DEB_DIR)/DEBIAN/postinst
	
	# Create prerm script
	@echo '#!/bin/bash' > $(DEB_DIR)/DEBIAN/prerm
	@echo 'set -e' >> $(DEB_DIR)/DEBIAN/prerm
	@echo 'systemctl stop littleblog 2>/dev/null || true' >> $(DEB_DIR)/DEBIAN/prerm
	@echo 'systemctl disable littleblog 2>/dev/null || true' >> $(DEB_DIR)/DEBIAN/prerm
	@chmod +x $(DEB_DIR)/DEBIAN/prerm
	
	# Copy documentation if exists
	@if [ -f "README.md" ]; then \
		cp README.md $(DEB_DIR)/usr/share/doc/littleblog/; \
	fi
	
	# Build the package
	@dpkg-deb --build $(DEB_DIR)
	@mv $(BUILD_DIR)/debian/$(DEB_NAME).deb $(BUILD_DIR)/
	@echo "✅ Debian package created: $(BUILD_DIR)/$(DEB_NAME).deb"
	@echo ""
	@echo "📦 Install with: sudo dpkg -i $(BUILD_DIR)/$(DEB_NAME).deb"
	@echo "🗑️  Remove with: sudo apt remove $(BINARY_NAME)"

# Clean debian build artifacts
deb-clean:
	@echo "🧹 Cleaning debian build artifacts..."
	@rm -rf $(BUILD_DIR)/debian
	@rm -f $(BUILD_DIR)/*.deb
	@echo "✅ Debian artifacts cleaned"

# Check system requirements
check:
	@echo "🔍 Checking system requirements..."
	@echo -n "Go version: "; $(GOCMD) version 2>/dev/null || echo "❌ Go not installed"
	@echo -n "Git version: "; git --version 2>/dev/null || echo "⚠️ Git not installed (optional)"
	@echo -n "Port 80 available: "; sudo netstat -tlnp | grep :80 > /dev/null && echo "❌ Port 80 in use" || echo "✅ Available"
	@echo -n "Port 443 available: "; sudo netstat -tlnp | grep :443 > /dev/null && echo "❌ Port 443 in use" || echo "✅ Available"
	@echo -n "Root privileges: "; [ $$(id -u) -eq 0 ] && echo "✅ Running as root" || echo "⚠️ Not running as root (needed for ports 80/443)"
	@echo -n "dpkg-deb: "; command -v dpkg-deb >/dev/null 2>&1 && echo "✅ Available" || echo "⚠️ Not found (needed for .deb creation)"

# Show version information
version:
	@echo "Version: $(VERSION)"
	@$(GOBUILD) $(LDFLAGS) -o /tmp/version-check . && /tmp/version-check -version 2>/dev/null || echo "Build required"

# Show help
help:
	@echo "🚀 littleblog Makefile Commands"
	@echo ""
	@echo "📦 Setup & Dependencies:"
	@echo "  make deps           - Install dependencies"
	@echo ""
	@echo "🔨 Build Commands:"
	@echo "  make build          - Build the binary"
	@echo "  make deb            - Create Debian package (.deb) for linux/amd64"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make deb-clean      - Clean debian build artifacts"
	@echo ""
	@echo "🏃 Run Commands:"
	@echo "  make run            - Build and run with littleblog.yaml"
	@echo "  make example        - Create example configuration"
	@echo ""
	@echo "🔧 Utilities:"
	@echo "  make test           - Run unit tests with coverage"
	@echo "  make test-all       - Run unit + integration tests"
	@echo "  make test-suite     - Run comprehensive test suite"
	@echo "  make test-ci        - Run CI test pipeline"
	@echo "  make test-bench     - Run benchmarks"
	@echo "  make test-security  - Run security tests"
	@echo "  make lint           - Run lint checks"
	@echo "  make coverage       - Generate HTML coverage report"
	@echo "  make check          - Check system requirements"
	@echo "  make version        - Show version info"
	@echo "  make help           - Show this help"