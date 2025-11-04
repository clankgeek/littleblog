# Variables
BINARY_NAME=littleblog
BUILD_DIR=build
BUILD_ID := $(shell date +%Y%m%d%H%M%S)
VERSION=$(shell grep  "const VERSION string = " main.go | egrep "[0-9\.]+" -o)
LDFLAGS=-ldflags "-X main.BuildID=${BUILD_ID} -s -w"
PLATFORMS=linux/386 linux/amd64 linux/arm linux/arm64 darwin/amd64 darwin/arm64 windows/386 windows/amd64

# Debian package variables
PKG_NAME=littleblog
PKG_VERSION=$(shell echo $(VERSION) | sed 's/^v//')
PKG_MAINTAINER=Clank <clank@ik.me>
PKG_DESCRIPTION=Un petit blog avec backend en golang
PKG_HOMEPAGE=https://github.com/clankgeek/littleblog
DEB_DIR=$(BUILD_DIR)/deb
DEB_PKG_DIR=$(DEB_DIR)/$(PKG_NAME)_$(PKG_VERSION)

# Go parameters
GOCMD=CGO_ENABLED=1 GOAMD64=v3 go
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
deb: deb-clean
	@echo "📦 Building Debian package..."
	@mkdir -p $(DEB_PKG_DIR)/DEBIAN
	@mkdir -p $(DEB_PKG_DIR)/usr/bin
	@mkdir -p $(DEB_PKG_DIR)/etc/littleblog
	@mkdir -p $(DEB_PKG_DIR)/etc/systemd/system
	@mkdir -p $(DEB_PKG_DIR)/var/lib/littleblog/static
	@mkdir -p $(DEB_PKG_DIR)/var/log/littleblog
	
	@echo "🔨 Building binary for linux/amd64..."
	@GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DEB_PKG_DIR)/usr/bin/$(BINARY_NAME) .
	
	@echo "📝 Creating control file..."
	@echo "Package: $(PKG_NAME)" > $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Version: $(PKG_VERSION)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Section: net" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Priority: optional" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Architecture: amd64" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Maintainer: $(PKG_MAINTAINER)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Description: $(PKG_DESCRIPTION)" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo " Un blog avec backend en golang" >> $(DEB_PKG_DIR)/DEBIAN/control
	@echo "Homepage: $(PKG_HOMEPAGE)" >> $(DEB_PKG_DIR)/DEBIAN/control
	
	@echo "📝 Creating postinst script..."
	@echo "#!/bin/bash" > $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "set -e" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "# Create littleblog user if it doesn't exist" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "if ! id -u littleblog > /dev/null 2>&1; then" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "    useradd --system --no-create-home --shell /bin/false littleblog" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "fi" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "# Set permissions" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chown -R littleblog:littleblog /ect/littleblog" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chown -R littleblog:littleblog /var/lib/littleblog" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chown -R littleblog:littleblog /var/log/littleblog" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chmod 750 /var/lib/littleblog -R" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "chmod 750 /var/log/littleblog -R" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "# Create example config if it doesn't exist" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "if [ ! -f /etc/littleblog/config.yaml ]; then" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "    /usr/bin/littleblog -example -config /etc/ > /dev/null 2>&1 || true" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "    chown littleblog:littleblog /etc/littleblog/config.yaml" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "fi" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "# Reload systemd" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "systemctl daemon-reload" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "echo '✅ littleblog installed successfully!'" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@echo "echo '📝 Edit /etc/littleblog/config.yaml and run: systemctl --now enable littleblog'" >> $(DEB_PKG_DIR)/DEBIAN/postinst
	@chmod 755 $(DEB_PKG_DIR)/DEBIAN/postinst
	
	@echo "📝 Creating prerm script..."
	@echo "#!/bin/bash" > $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "set -e" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "# Stop service if running" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "if systemctl is-active --quiet littleblog; then" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "    systemctl stop littleblog" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "fi" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "if systemctl is-enabled --quiet littleblog 2>/dev/null; then" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "    systemctl disable littleblog" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@echo "fi" >> $(DEB_PKG_DIR)/DEBIAN/prerm
	@chmod 755 $(DEB_PKG_DIR)/DEBIAN/prerm
	
	@echo "📝 Creating systemd service file..."
	@echo "[Unit]" > $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "Description=littleblog - un blog avec backend en golang" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "After=network.target" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "[Service]" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "Type=simple" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "User=littleblog" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "Group=littleblog" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "ExecStart=/usr/bin/littleblog -config /etc/littleblog/config.yaml" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "Restart=on-failure" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "RestartSec=5s" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "# Security hardening" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "NoNewPrivileges=true" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "PrivateTmp=true" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "ProtectSystem=strict" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "ProtectHome=false" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "ReadWritePaths=/var/lib/littleblog /var/log/littleblog /etc/littleblog" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "# Give permissions to bind to ports 80 and 443" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "AmbientCapabilities=CAP_NET_BIND_SERVICE" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "[Install]" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	@echo "WantedBy=multi-user.target" >> $(DEB_PKG_DIR)/etc/systemd/system/littleblog.service
	
	@echo "🔨 Building package..."
	@dpkg-deb --build $(DEB_PKG_DIR)
	@mv $(DEB_PKG_DIR).deb $(BUILD_DIR)/$(PKG_NAME)_$(PKG_VERSION)_amd64.deb
	@rm -rf $(DEB_DIR)
	@echo "✅ Debian package created: $(BUILD_DIR)/$(PKG_NAME)_$(PKG_VERSION)_amd64.deb"
	@echo ""
	@echo "📦 Install with: sudo dpkg -i $(BUILD_DIR)/$(PKG_NAME)_$(PKG_VERSION)_amd64.deb"

# Clean debian build artifacts
deb-clean:
	@rm -rf $(DEB_DIR)
	@rm -f $(BUILD_DIR)/*.deb

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