.PHONY: build build-cli test vet run clean install-tools check-tools migrate migrate-force

# Build both binaries (MCP server + CLI)
build:
	go build -o bin/hack-ai-v2 ./cmd/server/...
	go build -o bin/hack-ai ./cmd/cli/...

# Migrate the v1 mongo-export into the v2 cluster as *_v1 collections + seed
migrate:
	go run ./cmd/migrate

# Same, but drop and re-import existing *_v1 collections
migrate-force:
	go run ./cmd/migrate -force

# Build only the CLI wrapper
build-cli:
	go build -o bin/hack-ai ./cmd/cli/...

# Run go vet on all packages
vet:
	go vet ./...

# Run tests
test:
	go test ./... -v

# Run tests with coverage
cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

# Build and run the MCP server
run: build
	./bin/hack-ai-v2

# Install all 154 security tools
install-tools:
	./scripts/install_tools.sh --all

# Health check all tools
check-tools:
	./scripts/check_tools.sh

# Check specific category
check-recon:
	./scripts/check_tools.sh --category recon

check-web:
	./scripts/check_tools.sh --category web

check-mobile:
	./scripts/check_tools.sh --category mobile

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Full CI: vet + test + build
ci: vet test build
	@echo "✅ All checks passed"

# Install CLI to /usr/local/bin (symlink)
install: build-cli
	@ln -sf $(PWD)/bin/hack-ai /usr/local/bin/hack-ai
	@echo "✅ hack-ai installed to /usr/local/bin/hack-ai"

