get-deps:
	@command -v go >/dev/null 2>&1 || { \
		echo "Go is not installed. Please install Go first."; \
		exit 1; \
	}

	@echo "Installing sqlc..."
	@go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest

	@echo "Installing goose..."
	@go install github.com/pressly/goose/v3/cmd/goose@latest

	@echo "All tools installed successfully."

generate: get-deps
	@echo "Generating sqlc code..."
	@sqlc generate
	@echo "Done generating sqlc code."

build-server: generate
	@GOOS=$$(go env GOOS); \
	GOARCH=$$(go env GOARCH); \
	echo "Building server for $$GOOS/$$GOARCH..."; \
	LDFLAGS=$$(go run buildscripts/gen_ldflags.go); \
	GOOS=$$GOOS GOARCH=$$GOARCH go build -ldflags="$$LDFLAGS" -o build/server ./cmd/server
	@echo "Done building server."

dev: build-server
	@echo "Running dev version of server..."
	@SHORTY_DEVELOPMENT=true ./build/server

build-token: generate
	@GOOS=$$(go env GOOS); \
	GOARCH=$$(go env GOARCH); \
	echo "Building token for $$GOOS/$$GOARCH..."; \
	GOOS=$$GOOS GOARCH=$$GOARCH go build -ldflags="-s -w" -o build/token ./cmd/token
	@echo "Done building token."

token: build-token
	@echo "Running token app for username 'thisisatest'"
	@SHORTY_DEVELOPMENT=true ./build/token --username thisisatest