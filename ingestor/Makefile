.PHONY: build clean deploy test test-v test-cover

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Run tests with verbose output
test-v:
	@echo "Running tests (verbose)..."
	@go test -v ./...

# Run tests with coverage
test-cover:
	@echo "Running tests with coverage..."
	@go test -cover ./...

# Build Lambda function
build: clean
	@echo "Building CloudTrail ingestor Lambda..."
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/bootstrap .
	cd bin && zip bootstrap.zip bootstrap && rm bootstrap
	@echo "Ingestor build complete!"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/

# Validate SAM template
validate:
	@echo "Validating SAM template..."
	@sam validate

# Build and deploy to AWS
deploy: build validate
	@echo "Deploying ingestor..."
	@sam build
	@sam deploy --no-confirm-changeset --no-fail-on-empty-changeset

# View logs
logs:
	@echo "Tailing logs for CloudTrail ingestor..."
	@sam logs --tail
