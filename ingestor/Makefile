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
#
# DESTRUCTIVE over a pre-1.0 stack: the 1.0 tables use clean names
# (trailtool-sessions, trailtool-people, …), so this deploy DELETES the old
# *-aggregated tables and all their data. No migration — history rebuilds from
# CloudTrail going forward.
deploy: build validate
	@echo "Deploying ingestor..."
	@echo "NOTE: deploying over a pre-1.0 stack deletes the *-aggregated tables and their data."
	@sam build
	@sam deploy --no-confirm-changeset --no-fail-on-empty-changeset

# Build and deploy sandbox stack (all-in-one: CloudTrail + S3 + Lambda + DynamoDB)
# Unsets any ambient AWS credential env vars so the sandbox-admin profile is used.
# Same pre-1.0 caveat as `deploy`: old *-aggregated tables and data are deleted.
deploy-sandbox: build
	@echo "Deploying sandbox ingestor stack..."
	@echo "NOTE: deploying over a pre-1.0 stack deletes the *-aggregated tables and their data."
	@env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
		AWS_PROFILE=sandbox-admin sam deploy \
		--template-file template-sandbox.yaml \
		--stack-name trailtool-ingestor \
		--region us-east-1 \
		--capabilities CAPABILITY_NAMED_IAM \
		--no-confirm-changeset \
		--no-fail-on-empty-changeset \
		--resolve-s3 \
		--parameter-overrides TrailName=trailtool-trail
	@echo "Sandbox deploy complete!"

# View logs
logs:
	@echo "Tailing logs for CloudTrail ingestor..."
	@sam logs --tail

# View sandbox Lambda logs
logs-sandbox:
	@echo "Tailing logs for sandbox CloudTrail ingestor..."
	@sam logs --stack-name trailtool-ingestor --region us-east-1 --tail
