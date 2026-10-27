.PHONY: build clean deploy check-org-config deploy-org deploy-forwarder deploy-org-all check-sar-config publish-sar sar-public sar-bucket-policy test test-v test-cover

# ---------------------------------------------------------------------------
# Cross-account (organization trail) deployment
#
# Two accounts: the ingestor runs in INGESTOR_PROFILE's account, the CloudTrail
# bucket is owned by BUCKET_PROFILE's account (a Control Tower log archive).
# Supply the bucket details on the command line, e.g.
#   make deploy-org-all INGESTOR_PROFILE=security BUCKET_PROFILE=logs \
#     TRAIL_BUCKET=example-cloudtrail-bucket BUCKET_ACCOUNT=000000000000
# ---------------------------------------------------------------------------
INGESTOR_PROFILE ?= audit
BUCKET_PROFILE   ?= log-archive
REGION           ?= us-east-1
TRAIL_BUCKET     ?=
BUCKET_ACCOUNT   ?=
STACK            ?= trailtool-ingestor

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

# Refuse to deploy when environment-specific values have not been supplied.
check-org-config:
	@test -n "$(TRAIL_BUCKET)" || { echo "ERROR: set TRAIL_BUCKET to the CloudTrail bucket name."; exit 1; }
	@test -n "$(BUCKET_ACCOUNT)" || { echo "ERROR: set BUCKET_ACCOUNT to the bucket owner's AWS account ID."; exit 1; }

# Deploy the ingestor against an organization trail whose bucket lives in
# another account. ManageBucketNotification=false because this account cannot
# touch the bucket's notification config; EventSourceAccount lets the bucket's
# account forward events onto this account's default bus.
# Same pre-1.0 caveat as `deploy`: old *-aggregated tables and data are deleted.
deploy-org: check-org-config build
	@echo "Deploying ingestor to $(INGESTOR_PROFILE) for bucket $(TRAIL_BUCKET) ($(BUCKET_ACCOUNT))..."
	@sam deploy \
		--template-file template.yaml \
		--stack-name $(STACK) \
		--region $(REGION) \
		--profile $(INGESTOR_PROFILE) \
		--capabilities CAPABILITY_NAMED_IAM \
		--resolve-s3 \
		--no-confirm-changeset \
		--no-fail-on-empty-changeset \
		--parameter-overrides \
			CloudTrailBucketName=$(TRAIL_BUCKET) \
			ManageBucketNotification=false \
			EventSourceAccount=$(BUCKET_ACCOUNT)
	@echo "Ingestor deploy complete!"

# Deploy the forwarding rule into the bucket-owning account. Verifies the bucket
# has EventBridge notifications enabled first: without them S3 emits nothing and
# the rule is inert. REGION must be the bucket's region.
deploy-forwarder: check-org-config
	@echo "Checking EventBridge notifications on $(TRAIL_BUCKET)..."
	@aws s3api get-bucket-notification-configuration \
		--bucket $(TRAIL_BUCKET) --profile $(BUCKET_PROFILE) --region $(REGION) \
		--output json | grep -q EventBridgeConfiguration || { \
		echo "ERROR: EventBridge notifications are not enabled on $(TRAIL_BUCKET)."; \
		echo "Merge EventBridgeConfiguration into its notification config (see ingestor/README.md)."; \
		exit 1; }
	@echo "Deploying forwarder to $(BUCKET_PROFILE)..."
	@aws cloudformation deploy \
		--template-file template-forwarder.yaml \
		--stack-name trailtool-cloudtrail-forwarder \
		--region $(REGION) \
		--profile $(BUCKET_PROFILE) \
		--capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
		--no-fail-on-empty-changeset \
		--parameter-overrides \
			CloudTrailBucketName=$(TRAIL_BUCKET) \
			IngestorAccountId=$$(aws sts get-caller-identity --profile $(INGESTOR_PROFILE) --query Account --output text) \
			IngestorRegion=$(REGION)
	@echo "Forwarder deploy complete!"

# Full cross-account setup. Ingestor first: it creates the event bus policy the
# forwarder's rule needs before that rule can deliver anything.
deploy-org-all: deploy-org deploy-forwarder
	@echo "Cross-account deploy complete. Backfill history with 'trailtool replay'."

# View logs
logs:
	@echo "Tailing logs for CloudTrail ingestor..."
	@sam logs --tail

# View sandbox Lambda logs
logs-sandbox:
	@echo "Tailing logs for sandbox CloudTrail ingestor..."
	@sam logs --stack-name trailtool-ingestor --region us-east-1 --tail

# ---------------------------------------------------------------------------
# AWS Serverless Application Repository
#
# `make publish-sar sar-public VERSION=1.2.0 SAR_BUCKET=…` does by hand what the
# release workflow does on a tag. SAR versions are immutable, so versions that
# already exist are skipped and a partly failed run can be re-run.
# SAR_BUCKET must be readable by serverlessrepo.amazonaws.com — `make
# sar-bucket-policy` prints the statement.
# ---------------------------------------------------------------------------
SAR_BUCKET ?=
SAR_REGION ?= us-east-1
SAR_APPS   := template-forwarder.yaml:trailtool-cloudtrail-forwarder template.yaml:trailtool-ingestor
VERSION    ?=

# Refuse to publish when the version or the staging bucket has not been supplied.
check-sar-config:
	@test -n "$(VERSION)" || { echo "ERROR: set VERSION to the semantic version to publish, e.g. VERSION=1.2.0"; exit 1; }
	@test -n "$(SAR_BUCKET)" || { echo "ERROR: set SAR_BUCKET to an S3 bucket readable by serverlessrepo.amazonaws.com (see 'make sar-bucket-policy')."; exit 1; }

publish-sar: check-sar-config build
	@set -e; account=$$(aws sts get-caller-identity --query Account --output text); \
	for entry in $(SAR_APPS); do \
		template=$${entry%%:*}; app=$${entry#*:}; \
		if aws serverlessrepo list-application-versions --region $(SAR_REGION) \
			--application-id arn:aws:serverlessrepo:$(SAR_REGION):$$account:applications/$$app \
			--query 'Versions[].SemanticVersion' --output text 2>/dev/null | tr '\t' '\n' | grep -qFx '$(VERSION)'; then \
			echo "$$app $(VERSION) is already published, skipping."; continue; \
		fi; \
		echo "Publishing $$app $(VERSION)..."; \
		sam package \
			--template-file $$template \
			--s3-bucket $(SAR_BUCKET) \
			--s3-prefix $$app/$(VERSION) \
			--region $(SAR_REGION) \
			--output-template-file bin/packaged-$$app.yaml; \
		sam publish \
			--template bin/packaged-$$app.yaml \
			--semantic-version $(VERSION) \
			--region $(SAR_REGION); \
	done

# Principals='*' is what makes an application publicly listed.
sar-public:
	@set -e; account=$$(aws sts get-caller-identity --query Account --output text); \
	for entry in $(SAR_APPS); do \
		app_id=arn:aws:serverlessrepo:$(SAR_REGION):$$account:applications/$${entry#*:}; \
		aws serverlessrepo put-application-policy --region $(SAR_REGION) \
			--application-id $$app_id --statements Principals='*',Actions=Deploy; \
		echo "Published $$app_id"; \
	done

# Not applied automatically: put-bucket-policy REPLACES the bucket's whole
# policy, so merge this statement into the existing one.
sar-bucket-policy:
	@test -n "$(SAR_BUCKET)" || { echo "ERROR: set SAR_BUCKET to the bucket holding the packaged artifacts."; exit 1; }
	@echo 'Add this statement to the bucket policy of $(SAR_BUCKET)'
	@echo '(ACCOUNT_ID is the account that publishes the application):'
	@echo ''
	@echo '{'
	@echo '  "Version": "2012-10-17",'
	@echo '  "Statement": [{'
	@echo '    "Sid": "ServerlessRepositoryRead",'
	@echo '    "Effect": "Allow",'
	@echo '    "Principal": {"Service": "serverlessrepo.amazonaws.com"},'
	@echo '    "Action": "s3:GetObject",'
	@echo '    "Resource": "arn:aws:s3:::$(SAR_BUCKET)/*",'
	@echo '    "Condition": {"StringEquals": {"aws:SourceAccount": "ACCOUNT_ID"}}'
	@echo '  }]'
	@echo '}'
