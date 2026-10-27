variable "region" {
  description = "Region for the SAR application and its staging bucket. The CLI/SAM job defaults SAR_REGION to us-east-1, so keep these aligned."
  type        = string
  default     = "us-east-1"
}

variable "github_repo" {
  description = "GitHub repository (owner/name) allowed to assume the publish role via OIDC."
  type        = string
  default     = "engseclabs/trailtool"
}

variable "sar_app_name" {
  description = "SAR application name. Must match SAR_APP_NAME in the release workflow (trailtool-ingestor)."
  type        = string
  default     = "trailtool-ingestor"
}

variable "bucket_name" {
  description = "Override for the staging bucket name. Empty uses trailtool-sar-<account>-<region>, matching the ingestor's trailtool-<purpose>-<account>-<region> convention."
  type        = string
  default     = ""
}

# An AWS account can hold only one IAM OIDC provider per URL. Set this to false
# when token.actions.githubusercontent.com already exists in the target account
# (for example a shared CI provider) so the stack reuses it instead of failing
# to create a duplicate.
variable "create_oidc_provider" {
  description = "Whether to create the GitHub Actions OIDC provider. Set false to reuse an existing one in the account."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "trailtool"
    Component = "sar-publish"
    ManagedBy = "terraform"
  }
}
