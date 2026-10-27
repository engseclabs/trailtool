# Paste these into the GitHub repo variables (Settings -> Secrets and variables
# -> Actions -> Variables) that release.yaml's serverless-app-repo job reads.

output "sar_s3_bucket" {
  description = "Staging bucket name. Set as the GitHub repo variable SAR_S3_BUCKET."
  value       = aws_s3_bucket.sar.bucket
}

output "sar_publish_role_arn" {
  description = "Publish role ARN. Set as the GitHub repo variable SAR_PUBLISH_ROLE_ARN."
  value       = aws_iam_role.publish.arn
}

output "sar_region" {
  description = "Region of the bucket and SAR application. Matches SAR_REGION (defaults to us-east-1 in the workflow)."
  value       = var.region
}
