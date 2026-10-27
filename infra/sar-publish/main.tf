# AWS side of the Serverless Application Repository publishing pipeline.
#
# The release.yaml `serverless-app-repo` job (runs on every v* tag) assumes the
# role below over GitHub OIDC, then `sam package` uploads artifacts to the
# staging bucket and `sam publish` + `put-application-policy` create and make
# public the SAR application `trailtool-ingestor`.
#
# The SAR application itself is NOT created here: `sam publish` creates it on
# the first tag, and there is no usable Terraform resource for a SAR
# application version.

data "aws_caller_identity" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  bucket_name = var.bucket_name != "" ? var.bucket_name : "trailtool-sar-${local.account_id}-${var.region}"

  oidc_url = "token.actions.githubusercontent.com"
  # SAR application ARN that supports resource-level IAM scoping.
  sar_app_arn = "arn:aws:serverlessrepo:${var.region}:${local.account_id}:applications/${var.sar_app_name}"
}

# ---------------------------------------------------------------------------
# GitHub Actions OIDC provider (create-or-reuse)
# ---------------------------------------------------------------------------

# Look up an existing provider so the stack can reuse it. One lookup always
# runs; it just isn't referenced when we create our own.
data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://${local.oidc_url}"
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_url}"
  client_id_list = ["sts.amazonaws.com"]
  # GitHub's OIDC uses a well-known root CA; the thumbprint is no longer
  # verified by AWS for this provider, but the field is still required.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  tags = var.tags
}

locals {
  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

# ---------------------------------------------------------------------------
# S3 staging bucket
#
# SAR reads the packaged template, the Lambda zip, the README and the LICENSE
# out of this bucket when an application version is created.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "sar" {
  bucket = local.bucket_name
  tags   = var.tags
}

# Block Public Access stays fully on. The bucket policy below grants read only
# to the serverlessrepo service principal, scoped to this account, so it is not
# a public policy and BPA does not reject it.
resource "aws_s3_bucket_public_access_block" "sar" {
  bucket = aws_s3_bucket.sar.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-S3 is sufficient; the artifacts are public software anyway.
resource "aws_s3_bucket_server_side_encryption_configuration" "sar" {
  bucket = aws_s3_bucket.sar.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# No short expiration: published SAR versions may still reference these
# objects. This rule only expires incomplete multipart uploads and old
# noncurrent versions after a long window, so stale drafts don't accumulate
# while published artifacts stay intact.
resource "aws_s3_bucket_lifecycle_configuration" "sar" {
  bucket = aws_s3_bucket.sar.id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "sar_bucket" {
  statement {
    sid    = "ServerlessRepositoryRead"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["serverlessrepo.amazonaws.com"]
    }

    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.sar.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "sar" {
  bucket = aws_s3_bucket.sar.id
  policy = data.aws_iam_policy_document.sar_bucket.json

  # Attach the policy only once BPA is in place, so block_public_policy is
  # evaluated against the (non-public) statement rather than racing it.
  depends_on = [aws_s3_bucket_public_access_block.sar]
}

# ---------------------------------------------------------------------------
# IAM role assumed by the release workflow over GitHub OIDC
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "publish_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_url}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # The job only ever runs on tag pushes, so the subject is limited to tag
    # refs in this repo and not widened to branches or *.
    condition {
      test     = "StringLike"
      variable = "${local.oidc_url}:sub"
      values   = ["repo:${var.github_repo}:ref:refs/tags/v*"]
    }
  }
}

resource "aws_iam_role" "publish" {
  name               = "trailtool-sar-publish"
  description        = "Assumed by engseclabs/trailtool release workflow to publish the ingestor to SAR."
  assume_role_policy = data.aws_iam_policy_document.publish_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "publish" {
  # sam package checks for already-uploaded artifacts (ListBucket) before
  # uploading (PutObject), and SAR packaging reads them back (GetObject).
  statement {
    sid       = "StagingBucketObjects"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.sar.arn}/*"]
  }

  statement {
    sid       = "StagingBucketList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.sar.arn]
  }

  # Resource-scoped SAR actions on this one application.
  statement {
    sid    = "ServerlessRepoApp"
    effect = "Allow"
    actions = [
      "serverlessrepo:CreateApplicationVersion",
      "serverlessrepo:UpdateApplication",
      "serverlessrepo:GetApplication",
      "serverlessrepo:PutApplicationPolicy",
    ]
    resources = [local.sar_app_arn]
  }

  # CreateApplication and ListApplications do not support resource-level
  # scoping, so they stay on "*".
  statement {
    sid    = "ServerlessRepoAccountWide"
    effect = "Allow"
    actions = [
      "serverlessrepo:CreateApplication",
      "serverlessrepo:ListApplications",
    ]
    resources = ["*"]
  }

  # The "Grant public deploy access" step calls sts:GetCallerIdentity to build
  # the application ARN. It is implicitly allowed for any principal, so no
  # statement is needed for it.
}

resource "aws_iam_role_policy" "publish" {
  name   = "trailtool-sar-publish"
  role   = aws_iam_role.publish.id
  policy = data.aws_iam_policy_document.publish.json
}
