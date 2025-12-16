# main.tf

################################################################################
# 1. AWS Identity & Data Sources
################################################################################

data "aws_caller_identity" "current" {}

################################################################################
# 2. S3 Bucket for CloudTrail Logs
################################################################################

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = var.s3_bucket_name
  force_destroy = true

  tags = {
    Name        = "${var.trail_name}-logs"
    Environment = "Audit"
  }
}

# SEPARATE RESOURCE: Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_encryption" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# SEPARATE RESOURCE: Public Access Block
resource "aws_s3_bucket_public_access_block" "cloudtrail_bucket_access_block" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SEPARATE RESOURCE: Bucket Policy
resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AllowCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "AllowCloudTrailCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_bucket.arn]
  }
}

################################################################################
# 3. AWS CloudTrail Configuration
################################################################################

resource "aws_cloudtrail" "security_trail" {
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true # Required for IAM auditing
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # Capture all Management Events (IAM, Console Login, Security Group changes)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  # Capture all S3 Data Events (Object uploads, deletions, etc.)
  event_selector {
    read_write_type           = "All"
    include_management_events = false

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  tags = {
    Name        = var.trail_name
    Environment = "Audit"
  }

  # Ensure the bucket and policy are ready before the trail starts
  depends_on = [
    aws_s3_bucket_policy.cloudtrail_bucket_policy,
    aws_s3_bucket_public_access_block.cloudtrail_bucket_access_block
  ]
}
