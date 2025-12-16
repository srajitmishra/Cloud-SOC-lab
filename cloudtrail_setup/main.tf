# main.tf

################################################################################
# 1. CloudTrail S3 Bucket and Policy
################################################################################

# Create the S3 bucket for storing CloudTrail logs.
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = var.s3_bucket_name

  # Enable server-side encryption (SSE-S3) for logs at rest
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  # Block public access to the bucket (essential security practice)
  tags = {
    Name = "${var.trail_name}-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_bucket_access_block" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# The bucket policy allows the CloudTrail service to write logs.
data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AllowCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
      "s3:GetObject",
    ]

    resources = [
      "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
      "${aws_s3_bucket.cloudtrail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}",
    ]
  }

  statement {
    sid    = "AllowCloudTrailServiceGet"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      aws_s3_bucket.cloudtrail_bucket.arn,
    ]
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

################################################################################
# 2. AWS CloudTrail Configuration
################################################################################

# Required data source for getting the current AWS Account ID
data "aws_caller_identity" "current" {}

# Main CloudTrail resource
resource "aws_cloudtrail" "security_trail" {
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id

  # CRUCIAL SECURITY SETTINGS
  # 1. Enable logging globally (Multi-Region Trail)
  is_multi_region_trail         = true
  # 2. Include global services events (ESSENTIAL for IAM/Security Audit Logs)
  include_global_service_events = true
  # 3. Enable log file integrity validation (security best practice)
  enable_log_file_validation    = true

  # 4. Management Event Selector (for IAM, EC2, VPC, etc. control plane logs)
  # Logs ALL events (Read and Write), which includes all IAM and console actions.
  management_event_selector {
    read_write_type             = "All"
    include_management_events   = true
    # Exclude any events if necessary, but for a security audit, 'All' is best.
  }

  # 5. Data Event Selector (for S3 and other data plane changes)
  # This records S3 object level actions (e.g., PutObject, DeleteObject), 
  # which covers 'S3 bucket changes' and is security-crucial.
  event_selector {
    read_write_type = "All"
    # This selector must *not* include management events
    include_management_events = false

    data_resource {
      type = "AWS::S3::Object"
      # Target ALL S3 buckets in the account
      values = ["arn:aws:s3:::"] 
    }
  }

  tags = {
    Name = var.trail_name
    Environment = "Audit"
  }
}