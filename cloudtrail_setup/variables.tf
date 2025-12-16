# variables.tf

variable "aws_region" {
  description = "The AWS region to deploy the resources in (e.g., us-east-1). CloudTrail will still be global/multi-region."
  type        = string
  default     = "us-east-1"
}

variable "trail_name" {
  description = "Name for the CloudTrail trail."
  type        = string
  default     = "security-audit-trail"
}

variable "s3_bucket_name" {
  description = "A globally unique name for the S3 bucket to store CloudTrail logs."
  type        = string
  # IMPORTANT: You must change the default to a unique name.
  # For example: "my-company-cloudtrail-logs-12345"
  default     = "cloudtrail-logs-soclab" 
}
