# outputs.tf

output "cloudtrail_arn" {
  description = "The Amazon Resource Name (ARN) of the created CloudTrail."
  value       = aws_cloudtrail.security_trail.arn
}

output "s3_bucket_name" {
  description = "The name of the S3 bucket where CloudTrail logs are stored."
  value       = aws_s3_bucket.cloudtrail_bucket.id
}