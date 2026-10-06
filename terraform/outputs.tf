# terraform/outputs.tf

output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.application_logs.id
}

output "ec2_instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.application_server.id
}
