output "vpc_id" {
  description = "ID of the created VPC"
  value       = aws_vpc.this.id
}

output "alb_dns_name" {
  description = "Public DNS name of the load balancer"
  value       = aws_lb.app.dns_name
}

output "asg_name" {
  description = "Name of the Auto Scaling Group"
  value       = aws_autoscaling_group.app.name
}

output "db_instance_endpoint" {
  description = "Private RDS connection endpoint"
  value       = aws_db_instance.this.endpoint
}

output "secrets_manager_secret_arn" {
  description = "ARN of the database credentials secret"
  value       = aws_secretsmanager_secret.db_credentials.arn
}

output "sns_topic_arn" {
  description = "ARN of the application CloudWatch alerts SNS topic"
  value       = aws_sns_topic.alerts.arn
}

output "private_app_subnet_ids" {
  description = "Private application subnet IDs for the AI incident agent"
  value       = aws_subnet.private_app[*].id
}

output "private_app_route_table_ids" {
  description = "Private application route table IDs for AWS VPC endpoints"
  value       = [aws_route_table.private_app.id]
}

output "app_target_group_arn" {
  description = "Application ALB target group ARN for incident diagnostics"
  value       = aws_lb_target_group.app.arn
}