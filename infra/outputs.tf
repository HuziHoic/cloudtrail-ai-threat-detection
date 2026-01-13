output "sns_topic_arn" {
  value = aws_sns_topic.cloudtrail_alerts.arn
}
