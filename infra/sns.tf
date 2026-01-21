resource "aws_sns_topic" "cloudtrail_alerts" {
  name = "cloudtrail-ai-alerts"
}

# OPTIONAL: email subscription for testing
resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.cloudtrail_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
