import os
import json
import boto3

SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")

sns = boto3.client("sns")

def send_sns_alert(alert: dict):
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[{alert['what']['severity']}] CloudTrail Alert",
        Message=json.dumps(alert, indent=2)
    )
