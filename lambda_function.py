import json
import boto3
import os
from datetime import datetime


def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event, indent=2)}")

    # Initialize AWS clients
    iam = boto3.client("iam")
    sns = boto3.client("sns")
    sts = boto3.client("sts")

    # Extract CloudTrail event details from EventBridge
    detail = event.get("detail", {})
    event_name = detail.get("eventName")
    user_identity = detail.get("userIdentity", {})
    source_ip = detail.get("sourceIPAddress", "Unknown")
    event_time = detail.get("eventTime", "Unknown")
    aws_region = detail.get("awsRegion", "Unknown")

    # Get the created user name from the response elements
    response_elements = detail.get("responseElements", {})
    created_user = response_elements.get("user", {}).get("userName", "Unknown")

    # Only respond to CreateUser events
    if event_name != "CreateUser":
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Event ignored (not CreateUser)",
                    "event_processed": event_name,
                }
            ),
        }

    print(f"Detected CreateUser event for user: {created_user}")

    account_id = sts.get_caller_identity()["Account"]
    quarantine_policy_arn = f"arn:aws:iam::{account_id}:policy/AutomatedSecurityQuarantine"

    response_action = ""
    try:
        # Attach the pre-configured quarantine policy (deny-all)
        iam.attach_user_policy(UserName=created_user, PolicyArn=quarantine_policy_arn)

        # Tag the user as quarantined
        iam.tag_user(
            UserName=created_user,
            Tags=[
                {"Key": "SecurityStatus", "Value": "Quarantined"},
                {
                    "Key": "QuarantineReason",
                    "Value": "Automated response to suspicious user creation",
                },
                {"Key": "QuarantineTime", "Value": datetime.utcnow().isoformat()},
            ],
        )

        response_action = f"User '{created_user}' has been automatically quarantined"
        print(response_action)

    except Exception as e:
        response_action = f"Failed to quarantine user '{created_user}': {str(e)}"
        print(response_action)

    # Send SNS notification
    alert_message = f"""
SECURITY ALERT: Suspicious IAM User Creation Detected

Event Details:
- Event: {event_name}
- New User: {created_user}
- Source IP: {source_ip}
- Time: {event_time}
- Region: {aws_region}
- User Identity: {user_identity.get('type', 'Unknown')} ({user_identity.get('userName', 'Unknown')})

Automated Response:
{response_action}

Next Steps:
1. Investigate the source IP address and user identity
2. Verify if this user creation was authorized
3. If legitimate, remove the quarantine policy from the user
4. If malicious, consider additional containment actions
""".strip()

    try:
        sns.publish(
            TopicArn=os.environ["SNS_TOPIC_ARN"],
            Subject=f"Security Alert: Suspicious User Creation - {created_user}",
            Message=alert_message,
        )
        print("SNS notification sent successfully")
    except Exception as e:
        print(f"Failed to send SNS notification: {str(e)}")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Security response completed",
                "event_processed": event_name,
                "user_affected": created_user,
            }
        ),
    }
