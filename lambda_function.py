import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')

def lambda_handler(event, context):
    detail = event.get('detail', {})
    request_params = detail.get('requestParameters') or {}
    bucket_name = request_params.get('bucketName')
    
    # Extract forensic context for SOC L1 investigation
    event_name = detail.get('eventName', 'UnknownEvent')
    source_ip = detail.get('sourceIPAddress', 'UnknownIP')
    user_arn = detail.get('userIdentity', {}).get('arn', 'UnknownIdentity')
    event_time = detail.get('eventTime', 'UnknownTime')

    if not bucket_name:
        logger.error("No bucketName found in CloudTrail event payload. Aborting.")
        return {"statusCode": 400, "body": "Missing bucketName"}

    logger.warning(
        f"SECURITY ALERT: {event_name} detected on bucket '{bucket_name}' "
        f"by '{user_arn}' from IP '{source_ip}' at {event_time}."
    )

    try:
        # Enforce S3 Block Public Access settings
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        logger.info(f"REMEDIATION SUCCESS: Block Public Access enforced on '{bucket_name}'.")
        return {
            "statusCode": 200,
            "body": json.dumps(f"Remediated public access on {bucket_name}")
        }
    except Exception as e:
        logger.error(f"REMEDIATION FAILED for '{bucket_name}': {str(e)}")
        raise e
