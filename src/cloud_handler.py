"""
Cloud Anomaly Detection Handler
Triggered every 5 minutes by EventBridge
"""

import json
import boto3
from datetime import datetime
from src.models.cloud.cloudtrail_analyzer import CloudTrailAnalyzer
from src.response.auto_responder import AutoResponder

# Initialize
analyzer = CloudTrailAnalyzer()
responder = AutoResponder()
dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
table = dynamodb.Table('asectds-cloud-anomalies')


def lambda_handler(event, context):
    print("☁️ Cloud anomaly scan started")
    print(f"Scan time: {datetime.utcnow().isoformat()} UTC")

    try:
        # Scan last 6 minutes (slight overlap to avoid missing events)
        suspicious_events = analyzer.scan_recent_events(minutes=6)

        if not suspicious_events:
            print("✅ No suspicious activity detected")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'No anomalies detected'})
            }

        print(f"⚠️ Found {len(suspicious_events)} suspicious events")

        for event_data in suspicious_events:
            print(f"🚨 Anomaly: {event_data['event_name']} "
                  f"by {event_data['username']} "
                  f"(risk: {event_data['risk_score']}) "
                  f"from {event_data['source_ip']}")
            print(f"   Severity: {event_data['severity']}")
            print(f"   Flags: {event_data['flags']}")
            print(f"   MFA: {event_data['mfa_authenticated']}")

            # Write to DynamoDB
            try:
                table.put_item(Item={
                    'event_id': event_data['event_id'],
                    'event_name': event_data['event_name'],
                    'username': event_data['username'],
                    'source_ip': event_data['source_ip'],
                    'region': event_data['region'],
                    'event_time': event_data['event_time'],
                    'risk_score': str(event_data['risk_score']),
                    'severity': event_data['severity'],
                    'threat_type': event_data['threat_type'],
                    'flags': event_data['flags'],
                    'mfa_authenticated': event_data['mfa_authenticated'],
                    'timestamp': datetime.utcnow().isoformat(),
                    'status': 'detected'
                })
                print(f"📊 Written to DynamoDB: {event_data['event_id']}")
            except Exception as e:
                print(f"❌ DynamoDB write failed: {str(e)}")

            # Trigger auto-response for high risk
            if event_data['risk_score'] >= 70:
                try:
                    responder.respond_to_threat(event_data)
                except Exception as e:
                    print(f"❌ Auto-response failed: {str(e)}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f"Processed {len(suspicious_events)} anomalies",
                'count': len(suspicious_events)
            })
        }

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }