"""
CloudTrail Anomaly Detector
Scans recent AWS API calls for suspicious activity
"""

import boto3
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List


class CloudTrailAnalyzer:
    """
    Analyzes CloudTrail events for suspicious activity
    """

    def __init__(self):
        # Track already processed events to avoid duplicates
        self.processed_event_ids = set()

        # High risk events — immediate alert (write operations)
        self.critical_events = [
            'DeleteTrail',
            'StopLogging',
            'DeleteBucket',
            'PutBucketPolicy',
            'DeleteBucketPolicy',
            'CreateUser',
            'DeleteUser',
            'AttachUserPolicy',
            'PutUserPolicy',
            'CreateAccessKey',
            'DeleteAccessKey',
            'UpdateAccessKey',
            'AddUserToGroup',
            'AttachRolePolicy',
            'CreateLoginProfile',
            'UpdateLoginProfile',
            'PutUserPolicy',
            'CreateRole',
            'DeleteRole',
            'UpdateAssumeRolePolicy',
        ]

        # Medium risk events — write operations worth noting
        self.medium_events = [
            'ConsoleLogin',
            'UpdateTrail',
            'PutBucketAcl',
            'DeleteFunction',
            'UpdateFunctionCode',
            'UpdateFunctionConfiguration',
            'CreateStack',
            'DeleteStack',
            'RunInstances',
            'TerminateInstances',
            'AuthorizeSecurityGroupIngress',
            'RevokeSecurityGroupIngress',
            'CreateSecurityGroup',
            'DeleteSecurityGroup',
        ]

        # Read-only events — never alert on these
        # even if triggered by root
        self.readonly_events = [
            'DescribeAlarms',
            'ListManagedNotificationEvents',
            'DescribeInstances',
            'ListBuckets',
            'GetObject',
            'HeadObject',
            'ListObjects',
            'DescribeStacks',
            'ListFunctions',
            'GetFunction',
            'DescribeLogGroups',
            'DescribeLogStreams',
            'GetLogEvents',
            'ListTopics',
            'ListSubscriptions',
            'DescribeTrails',
            'GetTrailStatus',
            'LookupEvents',
            'DescribeTables',
            'ListTables',
            'Scan',
            'Query',
            'GetItem',
        ]

        # Whitelisted roles — ignore these
        self.whitelist = [
            'asectds-stack-ThreatDetectionFunctionRole',
            'asectds-cloudtrail-role',
            'asectds-stack-CloudAnomalyFunctionRole',
        ]

    def scan_recent_events(self, minutes: int = 5) -> List[Dict]:
        """
        Scan CloudTrail for suspicious events in the last N minutes.
        Scans both eu-north-1 and us-east-1 (IAM is global, logs to us-east-1)
        """
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=minutes)

        suspicious = []

        # Scan both regions — IAM events go to us-east-1
        regions = ['eu-north-1', 'us-east-1']

        for region in regions:
            try:
                client = boto3.client('cloudtrail', region_name=region)
                paginator = client.get_paginator('lookup_events')
                pages = paginator.paginate(
                    StartTime=start_time,
                    EndTime=end_time,
                    PaginationConfig={'MaxItems': 50}
                )

                for page in pages:
                    for event in page.get('Events', []):
                        analysis = self._analyze_event(event)
                        if analysis:
                            analysis['detected_in_region'] = region
                            suspicious.append(analysis)

            except Exception as e:
                print(f"CloudTrail scan error ({region}): {str(e)}")

        return suspicious

    def _analyze_event(self, event: Dict) -> Dict:
        """
        Analyze a single CloudTrail event for suspicious indicators
        """
        event_id = event.get('EventId', '')
        event_name = event.get('EventName', '')
        username = event.get('Username', 'Unknown')
        event_time = event.get('EventTime', '')

        # Skip already processed events (deduplication)
        if event_id in self.processed_event_ids:
            return None
        self.processed_event_ids.add(event_id)

        # Skip whitelisted roles
        for whitelisted in self.whitelist:
            if whitelisted in username:
                return None

        # Parse CloudTrail event details
        cloud_trail_event = {}
        raw = event.get('CloudTrailEvent', '{}')
        try:
            cloud_trail_event = json.loads(raw)
        except Exception:
            pass

        source_ip = cloud_trail_event.get('sourceIPAddress', 'Unknown')
        user_agent = cloud_trail_event.get('userAgent', '')
        error_code = cloud_trail_event.get('errorCode', '')
        region = cloud_trail_event.get('awsRegion', 'Unknown')
        read_only = cloud_trail_event.get('readOnly', False)

        mfa_authenticated = cloud_trail_event.get(
            'userIdentity', {}
        ).get(
            'sessionContext', {}
        ).get(
            'attributes', {}
        ).get('mfaAuthenticated', 'true')

        # Skip read-only events unless they are in critical_events
        if read_only and event_name not in self.critical_events:
            return None

        # Skip known safe read-only event names explicitly
        if event_name in self.readonly_events:
            return None

        # Determine risk level
        risk_score = 0
        severity = None
        flags = []

        if event_name in self.critical_events:
            risk_score = 90
            severity = 'CRITICAL'
            flags.append(f"Critical write event: {event_name}")

        elif event_name in self.medium_events:
            risk_score = 60
            severity = 'MEDIUM'
            flags.append(f"Notable event: {event_name}")

        elif 'root' in username.lower():
            # Root write activity not in known lists
            risk_score = 75
            severity = 'HIGH'
            flags.append(f"ROOT account write activity: {event_name}")

        else:
            return None  # Not suspicious

        # Additional risk factors
        if error_code == 'AccessDenied':
            risk_score = min(risk_score + 10, 100)
            flags.append("Access denied — possible unauthorized attempt")

        if 'root' in username.lower():
            risk_score = min(risk_score + 10, 100)
            flags.append("ROOT account used — high risk")

        if mfa_authenticated == 'false':
            risk_score = min(risk_score + 5, 100)
            flags.append("No MFA — account not secured")

        if source_ip not in ['AWS Internal', 'Unknown']:
            flags.append(f"Source IP: {source_ip}")

        if region not in ['eu-north-1', 'us-east-1', 'Unknown']:
            risk_score = min(risk_score + 10, 100)
            flags.append(f"Unusual region: {region}")

        # Cap at 100
        risk_score = min(risk_score, 100)

        return {
            'event_id': event_id or f"EVT-{int(datetime.now().timestamp())}",
            'event_name': event_name,
            'username': username,
            'source_ip': source_ip,
            'user_agent': user_agent,
            'region': region,
            'event_time': str(event_time),
            'risk_score': risk_score,
            'severity': severity,
            'flags': flags,
            'threat_type': f"Cloud Anomaly ({event_name})",
            'source': 'cloudtrail',
            'mfa_authenticated': mfa_authenticated,
            'error_code': error_code,
            'raw_event': cloud_trail_event
        }