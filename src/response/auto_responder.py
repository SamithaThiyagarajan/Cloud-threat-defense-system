"""
Auto-Response Engine - Automatically takes action against threats
"""

import time
from datetime import datetime
from collections import defaultdict
import sys
import os
import boto3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# AWS clients
# AWS clients
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns', region_name='eu-north-1')

SNS_TOPIC_ARN = 'arn:aws:sns:eu-north-1:824139110712:asectds-alerts'

class AutoResponder:
    """
    Automatically responds to threats based on risk score and type
    """

    def __init__(self):
        self.thresholds = {
            'block_ip': 80,
            'quarantine': 70,
            'revoke_keys': 85,
            'alert_human': 85,
            'rate_limit': 60
        }

        self.blocked_ips = set()
        self.quarantined_emails = []
        self.revoked_keys = []
        self.rate_limits = defaultdict(list)
        self.max_requests_per_minute = 100
        self.response_log = []
        self.stats = {
            'total_responses': 0,
            'blocks': 0,
            'quarantines': 0,
            'revocations': 0,
            'alerts': 0,
            'rate_limits': 0
        }

        # DynamoDB table for audit trail
        self.quarantine_table = dynamodb.Table('asectds-quarantine')

        print("🛡️ Auto-Responder initialized")
        print(f"  Block IP threshold: {self.thresholds['block_ip']}")
        print(f"  Quarantine threshold: {self.thresholds['quarantine']}")
        print(f"  Alert human threshold: {self.thresholds['alert_human']}")

    def respond_to_threat(self, threat):
        """
        Automatically respond to a detected threat
        """
        response = {
            'threat_id': threat.get('id', f"THR-{int(time.time())}"),
            'timestamp': datetime.utcnow().isoformat(),
            'threat_type': threat.get('threat_type', 'Suspicious Email'),
            'risk_score': threat.get('risk_score', 0),
            'actions_taken': [],
            'success': True
        }

        risk = threat.get('risk_score', 0)

        # 1. BLOCK IP if high risk
        if risk >= self.thresholds['block_ip']:
            ip = self._extract_ip(threat)
            if ip and ip not in self.blocked_ips:
                self._block_ip(ip, threat)
                response['actions_taken'].append({
                    'action': 'block_ip',
                    'target': ip,
                    'reason': f'Risk score {risk} exceeded threshold {self.thresholds["block_ip"]}'
                })
                self.stats['blocks'] += 1

        # 2. QUARANTINE email if phishing
        if risk >= self.thresholds['quarantine'] and threat.get('source') == 'email':
            quarantine_result = self._quarantine_email(threat)
            if quarantine_result:
                response['actions_taken'].append({
                    'action': 'quarantine',
                    'target': quarantine_result['quarantine_key'],
                    'reason': 'Phishing email detected',
                    'details': quarantine_result
                })
                self.stats['quarantines'] += 1

        # 3. REVOKE credentials if critical cloud threat
        if risk >= self.thresholds['revoke_keys'] and threat.get('attack_type') == 'cloud_anomaly':
            keys = self._extract_keys(threat)
            if keys:
                self._revoke_keys(keys, threat)
                response['actions_taken'].append({
                    'action': 'revoke_keys',
                    'target': keys,
                    'reason': 'Critical cloud threat detected'
                })
                self.stats['revocations'] += 1

        # 4. RATE LIMIT if suspicious but not critical
        if risk >= self.thresholds['rate_limit'] and risk < self.thresholds['block_ip']:
            source = self._extract_source(threat)
            if source:
                self._apply_rate_limit(source)
                response['actions_taken'].append({
                    'action': 'rate_limit',
                    'target': source,
                    'reason': f'Suspicious activity (risk {risk})'
                })
                self.stats['rate_limits'] += 1

        # 5. ALERT human if critical
        if risk >= self.thresholds['alert_human']:
            self._send_alert(threat, response['actions_taken'])
            response['actions_taken'].append({
                'action': 'alert',
                'severity': 'CRITICAL',
                'reason': 'Human review required'
            })
            self.stats['alerts'] += 1

        self._log_response(response)
        self.stats['total_responses'] += 1

        return response

    def _quarantine_email(self, threat):
        """
        Real quarantine — 3 actual actions:
        1. Move email from emails/ to quarantine/ in S3
        2. Tag the quarantined object with threat metadata
        3. Write audit record to DynamoDB
        """
        bucket = threat.get('bucket')
        key = threat.get('key')

        if not bucket or not key:
            print("⚠️ No bucket/key in threat — cannot quarantine")
            return None

        quarantine_key = key.replace('emails/', 'quarantine/')
        timestamp = datetime.utcnow().isoformat()
        threat_type = threat.get('threat_type', 'Suspicious Email')
        risk_score = threat.get('risk_score', 0)
        sender = threat.get('sender', 'Unknown')
        subject = threat.get('subject', 'No Subject')

        try:
            # ACTION 1: Copy email to quarantine/ folder
            s3.copy_object(
                Bucket=bucket,
                CopySource={'Bucket': bucket, 'Key': key},
                Key=quarantine_key
            )
            print(f"📁 Copied to quarantine: s3://{bucket}/{quarantine_key}")

            # ACTION 2: Tag the quarantined object with threat info
            # S3 tags don't allow special chars — sanitize values
            def safe_tag(value):
                import re
                return re.sub(r'[^a-zA-Z0-9 _.:/=+\-@]', '', str(value))[:256]

            s3.put_object_tagging(
                Bucket=bucket,
                Key=quarantine_key,
                Tagging={
                    'TagSet': [
                        {'Key': 'status',         'Value': 'quarantined'},
                        {'Key': 'threat_type',    'Value': safe_tag(threat_type)},
                        {'Key': 'risk_score',     'Value': safe_tag(risk_score)},
                        {'Key': 'quarantined_at', 'Value': safe_tag(timestamp)},
                        {'Key': 'sender',         'Value': safe_tag(sender)},
                    ]
                }
            )
            print(f"🏷️ Tagged quarantined object with threat metadata")

            # ACTION 3: Delete original from emails/ folder
            s3.delete_object(Bucket=bucket, Key=key)
            print(f"🗑️ Deleted original from: s3://{bucket}/{key}")

            # ACTION 4: Write audit record to DynamoDB
            self.quarantine_table.put_item(
                Item={
                    'email_id': key,
                    'quarantine_key': quarantine_key,
                    'timestamp': timestamp,
                    'threat_type': threat_type,
                    'risk_score': str(risk_score),
                    'sender': sender,
                    'subject': subject,
                    'bucket': bucket,
                    'status': 'quarantined',
                    'flags': threat.get('flags', [])
                }
            )
            print(f"📊 Audit record written to DynamoDB")

            return {
                'quarantine_key': quarantine_key,
                'original_key': key,
                'timestamp': timestamp,
                'dynamodb_record': 'written'
            }

        except Exception as e:
            print(f"❌ Quarantine failed: {str(e)}")
            return None

    def _extract_ip(self, threat):
        """Extract IP address from threat data"""
        ip = threat.get('source_ip')
        if ip:
            return ip
        raw = threat.get('raw_indicators', {})
        if isinstance(raw, dict):
            ip = raw.get('source_ip') or raw.get('ip') or raw.get('sourceIPAddress')
            if ip:
                return ip
        return None

    def _extract_keys(self, threat):
        """Extract AWS keys from cloud threat"""
        raw = threat.get('raw_indicators', {})
        if isinstance(raw, dict):
            logs = raw.get('logs', [])
            if logs and isinstance(logs, list) and len(logs) > 0:
                user = logs[0].get('userIdentity', {}).get('arn', 'unknown')
                return f"keys_for_{user.split('/')[-1]}"
        return None

    def _extract_source(self, threat):
        """Extract source identifier for rate limiting"""
        ip = self._extract_ip(threat)
        if ip:
            return ip
        sender = threat.get('sender')
        if sender:
            return sender
        return f"source_{int(time.time())}"

    def _block_ip(self, ip, threat):
        """Block an IP address"""
        self.blocked_ips.add(ip)
        print(f"🚫 Blocked IP: {ip} (risk: {threat.get('risk_score')})")

    def _revoke_keys(self, keys, threat):
        """Revoke AWS credentials"""
        self.revoked_keys.append({
            'keys': keys,
            'timestamp': datetime.utcnow().isoformat(),
            'reason': threat.get('raw_indicators', {}).get('eventName', 'Unknown')
        })
        print(f"🔑 Revoked keys: {keys}")

    def _apply_rate_limit(self, source):
        """Apply rate limiting to source"""
        now = time.time()
        self.rate_limits[source] = [
            t for t in self.rate_limits[source]
            if now - t < 60
        ]
        self.rate_limits[source].append(now)
        print(f"⏱️ Rate limiting applied to: {source}")

    def _send_alert(self, threat, actions):
        """Send alert to security team via SNS"""
        threat_type = threat.get('threat_type', 'Suspicious Email')
        risk = threat.get('risk_score')
        sender = threat.get('sender', 'Unknown')
        subject = threat.get('subject', 'No Subject')
        flags = threat.get('flags', [])

        message = f"""
🚨 ASECTDS SECURITY ALERT 🚨
=============================
Severity:    CRITICAL
Threat Type: {threat_type}
Risk Score:  {risk}/100

📧 Email Details:
  From:    {sender}
  Subject: {subject}

🚩 Detection Flags:
{chr(10).join(f'  • {f}' for f in flags)}

⚡ Actions Taken:
{chr(10).join(f'  • {a["action"]}' for a in actions)}

🕒 Timestamp: {datetime.utcnow().isoformat()} UTC
📁 Quarantine: s3://asectds-emails-20260228/quarantine/

-- ASECTDS Autonomous Security System
"""

        alert_subject = f"🚨 CRITICAL: {threat_type} detected (Risk: {risk}/100)"

        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=message,
                Subject=alert_subject
            )
            print(f"🔔 SNS alert sent: {alert_subject}")
        except Exception as e:
            print(f"❌ SNS alert failed: {str(e)}")

        print(f"🔔 ALERT: CRITICAL: {threat_type} detected with risk {risk}")

    def _log_response(self, response):
        """Log response for audit"""
        self.response_log.append(response)
        if len(self.response_log) > 1000:
            self.response_log = self.response_log[-1000:]

    def get_blocked_ips(self):
        return list(self.blocked_ips)

    def get_quarantined_emails(self):
        return self.quarantined_emails[-50:]

    def get_response_stats(self):
        return {
            **self.stats,
            'active_blocks': len(self.blocked_ips),
            'active_quarantines': len(self.quarantined_emails),
            'recent_responses': self.response_log[-10:]
        }

    def check_rate_limit(self, source):
        now = time.time()
        recent = [t for t in self.rate_limits.get(source, []) if now - t < 60]
        return len(recent) >= self.max_requests_per_minute