import json
import boto3
import os

# AWS client
s3 = boto3.client('s3')

# Import phishing modules
from src.models.phishing.email_detector import (
    PhishingEmailParser,
    EmailPhishingDetector
)
from src.response.auto_responder import AutoResponder

# Initialize components
parser = PhishingEmailParser()
detector = EmailPhishingDetector()
responder = AutoResponder()

# Initialize URL detector (LSTM-based)
url_detector = None
try:
    from src.models.phishing.url_detector import PhishingURLDetector
    # Get the model path (relative to lambda deployment)
    model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'phishing_url_latest.pt')
    url_detector = PhishingURLDetector(model_path=model_path)
    print("✅ LSTM URL detector loaded")
except Exception as e:
    print(f"⚠️ URL detector not loaded: {e}")


def lambda_handler(event, context):
    # Handle OPTIONS request for CORS
    if event.get('httpMethod') == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': ''
        }

    # ── API Gateway event (URL detection) ──────────────────────────
    if 'body' in event:
        return handle_url_detection(event)

    # ── S3 event (Email detection) ──────────────────────────────────
    if 'Records' in event:
        return handle_email_detection(event)

    return {
        'statusCode': 400,
        'body': json.dumps({'error': 'Unknown event type'})
    }


def handle_url_detection(event):
    """Handle URL detection from API Gateway"""
    try:
        # Parse body
        body = event.get('body', '{}')
        if isinstance(body, str):
            body = json.loads(body)

        url = body.get('url', '')
        if not url:
            return {
                'statusCode': 400,
                'headers': cors_headers(),
                'body': json.dumps({'error': 'url field is required'})
            }

        print(f"🔗 URL detection request: {url}")

        # Use LSTM detector if available
        if url_detector:
            try:
                result = url_detector.predict(url)
                print(f"✅ LSTM result - risk: {result.get('risk_score')}, class: {result.get('predicted_class', 'N/A')}")
                return {
                    'statusCode': 200,
                    'headers': cors_headers(),
                    'body': json.dumps(result)
                }
            except Exception as e:
                print(f"⚠️ LSTM model failed: {e}, falling back to rule-based")

        # Fallback to rule-based detection
        result = rule_based_url_check(url)
        print(f"✅ Rule-based result - risk: {result.get('risk_score')}")
        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps(result)
        }

    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return {
            'statusCode': 400,
            'headers': cors_headers(),
            'body': json.dumps({'error': 'Invalid JSON body'})
        }
    except Exception as e:
        print(f"URL detection error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def handle_email_detection(event):
    """Handle email detection from S3 trigger"""
    print("📧 S3 event received")
    try:
        for record in event['Records']:
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']
            print(f"Processing: s3://{bucket}/{key}")

            # Download email from S3
            response = s3.get_object(Bucket=bucket, Key=key)
            email_content = response['Body'].read()

            # Convert to string
            raw_email = email_content.decode('utf-8', errors='ignore')

            # Parse raw email
            parsed_email = parser.parse_raw_email(raw_email)
            sender = parsed_email.get("sender") or "Unknown"
            subject = parsed_email.get("subject") or "No Subject"
            body = parsed_email.get("content", "")

            print(f"Sender: {sender}")
            print(f"Subject: {subject}")
            print(f"Body preview: {body[:120]}...")

            # Run phishing detection
            result = detector.analyze_email(
                email_content=body,
                sender=sender,
                subject=subject
            )

            risk_score = result.get('risk_score', 0)
            is_phishing = result.get('is_phishing', False)
            severity = result.get('severity', 'UNKNOWN')
            threat_type = result.get('threat_type', 'Suspicious Email')

            print(f"Risk score: {risk_score}")
            print(f"Is phishing: {is_phishing}")
            print(f"Severity: {severity}")
            print(f"Threat type: {threat_type}")
            print(f"Flags: {result.get('flags', [])}")

            # Trigger auto-response if high risk
            if risk_score >= 70:
                print("⚠️ High risk detected - triggering auto-response")
                response_result = responder.respond_to_threat({
                    **result,
                    "source": "email",
                    "threat_type": threat_type,
                    "sender": sender,
                    "subject": subject,
                    "bucket": bucket,
                    "key": key
                })
                result['auto_response'] = response_result
                print(f"Auto-response actions: {response_result.get('actions_taken', [])}")

            print("✅ Email processed successfully")

        return {
            'statusCode': 200,
            'headers': cors_headers(),
            'body': json.dumps({'message': 'Email processed successfully'})
        }

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'headers': cors_headers(),
            'body': json.dumps({'error': str(e)})
        }


def rule_based_url_check(url: str) -> dict:
    """
    Rule-based URL phishing check
    Used as fallback when ML model is not available
    """
    import re
    url_lower = url.lower()
    risk_score = 0
    flags = []

    suspicious_keywords = [
        'login', 'verify', 'account', 'secure', 'update',
        'confirm', 'banking', 'paypal', 'amazon', 'apple',
        'microsoft', 'google', 'netflix', 'suspended', 'urgent',
        'password', 'credential', 'signin', 'wallet', 'payment'
    ]

    # Suspicious TLDs including fake-looking ones
    suspicious_tlds = [
        '.xyz', '.top', '.tk', '.ml', '.ga', '.cf',
        '.login', '.verify', '.secure', '.account',
        '.update', '.confirm', '.banking', '.payment'
    ]

    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'rebrand.ly']

    # Check for IP address instead of domain
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        risk_score += 40
        flags.append("IP address used instead of domain")

    # Check for suspicious TLDs
    for tld in suspicious_tlds:
        if url_lower.endswith(tld) or f'{tld}/' in url_lower:
            risk_score += 30
            flags.append(f"Suspicious TLD: {tld}")
            break

    # Check for URL shorteners
    for shortener in shorteners:
        if shortener in url_lower:
            risk_score += 20
            flags.append(f"URL shortener detected: {shortener}")
            break

    # Check for suspicious keywords
    keyword_hits = [k for k in suspicious_keywords if k in url_lower]
    if keyword_hits:
        risk_score += len(keyword_hits) * 10
        flags.append(f"Suspicious keywords: {', '.join(keyword_hits[:3])}")

    # Check for malformed URL (http: not followed by //)
    if re.match(r'https?:[^/]', url_lower):
        risk_score += 30
        flags.append("Malformed URL structure")

    # Check for excessive subdomains
    domain_part = re.sub(r'https?://', '', url_lower).split('/')[0]
    if domain_part.count('.') > 3:
        risk_score += 20
        flags.append("Excessive subdomains")

    # Check for brand name in URL but not on official domain
    brands = {
        'paypal': 'paypal.com',
        'amazon': 'amazon.com',
        'apple': 'apple.com',
        'microsoft': 'microsoft.com',
        'google': 'google.com',
        'netflix': 'netflix.com',
        'facebook': 'facebook.com',
        'instagram': 'instagram.com',
        'linkedin': 'linkedin.com',
        'ebay': 'ebay.com'
    }
    for brand, legit_domain in brands.items():
        if brand in url_lower and legit_domain not in url_lower:
            risk_score += 35
            flags.append(f"Possible {brand} spoofing")
            break

    # Check for HTTP (not HTTPS) on sensitive-looking pages
    if url_lower.startswith('http://') and any(
        k in url_lower for k in ['login', 'verify', 'account', 'secure', 'banking']
    ):
        risk_score += 15
        flags.append("HTTP used on sensitive page (not HTTPS)")

    # Check for long URL with many parameters
    if len(url) > 100:
        risk_score += 10
        flags.append("Unusually long URL")

    # Cap at 100
    risk_score = min(risk_score, 100)

    return {
        'url': url,
        'is_phishing': risk_score >= 50,
        'risk_score': risk_score,
        'confidence': risk_score / 100,
        'severity': get_severity(risk_score),
        'flags': flags,
        'recommendation': get_recommendation(risk_score),
        'detection_method': 'rule_based'
    }


def get_severity(score: int) -> str:
    if score >= 80:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    elif score >= 20:
        return 'LOW'
    else:
        return 'MINIMAL'


def get_recommendation(score: int) -> str:
    if score >= 80:
        return 'BLOCK - Clear phishing attempt'
    elif score >= 60:
        return 'WARN - Do not proceed'
    elif score >= 40:
        return 'CAUTION - Verify before proceeding'
    elif score >= 20:
        return 'MONITOR - Exercise caution'
    else:
        return 'SAFE - Appears legitimate'


def cors_headers():
    """CORS headers for browser extension compatibility"""
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,x-api-key',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Content-Type': 'application/json'
    }