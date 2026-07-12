"""
import json
import sys
import os
import traceback

# Add src to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("=== DEBUG INFO ===")
print(f"Current directory: {os.getcwd()}")
print(f"Files in current dir: {os.listdir('.')}")
print(f"Files in src: {os.listdir('src') if os.path.exists('src') else 'src not found'}")
print(f"Python path: {sys.path}")

try:
    from src.models.phishing.url_detector import RuleBasedPhishingDetector
    print("✅ Successfully imported URL detector")
    url_detector = RuleBasedPhishingDetector()
except Exception as e:
    print(f"❌ Failed to import URL detector: {e}")
    traceback.print_exc()
    url_detector = None

try:
    from src.response.auto_responder import AutoResponder
    print("✅ Successfully imported AutoResponder")
    responder = AutoResponder()
except Exception as e:
    print(f"❌ Failed to import AutoResponder: {e}")
    responder = None

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))
    
    try:
        # Parse the request
        if 'body' in event:
            body = json.loads(event['body'])
            url = body.get('url', '')
        else:
            url = event.get('url', '')
        
        if not url_detector:
            return {
                'statusCode': 500,
                'body': json.dumps({'error': 'URL detector not initialized'})
            }
        
        # Use your detector
        result = url_detector.analyze(url)
        
        # Add auto-response if high risk
        if responder and result.get('risk_score', 0) >= 70:
            response = responder.respond_to_threat(result)
            result['auto_response'] = response
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(result)
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        traceback.print_exc()
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }Lambda Handler for ASECTDS - Automatic Threat Detection
"""

import json
import boto3
import os
import sys
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import your system components
try:
    from src.models.phishing.url_detector import RuleBasedPhishingDetector
    from src.models.phishing.email_detector import PhishingEmailParser
    from src.models.cloud.cloudtrail_analyzer import CloudTrailAnalyzer
    from src.models.deepfake.detector import DeepfakeDetector
    from src.response.auto_responder import AutoResponder
    print("✅ Successfully imported ASECTDS modules")
except Exception as e:
    print(f"❌ Error importing modules: {e}")

# Initialize AWS clients
s3 = boto3.client('s3')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize detectors ONCE
print("🚀 Initializing ASECTDS detectors...")
url_detector = RuleBasedPhishingDetector()
email_detector = PhishingEmailParser()
cloud_analyzer = CloudTrailAnalyzer()
deepfake_detector = DeepfakeDetector()
responder = AutoResponder()

def lambda_handler(event, context):
    """Main entry point - triggered by various AWS events"""
    logger.info(f"Received event type: {type(event)}")
    
    try:
        # Handle different event sources
        if 'Records' in event:
            if 's3' in event['Records'][0]:
                return handle_s3_event(event)
        
        elif event.get('httpMethod'):
            return handle_api_gateway(event)
        
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Unsupported event type'})
            }
            
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_s3_event(event):
    """Process new emails uploaded to S3"""
    results = []
    
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        
        logger.info(f"Processing email: {key}")
        
        # This is where your email detection would go
        # For now, return a simple response
        
        results.append({
            'bucket': bucket,
            'key': key,
            'status': 'processed'
        })
    
    return {
        'statusCode': 200,
        'body': json.dumps({'processed': len(results)})
    }

def handle_api_gateway(event):
    """Handle URL check requests"""
    try:
        body = json.loads(event.get('body', '{}'))
        url = body.get('url')
        
        if not url:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'URL required'})
            }
        
        # Analyze URL with your detector
        result = url_detector.analyze(url)
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(result)
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
    try:
        from src.models.deepfake.detector import DeepfakeDetector
        deepfake_detector = DeepfakeDetector()
        print("✅ Deepfake detector loaded")
    except Exception as e:
        print(f"⚠️ Deepfake detector not loaded: {e}")
        deepfake_detector = None