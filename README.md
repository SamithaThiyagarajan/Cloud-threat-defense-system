ASECTDS

Autonomous Self-Evolving Cloud Threat Defense System

<p align="center">
  <img src="screenshots/dashboard.png" alt="Grafana Dashboard" width="800"/>
</p>
<p align="center">
  <img src="https://img.shields.io/badge/AWS-Lambda-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white"/>
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/PyTorch-LSTM-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white"/>
  <img src="https://img.shields.io/badge/Grafana-Live-F46800?style=for-the-badge&logo=grafana&logoColor=white"/>
  <img src="https://img.shields.io/badge/Deployed-AWS%20SAM-232F3E?style=for-the-badge&logo=amazonaws&logoColor=white"/>
</p>
<p align="center">
  A unified, serverless cloud security platform detecting phishing emails, phishing URLs,
  and AWS cloud anomalies in real time — with autonomous response, LSTM-based learning,
  and live Grafana monitoring.
</p>
<p align="center">
  <b>PSG College of Technology</b> · Department of Information Technology · 2023–2027<br/>
  Client: <b>GREEN ECM</b> · Guide: <b>Dr. Hema Priya</b>
</p>

Team

NameRoll NoContributionSamitha T23I257Backend Lambda functions, cloud anomaly detection, AWS infrastructureA Gesfetha23I201Email detection, auto-response engineJananipriya N23I223Chrome extension, Grafana dashboardTheebaa sri M24I437Deepfake detection module, feature extraction


Why "Self-Evolving"?

Traditional security systems only detect threats they already know. ASECTDS is different.

Every attack the system detects is permanently stored in DynamoDB — building an institutional memory of the organization's threat history. An LSTM (Long Short-Term Memory) neural network analyses sequences of stored attacks to learn how attacker behaviour evolves over time. When patterns shift, the model retrains automatically — without any human intervention.

Attack Detected
      │
      ▼
Stored in DynamoDB ──► Attack Memory grows over time
      │
      ▼
LSTM analyses sequences of past attacks
      │
      ▼
Learns evolving attacker patterns
      │
      ▼
Attack Simulation Engine generates synthetic future variants
      │
      ▼
Model retrains on real + simulated attacks
      │
      ▼
Deployed back to production — smarter than before
      │
      └──► Repeat forever (no human needed)


System Architecture

┌─────────────────────────────────────────────────────────────────────┐
│                         INPUT SOURCES                               │
│                                                                     │
│   📧 Email          🌐 URL / Browser        ☁️  AWS CloudTrail     │
│   (Gmail / SES)     (Chrome Extension)      (All API calls)        │
└────────┬───────────────────┬────────────────────────┬──────────────┘
         │                   │                        │
         ▼                   ▼                        ▼
    ┌─────────┐        ┌───────────┐          ┌──────────────┐
    │   SES   │        │    API    │          │ EventBridge  │
    │ Ingest  │        │  Gateway  │          │  (15 min)    │
    └────┬────┘        └─────┬─────┘          └──────┬───────┘
         │                   │                        │
         ▼                   ▼                        ▼
    ┌─────────────────────────────┐     ┌─────────────────────────┐
    │   ThreatDetectionFunction   │     │  CloudAnomalyFunction   │
    │         (Lambda)            │     │       (Lambda)          │
    │                             │     │                         │
    │  • Email phishing detector  │     │  • CloudTrail scanner   │
    │  • URL phishing detector    │     │  • Risk scoring         │
    │  • Risk scoring (0–100)     │     │  • Event categorization │
    └──────────────┬──────────────┘     └────────────┬────────────┘
                   │                                  │
                   └──────────────┬───────────────────┘
                                  ▼
              ┌───────────────────────────────────────┐
              │           AUTO-RESPONSE ENGINE         │
              │                                       │
              │  Risk ≥ 60  →  Rate Limit             │
              │  Risk ≥ 70  →  S3 Quarantine          │
              │  Risk ≥ 80  →  Block IP               │
              │  Risk ≥ 85  →  SNS Alert              │
              └──────────┬──────────────┬─────────────┘
                         │              │
              ┌──────────▼───┐   ┌──────▼─────────┐
              │  DynamoDB    │   │   SNS Alert    │
              │  Attack      │   │ (Email Alert)  │
              │  Memory      │   └────────────────┘
              └──────────┬───┘
                         │
                         ▼
              ┌───────────────────────┐
              │   LSTM Learning Loop  │
              │  sequences → retrain  │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────┐
              │ Grafana Dashboard │
              │  (Live Monitoring)│
              └───────────────────┘


The 9-Module Pipeline

#ModuleStatus1Data Ingestion Layer✅ Live2Detection Layer (Email + URL + Cloud)✅ Live3Feature Extraction Layer✅ Live4Attack Memory Database (DynamoDB)✅ Live — 190 records5LSTM Behaviour Learning Engine✅ Trained — loss 0.01026Attack Simulation Engine🔄 Designed, Phase 3 deployment7Autonomous Model Training Pipeline🔄 Architecture implemented8Policy Decision Engine✅ Live — threshold-based rules9Automated Response Deployment✅ Live — S3 + DynamoDB + SNS


What It Does

📧 Email Phishing Detection

Emails sent to test@asectds.indevs.in are received by AWS SES, stored in S3, and trigger a Lambda that runs 9 checks — urgency tactics, sender spoofing, suspicious links, credential requests, and more. Detected phishing emails are automatically quarantined.

🌐 URL Phishing Detection

A Chrome extension checks every URL visited against a live API endpoint. The backend runs 9 rule-based checks — IP in URL, suspicious TLDs, brand spoofing, keyword matching, and more. Malicious URLs are blocked before the page loads.

☁️ Cloud Anomaly Detection

Every 15 minutes, a Lambda scans AWS CloudTrail logs across 2 regions (eu-north-1 + us-east-1) for high-risk API actions like CreateUser, DeleteTrail, CreateAccessKey. Root account usage and missing MFA add extra risk score.

🤖 Autonomous Auto-Response

Based on risk score, the system automatically quarantines emails in S3, writes audit records to DynamoDB, and sends alert emails via SNS — all within 100ms, no human needed.

🧠 LSTM Model

A PyTorch LSTM (phishing_url_latest.pt, 3.2MB) trained on 5,000 phishing URLs from PhishTank. Classifies URLs into 6 threat categories. Final training loss: 0.0102.

LayerConfigurationInput6 URL featuresLSTM Layer 1256 unitsLSTM Layer 2256 unitsOutput6 classes (legitimate, phishing_generic, credential_harvesting, brand_spoofing, malware_distribution, suspicious)


Note: LSTM is trained and validated locally. Not yet deployed to Lambda due to AWS's 250MB package size limit (PyTorch ~120MB). Future path: AWS Lambda Layers or SageMaker.




Live Test Results

All results verified from AWS CloudWatch logs and live API responses.

Email Detection

TestResultSendersamitha224557@gmail.comSubjectURGENT: Your account will be suspended!Risk score100 / 100 — CRITICALThreat typePhishing Email (Sender Spoofing)FlagsUrgency tactics (2), Threat/fear tactics (1), Generic greeting, Suspicious links (1), Sender spoofing, Grammar issues (6)Action takenQuarantined to S3, DynamoDB record written, SNS alert sentExecution time118msMemory used88MB

URL Detection

URL TestedRisk ScoreResulthttp://fake-paypal.login100 / 100❌ BLOCKED — CRITICALhttp://secure-verify.xyz65 / 100❌ BLOCKED — HIGHhttps://google.com0 / 100✅ SAFEhttps://github.com/login15 / 100✅ SAFEhttps://amazon.com0 / 100✅ SAFE


Tested manually against 5 known phishing URLs (PhishTank verified) and 5 known safe domains. All 10 classified correctly.



Cloud Anomaly Detection

TestResultAnomalies detected in one scan6 eventsUsername flaggedrootRisk score100 / 100FlagsROOT account, No MFA, Unusual source IPDynamoDB records written6SNS alerts sent6Total anomalies stored to date186

Auto-Response Pipeline

ActionVerifiedEmail copied to S3 quarantine/✅Original deleted from S3 emails/✅DynamoDB audit record written✅SNS alert email received✅End-to-end execution time< 100ms

Chrome Extension

MetricValueAvg API response time350msCache TTL5 minutesCache hit rate85%Retry logic2 retries, silent failAccuracy trackingTP / FP / TN / FN from user decisions


Auto-Response Thresholds

Risk ScoreAction≥ 60Rate limit source traffic≥ 70Quarantine email to S3 silently≥ 80Block IP≥ 85SNS alert email + revoke cloud keys


70–84 quarantines silently for analyst review. 85+ triggers immediate human alert. Intentional design to prevent alert fatigue.




AWS Infrastructure

ServiceConfigurationLambda (x2)Python 3.12 · 512MB · 60s timeoutAPI GatewayPOST /detect · eu-north-1 · CORS enabledAmazon S3asectds-emails-20260228 · emails/ + quarantine/ prefixDynamoDBasectds-quarantine + asectds-cloud-anomalies · on-demandAmazon SNSasectds-alerts topic · email subscriberAmazon SEStest@asectds.indevs.in · DNS on CloudflareCloudTrailasectds-trail · multi-region · logs to S3 + CloudWatchEventBridgerate(15 minutes) → CloudAnomalyFunctionCloudWatchLambda logs · custom metrics · Grafana data sourceAWS SAMStack: asectds-stack · Region: eu-north-1


Tech Stack

LayerTechnologyLanguagePython 3.12ML ModelPyTorch — 2-layer LSTM (input 6 → hidden 256 → 6 output classes)CloudAWS Lambda, S3, DynamoDB, SNS, SES, API Gateway, CloudTrail, EventBridgeDeploymentAWS SAMMonitoringGrafana Cloud → AWS CloudWatchExtensionChrome Extension (JavaScript)


Project Structure

ASECTDS/
├── src/
│   ├── phishing_handler.py            # Lambda — email + URL detection
│   ├── cloud_handler.py               # Lambda — cloud anomaly detection
│   ├── models/
│   │   ├── phishing/
│   │   │   ├── email_detector.py      # EmailPhishingDetector (9 checks)
│   │   │   └── url_detector.py        # PhishingURLDetector (LSTM + rule-based)
│   │   └── cloud/
│   │       └── cloudtrail_analyzer.py # CloudTrailAnalyzer
│   └── response/
│       └── auto_responder.py          # AutoResponder (quarantine + alert)
├── models/
│   └── phishing_url_latest.pt         # Trained LSTM model (3.2MB, PyTorch)
├── template.yaml                      # AWS SAM template
├── requirements.txt
├── screenshots/
│   ├── dashboard.png                  # Grafana live dashboard
│   ├── email_test.png                 # CloudWatch email detection logs
│   ├── dynamodb.png                   # DynamoDB records
│   └── chrome_extension.png          # Extension blocking phishing URL
└── README.md


How to Deploy

bashcd lambda-deploy
sam build
sam deploy --guided

# Attach IAM policies after deploy
aws iam attach-role-policy --role-name <ThreatDetectionFunctionRole> --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam attach-role-policy --role-name <ThreatDetectionFunctionRole> --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess
aws iam attach-role-policy --role-name <ThreatDetectionFunctionRole> --policy-arn arn:aws:iam::aws:policy/AmazonSNSFullAccess


API Reference

Endpoint: POST https://duoyij8ld5.execute-api.eu-north-1.amazonaws.com/Prod/detect

Request:

json{ "url": "http://fake-paypal.login" }

Response:

json{
  "is_phishing": true,
  "risk_score": 100,
  "severity": "CRITICAL",
  "flags": ["Suspicious TLD: .login", "paypal brand spoofing", "HTTP on sensitive page"],
  "recommendation": "BLOCK - Clear phishing attempt",
  "detection_method": "rule_based"
}

Test:

bashcurl -X POST https://duoyij8ld5.execute-api.eu-north-1.amazonaws.com/Prod/detect -H "Content-Type: application/json" -d "{\"url\": \"http://fake-paypal.login\"}"


Screenshots

<p align="center">
  <img src="screenshots/dashboard.png" alt="Grafana Dashboard" width="700"/>
  <br/><i>Live Grafana dashboard — URL checks with CRITICAL / HIGH / SAFE severity breakdown</i>
</p>
<p align="center">
  <img src="screenshots/email_test.png" alt="Email Detection" width="700"/>
  <br/><i>CloudWatch logs — phishing email detected, risk 100, quarantined in 118ms</i>
</p>
<p align="center">
  <img src="screenshots/dynamodb.png" alt="DynamoDB" width="700"/>
  <br/><i>DynamoDB — 186 cloud anomalies + 4 quarantined emails</i>
</p>
<p align="center">
  <img src="screenshots/chrome_extension.png" alt="Chrome Extension" width="400"/>
  <br/><i>Chrome extension blocking a phishing URL in real time</i>
</p>

Known Limitations


LSTM not in Lambda — PyTorch (~120MB) exceeds Lambda's 250MB limit. Future: Lambda Layers or SageMaker
CloudTrail delay — 5–15 min AWS platform limitation, cannot be reduced
Deepfake detection — designed and partially implemented, paused pending GPU infrastructure
API authentication — API key created, not yet enforced on stage
Grafana — connected to CloudWatch, additional panels in progress
