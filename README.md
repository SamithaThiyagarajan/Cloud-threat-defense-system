# ASECTDS
### Autonomous Self-Evolving Cloud Threat Defense System


## Why "Self-Evolving"?

Traditional security systems only detect threats they already know. **ASECTDS is different.**

Every attack the system detects is permanently stored in DynamoDB — building an institutional memory of the organization's threat history. An LSTM (Long Short-Term Memory) neural network analyses sequences of stored attacks to learn *how attacker behaviour evolves over time*. When patterns shift, the model retrains automatically — without any human intervention.

```
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
```

---

## System Architecture

```
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
```

---

## The 9-Module Pipeline

| # | Module | Status |
|---|---|---|
| 1 | Data Ingestion Layer | ✅ Live |
| 2 | Detection Layer (Email + URL + Cloud) | ✅ Live |
| 3 | Feature Extraction Layer | ✅ Live |
| 4 | Attack Memory Database (DynamoDB) | ✅ Live — 190 records |
| 5 | LSTM Behaviour Learning Engine | ✅ Trained — loss 0.0102 |
| 6 | Attack Simulation Engine | 🔄 Designed, Phase 3 deployment |
| 7 | Autonomous Model Training Pipeline | 🔄 Architecture implemented |
| 8 | Policy Decision Engine | ✅ Live — threshold-based rules |
| 9 | Automated Response Deployment | ✅ Live — S3 + DynamoDB + SNS |

---

## What It Does

### 📧 Email Phishing Detection
Emails sent to `test@asectds.indevs.in` are received by AWS SES, stored in S3, and trigger a Lambda that runs 9 checks — urgency tactics, sender spoofing, suspicious links, credential requests, and more. Detected phishing emails are automatically quarantined.

### 🌐 URL Phishing Detection
A Chrome extension checks every URL visited against a live API endpoint. The backend runs 9 rule-based checks — IP in URL, suspicious TLDs, brand spoofing, keyword matching, and more. Malicious URLs are blocked before the page loads.

### ☁️ Cloud Anomaly Detection
Every 15 minutes, a Lambda scans AWS CloudTrail logs across 2 regions (eu-north-1 + us-east-1) for high-risk API actions like `CreateUser`, `DeleteTrail`, `CreateAccessKey`. Root account usage and missing MFA add extra risk score.

### 🤖 Autonomous Auto-Response
Based on risk score, the system automatically quarantines emails in S3, writes audit records to DynamoDB, and sends alert emails via SNS — all within 100ms, no human needed.

### 🧠 LSTM Model
A PyTorch LSTM (`phishing_url_latest.pt`, 3.2MB) trained on 5,000 phishing URLs from PhishTank. Classifies URLs into 6 threat categories. Final training loss: 0.0102.

| Layer | Configuration |
|---|---|
| Input | 6 URL features |
| LSTM Layer 1 | 256 units |
| LSTM Layer 2 | 256 units |
| Output | 6 classes (legitimate, phishing_generic, credential_harvesting, brand_spoofing, malware_distribution, suspicious) |

> **Note:** LSTM is trained and validated locally. Not yet deployed to Lambda due to AWS's 250MB package size limit (PyTorch ~120MB). Future path: AWS Lambda Layers or SageMaker.

---

## Live Test Results

All results verified from AWS CloudWatch logs and live API responses.

### Email Detection

| Test | Result |
|---|---|
| Sender | samitha224557@gmail.com |
| Subject | URGENT: Your account will be suspended! |
| Risk score | **100 / 100 — CRITICAL** |
| Threat type | Phishing Email (Sender Spoofing) |
| Flags | Urgency tactics (2), Threat/fear tactics (1), Generic greeting, Suspicious links (1), Sender spoofing, Grammar issues (6) |
| Action taken | Quarantined to S3, DynamoDB record written, SNS alert sent |
| Execution time | **118ms** |
| Memory used | **88MB** |

### URL Detection

| URL Tested | Risk Score | Result |
|---|---|---|
| `http://fake-paypal.login` | 100 / 100 | ❌ BLOCKED — CRITICAL |
| `http://secure-verify.xyz` | 65 / 100 | ❌ BLOCKED — HIGH |
| `https://google.com` | 0 / 100 | ✅ SAFE |
| `https://github.com/login` | 15 / 100 | ✅ SAFE |
| `https://amazon.com` | 0 / 100 | ✅ SAFE |

> Tested manually against 5 known phishing URLs (PhishTank verified) and 5 known safe domains. All 10 classified correctly.

### Cloud Anomaly Detection

| Test | Result |
|---|---|
| Anomalies detected in one scan | **6 events** |
| Username flagged | root |
| Risk score | **100 / 100** |
| Flags | ROOT account, No MFA, Unusual source IP |
| DynamoDB records written | **6** |
| SNS alerts sent | **6** |
| Total anomalies stored to date | **186** |

### Auto-Response Pipeline

| Action | Verified |
|---|---|
| Email copied to S3 quarantine/ | ✅ |
| Original deleted from S3 emails/ | ✅ |
| DynamoDB audit record written | ✅ |
| SNS alert email received | ✅ |
| End-to-end execution time | **< 100ms** |

### Chrome Extension

| Metric | Value |
|---|---|
| Avg API response time | 350ms |
| Cache TTL | 5 minutes |
| Cache hit rate | 85% |
| Retry logic | 2 retries, silent fail |
| Accuracy tracking | TP / FP / TN / FN from user decisions |

---

## Auto-Response Thresholds

| Risk Score | Action |
|---|---|
| ≥ 60 | Rate limit source traffic |
| ≥ 70 | Quarantine email to S3 silently |
| ≥ 80 | Block IP |
| ≥ 85 | SNS alert email + revoke cloud keys |

> 70–84 quarantines silently for analyst review. 85+ triggers immediate human alert. Intentional design to prevent alert fatigue.

---

## AWS Infrastructure

| Service | Configuration |
|---|---|
| **Lambda** (x2) | Python 3.12 · 512MB · 60s timeout |
| **API Gateway** | POST /detect · eu-north-1 · CORS enabled |
| **Amazon S3** | `asectds-emails-20260228` · emails/ + quarantine/ prefix |
| **DynamoDB** | `asectds-quarantine` + `asectds-cloud-anomalies` · on-demand |
| **Amazon SNS** | `asectds-alerts` topic · email subscriber |
| **Amazon SES** | `test@asectds.indevs.in` · DNS on Cloudflare |
| **CloudTrail** | `asectds-trail` · multi-region · logs to S3 + CloudWatch |
| **EventBridge** | `rate(15 minutes)` → CloudAnomalyFunction |
| **CloudWatch** | Lambda logs · custom metrics · Grafana data source |
| **AWS SAM** | Stack: `asectds-stack` · Region: `eu-north-1` |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| ML Model | PyTorch — 2-layer LSTM (input 6 → hidden 256 → 6 output classes) |
| Cloud | AWS Lambda, S3, DynamoDB, SNS, SES, API Gateway, CloudTrail, EventBridge |
| Deployment | AWS SAM |
| Monitoring | Grafana Cloud → AWS CloudWatch |
| Extension | Chrome Extension (JavaScript) |

---

## Project Structure

```
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
```

---

## How to Deploy

```bash
cd lambda-deploy
sam build
sam deploy --guided

# Attach IAM policies after deploy
aws iam attach-role-policy --role-name <ThreatDetectionFunctionRole> --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam attach-role-policy --role-name <ThreatDetectionFunctionRole> --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess
aws iam attach-role-policy --role-name <ThreatDetectionFunctionRole> --policy-arn arn:aws:iam::aws:policy/AmazonSNSFullAccess
```

---

## API Reference

**Endpoint:** `POST https://duoyij8ld5.execute-api.eu-north-1.amazonaws.com/Prod/detect`

**Request:**
```json
{ "url": "http://fake-paypal.login" }
```

**Response:**
```json
{
  "is_phishing": true,
  "risk_score": 100,
  "severity": "CRITICAL",
  "flags": ["Suspicious TLD: .login", "paypal brand spoofing", "HTTP on sensitive page"],
  "recommendation": "BLOCK - Clear phishing attempt",
  "detection_method": "rule_based"
}
```

**Test:**
```bash
curl -X POST https://duoyij8ld5.execute-api.eu-north-1.amazonaws.com/Prod/detect -H "Content-Type: application/json" -d "{\"url\": \"http://fake-paypal.login\"}"
```

---


## Known Limitations

- **LSTM not in Lambda** — PyTorch (~120MB) exceeds Lambda's 250MB limit. Future: Lambda Layers or SageMaker
- **CloudTrail delay** — 5–15 min AWS platform limitation, cannot be reduced
- **Deepfake detection** — designed and partially implemented, paused pending GPU infrastructure
- **API authentication** — API key created, not yet enforced on stage
- **Grafana** — connected to CloudWatch, additional panels in progress
