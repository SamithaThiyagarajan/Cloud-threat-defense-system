"""
Phishing URL Detection Module
LSTM-based classifier using pre-trained model (phishing_url_latest.pt)
2-layer LSTM: input_dim=6, hidden_dim=256, output=6 classes
Trained on 5000 attacks, final_loss=0.0102
"""

import re
import torch
import torch.nn as nn
import numpy as np
from urllib.parse import urlparse
from typing import Dict


# ── 1. LSTM Model Architecture ─────────────────────────────────────────────────
class PhishingLSTM(nn.Module):
    def __init__(self, input_dim=6, hidden_dim=256, num_layers=2, output_dim=6):
        super(PhishingLSTM, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.lstm = nn.LSTM(
            input_dim,
            hidden_dim,
            num_layers=num_layers,
            batch_first=True
        )
        self.fc = nn.Linear(hidden_dim, output_dim)

    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim)
        out, _ = self.lstm(x, (h0, c0))
        out = self.fc(out[:, -1, :])
        return out


# ── 2. Output class mapping ────────────────────────────────────────────────────
CLASS_LABELS = [
    "legitimate",
    "phishing_generic",
    "credential_harvesting",
    "brand_spoofing",
    "malware_distribution",
    "suspicious"
]

PHISHING_CLASSES = {1, 2, 3, 4, 5}


# ── 3. Feature extraction (6 features) ─────────────────────────────────────────
def extract_features(url: str) -> np.ndarray:
    features = []
    
    # 0 — URL length normalized
    features.append(min(len(url) / 200.0, 1.0))

    # 1 — IP address in URL
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(1.0 if re.search(ip_pattern, url) else 0.0)

    # 2 — Subdomain count normalized
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        parts = hostname.split('.')
        subdomain_count = max(len(parts) - 2, 0)
        features.append(min(subdomain_count / 5.0, 1.0))
    except Exception:
        features.append(0.0)

    # 3 — HTTPS
    features.append(1.0 if url.lower().startswith('https://') else 0.0)

    # 4 — Special character ratio
    if len(url) > 0:
        special = sum(1 for c in url if not c.isalnum() and c not in [':', '/', '.', '-', '_'])
        features.append(special / len(url))
    else:
        features.append(0.0)

    # 5 — Suspicious keyword presence
    keywords = ['verify', 'account', 'secure', 'update', 'confirm', 'login',
                'signin', 'banking', 'paypal', 'ebay', 'amazon', 'apple',
                'microsoft', 'suspended', 'locked', 'password', 'credential']
    has_keyword = any(kw in url.lower() for kw in keywords)
    features.append(1.0 if has_keyword else 0.0)

    return np.array(features, dtype=np.float32)


# ── 4. Main detector class ─────────────────────────────────────────────────────
class PhishingURLDetector:
    def __init__(self, model_path: str = None):
        self.model = None
        self.model_loaded = False
        self._load_model(model_path)

    def _load_model(self, model_path: str):
        if not model_path:
            print("[URLDetector] No model path — using rule-based fallback")
            return

        try:
            checkpoint = torch.load(model_path, map_location='cpu')

            if checkpoint.get('model_type') != 'phishing_url':
                print("[URLDetector] Wrong model type — using rule-based fallback")
                return

            input_dim = checkpoint.get('input_dim', 6)
            hidden_dim = checkpoint.get('hidden_dim', 256)

            self.model = PhishingLSTM(
                input_dim=input_dim,
                hidden_dim=hidden_dim,
                num_layers=2,
                output_dim=6
            )
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.eval()
            self.model_loaded = True

            print(f"[URLDetector] LSTM loaded — {checkpoint.get('attack_count', '?')} attacks, "
                  f"loss={checkpoint.get('final_loss', '?'):.4f}")

        except Exception as e:
            print(f"[URLDetector] Model load failed: {e} — using rule-based fallback")
            self.model = None
            self.model_loaded = False

    def predict(self, url: str) -> Dict:
        if self.model_loaded and self.model is not None:
            return self._lstm_predict(url)
        else:
            return self._rule_based_predict(url)

    def _lstm_predict(self, url: str) -> Dict:
        try:
            features = extract_features(url)
            x = torch.tensor(features).unsqueeze(0).unsqueeze(0)

            with torch.no_grad():
                logits = self.model(x)
                probs = torch.softmax(logits, dim=1)[0]

            predicted_class = int(torch.argmax(probs).item())
            phishing_score = float(sum(probs[i].item() for i in PHISHING_CLASSES))
            risk_score = round(phishing_score * 100, 1)

            # Apply rule-based boosters
            risk_score = self._apply_boosters(url, risk_score)

            return {
                'url': url,
                'is_phishing': predicted_class in PHISHING_CLASSES or risk_score >= 50,
                'risk_score': risk_score,
                'confidence': round(phishing_score, 4),
                'predicted_class': CLASS_LABELS[predicted_class],
                'severity': self._severity(risk_score),
                'recommendation': self._recommendation(risk_score),
                'detection_method': 'lstm'
            }

        except Exception as e:
            return self._rule_based_predict(url)

    def _apply_boosters(self, url: str, risk_score: float) -> float:
        url_lower = url.lower()

        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf',
                           '.login', '.verify', '.secure', '.account']
        if any(url_lower.endswith(tld) for tld in suspicious_tlds):
            risk_score += 20

        brands = ['paypal', 'amazon', 'google', 'apple', 'microsoft', 'facebook', 'netflix']
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            parts = hostname.split('.')
            domain = parts[-2] if len(parts) >= 2 else hostname
            for brand in brands:
                if brand in url_lower and brand not in domain:
                    risk_score += 25
                    break
        except Exception:
            pass

        if '@' in url:
            risk_score += 30

        if not url_lower.startswith('https') and any(kw in url_lower for kw in ['login', 'verify', 'account']):
            risk_score += 15

        return min(round(risk_score, 1), 100.0)

    def _rule_based_predict(self, url: str) -> Dict:
        risk_score = 0
        flags = []
        url_lower = url.lower()

        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            risk_score += 40
            flags.append("IP address in URL")

        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.login', '.verify']
        for tld in suspicious_tlds:
            if tld in url_lower:
                risk_score += 30
                flags.append(f"Suspicious TLD: {tld}")
                break

        keywords = ['verify', 'account', 'secure', 'update', 'confirm', 'login', 'paypal', 'suspended']
        for kw in keywords:
            if kw in url_lower:
                risk_score += 10
                flags.append(f"Phishing keyword: {kw}")

        if '@' in url:
            risk_score += 35
            flags.append("@ symbol in URL")

        try:
            parsed = urlparse(url)
            parts = (parsed.hostname or '').split('.')
            brands = ['paypal', 'amazon', 'google', 'apple', 'microsoft', 'facebook']
            domain = parts[-2] if len(parts) >= 2 else ''
            for brand in brands:
                if brand in url_lower and brand not in domain:
                    risk_score += 35
                    flags.append(f"Brand spoofing: {brand}")
                    break
        except Exception:
            pass

        if not url_lower.startswith('https') and any(kw in url_lower for kw in ['login', 'verify', 'account']):
            risk_score += 15
            flags.append("HTTP on sensitive page")

        risk_score = min(risk_score, 100)

        return {
            'url': url,
            'is_phishing': risk_score >= 50,
            'risk_score': float(risk_score),
            'confidence': round(risk_score / 100, 4),
            'flags': flags,
            'severity': self._severity(risk_score),
            'recommendation': self._recommendation(risk_score),
            'detection_method': 'rule_based'
        }

    def _severity(self, score: float) -> str:
        if score >= 85: return "CRITICAL"
        if score >= 70: return "HIGH"
        if score >= 50: return "MEDIUM"
        if score >= 30: return "LOW"
        return "MINIMAL"

    def _recommendation(self, score: float) -> str:
        if score >= 85: return "BLOCK - Clear phishing attempt"
        if score >= 70: return "BLOCK - High phishing risk"
        if score >= 50: return "WARN - Suspicious, verify before proceeding"
        if score >= 30: return "CAUTION - Some indicators present"
        return "SAFE - Appears legitimate"


# ── 5. Rule-based detector (fallback when ML fails) ──────────────────────────
class RuleBasedPhishingDetector:
    def __init__(self):
        self.suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf']
        self.phishing_keywords = ['verify', 'account', 'secure', 'update', 'confirm', 'login', 'paypal']
        self.url_shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co']

    def analyze(self, url: str) -> Dict:
        detector = PhishingURLDetector()
        return detector._rule_based_predict(url)