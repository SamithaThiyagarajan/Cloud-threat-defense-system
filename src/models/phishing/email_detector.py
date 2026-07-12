"""
Email Phishing Detection Module
Uses NLP and pattern matching to detect phishing emails
"""

import re
from typing import Dict, List
from email.parser import Parser
from email import policy


class EmailPhishingDetector:
    """
    Email phishing detector using NLP and rule-based analysis
    """

    def __init__(self):
        self.urgent_phrases = [
            'urgent action required', 'immediate action', 'act now', 'limited time',
            'expires today', 'last chance', 'final notice', 'respond immediately',
            'account will be closed', 'suspended', 'verify immediately'
        ]

        self.threat_phrases = [
            'account has been', 'unusual activity', 'suspicious activity',
            'unauthorized access', 'security alert', 'fraud alert',
            'your account has been locked', 'verify your identity'
        ]

        self.financial_lures = [
            'claim your reward', 'you\'ve won', 'refund available',
            'tax refund', 'inheritance', 'lottery', 'prize',
            'free money', 'cash reward', 'unclaimed funds'
        ]

        self.credential_requests = [
            'confirm your password', 'update your password', 'verify your account',
            'confirm your identity', 'social security number', 'ssn',
            'credit card', 'bank account', 'routing number', 'cvv'
        ]

        self.generic_greetings = [
            'dear customer', 'dear user', 'dear member', 'dear valued',
            'hello customer', 'attention user'
        ]

        self.common_brands = {
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

    def analyze_email(self, email_content: str, sender: str = None,
                      subject: str = None) -> Dict[str, any]:
        """
        Analyze email for phishing indicators

        Args:
            email_content: Email body text
            sender: Sender email address (optional)
            subject: Email subject (optional)

        Returns:
            Analysis results with risk assessment
        """
        risk_score = 0
        flags = []
        threat_categories = []  # Track which threat categories fired

        indicators = {
            'urgency': 0,
            'threats': 0,
            'financial_lures': 0,
            'credential_requests': 0,
            'generic_greeting': False,
            'suspicious_links': 0,
            'sender_spoofing': False,
            'poor_grammar': False
        }

        # Guard against None inputs
        email_lower = (email_content or "").lower()
        subject_lower = (subject or "").lower()

        # Check 1: Urgency tactics
        urgency_count = sum(1 for phrase in self.urgent_phrases
                            if phrase in email_lower or phrase in subject_lower)
        if urgency_count > 0:
            indicators['urgency'] = urgency_count
            risk_score += urgency_count * 15
            flags.append(f"Urgency tactics detected ({urgency_count} instances)")
            threat_categories.append("Urgency/Pressure")

        # Check 2: Threat/fear tactics
        threat_count = sum(1 for phrase in self.threat_phrases
                           if phrase in email_lower)
        if threat_count > 0:
            indicators['threats'] = threat_count
            risk_score += threat_count * 20
            flags.append(f"Threat/fear tactics detected ({threat_count} instances)")
            threat_categories.append("Fear Tactics")

        # Check 3: Financial lures
        financial_count = sum(1 for phrase in self.financial_lures
                              if phrase in email_lower)
        if financial_count > 0:
            indicators['financial_lures'] = financial_count
            risk_score += financial_count * 25
            flags.append(f"Financial lures detected ({financial_count} instances)")
            threat_categories.append("Financial Lure")

        # Check 4: Credential requests
        credential_count = sum(1 for phrase in self.credential_requests
                               if phrase in email_lower)
        if credential_count > 0:
            indicators['credential_requests'] = credential_count
            risk_score += credential_count * 30
            flags.append(f"Credential requests detected ({credential_count} instances)")
            threat_categories.append("Credential Harvesting")

        # Check 5: Generic greetings
        has_generic = any(greeting in email_lower for greeting in self.generic_greetings)
        if has_generic:
            indicators['generic_greeting'] = True
            risk_score += 10
            flags.append("Generic greeting used (not personalized)")

        # Check 6: Suspicious links
        suspicious_links = self._find_suspicious_links(email_content or "")
        if suspicious_links > 0:
            indicators['suspicious_links'] = suspicious_links
            risk_score += suspicious_links * 15
            flags.append(f"Suspicious links detected ({suspicious_links})")
            threat_categories.append("Suspicious Links")

        # Check 7: Sender spoofing
        if sender:
            is_spoofed = self._check_sender_spoofing(sender, email_content or "")
            if is_spoofed:
                indicators['sender_spoofing'] = True
                risk_score += 35
                flags.append("Potential sender spoofing detected")
                threat_categories.append("Sender Spoofing")

        # Check 8: Poor grammar/spelling
        grammar_issues = self._check_grammar_issues(email_content or "")
        if grammar_issues > 3:
            indicators['poor_grammar'] = True
            risk_score += 15
            flags.append(f"Grammar/spelling issues detected ({grammar_issues})")

        # Check 9: Excessive punctuation
        excessive_punct = (email_content or "").count('!') + (email_content or "").count('?')
        if excessive_punct > 5:
            risk_score += 10
            flags.append("Excessive punctuation detected")

        # Cap risk score at 100
        risk_score = min(risk_score, 100)

        # Derive a human-readable threat type from fired categories
        threat_type = self._derive_threat_type(threat_categories)

        return {
            'is_phishing': risk_score >= 60,
            'risk_score': risk_score,
            'confidence': risk_score / 100,
            'severity': self._get_severity(risk_score),
            'threat_type': threat_type,           # ← now always present, never None
            'threat_categories': threat_categories,
            'flags': flags,
            'indicators': indicators,
            'recommendation': self._get_recommendation(risk_score),
            'analysis': {
                'sender': sender,
                'subject': subject,
                'content_length': len(email_content or ""),
                'link_count': len(re.findall(r'https?://', email_content or ""))
            }
        }

    def _derive_threat_type(self, threat_categories: List[str]) -> str:
        """
        Derive a single threat type label from all fired categories.
        Priority order: most specific/dangerous first.
        """
        if not threat_categories:
            return "Suspicious Email"

        # Priority-ordered mapping
        priority = [
            "Credential Harvesting",
            "Sender Spoofing",
            "Financial Lure",
            "Suspicious Links",
            "Fear Tactics",
            "Urgency/Pressure",
        ]

        for p in priority:
            if p in threat_categories:
                return f"Phishing Email ({p})"

        # Fallback: join all categories
        return f"Phishing Email ({', '.join(threat_categories)})"

    def _find_suspicious_links(self, content: str) -> int:
        """Find suspicious links in email content"""
        # Broader pattern: catches malformed URLs like http:fake-paypal.login
        url_pattern = r'https?://[^\s<>"]+|https?:[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, content)

        suspicious_count = 0
        for url in urls:
            url_lower = url.lower()
            # IP address in URL
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                suspicious_count += 1
            # Suspicious TLDs
            elif any(url_lower.endswith(tld) for tld in ['.xyz', '.top', '.tk', '.ml']):
                suspicious_count += 1
            # URL shorteners
            elif any(shortener in url_lower for shortener in ['bit.ly', 'tinyurl', 'goo.gl']):
                suspicious_count += 1
            # Malformed/no-slash URLs (e.g. http:fake-paypal.login)
            elif re.match(r'https?:[^/]', url_lower):
                suspicious_count += 1
            # Brand name in URL but not legitimate domain
            else:
                for brand, legit_domain in self.common_brands.items():
                    if brand in url_lower and legit_domain not in url_lower:
                        suspicious_count += 1
                        break

        return suspicious_count

    def _check_sender_spoofing(self, sender: str, content: str) -> bool:
        """Check if sender might be spoofed"""
        content_lower = content.lower()
        sender_lower = sender.lower()

        for brand, legitimate_domain in self.common_brands.items():
            if brand in content_lower and legitimate_domain not in sender_lower:
                return True

        return False

    def _check_grammar_issues(self, content: str) -> int:
        """Simple grammar/spelling check"""
        issues = 0
        mistakes = [
            r'\bi\s+am\s+',
            r'\s+i\s+',
            r'[a-z]\.[A-Z]',
            r'\s{2,}',
        ]
        for pattern in mistakes:
            issues += len(re.findall(pattern, content))
        return issues

    def _get_severity(self, risk_score: float) -> str:
        """Get severity level"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def _get_recommendation(self, risk_score: float) -> str:
        """Get recommendation"""
        if risk_score >= 80:
            return "DELETE IMMEDIATELY - Clear phishing attempt"
        elif risk_score >= 60:
            return "QUARANTINE - Do not click any links or provide information"
        elif risk_score >= 40:
            return "SUSPICIOUS - Verify sender through official channels"
        elif risk_score >= 20:
            return "EXERCISE CAUTION - Be wary of requests for information"
        else:
            return "APPEARS LEGITIMATE - Standard security practices apply"

    def analyze_batch(self, emails: List[Dict]) -> List[Dict]:
        """
        Analyze multiple emails at once

        Args:
            emails: List of email dictionaries with 'content', 'sender', 'subject'

        Returns:
            List of analysis results
        """
        results = []
        for email in emails:
            result = self.analyze_email(
                email.get('content', ''),
                email.get('sender'),
                email.get('subject')
            )
            result['email_id'] = email.get('id', 'unknown')
            results.append(result)
        return results


class PhishingEmailParser:
    """
    Parse raw email messages for analysis
    """

    @staticmethod
    def parse_raw_email(raw_email: str) -> Dict[str, str]:
        """
        Parse raw email message

        Args:
            raw_email: Raw email content

        Returns:
            Dictionary with parsed email components
        """
        try:
            msg = Parser(policy=policy.default).parsestr(raw_email)

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode('utf-8', errors='ignore')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode('utf-8', errors='ignore')
                elif isinstance(msg.get_payload(), str):
                    # Fallback: payload already a string (not encoded)
                    body = msg.get_payload()

            return {
                'sender': msg.get('From', ''),
                'subject': msg.get('Subject', ''),
                'date': msg.get('Date', ''),
                'to': msg.get('To', ''),
                'content': body,
                'headers': dict(msg.items())
            }
        except Exception as e:
            return {
                'error': str(e),
                'sender': '',
                'subject': '',
                'content': raw_email  # fallback to raw so detection still runs
            }

    @staticmethod
    def extract_headers(raw_email: str) -> Dict[str, str]:
        """Extract email headers for additional analysis"""
        msg = Parser(policy=policy.default).parsestr(raw_email)
        return dict(msg.items())