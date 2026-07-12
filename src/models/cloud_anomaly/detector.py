"""
Cloud Anomaly Detection Module
Detects unusual patterns in AWS cloud infrastructure
"""

import json
from typing import Dict, List, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import numpy as np
from sklearn.ensemble import IsolationForest


class CloudAnomalyDetector:
    """
    Detect anomalies in cloud infrastructure behavior
    Focuses on AWS CloudTrail logs and resource usage
    """
    
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        # Define suspicious activities
        self.high_risk_actions = {
            'DeleteBucket', 'DeleteTable', 'DeleteUser', 'DeleteRole',
            'PutBucketPolicy', 'PutUserPolicy', 'AttachUserPolicy',
            'CreateAccessKey', 'CreateUser', 'CreateRole',
            'ModifyDBInstance', 'AuthorizeSecurityGroupIngress'
        }
        
        self.data_exfiltration_actions = {
            'GetObject', 'DownloadDBLogFilePortion', 'GetBucketLocation',
            'ListBucket', 'HeadBucket'
        }
        
        # Unusual locations/IPs
        self.unusual_locations = ['RU', 'CN', 'KP', 'IR']  # Example
        
    def analyze_cloudtrail_logs(self, logs: List[Dict]) -> Dict[str, Any]:
        """
        Analyze AWS CloudTrail logs for anomalies
        
        Args:
            logs: List of CloudTrail event dictionaries
            
        Returns:
            Analysis results with detected anomalies
        """
        anomalies = []
        risk_score = 0
        flags = []
        
        # Statistics
        stats = {
            'total_events': len(logs),
            'unique_users': set(),
            'unique_ips': set(),
            'unique_actions': set(),
            'error_events': 0,
            'high_risk_actions': 0
        }
        
        # Analyze each log entry
        for log in logs:
            event_name = log.get('eventName', '')
            user_identity = log.get('userIdentity', {})
            source_ip = log.get('sourceIPAddress', '')
            error_code = log.get('errorCode', '')
            event_time = log.get('eventTime', '')
            
            # Update statistics
            stats['unique_actions'].add(event_name)
            if source_ip:
                stats['unique_ips'].add(source_ip)
            
            user_name = user_identity.get('userName', 'unknown')
            stats['unique_users'].add(user_name)
            
            if error_code:
                stats['error_events'] += 1
            
            # Check 1: High-risk actions
            if event_name in self.high_risk_actions:
                stats['high_risk_actions'] += 1
                anomalies.append({
                    'type': 'high_risk_action',
                    'severity': 'HIGH',
                    'event': event_name,
                    'user': user_name,
                    'time': event_time,
                    'description': f'High-risk action detected: {event_name}'
                })
                risk_score += 20
            
            # Check 2: Failed authentication attempts
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                anomalies.append({
                    'type': 'failed_auth',
                    'severity': 'MEDIUM',
                    'event': event_name,
                    'user': user_name,
                    'error': error_code,
                    'description': f'Failed authentication: {error_code}'
                })
                risk_score += 10
            
            # Check 3: Unusual source IP
            if self._is_unusual_ip(source_ip):
                anomalies.append({
                    'type': 'unusual_ip',
                    'severity': 'HIGH',
                    'ip': source_ip,
                    'event': event_name,
                    'description': f'Access from unusual location: {source_ip}'
                })
                risk_score += 25
            
            # Check 4: Potential data exfiltration
            if event_name in self.data_exfiltration_actions:
                anomalies.append({
                    'type': 'data_exfiltration',
                    'severity': 'MEDIUM',
                    'event': event_name,
                    'user': user_name,
                    'description': f'Potential data access: {event_name}'
                })
                risk_score += 15
        
        # Check 5: Unusual activity patterns
        pattern_anomalies = self._detect_pattern_anomalies(logs)
        anomalies.extend(pattern_anomalies)
        risk_score += len(pattern_anomalies) * 15
        
        # Check 6: Time-based anomalies
        time_anomalies = self._detect_time_anomalies(logs)
        anomalies.extend(time_anomalies)
        risk_score += len(time_anomalies) * 10
        
        # Cap risk score
        risk_score = min(risk_score, 100)
        
        # Convert sets to lists for JSON serialization
        stats['unique_users'] = list(stats['unique_users'])
        stats['unique_ips'] = list(stats['unique_ips'])
        stats['unique_actions'] = list(stats['unique_actions'])
        
        return {
            'has_anomalies': len(anomalies) > 0,
            'risk_score': risk_score,
            'severity': self._get_severity(risk_score),
            'anomaly_count': len(anomalies),
            'anomalies': anomalies,
            'statistics': stats,
            'recommendation': self._get_recommendation(risk_score)
        }
    
    def analyze_resource_usage(self, metrics: Dict[str, List[float]]) -> Dict[str, Any]:
        """
        Analyze resource usage patterns for anomalies
        
        Args:
            metrics: Dictionary of metric names to values
                    Example: {'cpu_usage': [10, 12, 15, 95, 12], 
                             'network_out': [100, 120, 110, 5000, 115]}
        
        Returns:
            Analysis results
        """
        anomalies = []
        risk_score = 0
        
        for metric_name, values in metrics.items():
            if len(values) < 5:
                continue
            
            # Calculate statistics
            mean = np.mean(values)
            std = np.std(values)
            
            # Check for outliers (values > 3 standard deviations)
            outliers = []
            for i, value in enumerate(values):
                if abs(value - mean) > 3 * std:
                    outliers.append({
                        'index': i,
                        'value': float(value),
                        'mean': float(mean),
                        'std': float(std)
                    })
            
            if outliers:
                anomalies.append({
                    'type': 'resource_spike',
                    'metric': metric_name,
                    'severity': 'HIGH' if len(outliers) > 1 else 'MEDIUM',
                    'outliers': outliers,
                    'description': f'Unusual {metric_name} detected: {len(outliers)} outliers'
                })
                risk_score += 20 if len(outliers) > 1 else 10
            
            # Check for sustained high usage
            if mean > 80:  # 80% threshold
                anomalies.append({
                    'type': 'sustained_high_usage',
                    'metric': metric_name,
                    'severity': 'MEDIUM',
                    'average': float(mean),
                    'description': f'Sustained high {metric_name}: {mean:.2f}%'
                })
                risk_score += 15
        
        risk_score = min(risk_score, 100)
        
        return {
            'has_anomalies': len(anomalies) > 0,
            'risk_score': risk_score,
            'severity': self._get_severity(risk_score),
            'anomalies': anomalies,
            'recommendation': self._get_recommendation(risk_score)
        }
    
    def detect_unusual_access_patterns(self, access_logs: List[Dict]) -> Dict[str, Any]:
        """
        Detect unusual access patterns
        
        Args:
            access_logs: List of access log entries
                        Each entry: {'user': str, 'timestamp': str, 'action': str}
        
        Returns:
            Analysis results
        """
        anomalies = []
        risk_score = 0
        
        # Group by user
        user_actions = defaultdict(list)
        for log in access_logs:
            user = log.get('user', 'unknown')
            user_actions[user].append(log)
        
        # Analyze each user's behavior
        for user, actions in user_actions.items():
            # Check 1: Excessive actions in short time
            if len(actions) > 100:  # Threshold
                anomalies.append({
                    'type': 'excessive_activity',
                    'user': user,
                    'severity': 'HIGH',
                    'action_count': len(actions),
                    'description': f'User {user} performed {len(actions)} actions'
                })
                risk_score += 25
            
            # Check 2: Unusual action diversity
            unique_actions = len(set(a.get('action', '') for a in actions))
            if unique_actions > 20:  # Unusual diversity
                anomalies.append({
                    'type': 'unusual_diversity',
                    'user': user,
                    'severity': 'MEDIUM',
                    'unique_actions': unique_actions,
                    'description': f'User {user} performed {unique_actions} different actions'
                })
                risk_score += 15
            
            # Check 3: Access during unusual hours
            unusual_time_count = 0
            for action in actions:
                timestamp = action.get('timestamp', '')
                if self._is_unusual_time(timestamp):
                    unusual_time_count += 1
            
            if unusual_time_count > len(actions) * 0.3:  # >30% unusual time
                anomalies.append({
                    'type': 'unusual_time_access',
                    'user': user,
                    'severity': 'MEDIUM',
                    'unusual_count': unusual_time_count,
                    'total_count': len(actions),
                    'description': f'User {user} accessed during unusual hours'
                })
                risk_score += 20
        
        risk_score = min(risk_score, 100)
        
        return {
            'has_anomalies': len(anomalies) > 0,
            'risk_score': risk_score,
            'severity': self._get_severity(risk_score),
            'anomalies': anomalies,
            'users_analyzed': len(user_actions),
            'recommendation': self._get_recommendation(risk_score)
        }
    
    def _is_unusual_ip(self, ip: str) -> bool:
        """Check if IP is from unusual location"""
        # Simplified check - in production, use GeoIP database
        if not ip or ip == 'unknown':
            return False
        
        # Check for private IPs (these are normal)
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
            return False
        
        # In production: Use GeoIP to check country
        # For now, just flag non-private IPs as potentially unusual
        return True
    
    def _detect_pattern_anomalies(self, logs: List[Dict]) -> List[Dict]:
        """Detect unusual patterns in logs"""
        anomalies = []
        
        # Check for burst activity
        if len(logs) > 0:
            # Group by time windows (e.g., per minute)
            time_buckets = defaultdict(int)
            for log in logs:
                event_time = log.get('eventTime', '')
                if event_time:
                    # Extract minute
                    minute = event_time[:16]  # YYYY-MM-DDTHH:MM
                    time_buckets[minute] += 1
            
            # Check for bursts
            for time_window, count in time_buckets.items():
                if count > 50:  # Threshold
                    anomalies.append({
                        'type': 'activity_burst',
                        'severity': 'HIGH',
                        'time_window': time_window,
                        'event_count': count,
                        'description': f'Activity burst: {count} events in one minute'
                    })
        
        return anomalies
    
    def _detect_time_anomalies(self, logs: List[Dict]) -> List[Dict]:
        """Detect access during unusual times"""
        anomalies = []
        
        unusual_hour_count = 0
        for log in logs:
            event_time = log.get('eventTime', '')
            if self._is_unusual_time(event_time):
                unusual_hour_count += 1
        
        if unusual_hour_count > len(logs) * 0.2:  # >20% unusual time
            anomalies.append({
                'type': 'unusual_time_pattern',
                'severity': 'MEDIUM',
                'unusual_count': unusual_hour_count,
                'total_count': len(logs),
                'description': f'{unusual_hour_count} events during unusual hours'
            })
        
        return anomalies
    
    def _is_unusual_time(self, timestamp: str) -> bool:
        """Check if timestamp is during unusual hours (e.g., night)"""
        if not timestamp:
            return False
        
        try:
            # Parse timestamp
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour
            
            # Consider 11 PM - 6 AM as unusual
            return hour >= 23 or hour < 6
        except:
            return False
    
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
            return "IMMEDIATE ACTION REQUIRED - Potential security breach detected"
        elif risk_score >= 60:
            return "INVESTIGATE URGENTLY - Multiple suspicious activities detected"
        elif risk_score >= 40:
            return "REVIEW RECOMMENDED - Unusual patterns detected"
        elif risk_score >= 20:
            return "MONITOR - Minor anomalies detected"
        else:
            return "NORMAL - No significant anomalies detected"
