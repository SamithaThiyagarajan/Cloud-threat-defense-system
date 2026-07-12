"""
Attack Simulation Engine - Generates synthetic attack variants
"""

import numpy as np
import random
import sys
import os
from datetime import datetime, timedelta
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.memory.db_manager import AttackMemoryDB

class AttackSimulator:
    """
    Generates realistic attack variants for training
    """
    
    def __init__(self, memory_db=None):
        self.memory = memory_db or AttackMemoryDB()
        self.simulations_generated = 0
        
        # Mutation parameters
        self.url_mutations = {
            'homograph': ['0→o', '1→l', '3→e', '4→a', '5→s'],
            'tld_swaps': ['.com', '.org', '.net', '.xyz', '.top', '.club'],
            'subdomain_injections': ['login', 'secure', 'verify', 'account', 'update'],
            'path_variations': ['/login', '/verify', '/confirm', '/secure', '/auth']
        }
        
        self.email_mutations = {
            'urgency_phrases': [
                "URGENT: Your account will be suspended!",
                "IMMEDIATE ACTION REQUIRED",
                "Your account has been compromised",
                "Security alert: Unusual activity detected",
                "Final warning before account closure"
            ],
            'threat_phrases': [
                "Unauthorized access attempt",
                "Suspicious login detected",
                "Account limited due to unusual activity",
                "Security breach alert",
                "Immediate verification needed"
            ],
            'sender_domains': [
                'paypal-security.com',
                'amazon-verify.net',
                'apple-id.xyz',
                'microsoft-support.top',
                'bank-account.club'
            ]
        }
        
        print("🎲 Attack Simulator initialized")
    
    def simulate_from_attack(self, attack_id=None, attack_type=None, count=10):
        """
        Generate simulated attacks based on a real attack
        
        Args:
            attack_id: Specific attack to simulate from
            attack_type: Type of attack to simulate (if no ID)
            count: Number of simulations to generate
        """
        
        # Get source attack
        if attack_id:
            # Get specific attack
            attacks = self.memory.get_attacks_by_type('phishing_url', limit=100)
            source_attack = next((a for a in attacks if a.get('id') == attack_id), None)
            if not source_attack:
                return {"error": f"Attack ID {attack_id} not found"}
        elif attack_type:
            # Get latest attack of this type
            attacks = self.memory.get_attacks_by_type(attack_type, limit=1)
            source_attack = attacks[0] if attacks else None
            if not source_attack:
                return {"error": f"No {attack_type} attacks found"}
        else:
            return {"error": "Must provide attack_id or attack_type"}
        
        attack_type = source_attack.get('attack_type', 'unknown')
        features = source_attack.get('feature_vector', [])
        
        simulations = []
        
        # Generate variants based on attack type
        if attack_type == 'phishing_url':
            simulations = self._simulate_url_variants(source_attack, count)
        elif attack_type == 'phishing_email':
            simulations = self._simulate_email_variants(source_attack, count)
        elif attack_type == 'cloud_anomaly':
            simulations = self._simulate_cloud_variants(source_attack, count)
        elif attack_type == 'deepfake':
            simulations = self._simulate_deepfake_variants(source_attack, count)
        else:
            simulations = self._simulate_generic_variants(source_attack, count)
        
        # Store simulations in memory
        stored_ids = []
        for sim in simulations:
            sim_id = self.memory.store_simulation(sim)
            if sim_id:
                stored_ids.append(sim_id)
                self.simulations_generated += 1
        
        return {
            'source_attack_id': source_attack.get('id'),
            'attack_type': attack_type,
            'generated': len(simulations),
            'stored': len(stored_ids),
            'simulation_ids': stored_ids,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _simulate_url_variants(self, attack, count):
        """Generate URL phishing variants"""
        
        # Extract base URL if available
        raw = attack.get('raw_indicators', {})
        base_url = raw.get('url', 'http://example.com/login')
        
        simulations = []
        features = attack.get('feature_vector', [0]*6)
        
        for i in range(count):
            # Mutate URL
            mutated_url = self._mutate_url(base_url)
            
            # Mutate features slightly (add random noise)
            mutated_features = features + np.random.normal(0, 0.1, len(features))
            mutated_features = np.clip(mutated_features, 0, 1).tolist()
            
            # Calculate quality score (how realistic is this)
            quality = random.uniform(0.6, 0.95)
            
            sim = {
                'based_on_attack_id': attack.get('id'),
                'attack_type': 'phishing_url',
                'feature_vector': mutated_features,
                'raw_content': mutated_url,
                'quality_score': quality,
                'simulation_type': 'url_mutation',
                'timestamp': datetime.utcnow().isoformat()
            }
            simulations.append(sim)
        
        return simulations
    
    def _mutate_url(self, url):
        """Create realistic URL variations"""
        
        import re
        
        # Homograph substitutions (look similar but different)
        if random.random() < 0.3:
            url = url.replace('o', '0')
            url = url.replace('l', '1')
            url = url.replace('e', '3')
        
        # Change TLD
        if random.random() < 0.4:
            current_tld = re.search(r'\.[a-z]+$', url)
            if current_tld:
                new_tld = random.choice(self.url_mutations['tld_swaps'])
                url = url[:current_tld.start()] + new_tld
        
        # Add subdomain
        if random.random() < 0.3:
            sub = random.choice(self.url_mutations['subdomain_injections'])
            if '://' in url:
                parts = url.split('://')
                url = parts[0] + '://' + sub + '.' + parts[1]
            else:
                url = sub + '.' + url
        
        # Add path variation
        if random.random() < 0.5:
            path = random.choice(self.url_mutations['path_variations'])
            url = url.rstrip('/') + path
        
        return url
    
    def _simulate_email_variants(self, attack, count):
        """Generate email phishing variants"""
        
        raw = attack.get('raw_indicators', {})
        base_content = raw.get('content', '')
        base_sender = raw.get('sender', '')
        
        simulations = []
        features = attack.get('feature_vector', [0]*11)
        
        for i in range(count):
            # Mutate content
            mutated_content = self._mutate_email_content(base_content)
            
            # Mutate sender
            mutated_sender = self._mutate_sender(base_sender)
            
            # Mutate features
            mutated_features = features + np.random.normal(0, 0.1, len(features))
            mutated_features = np.clip(mutated_features, 0, 1).tolist()
            
            sim = {
                'based_on_attack_id': attack.get('id'),
                'attack_type': 'phishing_email',
                'feature_vector': mutated_features,
                'raw_content': f"From: {mutated_sender}\n\n{mutated_content}",
                'quality_score': random.uniform(0.5, 0.9),
                'simulation_type': 'email_mutation',
                'timestamp': datetime.utcnow().isoformat()
            }
            simulations.append(sim)
        
        return simulations
    
    def _mutate_email_content(self, content):
        """Create realistic email variations"""
        
        if not content:
            # Generate from templates
            urgency = random.choice(self.email_mutations['urgency_phrases'])
            threat = random.choice(self.email_mutations['threat_phrases'])
            return f"{urgency}\n\n{threat}\n\nClick here to verify: [link]"
        
        # Simple mutations (in production, use NLP)
        lines = content.split('\n')
        mutated = []
        for line in lines:
            if 'urgent' in line.lower() or 'immediate' in line.lower():
                # Replace with different urgency phrase
                line = random.choice(self.email_mutations['urgency_phrases'])
            elif 'http' in line:
                # Replace link
                line = f"Click here: http://verify-{random.randint(1000,9999)}.xyz"
            mutated.append(line)
        
        return '\n'.join(mutated)
    
    def _mutate_sender(self, sender):
        """Create realistic sender variations"""
        
        if not sender or '@' not in sender:
            domain = random.choice(self.email_mutations['sender_domains'])
            return f"security@{domain}"
        
        # Mutate domain
        if '@' in sender:
            local, domain = sender.split('@')
            new_domain = random.choice(self.email_mutations['sender_domains'])
            return f"{local}@{new_domain}"
        
        return sender
    
    def _simulate_cloud_variants(self, attack, count):
        """Generate cloud anomaly variants"""
        
        features = attack.get('feature_vector', [0]*8)
        simulations = []
        
        for i in range(count):
            # Create different cloud attack patterns
            attack_types = ['DeleteBucket', 'CreateUser', 'GetSecretValue', 
                           'PutBucketPolicy', 'TerminateInstances']
            
            mutated_features = features + np.random.normal(0, 0.15, len(features))
            mutated_features = np.clip(mutated_features, 0, 1).tolist()
            
            sim_content = {
                'eventName': random.choice(attack_types),
                'userIdentity': {'arn': f'user/attacker{random.randint(1,100)}'},
                'sourceIPAddress': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'eventTime': datetime.utcnow().isoformat() + 'Z'
            }
            
            sim = {
                'based_on_attack_id': attack.get('id'),
                'attack_type': 'cloud_anomaly',
                'feature_vector': mutated_features,
                'raw_content': str(sim_content),
                'quality_score': random.uniform(0.4, 0.8),
                'simulation_type': 'cloud_mutation',
                'timestamp': datetime.utcnow().isoformat()
            }
            simulations.append(sim)
        
        return simulations
    
    def _simulate_deepfake_variants(self, attack, count):
        """Generate deepfake variants"""
        
        features = attack.get('feature_vector', [0]*10)
        simulations = []
        
        for i in range(count):
            mutated_features = features + np.random.normal(0, 0.2, len(features))
            mutated_features = np.clip(mutated_features, 0, 1).tolist()
            
            sim = {
                'based_on_attack_id': attack.get('id'),
                'attack_type': 'deepfake',
                'feature_vector': mutated_features,
                'raw_content': f"Simulated deepfake image variant {i+1}",
                'quality_score': random.uniform(0.3, 0.7),
                'simulation_type': 'deepfake_mutation',
                'timestamp': datetime.utcnow().isoformat()
            }
            simulations.append(sim)
        
        return simulations
    
    def _simulate_generic_variants(self, attack, count):
        """Generic feature mutation for any attack type"""
        
        features = attack.get('feature_vector', [0]*6)
        simulations = []
        
        for i in range(count):
            mutated_features = features + np.random.normal(0, 0.1, len(features))
            mutated_features = np.clip(mutated_features, 0, 1).tolist()
            
            sim = {
                'based_on_attack_id': attack.get('id'),
                'attack_type': attack.get('attack_type', 'unknown'),
                'feature_vector': mutated_features,
                'raw_content': f"Generic simulation {i+1}",
                'quality_score': random.uniform(0.5, 0.9),
                'timestamp': datetime.utcnow().isoformat()
            }
            simulations.append(sim)
        
        return simulations
    
    def generate_bulk_simulations(self, count_per_type=20):
        """Generate simulations for all attack types"""
        
        results = {}
        
        for attack_type in ['phishing_url', 'phishing_email', 'cloud_anomaly', 'deepfake']:
            # Get latest attack of this type
            attacks = self.memory.get_attacks_by_type(attack_type, limit=1)
            if attacks:
                result = self.simulate_from_attack(
                    attack_id=attacks[0].get('id'),
                    count=count_per_type
                )
                results[attack_type] = result
            else:
                results[attack_type] = {'error': f'No {attack_type} attacks found'}
        
        return results
    
    def get_simulation_stats(self):
        """Get statistics about generated simulations"""
        
        # This would query the database in production
        return {
            'total_simulations_generated': self.simulations_generated,
            'by_type': {
                'phishing_url': 'TODO: query database',
                'phishing_email': 'TODO: query database',
                'cloud_anomaly': 'TODO: query database',
                'deepfake': 'TODO: query database'
            }
        }