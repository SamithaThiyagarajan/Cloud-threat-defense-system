"""
Learning Engine - LSTM-based attack pattern learning
"""

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from datetime import datetime, timedelta
import sys
import os
import json
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.memory.db_manager import AttackMemoryDB

class AttackSequenceDataset(Dataset):
    """Dataset for attack sequences"""
    
    def __init__(self, sequences, seq_length=5):
        self.sequences = sequences
        self.seq_length = seq_length
        
    def __len__(self):
        return max(0, len(self.sequences) - self.seq_length)
    
    def __getitem__(self, idx):
        x = self.sequences[idx:idx + self.seq_length]
        y = self.sequences[idx + self.seq_length]
        return torch.FloatTensor(x), torch.FloatTensor(y)

class LSTMAttackPredictor(nn.Module):
    """LSTM model for predicting attack evolution"""
    
    def __init__(self, input_dim, hidden_dim=64, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(
            input_dim, 
            hidden_dim, 
            num_layers, 
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0
        )
        self.fc = nn.Linear(hidden_dim, input_dim)
        self.dropout = nn.Dropout(0.2)
        
    def forward(self, x):
        # x shape: (batch_size, seq_length, input_dim)
        lstm_out, (hidden, cell) = self.lstm(x)
        
        # Take the last hidden state
        # hidden shape: (num_layers, batch_size, hidden_dim)
        last_hidden = hidden[-1]  # Get last layer's hidden state
        last_hidden = self.dropout(last_hidden)
        output = self.fc(last_hidden)
        return output
class AttackLearningEngine:
    """
    Learns patterns from attack memory and predicts future attacks
    """
    
    def __init__(self, memory_db=None):
        self.memory = memory_db or AttackMemoryDB()
        self.models = {}
        self.trained = False
        
        # Model parameters
        self.seq_length = 5  # Look at last 5 attacks
        self.hidden_dim = 256
        self.num_epochs = 50
        self.learning_rate = 0.001
        self.min_attacks_required = 10  # Minimum attacks needed for training
        
        # Expected dimensions per attack type
        self.expected_dims = {
            'phishing_url': 6,
            'phishing_email': 11,
            'cloud_anomaly': 8,
            'deepfake': 10
        }
        
        print("🧠 Learning Engine initialized")
    
    def _normalize_features(self, features, attack_type):
        """Ensure features have correct dimensions and are valid"""
        expected = self.expected_dims.get(attack_type, 6)
        
        # Handle None or empty
        if features is None:
            return [0.0] * expected
        
        # Handle string JSON
        if isinstance(features, str):
            try:
                features = json.loads(features)
            except:
                features = [0.0] * expected
        
        # Handle numpy arrays
        if isinstance(features, np.ndarray):
            features = features.tolist()
        
        # Ensure list
        if not isinstance(features, list):
            features = [0.0] * expected
        
        # Convert all values to float
        features = [float(x) if x is not None else 0.0 for x in features]
        
        # Pad or truncate
        if len(features) < expected:
            features = features + [0.0] * (expected - len(features))
        elif len(features) > expected:
            features = features[:expected]
        
        # Ensure values are in [0, 1] range
        features = [max(0.0, min(1.0, x)) for x in features]
        
        return features
    
    def prepare_sequences(self, attack_type='phishing_url'):
        """Prepare attack sequences for training"""
        
        # Get attacks from memory
        attacks = self.memory.get_attacks_by_type(attack_type, limit=20000000)
        
        if len(attacks) < self.min_attacks_required:
            print(f"⚠️ Not enough {attack_type} attacks for training (need {self.min_attacks_required}, have {len(attacks)})")
            return None, None
        
        # Sort by timestamp
        try:
            attacks.sort(key=lambda x: x.get('timestamp', ''))
        except:
            print(f"⚠️ Error sorting attacks by timestamp")
            return None, None
        
        # Extract and normalize feature vectors
        sequences = []
        valid_attacks = []
        
        for attack in attacks:
            features = attack.get('feature_vector')
            normalized = self._normalize_features(features, attack_type)
            sequences.append(normalized)
            valid_attacks.append(attack)
        
        if len(sequences) < self.seq_length + 1:
            print(f"⚠️ Not enough sequences after normalization (need {self.seq_length+1}, have {len(sequences)})")
            return None, None
        
        print(f"📊 Prepared {len(sequences)} feature vectors for {attack_type} (each {len(sequences[0])}-dim)")
        
        return sequences, valid_attacks
    
    def train(self, attack_type='phishing_url'):
        """Train LSTM model on attack sequences"""
        
        sequences, attacks = self.prepare_sequences(attack_type)
        
        if sequences is None:
            return False
        
        # Convert to numpy array
        try:
            sequences = np.array(sequences, dtype=np.float32)
            print(f"✅ Converted to array with shape: {sequences.shape}")
        except Exception as e:
            print(f"❌ Error converting sequences: {e}")
            return False

        # Normalize features (clip to 0-1 range)
        sequences = np.clip(sequences, 0, 1)
        
        # Create dataset
        dataset = AttackSequenceDataset(sequences, self.seq_length)
        
        if len(dataset) == 0:
            print(f"⚠️ Not enough sequences for {attack_type}")
            return False
        
        dataloader = DataLoader(dataset, batch_size=4, shuffle=True)
        
        # Initialize model
        input_dim = sequences.shape[1]
        model = LSTMAttackPredictor(input_dim, self.hidden_dim)
        
        # Loss and optimizer
        criterion = nn.MSELoss()
        optimizer = optim.Adam(model.parameters(), lr=self.learning_rate)
        
        print(f"🚀 Training LSTM on {len(dataset)} sequences...")
        
        # Training loop
        model.train()
        for epoch in range(self.num_epochs):
            total_loss = 0
            for batch_x, batch_y in dataloader:
                optimizer.zero_grad()
                output = model(batch_x)
                loss = criterion(output, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            if (epoch + 1) % 10 == 0:
                avg_loss = total_loss / len(dataloader)
                print(f"  Epoch {epoch+1}/{self.num_epochs}, Loss: {avg_loss:.4f}")
        
        # Save model info (move to CPU for saving)
        model.cpu()
        self.models[attack_type] = {
            'model': model,
            'input_dim': input_dim,
            'last_sequence': sequences[-self.seq_length:].tolist(),
            'attack_count': len(attacks),
            'trained_at': datetime.utcnow().isoformat()
        }
        
        self.trained = True
        print(f"✅ Model trained for {attack_type} with {len(attacks)} attacks")
        
        return True    
    def predict_next_attack(self, attack_type='phishing_url'):
        """Predict the next attack's feature vector"""
        
        if attack_type not in self.models:
            print(f"⚠️ No trained model for {attack_type}")
            return None
        
        model_info = self.models[attack_type]
        model = model_info['model']
        last_sequence = model_info['last_sequence']
        
        # Prepare input
        model.eval()
        with torch.no_grad():
            input_tensor = torch.FloatTensor(last_sequence).unsqueeze(0)
            prediction = model(input_tensor)
            predicted_features = prediction.squeeze().numpy()
        
        # Clip to valid range
        predicted_features = np.clip(predicted_features, 0, 1)
        
        return predicted_features
    
    def detect_attack_campaign(self, attack_type='phishing_url', window_hours=24):
        """Detect if attacks are part of a campaign"""
        
        attacks = self.memory.get_attacks_by_type(attack_type, limit=50)
        
        if len(attacks) < 3:
            return None
        
        # Sort by time
        try:
            attacks.sort(key=lambda x: x.get('timestamp', ''))
        except:
            return None
        
        # Calculate time differences
        timestamps = []
        for attack in attacks[-10:]:  # Last 10 attacks
            try:
                ts_str = attack.get('timestamp', '')
                if ts_str:
                    # Handle different timestamp formats
                    ts_str = ts_str.replace('Z', '+00:00')
                    if '.' in ts_str:
                        ts_str = ts_str.split('.')[0] + '+00:00'
                    ts = datetime.fromisoformat(ts_str)
                    timestamps.append(ts)
            except Exception:
                continue
        
        if len(timestamps) < 3:
            return None
        
        # Check for regular intervals (campaign pattern)
        time_diffs = []
        for i in range(len(timestamps)-1):
            diff = (timestamps[i+1] - timestamps[i]).total_seconds() / 3600
            if diff > 0:  # Only positive differences
                time_diffs.append(diff)
        
        avg_diff = np.mean(time_diffs) if time_diffs else 0
        std_diff = np.std(time_diffs) if time_diffs else 0
        
        # Low variance in timing suggests automated campaign
        is_campaign = False
        confidence = 0
        
        if avg_diff > 0 and len(time_diffs) > 1:
            cv = std_diff / avg_diff if avg_diff > 0 else float('inf')
            is_campaign = cv < 0.3 and avg_diff < window_hours
            confidence = max(0, min(1, 1 - cv))
        
        # Check feature similarity
        feature_vectors = []
        for attack in attacks[-10:]:
            fv = attack.get('feature_vector')
            if fv:
                normalized = self._normalize_features(fv, attack_type)
                feature_vectors.append(normalized)
        
        feature_similarity = 0
        if len(feature_vectors) >= 2:
            similarities = []
            for i in range(len(feature_vectors)-1):
                v1 = np.array(feature_vectors[i])
                v2 = np.array(feature_vectors[i+1])
                norm1 = np.linalg.norm(v1)
                norm2 = np.linalg.norm(v2)
                if norm1 > 0 and norm2 > 0:
                    sim = np.dot(v1, v2) / (norm1 * norm2)
                    similarities.append(sim)
            
            feature_similarity = np.mean(similarities) if similarities else 0
        
        # Determine pattern
        pattern = 'No clear pattern'
        if std_diff < avg_diff * 0.3 and avg_diff > 0:
            pattern = 'Regular timing'
        elif feature_similarity > 0.8:
            pattern = 'Feature similarity'
        
        return {
            'is_campaign': is_campaign or feature_similarity > 0.8,
            'confidence': float(confidence),
            'attacks_analyzed': len(timestamps),
            'avg_hours_between': float(avg_diff) if avg_diff else 0,
            'std_dev_hours': float(std_diff) if std_diff else 0,
            'feature_similarity': float(feature_similarity),
            'pattern': pattern
        }
    
    def get_attack_trend(self, attack_type='phishing_url', hours=168):  # 7 days
        """Get trend analysis of attack patterns"""
        
        attacks = self.memory.get_attacks_by_type(attack_type, limit=200)
        
        if len(attacks) < 5:
            return None
        
        # Sort by time
        try:
            attacks.sort(key=lambda x: x.get('timestamp', ''))
        except:
            return None
        
        # Group by day
        from collections import defaultdict
        daily_counts = defaultdict(int)
        daily_risks = defaultdict(list)
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        for attack in attacks:
            try:
                ts_str = attack.get('timestamp', '')
                if ts_str:
                    ts_str = ts_str.replace('Z', '+00:00')
                    if '.' in ts_str:
                        ts_str = ts_str.split('.')[0] + '+00:00'
                    ts = datetime.fromisoformat(ts_str)
                    
                    if ts < cutoff:
                        continue
                        
                    day = ts.strftime('%Y-%m-%d')
                    daily_counts[day] += 1
                    daily_risks[day].append(attack.get('risk_score', 0))
            except Exception:
                continue
        
        if not daily_counts:
            return None
        
        # Calculate trend
        days = sorted(daily_counts.keys())
        counts = [daily_counts[d] for d in days]
        
        # Simple linear trend
        if len(counts) > 1:
            x = np.arange(len(counts))
            z = np.polyfit(x, counts, 1)
            slope = z[0]
        else:
            slope = 0
        
        # Calculate average risk per day
        avg_risks = []
        for d in days:
            if daily_risks[d]:
                avg_risks.append(np.mean(daily_risks[d]))
            else:
                avg_risks.append(0)
        
        return {
            'attack_type': attack_type,
            'period_hours': hours,
            'total_attacks': len(attacks),
            'days_analyzed': len(days),
            'daily_counts': dict(zip(days, counts)),
            'trend': 'Increasing' if slope > 0.1 else 'Decreasing' if slope < -0.1 else 'Stable',
            'trend_slope': float(slope),
            'average_risk_trend': float(np.mean(avg_risks)) if avg_risks else 0,
            'peak_day': max(daily_counts.items(), key=lambda x: x[1])[0] if daily_counts else None,
            'peak_count': max(counts) if counts else 0
        }
    
    def get_learning_insights(self):
        """Get insights from all trained models"""
        
        insights = {}
        
        for attack_type in ['phishing_url', 'phishing_email', 'cloud_anomaly', 'deepfake']:
            if attack_type in self.models:
                model_info = self.models[attack_type]
                
                # Get recent context
                context = self.memory.get_attacks_by_type(attack_type, limit=10)
                
                # Predict next attack
                next_features = self.predict_next_attack(attack_type)
                
                # Detect campaign
                campaign = self.detect_attack_campaign(attack_type)
                
                # Get trend
                trend = self.get_attack_trend(attack_type)
                
                insights[attack_type] = {
                    'trained': True,
                    'attacks_learned': model_info['attack_count'],
                    'trained_at': model_info['trained_at'],
                    'next_attack_prediction': next_features.tolist() if next_features is not None else None,
                    'campaign_detected': campaign,
                    'trend_analysis': trend,
                    'recent_attacks': len(context)
                }
            else:
                # Check if we have enough attacks but haven't trained
                attacks = self.memory.get_attacks_by_type(attack_type, limit=10)
                attack_count = len(attacks)
                
                if attack_count >= self.min_attacks_required:
                    message = f"Ready to train ({attack_count} attacks available)"
                else:
                    message = f"Need {self.min_attacks_required - attack_count} more attacks"
                
                insights[attack_type] = {
                    'trained': False,
                    'attacks_available': attack_count,
                    'attacks_learned': 0,
                    'message': message
                }
        
        return insights
    
    def train_all(self):
        """Train models for all attack types"""
        
        results = {}
        
        for attack_type in ['phishing_url', 'phishing_email', 'cloud_anomaly', 'deepfake']:
            print(f"\n📚 Training for {attack_type}...")
            success = self.train(attack_type)
            results[attack_type] = success
        
        self.trained = any(results.values())
        
        return results

# Quick test
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🧠 LEARNING ENGINE TEST")
    print("="*60)
    
    engine = AttackLearningEngine()
    
    print("\n📊 Current attack counts:")
    for attack_type in ['phishing_url', 'phishing_email', 'cloud_anomaly', 'deepfake']:
        attacks = engine.memory.get_attacks_by_type(attack_type, limit=100)
        print(f"  {attack_type}: {len(attacks)} attacks")
    
    print("\n🚀 Training models...")
    results = engine.train_all()
    
    print("\n📊 Learning Insights:")
    insights = engine.get_learning_insights()
    
    for attack_type, info in insights.items():
        print(f"\n{attack_type}:")
        if info.get('trained', False):
            print(f"  ✅ Attacks learned: {info['attacks_learned']}")
            
            if info.get('campaign_detected'):
                camp = info['campaign_detected']
                print(f"  🎯 Campaign detected: {camp['is_campaign']}")
                print(f"     Confidence: {camp['confidence']:.2f}")
                print(f"     Pattern: {camp['pattern']}")
            
            if info.get('trend_analysis'):
                trend = info['trend_analysis']
                print(f"  📈 Trend: {trend['trend']}")
                print(f"     Peak day: {trend['peak_day']} ({trend['peak_count']} attacks)")
            
            if info.get('next_attack_prediction'):
                pred = info['next_attack_prediction'][:5]
                print(f"  🔮 Next attack (first 5 features): {[round(p, 3) for p in pred]}")
        else:
            attacks_available = info.get('attacks_available', 0)
            if attacks_available >= engine.min_attacks_required:
                print(f"  ⚠️ {info.get('message', 'Ready to train but not trained yet')}")
                print(f"     Run engine.train('{attack_type}') to train")
            else:
                print(f"  ⏳ {info.get('message', 'Not enough data')}")
    
    print("\n" + "="*60)