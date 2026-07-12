"""
Auto-Training Pipeline - Automatically retrains and deploys models
"""

import numpy as np
import torch
import sys
import os
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.learning.engine import AttackLearningEngine
from src.memory.db_manager import AttackMemoryDB

class AutoTrainingPipeline:
    """
    Automatically retrains models when enough new data arrives
    """
    
    def __init__(self, memory_db=None):
        self.memory = memory_db or AttackMemoryDB()
        self.learning_engine = AttackLearningEngine(self.memory)
        self.models_dir = Path("models/trained")
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Training thresholds
        self.min_new_attacks = 5  # Retrain after 5 new attacks
        self.min_improvement = 0.05  # Need 5% improvement to deploy
        self.max_model_age_days = 7  # Retrain weekly anyway
        
        # Track last training
        self.last_training = {}
        self.training_history = []
        
        print("🔄 Auto-Training Pipeline initialized")
        print(f"📁 Models will be saved to: {self.models_dir}")
    
    def check_retrain_needed(self, attack_type='phishing_url'):
        """
        Check if we should retrain this model type
        """
        # Get current attack count
        attacks = self.memory.get_attacks_by_type(attack_type, limit=100)
        current_count = len(attacks)
        
        # Check if we have enough data to train
        if current_count < self.learning_engine.min_attacks_required:
            return False, f"Need {self.learning_engine.min_attacks_required - current_count} more attacks"
        
        # Check when we last trained
        last_info = self.last_training.get(attack_type, {})
        last_count = last_info.get('attack_count', 0)
        last_time = last_info.get('timestamp')
        
        # Case 1: Never trained before
        if not last_time:
            return True, "Never trained before"
        
        # Case 2: Enough new attacks arrived
        new_attacks = current_count - last_count
        if new_attacks >= self.min_new_attacks:
            return True, f"{new_attacks} new attacks since last training"
        
        # Case 3: Model is too old
        last_time_obj = datetime.fromisoformat(last_time)
        days_old = (datetime.utcnow() - last_time_obj).days
        if days_old >= self.max_model_age_days:
            return True, f"Model is {days_old} days old"
        
        return False, f"Only {new_attacks} new attacks (need {self.min_new_attacks})"
    
    def train_and_validate(self, attack_type='phishing_url'):
        """
        Train new model and validate against old one
        """
        print(f"\n📚 Training new model for {attack_type}...")
        
        # Train new model
        success = self.learning_engine.train(attack_type)
        if not success:
            return None, "Training failed"
        
        # Get new model info
        new_model_info = self.learning_engine.models.get(attack_type)
        if not new_model_info:
            return None, "No model produced"
        
        # Get old model if exists
        old_model_path = self.models_dir / f"{attack_type}_latest.pt"
        old_model_info = None
        old_loss = float('inf')
        
        if old_model_path.exists():
            try:
                # Load old model metadata
                meta_path = self.models_dir / f"{attack_type}_meta.json"
                if meta_path.exists():
                    with open(meta_path, 'r') as f:
                        old_model_info = json.load(f)
                    old_loss = old_model_info.get('validation_loss', float('inf'))
            except:
                pass
        
        # Validate new model
        validation_loss = self._validate_model(new_model_info['model'], attack_type)
        
        # Compare performance
        improvement = 0
        if old_loss != float('inf'):
            improvement = (old_loss - validation_loss) / old_loss
        
        result = {
            'attack_type': attack_type,
            'timestamp': datetime.utcnow().isoformat(),
            'attack_count': new_model_info['attack_count'],
            'validation_loss': float(validation_loss),
            'old_loss': float(old_loss) if old_loss != float('inf') else None,
            'improvement': float(improvement),
            'should_deploy': improvement >= self.min_improvement or old_loss == float('inf')
        }
        
        return result, "Validation complete"
    
    def _validate_model(self, model, attack_type):
        """Validate model on recent data"""
        # Get recent attacks for validation
        attacks = self.memory.get_attacks_by_type(attack_type, limit=20)
        if len(attacks) < 5:
            return 0.1  # Default loss
        
        # Extract features
        sequences = []
        for attack in attacks[-10:]:  # Use last 10 for validation
            features = attack.get('feature_vector')
            if features:
                normalized = self.learning_engine._normalize_features(features, attack_type)
                sequences.append(normalized)
        
        if len(sequences) < 3:
            return 0.1
        
        # Convert to tensor and add batch dimension
        sequences = np.array(sequences[-5:], dtype=np.float32)
        
        # Validate
        model.eval()
        with torch.no_grad():
            losses = []
            # Need at least 2 sequences for validation
            for i in range(len(sequences) - 1):
                # Input: single sequence with batch dimension
                input_seq = torch.FloatTensor(sequences[i:i+1])  # Shape: (1, seq_len, features)
                actual = torch.FloatTensor(sequences[i+1:i+2])   # Shape: (1, 1, features)
                
                # Model expects (batch, seq_len, features)
                predicted = model(input_seq)  # Returns (1, features)
                
                # Reshape for loss calculation
                loss = torch.nn.functional.mse_loss(predicted, actual.squeeze(0))
                losses.append(loss.item())
            
            avg_loss = np.mean(losses) if losses else 0.1
        
        return avg_loss
    def deploy_model(self, attack_type, training_result):
        """
        Deploy trained model to production
        """
        model_info = self.learning_engine.models.get(attack_type)
        if not model_info:
            return False, "No model to deploy"
        
        # Save model
        model_path = self.models_dir / f"{attack_type}_latest.pt"
        torch.save(model_info['model'].state_dict(), model_path)
        
        # Save metadata
        meta = {
            'attack_type': attack_type,
            'trained_at': datetime.utcnow().isoformat(),
            'attack_count': model_info['attack_count'],
            'validation_loss': training_result['validation_loss'],
            'input_dim': model_info['input_dim'],
            'improvement': training_result['improvement']
        }
        
        meta_path = self.models_dir / f"{attack_type}_meta.json"
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
        
        # Update last training record
        self.last_training[attack_type] = {
            'timestamp': datetime.utcnow().isoformat(),
            'attack_count': model_info['attack_count'],
            'validation_loss': training_result['validation_loss']
        }
        
        # Log to history
        self.training_history.append({
            **training_result,
            'deployed': True
        })
        
        print(f"✅ Deployed new {attack_type} model (improvement: {training_result['improvement']*100:.1f}%)")
        
        return True, meta
    
    def auto_train_all(self):
        """
        Check all attack types and retrain if needed
        """
        results = {}
        
        for attack_type in ['phishing_url', 'phishing_email', 'cloud_anomaly', 'deepfake']:
            print(f"\n🔍 Checking {attack_type}...")
            
            # Check if retrain needed
            needed, reason = self.check_retrain_needed(attack_type)
            print(f"  {reason}")
            
            if needed:
                # Train and validate
                training_result, msg = self.train_and_validate(attack_type)
                
                if training_result:
                    print(f"  Validation loss: {training_result['validation_loss']:.4f}")
                    
                    if training_result['should_deploy']:
                        # Deploy if better
                        success, meta = self.deploy_model(attack_type, training_result)
                        results[attack_type] = {
                            'action': 'deployed',
                            'improvement': training_result['improvement'],
                            'loss': training_result['validation_loss']
                        }
                    else:
                        print(f"  ⚠️ Model not better enough ({training_result['improvement']*100:.1f}% < {self.min_improvement*100}%)")
                        results[attack_type] = {
                            'action': 'skipped',
                            'improvement': training_result['improvement'],
                            'reason': 'Insufficient improvement'
                        }
                else:
                    print(f"  ❌ {msg}")
                    results[attack_type] = {'action': 'failed', 'reason': msg}
            else:
                results[attack_type] = {'action': 'not_needed', 'reason': reason}
        
        return results
    
    def get_pipeline_status(self):
        """
        Get status of all models and training pipeline
        """
        status = {
            'last_training': self.last_training,
            'history': self.training_history[-10:],  # Last 10 events
            'models_available': []
        }
        
        # Check which models are deployed
        for attack_type in ['phishing_url', 'phishing_email', 'cloud_anomaly', 'deepfake']:
            model_path = self.models_dir / f"{attack_type}_latest.pt"
            meta_path = self.models_dir / f"{attack_type}_meta.json"
            
            if model_path.exists() and meta_path.exists():
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                status['models_available'].append({
                    'attack_type': attack_type,
                    'deployed': True,
                    'trained_at': meta['trained_at'],
                    'attack_count': meta['attack_count']
                })
            else:
                status['models_available'].append({
                    'attack_type': attack_type,
                    'deployed': False
                })
        
        return status
    
    def load_model(self, attack_type):
        """
        Load a trained model for inference
        """
        model_path = self.models_dir / f"{attack_type}_latest.pt"
        meta_path = self.models_dir / f"{attack_type}_meta.json"
        
        if not model_path.exists() or not meta_path.exists():
            return None, "Model not found"
        
        # Load metadata
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        
        # Recreate model
        from src.learning.engine import LSTMAttackPredictor
        model = LSTMAttackPredictor(meta['input_dim'])
        model.load_state_dict(torch.load(model_path))
        model.eval()
        
        return model, meta

# Quick test
if __name__ == "__main__":
    print("="*60)
    print("🔄 TESTING AUTO-TRAINING PIPELINE")
    print("="*60)
    
    pipeline = AutoTrainingPipeline()
    
    print("\n📊 Checking if retraining needed...")
    results = pipeline.auto_train_all()
    
    print("\n📈 Pipeline Status:")
    status = pipeline.get_pipeline_status()
    for model in status['models_available']:
        if model['deployed']:
            print(f"  ✅ {model['attack_type']}: Deployed ({model['attack_count']} attacks)")
        else:
            print(f"  ⏳ {model['attack_type']}: Not deployed")
    
    print("\n✅ Pipeline test complete")