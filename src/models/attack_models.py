"""
Attack Memory Database Models
SQLAlchemy models for storing attack patterns
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json
import os

Base = declarative_base()

class AttackRecord(Base):
    """Main attack memory table"""
    __tablename__ = 'attacks'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    attack_type = Column(String(50), index=True)
    source = Column(String(50))
    
    # Core data
    risk_score = Column(Float)
    confidence = Column(Float)
    feature_vector = Column(JSON)  # Store as JSON array
    raw_indicators = Column(JSON)   # Original detection data
    
    # Context
    user_context = Column(String(100), nullable=True)
    system_context = Column(JSON, nullable=True)
    source_ip = Column(String(45), nullable=True)
    
    # Response
    response_taken = Column(JSON, default=[])  # List of actions
    response_success = Column(JSON, default=[])
    
    # Attack evolution tracking
    attack_family = Column(String(50), nullable=True)  # Group similar attacks
    mutation_count = Column(Integer, default=0)  # How many variants seen
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'attack_type': self.attack_type,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'feature_vector': self.feature_vector,
            'source': self.source
        }

class AttackFamily(Base):
    """Groups similar attacks into families"""
    __tablename__ = 'attack_families'
    
    id = Column(Integer, primary_key=True)
    family_name = Column(String(50), unique=True)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    attack_count = Column(Integer, default=0)
    common_features = Column(JSON)  # Prototype features
    evolution_trajectory = Column(JSON)  # How features change over time

class SimulationRecord(Base):
    """Tracks generated synthetic attacks"""
    __tablename__ = 'simulations'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    based_on_attack_id = Column(Integer)  # Which real attack inspired this
    attack_type = Column(String(50))
    feature_vector = Column(JSON)
    raw_content = Column(Text)  # The actual simulated email/URL/image
    quality_score = Column(Float)  # How realistic is it?
    used_in_training = Column(JSON, default=[])  # Which training runs used this