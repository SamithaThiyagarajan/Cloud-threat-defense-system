"""
Database connection manager for Attack Memory
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool
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
    response_taken = Column(JSON, default=[])
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'attack_type': self.attack_type,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'feature_vector': self.feature_vector,
            'source': self.source,
            'user_context': self.user_context,
            'source_ip': self.source_ip,
            'response_taken': self.response_taken
        }

class AttackFamily(Base):
    """Groups similar attacks into families"""
    __tablename__ = 'attack_families'
    
    id = Column(Integer, primary_key=True)
    family_name = Column(String(50), unique=True)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    attack_count = Column(Integer, default=0)
    common_features = Column(JSON)

class SimulationRecord(Base):
    """Tracks generated synthetic attacks"""
    __tablename__ = 'simulations'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    based_on_attack_id = Column(Integer)
    attack_type = Column(String(50))
    feature_vector = Column(JSON)
    raw_content = Column(Text)
    quality_score = Column(Float)

class AttackMemoryDB:
    def __init__(self, db_path=None):
        """Initialize database connection"""
        if db_path is None:
            # Use SQLite for development
            self.engine = create_engine(
                'sqlite:///attack_memory.db',
                poolclass=QueuePool,
                pool_size=5,
                max_overflow=10
            )
        else:
            self.engine = create_engine(db_path)
        
        # Create tables
        Base.metadata.create_all(self.engine)
        
        # Create session factory
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        print("✅ Attack Memory Database initialized")
    
    def store_attack(self, attack_data):
        """
        Store a detected attack in memory
        
        Args:
            attack_data: Dictionary with attack information
        """
        session = self.Session()
        try:
            record = AttackRecord(
                attack_type=attack_data.get('attack_type', 'unknown'),
                source=attack_data.get('source', 'api'),
                risk_score=attack_data.get('risk_score', 0),
                confidence=attack_data.get('confidence', 0),
                feature_vector=attack_data.get('feature_vector', []),
                raw_indicators=attack_data.get('raw_indicators', {}),
                user_context=attack_data.get('user_context'),
                source_ip=attack_data.get('source_ip'),
                response_taken=attack_data.get('response_taken', [])
            )
            session.add(record)
            session.commit()
            
            # Try to assign to family (but don't fail if it doesn't work)
            try:
                self._assign_to_family(record, session)
            except:
                pass  # Family assignment is optional
            
            return record.id
        except Exception as e:
            session.rollback()
            print(f"Error storing attack: {e}")
            return None
        finally:
            session.close()
    
    def _assign_to_family(self, attack, session):
        """Assign attack to a family or create new family"""
        try:
            similar = session.query(AttackFamily).filter(
                AttackFamily.family_name.like(f"{attack.attack_type}%")
            ).first()
            
            if similar:
                similar.last_seen = datetime.utcnow()
                similar.attack_count += 1
            else:
                family = AttackFamily(
                    family_name=f"{attack.attack_type}_{datetime.utcnow().strftime('%Y%m')}",
                    first_seen=attack.timestamp,
                    last_seen=attack.timestamp,
                    attack_count=1,
                    common_features=attack.feature_vector
                )
                session.add(family)
            
            session.commit()
        except Exception as e:
            # Just log and continue - family assignment is non-critical
            print(f"Note: Family assignment skipped - {e}")
    
    def get_attacks_by_type(self, attack_type, limit=10000000):
        """
        Retrieve recent attacks of a specific type
        """
        session = self.Session()
        try:
            attacks = session.query(AttackRecord).filter(
                AttackRecord.attack_type == attack_type
            ).order_by(
                AttackRecord.timestamp.desc()
            ).limit(limit).all()
            
            return [a.to_dict() for a in attacks]
        except Exception as e:
            print(f"Error retrieving attacks: {e}")
            return []
        finally:
            session.close()
    
    def get_attack_sequence(self, attack_type, hours=24):
        """
        Get temporal sequence of attacks for learning
        """
        from datetime import timedelta
        
        session = self.Session()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            attacks = session.query(AttackRecord).filter(
                AttackRecord.attack_type == attack_type,
                AttackRecord.timestamp >= cutoff
            ).order_by(
                AttackRecord.timestamp.asc()
            ).all()
            
            # Return as sequence of feature vectors
            return [a.feature_vector for a in attacks if a.feature_vector]
        except Exception as e:
            print(f"Error getting attack sequence: {e}")
            return []
        finally:
            session.close()
    
    def store_simulation(self, simulation_data):
        """Store a generated attack simulation"""
        session = self.Session()
        try:
            sim = SimulationRecord(
                based_on_attack_id=simulation_data.get('based_on_id'),
                attack_type=simulation_data.get('attack_type'),
                feature_vector=simulation_data.get('feature_vector', []),
                raw_content=simulation_data.get('raw_content'),
                quality_score=simulation_data.get('quality_score', 0.5)
            )
            session.add(sim)
            session.commit()
            return sim.id
        except Exception as e:
            session.rollback()
            print(f"Error storing simulation: {e}")
            return None
        finally:
            session.close()