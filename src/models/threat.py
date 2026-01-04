"""
Threat analysis models for HoneyMoon.
Represents LLM-generated threat analyses and attacker clusters.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, JSON
from datetime import datetime, timezone

from .base import Base


class ThreatAnalysis(Base):
    """
    Stores LLM-generated threat analyses for honeypot sessions, connections, and web accesses.
    Links to the source entity and stores the full analysis results.
    """
    __tablename__ = 'threat_analyses'

    id = Column(Integer, primary_key=True)
    # Source entity type and ID for polymorphic association
    source_type = Column(String, nullable=False)  # 'session', 'connection', 'access', 'node'
    source_id = Column(Integer, nullable=True)  # ID in the source table
    source_ip = Column(String, nullable=True)  # For node-based analyses
    
    # Analysis metadata
    analyzed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    model_used = Column(String, nullable=True)
    
    # Core threat assessment
    threat_type = Column(String, nullable=True)
    severity = Column(String, nullable=True)  # critical, high, medium, low, info
    confidence = Column(Float, nullable=True)
    summary = Column(String, nullable=True)
    
    # MITRE ATT&CK mapping
    tactics = Column(JSON, default=list)  # List of tactics
    techniques = Column(JSON, default=list)  # List of techniques
    
    # Indicators and attacker info
    indicators = Column(JSON, default=list)  # IoCs extracted
    attacker_profile = Column(JSON, default=dict)  # Skill level, automation, attribution
    
    # Counter-measure planning
    countermeasures = Column(JSON, default=dict)  # Planned countermeasures
    
    # Full analysis results
    raw_analysis = Column(JSON, default=dict)  # Full LLM response
    
    # Vector embedding flag
    is_indexed = Column(Boolean, default=False)

    def __repr__(self):
        return f"<ThreatAnalysis(id={self.id}, source_type={self.source_type}, threat_type={self.threat_type})>"

    def dict(self):
        return {
            "id": self.id,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "source_ip": self.source_ip,
            "analyzed_at": self.analyzed_at.isoformat() if self.analyzed_at else None,
            "model_used": self.model_used,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "indicators": self.indicators,
            "attacker_profile": self.attacker_profile,
            "countermeasures": self.countermeasures,
            "raw_analysis": self.raw_analysis,
            "is_indexed": self.is_indexed
        }


class AttackerCluster(Base):
    """
    Stores clusters of related attackers/IPs based on similarity analysis.
    """
    __tablename__ = 'attacker_clusters'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=True)  # Auto-generated or user-defined cluster name
    description = Column(String, nullable=True)
    
    # Cluster membership
    member_ips = Column(JSON, default=list)  # List of IP addresses in this cluster
    member_session_ids = Column(JSON, default=list)  # Session IDs in this cluster
    
    # Unified threat profile
    unified_profile = Column(JSON, default=dict)  # LLM-generated unified threat profile
    
    # Cluster metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    member_count = Column(Integer, default=0)
    
    # Cluster characteristics
    common_tactics = Column(JSON, default=list)
    common_techniques = Column(JSON, default=list)
    common_patterns = Column(JSON, default=list)
    
    # Severity assessment
    overall_severity = Column(String, nullable=True)

    def __repr__(self):
        return f"<AttackerCluster(id={self.id}, name={self.name}, members={self.member_count})>"

    def dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "member_ips": self.member_ips,
            "member_session_ids": self.member_session_ids,
            "unified_profile": self.unified_profile,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "member_count": self.member_count,
            "common_tactics": self.common_tactics,
            "common_techniques": self.common_techniques,
            "common_patterns": self.common_patterns,
            "overall_severity": self.overall_severity
        }
