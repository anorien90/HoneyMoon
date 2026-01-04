"""
Countermeasure and detection rule models for HoneyMoon.
Tracks countermeasure plans and generated detection rules.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON
from datetime import datetime, timezone

from .base import Base


class CountermeasureRecord(Base):
    """
    Stores countermeasure plans and their execution status.
    Allows tracking of security responses and their effectiveness.
    """
    __tablename__ = 'countermeasure_records'

    id = Column(Integer, primary_key=True)
    threat_analysis_id = Column(Integer, ForeignKey('threat_analyses.id'), nullable=True)
    
    # Plan details
    name = Column(String, nullable=True)
    description = Column(String, nullable=True)
    plan = Column(JSON, default=dict)  # Full countermeasure plan from LLM
    
    # Execution tracking
    status = Column(String, default="planned")  # planned, approved, executing, completed, failed, skipped
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    
    # Actions taken
    immediate_actions = Column(JSON, default=list)
    short_term_actions = Column(JSON, default=list)
    long_term_actions = Column(JSON, default=list)
    
    # Execution results
    actions_completed = Column(JSON, default=list)
    actions_failed = Column(JSON, default=list)
    execution_notes = Column(String, nullable=True)
    
    # Generated rules
    firewall_rules = Column(JSON, default=list)
    detection_rules = Column(JSON, default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<CountermeasureRecord(id={self.id}, name={self.name}, status={self.status})>"

    def dict(self):
        return {
            "id": self.id,
            "threat_analysis_id": self.threat_analysis_id,
            "name": self.name,
            "description": self.description,
            "plan": self.plan,
            "status": self.status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "immediate_actions": self.immediate_actions,
            "short_term_actions": self.short_term_actions,
            "long_term_actions": self.long_term_actions,
            "actions_completed": self.actions_completed,
            "actions_failed": self.actions_failed,
            "execution_notes": self.execution_notes,
            "firewall_rules": self.firewall_rules,
            "detection_rules": self.detection_rules,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class DetectionRuleRecord(Base):
    """
    Stores generated detection rules from threat analyses.
    Allows the system to learn and accumulate detection capabilities over time.
    """
    __tablename__ = 'detection_rule_records'

    id = Column(Integer, primary_key=True)
    
    # Source information
    source_type = Column(String, nullable=False)  # 'session', 'node', 'access', 'threat'
    source_id = Column(Integer, nullable=True)
    source_ip = Column(String, nullable=True)
    
    # Rule metadata
    name = Column(String, nullable=True)
    description = Column(String, nullable=True)
    rule_type = Column(String, nullable=True)  # 'sigma', 'snort', 'yara', 'firewall', 'cowrie'
    severity = Column(String, nullable=True)
    
    # The actual rule content
    rule_content = Column(String, nullable=True)  # Raw rule text
    rule_data = Column(JSON, default=dict)  # Structured rule data
    
    # Pattern information for learning
    command_patterns = Column(JSON, default=list)  # Command patterns that triggered this rule
    ioc_patterns = Column(JSON, default=list)  # IOC patterns
    
    # Usage tracking
    deployment_status = Column(String, default="generated")  # generated, deployed, deprecated
    hit_count = Column(Integer, default=0)  # How many times this rule matched
    false_positive_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_matched_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<DetectionRuleRecord(id={self.id}, name={self.name}, rule_type={self.rule_type})>"

    def dict(self):
        return {
            "id": self.id,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "source_ip": self.source_ip,
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type,
            "severity": self.severity,
            "rule_content": self.rule_content,
            "rule_data": self.rule_data,
            "command_patterns": self.command_patterns,
            "ioc_patterns": self.ioc_patterns,
            "deployment_status": self.deployment_status,
            "hit_count": self.hit_count,
            "false_positive_count": self.false_positive_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_matched_at": self.last_matched_at.isoformat() if self.last_matched_at else None
        }
