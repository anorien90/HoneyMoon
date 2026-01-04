"""
HoneyMoon Database Models.

This package contains all SQLAlchemy ORM models for the HoneyMoon system.
Models are organized by concern into separate modules for better maintainability.

All models are re-exported from this __init__.py for backward compatibility.
Import from here for most use cases:
    from src.models import NetworkNode, Organization, ThreatAnalysis, etc.
"""

# Base
from .base import Base

# Organization and ISP models
from .organization import Organization
from .isp import ISP

# Network node model
from .network_node import NetworkNode

# Analysis and path tracking models
from .analysis import AnalysisSession, PathHop

# Web access and connection models
from .web_access import WebAccess, OutgoingConnection

# Threat analysis models
from .threat import ThreatAnalysis, AttackerCluster

# Agent system models
from .agent import AgentTaskRecord, ChatConversation

# Countermeasure and detection rule models
from .countermeasure import CountermeasureRecord, DetectionRuleRecord


# Export all models for convenient imports
__all__ = [
    # Base
    'Base',
    
    # Organization
    'Organization',
    'ISP',
    
    # Network
    'NetworkNode',
    
    # Analysis
    'AnalysisSession',
    'PathHop',
    
    # Web Access
    'WebAccess',
    'OutgoingConnection',
    
    # Threats
    'ThreatAnalysis',
    'AttackerCluster',
    
    # Agent
    'AgentTaskRecord',
    'ChatConversation',
    
    # Countermeasures
    'CountermeasureRecord',
    'DetectionRuleRecord',
]
