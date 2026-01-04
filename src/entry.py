"""
HoneyMoon Database Models - Legacy Entry Point.

This file is maintained for backward compatibility. All models have been
refactored into separate files in src/models/ for better maintainability.

For new code, prefer importing from src.models directly:
    from src.models import NetworkNode, Organization, ThreatAnalysis, etc.

This file re-exports all models so existing imports continue to work:
    from src.entry import NetworkNode, Organization, etc.
"""

# Re-export all models from the new models package
from src.models import (
    Base,
    Organization,
    ISP,
    NetworkNode,
    AnalysisSession,
    PathHop,
    WebAccess,
    OutgoingConnection,
    ThreatAnalysis,
    AttackerCluster,
    AgentTaskRecord,
    ChatConversation,
    CountermeasureRecord,
    DetectionRuleRecord,
)

# Maintain __all__ for explicit exports
__all__ = [
    'Base',
    'Organization',
    'ISP',
    'NetworkNode',
    'AnalysisSession',
    'PathHop',
    'WebAccess',
    'OutgoingConnection',
    'ThreatAnalysis',
    'AttackerCluster',
    'AgentTaskRecord',
    'ChatConversation',
    'CountermeasureRecord',
    'DetectionRuleRecord',
]
