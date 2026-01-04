"""
Analysis models for HoneyMoon.
Represents analysis sessions and path hops for traceroutes.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from .base import Base


class AnalysisSession(Base):
    """Represents a single run of the forensic engine."""
    __tablename__ = 'analysis_sessions'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    target_ip = Column(String, ForeignKey('network_nodes.ip'))
    mode = Column(String)  # 'Plain' or 'Deep'

    # Relationship: AnalysisSession.hops <-> PathHop.session
    hops = relationship("PathHop", back_populates="session", order_by="(PathHop.hop_number, PathHop.probe_index)", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<AnalysisSession(id={self.id}, target_ip={self.target_ip}, mode={self.mode})>"

    def dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "target_ip": self.target_ip,
            "mode": self.mode,
            "hops": [
                {"hop_number": hop.hop_number, "probe_index": hop.probe_index, "ip": hop.ip, "rtt": hop.rtt}
                for hop in self.hops
            ]
        }


class PathHop(Base):
    """The connector that maps a path for a specific session and probe."""
    __tablename__ = 'path_hops'

    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('analysis_sessions.id'))
    ip = Column(String, ForeignKey('network_nodes.ip'), nullable=True)
    hop_number = Column(Integer)  # 1, 2, 3...
    probe_index = Column(Integer, default=1)  # which probe for this TTL (1..n)
    rtt = Column(Float, nullable=True)  # Round Trip Time for this probe (seconds)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships with back_populates to keep things consistent
    session = relationship("AnalysisSession", back_populates="hops")
    node = relationship("NetworkNode", back_populates="path_hops")

    def __repr__(self):
        return f"<PathHop(session_id={self.session_id}, hop_number={self.hop_number}, probe_index={self.probe_index}, ip={self.ip})>"

    def dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "ip": self.ip,
            "hop_number": self.hop_number,
            "probe_index": self.probe_index,
            "rtt": self.rtt,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "node": self.node.ip if self.node else None
        }
