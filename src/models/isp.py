"""
ISP model for HoneyMoon.
Represents Internet Service Providers.
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from .base import Base


class ISP(Base):
    """
    Internet Service Provider table to associate many IPs with one ISP record.
    Separate from Organization to distinguish between the ISP (network provider) and
    the organization that owns the IP allocation.
    - name: human-friendly display name
    - name_normalized: lowercase/stripped name used for uniqueness lookups
    - asn: Autonomous System Number (e.g., "AS15169")
    - extra_data: any other enrichment data
    """
    __tablename__ = 'isps'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    name_normalized = Column(String, nullable=False, unique=True)
    asn = Column(String, nullable=True)
    abuse_email = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    extra_data = Column(JSON, default=dict)

    # Relationship: ISP.nodes <-> NetworkNode.isp_obj
    # Using save-update cascade so network nodes persist even if ISP is removed
    nodes = relationship("NetworkNode", back_populates="isp_obj", cascade="save-update")

    def __repr__(self):
        return f"<ISP(id={self.id}, name={self.name}, asn={self.asn})>"

    def dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "name_normalized": self.name_normalized,
            "asn": self.asn,
            "abuse_email": self.abuse_email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "extra_data": self.extra_data
        }
