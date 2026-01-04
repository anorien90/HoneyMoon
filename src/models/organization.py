"""
Organization model for HoneyMoon.
Represents organizations that own IP allocations.
"""
from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from .base import Base


class Organization(Base):
    """
    Canonical organization table so we can associate many IPs with one Organization record.
    - name: human-friendly display name
    - name_normalized: lowercase/stripped name used for uniqueness lookups
    - rdap: optional RDAP/details blob
    - extra_data: any other enrichment
    """
    __tablename__ = 'organizations'

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    name_normalized = Column(String, nullable=False, unique=True)
    rdap = Column(JSON, default=dict)
    abuse_email = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    extra_data = Column(JSON, default=dict)

    # Relationship: Organization.nodes <-> NetworkNode.organization_obj
    nodes = relationship("NetworkNode", back_populates="organization_obj", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Organization(id={self.id}, name={self.name})>"

    def dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "name_normalized": self.name_normalized,
            "rdap": self.rdap,
            "abuse_email": self.abuse_email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "extra_data": self.extra_data
        }
