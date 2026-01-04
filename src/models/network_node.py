"""
NetworkNode model for HoneyMoon.
Represents unique IP addresses encountered in the system.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from .base import Base


class NetworkNode(Base):
    """
    Stores unique data for any IP encountered (Hops or Targets).
    Prevents re-fetching data for known IPs.
    """
    __tablename__ = 'network_nodes'

    ip = Column(String, primary_key=True)
    # legacy/denormalized organization string (kept for compatibility)
    organization = Column(String, nullable=True)
    # canonical FK to Organization table
    organization_id = Column(Integer, ForeignKey('organizations.id'), nullable=True)
    # legacy/denormalized isp string (kept for compatibility)
    isp = Column(String)
    # canonical FK to ISP table
    isp_id = Column(Integer, ForeignKey('isps.id'), nullable=True)

    hostname = Column(String)
    asn = Column(String)
    country = Column(String)
    city = Column(String)
    latitude = Column(Float)
    longitude = Column(Float)
    is_tor_exit = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    seen_count = Column(Integer, default=0)
    extra_data = Column(JSON, default=dict)

    # Relationship: NetworkNode.path_hops <-> PathHop.node
    path_hops = relationship("PathHop", back_populates="node", cascade="all, delete-orphan")
    # Relationship: NetworkNode.web_accesses <-> WebAccess.node
    web_accesses = relationship("WebAccess", back_populates="node", cascade="all, delete-orphan")
    # Relationship: NetworkNode.organization_obj <-> Organization.nodes
    organization_obj = relationship("Organization", back_populates="nodes")
    # Relationship: NetworkNode.isp_obj <-> ISP.nodes
    isp_obj = relationship("ISP", back_populates="nodes")

    def __repr__(self):
        return f"<NetworkNode(ip={self.ip}, hostname={self.hostname}, organization={self.organization})>"

    def dict(self):
        org_obj = None
        if self.organization_obj:
            try:
                org_obj = self.organization_obj.dict()
            except Exception:
                org_obj = {"id": self.organization_obj.id, "name": self.organization_obj.name}

        isp_obj_dict = None
        if self.isp_obj:
            try:
                isp_obj_dict = self.isp_obj.dict()
            except Exception:
                isp_obj_dict = {"id": self.isp_obj.id, "name": self.isp_obj.name}

        return {
            "ip": self.ip,
            "hostname": self.hostname,
            # keep denormalized organization for backwards compatibility
            "organization": self.organization,
            "organization_id": self.organization_id,
            "organization_obj": org_obj,
            # keep denormalized isp for backwards compatibility
            "isp": self.isp,
            "isp_id": self.isp_id,
            "isp_obj": isp_obj_dict,
            "asn": self.asn,
            "country": self.country,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "is_tor_exit": self.is_tor_exit,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "seen_count": self.seen_count,
            "extra_data": self.extra_data,
            "path_hops": [
                {"session_id": hop.session_id, "hop_number": hop.hop_number, "probe_index": hop.probe_index, "ip": hop.ip}
                for hop in self.path_hops
            ],
            "web_accesses_count": len(self.web_accesses)
        }
