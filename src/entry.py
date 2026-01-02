from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime, timezone

Base = declarative_base()

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

    hostname = Column(String)
    isp = Column(String)
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

    def __repr__(self):
        return f"<NetworkNode(ip={self.ip}, hostname={self.hostname}, organization={self.organization})>"

    def dict(self):
        org_obj = None
        if self.organization_obj:
            try:
                org_obj = self.organization_obj.dict()
            except Exception:
                org_obj = {"id": self.organization_obj.id, "name": self.organization_obj.name}

        return {
            "ip": self.ip,
            "hostname": self.hostname,
            # keep denormalized organization for backwards compatibility
            "organization": self.organization,
            "organization_id": self.organization_id,
            "organization_obj": org_obj,
            "isp": self.isp,
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

class WebAccess(Base):
    """
    Stores parsed nginx access JSON log entries and links them to NetworkNode by remote_addr.
    Useful for correlating web hits with network intelligence already in the DB.
    """
    __tablename__ = 'web_accesses'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    remote_addr = Column(String, ForeignKey('network_nodes.ip'), nullable=True)
    remote_port = Column(Integer, nullable=True)
    remote_user = Column(String, nullable=True)
    request = Column(String, nullable=True)
    method = Column(String, nullable=True)
    path = Column(String, nullable=True)
    status = Column(Integer, nullable=True)
    body_bytes_sent = Column(Integer, nullable=True)
    http_referer = Column(String, nullable=True)
    http_user_agent = Column(String, nullable=True)
    http_x_forwarded_for = Column(String, nullable=True)
    server_name = Column(String, nullable=True)
    upstream_addr = Column(String, nullable=True)
    ssl_protocol = Column(String, nullable=True)
    ssl_cipher = Column(String, nullable=True)
    request_time = Column(Float, nullable=True)
    raw = Column(JSON, default=dict)

    node = relationship("NetworkNode", back_populates="web_accesses")

    def dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "request": self.request,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "body_bytes_sent": self.body_bytes_sent,
            "http_user_agent": self.http_user_agent,
            "server_name": self.server_name,
            "upstream_addr": self.upstream_addr,
            "request_time": self.request_time,
            "raw": self.raw
        }
