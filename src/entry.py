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


class OutgoingConnection(Base):
    """
    Stores outgoing network connections observed from the local system.
    Useful for monitoring what connections are being made FROM the honeypot/server
    TO external destinations.
    """
    __tablename__ = 'outgoing_connections'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    local_addr = Column(String, nullable=True)
    local_port = Column(Integer, nullable=True)
    remote_addr = Column(String, nullable=True)
    remote_port = Column(Integer, nullable=True)
    proto = Column(String, nullable=True)  # tcp, udp, etc.
    status = Column(String, nullable=True)  # ESTABLISHED, TIME_WAIT, etc.
    pid = Column(Integer, nullable=True)
    process_name = Column(String, nullable=True)
    direction = Column(String, default="outgoing")  # 'outgoing' or 'incoming' for completeness
    bytes_sent = Column(Integer, nullable=True)
    bytes_recv = Column(Integer, nullable=True)
    extra_data = Column(JSON, default=dict)

    def __repr__(self):
        return f"<OutgoingConnection(id={self.id}, local={self.local_addr}:{self.local_port} -> remote={self.remote_addr}:{self.remote_port})>"

    def dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "proto": self.proto,
            "status": self.status,
            "pid": self.pid,
            "process_name": self.process_name,
            "direction": self.direction,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "extra_data": self.extra_data
        }


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
