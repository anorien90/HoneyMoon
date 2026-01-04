"""
Web access and connection models for HoneyMoon.
Tracks HTTP access logs and outgoing network connections.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from .base import Base


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
