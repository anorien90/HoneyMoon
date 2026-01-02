# Replace honeypot_models.py with this version (exposes saved_path in file dict and extra in session dict)
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .entry import Base

def utcnow():
    return datetime.now(timezone.utc)

class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"
    id = Column(Integer, primary_key=True)
    cowrie_session = Column(String, nullable=True, unique=True)  # original Cowrie session id if present
    src_ip = Column(String, nullable=False)
    src_port = Column(Integer, nullable=True)
    username = Column(String, nullable=True)
    auth_success = Column(String, nullable=True)
    start_ts = Column(DateTime, default=utcnow)
    end_ts = Column(DateTime, nullable=True)
    raw_events = Column(JSON, default=list)  # keep raw event lines for audit
    extra = Column(JSON, default=dict)

    commands = relationship("HoneypotCommand", back_populates="session", cascade="all, delete-orphan")
    files = relationship("HoneypotFile", back_populates="session", cascade="all, delete-orphan")

    def dict(self):
        return {
            "id": self.id,
            "cowrie_session": self.cowrie_session,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "username": self.username,
            "auth_success": self.auth_success,
            "start_ts": self.start_ts.isoformat() if self.start_ts else None,
            "end_ts": self.end_ts.isoformat() if self.end_ts else None,
            "extra": self.extra,
            "raw_events_count": len(self.raw_events) if self.raw_events else 0
        }

class HoneypotCommand(Base):
    __tablename__ = "honeypot_commands"
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("honeypot_sessions.id"))
    timestamp = Column(DateTime, default=utcnow)
    command = Column(Text)
    raw = Column(JSON, default=dict)

    session = relationship("HoneypotSession", back_populates="commands")

    def dict(self):
        return {"id": self.id, "session_id": self.session_id, "timestamp": self.timestamp.isoformat(), "command": self.command}

class HoneypotFile(Base):
    __tablename__ = "honeypot_files"
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("honeypot_sessions.id"))
    timestamp = Column(DateTime, default=utcnow)
    filename = Column(String)
    direction = Column(String)  # "download" or "upload" or "unknown"
    size = Column(Integer, nullable=True)
    sha256 = Column(String, nullable=True)
    saved_path = Column(String, nullable=True)  # path on disk (if captured)
    raw = Column(JSON, default=dict)

    session = relationship("HoneypotSession", back_populates="files")

    def dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "filename": self.filename,
            "direction": self.direction,
            "sha256": self.sha256,
            "saved_path": self.saved_path
        }

class HoneypotNetworkFlow(Base):
    __tablename__ = "honeypot_network_flows"
    id = Column(Integer, primary_key=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    proto = Column(String, nullable=True)
    bytes = Column(Integer, nullable=True)
    packets = Column(Integer, nullable=True)
    start_ts = Column(DateTime, default=utcnow)
    end_ts = Column(DateTime, nullable=True)
    extra = Column(JSON, default=dict)

    def dict(self):
        return {
            "id": self.id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "bytes": self.bytes,
            "packets": self.packets,
            "start_ts": self.start_ts.isoformat() if self.start_ts else None,
            "end_ts": self.end_ts.isoformat() if self.end_ts else None
        }
