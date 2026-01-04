"""
Agent system models for HoneyMoon.
Represents agent tasks and chat conversations.
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, JSON
from datetime import datetime, timezone

from .base import Base


class AgentTaskRecord(Base):
    """
    Persistent storage for agent tasks.
    Allows tasks to survive application restarts and enables task history tracking.
    """
    __tablename__ = 'agent_tasks'

    id = Column(String, primary_key=True)  # UUID
    task_type = Column(String, nullable=False)  # investigation, monitoring, analysis, countermeasure, scheduled
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    priority = Column(Integer, default=2)  # 1=low, 2=normal, 3=high, 4=critical
    parameters = Column(JSON, default=dict)
    status = Column(String, default="pending")  # pending, running, completed, failed, cancelled, paused
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Results
    result = Column(JSON, nullable=True)
    error = Column(String, nullable=True)
    progress = Column(Float, default=0.0)
    
    # Confirmation handling
    requires_confirmation = Column(Boolean, default=False)
    confirmed = Column(Boolean, default=False)
    
    # Scheduling
    schedule_interval = Column(Integer, nullable=True)  # seconds
    next_run = Column(DateTime, nullable=True)
    run_count = Column(Integer, default=0)

    def __repr__(self):
        return f"<AgentTaskRecord(id={self.id}, name={self.name}, status={self.status})>"

    def dict(self):
        return {
            "id": self.id,
            "task_type": self.task_type,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "parameters": self.parameters,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error": self.error,
            "progress": self.progress,
            "requires_confirmation": self.requires_confirmation,
            "confirmed": self.confirmed,
            "schedule_interval": self.schedule_interval,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count
        }


class ChatConversation(Base):
    """
    Stores chat/analysis conversations for persistence.
    Allows users to continue investigations across sessions.
    """
    __tablename__ = 'chat_conversations'

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=True)  # Auto-generated or user-defined title
    context_type = Column(String, nullable=True)  # session, node, threat, cluster
    context_id = Column(String, nullable=True)  # ID of related entity
    
    # Conversation content
    messages = Column(JSON, default=list)  # List of {role, content, timestamp} messages
    
    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    model_used = Column(String, nullable=True)
    
    # Summary and insights
    summary = Column(String, nullable=True)
    key_findings = Column(JSON, default=list)
    
    # Vector embedding for RAG
    is_indexed = Column(Boolean, default=False)

    def __repr__(self):
        return f"<ChatConversation(id={self.id}, title={self.title})>"

    def dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "context_type": self.context_type,
            "context_id": self.context_id,
            "messages": self.messages,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "model_used": self.model_used,
            "summary": self.summary,
            "key_findings": self.key_findings,
            "is_indexed": self.is_indexed
        }
