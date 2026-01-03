"""
Tests for the new integration models: AgentTaskRecord, ChatConversation, CountermeasureRecord.
"""
import pytest
from datetime import datetime, timezone


class TestAgentTaskRecord:
    """Tests for AgentTaskRecord model."""

    def test_agent_task_record_creation(self, db_session):
        """Test creating an agent task record."""
        from src.entry import AgentTaskRecord
        
        task = AgentTaskRecord(
            id="test-uuid-1234",
            task_type="investigation",
            name="Test Investigation",
            description="Test task for investigation",
            priority=3,
            parameters={"ip": "192.168.1.1"},
            status="pending"
        )
        db_session.add(task)
        db_session.commit()
        
        assert task.id == "test-uuid-1234"
        assert task.task_type == "investigation"
        assert task.name == "Test Investigation"
        assert task.priority == 3
        assert task.status == "pending"
        assert task.progress == 0.0

    def test_agent_task_record_dict(self, db_session):
        """Test AgentTaskRecord.dict() method."""
        from src.entry import AgentTaskRecord
        
        task = AgentTaskRecord(
            id="test-uuid-5678",
            task_type="analysis",
            name="Test Analysis",
            description="Analyzing threats",
            priority=2,
            parameters={"session_id": 123},
            status="completed",
            progress=1.0,
            result={"findings": ["threat detected"]},
            requires_confirmation=True,
            confirmed=True
        )
        db_session.add(task)
        db_session.commit()
        
        task_dict = task.dict()
        
        assert task_dict["id"] == "test-uuid-5678"
        assert task_dict["task_type"] == "analysis"
        assert task_dict["status"] == "completed"
        assert task_dict["progress"] == 1.0
        assert task_dict["result"]["findings"] == ["threat detected"]
        assert task_dict["requires_confirmation"] is True
        assert task_dict["confirmed"] is True

    def test_agent_task_record_scheduled(self, db_session):
        """Test creating a scheduled agent task."""
        from src.entry import AgentTaskRecord
        
        task = AgentTaskRecord(
            id="scheduled-task-1",
            task_type="scheduled",
            name="Periodic Monitoring",
            description="Monitor every 5 minutes",
            priority=1,
            parameters={},
            status="pending",
            schedule_interval=300,
            run_count=5
        )
        db_session.add(task)
        db_session.commit()
        
        assert task.schedule_interval == 300
        assert task.run_count == 5


class TestChatConversation:
    """Tests for ChatConversation model."""

    def test_chat_conversation_creation(self, db_session):
        """Test creating a chat conversation."""
        from src.entry import ChatConversation
        
        conv = ChatConversation(
            title="Session Analysis",
            context_type="session",
            context_id="123",
            messages=[
                {"role": "user", "content": "What threats were detected?"},
                {"role": "assistant", "content": "Several SSH brute force attempts."}
            ]
        )
        db_session.add(conv)
        db_session.commit()
        
        assert conv.id is not None
        assert conv.title == "Session Analysis"
        assert conv.context_type == "session"
        assert len(conv.messages) == 2

    def test_chat_conversation_dict(self, db_session):
        """Test ChatConversation.dict() method."""
        from src.entry import ChatConversation
        
        conv = ChatConversation(
            title="Investigation Chat",
            context_type="node",
            context_id="192.168.1.1",
            messages=[{"role": "user", "content": "Analyze this IP"}],
            model_used="granite3.1-dense:8b",
            summary="IP analysis conversation",
            key_findings=["suspicious activity detected"],
            is_indexed=True
        )
        db_session.add(conv)
        db_session.commit()
        
        conv_dict = conv.dict()
        
        assert conv_dict["title"] == "Investigation Chat"
        assert conv_dict["context_type"] == "node"
        assert conv_dict["model_used"] == "granite3.1-dense:8b"
        assert conv_dict["key_findings"] == ["suspicious activity detected"]
        assert conv_dict["is_indexed"] is True

    def test_chat_conversation_message_append(self, db_session):
        """Test appending messages to a conversation."""
        from src.entry import ChatConversation
        
        conv = ChatConversation(
            title="Test Chat",
            messages=[]
        )
        db_session.add(conv)
        db_session.commit()
        
        # Add a message
        conv.messages = conv.messages + [{"role": "user", "content": "Hello"}]
        conv.updated_at = datetime.now(timezone.utc)
        db_session.commit()
        
        # Refresh from DB
        db_session.refresh(conv)
        assert len(conv.messages) == 1
        assert conv.messages[0]["content"] == "Hello"


class TestCountermeasureRecord:
    """Tests for CountermeasureRecord model."""

    def test_countermeasure_record_creation(self, db_session):
        """Test creating a countermeasure record."""
        from src.entry import CountermeasureRecord, ThreatAnalysis
        
        # Create a threat analysis first
        threat = ThreatAnalysis(
            source_type="session",
            source_id=1,
            threat_type="SSH Brute Force",
            severity="high"
        )
        db_session.add(threat)
        db_session.commit()
        
        record = CountermeasureRecord(
            threat_analysis_id=threat.id,
            name="Block Attacker",
            description="Block attacking IP",
            plan={"immediate_actions": ["block IP at firewall"]},
            status="planned",
            immediate_actions=["block IP"],
            firewall_rules=["iptables -A INPUT -s 192.168.1.100 -j DROP"]
        )
        db_session.add(record)
        db_session.commit()
        
        assert record.id is not None
        assert record.threat_analysis_id == threat.id
        assert record.status == "planned"
        assert "block IP" in record.immediate_actions

    def test_countermeasure_record_dict(self, db_session):
        """Test CountermeasureRecord.dict() method."""
        from src.entry import CountermeasureRecord
        
        record = CountermeasureRecord(
            name="Security Response",
            description="Response to detected threat",
            plan={"risk_if_unaddressed": "High risk of data breach"},
            status="approved",
            approved_by="security_admin",
            approved_at=datetime.now(timezone.utc),
            immediate_actions=["enable rate limiting"],
            short_term_actions=["review firewall rules"],
            long_term_actions=["implement MFA"],
            firewall_rules=["block 192.168.1.0/24"],
            detection_rules=["alert on SSH failures > 10"]
        )
        db_session.add(record)
        db_session.commit()
        
        record_dict = record.dict()
        
        assert record_dict["name"] == "Security Response"
        assert record_dict["status"] == "approved"
        assert record_dict["approved_by"] == "security_admin"
        assert "enable rate limiting" in record_dict["immediate_actions"]
        assert "block 192.168.1.0/24" in record_dict["firewall_rules"]

    def test_countermeasure_record_execution(self, db_session):
        """Test recording countermeasure execution."""
        from src.entry import CountermeasureRecord
        
        record = CountermeasureRecord(
            name="Executed Countermeasure",
            status="approved"
        )
        db_session.add(record)
        db_session.commit()
        
        # Mark as executed
        record.status = "completed"
        record.executed_at = datetime.now(timezone.utc)
        record.actions_completed = ["blocked IP", "updated firewall"]
        record.actions_failed = []
        record.execution_notes = "Successfully blocked attacker"
        db_session.commit()
        
        db_session.refresh(record)
        assert record.status == "completed"
        assert record.executed_at is not None
        assert len(record.actions_completed) == 2


class TestThreatAnalysis:
    """Tests for ThreatAnalysis model."""

    def test_threat_analysis_creation(self, db_session):
        """Test creating a threat analysis."""
        from src.entry import ThreatAnalysis
        
        analysis = ThreatAnalysis(
            source_type="session",
            source_id=1,
            source_ip="192.168.1.100",
            model_used="granite3.1-dense:8b",
            threat_type="SSH Brute Force",
            severity="high",
            confidence=0.95,
            summary="Multiple failed login attempts detected",
            tactics=["Initial Access", "Credential Access"],
            techniques=["T1110 - Brute Force"],
            indicators=["repeated failed logins", "password spraying"],
            attacker_profile={"skill_level": "low", "automated": True}
        )
        db_session.add(analysis)
        db_session.commit()
        
        assert analysis.id is not None
        assert analysis.threat_type == "SSH Brute Force"
        assert analysis.severity == "high"
        assert analysis.confidence == 0.95

    def test_threat_analysis_dict(self, db_session):
        """Test ThreatAnalysis.dict() method."""
        from src.entry import ThreatAnalysis
        
        analysis = ThreatAnalysis(
            source_type="connection",
            threat_type="Data Exfiltration",
            severity="critical",
            confidence=0.85,
            summary="Suspicious outbound traffic detected",
            countermeasures={"immediate": ["block outbound"], "long_term": ["DLP solution"]}
        )
        db_session.add(analysis)
        db_session.commit()
        
        analysis_dict = analysis.dict()
        
        assert analysis_dict["source_type"] == "connection"
        assert analysis_dict["threat_type"] == "Data Exfiltration"
        assert analysis_dict["severity"] == "critical"
        assert "block outbound" in analysis_dict["countermeasures"]["immediate"]


class TestAttackerCluster:
    """Tests for AttackerCluster model."""

    def test_attacker_cluster_creation(self, db_session):
        """Test creating an attacker cluster."""
        from src.entry import AttackerCluster
        
        cluster = AttackerCluster(
            name="Botnet Campaign A",
            description="Related attackers from same campaign",
            member_ips=["192.168.1.100", "192.168.1.101", "192.168.1.102"],
            member_session_ids=[1, 2, 3, 4, 5],
            unified_profile={"campaign": "credential_stuffing"},
            member_count=5,
            common_tactics=["Initial Access"],
            common_techniques=["T1110"],
            overall_severity="high"
        )
        db_session.add(cluster)
        db_session.commit()
        
        assert cluster.id is not None
        assert cluster.name == "Botnet Campaign A"
        assert len(cluster.member_ips) == 3
        assert cluster.member_count == 5

    def test_attacker_cluster_dict(self, db_session):
        """Test AttackerCluster.dict() method."""
        from src.entry import AttackerCluster
        
        cluster = AttackerCluster(
            name="Test Cluster",
            member_ips=["10.0.0.1"],
            member_session_ids=[1],
            member_count=1,
            overall_severity="medium"
        )
        db_session.add(cluster)
        db_session.commit()
        
        cluster_dict = cluster.dict()
        
        assert cluster_dict["name"] == "Test Cluster"
        assert cluster_dict["member_count"] == 1
        assert cluster_dict["overall_severity"] == "medium"
        assert cluster_dict["created_at"] is not None
