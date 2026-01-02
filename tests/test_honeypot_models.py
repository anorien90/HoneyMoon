"""
Tests for src/honeypot_models.py SQLAlchemy models.
"""
import pytest
from datetime import datetime, timezone

from src.honeypot_models import HoneypotSession, HoneypotCommand, HoneypotFile, HoneypotNetworkFlow


class TestHoneypotSession:
    """Tests for the HoneypotSession model."""

    def test_honeypot_session_creation(self, db_session):
        """Test creating a honeypot session."""
        session = HoneypotSession(
            cowrie_session="cowrie_abc123",
            src_ip="10.0.0.100",
            src_port=12345,
            username="admin",
            auth_success="success",
            raw_events=[{"event": "connect"}, {"event": "login"}],
            extra={"note": "suspicious"}
        )
        db_session.add(session)
        db_session.commit()
        
        assert session.id is not None
        assert session.cowrie_session == "cowrie_abc123"
        assert session.src_ip == "10.0.0.100"
        assert session.src_port == 12345
        assert session.username == "admin"
        assert session.auth_success == "success"
        assert len(session.raw_events) == 2
        assert session.start_ts is not None

    def test_honeypot_session_dict(self, sample_honeypot_session):
        """Test the HoneypotSession.dict() method."""
        session_dict = sample_honeypot_session.dict()
        
        assert session_dict["id"] == sample_honeypot_session.id
        assert session_dict["cowrie_session"] == "session_12345"
        assert session_dict["src_ip"] == "10.0.0.1"
        assert session_dict["src_port"] == 54321
        assert session_dict["username"] == "root"
        assert session_dict["auth_success"] == "failed"
        assert "start_ts" in session_dict
        assert session_dict["raw_events_count"] == 1

    def test_honeypot_session_unique_cowrie_session(self, db_session):
        """Test that cowrie_session must be unique."""
        session1 = HoneypotSession(cowrie_session="unique_id", src_ip="1.1.1.1")
        db_session.add(session1)
        db_session.commit()

        session2 = HoneypotSession(cowrie_session="unique_id", src_ip="2.2.2.2")
        db_session.add(session2)
        
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()

    def test_honeypot_session_nullable_cowrie_session(self, db_session):
        """Test that cowrie_session can be null."""
        session = HoneypotSession(cowrie_session=None, src_ip="3.3.3.3")
        db_session.add(session)
        db_session.commit()
        
        assert session.id is not None
        assert session.cowrie_session is None

    def test_honeypot_session_end_ts(self, db_session, sample_honeypot_session):
        """Test setting end_ts on a honeypot session."""
        end_time = datetime.now(timezone.utc)
        sample_honeypot_session.end_ts = end_time
        db_session.commit()
        
        db_session.refresh(sample_honeypot_session)
        assert sample_honeypot_session.end_ts is not None


class TestHoneypotCommand:
    """Tests for the HoneypotCommand model."""

    def test_honeypot_command_creation(self, db_session, sample_honeypot_session):
        """Test creating a honeypot command."""
        cmd = HoneypotCommand(
            session_id=sample_honeypot_session.id,
            command="cat /etc/passwd",
            raw={"input": "cat /etc/passwd"}
        )
        db_session.add(cmd)
        db_session.commit()
        
        assert cmd.id is not None
        assert cmd.session_id == sample_honeypot_session.id
        assert cmd.command == "cat /etc/passwd"
        assert cmd.timestamp is not None

    def test_honeypot_command_dict(self, sample_honeypot_command):
        """Test the HoneypotCommand.dict() method."""
        cmd_dict = sample_honeypot_command.dict()
        
        assert cmd_dict["id"] == sample_honeypot_command.id
        assert cmd_dict["session_id"] == sample_honeypot_command.session_id
        assert cmd_dict["command"] == "ls -la"
        assert "timestamp" in cmd_dict

    def test_honeypot_command_session_relationship(self, db_session, sample_honeypot_command, sample_honeypot_session):
        """Test the relationship between HoneypotCommand and HoneypotSession."""
        db_session.refresh(sample_honeypot_command)
        db_session.refresh(sample_honeypot_session)
        
        assert sample_honeypot_command.session is not None
        assert sample_honeypot_command.session.id == sample_honeypot_session.id
        assert sample_honeypot_command in sample_honeypot_session.commands

    def test_multiple_commands_per_session(self, db_session, sample_honeypot_session):
        """Test adding multiple commands to a session."""
        cmd1 = HoneypotCommand(session_id=sample_honeypot_session.id, command="pwd")
        cmd2 = HoneypotCommand(session_id=sample_honeypot_session.id, command="whoami")
        cmd3 = HoneypotCommand(session_id=sample_honeypot_session.id, command="id")
        
        db_session.add_all([cmd1, cmd2, cmd3])
        db_session.commit()
        
        db_session.refresh(sample_honeypot_session)
        assert len(sample_honeypot_session.commands) == 3


class TestHoneypotFile:
    """Tests for the HoneypotFile model."""

    def test_honeypot_file_creation(self, db_session, sample_honeypot_session):
        """Test creating a honeypot file record."""
        f = HoneypotFile(
            session_id=sample_honeypot_session.id,
            filename="exploit.py",
            direction="download",
            size=2048,
            sha256="def456abc789",
            saved_path="/tmp/artifacts/def456abc789_exploit.py",
            raw={"outfile": "exploit.py"}
        )
        db_session.add(f)
        db_session.commit()
        
        assert f.id is not None
        assert f.session_id == sample_honeypot_session.id
        assert f.filename == "exploit.py"
        assert f.direction == "download"
        assert f.size == 2048
        assert f.sha256 == "def456abc789"

    def test_honeypot_file_dict(self, sample_honeypot_file):
        """Test the HoneypotFile.dict() method."""
        file_dict = sample_honeypot_file.dict()
        
        assert file_dict["id"] == sample_honeypot_file.id
        assert file_dict["session_id"] == sample_honeypot_file.session_id
        assert file_dict["filename"] == "malware.sh"
        assert file_dict["direction"] == "download"
        assert file_dict["sha256"] == "abc123def456"
        assert file_dict["saved_path"] == "/tmp/artifacts/abc123def456_malware.sh"
        assert "timestamp" in file_dict

    def test_honeypot_file_session_relationship(self, db_session, sample_honeypot_file, sample_honeypot_session):
        """Test the relationship between HoneypotFile and HoneypotSession."""
        db_session.refresh(sample_honeypot_file)
        db_session.refresh(sample_honeypot_session)
        
        assert sample_honeypot_file.session is not None
        assert sample_honeypot_file.session.id == sample_honeypot_session.id
        assert sample_honeypot_file in sample_honeypot_session.files

    def test_honeypot_file_upload_direction(self, db_session, sample_honeypot_session):
        """Test creating an upload file record."""
        f = HoneypotFile(
            session_id=sample_honeypot_session.id,
            filename="uploaded_script.sh",
            direction="upload",
            size=512
        )
        db_session.add(f)
        db_session.commit()
        
        assert f.direction == "upload"


class TestHoneypotNetworkFlow:
    """Tests for the HoneypotNetworkFlow model."""

    def test_network_flow_creation(self, db_session):
        """Test creating a network flow record."""
        flow = HoneypotNetworkFlow(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=54321,
            dst_port=443,
            proto="tcp",
            bytes=8192,
            packets=20,
            start_ts=datetime.now(timezone.utc),
            end_ts=datetime.now(timezone.utc),
            extra={"flags": "SYN"}
        )
        db_session.add(flow)
        db_session.commit()
        
        assert flow.id is not None
        assert flow.src_ip == "10.0.0.1"
        assert flow.dst_ip == "10.0.0.2"
        assert flow.proto == "tcp"
        assert flow.bytes == 8192
        assert flow.packets == 20

    def test_network_flow_dict(self, sample_network_flow):
        """Test the HoneypotNetworkFlow.dict() method."""
        flow_dict = sample_network_flow.dict()
        
        assert flow_dict["id"] == sample_network_flow.id
        assert flow_dict["src_ip"] == "192.168.1.100"
        assert flow_dict["dst_ip"] == "192.168.1.1"
        assert flow_dict["src_port"] == 12345
        assert flow_dict["dst_port"] == 80
        assert flow_dict["proto"] == "tcp"
        assert flow_dict["bytes"] == 4096
        assert flow_dict["packets"] == 10
        assert "start_ts" in flow_dict
        assert "end_ts" in flow_dict

    def test_network_flow_udp(self, db_session):
        """Test creating a UDP flow record."""
        flow = HoneypotNetworkFlow(
            src_ip="172.16.0.1",
            dst_ip="172.16.0.2",
            src_port=53,
            dst_port=12345,
            proto="udp",
            bytes=256,
            packets=2
        )
        db_session.add(flow)
        db_session.commit()
        
        assert flow.proto == "udp"

    def test_network_flow_nullable_ports(self, db_session):
        """Test that ports can be null (for protocols like ICMP)."""
        flow = HoneypotNetworkFlow(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=None,
            dst_port=None,
            proto="icmp",
            bytes=64,
            packets=1
        )
        db_session.add(flow)
        db_session.commit()
        
        assert flow.src_port is None
        assert flow.dst_port is None
        assert flow.proto == "icmp"
