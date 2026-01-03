"""
Shared pytest fixtures for HoneyMoon tests.
"""
import os
import sys
import tempfile
import pytest
from datetime import datetime, timezone

# Ensure the src module is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.entry import Base, NetworkNode, Organization, AnalysisSession, PathHop, WebAccess, ISP, OutgoingConnection, ThreatAnalysis, AttackerCluster, AgentTaskRecord, ChatConversation, CountermeasureRecord
from src.honeypot_models import HoneypotSession, HoneypotCommand, HoneypotFile, HoneypotNetworkFlow


@pytest.fixture
def db_session():
    """
    Create an in-memory SQLite database session for tests.
    Tables are created fresh for each test.
    """
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def sample_organization(db_session):
    """Create a sample organization for testing."""
    org = Organization(
        name="Test Organization",
        name_normalized="test organization",
        rdap={"provider": "Test Provider"},
        abuse_email="abuse@test.org",
        extra_data={"note": "test org"}
    )
    db_session.add(org)
    db_session.commit()
    return org


@pytest.fixture
def sample_network_node(db_session, sample_organization):
    """Create a sample network node for testing."""
    node = NetworkNode(
        ip="192.168.1.1",
        hostname="test-host.local",
        organization="Test Organization",
        organization_id=sample_organization.id,
        isp="Test ISP",
        asn="AS12345",
        country="United States",
        city="Test City",
        latitude=37.7749,
        longitude=-122.4194,
        is_tor_exit=False,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        seen_count=1,
        extra_data={"test": "data"}
    )
    db_session.add(node)
    db_session.commit()
    db_session.refresh(node)
    return node


@pytest.fixture
def sample_analysis_session(db_session, sample_network_node):
    """Create a sample analysis session for testing."""
    session = AnalysisSession(
        target_ip=sample_network_node.ip,
        mode="Plain",
        timestamp=datetime.now(timezone.utc)
    )
    db_session.add(session)
    db_session.commit()
    return session


@pytest.fixture
def sample_path_hop(db_session, sample_analysis_session, sample_network_node):
    """Create a sample path hop for testing."""
    hop = PathHop(
        session_id=sample_analysis_session.id,
        ip=sample_network_node.ip,
        hop_number=1,
        probe_index=1,
        rtt=0.005,
        timestamp=datetime.now(timezone.utc)
    )
    db_session.add(hop)
    db_session.commit()
    return hop


@pytest.fixture
def sample_web_access(db_session, sample_network_node):
    """Create a sample web access record for testing."""
    access = WebAccess(
        timestamp=datetime.now(timezone.utc),
        remote_addr=sample_network_node.ip,
        remote_port=54321,
        request="GET /test HTTP/1.1",
        method="GET",
        path="/test",
        status=200,
        body_bytes_sent=1024,
        http_user_agent="TestAgent/1.0",
        raw={"original": "data"}
    )
    db_session.add(access)
    db_session.commit()
    return access


@pytest.fixture
def sample_honeypot_session(db_session):
    """Create a sample honeypot session for testing."""
    session = HoneypotSession(
        cowrie_session="session_12345",
        src_ip="10.0.0.1",
        src_port=54321,
        username="root",
        auth_success="failed",
        raw_events=[{"event": "session.connect"}],
        extra={"note": "test"}
    )
    db_session.add(session)
    db_session.commit()
    return session


@pytest.fixture
def sample_honeypot_command(db_session, sample_honeypot_session):
    """Create a sample honeypot command for testing."""
    cmd = HoneypotCommand(
        session_id=sample_honeypot_session.id,
        command="ls -la",
        raw={"input": "ls -la"}
    )
    db_session.add(cmd)
    db_session.commit()
    return cmd


@pytest.fixture
def sample_honeypot_file(db_session, sample_honeypot_session):
    """Create a sample honeypot file for testing."""
    f = HoneypotFile(
        session_id=sample_honeypot_session.id,
        filename="malware.sh",
        direction="download",
        size=1024,
        sha256="abc123def456",
        saved_path="/tmp/artifacts/abc123def456_malware.sh",
        raw={"outfile": "malware.sh"}
    )
    db_session.add(f)
    db_session.commit()
    return f


@pytest.fixture
def sample_network_flow(db_session):
    """Create a sample network flow for testing."""
    flow = HoneypotNetworkFlow(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        src_port=12345,
        dst_port=80,
        proto="tcp",
        bytes=4096,
        packets=10,
        start_ts=datetime.now(timezone.utc),
        end_ts=datetime.now(timezone.utc),
        extra={}
    )
    db_session.add(flow)
    db_session.commit()
    return flow


@pytest.fixture
def sample_isp(db_session):
    """Create a sample ISP for testing."""
    isp = ISP(
        name="Test ISP Provider",
        name_normalized="test isp provider",
        asn="AS12345",
        abuse_email="abuse@testisp.net",
        extra_data={"note": "test isp"}
    )
    db_session.add(isp)
    db_session.commit()
    return isp


@pytest.fixture
def sample_outgoing_connection(db_session):
    """Create a sample outgoing connection for testing."""
    conn = OutgoingConnection(
        timestamp=datetime.now(timezone.utc),
        local_addr="192.168.1.100",
        local_port=54321,
        remote_addr="8.8.8.8",
        remote_port=443,
        proto="tcp",
        status="ESTABLISHED",
        pid=1234,
        process_name="python3",
        direction="outgoing",
        extra_data={}
    )
    db_session.add(conn)
    db_session.commit()
    return conn


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def flask_test_client(temp_dir):
    """
    Create a Flask test client with a temporary database.
    This fixture mocks the ForensicEngine to use a test database.
    """
    # Set environment variables for test configuration
    os.environ["IPMAP_TEMPLATES"] = os.path.join(os.path.dirname(__file__), "..", "templates")
    os.environ["IPMAP_STATIC"] = os.path.join(os.path.dirname(__file__), "..", "static")
    os.environ["HONEY_AUTO_INGEST"] = "false"
    os.environ["NGINX_AUTO_INGEST"] = "false"
    os.environ["OUTGOING_MONITOR"] = "false"
    os.environ["HONEY_DATA_DIR"] = temp_dir
    
    # Import app after setting environment variables
    from src.app import app
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        yield client
