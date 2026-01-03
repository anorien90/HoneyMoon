"""
Tests for src/forensic_engine.py ForensicEngine class.
"""
import pytest
import os
import json
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.entry import Base, NetworkNode, Organization, AnalysisSession, PathHop, WebAccess
from src.honeypot_models import HoneypotSession, HoneypotCommand, HoneypotFile, HoneypotNetworkFlow


@pytest.fixture
def mock_nmap():
    """Mock nmap.PortScanner to avoid requiring nmap to be installed."""
    with patch('nmap.PortScanner') as mock:
        mock.return_value = MagicMock()
        yield mock


class TestForensicEngineInit:
    """Tests for ForensicEngine initialization."""

    def test_forensic_engine_creates_tables(self, temp_dir, mock_nmap):
        """Test that ForensicEngine creates database tables on init."""
        db_path = os.path.join(temp_dir, "test.db")
        
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path=f"sqlite:///{db_path}",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            
            # Verify tables exist by querying them
            assert engine.db.query(NetworkNode).count() >= 0
            assert engine.db.query(Organization).count() >= 0
            assert engine.db.query(HoneypotSession).count() >= 0

    def test_forensic_engine_creates_honeypot_dirs(self, temp_dir, mock_nmap):
        """Test that ForensicEngine creates honeypot data directories."""
        honeypot_dir = os.path.join(temp_dir, "honeypot_data")
        
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": honeypot_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path=f"sqlite:///{os.path.join(temp_dir, 'test.db')}",
                honeypot_data_dir=honeypot_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            
            assert os.path.isdir(honeypot_dir)
            assert os.path.isdir(os.path.join(honeypot_dir, "artifacts"))


class TestForensicEngineHelpers:
    """Tests for ForensicEngine helper methods."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_ensure_aware_with_naive_datetime(self, engine):
        """Test _ensure_aware with a naive datetime."""
        naive_dt = datetime(2024, 1, 1, 12, 0, 0)
        aware_dt = engine._ensure_aware(naive_dt)
        
        assert aware_dt.tzinfo is not None
        assert aware_dt.tzinfo == timezone.utc

    def test_ensure_aware_with_aware_datetime(self, engine):
        """Test _ensure_aware with an aware datetime."""
        aware_dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = engine._ensure_aware(aware_dt)
        
        assert result.tzinfo == timezone.utc

    def test_ensure_aware_with_none(self, engine):
        """Test _ensure_aware with None."""
        assert engine._ensure_aware(None) is None


class TestOrganizationMethods:
    """Tests for organization-related methods."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_get_or_create_organization_new(self, engine):
        """Test creating a new organization."""
        with patch.object(engine, 'search_company_registry', return_value=None):
            org = engine.get_or_create_organization("New Test Org")
            
            assert org is not None
            assert org.name == "New Test Org"
            assert org.name_normalized == "new test org"

    def test_get_or_create_organization_existing(self, engine):
        """Test getting an existing organization."""
        with patch.object(engine, 'search_company_registry', return_value=None):
            # Create first
            org1 = engine.get_or_create_organization("Existing Org")
            # Get again
            org2 = engine.get_or_create_organization("Existing Org")
            
            assert org1.id == org2.id

    def test_get_or_create_organization_empty_name(self, engine):
        """Test with empty organization name."""
        org = engine.get_or_create_organization("")
        assert org is None

    def test_get_or_create_organization_none_name(self, engine):
        """Test with None organization name."""
        org = engine.get_or_create_organization(None)
        assert org is None

    def test_search_organizations_empty_query(self, engine):
        """Test searching organizations with empty query."""
        with patch.object(engine, 'search_company_registry', return_value=None):
            # Create some organizations
            engine.get_or_create_organization("Test Org 1")
            engine.get_or_create_organization("Test Org 2")
            
            results = engine.search_organizations(query="", limit=10)
            
            assert len(results) == 2

    def test_search_organizations_fuzzy(self, engine):
        """Test fuzzy search for organizations."""
        with patch.object(engine, 'search_company_registry', return_value=None):
            engine.get_or_create_organization("Google LLC")
            engine.get_or_create_organization("Microsoft Corp")
            
            results = engine.search_organizations(query="goo", fuzzy=True, limit=10)
            
            assert len(results) == 1
            assert "Google" in results[0]["name"]

    def test_search_organizations_exact(self, engine):
        """Test exact search for organizations."""
        with patch.object(engine, 'search_company_registry', return_value=None):
            engine.get_or_create_organization("Exact Match Org")
            
            results = engine.search_organizations(query="Exact Match Org", fuzzy=False, limit=10)
            
            assert len(results) == 1


class TestNodeMethods:
    """Tests for network node methods."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_ensure_node_minimal(self, engine):
        """Test creating a minimal node record."""
        node = engine.ensure_node_minimal("10.0.0.1")
        
        assert node is not None
        assert node.ip == "10.0.0.1"
        assert node.seen_count == 1

    def test_ensure_node_minimal_existing(self, engine):
        """Test ensure_node_minimal with existing node."""
        # Create first
        node1 = engine.ensure_node_minimal("10.0.0.2")
        # Call again
        node2 = engine.ensure_node_minimal("10.0.0.2")
        
        assert node2.seen_count == 2

    def test_ensure_node_minimal_none_ip(self, engine):
        """Test ensure_node_minimal with None IP."""
        node = engine.ensure_node_minimal(None)
        assert node is None

    def test_search_nodes_empty_query(self, engine):
        """Test searching nodes with empty query."""
        engine.ensure_node_minimal("192.168.1.1")
        engine.ensure_node_minimal("192.168.1.2")
        
        results = engine.search_nodes(query="", limit=10)
        
        assert len(results) == 2

    def test_search_nodes_fuzzy(self, engine):
        """Test fuzzy search for nodes."""
        node = engine.ensure_node_minimal("192.168.1.1")
        node.hostname = "server-one.local"
        engine.db.commit()
        
        engine.ensure_node_minimal("10.0.0.1")
        
        results = engine.search_nodes(query="server", fuzzy=True, limit=10)
        
        assert len(results) == 1
        assert results[0]["ip"] == "192.168.1.1"

    def test_get_entry_existing(self, engine):
        """Test getting an existing entry."""
        engine.ensure_node_minimal("8.8.8.8")
        
        entry = engine.get_entry("8.8.8.8")
        
        assert entry is not None
        assert entry["ip"] == "8.8.8.8"

    def test_get_entry_nonexistent(self, engine):
        """Test getting a non-existent entry."""
        entry = engine.get_entry("1.2.3.4")
        
        assert entry is None


class TestHoneypotMethods:
    """Tests for honeypot-related methods."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_get_honeypot_sessions_empty(self, engine):
        """Test getting honeypot sessions when none exist."""
        sessions = engine.get_honeypot_sessions()
        assert sessions == []

    def test_get_honeypot_sessions(self, engine):
        """Test getting honeypot sessions."""
        # Create some sessions directly
        session1 = HoneypotSession(cowrie_session="sess1", src_ip="10.0.0.1")
        session2 = HoneypotSession(cowrie_session="sess2", src_ip="10.0.0.2")
        engine.db.add_all([session1, session2])
        engine.db.commit()
        
        sessions = engine.get_honeypot_sessions(limit=10)
        
        assert len(sessions) == 2

    def test_get_honeypot_session_by_id(self, engine):
        """Test getting a specific honeypot session by ID."""
        session = HoneypotSession(cowrie_session="test_sess", src_ip="10.0.0.1")
        engine.db.add(session)
        engine.db.commit()
        
        result = engine.get_honeypot_session(session.id)
        
        assert result is not None
        assert result["cowrie_session"] == "test_sess"

    def test_get_honeypot_session_nonexistent(self, engine):
        """Test getting a non-existent honeypot session."""
        result = engine.get_honeypot_session(99999)
        assert result is None

    def test_ingest_cowrie_file_not_found(self, engine, temp_dir):
        """Test ingesting a non-existent cowrie file."""
        result = engine.ingest_cowrie_file("/nonexistent/path.json")
        
        assert result["errors"] == 1
        assert "File not found" in result.get("message", "")

    def test_ingest_cowrie_file(self, engine, temp_dir):
        """Test ingesting a cowrie JSON file."""
        # Create a test file
        cowrie_log = os.path.join(temp_dir, "cowrie.json")
        events = [
            {"session": "sess1", "src_ip": "10.0.0.1", "event": "session.connect"},
            {"session": "sess1", "src_ip": "10.0.0.1", "input": "ls -la", "event": "command.input"},
        ]
        with open(cowrie_log, "w") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
        
        with patch.object(engine, 'get_node_from_db_or_web', return_value=MagicMock(ip="10.0.0.1", organization="Test Org", asn="AS123", country="US")):
            result = engine.ingest_cowrie_file(cowrie_log, enrich=True)
        
        assert result["lines_processed"] == 2
        
        # Verify session was created
        sessions = engine.get_honeypot_sessions()
        assert len(sessions) >= 1


class TestWebAccessMethods:
    """Tests for web access methods."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_get_accesses_for_ip_empty(self, engine):
        """Test getting accesses for IP with no records."""
        accesses = engine.get_accesses_for_ip("192.168.1.1")
        assert accesses == []

    def test_get_accesses_for_ip(self, engine):
        """Test getting accesses for a specific IP."""
        # Create a node first
        node = engine.ensure_node_minimal("192.168.1.1")
        engine.db.commit()
        
        # Create some access records
        access = WebAccess(
            remote_addr="192.168.1.1",
            request="GET / HTTP/1.1",
            method="GET",
            path="/",
            status=200
        )
        engine.db.add(access)
        engine.db.commit()
        
        accesses = engine.get_accesses_for_ip("192.168.1.1")
        
        assert len(accesses) == 1
        assert accesses[0]["method"] == "GET"

    def test_get_accesses_for_ip_empty_ip(self, engine):
        """Test getting accesses with empty IP."""
        accesses = engine.get_accesses_for_ip("")
        assert accesses == []


class TestLookupMethods:
    """Tests for IP lookup methods."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_lookup_with_fallback(self, engine):
        """Test IP lookup with fallback to ip-api.com when GeoLite is not available."""
        # Mock the geolite lookup to return None to trigger fallback
        with patch.object(engine, '_geolite_lookup', return_value=None), \
             patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "status": "success",
                "country": "United States",
                "city": "Mountain View",
                "isp": "Google LLC",
                "org": "Google LLC",
                "as": "AS15169 Google LLC",
                "lat": 37.386,
                "lon": -122.084
            }
            mock_get.return_value = mock_response
            
            result = engine.lookup("8.8.8.8")
            
            assert result["country"] == "United States"
            assert result["city"] == "Mountain View"

    def test_check_tor_not_exit(self, engine):
        """Test checking a non-Tor exit node."""
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.text = "ExitAddress 1.2.3.4\nExitAddress 5.6.7.8"
            mock_get.return_value = mock_response
            
            result = engine.check_tor("192.168.1.1")
            
            assert result is False

    def test_check_tor_is_exit(self, engine):
        """Test checking a Tor exit node."""
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.text = "ExitAddress 192.168.1.1\nExitAddress 5.6.7.8"
            mock_get.return_value = mock_response
            
            result = engine.check_tor("192.168.1.1")
            
            assert result is True


class TestHoneypotState:
    """Tests for honeypot state management."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_load_honeypot_state_no_file(self, engine):
        """Test loading honeypot state when no file exists."""
        state = engine._load_honeypot_state()
        
        assert state["offset"] == 0
        assert state["processed_hashes"] == []

    def test_save_and_load_honeypot_state(self, engine):
        """Test saving and loading honeypot state."""
        state = {"offset": 1000, "processed_hashes": ["abc123", "def456"]}
        engine._save_honeypot_state(state)
        
        loaded = engine._load_honeypot_state()
        
        assert loaded["offset"] == 1000
        assert "abc123" in loaded["processed_hashes"]
        assert "def456" in loaded["processed_hashes"]


class TestNginxState:
    """Tests for nginx state management."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_load_nginx_state_no_file(self, engine):
        """Test loading nginx state when no file exists."""
        state = engine._load_nginx_state()
        
        assert state["offset"] == 0
        assert state["processed_hashes"] == []

    def test_save_and_load_nginx_state(self, engine, temp_dir):
        """Test saving and loading nginx state."""
        # Update the state path to be in our temp dir
        engine._nginx_state_path = os.path.join(temp_dir, ".nginx_state.json")
        
        state = {"offset": 2000, "processed_hashes": ["xyz789"]}
        engine._save_nginx_state(state)
        
        loaded = engine._load_nginx_state()
        
        assert loaded["offset"] == 2000
        assert "xyz789" in loaded["processed_hashes"]


class TestServiceBanners:
    """Tests for service banner methods."""

    @pytest.fixture
    def engine(self, temp_dir, mock_nmap):
        """Create a ForensicEngine instance for testing."""
        with patch.dict(os.environ, {
            "HONEY_AUTO_INGEST": "false",
            "NGINX_AUTO_INGEST": "false",
            "HONEY_DATA_DIR": temp_dir
        }):
            from src.forensic_engine import ForensicEngine
            engine = ForensicEngine(
                db_path="sqlite:///:memory:",
                honeypot_data_dir=temp_dir,
                honey_auto_ingest=False,
                nginx_auto_ingest=False
            )
            return engine

    def test_get_service_banner_success(self, engine):
        """Test successful banner grab."""
        with patch('socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_7.9"
            
            banner = engine.get_service_banner("192.168.1.1", 22)
            
            assert banner == "SSH-2.0-OpenSSH_7.9"

    def test_get_service_banner_failure(self, engine):
        """Test banner grab failure."""
        with patch('socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock
            mock_sock.connect.side_effect = ConnectionRefusedError()
            
            banner = engine.get_service_banner("192.168.1.1", 9999)
            
            assert banner is None

    def test_get_service_banners_multiple(self, engine):
        """Test getting banners from multiple ports."""
        with patch.object(engine, 'get_service_banner') as mock_banner:
            mock_banner.side_effect = ["SSH-2.0-OpenSSH", "220 SMTP Ready", None]
            
            banners = engine.get_service_banners("192.168.1.1", [22, 25, 80])
            
            assert 22 in banners
            assert 25 in banners
            assert 80 not in banners  # None values not included
