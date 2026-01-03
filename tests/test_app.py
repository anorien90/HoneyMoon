"""
Tests for src/app.py Flask API routes.
"""
import pytest
import os
import sys
import tempfile
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone


@pytest.fixture
def app_client(temp_dir):
    """
    Create a Flask test client with a mocked ForensicEngine.
    """
    # Set environment variables before importing app
    os.environ["IPMAP_TEMPLATES"] = os.path.join(os.path.dirname(__file__), "..", "templates")
    os.environ["IPMAP_STATIC"] = os.path.join(os.path.dirname(__file__), "..", "static")
    os.environ["HONEY_AUTO_INGEST"] = "false"
    os.environ["NGINX_AUTO_INGEST"] = "false"
    os.environ["HONEY_DATA_DIR"] = temp_dir
    
    # Mock nmap.PortScanner at module level before src.app imports
    with patch.dict(sys.modules, {'nmap': MagicMock()}):
        # Clear any cached imports
        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith('src.'):
                del sys.modules[mod_name]
        
        # Import app with mocked nmap
        from src import app as app_module
        
        # Create a mock engine
        mock_engine = MagicMock()
        mock_engine.honeypot_data_dir = temp_dir
        
        # Replace the engine
        original_engine = app_module.engine
        app_module.engine = mock_engine
        
        app_module.app.config['TESTING'] = True
        
        with app_module.app.test_client() as client:
            yield client, mock_engine
        
        # Restore original engine
        app_module.engine = original_engine


class TestHealthEndpoint:
    """Tests for the /api/v1/health endpoint."""

    def test_health_check(self, app_client):
        """Test health check returns ok."""
        client, _ = app_client
        response = client.get('/api/v1/health')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"


class TestLocateEndpoint:
    """Tests for the /api/v1/locate endpoint."""

    def test_locate_no_ip(self, app_client):
        """Test locate without IP returns 400."""
        client, _ = app_client
        response = client.get('/api/v1/locate')
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_locate_ip_not_found(self, app_client):
        """Test locate with unknown IP returns 404."""
        client, mock_engine = app_client
        mock_engine.get_entry.return_value = None
        
        response = client.get('/api/v1/locate?ip=1.2.3.4')
        
        assert response.status_code == 404

    def test_locate_ip_success(self, app_client):
        """Test successful IP location."""
        client, mock_engine = app_client
        mock_engine.get_entry.return_value = {
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "organization": "Google LLC",
            "country": "United States"
        }
        mock_engine.get_organization_info.return_value = {
            "id": 1,
            "name": "Google LLC"
        }
        
        response = client.get('/api/v1/locate?ip=8.8.8.8')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["node"]["ip"] == "8.8.8.8"
        assert "organization" in data


class TestTraceEndpoint:
    """Tests for the /api/v1/trace endpoint."""

    def test_trace_no_ip(self, app_client):
        """Test trace without IP returns 400."""
        client, _ = app_client
        response = client.get('/api/v1/trace')
        
        assert response.status_code == 400

    def test_trace_success(self, app_client):
        """Test successful trace."""
        client, mock_engine = app_client
        mock_engine.run_analysis.return_value = {
            "session_id": 1,
            "target_ip": "8.8.8.8",
            "path": [
                {"hop_number": 1, "ip": "192.168.1.1", "rtt": 0.001}
            ]
        }
        mock_engine.get_entry.return_value = {
            "ip": "192.168.1.1",
            "organization": "Local"
        }
        
        response = client.get('/api/v1/trace?ip=8.8.8.8')
        
        assert response.status_code == 200
        data = response.get_json()
        assert "session" in data
        assert "nodes" in data

    def test_trace_deep_mode(self, app_client):
        """Test trace with deep mode."""
        client, mock_engine = app_client
        mock_engine.run_analysis.return_value = {
            "session_id": 1,
            "target_ip": "8.8.8.8",
            "path": []
        }
        
        response = client.get('/api/v1/trace?ip=8.8.8.8&deep=1')
        
        assert response.status_code == 200
        mock_engine.run_analysis.assert_called_once()
        _, kwargs = mock_engine.run_analysis.call_args
        assert kwargs.get("deep_mode") is True

    def test_trace_error(self, app_client):
        """Test trace error handling."""
        client, mock_engine = app_client
        mock_engine.run_analysis.side_effect = Exception("Trace failed")
        
        response = client.get('/api/v1/trace?ip=8.8.8.8')
        
        assert response.status_code == 500


class TestSearchEndpoint:
    """Tests for the /api/v1/search endpoint."""

    def test_search_nodes(self, app_client):
        """Test node search."""
        client, mock_engine = app_client
        mock_engine.search_nodes.return_value = [
            {"ip": "192.168.1.1", "hostname": "test.local"}
        ]
        
        response = client.get('/api/v1/search?type=node&q=192.168')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["type"] == "node"
        assert len(data["results"]) == 1

    def test_search_organizations(self, app_client):
        """Test organization search."""
        client, mock_engine = app_client
        mock_engine.search_organizations.return_value = [
            {"id": 1, "name": "Google LLC"}
        ]
        
        response = client.get('/api/v1/search?type=org&q=google')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["type"] == "organization"

    def test_search_fuzzy(self, app_client):
        """Test fuzzy search."""
        client, mock_engine = app_client
        mock_engine.search_nodes.return_value = []
        
        response = client.get('/api/v1/search?type=node&q=test&fuzzy=1')
        
        assert response.status_code == 200
        mock_engine.search_nodes.assert_called_once()
        _, kwargs = mock_engine.search_nodes.call_args
        assert kwargs.get("fuzzy") is True


class TestAccessesEndpoint:
    """Tests for the /api/v1/accesses endpoint."""

    def test_accesses_no_ip(self, app_client):
        """Test accesses without IP returns 400."""
        client, _ = app_client
        response = client.get('/api/v1/accesses')
        
        assert response.status_code == 400

    def test_accesses_success(self, app_client):
        """Test successful accesses lookup."""
        client, mock_engine = app_client
        mock_engine.get_accesses_for_ip.return_value = [
            {"id": 1, "remote_addr": "192.168.1.1", "path": "/test", "status": 200}
        ]
        
        response = client.get('/api/v1/accesses?ip=192.168.1.1')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["ip"] == "192.168.1.1"
        assert len(data["accesses"]) == 1


class TestHoneypotEndpoints:
    """Tests for honeypot-related endpoints."""

    def test_honeypot_sessions(self, app_client):
        """Test listing honeypot sessions."""
        client, mock_engine = app_client
        mock_engine.get_honeypot_sessions.return_value = [
            {"id": 1, "cowrie_session": "sess1", "src_ip": "10.0.0.1"}
        ]
        
        response = client.get('/api/v1/honeypot/sessions')
        
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["sessions"]) == 1

    def test_honeypot_session_by_id(self, app_client):
        """Test getting a specific honeypot session."""
        client, mock_engine = app_client
        mock_engine.get_honeypot_session.return_value = {
            "id": 1,
            "cowrie_session": "sess1",
            "src_ip": "10.0.0.1",
            "commands": [],
            "files": []
        }
        
        response = client.get('/api/v1/honeypot/session?id=1')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["session"]["id"] == 1

    def test_honeypot_session_not_found(self, app_client):
        """Test getting non-existent honeypot session."""
        client, mock_engine = app_client
        mock_engine.get_honeypot_session.return_value = None
        
        response = client.get('/api/v1/honeypot/session?id=99999')
        
        assert response.status_code == 404

    def test_honeypot_session_no_params(self, app_client):
        """Test honeypot session without params returns 400."""
        client, _ = app_client
        response = client.get('/api/v1/honeypot/session')
        
        assert response.status_code == 400

    def test_honeypot_ingest_no_path(self, app_client):
        """Test ingest without path returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/honeypot/ingest',
                               json={})
        
        assert response.status_code == 400

    def test_honeypot_ingest_outside_data_dir(self, app_client, temp_dir):
        """Test ingest with path outside data dir returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/honeypot/ingest',
                               json={"path": "/etc/passwd"})
        
        assert response.status_code == 400
        data = response.get_json()
        assert "inside honeypot data directory" in data["error"]

    def test_honeypot_ingest_success(self, app_client, temp_dir):
        """Test successful ingest."""
        client, mock_engine = app_client
        
        # Create a test file inside the honeypot data dir
        test_file = os.path.join(temp_dir, "test_cowrie.json")
        with open(test_file, "w") as f:
            f.write('{"session": "test"}\n')
        
        mock_engine.ingest_cowrie_file.return_value = {
            "lines_processed": 1,
            "errors": 0
        }
        
        response = client.post('/api/v1/honeypot/ingest',
                               json={"path": test_file})
        
        assert response.status_code == 200


class TestOrganizationEndpoints:
    """Tests for organization-related endpoints."""

    def test_organization_by_ip(self, app_client):
        """Test getting organization by IP."""
        client, mock_engine = app_client
        mock_engine.get_organization_info.return_value = {
            "id": 1,
            "name": "Google LLC"
        }
        
        response = client.get('/api/v1/organization?ip=8.8.8.8')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["organization"]["name"] == "Google LLC"

    def test_organization_by_id(self, app_client):
        """Test getting organization by ID."""
        client, mock_engine = app_client
        mock_engine.get_organization.return_value = {
            "id": 1,
            "name": "Google LLC"
        }
        
        response = client.get('/api/v1/organization?id=1')
        
        assert response.status_code == 200

    def test_organization_no_params(self, app_client):
        """Test organization without params returns 400."""
        client, _ = app_client
        response = client.get('/api/v1/organization')
        
        assert response.status_code == 400

    def test_organization_not_found(self, app_client):
        """Test organization not found returns 404."""
        client, mock_engine = app_client
        mock_engine.get_organization_info.return_value = None
        
        response = client.get('/api/v1/organization?ip=1.2.3.4')
        
        assert response.status_code == 404

    def test_organization_refresh(self, app_client):
        """Test organization refresh."""
        client, mock_engine = app_client
        mock_engine.refresh_organization.return_value = {
            "id": 1,
            "name": "Google LLC",
            "extra_data": {"company_search": {"source": "opencorporates"}}
        }
        
        response = client.get('/api/v1/organization/refresh?id=8.8.8.8')
        
        assert response.status_code == 200


class TestDbSearchEndpoint:
    """Tests for the /api/v1/db/search endpoint."""

    def test_db_search_nodes(self, app_client):
        """Test DB search for nodes."""
        client, mock_engine = app_client
        mock_engine.search_nodes.return_value = [
            {"ip": "192.168.1.1"}
        ]
        
        response = client.get('/api/v1/db/search?type=node&q=192.168')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["type"] == "node"

    def test_db_search_organizations(self, app_client):
        """Test DB search for organizations."""
        client, mock_engine = app_client
        mock_engine.search_organizations.return_value = []
        
        response = client.get('/api/v1/db/search?type=org&q=test')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["type"] == "organization"

    def test_db_search_unknown_type(self, app_client):
        """Test DB search with unknown type returns 400."""
        client, _ = app_client
        response = client.get('/api/v1/db/search?type=unknown&q=test')
        
        assert response.status_code == 400


class TestDbNodeEndpoint:
    """Tests for the /api/v1/db/node endpoint."""

    def test_db_node_no_ip(self, app_client):
        """Test db node without IP returns 400."""
        client, _ = app_client
        response = client.get('/api/v1/db/node')
        
        assert response.status_code == 400

    def test_db_node_not_found(self, app_client):
        """Test db node not found returns 404."""
        client, mock_engine = app_client
        mock_engine.db.query.return_value.filter_by.return_value.first.return_value = None
        
        response = client.get('/api/v1/db/node?ip=1.2.3.4')
        
        assert response.status_code == 404


class TestLiveConnectionsEndpoint:
    """Tests for the /api/v1/live/connections endpoint."""

    def test_live_connections_default_params(self, app_client):
        """Test live connections with default parameters."""
        client, mock_engine = app_client
        # Mock the db.query to return empty lists
        mock_engine.db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        
        response = client.get('/api/v1/live/connections')
        
        assert response.status_code == 200
        data = response.get_json()
        assert "minutes" in data
        assert data["minutes"] == 15  # default value
        assert "sessions" in data
        assert "flows" in data
        assert "cutoff" in data

    def test_live_connections_custom_minutes(self, app_client):
        """Test live connections with custom time window."""
        client, mock_engine = app_client
        mock_engine.db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        
        response = client.get('/api/v1/live/connections?minutes=30')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["minutes"] == 30

    def test_live_connections_max_minutes(self, app_client):
        """Test live connections clamps minutes to max value."""
        client, mock_engine = app_client
        mock_engine.db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        
        response = client.get('/api/v1/live/connections?minutes=9999')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["minutes"] == 1440  # max value

    def test_live_connections_min_minutes(self, app_client):
        """Test live connections clamps minutes to min value."""
        client, mock_engine = app_client
        mock_engine.db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        
        response = client.get('/api/v1/live/connections?minutes=0')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["minutes"] == 1  # min value

    def test_live_connections_custom_limit(self, app_client):
        """Test live connections with custom limit."""
        client, mock_engine = app_client
        mock_engine.db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
        
        response = client.get('/api/v1/live/connections?limit=50')
        
        assert response.status_code == 200
        # Verify limit was passed (indirectly via successful response)


class TestEnhancedLLMEndpoints:
    """Tests for enhanced LLM analysis endpoints."""

    def test_formal_report_no_session_id(self, app_client):
        """Test formal report without session_id returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/llm/formal_report',
                               json={})
        
        assert response.status_code == 400

    def test_formal_report_invalid_session_id(self, app_client):
        """Test formal report with invalid session_id returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/llm/formal_report',
                               json={"session_id": "invalid"})
        
        assert response.status_code == 400

    def test_formal_report_success(self, app_client):
        """Test successful formal report generation."""
        client, mock_engine = app_client
        mock_engine.generate_formal_report.return_value = {
            "generated": True,
            "severity": "high",
            "summary": "Test summary"
        }
        
        response = client.post('/api/v1/llm/formal_report',
                               json={"session_id": 1})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data.get("generated") is True

    def test_countermeasures_no_session_id(self, app_client):
        """Test countermeasures without session_id returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/llm/countermeasures',
                               json={})
        
        assert response.status_code == 400

    def test_countermeasures_success(self, app_client):
        """Test successful countermeasure recommendation."""
        client, mock_engine = app_client
        mock_engine.recommend_active_countermeasures.return_value = {
            "recommended": True,
            "recommended_capability": "json_tail",
            "priority": "high"
        }
        
        response = client.post('/api/v1/llm/countermeasures',
                               json={"session_id": 1})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data.get("recommended") is True

    def test_output_plugin_no_trigger_events(self, app_client):
        """Test output plugin without trigger_events returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/llm/output_plugin',
                               json={"response_actions": ["alert"]})
        
        assert response.status_code == 400

    def test_output_plugin_no_response_actions(self, app_client):
        """Test output plugin without response_actions returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/llm/output_plugin',
                               json={"trigger_events": ["cowrie.command.input"]})
        
        assert response.status_code == 400

    def test_output_plugin_success(self, app_client):
        """Test successful output plugin generation."""
        client, mock_engine = app_client
        mock_engine.generate_output_plugin_code.return_value = {
            "generated": True,
            "plugin_code": "# Generated code"
        }
        
        response = client.post('/api/v1/llm/output_plugin',
                               json={
                                   "trigger_events": ["cowrie.command.input"],
                                   "response_actions": ["alert"]
                               })
        
        assert response.status_code == 200
        data = response.get_json()
        assert data.get("generated") is True

    def test_realtime_analysis_no_commands(self, app_client):
        """Test realtime analysis without commands returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/llm/realtime_analysis',
                               json={})
        
        assert response.status_code == 400

    def test_realtime_analysis_success(self, app_client):
        """Test successful realtime analysis."""
        client, mock_engine = app_client
        mock_engine.analyze_real_time_commands.return_value = {
            "analyzed": True,
            "urgency": "high",
            "threat_detected": True
        }
        
        response = client.post('/api/v1/llm/realtime_analysis',
                               json={"commands": ["ls -la", "cat /etc/passwd"]})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data.get("analyzed") is True

    def test_detection_rules_no_session_id(self, app_client):
        """Test detection rules without session_id returns 400."""
        client, _ = app_client
        response = client.post('/api/v1/llm/detection_rules',
                               json={})
        
        assert response.status_code == 400

    def test_detection_rules_success(self, app_client):
        """Test successful detection rules generation."""
        client, mock_engine = app_client
        mock_engine.generate_detection_rules.return_value = {
            "generated": True,
            "sigma_rules": ["rule: test"],
            "firewall_rules": ["iptables -A INPUT -s 1.2.3.4 -j DROP"]
        }
        
        response = client.post('/api/v1/llm/detection_rules',
                               json={"session_id": 1})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data.get("generated") is True
