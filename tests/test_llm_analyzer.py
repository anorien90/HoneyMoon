"""
Tests for src/llm_analyzer.py LLMAnalyzer class.
"""
import pytest
import os
from unittest.mock import patch, MagicMock


class TestLLMAnalyzerInit:
    """Tests for LLMAnalyzer initialization."""

    def test_llm_analyzer_unavailable_without_deps(self, temp_dir):
        """Test that LLMAnalyzer handles missing dependencies gracefully."""
        with patch.dict('sys.modules', {'ollama': None}):
            import importlib
            from src import llm_analyzer
            importlib.reload(llm_analyzer)
            
            analyzer = llm_analyzer.LLMAnalyzer()
            assert analyzer.is_available() is False


class TestLLMAnalyzerHelpers:
    """Tests for LLMAnalyzer helper methods."""

    @pytest.fixture
    def mock_analyzer(self):
        """Create an LLMAnalyzer with mocked dependencies."""
        with patch('src.llm_analyzer._HAS_OLLAMA', False):
            from src.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer()
            return analyzer

    def test_is_available_returns_false_without_deps(self, mock_analyzer):
        """Test that is_available returns False without dependencies."""
        assert mock_analyzer.is_available() is False

    def test_parse_json_response_valid_json(self, mock_analyzer):
        """Test parsing valid JSON response."""
        response = '{"threat_type": "SSH Brute Force", "severity": "high"}'
        result = mock_analyzer._parse_json_response(response)
        
        assert result is not None
        assert result["threat_type"] == "SSH Brute Force"
        assert result["severity"] == "high"

    def test_parse_json_response_json_in_markdown(self, mock_analyzer):
        """Test parsing JSON from markdown code block."""
        response = '''Here is the analysis:
```json
{"threat_type": "Malware", "severity": "critical"}
```
'''
        result = mock_analyzer._parse_json_response(response)
        
        assert result is not None
        assert result["threat_type"] == "Malware"

    def test_parse_json_response_invalid_json(self, mock_analyzer):
        """Test parsing invalid JSON response."""
        response = "This is not JSON at all"
        result = mock_analyzer._parse_json_response(response)
        
        assert result is None

    def test_parse_json_response_empty(self, mock_analyzer):
        """Test parsing empty response."""
        result = mock_analyzer._parse_json_response("")
        assert result is None

    def test_parse_json_response_none(self, mock_analyzer):
        """Test parsing None response."""
        result = mock_analyzer._parse_json_response(None)
        assert result is None


class TestLLMAnalyzerAnalysis:
    """Tests for LLMAnalyzer analysis methods."""

    @pytest.fixture
    def mock_analyzer(self):
        """Create an LLMAnalyzer with mocked dependencies."""
        with patch('src.llm_analyzer._HAS_OLLAMA', False):
            from src.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer()
            return analyzer

    def test_analyze_session_returns_error_without_deps(self, mock_analyzer):
        """Test that analyze_session returns error when not available."""
        session = {
            "src_ip": "192.168.1.100",
            "commands": [{"command": "ls -la"}]
        }
        
        result = mock_analyzer.analyze_session(session)
        
        assert "error" in result
        assert result.get("analyzed") is False

    def test_analyze_access_logs_returns_error_without_deps(self, mock_analyzer):
        """Test that analyze_access_logs returns error when not available."""
        accesses = [
            {"remote_addr": "10.0.0.1", "method": "GET", "path": "/admin"}
        ]
        
        result = mock_analyzer.analyze_access_logs(accesses)
        
        assert "error" in result
        assert result.get("analyzed") is False

    def test_analyze_connections_returns_error_without_deps(self, mock_analyzer):
        """Test that analyze_connections returns error when not available."""
        connections = [
            {"local_addr": "192.168.1.1", "remote_addr": "8.8.8.8", "remote_port": 443}
        ]
        
        result = mock_analyzer.analyze_connections(connections)
        
        assert "error" in result
        assert result.get("analyzed") is False


class TestLLMAnalyzerCountermeasure:
    """Tests for LLMAnalyzer countermeasure methods."""

    @pytest.fixture
    def mock_analyzer(self):
        """Create an LLMAnalyzer with mocked dependencies."""
        with patch('src.llm_analyzer._HAS_OLLAMA', False):
            from src.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer()
            return analyzer

    def test_plan_countermeasure_returns_error_without_deps(self, mock_analyzer):
        """Test that plan_countermeasure returns error when not available."""
        threat_analysis = {
            "threat_type": "SSH Brute Force",
            "severity": "high"
        }
        
        result = mock_analyzer.plan_countermeasure(threat_analysis)
        
        assert "error" in result
        assert result.get("planned") is False


class TestLLMAnalyzerUnify:
    """Tests for LLMAnalyzer unification methods."""

    @pytest.fixture
    def mock_analyzer(self):
        """Create an LLMAnalyzer with mocked dependencies."""
        with patch('src.llm_analyzer._HAS_OLLAMA', False):
            from src.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer()
            return analyzer

    def test_unify_threat_profile_returns_error_without_deps(self, mock_analyzer):
        """Test that unify_threat_profile returns error when not available."""
        sessions = [
            {"src_ip": "192.168.1.100", "commands": [{"command": "ls"}]},
            {"src_ip": "192.168.1.101", "commands": [{"command": "pwd"}]}
        ]
        
        result = mock_analyzer.unify_threat_profile(sessions)
        
        assert "error" in result
        assert result.get("unified") is False


class TestLLMAnalyzerArtifact:
    """Tests for LLMAnalyzer artifact examination methods."""

    @pytest.fixture
    def mock_analyzer(self):
        """Create an LLMAnalyzer with mocked dependencies."""
        with patch('src.llm_analyzer._HAS_OLLAMA', False):
            from src.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer()
            return analyzer

    def test_examine_artifact_returns_error_without_deps(self, mock_analyzer, temp_dir):
        """Test that examine_artifact returns error when not available."""
        # Create a test artifact
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("#!/bin/bash\necho 'test'")
        
        result = mock_analyzer.examine_artifact(artifact_path)
        
        assert "error" in result
        assert result.get("examined") is False

    def test_examine_artifact_handles_missing_file(self, mock_analyzer):
        """Test that examine_artifact handles missing file."""
        with patch.object(mock_analyzer, 'is_available', return_value=True):
            result = mock_analyzer.examine_artifact("/nonexistent/path.txt")
            
            assert "error" in result


class TestLLMAnalyzerModelInfo:
    """Tests for LLMAnalyzer model info methods."""

    def test_get_model_info(self):
        """Test getting model info."""
        with patch('src.llm_analyzer._HAS_OLLAMA', False):
            from src.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer()
            
            info = analyzer.get_model_info()
            
            assert "model" in info
            assert "available" in info
            assert "supported_models" in info


class TestLLMAnalyzerWithMockedOllama:
    """Tests for LLMAnalyzer with mocked Ollama."""

    def test_analyze_session_with_mock(self):
        """Test session analysis with mocked Ollama."""
        mock_ollama = MagicMock()
        mock_ollama.list.return_value = {"models": [{"name": "granite3.1-dense:8b"}]}
        mock_ollama.chat.return_value = {
            "message": {
                "content": '{"threat_type": "SSH Brute Force", "severity": "high", "confidence": 0.9}'
            }
        }
        
        from src.llm_analyzer import LLMAnalyzer
        analyzer = LLMAnalyzer()
        # Manually set up the mocked state
        analyzer._client = mock_ollama
        analyzer._model_available = True
        
        session = {
            "src_ip": "192.168.1.100",
            "username": "admin",
            "auth_success": "failed",
            "commands": [
                {"command": "ls -la"},
                {"command": "cat /etc/passwd"}
            ]
        }
        
        # Mock _HAS_OLLAMA by patching the module-level variable
        with patch('src.llm_analyzer._HAS_OLLAMA', True):
            result = analyzer.analyze_session(session)
        
        assert result.get("analyzed") is True
        assert result.get("threat_type") == "SSH Brute Force"
        assert result.get("severity") == "high"

    def test_is_available_with_mock(self):
        """Test that is_available returns True with mocked Ollama."""
        mock_ollama = MagicMock()
        
        from src.llm_analyzer import LLMAnalyzer
        analyzer = LLMAnalyzer()
        analyzer._client = mock_ollama
        analyzer._model_available = True
        
        with patch('src.llm_analyzer._HAS_OLLAMA', True):
            assert analyzer.is_available() is True
