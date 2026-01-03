"""
Tests for src/vector_store.py VectorStore class.
"""
import pytest
import os
from unittest.mock import patch, MagicMock


class TestVectorStoreInit:
    """Tests for VectorStore initialization."""

    def test_vector_store_unavailable_without_deps(self, temp_dir):
        """Test that VectorStore handles missing dependencies gracefully."""
        with patch.dict('sys.modules', {'qdrant_client': None, 'sentence_transformers': None}):
            # Force reimport with mocked modules
            import importlib
            from src import vector_store
            importlib.reload(vector_store)
            
            # Create instance - should not raise even without dependencies
            vs = vector_store.VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            assert vs.is_available() is False


class TestVectorStoreHelpers:
    """Tests for VectorStore helper methods."""

    @pytest.fixture
    def mock_vector_store(self, temp_dir):
        """Create a VectorStore with mocked dependencies."""
        with patch('src.vector_store._HAS_QDRANT', False), \
             patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            return vs

    def test_session_to_text_basic(self, mock_vector_store):
        """Test converting a session to text."""
        session = {
            "src_ip": "192.168.1.100",
            "username": "admin",
            "auth_success": "failed",
            "commands": [
                {"command": "ls -la"},
                {"command": "cat /etc/passwd"}
            ]
        }
        
        text = mock_vector_store._session_to_text(session)
        
        assert "192.168.1.100" in text
        assert "admin" in text
        assert "failed" in text
        assert "ls -la" in text

    def test_session_to_text_empty(self, mock_vector_store):
        """Test converting an empty session to text."""
        text = mock_vector_store._session_to_text({})
        assert "unknown" in text

    def test_node_to_text_basic(self, mock_vector_store):
        """Test converting a node to text."""
        node = {
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "organization": "Google LLC",
            "country": "United States"
        }
        
        text = mock_vector_store._node_to_text(node)
        
        assert "8.8.8.8" in text
        assert "dns.google" in text
        assert "Google LLC" in text

    def test_access_to_text_basic(self, mock_vector_store):
        """Test converting a web access to text."""
        access = {
            "remote_addr": "10.0.0.1",
            "method": "GET",
            "path": "/admin",
            "status": 403
        }
        
        text = mock_vector_store._access_to_text(access)
        
        assert "10.0.0.1" in text
        assert "GET" in text
        assert "/admin" in text

    def test_is_available_returns_false_without_deps(self, mock_vector_store):
        """Test that is_available returns False without dependencies."""
        assert mock_vector_store.is_available() is False


class TestVectorStoreEmbedding:
    """Tests for VectorStore embedding methods."""

    def test_embed_text_returns_none_without_model(self, temp_dir):
        """Test that embed_text returns None when model is not available."""
        with patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            
            result = vs.embed_text("test text")
            assert result is None

    def test_embed_texts_returns_none_without_model(self, temp_dir):
        """Test that embed_texts returns None when model is not available."""
        with patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            
            result = vs.embed_texts(["text1", "text2"])
            assert result is None


class TestVectorStoreIndexing:
    """Tests for VectorStore indexing methods."""

    def test_index_session_returns_false_without_deps(self, temp_dir):
        """Test that index_session returns False when not available."""
        with patch('src.vector_store._HAS_QDRANT', False), \
             patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            
            result = vs.index_session({"src_ip": "1.2.3.4"}, 1)
            assert result is False

    def test_index_node_returns_false_without_deps(self, temp_dir):
        """Test that index_node returns False when not available."""
        with patch('src.vector_store._HAS_QDRANT', False), \
             patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            
            result = vs.index_node({"ip": "1.2.3.4"}, "1.2.3.4")
            assert result is False


class TestVectorStoreSearch:
    """Tests for VectorStore search methods."""

    def test_search_similar_sessions_returns_empty_without_deps(self, temp_dir):
        """Test that search returns empty list when not available."""
        with patch('src.vector_store._HAS_QDRANT', False), \
             patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            
            result = vs.search_similar_sessions(query_text="test")
            assert result == []

    def test_search_similar_nodes_returns_empty_without_deps(self, temp_dir):
        """Test that node search returns empty list when not available."""
        with patch('src.vector_store._HAS_QDRANT', False), \
             patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            
            result = vs.search_similar_nodes(query_text="google")
            assert result == []

    def test_search_similar_threats_returns_empty_without_deps(self, temp_dir):
        """Test that threat search returns empty list when not available."""
        with patch('src.vector_store._HAS_QDRANT', False), \
             patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            
            result = vs.search_similar_threats(query_text="brute force")
            assert result == []


class TestVectorStoreStats:
    """Tests for VectorStore statistics methods."""

    def test_get_collection_stats_returns_error_without_deps(self, temp_dir):
        """Test that stats returns error when not available."""
        with patch('src.vector_store._HAS_QDRANT', False), \
             patch('src.vector_store._HAS_SENTENCE_TRANSFORMERS', False):
            from src.vector_store import VectorStore
            vs = VectorStore(qdrant_path=os.path.join(temp_dir, "qdrant"))
            
            result = vs.get_collection_stats()
            assert "error" in result
