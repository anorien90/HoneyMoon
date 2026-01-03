"""
Tests for src/mcp_server.py MCP Server.
"""
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone


class TestMCPServer:
    """Tests for the MCP Server."""

    @pytest.fixture
    def mock_engine(self):
        """Create a mock forensic engine."""
        engine = MagicMock()
        engine.get_entry.return_value = {
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "organization": "Google LLC",
            "country": "United States"
        }
        engine.get_organization_info.return_value = {"id": 1, "name": "Google LLC"}
        engine.get_accesses_for_ip.return_value = []
        engine.get_honeypot_sessions.return_value = []
        engine.get_honeypot_session.return_value = {
            "id": 1,
            "cowrie_session": "test123",
            "src_ip": "10.0.0.1",
            "commands": [],
            "files": []
        }
        engine.search_similar_sessions.return_value = []
        engine.search_similar_threats.return_value = []
        engine.search_nodes.return_value = []
        engine.find_similar_attackers.return_value = []
        engine.analyze_session_with_llm.return_value = {"analyzed": True}
        engine.get_llm_status.return_value = {"available": True}
        engine.get_vector_store_status.return_value = {"available": True}
        engine.get_outgoing_connections.return_value = []
        return engine

    @pytest.fixture
    def mcp_server(self, mock_engine):
        """Create an MCP server with mocked engine."""
        from src.mcp_server import MCPServer
        server = MCPServer(forensic_engine=mock_engine)
        return server

    def test_server_initialization(self, mcp_server):
        """Test MCP server initializes with default tools."""
        tools = mcp_server.get_tools()
        assert len(tools) > 0
        
        # Check some expected tools exist
        tool_names = [t["name"] for t in tools]
        assert "get_ip_intel" in tool_names
        assert "get_honeypot_session" in tool_names
        assert "search_similar_sessions" in tool_names
        assert "analyze_session" in tool_names

    def test_get_tools_by_category(self, mcp_server):
        """Test filtering tools by category."""
        from src.mcp_server import ToolCategory
        
        investigation_tools = mcp_server.get_tools(category=ToolCategory.INVESTIGATION)
        assert all(t["category"] == "investigation" for t in investigation_tools)
        
        analysis_tools = mcp_server.get_tools(category=ToolCategory.ANALYSIS)
        assert all(t["category"] == "analysis" for t in analysis_tools)

    def test_get_tools_exclude_intrusive(self, mcp_server):
        """Test excluding intrusive tools."""
        all_tools = mcp_server.get_tools(include_intrusive=True)
        safe_tools = mcp_server.get_tools(include_intrusive=False)
        
        assert len(safe_tools) <= len(all_tools)
        assert all(not t["is_intrusive"] for t in safe_tools)

    def test_get_tool(self, mcp_server):
        """Test getting a specific tool."""
        tool = mcp_server.get_tool("get_ip_intel")
        
        assert tool is not None
        assert tool["name"] == "get_ip_intel"
        assert "description" in tool
        assert "parameters" in tool

    def test_get_tool_not_found(self, mcp_server):
        """Test getting non-existent tool returns None."""
        tool = mcp_server.get_tool("nonexistent_tool")
        assert tool is None

    def test_execute_tool_unknown(self, mcp_server):
        """Test executing unknown tool returns error."""
        result = mcp_server.execute_tool("unknown_tool", {})
        
        assert result.success is False
        assert "Unknown tool" in result.error

    def test_execute_tool_no_engine(self):
        """Test executing tool without bound engine returns error."""
        from src.mcp_server import MCPServer
        server = MCPServer()  # No engine
        
        result = server.execute_tool("get_ip_intel", {"ip": "8.8.8.8"})
        
        assert result.success is False
        assert "engine not bound" in result.error

    def test_execute_get_ip_intel(self, mcp_server, mock_engine):
        """Test executing get_ip_intel tool."""
        result = mcp_server.execute_tool("get_ip_intel", {"ip": "8.8.8.8"})
        
        assert result.success is True
        assert "node" in result.data
        assert result.data["node"]["ip"] == "8.8.8.8"
        mock_engine.get_entry.assert_called_once_with("8.8.8.8")

    def test_execute_get_honeypot_session(self, mcp_server, mock_engine):
        """Test executing get_honeypot_session tool."""
        result = mcp_server.execute_tool("get_honeypot_session", {"session_id": 1})
        
        assert result.success is True
        assert result.data["id"] == 1
        mock_engine.get_honeypot_session.assert_called_once_with(1)

    def test_execute_list_honeypot_sessions(self, mcp_server, mock_engine):
        """Test executing list_honeypot_sessions tool."""
        mock_engine.get_honeypot_sessions.return_value = [
            {"id": 1, "src_ip": "10.0.0.1"},
            {"id": 2, "src_ip": "10.0.0.2"}
        ]
        
        result = mcp_server.execute_tool("list_honeypot_sessions", {"limit": 10})
        
        assert result.success is True
        assert "sessions" in result.data
        assert result.data["count"] == 2

    def test_execute_list_honeypot_sessions_with_filter(self, mcp_server, mock_engine):
        """Test list_honeypot_sessions with IP filter."""
        mock_engine.get_honeypot_sessions.return_value = [
            {"id": 1, "src_ip": "10.0.0.1"},
            {"id": 2, "src_ip": "10.0.0.2"}
        ]
        
        result = mcp_server.execute_tool("list_honeypot_sessions", {
            "limit": 10,
            "ip_filter": "10.0.0.1"
        })
        
        assert result.success is True
        assert result.data["count"] == 1

    def test_execute_search_similar_sessions(self, mcp_server, mock_engine):
        """Test executing search_similar_sessions tool."""
        result = mcp_server.execute_tool("search_similar_sessions", {
            "query": "ssh brute force"
        })
        
        assert result.success is True
        mock_engine.search_similar_sessions.assert_called_once()

    def test_execute_search_nodes(self, mcp_server, mock_engine):
        """Test executing search_nodes tool."""
        result = mcp_server.execute_tool("search_nodes", {
            "query": "google",
            "fuzzy": True,
            "limit": 20
        })
        
        assert result.success is True
        mock_engine.search_nodes.assert_called_once_with(
            query="google",
            fuzzy=True,
            limit=20
        )

    def test_execute_analyze_session(self, mcp_server, mock_engine):
        """Test executing analyze_session tool."""
        result = mcp_server.execute_tool("analyze_session", {
            "session_id": 1,
            "save_result": True
        })
        
        assert result.success is True
        mock_engine.analyze_session_with_llm.assert_called_once()

    def test_execute_get_system_status(self, mcp_server, mock_engine):
        """Test executing get_system_status tool."""
        result = mcp_server.execute_tool("get_system_status", {})
        
        assert result.success is True
        assert "llm" in result.data
        assert "vector_store" in result.data
        assert "mcp_tools_count" in result.data

    def test_execute_intrusive_tool_without_confirmation(self, mcp_server, mock_engine):
        """Test that intrusive tools require confirmation."""
        # First, check if the tool requires confirmation
        tool = mcp_server.get_tool("recommend_active_countermeasures")
        
        if tool and tool.get("requires_confirmation"):
            result = mcp_server.execute_tool("recommend_active_countermeasures", {
                "session_id": 1
            }, confirmed=False)
            
            assert result.success is False
            assert "requires confirmation" in result.error.lower()

    def test_execute_intrusive_tool_with_confirmation(self, mcp_server, mock_engine):
        """Test that intrusive tools work with confirmation."""
        mock_engine.recommend_active_countermeasures.return_value = {"recommended": True}
        
        result = mcp_server.execute_tool("recommend_active_countermeasures", {
            "session_id": 1
        }, confirmed=True)
        
        assert result.success is True

    def test_get_context_for_query(self, mcp_server, mock_engine):
        """Test getting RAG context for a query."""
        context = mcp_server.get_context_for_query("ssh brute force attack")
        
        assert "query" in context
        assert "similar_sessions" in context
        assert "similar_threats" in context
        assert "similar_nodes" in context
        assert context["query"] == "ssh brute force attack"

    def test_bind_engine(self):
        """Test binding engine to MCP server."""
        from src.mcp_server import MCPServer
        
        server = MCPServer()
        assert server.engine is None
        
        mock_engine = MagicMock()
        server.bind_engine(mock_engine)
        
        assert server.engine is mock_engine


class TestMCPToolResult:
    """Tests for ToolResult dataclass."""

    def test_tool_result_success(self):
        """Test successful ToolResult."""
        from src.mcp_server import ToolResult
        
        result = ToolResult(
            success=True,
            data={"key": "value"},
            metadata={"tool": "test"}
        )
        
        assert result.success is True
        assert result.data == {"key": "value"}
        assert result.error is None
        assert result.metadata == {"tool": "test"}

    def test_tool_result_failure(self):
        """Test failed ToolResult."""
        from src.mcp_server import ToolResult
        
        result = ToolResult(
            success=False,
            data=None,
            error="Something went wrong"
        )
        
        assert result.success is False
        assert result.data is None
        assert result.error == "Something went wrong"


class TestMCPToolCategory:
    """Tests for ToolCategory enum."""

    def test_tool_categories(self):
        """Test ToolCategory enum values."""
        from src.mcp_server import ToolCategory
        
        assert ToolCategory.INVESTIGATION.value == "investigation"
        assert ToolCategory.ANALYSIS.value == "analysis"
        assert ToolCategory.SEARCH.value == "search"
        assert ToolCategory.COUNTERMEASURE.value == "countermeasure"
        assert ToolCategory.MONITORING.value == "monitoring"
