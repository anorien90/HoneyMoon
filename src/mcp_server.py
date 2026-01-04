"""
Model Context Protocol (MCP) Server for HoneyMoon.

Provides a tool-based interface for LLM agents to interact with the forensic engine.
Tools are exposed for investigation, analysis, and countermeasure execution.

The MCP server enables:
- RAG (Retrieval Augmented Generation) via vector store searches
- Tool-based access to forensic capabilities
- Context-aware responses using honeypot data
"""
import os
import json
import logging
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Categories of MCP tools available to agents."""
    INVESTIGATION = "investigation"  # Read-only data gathering
    ANALYSIS = "analysis"  # LLM-based analysis
    SEARCH = "search"  # RAG/vector search
    COUNTERMEASURE = "countermeasure"  # Active defense tools
    MONITORING = "monitoring"  # Real-time monitoring


@dataclass
class MCPTool:
    """Definition of an MCP tool."""
    name: str
    description: str
    category: ToolCategory
    parameters: Dict[str, Any]  # JSON Schema for parameters
    requires_confirmation: bool = False  # If True, requires user confirmation
    is_intrusive: bool = False  # If True, may affect target systems
    handler: Optional[Callable] = None


@dataclass
class ToolResult:
    """Result from executing an MCP tool."""
    success: bool
    data: Any
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class MCPServer:
    """
    MCP Server providing tool-based access to HoneyMoon capabilities.
    
    This server exposes forensic engine functionality as discrete tools
    that can be called by LLM agents for investigation and response.
    """
    
    def __init__(self, forensic_engine=None):
        """
        Initialize the MCP server.
        
        Args:
            forensic_engine: Optional ForensicEngine instance. If not provided,
                           tools will need to be bound later.
        """
        self.engine = forensic_engine
        self._tools: Dict[str, MCPTool] = {}
        self._register_default_tools()
    
    def bind_engine(self, engine):
        """Bind a forensic engine to the MCP server."""
        self.engine = engine
    
    def _register_default_tools(self):
        """Register all default MCP tools."""
        # Investigation tools
        self._register_tool(MCPTool(
            name="get_ip_intel",
            description="Get comprehensive intelligence data for an IP address including geolocation, organization, ISP, ASN, and historical access data.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to investigate"}
                },
                "required": ["ip"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="get_honeypot_session",
            description="Get detailed information about a specific honeypot session including commands executed, files transferred, and timeline.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "session_id": {"type": "integer", "description": "Session ID to retrieve"}
                },
                "required": ["session_id"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="list_honeypot_sessions",
            description="List recent honeypot sessions with optional filtering by IP or time range.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 50, "description": "Maximum number of sessions"},
                    "ip_filter": {"type": "string", "description": "Filter by source IP (optional)"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="get_web_accesses",
            description="Get web access logs for a specific IP address.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to query"},
                    "limit": {"type": "integer", "default": 100, "description": "Maximum results"}
                },
                "required": ["ip"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="get_network_flows",
            description="Get network flow data from PCAP analysis.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 100, "description": "Maximum flows"},
                    "ip_filter": {"type": "string", "description": "Filter by IP (optional)"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="get_outgoing_connections",
            description="Get outgoing network connections from the monitored system.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "default": 100, "description": "Maximum results"},
                    "direction": {"type": "string", "enum": ["outgoing", "internal"], "description": "Filter by direction"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="get_threat_analysis",
            description="Get existing threat analysis for a session or IP.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "threat_id": {"type": "integer", "description": "Threat analysis ID"},
                    "session_id": {"type": "integer", "description": "Session ID to look up analysis for"}
                }
            }
        ))
        
        # RAG/Search tools
        self._register_tool(MCPTool(
            name="search_similar_sessions",
            description="Search for honeypot sessions similar to a query or existing session using vector similarity.",
            category=ToolCategory.SEARCH,
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Text query describing attack pattern"},
                    "session_id": {"type": "integer", "description": "Find sessions similar to this one"},
                    "limit": {"type": "integer", "default": 10, "description": "Maximum results"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="search_similar_threats",
            description="Search for similar threat analyses using semantic search.",
            category=ToolCategory.SEARCH,
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Threat description to search for"},
                    "limit": {"type": "integer", "default": 10, "description": "Maximum results"}
                },
                "required": ["query"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="search_similar_attackers",
            description="Find attackers with similar behavior patterns to a given IP.",
            category=ToolCategory.SEARCH,
            parameters={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to find similar attackers for"},
                    "threshold": {"type": "number", "default": 0.7, "description": "Similarity threshold (0-1)"},
                    "limit": {"type": "integer", "default": 10, "description": "Maximum results"}
                },
                "required": ["ip"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="search_nodes",
            description="Search network nodes by IP, hostname, organization, or location.",
            category=ToolCategory.SEARCH,
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "fuzzy": {"type": "boolean", "default": True, "description": "Enable fuzzy matching"},
                    "limit": {"type": "integer", "default": 50, "description": "Maximum results"}
                },
                "required": ["query"]
            }
        ))
        
        # Analysis tools
        self._register_tool(MCPTool(
            name="analyze_session",
            description="Perform LLM-based threat analysis on a honeypot session.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "session_id": {"type": "integer", "description": "Session ID to analyze"},
                    "save_result": {"type": "boolean", "default": True, "description": "Save analysis to database"}
                },
                "required": ["session_id"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="analyze_commands_realtime",
            description="Perform real-time threat analysis on a list of commands.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "commands": {"type": "array", "items": {"type": "string"}, "description": "Commands to analyze"},
                    "context": {"type": "object", "description": "Additional context"}
                },
                "required": ["commands"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="generate_threat_report",
            description="Generate a formal forensic report for a honeypot session.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "session_id": {"type": "integer", "description": "Session ID for report"}
                },
                "required": ["session_id"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="unify_threat_profile",
            description="Create a unified threat profile from multiple related sessions.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "session_ids": {"type": "array", "items": {"type": "integer"}, "description": "Session IDs to unify"}
                },
                "required": ["session_ids"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="examine_artifact",
            description="Analyze a captured artifact (file) from a honeypot session.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "artifact_name": {"type": "string", "description": "Name of the artifact file"}
                },
                "required": ["artifact_name"]
            }
        ))
        
        # Countermeasure tools (intrusive)
        self._register_tool(MCPTool(
            name="plan_countermeasures",
            description="Generate a countermeasure plan for an identified threat.",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "threat_analysis_id": {"type": "integer", "description": "Threat analysis ID"},
                    "context": {"type": "object", "description": "Additional context"}
                },
                "required": ["threat_analysis_id"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="recommend_active_countermeasures",
            description="Get active countermeasure recommendations for a session (Cowrie-based).",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "session_id": {"type": "integer", "description": "Session ID"},
                    "capabilities": {"type": "array", "items": {"type": "string"}, "description": "Available Cowrie capabilities"}
                },
                "required": ["session_id"]
            },
            requires_confirmation=True,
            is_intrusive=True
        ))
        
        self._register_tool(MCPTool(
            name="generate_detection_rules",
            description="Generate detection rules (Sigma, firewall, etc.) based on attack patterns.",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "session_id": {"type": "integer", "description": "Session ID to base rules on"},
                    "rule_formats": {"type": "array", "items": {"type": "string"}, "description": "Rule formats to generate"}
                },
                "required": ["session_id"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="generate_output_plugin",
            description="Generate Cowrie output plugin code for automated responses.",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "trigger_events": {"type": "array", "items": {"type": "string"}, "description": "Cowrie events to trigger on"},
                    "response_actions": {"type": "array", "items": {"type": "string"}, "description": "Actions to perform"},
                    "conditions": {"type": "object", "description": "Filtering conditions"}
                },
                "required": ["trigger_events", "response_actions"]
            },
            requires_confirmation=True,
            is_intrusive=True
        ))
        
        self._register_tool(MCPTool(
            name="create_attacker_cluster",
            description="Create a cluster of related attackers from session IDs.",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "session_ids": {"type": "array", "items": {"type": "integer"}, "description": "Session IDs to cluster"},
                    "name": {"type": "string", "description": "Cluster name"}
                },
                "required": ["session_ids"]
            }
        ))
        
        # Monitoring tools
        self._register_tool(MCPTool(
            name="get_live_connections",
            description="Get live honeypot connections from the last N minutes.",
            category=ToolCategory.MONITORING,
            parameters={
                "type": "object",
                "properties": {
                    "minutes": {"type": "integer", "default": 15, "description": "Time window in minutes"},
                    "limit": {"type": "integer", "default": 100, "description": "Maximum results"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="get_system_status",
            description="Get status of LLM analyzer, vector store, and other system components.",
            category=ToolCategory.MONITORING,
            parameters={
                "type": "object",
                "properties": {}
            }
        ))
        
        # Chat conversation tools
        self._register_tool(MCPTool(
            name="create_conversation",
            description="Create a new chat conversation for persistent analysis sessions.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Conversation title"},
                    "context_type": {"type": "string", "description": "Type of context (session, node, threat, cluster)"},
                    "context_id": {"type": "string", "description": "ID of the related entity"},
                    "initial_message": {"type": "string", "description": "Initial user message"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="continue_conversation",
            description="Continue a chat conversation with an LLM response.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "conversation_id": {"type": "integer", "description": "Conversation ID"},
                    "message": {"type": "string", "description": "User message"}
                },
                "required": ["conversation_id", "message"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="list_conversations",
            description="List chat conversations, optionally filtered by context type.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "context_type": {"type": "string", "description": "Filter by context type"},
                    "limit": {"type": "integer", "default": 50, "description": "Maximum results"}
                }
            }
        ))
        
        # Countermeasure record tools
        self._register_tool(MCPTool(
            name="create_countermeasure_record",
            description="Create a countermeasure record from a planned response.",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "threat_analysis_id": {"type": "integer", "description": "Associated threat analysis ID"},
                    "name": {"type": "string", "description": "Countermeasure name"}
                },
                "required": ["threat_analysis_id"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="approve_countermeasure",
            description="Approve a countermeasure for execution.",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "countermeasure_id": {"type": "integer", "description": "Countermeasure ID"},
                    "approved_by": {"type": "string", "description": "Approver identifier"}
                },
                "required": ["countermeasure_id"]
            },
            requires_confirmation=True
        ))
        
        self._register_tool(MCPTool(
            name="list_countermeasure_records",
            description="List countermeasure records, optionally filtered by status.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "status": {"type": "string", "description": "Filter by status (planned, approved, executing, completed, failed)"},
                    "limit": {"type": "integer", "default": 50, "description": "Maximum results"}
                }
            }
        ))
        
        # Reindexing tools
        self._register_tool(MCPTool(
            name="reindex_sessions",
            description="Reindex honeypot sessions to the vector store for improved RAG search.",
            category=ToolCategory.MONITORING,
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Maximum sessions to index"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="reindex_nodes",
            description="Reindex network nodes to the vector store for improved RAG search.",
            category=ToolCategory.MONITORING,
            parameters={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Maximum nodes to index"}
                }
            }
        ))
        
        # Node and HTTP report tools
        self._register_tool(MCPTool(
            name="generate_node_report",
            description="Generate a formal intelligence report for a network node including all activity.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address of the node"}
                },
                "required": ["ip"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="generate_http_report",
            description="Generate a report analyzing HTTP activity patterns.",
            category=ToolCategory.ANALYSIS,
            parameters={
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to filter by (optional)"},
                    "limit": {"type": "integer", "default": 100, "description": "Maximum accesses to include"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="get_detection_rules",
            description="Get stored detection rules from the database.",
            category=ToolCategory.INVESTIGATION,
            parameters={
                "type": "object",
                "properties": {
                    "source_type": {"type": "string", "description": "Filter by source type (session, node, access)"},
                    "rule_type": {"type": "string", "description": "Filter by rule type (sigma, firewall, yara, cowrie)"},
                    "limit": {"type": "integer", "default": 100, "description": "Maximum results"}
                }
            }
        ))
        
        self._register_tool(MCPTool(
            name="save_detection_rules",
            description="Save generated detection rules to the database for persistent learning.",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "session_id": {"type": "integer", "description": "Session ID the rules were generated from"},
                    "rules_data": {"type": "object", "description": "Detection rules data from LLM"}
                },
                "required": ["session_id", "rules_data"]
            }
        ))
        
        self._register_tool(MCPTool(
            name="save_countermeasures",
            description="Save countermeasure recommendations to the database for tracking.",
            category=ToolCategory.COUNTERMEASURE,
            parameters={
                "type": "object",
                "properties": {
                    "session_id": {"type": "integer", "description": "Session ID"},
                    "countermeasures_data": {"type": "object", "description": "Countermeasure data from LLM"}
                },
                "required": ["session_id", "countermeasures_data"]
            }
        ))
    
    def _register_tool(self, tool: MCPTool):
        """Register a tool with the MCP server."""
        self._tools[tool.name] = tool
    
    def get_tools(self, category: Optional[ToolCategory] = None, include_intrusive: bool = True) -> List[Dict[str, Any]]:
        """
        Get list of available tools.
        
        Args:
            category: Optional category filter
            include_intrusive: Whether to include intrusive tools
            
        Returns:
            List of tool definitions
        """
        tools = []
        for tool in self._tools.values():
            if category and tool.category != category:
                continue
            if not include_intrusive and tool.is_intrusive:
                continue
            tools.append({
                "name": tool.name,
                "description": tool.description,
                "category": tool.category.value,
                "parameters": tool.parameters,
                "requires_confirmation": tool.requires_confirmation,
                "is_intrusive": tool.is_intrusive
            })
        return tools
    
    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a specific tool definition."""
        tool = self._tools.get(name)
        if not tool:
            return None
        return {
            "name": tool.name,
            "description": tool.description,
            "category": tool.category.value,
            "parameters": tool.parameters,
            "requires_confirmation": tool.requires_confirmation,
            "is_intrusive": tool.is_intrusive
        }
    
    def execute_tool(self, name: str, params: Dict[str, Any], confirmed: bool = False) -> ToolResult:
        """
        Execute an MCP tool.
        
        Args:
            name: Tool name
            params: Tool parameters
            confirmed: Whether user has confirmed (for intrusive tools)
            
        Returns:
            ToolResult with execution results
        """
        tool = self._tools.get(name)
        if not tool:
            return ToolResult(success=False, data=None, error=f"Unknown tool: {name}")
        
        if tool.requires_confirmation and not confirmed:
            return ToolResult(
                success=False, 
                data=None, 
                error="This tool requires confirmation. Set confirmed=true to execute.",
                metadata={"requires_confirmation": True, "tool": name}
            )
        
        if not self.engine:
            return ToolResult(success=False, data=None, error="Forensic engine not bound to MCP server")
        
        try:
            result = self._execute_tool_impl(name, params)
            return ToolResult(
                success=True,
                data=result,
                metadata={"tool": name, "executed_at": datetime.now(timezone.utc).isoformat()}
            )
        except Exception as e:
            logger.error("Tool execution failed: %s - %s", name, e)
            return ToolResult(success=False, data=None, error=str(e), metadata={"tool": name})
    
    def _execute_tool_impl(self, name: str, params: Dict[str, Any]) -> Any:
        """Internal tool execution implementation."""
        # Investigation tools
        if name == "get_ip_intel":
            ip = params["ip"]
            node = self.engine.get_entry(ip)
            if not node:
                return {"error": "IP not found", "ip": ip}
            org = self.engine.get_organization_info(ip)
            accesses = self.engine.get_accesses_for_ip(ip, limit=10)
            return {"node": node, "organization": org, "recent_accesses": accesses}
        
        elif name == "get_honeypot_session":
            return self.engine.get_honeypot_session(params["session_id"])
        
        elif name == "list_honeypot_sessions":
            limit = params.get("limit", 50)
            sessions = self.engine.get_honeypot_sessions(limit=limit)
            ip_filter = params.get("ip_filter")
            if ip_filter:
                sessions = [s for s in sessions if s.get("src_ip") == ip_filter]
            return {"sessions": sessions, "count": len(sessions)}
        
        elif name == "get_web_accesses":
            return {
                "ip": params["ip"],
                "accesses": self.engine.get_accesses_for_ip(params["ip"], limit=params.get("limit", 100))
            }
        
        elif name == "get_network_flows":
            from src.honeypot_models import HoneypotNetworkFlow
            limit = params.get("limit", 100)
            query = self.engine.db.query(HoneypotNetworkFlow).order_by(HoneypotNetworkFlow.start_ts.desc())
            ip_filter = params.get("ip_filter")
            if ip_filter:
                query = query.filter(
                    (HoneypotNetworkFlow.src_ip == ip_filter) | (HoneypotNetworkFlow.dst_ip == ip_filter)
                )
            rows = query.limit(limit).all()
            return {"flows": [r.dict() for r in rows], "count": len(rows)}
        
        elif name == "get_outgoing_connections":
            return {
                "connections": self.engine.get_outgoing_connections(
                    limit=params.get("limit", 100),
                    direction=params.get("direction")
                )
            }
        
        elif name == "get_threat_analysis":
            from src.entry import ThreatAnalysis
            if params.get("threat_id"):
                threat = self.engine.db.query(ThreatAnalysis).filter_by(id=params["threat_id"]).first()
                return threat.dict() if threat else {"error": "Threat not found"}
            elif params.get("session_id"):
                threat = self.engine.db.query(ThreatAnalysis).filter_by(
                    source_type="session", source_id=params["session_id"]
                ).first()
                return threat.dict() if threat else {"error": "No analysis for session"}
            return {"error": "Provide threat_id or session_id"}
        
        # Search/RAG tools
        elif name == "search_similar_sessions":
            return {
                "results": self.engine.search_similar_sessions(
                    query=params.get("query"),
                    session_id=params.get("session_id"),
                    limit=params.get("limit", 10)
                )
            }
        
        elif name == "search_similar_threats":
            query = params.get("query")
            if not query:
                return {"error": "Query parameter is required", "results": []}
            return {
                "results": self.engine.search_similar_threats(
                    query=query,
                    limit=params.get("limit", 10)
                )
            }
        
        elif name == "search_similar_attackers":
            return {
                "ip": params["ip"],
                "similar_attackers": self.engine.find_similar_attackers(
                    params["ip"],
                    threshold=params.get("threshold", 0.7),
                    limit=params.get("limit", 10)
                )
            }
        
        elif name == "search_nodes":
            return {
                "results": self.engine.search_nodes(
                    query=params["query"],
                    fuzzy=params.get("fuzzy", True),
                    limit=params.get("limit", 50)
                )
            }
        
        # Analysis tools
        elif name == "analyze_session":
            return self.engine.analyze_session_with_llm(
                params["session_id"],
                save_result=params.get("save_result", True)
            )
        
        elif name == "analyze_commands_realtime":
            return self.engine.analyze_real_time_commands(
                params["commands"],
                context=params.get("context")
            )
        
        elif name == "generate_threat_report":
            return self.engine.generate_formal_report(params["session_id"])
        
        elif name == "unify_threat_profile":
            return self.engine.unify_threats(params["session_ids"])
        
        elif name == "examine_artifact":
            return self.engine.examine_artifact_with_llm(params["artifact_name"])
        
        # Countermeasure tools
        elif name == "plan_countermeasures":
            return self.engine.plan_countermeasure(
                params["threat_analysis_id"],
                context=params.get("context")
            )
        
        elif name == "recommend_active_countermeasures":
            return self.engine.recommend_active_countermeasures(
                params["session_id"],
                capabilities=params.get("capabilities")
            )
        
        elif name == "generate_detection_rules":
            return self.engine.generate_detection_rules(
                params["session_id"],
                rule_formats=params.get("rule_formats")
            )
        
        elif name == "generate_output_plugin":
            return self.engine.generate_output_plugin_code(
                params["trigger_events"],
                params["response_actions"],
                conditions=params.get("conditions")
            )
        
        elif name == "create_attacker_cluster":
            return self.engine.create_attacker_cluster(
                params["session_ids"],
                name=params.get("name")
            )
        
        # Monitoring tools
        elif name == "get_live_connections":
            from src.honeypot_models import HoneypotSession, HoneypotNetworkFlow
            from datetime import timedelta
            
            minutes = params.get("minutes", 15)
            limit = params.get("limit", 100)
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
            
            result = {"minutes": minutes, "cutoff": cutoff.isoformat(), "sessions": [], "flows": []}
            
            # Get recent sessions
            sessions = self.engine.db.query(HoneypotSession).filter(
                HoneypotSession.start_ts >= cutoff
            ).order_by(HoneypotSession.start_ts.desc()).limit(limit).all()
            result["sessions"] = [s.dict() for s in sessions]
            
            # Get recent flows
            flows = self.engine.db.query(HoneypotNetworkFlow).filter(
                HoneypotNetworkFlow.start_ts >= cutoff
            ).order_by(HoneypotNetworkFlow.start_ts.desc()).limit(limit).all()
            result["flows"] = [f.dict() for f in flows]
            
            return result
        
        elif name == "get_system_status":
            return {
                "llm": self.engine.get_llm_status(),
                "vector_store": self.engine.get_vector_store_status(),
                "mcp_tools_count": len(self._tools)
            }
        
        # Chat conversation tools
        elif name == "create_conversation":
            return self.engine.create_conversation(
                title=params.get("title"),
                context_type=params.get("context_type"),
                context_id=params.get("context_id"),
                initial_message=params.get("initial_message")
            )
        
        elif name == "continue_conversation":
            return self.engine.continue_conversation(
                params["conversation_id"],
                params["message"]
            )
        
        elif name == "list_conversations":
            return {
                "conversations": self.engine.list_conversations(
                    context_type=params.get("context_type"),
                    limit=params.get("limit", 50)
                )
            }
        
        # Countermeasure record tools
        elif name == "create_countermeasure_record":
            # First get the threat analysis plan
            plan = self.engine.plan_countermeasure(params["threat_analysis_id"])
            if plan.get("error"):
                return plan
            return self.engine.create_countermeasure_record(
                params["threat_analysis_id"],
                plan,
                name=params.get("name")
            )
        
        elif name == "approve_countermeasure":
            return self.engine.approve_countermeasure(
                params["countermeasure_id"],
                approved_by=params.get("approved_by")
            )
        
        elif name == "list_countermeasure_records":
            return {
                "countermeasures": self.engine.list_countermeasure_records(
                    status=params.get("status"),
                    limit=params.get("limit", 50)
                )
            }
        
        # Reindexing tools
        elif name == "reindex_sessions":
            return self.engine.reindex_all_sessions(limit=params.get("limit"))
        
        elif name == "reindex_nodes":
            return self.engine.reindex_all_nodes(limit=params.get("limit"))
        
        # Node and HTTP report tools
        elif name == "generate_node_report":
            return self.engine.generate_node_report(params["ip"])
        
        elif name == "generate_http_report":
            return self.engine.generate_http_activity_report(
                ip=params.get("ip"),
                limit=params.get("limit", 100)
            )
        
        # Detection rules and countermeasures persistence
        elif name == "get_detection_rules":
            return {
                "rules": self.engine.get_detection_rules(
                    source_type=params.get("source_type"),
                    rule_type=params.get("rule_type"),
                    limit=params.get("limit", 100)
                )
            }
        
        elif name == "save_detection_rules":
            return self.engine.save_detection_rules(
                params["session_id"],
                params["rules_data"]
            )
        
        elif name == "save_countermeasures":
            return self.engine.save_countermeasures(
                params["session_id"],
                params["countermeasures_data"]
            )
        
        return {"error": f"Tool implementation not found: {name}"}
    
    def get_context_for_query(self, query: str, limit: int = 5) -> Dict[str, Any]:
        """
        Get relevant context for a query using RAG.
        
        This performs semantic search across the vector store to find
        relevant sessions, threats, and nodes for the given query.
        
        Args:
            query: Natural language query
            limit: Maximum results per category
            
        Returns:
            Dictionary with relevant context
        """
        context = {
            "query": query,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "similar_sessions": [],
            "similar_threats": [],
            "similar_nodes": []
        }
        
        if not self.engine:
            context["error"] = "Engine not bound"
            return context
        
        # Search similar sessions
        try:
            context["similar_sessions"] = self.engine.search_similar_sessions(
                query=query, limit=limit
            )
        except Exception as e:
            context["sessions_error"] = str(e)
        
        # Search similar threats
        try:
            context["similar_threats"] = self.engine.search_similar_threats(
                query=query, limit=limit
            )
        except Exception as e:
            context["threats_error"] = str(e)
        
        # Search similar nodes
        try:
            context["similar_nodes"] = self.engine.search_similar_nodes(
                query=query, limit=limit
            )
        except Exception as e:
            context["nodes_error"] = str(e)
        
        return context
