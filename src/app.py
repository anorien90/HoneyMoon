"""
HoneyMoon Flask Application.

This is the main entry point for the HoneyMoon web application.
Routes are organized into blueprints in src/routes/ for better maintainability.
"""
import os
from flask import Flask, send_file
from src.forensic_engine import ForensicEngine

# Try to import honeypot models
try:
    from src.honeypot_models import HoneypotSession, HoneypotNetworkFlow
except Exception:
    HoneypotSession = None
    HoneypotNetworkFlow = None

# Try to import entry models
try:
    from src.entry import (
        NetworkNode, Organization, WebAccess, AnalysisSession,
        ISP, OutgoingConnection, ThreatAnalysis, AttackerCluster,
        CountermeasureRecord, DetectionRuleRecord
    )
except Exception:
    NetworkNode = None
    Organization = None
    WebAccess = None
    AnalysisSession = None
    ISP = None
    OutgoingConnection = None
    ThreatAnalysis = None
    AttackerCluster = None
    CountermeasureRecord = None
    DetectionRuleRecord = None

# Configure paths
TEMPLATE_DIR = os.environ.get("IPMAP_TEMPLATES", "/home/anorien/lib/HoneyMoon/templates")
STATIC_DIR = os.environ.get("IPMAP_STATIC", "/home/anorien/lib/HoneyMoon/static")

# Create Flask app
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

# Create forensic engine
engine = ForensicEngine()

# Try to import and initialize MCP server
try:
    from src.mcp_server import MCPServer, ToolCategory
    mcp_server = MCPServer(forensic_engine=engine)
    _HAS_MCP_SERVER = True
except Exception as e:
    mcp_server = None
    ToolCategory = None
    _HAS_MCP_SERVER = False
    import logging
    logging.getLogger(__name__).warning("MCP server not available: %s", e)

# Try to import and initialize Agent system
try:
    from src.agent_system import AgentSystem, TaskType, TaskStatus, TaskPriority
    agent_system = AgentSystem(mcp_server=mcp_server, forensic_engine=engine)
    agent_enabled = os.environ.get("AGENT_ENABLED", "true").lower() in ("1", "true", "yes", "on")
    if agent_enabled:
        agent_system.start()
    _HAS_AGENT_SYSTEM = True
except Exception as e:
    agent_system = None
    TaskType = None
    TaskStatus = None
    TaskPriority = None
    _HAS_AGENT_SYSTEM = False
    import logging
    logging.getLogger(__name__).warning("Agent system not available: %s", e)

# Register all blueprints
from src.routes import register_all_blueprints
register_all_blueprints(
    app=app,
    engine=engine,
    agent_system=agent_system if _HAS_AGENT_SYSTEM else None,
    mcp_server=mcp_server if _HAS_MCP_SERVER else None,
    honeypot_session_model=HoneypotSession,
    honeypot_flow_model=HoneypotNetworkFlow,
    network_node_model=NetworkNode,
    web_access_model=WebAccess,
    analysis_session_model=AnalysisSession,
    isp_model=ISP,
    outgoing_connection_model=OutgoingConnection,
    threat_analysis_model=ThreatAnalysis,
    attacker_cluster_model=AttackerCluster,
    countermeasure_model=CountermeasureRecord,
    detection_rule_model=DetectionRuleRecord,
    task_type=TaskType if _HAS_AGENT_SYSTEM else None,
    task_status=TaskStatus if _HAS_AGENT_SYSTEM else None,
    task_priority=TaskPriority if _HAS_AGENT_SYSTEM else None,
    tool_category=ToolCategory if _HAS_MCP_SERVER else None,
)

# Static file routes
@app.route('/favicon.ico')
def favicon():
    return send_file(os.path.join(STATIC_DIR, 'favicon.ico'))


if __name__ == '__main__':
    debug = os.environ.get("IPMAP_DEBUG", "1") in ("1", "true", "yes")
    app.run(host='0.0.0.0', port=int(os.environ.get("IPMAP_PORT", "5000")), debug=debug)
