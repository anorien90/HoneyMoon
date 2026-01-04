"""
HoneyMoon API Routes.

This package contains all Flask blueprints for the HoneyMoon API.
Routes are organized by concern into separate modules for better maintainability.

Usage:
    from src.routes import register_all_blueprints
    register_all_blueprints(app, engine, agent_system, mcp_server)
"""

from .main import main_bp, register_status_route
from .locate import locate_bp, init_locate_routes
from .honeypot import honeypot_bp, init_honeypot_routes
from .database import database_bp, init_database_routes
from .llm import llm_bp, init_llm_routes
from .vector import vector_bp, init_vector_routes
from .threats import threats_bp, init_threats_routes
from .agent import agent_bp, init_agent_routes
from .mcp import mcp_bp, init_mcp_routes


def register_all_blueprints(app, engine, agent_system=None, mcp_server=None,
                             honeypot_session_model=None, honeypot_flow_model=None,
                             network_node_model=None, web_access_model=None,
                             analysis_session_model=None, isp_model=None,
                             outgoing_connection_model=None, threat_analysis_model=None,
                             attacker_cluster_model=None, task_type=None,
                             task_status=None, task_priority=None, tool_category=None):
    """
    Register all blueprints with the Flask app.
    
    Args:
        app: Flask application instance
        engine: ForensicEngine instance
        agent_system: Optional AgentSystem instance
        mcp_server: Optional MCPServer instance
        honeypot_session_model: HoneypotSession model class
        honeypot_flow_model: HoneypotNetworkFlow model class
        network_node_model: NetworkNode model class
        web_access_model: WebAccess model class
        analysis_session_model: AnalysisSession model class
        isp_model: ISP model class
        outgoing_connection_model: OutgoingConnection model class
        threat_analysis_model: ThreatAnalysis model class
        attacker_cluster_model: AttackerCluster model class
        task_type: TaskType enum
        task_status: TaskStatus enum
        task_priority: TaskPriority enum
        tool_category: ToolCategory enum
    """
    # Initialize route modules with dependencies
    init_locate_routes(engine)
    init_honeypot_routes(engine, honeypot_session_model, honeypot_flow_model)
    init_database_routes(
        engine, network_node_model, web_access_model, analysis_session_model,
        isp_model, outgoing_connection_model, honeypot_session_model, honeypot_flow_model
    )
    init_llm_routes(engine)
    init_vector_routes(engine)
    init_threats_routes(engine, threat_analysis_model, attacker_cluster_model)
    init_agent_routes(engine, agent_system, mcp_server, task_type, task_status, task_priority)
    init_mcp_routes(mcp_server, tool_category)
    
    # Register the status route with dependencies
    has_agent = agent_system is not None
    has_mcp = mcp_server is not None
    register_status_route(main_bp, engine, agent_system, mcp_server, has_agent, has_mcp)
    
    # Register blueprints with the app
    app.register_blueprint(main_bp)
    app.register_blueprint(locate_bp)
    app.register_blueprint(honeypot_bp)
    app.register_blueprint(database_bp)
    app.register_blueprint(llm_bp)
    app.register_blueprint(vector_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(agent_bp)
    app.register_blueprint(mcp_bp)


__all__ = [
    'register_all_blueprints',
    'main_bp',
    'locate_bp',
    'honeypot_bp',
    'database_bp',
    'llm_bp',
    'vector_bp',
    'threats_bp',
    'agent_bp',
    'mcp_bp',
]
