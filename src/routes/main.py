"""
Main routes blueprint for HoneyMoon.
Handles core routes: index, health, status.
"""
from flask import Blueprint, render_template, jsonify
from sqlalchemy import text

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Serve the main application page."""
    return render_template('index.html')


@main_bp.route('/api/v1/health')
def health():
    """Simple health check endpoint."""
    return jsonify({"status": "ok"}), 200


def register_status_route(bp, engine, agent_system, mcp_server, has_agent, has_mcp):
    """
    Register the status route with dependencies.
    Called during blueprint registration to inject dependencies.
    """
    @bp.route('/api/v1/status')
    def system_status():
        """
        Get comprehensive system status including Docker service connections.
        Returns information about:
        - LLM (Ollama) connection status
        - Vector store (Qdrant) connection status
        - Agent system status
        - Database connectivity
        """
        status = {
            "status": "ok",
            "services": {},
            "hints": []
        }
        
        # LLM/Ollama status
        try:
            llm_status = engine.get_llm_status()
            status["services"]["llm"] = {
                "available": llm_status.get("available", False),
                "model": llm_status.get("model"),
                "host": llm_status.get("ollama_host"),
                "supported_models": llm_status.get("supported_models", [])
            }
            if not llm_status.get("available"):
                status["hints"].append("LLM not available. Start Ollama Docker: docker run -d -p 11434:11434 --name ollama ollama/ollama")
        except Exception as e:
            status["services"]["llm"] = {"available": False, "error": str(e)}
            status["hints"].append("LLM service error. Check Ollama Docker container.")
        
        # Vector store/Qdrant status
        try:
            vector_status = engine.get_vector_store_status()
            status["services"]["vector_store"] = {
                "available": vector_status.get("available", False),
                "collections": vector_status.get("collections", {}) if vector_status.get("available") else None
            }
            if not vector_status.get("available"):
                status["hints"].append("Vector store not available. Start Qdrant Docker: docker run -d -p 6333:6333 --name qdrant qdrant/qdrant")
        except Exception as e:
            status["services"]["vector_store"] = {"available": False, "error": str(e)}
            status["hints"].append("Vector store error. Check Qdrant Docker container.")
        
        # Agent system status
        if has_agent and agent_system:
            try:
                agent_status = agent_system.get_status()
                status["services"]["agent_system"] = {
                    "available": True,
                    "running": agent_status.get("running", False),
                    "workers": agent_status.get("workers", 0),
                    "total_tasks": agent_status.get("total_tasks", 0),
                    "tasks_by_status": agent_status.get("tasks_by_status", {}),
                    "mcp_server_bound": agent_status.get("mcp_server_bound", False),
                    "engine_bound": agent_status.get("engine_bound", False)
                }
            except Exception as e:
                status["services"]["agent_system"] = {"available": False, "error": str(e)}
        else:
            status["services"]["agent_system"] = {"available": False, "reason": "Agent system not initialized"}
        
        # MCP Server status
        if has_mcp and mcp_server:
            try:
                tools = mcp_server.get_tools()
                status["services"]["mcp_server"] = {
                    "available": True,
                    "tools_count": len(tools)
                }
            except Exception as e:
                status["services"]["mcp_server"] = {"available": False, "error": str(e)}
        else:
            status["services"]["mcp_server"] = {"available": False, "reason": "MCP server not initialized"}
        
        # Database status
        try:
            engine.db.execute(text("SELECT 1"))
            status["services"]["database"] = {"available": True}
        except Exception as e:
            status["services"]["database"] = {"available": False, "error": str(e)}
        
        # Overall status
        all_services_available = all(
            svc.get("available", False) for svc in status["services"].values()
        )
        status["status"] = "healthy" if all_services_available else "degraded"
        
        return jsonify(status), 200
