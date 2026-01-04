"""
MCP server routes blueprint for HoneyMoon.
Handles Model Context Protocol tool listing and execution.
"""
from flask import Blueprint, request, jsonify

mcp_bp = Blueprint('mcp', __name__)

# Dependencies - will be set during registration
_mcp_server = None
_ToolCategory = None


def init_mcp_routes(mcp_server=None, tool_category=None):
    """Initialize MCP routes with dependencies."""
    global _mcp_server, _ToolCategory
    _mcp_server = mcp_server
    _ToolCategory = tool_category


@mcp_bp.route('/api/v1/mcp/tools')
def mcp_list_tools():
    """
    List available MCP tools.
    Query params:
      - category: Filter by tool category (investigation, analysis, search, countermeasure, monitoring)
      - include_intrusive: Include intrusive tools (default: true)
    """
    if not _mcp_server:
        return jsonify({"error": "MCP server not available"}), 503
    
    category_str = request.args.get('category')
    include_intrusive = request.args.get('include_intrusive', '1').lower() in ("1", "true", "yes", "on")
    
    category = None
    if category_str and _ToolCategory:
        try:
            category = _ToolCategory(category_str)
        except ValueError:
            return jsonify({"error": f"Invalid category: {category_str}"}), 400
    
    tools = _mcp_server.get_tools(category=category, include_intrusive=include_intrusive)
    return jsonify({"tools": tools, "count": len(tools)}), 200


@mcp_bp.route('/api/v1/mcp/tool')
def mcp_get_tool():
    """
    Get details of a specific MCP tool.
    Query params:
      - name: Tool name (required)
    """
    if not _mcp_server:
        return jsonify({"error": "MCP server not available"}), 503
    
    name = request.args.get('name')
    if not name:
        return jsonify({"error": "Provide tool name"}), 400
    
    tool = _mcp_server.get_tool(name)
    if not tool:
        return jsonify({"error": f"Tool not found: {name}"}), 404
    
    return jsonify({"tool": tool}), 200


@mcp_bp.route('/api/v1/mcp/execute', methods=['POST'])
def mcp_execute_tool():
    """
    Execute an MCP tool.
    JSON body: {"tool": "<tool_name>", "params": {...}, "confirmed": <bool>}
    """
    if not _mcp_server:
        return jsonify({"error": "MCP server not available"}), 503
    
    data = request.get_json(silent=True) or {}
    tool_name = data.get('tool')
    params = data.get('params', {})
    confirmed = data.get('confirmed', False)
    
    if not tool_name:
        return jsonify({"error": "Provide tool name"}), 400
    
    result = _mcp_server.execute_tool(tool_name, params, confirmed=confirmed)
    
    response = {
        "success": result.success,
        "data": result.data,
        "error": result.error,
        "metadata": result.metadata
    }
    
    status_code = 200 if result.success else 400
    return jsonify(response), status_code


@mcp_bp.route('/api/v1/mcp/context')
def mcp_get_context():
    """
    Get relevant context for a query using RAG.
    Query params:
      - q: Query string (required)
      - limit: Maximum results per category (default: 5)
    """
    if not _mcp_server:
        return jsonify({"error": "MCP server not available"}), 503
    
    query = request.args.get('q')
    if not query:
        return jsonify({"error": "Provide query parameter q"}), 400
    
    try:
        limit = int(request.args.get('limit', 5))
    except ValueError:
        limit = 5
    
    context = _mcp_server.get_context_for_query(query, limit=limit)
    return jsonify(context), 200
