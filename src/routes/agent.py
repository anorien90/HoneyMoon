"""
Agent system routes blueprint for HoneyMoon.
Handles agent tasks, templates, messages, and chat interface.
"""
import json
from datetime import datetime
from flask import Blueprint, request, jsonify

agent_bp = Blueprint('agent', __name__)

# Dependencies - will be set during registration
_agent_system = None
_mcp_server = None
_engine = None
_TaskType = None
_TaskStatus = None
_TaskPriority = None


def init_agent_routes(engine, agent_system=None, mcp_server=None, 
                      task_type=None, task_status=None, task_priority=None):
    """Initialize agent routes with dependencies."""
    global _agent_system, _mcp_server, _engine, _TaskType, _TaskStatus, _TaskPriority
    _engine = engine
    _agent_system = agent_system
    _mcp_server = mcp_server
    _TaskType = task_type
    _TaskStatus = task_status
    _TaskPriority = task_priority


@agent_bp.route('/api/v1/agent/status')
def agent_status():
    """Get agent system status."""
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    return jsonify(_agent_system.get_status()), 200


@agent_bp.route('/api/v1/agent/tasks')
def agent_list_tasks():
    """
    List agent tasks.
    Query params:
      - status: Filter by status (pending, running, completed, failed, cancelled, paused)
      - type: Filter by task type (investigation, monitoring, analysis, countermeasure, scheduled)
      - limit: Maximum results (default: 50)
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    status_str = request.args.get('status')
    type_str = request.args.get('type')
    
    try:
        limit = int(request.args.get('limit', 50))
    except ValueError:
        limit = 50
    
    status = None
    if status_str and _TaskStatus:
        try:
            status = _TaskStatus(status_str)
        except ValueError:
            return jsonify({"error": f"Invalid status: {status_str}"}), 400
    
    task_type = None
    if type_str and _TaskType:
        try:
            task_type = _TaskType(type_str)
        except ValueError:
            return jsonify({"error": f"Invalid task type: {type_str}"}), 400
    
    tasks = _agent_system.list_tasks(status=status, task_type=task_type, limit=limit)
    return jsonify({"tasks": tasks, "count": len(tasks)}), 200


@agent_bp.route('/api/v1/agent/task')
def agent_get_task():
    """
    Get details of a specific task.
    Query params:
      - id: Task ID (required)
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    task_id = request.args.get('id')
    if not task_id:
        return jsonify({"error": "Provide task id"}), 400
    
    task = _agent_system.get_task(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    
    return jsonify({"task": task}), 200


@agent_bp.route('/api/v1/agent/task/create', methods=['POST'])
def agent_create_task():
    """
    Create a new agent task.
    JSON body: {
        "type": "<task_type>",
        "name": "<task_name>",
        "description": "<description>",
        "parameters": {...},
        "priority": "<priority>",
        "requires_confirmation": <bool>,
        "schedule_interval": <int>
    }
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    data = request.get_json(silent=True) or {}
    
    type_str = data.get('type', 'investigation')
    if _TaskType:
        try:
            task_type = _TaskType(type_str)
        except ValueError:
            return jsonify({"error": f"Invalid task type: {type_str}"}), 400
    else:
        return jsonify({"error": "Task types not available"}), 500
    
    name = data.get('name')
    if not name:
        return jsonify({"error": "Provide task name"}), 400
    
    description = data.get('description', '')
    parameters = data.get('parameters', {})
    
    priority_str = data.get('priority', 'normal')
    priority_map = {'low': _TaskPriority.LOW, 'normal': _TaskPriority.NORMAL, 
                    'high': _TaskPriority.HIGH, 'critical': _TaskPriority.CRITICAL}
    priority = priority_map.get(priority_str.lower(), _TaskPriority.NORMAL)
    
    requires_confirmation = data.get('requires_confirmation', False)
    schedule_interval = data.get('schedule_interval')
    
    try:
        task = _agent_system.create_task(
            task_type=task_type,
            name=name,
            description=description,
            parameters=parameters,
            priority=priority,
            requires_confirmation=requires_confirmation,
            schedule_interval=schedule_interval
        )
        return jsonify({"task": task.dict()}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to create task: {e}"}), 500


@agent_bp.route('/api/v1/agent/task/template', methods=['POST'])
def agent_create_task_from_template():
    """
    Create a task from a template.
    JSON body: {
        "template": "<template_name>",
        "parameters": {...},
        "priority": "<priority>"
    }
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    data = request.get_json(silent=True) or {}
    
    template_name = data.get('template')
    if not template_name:
        return jsonify({"error": "Provide template name"}), 400
    
    parameters = data.get('parameters', {})
    
    priority_str = data.get('priority')
    priority = None
    if priority_str and _TaskPriority:
        priority_map = {'low': _TaskPriority.LOW, 'normal': _TaskPriority.NORMAL, 
                        'high': _TaskPriority.HIGH, 'critical': _TaskPriority.CRITICAL}
        priority = priority_map.get(priority_str.lower())
    
    task = _agent_system.create_task_from_template(template_name, parameters, priority)
    
    if not task:
        return jsonify({"error": f"Template not found: {template_name}"}), 404
    
    return jsonify({"task": task.dict()}), 201


@agent_bp.route('/api/v1/agent/task/confirm', methods=['POST'])
def agent_confirm_task():
    """
    Confirm a task that requires confirmation.
    JSON body: {"task_id": "<id>"}
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    data = request.get_json(silent=True) or {}
    task_id = data.get('task_id')
    
    if not task_id:
        return jsonify({"error": "Provide task_id"}), 400
    
    if _agent_system.confirm_task(task_id):
        return jsonify({"confirmed": True, "task_id": task_id}), 200
    
    return jsonify({"error": "Task not found or already confirmed"}), 400


@agent_bp.route('/api/v1/agent/task/cancel', methods=['POST'])
def agent_cancel_task():
    """
    Cancel a pending task.
    JSON body: {"task_id": "<id>"}
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    data = request.get_json(silent=True) or {}
    task_id = data.get('task_id')
    
    if not task_id:
        return jsonify({"error": "Provide task_id"}), 400
    
    if _agent_system.cancel_task(task_id):
        return jsonify({"cancelled": True, "task_id": task_id}), 200
    
    return jsonify({"error": "Task not found or cannot be cancelled"}), 400


@agent_bp.route('/api/v1/agent/templates')
def agent_list_templates():
    """List available task templates."""
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    templates = _agent_system.get_task_templates()
    return jsonify({"templates": templates}), 200


@agent_bp.route('/api/v1/agent/messages')
def agent_get_messages():
    """
    Get agent messages.
    Query params:
      - since: ISO timestamp to filter messages (optional)
      - limit: Maximum messages (default: 100)
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    since_str = request.args.get('since')
    since = None
    if since_str:
        try:
            since = datetime.fromisoformat(since_str.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({"error": "Invalid since timestamp"}), 400
    
    try:
        limit = int(request.args.get('limit', 100))
    except ValueError:
        limit = 100
    
    messages = _agent_system.get_messages(since=since, limit=limit)
    return jsonify({"messages": messages, "count": len(messages)}), 200


@agent_bp.route('/api/v1/agent/chat', methods=['POST'])
def agent_chat():
    """
    Chat with the agent system - provides access to all agent tools.
    JSON body: {
        "message": "<user message>",
        "conversation_id": <int optional>,
        "context_type": "<context type optional>",
        "context_id": "<context id optional>"
    }
    
    The agent will interpret the message and execute appropriate tools.
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    if not _mcp_server:
        return jsonify({"error": "MCP server not available"}), 503
    
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()
    conversation_id = data.get('conversation_id')
    context_type = data.get('context_type')
    context_id = data.get('context_id')
    
    if not message:
        return jsonify({"error": "Provide a message"}), 400
    
    try:
        # Get or create conversation
        if conversation_id:
            conv_data = _engine.get_conversation(conversation_id)
            if not conv_data:
                return jsonify({"error": "Conversation not found"}), 404
        else:
            conv_data = _engine.create_conversation(
                title=f"Chat: {message[:50]}...",
                context_type=context_type,
                context_id=context_id,
                initial_message=message
            )
            conversation_id = conv_data.get('id')
        
        # Get RAG context based on the message
        rag_context = _mcp_server.get_context_for_query(message, limit=3)
        
        # Determine which tools might be relevant based on the message
        suggested_tools = []
        message_lower = message.lower()
        
        if any(kw in message_lower for kw in ['ip', 'address', 'locate', 'where']):
            suggested_tools.append('get_ip_intel')
        if any(kw in message_lower for kw in ['session', 'honeypot', 'attack']):
            suggested_tools.append('list_honeypot_sessions')
            suggested_tools.append('get_honeypot_session')
        if any(kw in message_lower for kw in ['similar', 'find', 'search']):
            suggested_tools.append('search_similar_sessions')
            suggested_tools.append('search_similar_attackers')
        if any(kw in message_lower for kw in ['analyze', 'threat', 'analysis']):
            suggested_tools.append('analyze_session')
        if any(kw in message_lower for kw in ['countermeasure', 'defense', 'protect']):
            suggested_tools.append('recommend_active_countermeasures')
        if any(kw in message_lower for kw in ['rule', 'detect']):
            suggested_tools.append('generate_detection_rules')
        if any(kw in message_lower for kw in ['report', 'formal']):
            suggested_tools.append('generate_threat_report')
        
        # Continue conversation with LLM
        response_data = _engine.continue_conversation(conversation_id, message)
        
        return jsonify({
            "conversation_id": conversation_id,
            "response": response_data.get('response', ''),
            "rag_context": {
                "similar_sessions_count": len(rag_context.get('similar_sessions', [])),
                "similar_threats_count": len(rag_context.get('similar_threats', [])),
                "similar_nodes_count": len(rag_context.get('similar_nodes', []))
            },
            "suggested_tools": suggested_tools,
            "available_tools": [t['name'] for t in _mcp_server.get_tools()[:10]]
        }), 200
        
    except Exception as e:
        return jsonify({"error": f"Chat failed: {e}"}), 500


@agent_bp.route('/api/v1/agent/execute_tool', methods=['POST'])
def agent_execute_tool_via_chat():
    """
    Execute a specific MCP tool via the chat interface.
    JSON body: {
        "tool": "<tool name>",
        "params": {...},
        "conversation_id": <int optional>
    }
    """
    if not _mcp_server:
        return jsonify({"error": "MCP server not available"}), 503
    
    data = request.get_json(silent=True) or {}
    tool_name = data.get('tool')
    params = data.get('params', {})
    conversation_id = data.get('conversation_id')
    confirmed = data.get('confirmed', False)
    
    if not tool_name:
        return jsonify({"error": "Provide tool name"}), 400
    
    try:
        # Execute the tool
        result = _mcp_server.execute_tool(tool_name, params, confirmed=confirmed)
        
        response = {
            "tool": tool_name,
            "success": result.success,
            "data": result.data,
            "error": result.error
        }
        
        # If we have a conversation, add the tool execution to it
        if conversation_id and result.success:
            try:
                _engine.add_message_to_conversation(
                    conversation_id,
                    "assistant",
                    f"Executed tool '{tool_name}': {json.dumps(result.data)[:500]}..."
                )
            except Exception:
                pass  # Don't fail if conversation logging fails
        
        return jsonify(response), 200 if result.success else 400
        
    except Exception as e:
        return jsonify({"error": f"Tool execution failed: {e}"}), 500
