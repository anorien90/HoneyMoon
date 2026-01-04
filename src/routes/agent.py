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
    
    This endpoint supports natural language interaction with the honeypot analysis system.
    It interprets user messages, retrieves relevant context via RAG, suggests tools,
    and can optionally execute actions automatically.
    
    JSON body: {
        "message": "<user message>",
        "conversation_id": <int optional>,
        "context_type": "<context type optional: session, node, threat, cluster>",
        "context_id": "<context id optional>",
        "auto_execute": <bool optional - if true, auto-execute suggested actions>,
        "include_context_data": <bool optional - if true, include full RAG context>
    }
    
    Returns natural language response with suggested actions and context.
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
    auto_execute = data.get('auto_execute', False)
    include_context_data = data.get('include_context_data', False)
    
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
        rag_context = _mcp_server.get_context_for_query(message, limit=5)
        
        # Determine which tools might be relevant based on the message
        suggested_tools = _determine_suggested_tools(message)
        
        # Determine quick actions based on context and message
        quick_actions = _determine_quick_actions(message, context_type, context_id, rag_context)
        
        # Continue conversation with LLM
        response_data = _engine.continue_conversation(conversation_id, message)
        llm_response = response_data.get('response', '')
        
        # If auto_execute is enabled, try to execute the most relevant tool
        auto_execute_result = None
        if auto_execute and suggested_tools:
            auto_execute_result = _try_auto_execute(suggested_tools[0], message, context_type, context_id)
        
        # Build response
        response = {
            "conversation_id": conversation_id,
            "response": llm_response,
            "rag_context": {
                "similar_sessions_count": len(rag_context.get('similar_sessions', [])),
                "similar_threats_count": len(rag_context.get('similar_threats', [])),
                "similar_nodes_count": len(rag_context.get('similar_nodes', []))
            },
            "suggested_tools": suggested_tools[:10],
            "quick_actions": quick_actions[:5],
            "available_tools": [t['name'] for t in _mcp_server.get_tools()[:15]]
        }
        
        # Include full context data if requested
        if include_context_data and rag_context:
            response["context_data"] = {
                "similar_sessions": rag_context.get('similar_sessions', [])[:3],
                "similar_threats": rag_context.get('similar_threats', [])[:3],
                "similar_nodes": rag_context.get('similar_nodes', [])[:3]
            }
        
        # Include auto-execute result if available
        if auto_execute_result:
            response["auto_execute_result"] = auto_execute_result
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({"error": f"Chat failed: {e}"}), 500


def _determine_suggested_tools(message: str) -> list:
    """Determine suggested tools based on message content."""
    suggested_tools = []
    message_lower = message.lower()
    
    # IP-related keywords
    if any(kw in message_lower for kw in ['ip', 'address', 'locate', 'where', 'geo']):
        suggested_tools.extend(['get_ip_intel', 'generate_node_report', 'search_similar_attackers'])
    
    # Session-related keywords
    if any(kw in message_lower for kw in ['session', 'honeypot', 'attack', 'cowrie']):
        suggested_tools.extend(['list_honeypot_sessions', 'get_honeypot_session', 'analyze_session'])
    
    # Search-related keywords
    if any(kw in message_lower for kw in ['similar', 'find', 'search', 'like']):
        suggested_tools.extend(['search_similar_sessions', 'search_similar_attackers', 'search_similar_threats', 'search_nodes'])
    
    # Analysis keywords
    if any(kw in message_lower for kw in ['analyze', 'threat', 'analysis', 'assess']):
        suggested_tools.extend(['analyze_session', 'analyze_commands_realtime'])
    
    # Countermeasure keywords
    if any(kw in message_lower for kw in ['countermeasure', 'defense', 'protect', 'block', 'mitigate']):
        suggested_tools.extend(['recommend_active_countermeasures', 'plan_countermeasures'])
    
    # Detection rules keywords
    if any(kw in message_lower for kw in ['rule', 'detect', 'sigma', 'yara', 'firewall']):
        suggested_tools.extend(['generate_detection_rules', 'get_detection_rules'])
    
    # Report keywords
    if any(kw in message_lower for kw in ['report', 'formal', 'document', 'summary']):
        suggested_tools.extend(['generate_threat_report', 'generate_node_report', 'generate_http_report'])
    
    # Monitoring keywords
    if any(kw in message_lower for kw in ['monitor', 'live', 'watch', 'real-time', 'realtime']):
        suggested_tools.extend(['get_live_connections', 'analyze_commands_realtime'])
    
    # Status keywords
    if any(kw in message_lower for kw in ['status', 'health', 'system']):
        suggested_tools.extend(['get_system_status'])
    
    # Remove duplicates while preserving order
    seen = set()
    result = []
    for tool in suggested_tools:
        if tool not in seen:
            seen.add(tool)
            result.append(tool)
    
    return result


def _determine_quick_actions(message: str, context_type: str, context_id: str, rag_context: dict) -> list:
    """Determine quick actions based on context."""
    actions = []
    message_lower = message.lower()
    
    # IP address pattern
    import re
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
    if ip_match:
        ip = ip_match.group(0)
        actions.append({
            "type": "investigate_ip",
            "label": f"🔍 Investigate {ip}",
            "tool": "get_ip_intel",
            "params": {"ip": ip}
        })
        actions.append({
            "type": "similar_attackers",
            "label": f"🔗 Find similar to {ip}",
            "tool": "search_similar_attackers",
            "params": {"ip": ip}
        })
    
    # Session ID pattern
    session_match = re.search(r'session\s*(?:#|id:?)?\s*(\d+)', message_lower)
    if session_match:
        session_id = int(session_match.group(1))
        actions.append({
            "type": "analyze_session",
            "label": f"🔍 Analyze Session #{session_id}",
            "tool": "analyze_session",
            "params": {"session_id": session_id}
        })
        actions.append({
            "type": "report",
            "label": f"📋 Report for Session #{session_id}",
            "tool": "generate_threat_report",
            "params": {"session_id": session_id}
        })
    
    # Context-based actions
    if context_type == 'session' and context_id:
        try:
            sid = int(context_id)
            actions.append({
                "type": "analyze",
                "label": "🔍 Analyze this session",
                "tool": "analyze_session",
                "params": {"session_id": sid}
            })
        except ValueError:
            pass
    
    elif context_type == 'node' and context_id:
        actions.append({
            "type": "intel",
            "label": "🔍 Get Intel",
            "tool": "get_ip_intel",
            "params": {"ip": context_id}
        })
    
    # RAG context-based actions
    if rag_context:
        similar_sessions = rag_context.get('similar_sessions', [])
        if similar_sessions:
            actions.append({
                "type": "explore_similar",
                "label": f"📊 Explore {len(similar_sessions)} similar sessions",
                "tool": "list_honeypot_sessions",
                "params": {}
            })
    
    return actions


def _try_auto_execute(tool_name: str, message: str, context_type: str, context_id: str) -> dict:
    """Try to auto-execute a tool based on message context."""
    import re
    
    params = {}
    
    # Extract IP if present
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
    if ip_match and tool_name in ['get_ip_intel', 'search_similar_attackers', 'generate_node_report']:
        params['ip'] = ip_match.group(0)
    
    # Extract session ID if present
    session_match = re.search(r'session\s*(?:#|id:?)?\s*(\d+)', message.lower())
    if session_match and tool_name in ['analyze_session', 'get_honeypot_session', 'generate_threat_report']:
        params['session_id'] = int(session_match.group(1))
    
    # Use context if no params extracted
    if not params:
        if context_type == 'session' and context_id:
            try:
                params['session_id'] = int(context_id)
            except ValueError:
                pass
        elif context_type == 'node' and context_id:
            params['ip'] = context_id
    
    # Execute if we have params
    if params and _mcp_server:
        try:
            result = _mcp_server.execute_tool(tool_name, params)
            return {
                "tool": tool_name,
                "params": params,
                "success": result.success,
                "data": result.data if result.success else None,
                "error": result.error
            }
        except Exception as e:
            return {
                "tool": tool_name,
                "params": params,
                "success": False,
                "error": str(e)
            }
    
    return None


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


@agent_bp.route('/api/v1/agent/task/natural', methods=['POST'])
def agent_create_natural_task():
    """
    Create a task from a natural language request.
    
    This endpoint interprets natural language and creates an appropriate task.
    
    JSON body: {
        "request": "<natural language request>",
        "context_type": "<optional context type: session, node, threat, cluster>",
        "context_id": "<optional context id>",
        "priority": "<optional priority override: low, normal, high, critical>"
    }
    
    Returns task with natural language response expectations.
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    data = request.get_json(silent=True) or {}
    request_text = data.get('request', '').strip()
    context_type = data.get('context_type')
    context_id = data.get('context_id')
    priority_override = data.get('priority')
    
    if not request_text:
        return jsonify({"error": "Provide a request"}), 400
    
    try:
        # Create task from natural language
        task = _agent_system.create_task_from_natural_language(
            request_text=request_text,
            context_type=context_type,
            context_id=context_id
        )
        
        if not task:
            return jsonify({
                "error": "Could not interpret request",
                "suggestion": "Try being more specific, e.g., 'investigate IP 8.8.8.8' or 'analyze session #123'"
            }), 400
        
        # Apply priority override if provided
        if priority_override and _TaskPriority is not None:
            priority_map = {
                'low': _TaskPriority.LOW,
                'normal': _TaskPriority.NORMAL,
                'high': _TaskPriority.HIGH,
                'critical': _TaskPriority.CRITICAL
            }
            if priority_override.lower() in priority_map:
                task.priority = priority_map[priority_override.lower()]
        
        # Get RAG context for the request
        rag_context = None
        if _mcp_server:
            try:
                rag_context = _mcp_server.get_context_for_query(request_text, limit=3)
            except Exception:
                pass
        
        return jsonify({
            "task": task.dict(),
            "interpretation": {
                "task_type": task.task_type.value,
                "name": task.name,
                "description": task.description,
                "parameters": task.parameters
            },
            "rag_context": {
                "similar_sessions_count": len(rag_context.get('similar_sessions', [])) if rag_context else 0,
                "similar_threats_count": len(rag_context.get('similar_threats', [])) if rag_context else 0,
                "similar_nodes_count": len(rag_context.get('similar_nodes', [])) if rag_context else 0
            } if rag_context else None,
            "message": f"Task '{task.name}' created and queued for execution."
        }), 201
        
    except Exception as e:
        return jsonify({"error": f"Failed to create task: {e}"}), 500


@agent_bp.route('/api/v1/agent/task/result', methods=['GET'])
def agent_get_task_result():
    """
    Get task result with natural language response.
    
    Query params:
      - id: Task ID (required)
      - format: Response format ('full', 'natural', 'raw') - default 'full'
    
    Returns task details including natural language summary if available.
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    task_id = request.args.get('id')
    response_format = request.args.get('format', 'full')
    
    if not task_id:
        return jsonify({"error": "Provide task id"}), 400
    
    task = _agent_system.get_task(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    
    if response_format == 'natural':
        return jsonify({
            "task_id": task_id,
            "status": task.get("status"),
            "response_text": task.get("response_text"),
            "suggested_actions": task.get("suggested_actions", [])
        }), 200
    
    elif response_format == 'raw':
        return jsonify({
            "task_id": task_id,
            "status": task.get("status"),
            "result": task.get("result"),
            "error": task.get("error")
        }), 200
    
    # Full format (default)
    return jsonify({
        "task": task,
        "natural_response": task.get("response_text"),
        "suggested_actions": task.get("suggested_actions", []),
        "has_result": task.get("result") is not None
    }), 200


@agent_bp.route('/api/v1/agent/suggestions', methods=['GET'])
def agent_get_suggestions():
    """
    Get intelligent suggestions based on current context.
    
    Query params:
      - context_type: Optional context type (session, node, threat)
      - context_id: Optional context ID
      - query: Optional query text for RAG-based suggestions
    
    Returns suggested actions and tools.
    """
    if not _agent_system:
        return jsonify({"error": "Agent system not available"}), 503
    
    context_type = request.args.get('context_type')
    context_id = request.args.get('context_id')
    query = request.args.get('query', '')
    
    suggestions = {
        "quick_actions": [],
        "suggested_tools": [],
        "templates": [],
        "rag_context": None
    }
    
    # Get RAG context if query provided
    if _mcp_server and query:
        try:
            rag_context = _mcp_server.get_context_for_query(query, limit=3)
            suggestions["rag_context"] = {
                "similar_sessions_count": len(rag_context.get('similar_sessions', [])),
                "similar_threats_count": len(rag_context.get('similar_threats', [])),
                "similar_nodes_count": len(rag_context.get('similar_nodes', []))
            }
        except Exception:
            pass
    
    # Context-specific suggestions
    if context_type == 'session':
        suggestions["quick_actions"] = [
            {"action": "analyze", "label": "🔍 Analyze Session", "params": {"session_id": context_id}},
            {"action": "report", "label": "📋 Generate Report", "params": {"session_id": context_id}},
            {"action": "countermeasures", "label": "🛡️ Plan Countermeasures", "params": {"session_id": context_id}},
            {"action": "similar", "label": "🔗 Find Similar", "params": {"session_id": context_id}},
            {"action": "rules", "label": "📜 Generate Detection Rules", "params": {"session_id": context_id}}
        ]
        suggestions["suggested_tools"] = [
            "analyze_session", "generate_threat_report", "search_similar_sessions",
            "recommend_active_countermeasures", "generate_detection_rules"
        ]
    
    elif context_type == 'node':
        suggestions["quick_actions"] = [
            {"action": "intel", "label": "🔍 Get IP Intel", "params": {"ip": context_id}},
            {"action": "report", "label": "📋 Node Report", "params": {"ip": context_id}},
            {"action": "similar", "label": "🔗 Similar Attackers", "params": {"ip": context_id}},
            {"action": "accesses", "label": "📊 View Accesses", "params": {"ip": context_id}}
        ]
        suggestions["suggested_tools"] = [
            "get_ip_intel", "generate_node_report", "search_similar_attackers",
            "get_web_accesses", "list_honeypot_sessions"
        ]
    
    elif context_type == 'threat':
        suggestions["quick_actions"] = [
            {"action": "countermeasures", "label": "🛡️ Plan Response", "params": {"threat_id": context_id}},
            {"action": "similar", "label": "🔗 Similar Threats", "params": {"threat_id": context_id}},
            {"action": "rules", "label": "📜 Detection Rules", "params": {"threat_id": context_id}}
        ]
        suggestions["suggested_tools"] = [
            "plan_countermeasures", "search_similar_threats", "generate_detection_rules"
        ]
    
    else:
        # General suggestions
        suggestions["quick_actions"] = [
            {"action": "sessions", "label": "📋 List Sessions", "params": {}},
            {"action": "threats", "label": "⚠️ Recent Threats", "params": {}},
            {"action": "monitor", "label": "📡 Live Monitor", "params": {}},
            {"action": "status", "label": "📊 System Status", "params": {}}
        ]
        suggestions["suggested_tools"] = [
            "list_honeypot_sessions", "get_live_connections", "get_system_status",
            "search_similar_sessions"
        ]
    
    # Add relevant templates
    templates = _agent_system.get_task_templates()
    if context_type == 'session':
        suggestions["templates"] = [t for t in templates if 'session' in t.get('name', '').lower() or 'investigation' in t.get('description', '').lower()]
    elif context_type == 'node':
        suggestions["templates"] = [t for t in templates if 'ip' in t.get('name', '').lower()]
    else:
        suggestions["templates"] = templates[:5]
    
    return jsonify(suggestions), 200
