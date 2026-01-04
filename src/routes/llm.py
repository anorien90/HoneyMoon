"""
LLM analysis routes blueprint for HoneyMoon.
Handles all LLM-powered analysis endpoints.
"""
from flask import Blueprint, request, jsonify

llm_bp = Blueprint('llm', __name__)

# Engine reference - will be set during registration
_engine = None


def init_llm_routes(engine):
    """Initialize LLM routes with the forensic engine."""
    global _engine
    _engine = engine


@llm_bp.route('/api/v1/llm/status')
def llm_status():
    """Get LLM analyzer status."""
    try:
        status = _engine.get_llm_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"error": f"Failed to get LLM status: {e}"}), 500


@llm_bp.route('/api/v1/llm/analyze/session', methods=['POST'])
def llm_analyze_session():
    """
    Analyze a honeypot session using LLM.
    JSON body: {"session_id": <int>, "save": <bool>}
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id') or request.args.get('session_id')
    
    if not session_id:
        return jsonify({"error": "Provide session_id"}), 400
    
    try:
        session_id = int(session_id)
    except Exception:
        return jsonify({"error": "Invalid session_id"}), 400
    
    save = data.get('save', True)
    
    try:
        result = _engine.analyze_session_with_llm(session_id, save_result=save)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/analyze/accesses', methods=['POST'])
def llm_analyze_accesses():
    """
    Analyze web access logs using LLM.
    JSON body: {"ip": <str optional>, "limit": <int>, "save": <bool>}
    """
    data = request.get_json(silent=True) or {}
    ip = data.get('ip') or request.args.get('ip')
    
    try:
        limit = int(data.get('limit', 100))
    except Exception:
        limit = 100
    
    save = data.get('save', True)
    
    try:
        result = _engine.analyze_accesses_with_llm(ip=ip, limit=limit, save_result=save)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/analyze/connections', methods=['POST'])
def llm_analyze_connections():
    """
    Analyze network connections using LLM.
    JSON body: {"direction": <str optional>, "limit": <int>, "save": <bool>}
    """
    data = request.get_json(silent=True) or {}
    direction = data.get('direction') or request.args.get('direction')
    
    try:
        limit = int(data.get('limit', 100))
    except Exception:
        limit = 100
    
    save = data.get('save', True)
    
    try:
        result = _engine.analyze_connections_with_llm(direction=direction, limit=limit, save_result=save)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/countermeasure', methods=['POST'])
def llm_countermeasure():
    """
    Generate countermeasure plan for a threat analysis.
    JSON body: {"threat_analysis_id": <int>, "context": <dict optional>}
    """
    data = request.get_json(silent=True) or {}
    threat_id = data.get('threat_analysis_id') or request.args.get('threat_analysis_id')
    
    if not threat_id:
        return jsonify({"error": "Provide threat_analysis_id"}), 400
    
    try:
        threat_id = int(threat_id)
    except Exception:
        return jsonify({"error": "Invalid threat_analysis_id"}), 400
    
    context = data.get('context', {})
    
    try:
        result = _engine.plan_countermeasure(threat_id, context=context)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Countermeasure planning failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/examine/artifact', methods=['POST'])
def llm_examine_artifact():
    """
    Examine a captured artifact using LLM.
    JSON body: {"artifact_name": <str>}
    """
    data = request.get_json(silent=True) or {}
    artifact_name = data.get('artifact_name') or request.args.get('artifact_name')
    
    if not artifact_name:
        return jsonify({"error": "Provide artifact_name"}), 400
    
    try:
        result = _engine.examine_artifact_with_llm(artifact_name)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Examination failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/unify', methods=['POST'])
def llm_unify_threats():
    """
    Create unified threat profile from multiple sessions.
    JSON body: {"session_ids": [<int>, ...]}
    """
    data = request.get_json(silent=True) or {}
    session_ids = data.get('session_ids', [])
    
    if not session_ids:
        return jsonify({"error": "Provide session_ids array"}), 400
    
    try:
        session_ids = [int(sid) for sid in session_ids]
    except Exception:
        return jsonify({"error": "Invalid session_ids"}), 400
    
    try:
        result = _engine.unify_threats(session_ids)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Unification failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/formal_report', methods=['POST'])
def llm_formal_report():
    """
    Generate a formal forensic analysis report for a honeypot session.
    JSON body: {"session_id": <int>}
    
    Returns a detailed, formal-format report suitable for:
    - Incident documentation
    - Legal proceedings
    - Compliance reporting
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id') or request.args.get('session_id')
    
    if not session_id:
        return jsonify({"error": "Provide session_id"}), 400
    
    try:
        session_id = int(session_id)
    except Exception:
        return jsonify({"error": "Invalid session_id"}), 400
    
    try:
        result = _engine.generate_formal_report(session_id)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Formal report generation failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/countermeasures', methods=['POST'])
def llm_active_countermeasures():
    """
    Get active countermeasure recommendations for a honeypot session.
    JSON body: {"session_id": <int>, "capabilities": [<str>, ...]}
    
    Returns recommendations for Cowrie-based active countermeasures:
    - JSON tail monitoring
    - Manhole interaction
    - Output plugin configuration
    - Proxy mode setup
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id') or request.args.get('session_id')
    capabilities = data.get('capabilities')
    
    if not session_id:
        return jsonify({"error": "Provide session_id"}), 400
    
    try:
        session_id = int(session_id)
    except Exception:
        return jsonify({"error": "Invalid session_id"}), 400
    
    try:
        result = _engine.recommend_active_countermeasures(session_id, capabilities)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Countermeasure recommendation failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/output_plugin', methods=['POST'])
def llm_output_plugin():
    """
    Generate Cowrie output plugin code for automated responses.
    JSON body: {
        "trigger_events": [<str>, ...],
        "response_actions": [<str>, ...],
        "conditions": {<filters>}
    }
    """
    data = request.get_json(silent=True) or {}
    trigger_events = data.get('trigger_events', [])
    response_actions = data.get('response_actions', [])
    conditions = data.get('conditions')
    
    if not trigger_events:
        return jsonify({"error": "Provide trigger_events"}), 400
    
    if not response_actions:
        return jsonify({"error": "Provide response_actions"}), 400
    
    try:
        result = _engine.generate_output_plugin_code(trigger_events, response_actions, conditions)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Plugin generation failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/realtime_analysis', methods=['POST'])
def llm_realtime_analysis():
    """
    Perform real-time threat analysis on a stream of commands.
    JSON body: {"commands": [<str>, ...], "context": {<optional context>}}
    """
    data = request.get_json(silent=True) or {}
    commands = data.get('commands', [])
    context = data.get('context')
    
    if not commands:
        return jsonify({"error": "Provide commands list"}), 400
    
    try:
        result = _engine.analyze_real_time_commands(commands, context)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Real-time analysis failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/detection_rules', methods=['POST'])
def llm_detection_rules():
    """
    Generate detection rules based on attack patterns from a session.
    JSON body: {
        "session_id": <int>,
        "rule_formats": [<str>, ...] (optional, e.g., ['sigma', 'firewall'])
    }
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id') or request.args.get('session_id')
    rule_formats = data.get('rule_formats')
    
    if not session_id:
        return jsonify({"error": "Provide session_id"}), 400
    
    try:
        session_id = int(session_id)
    except Exception:
        return jsonify({"error": "Invalid session_id"}), 400
    
    try:
        result = _engine.generate_detection_rules(session_id, rule_formats)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Detection rule generation failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/node_report', methods=['POST'])
def llm_node_report():
    """
    Generate a formal intelligence report for a network node.
    JSON body: {"ip": <str>}
    """
    data = request.get_json(silent=True) or {}
    ip = data.get('ip') or request.args.get('ip')
    
    if not ip:
        return jsonify({"error": "Provide ip"}), 400
    
    try:
        result = _engine.generate_node_report(ip)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Node report generation failed: {e}"}), 500


@llm_bp.route('/api/v1/llm/http_report', methods=['POST'])
def llm_http_report():
    """
    Generate a report analyzing HTTP activity.
    JSON body: {"ip": <str optional>, "limit": <int>}
    """
    data = request.get_json(silent=True) or {}
    ip = data.get('ip') or request.args.get('ip')
    
    try:
        limit = int(data.get('limit', 100))
    except Exception:
        limit = 100
    
    try:
        result = _engine.generate_http_activity_report(ip=ip, limit=limit)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"HTTP report generation failed: {e}"}), 500
