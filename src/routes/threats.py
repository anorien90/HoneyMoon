"""
Threats routes blueprint for HoneyMoon.
Handles threat analysis, clusters, and detection rules.
"""
from flask import Blueprint, request, jsonify

threats_bp = Blueprint('threats', __name__)

# Dependencies - will be set during registration
_engine = None
_ThreatAnalysis = None
_AttackerCluster = None


def init_threats_routes(engine, threat_analysis=None, attacker_cluster=None):
    """Initialize threats routes with dependencies."""
    global _engine, _ThreatAnalysis, _AttackerCluster
    _engine = engine
    _ThreatAnalysis = threat_analysis
    _AttackerCluster = attacker_cluster


@threats_bp.route('/api/v1/threats')
def list_threats():
    """
    List threat analyses.
    Query params: type=<session|access|connection>, limit=<int>
    """
    source_type = request.args.get('type')
    
    try:
        limit = int(request.args.get('limit', 100))
    except Exception:
        limit = 100
    
    try:
        threats = _engine.get_threat_analyses(source_type=source_type, limit=limit)
        return jsonify({"threats": threats, "count": len(threats)}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list threats: {e}"}), 500


@threats_bp.route('/api/v1/threat')
def get_threat():
    """
    Get a specific threat analysis.
    Query params: id=<int>
    """
    threat_id = request.args.get('id')
    
    if not threat_id:
        return jsonify({"error": "Provide id parameter"}), 400
    
    try:
        threat_id = int(threat_id)
    except Exception:
        return jsonify({"error": "Invalid id"}), 400
    
    try:
        if _ThreatAnalysis is None:
            return jsonify({"error": "ThreatAnalysis model not available"}), 500
        threat = _engine.db.query(_ThreatAnalysis).filter_by(id=threat_id).first()
        if not threat:
            return jsonify({"error": "Threat not found"}), 404
        return jsonify({"threat": threat.dict()}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to get threat: {e}"}), 500


@threats_bp.route('/api/v1/clusters')
def list_clusters():
    """
    List attacker clusters.
    Query params: limit=<int>
    """
    try:
        limit = int(request.args.get('limit', 100))
    except Exception:
        limit = 100
    
    try:
        clusters = _engine.get_attacker_clusters(limit=limit)
        return jsonify({"clusters": clusters, "count": len(clusters)}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list clusters: {e}"}), 500


@threats_bp.route('/api/v1/cluster', methods=['GET', 'POST'])
def cluster():
    """
    GET: Get a specific cluster by id.
    POST: Create a new cluster from session IDs.
    """
    if request.method == 'GET':
        cluster_id = request.args.get('id')
        
        if not cluster_id:
            return jsonify({"error": "Provide id parameter"}), 400
        
        try:
            cluster_id = int(cluster_id)
        except Exception:
            return jsonify({"error": "Invalid id"}), 400
        
        try:
            if _AttackerCluster is None:
                return jsonify({"error": "AttackerCluster model not available"}), 500
            cluster = _engine.db.query(_AttackerCluster).filter_by(id=cluster_id).first()
            if not cluster:
                return jsonify({"error": "Cluster not found"}), 404
            return jsonify({"cluster": cluster.dict()}), 200
        except Exception as e:
            return jsonify({"error": f"Failed to get cluster: {e}"}), 500
    
    # POST: Create cluster
    data = request.get_json(silent=True) or {}
    session_ids = data.get('session_ids', [])
    name = data.get('name')
    
    if not session_ids:
        return jsonify({"error": "Provide session_ids array"}), 400
    
    try:
        session_ids = [int(sid) for sid in session_ids]
    except Exception:
        return jsonify({"error": "Invalid session_ids"}), 400
    
    try:
        result = _engine.create_attacker_cluster(session_ids, name=name)
        if result.get("error"):
            return jsonify(result), 400
        return jsonify({"cluster": result}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to create cluster: {e}"}), 500


@threats_bp.route('/api/v1/similar/attackers')
def similar_attackers():
    """
    Find attackers similar to a given IP.
    Query params: ip=<str>, threshold=<float>, limit=<int>
    """
    ip = request.args.get('ip')
    
    if not ip:
        return jsonify({"error": "Provide ip parameter"}), 400
    
    try:
        threshold = float(request.args.get('threshold', 0.7))
    except Exception:
        threshold = 0.7
    
    try:
        limit = int(request.args.get('limit', 10))
    except Exception:
        limit = 10
    
    try:
        results = _engine.find_similar_attackers(ip, threshold=threshold, limit=limit)
        return jsonify({"ip": ip, "similar_attackers": results, "count": len(results)}), 200
    except Exception as e:
        return jsonify({"error": f"Search failed: {e}"}), 500


@threats_bp.route('/api/v1/detection_rules')
def list_detection_rules():
    """
    List stored detection rules.
    Query params: source_type, rule_type, limit
    """
    source_type = request.args.get('source_type')
    rule_type = request.args.get('rule_type')
    
    try:
        limit = int(request.args.get('limit', 100))
    except Exception:
        limit = 100
    
    try:
        rules = _engine.get_detection_rules(source_type=source_type, rule_type=rule_type, limit=limit)
        return jsonify({"rules": rules, "count": len(rules)}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list detection rules: {e}"}), 500


@threats_bp.route('/api/v1/detection_rules/save', methods=['POST'])
def save_detection_rules():
    """
    Save generated detection rules to the database.
    JSON body: {"session_id": <int>, "rules_data": <dict>}
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id')
    rules_data = data.get('rules_data')
    
    if not session_id:
        return jsonify({"error": "Provide session_id"}), 400
    
    if not rules_data:
        return jsonify({"error": "Provide rules_data"}), 400
    
    try:
        session_id = int(session_id)
    except Exception:
        return jsonify({"error": "Invalid session_id"}), 400
    
    try:
        result = _engine.save_detection_rules(session_id, rules_data)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Failed to save detection rules: {e}"}), 500


@threats_bp.route('/api/v1/countermeasures/save', methods=['POST'])
def save_countermeasures():
    """
    Save countermeasure recommendations to the database.
    JSON body: {"session_id": <int>, "countermeasures_data": <dict>}
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get('session_id')
    countermeasures_data = data.get('countermeasures_data')
    
    if not session_id:
        return jsonify({"error": "Provide session_id"}), 400
    
    if not countermeasures_data:
        return jsonify({"error": "Provide countermeasures_data"}), 400
    
    try:
        session_id = int(session_id)
    except Exception:
        return jsonify({"error": "Invalid session_id"}), 400
    
    try:
        result = _engine.save_countermeasures(session_id, countermeasures_data)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Failed to save countermeasures: {e}"}), 500
