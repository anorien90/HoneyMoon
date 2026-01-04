"""
Vector search routes blueprint for HoneyMoon.
Handles vector store indexing and similarity search.
"""
from flask import Blueprint, request, jsonify

vector_bp = Blueprint('vector', __name__)

# Engine reference - will be set during registration
_engine = None


def init_vector_routes(engine):
    """Initialize vector routes with the forensic engine."""
    global _engine
    _engine = engine


@vector_bp.route('/api/v1/vector/status')
def vector_status():
    """Get vector store status."""
    try:
        status = _engine.get_vector_store_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"error": f"Failed to get vector status: {e}"}), 500


@vector_bp.route('/api/v1/vector/index/session', methods=['POST'])
def vector_index_session():
    """
    Index a honeypot session for similarity search.
    JSON body: {"session_id": <int>}
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
        success = _engine.index_session_vector(session_id)
        return jsonify({"indexed": success, "session_id": session_id}), 200
    except Exception as e:
        return jsonify({"error": f"Indexing failed: {e}"}), 500


@vector_bp.route('/api/v1/vector/index/node', methods=['POST'])
def vector_index_node():
    """
    Index a network node for similarity search.
    JSON body: {"ip": <str>}
    """
    data = request.get_json(silent=True) or {}
    ip = data.get('ip') or request.args.get('ip')
    
    if not ip:
        return jsonify({"error": "Provide ip"}), 400
    
    try:
        success = _engine.index_node_vector(ip)
        return jsonify({"indexed": success, "ip": ip}), 200
    except Exception as e:
        return jsonify({"error": f"Indexing failed: {e}"}), 500


@vector_bp.route('/api/v1/vector/search/sessions')
def vector_search_sessions():
    """
    Search for similar honeypot sessions.
    Query params: q=<query>, session_id=<int>, limit=<int>
    """
    query = request.args.get('q')
    session_id = request.args.get('session_id')
    
    try:
        limit = int(request.args.get('limit', 10))
    except Exception:
        limit = 10
    
    if session_id:
        try:
            session_id = int(session_id)
        except Exception:
            return jsonify({"error": "Invalid session_id"}), 400
    
    try:
        results = _engine.search_similar_sessions(query=query, session_id=session_id, limit=limit)
        return jsonify({"results": results, "count": len(results)}), 200
    except Exception as e:
        return jsonify({"error": f"Search failed: {e}"}), 500


@vector_bp.route('/api/v1/vector/search/nodes')
def vector_search_nodes():
    """
    Search for similar network nodes.
    Query params: q=<query>, ip=<str>, limit=<int>
    """
    query = request.args.get('q')
    ip = request.args.get('ip')
    
    try:
        limit = int(request.args.get('limit', 10))
    except Exception:
        limit = 10
    
    try:
        results = _engine.search_similar_nodes(query=query, ip=ip, limit=limit)
        return jsonify({"results": results, "count": len(results)}), 200
    except Exception as e:
        return jsonify({"error": f"Search failed: {e}"}), 500


@vector_bp.route('/api/v1/vector/search/threats')
def vector_search_threats():
    """
    Search for similar threat analyses.
    Query params: q=<query>, limit=<int>
    """
    query = request.args.get('q')
    
    if not query:
        return jsonify({"error": "Provide q query parameter"}), 400
    
    try:
        limit = int(request.args.get('limit', 10))
    except Exception:
        limit = 10
    
    try:
        results = _engine.search_similar_threats(query=query, limit=limit)
        return jsonify({"results": results, "count": len(results)}), 200
    except Exception as e:
        return jsonify({"error": f"Search failed: {e}"}), 500
