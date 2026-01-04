"""
Honeypot routes blueprint for HoneyMoon.
Handles honeypot sessions, flows, ingestion, and live connections.
"""
import os
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, send_file

honeypot_bp = Blueprint('honeypot', __name__)

# Dependencies - will be set during registration
_engine = None
_HoneypotSession = None
_HoneypotNetworkFlow = None


def init_honeypot_routes(engine, honeypot_session_model=None, honeypot_flow_model=None):
    """Initialize honeypot routes with dependencies."""
    global _engine, _HoneypotSession, _HoneypotNetworkFlow
    _engine = engine
    _HoneypotSession = honeypot_session_model
    _HoneypotNetworkFlow = honeypot_flow_model


@honeypot_bp.route('/api/v1/honeypot/sessions')
def honeypot_sessions():
    """List honeypot sessions."""
    try:
        limit = int(request.args.get('limit', 200))
    except Exception:
        limit = 200
    try:
        sessions = _engine.get_honeypot_sessions(limit=limit)
        return jsonify({"sessions": sessions}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list sessions: {e}"}), 500


@honeypot_bp.route('/api/v1/honeypot/session')
def honeypot_session():
    """Get a single honeypot session by ID or cowrie session."""
    sid = request.args.get('id')
    cowrie_sess = request.args.get('cowrie_session')
    try:
        if sid:
            s = _engine.get_honeypot_session(int(sid))
            if not s:
                return jsonify({"error": "Session not found"}), 404
            return jsonify({"session": s}), 200

        if cowrie_sess:
            if _HoneypotSession is None:
                return jsonify({"error": "Honeypot models not available"}), 500
            row = _engine.db.query(_HoneypotSession).filter_by(cowrie_session=cowrie_sess).first()
            if not row:
                return jsonify({"error": "Session not found"}), 404
            s = _engine.get_honeypot_session(row.id)
            return jsonify({"session": s}), 200

        return jsonify({"error": "Provide id or cowrie_session parameter"}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to fetch session: {e}"}), 500


@honeypot_bp.route('/api/v1/honeypot/ingest', methods=['POST'])
def honeypot_ingest():
    """
    Trigger ingestion of a Cowrie JSON log file.
    JSON body: {"path": "/data/cowrie/cowrie.json"}
    """
    data = request.get_json(silent=True) or {}
    path = data.get('path') or request.form.get('path') or request.args.get('path')
    if not path:
        return jsonify({"error": "Provide path to cowrie json file"}), 400

    safe_base = os.path.abspath(_engine.honeypot_data_dir)
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(safe_base):
        return jsonify({"error": "Ingest path must be inside honeypot data directory"}), 400

    try:
        res = _engine.ingest_cowrie_file(abs_path, enrich=True)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": f"Ingest failed: {e}"}), 500


@honeypot_bp.route('/api/v1/honeypot/ingest_pcap', methods=['POST'])
def honeypot_ingest_pcap():
    """
    Trigger PCAP ingest.
    JSON body: {"path": "/data/honeypot/pkt.pcap", "filter_host": "1.2.3.4"}
    """
    data = request.get_json(silent=True) or {}
    path = data.get('path') or request.form.get('path') or request.args.get('path')
    filter_host = data.get('filter_host') or request.args.get('filter_host')
    if not path:
        return jsonify({"error": "Provide path to pcap file"}), 400

    safe_base = os.path.abspath(_engine.honeypot_data_dir)
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(safe_base):
        return jsonify({"error": "PCAP path must be inside honeypot data directory"}), 400

    try:
        res = _engine.ingest_pcap(abs_path, filter_host=filter_host)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": f"PCAP ingest failed: {e}"}), 500


@honeypot_bp.route('/api/v1/honeypot/artifact')
def honeypot_artifact():
    """
    Download a captured artifact by filename.
    Query: ?name=<filename>
    Only serves files from the artifacts directory to avoid path traversal.
    """
    name = request.args.get('name')
    if not name:
        return jsonify({"error": "Provide artifact name"}), 400

    artifacts_dir = os.path.join(_engine.honeypot_data_dir, "artifacts")
    safe_path = os.path.abspath(os.path.join(artifacts_dir, name))
    if not safe_path.startswith(os.path.abspath(artifacts_dir)) or not os.path.isfile(safe_path):
        return jsonify({"error": "Artifact not found"}), 404

    return send_file(safe_path, as_attachment=True)


@honeypot_bp.route('/api/v1/honeypot/flows')
def honeypot_flows():
    """List network flows captured by the honeypot."""
    try:
        limit = int(request.args.get('limit', 200))
    except Exception:
        limit = 200
    if _HoneypotNetworkFlow is None:
        return jsonify({"error": "Honeypot models not available"}), 500
    try:
        rows = _engine.db.query(_HoneypotNetworkFlow).order_by(_HoneypotNetworkFlow.start_ts.desc()).limit(limit).all()
        return jsonify({"flows": [r.dict() for r in rows]}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list flows: {e}"}), 500


@honeypot_bp.route('/api/v1/live/connections')
def live_connections():
    """
    Get recent connections (honeypot sessions and network flows) from the last X minutes.
    Query params:
      - minutes: time window in minutes (default: 15, max: 1440)
      - limit: max results per category (default: 100)
    Returns:
      - sessions: recent honeypot sessions with geolocation data
      - flows: recent network flows with geolocation data
      - honeypot_location: the honeypot's location (if known)
    """
    try:
        minutes = int(request.args.get('minutes', 15))
        minutes = max(1, min(1440, minutes))
    except Exception:
        minutes = 15

    try:
        limit = int(request.args.get('limit', 100))
        limit = max(1, min(500, limit))
    except Exception:
        limit = 100

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    result = {
        "minutes": minutes,
        "cutoff": cutoff.isoformat(),
        "sessions": [],
        "flows": [],
        "honeypot_location": None
    }

    # Try to determine the honeypot's location from config or first local IP
    honeypot_ip = os.environ.get("HONEYPOT_IP")
    if honeypot_ip:
        hp_node = _engine.get_entry(honeypot_ip)
        if hp_node and hp_node.get("latitude") and hp_node.get("longitude"):
            result["honeypot_location"] = {
                "ip": honeypot_ip,
                "latitude": hp_node.get("latitude"),
                "longitude": hp_node.get("longitude"),
                "city": hp_node.get("city"),
                "country": hp_node.get("country")
            }

    # Get recent honeypot sessions
    if _HoneypotSession is not None:
        try:
            rows = _engine.db.query(_HoneypotSession).filter(
                _HoneypotSession.start_ts >= cutoff
            ).order_by(_HoneypotSession.start_ts.desc()).limit(limit).all()

            for session in rows:
                session_dict = session.dict()
                src_ip = session.src_ip
                if src_ip:
                    node = _engine.get_entry(src_ip)
                    if node:
                        session_dict["node"] = {
                            "ip": node.get("ip"),
                            "latitude": node.get("latitude"),
                            "longitude": node.get("longitude"),
                            "city": node.get("city"),
                            "country": node.get("country"),
                            "organization": node.get("organization")
                        }
                result["sessions"].append(session_dict)
        except Exception as e:
            result["sessions_error"] = str(e)

    # Get recent network flows
    if _HoneypotNetworkFlow is not None:
        try:
            rows = _engine.db.query(_HoneypotNetworkFlow).filter(
                _HoneypotNetworkFlow.start_ts >= cutoff
            ).order_by(_HoneypotNetworkFlow.start_ts.desc()).limit(limit).all()

            for flow in rows:
                flow_dict = flow.dict()
                if flow.src_ip:
                    src_node = _engine.get_entry(flow.src_ip)
                    if src_node:
                        flow_dict["src_node"] = {
                            "ip": src_node.get("ip"),
                            "latitude": src_node.get("latitude"),
                            "longitude": src_node.get("longitude"),
                            "city": src_node.get("city"),
                            "country": src_node.get("country"),
                            "organization": src_node.get("organization")
                        }
                if flow.dst_ip:
                    dst_node = _engine.get_entry(flow.dst_ip)
                    if dst_node:
                        flow_dict["dst_node"] = {
                            "ip": dst_node.get("ip"),
                            "latitude": dst_node.get("latitude"),
                            "longitude": dst_node.get("longitude"),
                            "city": dst_node.get("city"),
                            "country": dst_node.get("country"),
                            "organization": dst_node.get("organization")
                        }
                result["flows"].append(flow_dict)
        except Exception as e:
            result["flows_error"] = str(e)

    return jsonify(result), 200
