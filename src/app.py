import os
import logging
from typing import Optional
from flask import Flask, request, jsonify, render_template, send_file
from src.forensic_engine import ForensicEngine

try:
    from src.honeypot_models import HoneypotSession, HoneypotNetworkFlow
except Exception:
    HoneypotSession = None
    HoneypotNetworkFlow = None

try:
    from src.entry import NetworkNode, Organization, WebAccess, AnalysisSession
except Exception:
    NetworkNode = None
    Organization = None
    WebAccess = None
    AnalysisSession = None

logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
DEFAULT_STATIC_DIR = os.path.join(BASE_DIR, "static")

def _resolve_path(env_value: Optional[str], fallback: str, *, label: str) -> str:
    if env_value is not None:
        candidate = os.path.abspath(env_value)
        try:
            rel_candidate = os.path.relpath(candidate, BASE_DIR)
            if rel_candidate.startswith(os.pardir):
                logger.warning("%s path is outside the application directory; falling back to defaults", label)
                return fallback
        except ValueError:
            logger.warning("%s path is not comparable to application root; falling back to defaults", label)
            return fallback
        if os.path.isdir(candidate):
            return candidate
        logger.warning("%s path is invalid or inaccessible; falling back to defaults", label)
    return fallback

env_templates = os.environ.get("IPMAP_TEMPLATES")
env_static = os.environ.get("IPMAP_STATIC")

TEMPLATE_DIR = _resolve_path(env_templates, DEFAULT_TEMPLATE_DIR, label="Template")
STATIC_DIR = _resolve_path(env_static, DEFAULT_STATIC_DIR, label="Static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

engine = ForensicEngine()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/v1/locate')
def locate():
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify({"error": "No IP provided"}), 400

    entry = engine.get_entry(target_ip)
    if not entry:
        return jsonify({"error": "IP not found"}), 404

    org = engine.get_organization_info(target_ip)
    return jsonify({"node": entry, "organization": org}), 200


@app.route('/api/v1/trace')
def trace():
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify({"error": "No IP provided"}), 400

    deep_val = request.args.get('deep', "0").lower()
    deep_mode = deep_val in ("1", "true", "yes", "on")
    try:
        maxttl = int(request.args.get('maxttl', 30))
    except Exception:
        maxttl = 30

    try:
        session_results = engine.run_analysis(target_ip, deep_mode=deep_mode, maxttl=maxttl)
    except Exception as e:
        return jsonify({"error": f"Traceroute failed: {e}"}), 500

    nodes = {}
    for hop in session_results.get("path", []):
        hop_ip = hop.get("ip")
        if hop_ip:
            node = engine.get_entry(hop_ip)
            nodes[hop_ip] = node

    return jsonify({"session": session_results, "nodes": nodes}), 200


@app.route('/api/v1/accesses')
def accesses():
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify({"error": "No IP provided"}), 400

    try:
        limit = int(request.args.get('limit', 100))
    except Exception:
        limit = 100

    accesses = engine.get_accesses_for_ip(target_ip, limit=limit)
    return jsonify({"ip": target_ip, "accesses": accesses}), 200


@app.route('/api/v1/search')
def search():
    typ = request.args.get('type', 'node').lower()
    q = request.args.get('q', '') or ''
    fuzzy = request.args.get('fuzzy', '0').lower() in ("1", "true", "yes", "on")
    try:
        limit = int(request.args.get('limit', 100))
    except Exception:
        limit = 100

    if typ in ('org', 'organization'):
        try:
            results = engine.search_organizations(query=q, fuzzy=fuzzy, limit=limit)
        except Exception as e:
            return jsonify({"error": f"Search failed: {e}"}), 500
        return jsonify({"type": "organization", "query": q, "fuzzy": fuzzy, "results": results}), 200

    try:
        results = engine.search_nodes(query=q, fuzzy=fuzzy, limit=limit)
    except Exception as e:
        return jsonify({"error": f"Search failed: {e}"}), 500
    return jsonify({"type": "node", "query": q, "fuzzy": fuzzy, "results": results}), 200


# Honeypot endpoints ---------------------------------------------------------
@app.route('/api/v1/honeypot/sessions')
def honeypot_sessions():
    try:
        limit = int(request.args.get('limit', 200))
    except Exception:
        limit = 200
    try:
        sessions = engine.get_honeypot_sessions(limit=limit)
        return jsonify({"sessions": sessions}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list sessions: {e}"}), 500


@app.route('/api/v1/honeypot/session')
def honeypot_session():
    sid = request.args.get('id')
    cowrie_sess = request.args.get('cowrie_session')
    try:
        if sid:
            s = engine.get_honeypot_session(int(sid))
            if not s:
                return jsonify({"error": "Session not found"}), 404
            return jsonify({"session": s}), 200

        if cowrie_sess:
            # try to resolve the cowrie_session to an internal id
            if HoneypotSession is None:
                return jsonify({"error": "Honeypot models not available"}), 500
            row = engine.db.query(HoneypotSession).filter_by(cowrie_session=cowrie_sess).first()
            if not row:
                return jsonify({"error": "Session not found"}), 404
            s = engine.get_honeypot_session(row.id)
            return jsonify({"session": s}), 200

        return jsonify({"error": "Provide id or cowrie_session parameter"}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to fetch session: {e}"}), 500


@app.route('/api/v1/honeypot/ingest', methods=['POST'])
def honeypot_ingest():
    """
    Trigger ingestion of a Cowrie JSON log file.
    JSON body: {"path": "/data/cowrie/cowrie.json"}
    """
    data = request.get_json(silent=True) or {}
    path = data.get('path') or request.form.get('path') or request.args.get('path')
    if not path:
        return jsonify({"error": "Provide path to cowrie json file"}), 400

    # Basic safety: restrict to honeypot data dir when possible
    safe_base = os.path.abspath(engine.honeypot_data_dir)
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(safe_base):
        return jsonify({"error": "Ingest path must be inside honeypot data directory"}), 400

    try:
        res = engine.ingest_cowrie_file(abs_path, enrich=True)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": f"Ingest failed: {e}"}), 500


@app.route('/api/v1/honeypot/ingest_pcap', methods=['POST'])
def honeypot_ingest_pcap():
    """
    Trigger PCAP ingest. JSON body: {"path": "/data/honeypot/pkt.pcap", "filter_host": "1.2.3.4"}
    """
    data = request.get_json(silent=True) or {}
    path = data.get('path') or request.form.get('path') or request.args.get('path')
    filter_host = data.get('filter_host') or request.args.get('filter_host')
    if not path:
        return jsonify({"error": "Provide path to pcap file"}), 400

    safe_base = os.path.abspath(engine.honeypot_data_dir)
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(safe_base):
        return jsonify({"error": "PCAP path must be inside honeypot data directory"}), 400

    try:
        res = engine.ingest_pcap(abs_path, filter_host=filter_host)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": f"PCAP ingest failed: {e}"}), 500


@app.route('/api/v1/honeypot/artifact')
def honeypot_artifact():
    """
    Download a captured artifact by filename. Query: ?name=<filename>
    Only serves files from the artifacts directory to avoid path traversal.
    """
    name = request.args.get('name')
    if not name:
        return jsonify({"error": "Provide artifact name"}), 400

    artifacts_dir = os.path.join(engine.honeypot_data_dir, "artifacts")
    safe_path = os.path.abspath(os.path.join(artifacts_dir, name))
    if not safe_path.startswith(os.path.abspath(artifacts_dir)) or not os.path.isfile(safe_path):
        return jsonify({"error": "Artifact not found"}), 404

    return send_file(safe_path, as_attachment=True)


@app.route('/api/v1/honeypot/flows')
def honeypot_flows():
    try:
        limit = int(request.args.get('limit', 200))
    except Exception:
        limit = 200
    if HoneypotNetworkFlow is None:
        return jsonify({"error": "Honeypot models not available"}), 500
    try:
        rows = engine.db.query(HoneypotNetworkFlow).order_by(HoneypotNetworkFlow.start_ts.desc()).limit(limit).all()
        return jsonify({"flows": [r.dict() for r in rows]}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to list flows: {e}"}), 500
# ---------------------------------------------------------------------------


@app.route('/api/v1/organization')
def organization():
    ip = request.args.get('ip')
    org_id = request.args.get('id')
    if not ip and not org_id:
        return jsonify({"error": "Provide an ip or id query parameter"}), 400

    if ip:
        org = engine.get_organization_info(ip)
        if not org:
            return jsonify({"error": "Organization not found for IP"}), 404
        return jsonify({"organization": org}), 200

    try:
        oid = int(org_id)
    except Exception:
        return jsonify({"error": "Invalid organization id"}), 400

    org = engine.get_organization(oid)
    if not org:
        return jsonify({"error": "Organization not found for id"}), 404
    return jsonify({"organization": org}), 200


@app.route('/api/v1/organization/refresh')
def refresh_organization():
    identifier = request.args.get('id') or request.args.get('ip')
    if not identifier:
        return jsonify({"error": "Provide id (IP, org id or org name)"}), 400

    force_val = request.args.get('force', '1').lower()
    force = force_val in ("1", "true", "yes", "on")

    refresh_fn = getattr(engine, "refresh_organization", None)
    if not refresh_fn:
        return jsonify({"error": "Refresh function not available on this engine build"}), 501

    try:
        org = refresh_fn(identifier, force=force)
    except Exception as e:
        return jsonify({"error": f"Refresh failed: {e}"}), 500

    if not org:
        return jsonify({"error": "Organization not found or enrichment failed"}), 404

    return jsonify({"organization": org}), 200


# -------------------------
# New DB endpoints for "Database" tab
# -------------------------
@app.route('/api/v1/db/search')
def db_search():
    """
    Unified DB search for the Database tab.
    Query params:
      - type: node|org|honeypot|access|analysis|flow
      - q: query string (free text)
      - fuzzy: bool (0/1)
      - limit: integer
    """
    typ = (request.args.get('type') or 'node').lower()
    q = (request.args.get('q') or '').strip()
    fuzzy = request.args.get('fuzzy', '0').lower() in ("1", "true", "yes", "on")
    try:
        limit = int(request.args.get('limit', 200))
    except Exception:
        limit = 200

    try:
        if typ in ('node', 'nodes'):
            # reuse engine helper (returns node.dict())
            results = engine.search_nodes(query=q, fuzzy=fuzzy, limit=limit)
            return jsonify({"type": "node", "query": q, "results": results}), 200

        if typ in ('org', 'organization', 'orgs'):
            results = engine.search_organizations(query=q, fuzzy=fuzzy, limit=limit)
            return jsonify({"type": "organization", "query": q, "results": results}), 200

        if typ in ('honeypot', 'honeypot_session', 'session', 'sessions'):
            if HoneypotSession is None:
                return jsonify({"error": "Honeypot models not available"}), 500
            qlike = f"%{q}%"
            qobj = engine.db.query(HoneypotSession)
            if q:
                qobj = qobj.filter(
                    (HoneypotSession.src_ip.ilike(qlike)) |
                    (HoneypotSession.username.ilike(qlike)) |
                    (HoneypotSession.cowrie_session.ilike(qlike))
                )
            rows = qobj.order_by(HoneypotSession.start_ts.desc()).limit(limit).all()
            return jsonify({"type": "honeypot_sessions", "query": q, "results": [r.dict() for r in rows]}), 200

        if typ in ('access', 'accesses', 'webaccess'):
            if WebAccess is None:
                return jsonify({"error": "WebAccess model not available"}), 500
            qlike = f"%{q}%"
            qobj = engine.db.query(WebAccess)
            if q:
                qobj = qobj.filter(
                    (WebAccess.remote_addr.ilike(qlike)) |
                    (WebAccess.request.ilike(qlike)) |
                    (WebAccess.path.ilike(qlike)) |
                    (WebAccess.http_user_agent.ilike(qlike))
                )
            rows = qobj.order_by(WebAccess.timestamp.desc()).limit(limit).all()
            return jsonify({"type": "web_accesses", "query": q, "results": [r.dict() for r in rows]}), 200

        if typ in ('analysis', 'analyses', 'trace'):
            if AnalysisSession is None:
                return jsonify({"error": "AnalysisSession model not available"}), 500
            qlike = f"%{q}%"
            qobj = engine.db.query(AnalysisSession)
            if q:
                # allow searching by target_ip or id
                try:
                    qid = int(q)
                    qobj = qobj.filter(AnalysisSession.id == qid)
                except Exception:
                    qobj = qobj.filter(AnalysisSession.target_ip.ilike(qlike))
            rows = qobj.order_by(AnalysisSession.timestamp.desc()).limit(limit).all()
            return jsonify({"type": "analyses", "query": q, "results": [r.dict() for r in rows]}), 200

        if typ in ('flow', 'flows'):
            if HoneypotNetworkFlow is None:
                return jsonify({"error": "HoneypotNetworkFlow model not available"}), 500
            qlike = f"%{q}%"
            qobj = engine.db.query(HoneypotNetworkFlow)
            if q:
                qobj = qobj.filter(
                    (HoneypotNetworkFlow.src_ip.ilike(qlike)) |
                    (HoneypotNetworkFlow.dst_ip.ilike(qlike)) |
                    (HoneypotNetworkFlow.proto.ilike(qlike))
                )
            rows = qobj.order_by(HoneypotNetworkFlow.start_ts.desc()).limit(limit).all()
            return jsonify({"type": "flows", "query": q, "results": [r.dict() for r in rows]}), 200

        return jsonify({"error": "Unknown type parameter"}), 400
    except Exception as e:
        return jsonify({"error": f"DB search failed: {e}"}), 500


@app.route('/api/v1/db/node')
def db_node():
    """
    Return a detailed view for a NetworkNode including:
      - node dict (same as engine.get_entry)
      - recent web accesses
      - recent analysis sessions targeting that IP
      - recent honeypot sessions from that IP
    Query params:
      - ip=<ip>
      - limit=<N> (optional, default 50)
    """
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "Provide ip query parameter"}), 400

    try:
        limit = int(request.args.get('limit', 50))
    except Exception:
        limit = 50

    node = engine.db.query(NetworkNode).filter_by(ip=ip).first()
    if not node:
        return jsonify({"error": "Node not found"}), 404

    node_dict = node.dict()

    accesses = []
    try:
        accesses = engine.get_accesses_for_ip(ip, limit=limit)
    except Exception:
        accesses = []

    analyses = []
    try:
        if AnalysisSession is not None:
            rows = engine.db.query(AnalysisSession).filter(AnalysisSession.target_ip == ip).order_by(AnalysisSession.timestamp.desc()).limit(limit).all()
            analyses = [r.dict() for r in rows]
    except Exception:
        analyses = []

    honeypot_sessions = []
    try:
        if HoneypotSession is not None:
            rows = engine.db.query(HoneypotSession).filter(HoneypotSession.src_ip == ip).order_by(HoneypotSession.start_ts.desc()).limit(limit).all()
            honeypot_sessions = [r.dict() for r in rows]
    except Exception:
        honeypot_sessions = []

    return jsonify({
        "node": node_dict,
        "recent_accesses": accesses,
        "analyses": analyses,
        "honeypot_sessions": honeypot_sessions
    }), 200

@app.route('/api/v1/health')
def health():
    return jsonify({"status": "ok"}), 200

@app.route('/favicon.ico')
def favicon():
    return send_file(os.path.join(STATIC_DIR, 'favicon.ico'))


if __name__ == '__main__':
    debug = os.environ.get("IPMAP_DEBUG", "1") in ("1", "true", "yes")
    app.run(host='0.0.0.0', port=int(os.environ.get("IPMAP_PORT", "5000")), debug=debug)
