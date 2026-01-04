"""
Locate and trace routes blueprint for HoneyMoon.
Handles IP location, trace, and search operations.
"""
from flask import Blueprint, request, jsonify

locate_bp = Blueprint('locate', __name__)

# Engine reference - will be set during registration
_engine = None


def init_locate_routes(engine):
    """Initialize locate routes with the forensic engine."""
    global _engine
    _engine = engine


@locate_bp.route('/api/v1/locate')
def locate():
    """Locate an IP address and get its information."""
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify({"error": "No IP provided"}), 400

    entry = _engine.get_entry(target_ip)
    if not entry:
        return jsonify({"error": "IP not found"}), 404

    org = _engine.get_organization_info(target_ip)
    return jsonify({"node": entry, "organization": org}), 200


@locate_bp.route('/api/v1/trace')
def trace():
    """Run a traceroute analysis to the target IP."""
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
        session_results = _engine.run_analysis(target_ip, deep_mode=deep_mode, maxttl=maxttl)
    except Exception as e:
        return jsonify({"error": f"Traceroute failed: {e}"}), 500

    nodes = {}
    for hop in session_results.get("path", []):
        hop_ip = hop.get("ip")
        if hop_ip:
            node = _engine.get_entry(hop_ip)
            nodes[hop_ip] = node

    return jsonify({"session": session_results, "nodes": nodes}), 200


@locate_bp.route('/api/v1/accesses')
def accesses():
    """Get web accesses for an IP address."""
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify({"error": "No IP provided"}), 400

    try:
        limit = int(request.args.get('limit', 100))
    except Exception:
        limit = 100

    accesses = _engine.get_accesses_for_ip(target_ip, limit=limit)
    return jsonify({"ip": target_ip, "accesses": accesses}), 200


@locate_bp.route('/api/v1/search')
def search():
    """Search for nodes or organizations."""
    typ = request.args.get('type', 'node').lower()
    q = request.args.get('q', '') or ''
    fuzzy = request.args.get('fuzzy', '0').lower() in ("1", "true", "yes", "on")
    try:
        limit = int(request.args.get('limit', 100))
    except Exception:
        limit = 100

    if typ in ('org', 'organization'):
        try:
            results = _engine.search_organizations(query=q, fuzzy=fuzzy, limit=limit)
        except Exception as e:
            return jsonify({"error": f"Search failed: {e}"}), 500
        return jsonify({"type": "organization", "query": q, "fuzzy": fuzzy, "results": results}), 200

    try:
        results = _engine.search_nodes(query=q, fuzzy=fuzzy, limit=limit)
    except Exception as e:
        return jsonify({"error": f"Search failed: {e}"}), 500
    return jsonify({"type": "node", "query": q, "fuzzy": fuzzy, "results": results}), 200


@locate_bp.route('/api/v1/organization')
def organization():
    """Get organization information by IP or ID."""
    ip = request.args.get('ip')
    org_id = request.args.get('id')
    if not ip and not org_id:
        return jsonify({"error": "Provide an ip or id query parameter"}), 400

    if ip:
        org = _engine.get_organization_info(ip)
        if not org:
            return jsonify({"error": "Organization not found for IP"}), 404
        return jsonify({"organization": org}), 200

    try:
        oid = int(org_id)
    except Exception:
        return jsonify({"error": "Invalid organization id"}), 400

    org = _engine.get_organization(oid)
    if not org:
        return jsonify({"error": "Organization not found for id"}), 404
    return jsonify({"organization": org}), 200


@locate_bp.route('/api/v1/organization/refresh')
def refresh_organization():
    """Refresh organization data."""
    identifier = request.args.get('id') or request.args.get('ip')
    if not identifier:
        return jsonify({"error": "Provide id (IP, org id or org name)"}), 400

    force_val = request.args.get('force', '1').lower()
    force = force_val in ("1", "true", "yes", "on")

    refresh_fn = getattr(_engine, "refresh_organization", None)
    if not refresh_fn:
        return jsonify({"error": "Refresh function not available on this engine build"}), 501

    try:
        org = refresh_fn(identifier, force=force)
    except Exception as e:
        return jsonify({"error": f"Refresh failed: {e}"}), 500

    if not org:
        return jsonify({"error": "Organization not found or enrichment failed"}), 404

    return jsonify({"organization": org}), 200
