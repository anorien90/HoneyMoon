"""
Database routes blueprint for HoneyMoon.
Handles database search, node details, ISP, and outgoing connections.
"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify

database_bp = Blueprint('database', __name__)

# Dependencies - will be set during registration
_engine = None
_NetworkNode = None
_WebAccess = None
_AnalysisSession = None
_ISP = None
_OutgoingConnection = None
_HoneypotSession = None
_HoneypotNetworkFlow = None
_ThreatAnalysis = None
_DetectionRuleRecord = None
_CountermeasureRecord = None


def init_database_routes(engine, network_node=None, web_access=None, analysis_session=None,
                         isp=None, outgoing_connection=None, honeypot_session=None,
                         honeypot_flow=None, threat_analysis=None, detection_rule=None,
                         countermeasure=None):
    """Initialize database routes with dependencies."""
    global _engine, _NetworkNode, _WebAccess, _AnalysisSession, _ISP
    global _OutgoingConnection, _HoneypotSession, _HoneypotNetworkFlow
    global _ThreatAnalysis, _DetectionRuleRecord, _CountermeasureRecord
    _engine = engine
    _NetworkNode = network_node
    _WebAccess = web_access
    _AnalysisSession = analysis_session
    _ISP = isp
    _OutgoingConnection = outgoing_connection
    _HoneypotSession = honeypot_session
    _HoneypotNetworkFlow = honeypot_flow
    _ThreatAnalysis = threat_analysis
    _DetectionRuleRecord = detection_rule
    _CountermeasureRecord = countermeasure


@database_bp.route('/api/v1/isp')
def isp():
    """Get ISP by id or by IP."""
    ip = request.args.get('ip')
    isp_id = request.args.get('id')
    if not ip and not isp_id:
        return jsonify({"error": "Provide an ip or id query parameter"}), 400

    if ip:
        node = _engine.db.query(_NetworkNode).filter_by(ip=ip).first() if _NetworkNode else None
        if not node or not node.isp_obj:
            return jsonify({"error": "ISP not found for IP"}), 404
        return jsonify({"isp": node.isp_obj.dict()}), 200

    try:
        iid = int(isp_id)
    except Exception:
        return jsonify({"error": "Invalid ISP id"}), 400

    if _ISP is None:
        return jsonify({"error": "ISP model not available"}), 500
    
    isp_record = _engine.db.query(_ISP).filter_by(id=iid).first()
    if not isp_record:
        return jsonify({"error": "ISP not found for id"}), 404
    return jsonify({"isp": isp_record.dict()}), 200


@database_bp.route('/api/v1/isp/search')
def isp_search():
    """Search ISPs by name or ASN."""
    q = request.args.get('q', '') or ''
    fuzzy = request.args.get('fuzzy', '0').lower() in ("1", "true", "yes", "on")
    try:
        limit = int(request.args.get('limit', 100))
    except Exception:
        limit = 100

    try:
        results = _engine.search_isps(query=q, fuzzy=fuzzy, limit=limit)
        return jsonify({"type": "isp", "query": q, "fuzzy": fuzzy, "results": results}), 200
    except Exception as e:
        return jsonify({"error": f"ISP search failed: {e}"}), 500


@database_bp.route('/api/v1/outgoing/connections')
def outgoing_connections():
    """Get recent outgoing network connections."""
    try:
        limit = int(request.args.get('limit', 100))
        limit = max(1, min(500, limit))
    except Exception:
        limit = 100

    direction = request.args.get('direction')
    
    try:
        connections = _engine.get_outgoing_connections(limit=limit, direction=direction)
        return jsonify({"connections": connections, "count": len(connections)}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to get outgoing connections: {e}"}), 500


@database_bp.route('/api/v1/outgoing/live')
def outgoing_live():
    """
    Get recent outgoing connections from the last X minutes.
    Query params:
      - minutes: time window in minutes (default: 15, max: 1440)
      - limit: max results (default: 100)
      - direction: filter by direction ('outgoing', 'internal', or None for all)
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

    direction = request.args.get('direction')
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    result = {
        "minutes": minutes,
        "cutoff": cutoff.isoformat(),
        "connections": []
    }

    if _OutgoingConnection is not None:
        try:
            query = _engine.db.query(_OutgoingConnection).filter(
                _OutgoingConnection.timestamp >= cutoff
            )
            if direction:
                query = query.filter(_OutgoingConnection.direction == direction)
            
            rows = query.order_by(_OutgoingConnection.timestamp.desc()).limit(limit).all()

            for conn in rows:
                conn_dict = conn.dict()
                if conn.remote_addr:
                    node = _engine.get_entry(conn.remote_addr)
                    if node:
                        conn_dict["remote_node"] = {
                            "ip": node.get("ip"),
                            "latitude": node.get("latitude"),
                            "longitude": node.get("longitude"),
                            "city": node.get("city"),
                            "country": node.get("country"),
                            "organization": node.get("organization"),
                            "isp": node.get("isp")
                        }
                result["connections"].append(conn_dict)
        except Exception as e:
            result["connections_error"] = str(e)

    return jsonify(result), 200


@database_bp.route('/api/v1/db/search')
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
            results = _engine.search_nodes(query=q, fuzzy=fuzzy, limit=limit)
            return jsonify({"type": "node", "query": q, "results": results}), 200

        if typ in ('org', 'organization', 'orgs'):
            results = _engine.search_organizations(query=q, fuzzy=fuzzy, limit=limit)
            return jsonify({"type": "organization", "query": q, "results": results}), 200

        if typ in ('honeypot', 'honeypot_session', 'session', 'sessions'):
            if _HoneypotSession is None:
                return jsonify({"error": "Honeypot models not available"}), 500
            qlike = f"%{q}%"
            qobj = _engine.db.query(_HoneypotSession)
            if q:
                qobj = qobj.filter(
                    (_HoneypotSession.src_ip.ilike(qlike)) |
                    (_HoneypotSession.username.ilike(qlike)) |
                    (_HoneypotSession.cowrie_session.ilike(qlike))
                )
            rows = qobj.order_by(_HoneypotSession.start_ts.desc()).limit(limit).all()
            return jsonify({"type": "honeypot_sessions", "query": q, "results": [r.dict() for r in rows]}), 200

        if typ in ('access', 'accesses', 'webaccess'):
            if _WebAccess is None:
                return jsonify({"error": "WebAccess model not available"}), 500
            qlike = f"%{q}%"
            qobj = _engine.db.query(_WebAccess)
            if q:
                qobj = qobj.filter(
                    (_WebAccess.remote_addr.ilike(qlike)) |
                    (_WebAccess.request.ilike(qlike)) |
                    (_WebAccess.path.ilike(qlike)) |
                    (_WebAccess.http_user_agent.ilike(qlike))
                )
            rows = qobj.order_by(_WebAccess.timestamp.desc()).limit(limit).all()
            return jsonify({"type": "web_accesses", "query": q, "results": [r.dict() for r in rows]}), 200

        if typ in ('analysis', 'analyses', 'trace'):
            if _AnalysisSession is None:
                return jsonify({"error": "AnalysisSession model not available"}), 500
            qlike = f"%{q}%"
            qobj = _engine.db.query(_AnalysisSession)
            if q:
                try:
                    qid = int(q)
                    qobj = qobj.filter(_AnalysisSession.id == qid)
                except Exception:
                    qobj = qobj.filter(_AnalysisSession.target_ip.ilike(qlike))
            rows = qobj.order_by(_AnalysisSession.timestamp.desc()).limit(limit).all()
            return jsonify({"type": "analyses", "query": q, "results": [r.dict() for r in rows]}), 200

        if typ in ('flow', 'flows'):
            if _HoneypotNetworkFlow is None:
                return jsonify({"error": "HoneypotNetworkFlow model not available"}), 500
            qlike = f"%{q}%"
            qobj = _engine.db.query(_HoneypotNetworkFlow)
            if q:
                qobj = qobj.filter(
                    (_HoneypotNetworkFlow.src_ip.ilike(qlike)) |
                    (_HoneypotNetworkFlow.dst_ip.ilike(qlike)) |
                    (_HoneypotNetworkFlow.proto.ilike(qlike))
                )
            rows = qobj.order_by(_HoneypotNetworkFlow.start_ts.desc()).limit(limit).all()
            return jsonify({"type": "flows", "query": q, "results": [r.dict() for r in rows]}), 200

        if typ in ('isp', 'isps'):
            results = _engine.search_isps(query=q, fuzzy=fuzzy, limit=limit)
            return jsonify({"type": "isp", "query": q, "results": results}), 200

        if typ in ('outgoing', 'outgoing_connections'):
            if _OutgoingConnection is None:
                return jsonify({"error": "OutgoingConnection model not available"}), 500
            qlike = f"%{q}%"
            qobj = _engine.db.query(_OutgoingConnection)
            if q:
                qobj = qobj.filter(
                    (_OutgoingConnection.local_addr.ilike(qlike)) |
                    (_OutgoingConnection.remote_addr.ilike(qlike)) |
                    (_OutgoingConnection.process_name.ilike(qlike)) |
                    (_OutgoingConnection.status.ilike(qlike))
                )
            rows = qobj.order_by(_OutgoingConnection.timestamp.desc()).limit(limit).all()
            return jsonify({"type": "outgoing_connections", "query": q, "results": [r.dict() for r in rows]}), 200

        # Search for threat analyses (reports)
        if typ in ('threat', 'threats', 'report', 'reports', 'threat_analysis'):
            if _ThreatAnalysis is None:
                return jsonify({"error": "ThreatAnalysis model not available"}), 500
            qlike = f"%{q}%"
            qobj = _engine.db.query(_ThreatAnalysis)
            if q:
                qobj = qobj.filter(
                    (_ThreatAnalysis.source_ip.ilike(qlike)) |
                    (_ThreatAnalysis.threat_type.ilike(qlike)) |
                    (_ThreatAnalysis.severity.ilike(qlike)) |
                    (_ThreatAnalysis.summary.ilike(qlike))
                )
            rows = qobj.order_by(_ThreatAnalysis.analyzed_at.desc()).limit(limit).all()
            return jsonify({"type": "threat_analyses", "query": q, "results": [r.dict() for r in rows]}), 200

        # Search for detection rules
        if typ in ('detection_rule', 'detection_rules', 'rules'):
            if _DetectionRuleRecord is None:
                return jsonify({"error": "DetectionRuleRecord model not available"}), 500
            qlike = f"%{q}%"
            qobj = _engine.db.query(_DetectionRuleRecord)
            if q:
                qobj = qobj.filter(
                    (_DetectionRuleRecord.source_ip.ilike(qlike)) |
                    (_DetectionRuleRecord.name.ilike(qlike)) |
                    (_DetectionRuleRecord.rule_type.ilike(qlike)) |
                    (_DetectionRuleRecord.rule_content.ilike(qlike))
                )
            rows = qobj.order_by(_DetectionRuleRecord.created_at.desc()).limit(limit).all()
            return jsonify({"type": "detection_rules", "query": q, "results": [r.dict() for r in rows]}), 200

        # Search for countermeasures
        if typ in ('countermeasure', 'countermeasures'):
            if _CountermeasureRecord is None:
                return jsonify({"error": "CountermeasureRecord model not available"}), 500
            qlike = f"%{q}%"
            qobj = _engine.db.query(_CountermeasureRecord)
            if q:
                qobj = qobj.filter(
                    (_CountermeasureRecord.name.ilike(qlike)) |
                    (_CountermeasureRecord.description.ilike(qlike)) |
                    (_CountermeasureRecord.status.ilike(qlike))
                )
            rows = qobj.order_by(_CountermeasureRecord.created_at.desc()).limit(limit).all()
            return jsonify({"type": "countermeasures", "query": q, "results": [r.dict() for r in rows]}), 200

        return jsonify({"error": "Unknown type parameter"}), 400
    except Exception as e:
        return jsonify({"error": f"DB search failed: {e}"}), 500


@database_bp.route('/api/v1/db/node')
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

    node = _engine.db.query(_NetworkNode).filter_by(ip=ip).first()
    if not node:
        return jsonify({"error": "Node not found"}), 404

    node_dict = node.dict()

    accesses = []
    try:
        accesses = _engine.get_accesses_for_ip(ip, limit=limit)
    except Exception:
        accesses = []

    analyses = []
    try:
        if _AnalysisSession is not None:
            rows = _engine.db.query(_AnalysisSession).filter(
                _AnalysisSession.target_ip == ip
            ).order_by(_AnalysisSession.timestamp.desc()).limit(limit).all()
            analyses = [r.dict() for r in rows]
    except Exception:
        analyses = []

    honeypot_sessions = []
    try:
        if _HoneypotSession is not None:
            rows = _engine.db.query(_HoneypotSession).filter(
                _HoneypotSession.src_ip == ip
            ).order_by(_HoneypotSession.start_ts.desc()).limit(limit).all()
            honeypot_sessions = [r.dict() for r in rows]
    except Exception:
        honeypot_sessions = []

    # Get threat analyses associated with this IP
    threat_analyses = []
    try:
        if _ThreatAnalysis is not None:
            rows = _engine.db.query(_ThreatAnalysis).filter(
                _ThreatAnalysis.source_ip == ip
            ).order_by(_ThreatAnalysis.analyzed_at.desc()).limit(limit).all()
            threat_analyses = [r.dict() for r in rows]
    except Exception:
        threat_analyses = []

    # Get detection rules associated with this IP
    detection_rules = []
    try:
        if _DetectionRuleRecord is not None:
            rows = _engine.db.query(_DetectionRuleRecord).filter(
                _DetectionRuleRecord.source_ip == ip
            ).order_by(_DetectionRuleRecord.created_at.desc()).limit(limit).all()
            detection_rules = [r.dict() for r in rows]
    except Exception:
        detection_rules = []

    # Get countermeasures for threat analyses associated with this IP
    countermeasures = []
    try:
        if _CountermeasureRecord is not None and threat_analyses:
            threat_ids = [t.get('id') for t in threat_analyses if t.get('id')]
            if threat_ids:
                rows = _engine.db.query(_CountermeasureRecord).filter(
                    _CountermeasureRecord.threat_analysis_id.in_(threat_ids)
                ).order_by(_CountermeasureRecord.created_at.desc()).limit(limit).all()
                countermeasures = [r.dict() for r in rows]
    except Exception:
        countermeasures = []

    return jsonify({
        "node": node_dict,
        "recent_accesses": accesses,
        "analyses": analyses,
        "honeypot_sessions": honeypot_sessions,
        "threat_analyses": threat_analyses,
        "detection_rules": detection_rules,
        "countermeasures": countermeasures
    }), 200
