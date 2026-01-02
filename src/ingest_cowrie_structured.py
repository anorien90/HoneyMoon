#!/usr/bin/env python3
import sys
import os
import json
import hashlib
from datetime import datetime, timezone
from src.forensic_engine import ForensicEngine
from src.honeypot_models import HoneypotSession, HoneypotCommand, HoneypotFile
from sqlalchemy.exc import IntegrityError

DATA_DIR = os.environ.get("HONEY_DATA_DIR", "./honeypot-data")
ARTIFACT_DIR = os.path.join(DATA_DIR, "artifacts")
os.makedirs(ARTIFACT_DIR, exist_ok=True)

def sha256_bytes(b):
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def parse_cowrie_events(path_or_stdin):
    if path_or_stdin == "-":
        fh = sys.stdin
    else:
        fh = open(path_or_stdin, "r", encoding="utf-8", errors="replace")
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue
    if path_or_stdin != "-":
        fh.close()

def ensure_session(db, ev):
    # Cowrie often includes "session" or "session" id keys; adapt to actual event structure
    sess_id = ev.get("session") or ev.get("sessionid") or ev.get("cowrie_session")
    src_ip = ev.get("src_ip") or ev.get("src_addr") or ev.get("src")
    src_port = ev.get("src_port") or ev.get("src_port", None)
    username = ev.get("username") or ev.get("user", None)

    if sess_id:
        s = db.query(HoneypotSession).filter_by(cowrie_session=sess_id).first()
        if s:
            return s
    # Create a new session record for events without known session
    s = HoneypotSession(cowrie_session=sess_id, src_ip=src_ip or "UNKNOWN", src_port=src_port, username=username, raw_events=[])
    db.add(s)
    db.flush()
    return s

def handle_file_event(db, sess, ev):
    # Cowrie may include file download events with "outfile" or URL/sha256. We look for common keys.
    filename = ev.get("outfile") or ev.get("filename") or ev.get("url_filename") or ev.get("file")
    data_b64 = ev.get("file_data_b64") or ev.get("file_contents_b64")
    url = ev.get("url") or ev.get("download_url")
    direction = "download" if url or ev.get("direction") == "download" else ev.get("direction", "unknown")
    saved_path = None
    sha256 = None
    size = None

    # If Cowrie produced raw bytes inline (rare), decode and save
    if data_b64:
        try:
            import base64
            b = base64.b64decode(data_b64)
            sha256 = sha256_bytes(b)
            size = len(b)
            safe_name = f"{sha256}_{filename or 'file'}"
            saved_path = os.path.join(ARTIFACT_DIR, safe_name)
            with open(saved_path, "wb") as fh:
                fh.write(b)
        except Exception:
            pass

    hf = HoneypotFile(session_id=sess.id, timestamp=datetime.now(timezone.utc), filename=filename, direction=direction, size=size, sha256=sha256, saved_path=saved_path, raw=ev)
    db.add(hf)
    db.flush()
    return hf

def handle_command_event(db, sess, ev):
    cmd = ev.get("input") or ev.get("command") or ev.get("cmd")
    if not cmd:
        return None
    hc = HoneypotCommand(session_id=sess.id, timestamp=datetime.now(timezone.utc), command=cmd, raw=ev)
    db.add(hc)
    db.flush()
    return hc

def ingest(path):
    engine = ForensicEngine()  # uses existing DB
    db = engine.db

    for ev in parse_cowrie_events(path):
        try:
            sess = ensure_session(db, ev)
            # append raw event for audit
            raw = sess.raw_events or []
            raw.append(ev)
            sess.raw_events = raw

            # persist common event types
            evtype = ev.get("event") or ev.get("message") or ev.get("type")

            # command
            if evtype and "input" in ev:
                handle_command_event(db, sess, ev)

            # file/download
            if evtype and ("url" in ev or "outfile" in ev or "file" in ev):
                handle_file_event(db, sess, ev)

            # session close or auth result
            if evtype and evtype in ("session.closed", "session.connect", "session.login.success", "session.login.failed"):
                if evtype == "session.closed":
                    sess.end_ts = datetime.now(timezone.utc)
                if evtype.startswith("session.login"):
                    sess.auth_success = "success" if "success" in evtype else "failed"
                    sess.username = ev.get("username") or sess.username

            # Ensure src_ip is enriched in ForensicEngine DB
            try:
                if sess.src_ip:
                    node = engine.get_node_from_db_or_web(sess.src_ip)
                    # optionally store reference id in session.extra
                    sess.extra = sess.extra or {}
                    sess.extra["node_cached"] = {"ip": sess.src_ip, "organization": getattr(node, "organization", None) if node else None}
            except Exception:
                pass

            # commit periodically
            db.commit()
        except IntegrityError:
            db.rollback()
        except Exception:
            db.rollback()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ingest_cowrie_structured.py /path/to/cowrie.json")
        sys.exit(1)
    ingest(sys.argv[1])
