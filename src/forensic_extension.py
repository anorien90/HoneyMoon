"""
Small helpers for non‑intrusive service and protocol fingerprinting.

Intended to be imported by forensic_engine.ForensicEngine. Designed to be
safe-by-default (timeouts, limited payloads) and to return parsed dicts
that can be stored in NetworkNode.extra_data['fingerprints'].

WARNING: Use only on systems you own or have permission to scan.
"""
import socket
import ssl
import json
from typing import Optional, Dict, Any, List
import requests
import time

# Optional nmap import - if it's not installed, the nmap scan functions will
# return a helpful error dict instead of throwing.
try:
    import nmap
    _HAS_NMAP = True
except Exception:
    nmap = None
    _HAS_NMAP = False


def banner_grab(ip: str, port: int, timeout: float = 2.0, send_bytes: Optional[bytes] = None) -> Optional[str]:
    """Simple TCP connect + optional probe bytes then read banner (non-blocking)."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        if send_bytes:
            try:
                s.sendall(send_bytes)
            except Exception:
                pass
        try:
            data = s.recv(2048)
            return data.decode(errors='ignore').strip()
        except Exception:
            return None
    except Exception:
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def ssh_banner(ip: str, port: int = 22, timeout: float = 3.0) -> Optional[str]:
    """Read the initial SSH banner line (e.g. 'SSH-2.0-OpenSSH_7.4')."""
    return banner_grab(ip, port, timeout=timeout)


def fetch_http_headers(ip: str, port: int = 80, use_https: bool = False, path: str = "/", host_header: Optional[str] = None,
                       timeout: float = 4.0) -> Dict[str, Any]:
    """
    Perform a simple HTTP(S) GET of the given path and return headers and a few heuristics.
    :param host_header: if provided, sets Host: header to this value (useful when scanning by IP for virtual hosts)
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}{path}"
    headers = {"User-Agent": "IPMap/ForensicEngine (+https://example.local)"}
    if host_header:
        headers["Host"] = host_header
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False, verify=False)
        sec_headers = {k: v for k, v in r.headers.items() if k.lower().startswith(("x-", "server", "set-cookie", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"))}
        result = {
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "security_headers": sec_headers,
            "server": r.headers.get("Server"),
            "x_powered_by": r.headers.get("X-Powered-By"),
            "content_snippet": (r.text or "")[:1024] if isinstance(r.text, str) else None,
            "timestamp": time.time()
        }
        return result
    except Exception as e:
        return {"error": str(e), "timestamp": time.time()}


def fetch_tls_info(ip: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Connect via TLS and return basic cert fields and negotiated cipher.
    Does not do deep protocol probing (use specialized tools for that).
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                # normalize some fields from cert dict
                subject = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
                issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
                san = cert.get("subjectAltName", [])
                notBefore = cert.get("notBefore")
                notAfter = cert.get("notAfter")
                return {
                    "cert_subject": subject,
                    "cert_issuer": issuer,
                    "san": san,
                    "notBefore": notBefore,
                    "notAfter": notAfter,
                    "cipher": cipher,
                    "peercert": cert
                }
    except Exception as e:
        return {"error": str(e)}


def nmap_service_scan(ip: str, ports: Optional[str] = None, sudo_for_os: bool = False, timeout: int = 60) -> Dict[str, Any]:
    """
    Wrapper around python-nmap to run a small service/version scan.
    - ports: string like "22,80,443" or "-F" for fast; if None, uses -F (fast)
    - sudo_for_os: if True and nmap supports -O, it will request OS detection (note: requires privileges)
    Returns a dict describing scanned ports and optionally OS matches.
    """
    if not _HAS_NMAP:
        return {"error": "nmap python library not available"}
    nm = nmap.PortScanner()
    args = "-sV --version-intensity 2 -Pn"
    if not ports:
        args += " -F"
    else:
        args += f" -p {ports}"
    if sudo_for_os:
        args += " -O"

    try:
        nm.scan(hosts=ip, arguments=args, timeout=timeout)
        out = {}
        if ip in nm.all_hosts():
            host = nm[ip]
            # services
            services = {}
            for proto in host.get('tcp', {}), host.get('udp', {}):
                # proto is a dict of port -> info; iterate safely
                if not isinstance(proto, dict):
                    continue
                for p, info in proto.items():
                    services.setdefault(p, {}).update(info or {})
            # os
            osmatch = host.get('osmatch', [])
            out['services'] = services
            out['osmatch'] = osmatch
            out['nmap_raw'] = host
        else:
            out['error'] = "host not found in nmap result"
        return out
    except Exception as e:
        return {"error": str(e)}


def safe_http_enum_well_known(ip: str, port: int = 80, use_https: bool = False, host_header: Optional[str] = None,
                              timeout: float = 4.0) -> Dict[str, Any]:
    """
    Fetch a small list of well-known paths that attackers commonly probe:
    - /
    - /robots.txt
    - /.git/ (check simple existence)
    - /server-status (common)
    Returns a map of path -> summary
    """
    paths = ["/", "/robots.txt", "/server-status", "/.git/config"]
    results = {}
    for p in paths:
        info = fetch_http_headers(ip, port=port, use_https=use_https, path=p, host_header=host_header, timeout=timeout)
        results[p] = {
            "status_code": info.get("status_code") if isinstance(info, dict) else None,
            "server": info.get("server") if isinstance(info, dict) else None,
            "error": info.get("error") if isinstance(info, dict) else None
        }
    return results
