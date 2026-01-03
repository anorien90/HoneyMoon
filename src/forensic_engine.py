import os
import re
import socket
import requests
import whois
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
import logging
from sqlalchemy import create_engine, or_, text
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import sessionmaker
import json
import hashlib
import threading
import time
import traceback
try:
    import maxminddb  # type: ignore
except ImportError:
    maxminddb = None

# scapy imports (used for traceroute and optional pcap ingest)
from scapy.all import traceroute

# package-relative import
from .entry import Base, NetworkNode, AnalysisSession, PathHop, WebAccess, Organization, ISP, OutgoingConnection, ThreatAnalysis, AttackerCluster

# new honeypot models
from .honeypot_models import HoneypotSession, HoneypotCommand, HoneypotFile, HoneypotNetworkFlow

# forensic helpers (banner/http/tls/nmap wrappers)
from .forensic_extension import (
    banner_grab, ssh_banner, fetch_http_headers, fetch_tls_info, nmap_service_scan, safe_http_enum_well_known
)

# Vector store and LLM analyzer imports
try:
    from .vector_store import VectorStore
    _HAS_VECTOR_STORE = True
except ImportError:
    VectorStore = None
    _HAS_VECTOR_STORE = False

try:
    from .llm_analyzer import LLMAnalyzer
    _HAS_LLM_ANALYZER = True
except ImportError:
    LLMAnalyzer = None
    _HAS_LLM_ANALYZER = False

import nmap

# Optional: BeautifulSoup for more robust HTML parsing
try:
    from bs4 import BeautifulSoup  # type: ignore
    _HAS_BS4 = True
except Exception:
    _HAS_BS4 = False

# Optional: psutil for outgoing connection monitoring
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    psutil = None
    _HAS_PSUTIL = False

# Configure logging with thread name
logging.basicConfig(
    format='%(asctime)s [%(threadName)s] %(levelname)s: %(message)s',
    level=logging.INFO
)


def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def _sha256_text(s: str) -> str:
    return _sha256_bytes(s.encode('utf-8', errors='replace'))


def _is_public_ipv4(ip_addr: str) -> bool:
    """
    Check if the given IP address is a public IPv4 address.
    Returns False for private/internal IPv4, IPv6, or invalid addresses.
    
    Note: IPv4-mapped IPv6 addresses (e.g., '::ffff:192.0.2.1') are treated as IPv6
    and will return False. If needed, extract the IPv4 portion before calling this function.
    """
    if not ip_addr:
        return False
    
    # Check if it's IPv6 (contains colons)
    # This includes IPv4-mapped IPv6 addresses like ::ffff:192.0.2.1
    if ':' in ip_addr:
        return False
    
    # Check if it's a valid IPv4 pattern
    parts = ip_addr.split('.')
    if len(parts) != 4:
        return False
    
    try:
        octets = [int(p) for p in parts]
        if not all(0 <= o <= 255 for o in octets):
            return False
    except ValueError:
        return False
    
    # Check for private/internal IP ranges (RFC 1918 + localhost + link-local)
    # 10.0.0.0/8
    if octets[0] == 10:
        return False
    # 172.16.0.0/12
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    # 192.168.0.0/16
    if octets[0] == 192 and octets[1] == 168:
        return False
    # 127.0.0.0/8 (localhost)
    if octets[0] == 127:
        return False
    # 169.254.0.0/16 (link-local)
    if octets[0] == 169 and octets[1] == 254:
        return False
    # 0.0.0.0/8
    if octets[0] == 0:
        return False
    # 224.0.0.0/4 (multicast)
    if octets[0] >= 224:
        return False
    
    return True


class ForensicEngine:
    def __init__(self, db_path='sqlite:///forensic_engine.db', honeypot_data_dir='./data/honeypot', honey_auto_ingest=True, nginx_auto_ingest=True, outgoing_monitor=True):
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        self.lookup_url = "http://api.hostip.info/get_html.php?ip={}"
        db_url = str(db_path)
        db_url_lower = db_url.lower()
        if db_url_lower.startswith("sqlite:"):
            env_timeout = os.environ.get("SQLITE_BUSY_TIMEOUT_SECONDS", "30")
            try:
                sqlite_timeout_seconds = float(env_timeout) if env_timeout else 30.0
            except ValueError:
                sqlite_timeout_seconds = 30.0
            sqlite_timeout_ms = int(sqlite_timeout_seconds * 1000)
            self.engine = create_engine(
                db_url,
                echo=False,
                connect_args={"check_same_thread": False}
            )
            try:
                with self.engine.begin() as conn:
                    conn.execute(text(f"PRAGMA busy_timeout={sqlite_timeout_ms}"))
                    conn.execute(text("PRAGMA journal_mode=WAL"))
            except SQLAlchemyError as e:
                self.logger.warning(
                    "SQLite PRAGMA setup failed (WAL/busy timeout disabled; concurrent ingestion may face lock errors): %s",
                    e,
                )
        else:
            self.engine = create_engine(db_path, echo=False)

        # store honeypot artifacts here by default
        self.honeypot_data_dir = os.environ.get("HONEY_DATA_DIR", honeypot_data_dir)
        os.makedirs(self.honeypot_data_dir, exist_ok=True)
        os.makedirs(os.path.join(self.honeypot_data_dir, "artifacts"), exist_ok=True)

        # state file for honeypot watcher
        self._honeypot_state_path = os.path.join(self.honeypot_data_dir, "honeypot_state.json")
        self._honeypot_lock = threading.Lock()

        # Create tables - includes honeypot models
        try:
            Base.metadata.create_all(self.engine)
        except Exception as e:
            self.logger.error("DB Error during create_all: %s", e)
            raise

        self.Session = sessionmaker(bind=self.engine)
        # Keep a convenience session for synchronous work (web thread). Long-running threads will create their own sessions.
        self.db = self.Session()

        # GeoLite database (preferred) configuration
        self.geolite_path = os.path.abspath(os.environ.get("GEOLITE_MMDB_PATH", os.path.join(os.getcwd(), "data", "GeoLite2-City.mmdb")))
        self.geolite_url = os.environ.get("GEOLITE_MMDB_URL", "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb")
        self._geolite_reader = None
        if maxminddb:
            self._ensure_geolite_db()
        else:
            self.logger.info("maxminddb module not available; GeoLite lookups disabled.")

        # Automatic honeypot ingestion configuration
        honey_flag = os.environ.get("HONEY_AUTO_INGEST", honey_auto_ingest)
        if isinstance(honey_flag, bool):
            self.honey_auto_ingest = honey_flag
        else:
            self.honey_auto_ingest = str(honey_flag).lower() in ("1", "true", "yes", "on")
        self.honey_log_path = os.environ.get("HONEY_LOG_PATH", os.path.join(self.honeypot_data_dir, "log", "cowrie.json"))
        self.logger.info("Honeypot auto-ingest: %s, log path: %s", self.honey_auto_ingest, self.honey_log_path)
        try:
            self.honey_ingest_interval = int(os.environ.get("HONEY_INGEST_INTERVAL", "30"))
        except (TypeError, ValueError, OverflowError):
            self.honey_ingest_interval = 30

        if self.honey_auto_ingest and self.honey_log_path:
            # Start background watcher thread
            t = threading.Thread(target=self._honeypot_watcher, args=(self.honey_log_path, self.honey_ingest_interval), daemon=True, name="HoneypotWatcher")
            t.start()
            self.logger.info("Started honeypot watcher thread (name=%s).", t.name)

        # Automatic nginx access log ingestion configuration
        access_flag = os.environ.get("NGINX_AUTO_INGEST", nginx_auto_ingest)
        if isinstance(access_flag, bool):
            self.access_auto_ingest = access_flag
        else:
            self.access_auto_ingest = str(access_flag).lower() in ("1", "true", "yes", "on")
        default_access_path = os.path.join(os.getcwd(), "data", "access.json")
        self.access_log_path = os.path.abspath(os.environ.get("NGINX_LOG_PATH", default_access_path))
        try:
            self.access_ingest_interval = int(os.environ.get("NGINX_INGEST_INTERVAL", "30"))
        except (TypeError, ValueError, OverflowError):
            self.access_ingest_interval = 30
        self._nginx_state_path = os.path.abspath(os.environ.get("NGINX_STATE_PATH", os.path.join(os.path.dirname(self.access_log_path), ".nginx_access_state.json")))

        if self.access_auto_ingest and self.access_log_path:
            t = threading.Thread(target=self._nginx_access_watcher, args=(self.access_log_path, self.access_ingest_interval), daemon=True, name="NginxAccessWatcher")
            t.start()
            self.logger.info("Started nginx access watcher (name=%s) for %s", t.name, self.access_log_path)

        # Outgoing connection monitoring configuration
        outgoing_flag = os.environ.get("OUTGOING_MONITOR", outgoing_monitor)
        if isinstance(outgoing_flag, bool):
            self.outgoing_monitor = outgoing_flag
        else:
            self.outgoing_monitor = str(outgoing_flag).lower() in ("1", "true", "yes", "on")
        try:
            self.outgoing_monitor_interval = int(os.environ.get("OUTGOING_MONITOR_INTERVAL", "30"))
        except (TypeError, ValueError, OverflowError):
            self.outgoing_monitor_interval = 30
        self._outgoing_state_path = os.path.join(self.honeypot_data_dir, "outgoing_state.json")
        self._outgoing_lock = threading.Lock()

        if self.outgoing_monitor:
            if _HAS_PSUTIL:
                t = threading.Thread(target=self._outgoing_connection_watcher, args=(self.outgoing_monitor_interval,), daemon=True, name="OutgoingConnectionWatcher")
                t.start()
                self.logger.info("Started outgoing connection watcher thread (name=%s).", t.name)
            else:
                self.logger.warning("Outgoing connection monitoring requested but psutil not available. Install psutil to enable.")

        # Initialize vector store for similarity search
        self.vector_store = None
        if _HAS_VECTOR_STORE:
            try:
                vector_enabled = os.environ.get("VECTOR_STORE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
                if vector_enabled:
                    self.vector_store = VectorStore()
                    if self.vector_store.is_available():
                        self.logger.info("Vector store initialized successfully")
                    else:
                        self.logger.warning("Vector store initialized but not fully available (check Qdrant/embedding model)")
            except Exception as e:
                self.logger.warning("Failed to initialize vector store: %s", e)
                self.vector_store = None
        else:
            self.logger.info("Vector store module not available; similarity search disabled.")

        # Initialize LLM analyzer for threat analysis
        self.llm_analyzer = None
        if _HAS_LLM_ANALYZER:
            try:
                llm_enabled = os.environ.get("LLM_ENABLED", "true").lower() in ("1", "true", "yes", "on")
                if llm_enabled:
                    self.llm_analyzer = LLMAnalyzer()
                    if self.llm_analyzer.is_available():
                        self.logger.info("LLM analyzer initialized with model: %s", self.llm_analyzer.model)
                    else:
                        self.logger.warning("LLM analyzer initialized but not available (check Ollama installation)")
            except Exception as e:
                self.logger.warning("Failed to initialize LLM analyzer: %s", e)
                self.llm_analyzer = None
        else:
            self.logger.info("LLM analyzer module not available; threat analysis disabled.")

    def _ensure_aware(self, dt):
        if not dt:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _trace_ipv4_address(self, ip_addr: str, session, thread_name: str):
        """
        Trace a public IPv4 address by creating/enriching its NetworkNode entry with geolocation.
        This enables the address to be displayed on the map with proper markers.
        
        Args:
            ip_addr: IP address to trace
            session: SQLAlchemy session to use for database operations
            thread_name: Name of the calling thread (for logging)
        """
        if ip_addr and _is_public_ipv4(ip_addr):
            try:
                # Use get_node_from_db_or_web to fetch full geolocation data
                # This is needed for map display (latitude/longitude)
                self.get_node_from_db_or_web(ip_addr, session=session)
            except Exception as trace_err:
                self.logger.debug("[%s] Error tracing address %s: %s", thread_name, ip_addr, trace_err)

    # -------------------------
    # Honeypot watcher state helpers
    # -------------------------
    def _load_honeypot_state(self):
        try:
            if os.path.isfile(self._honeypot_state_path):
                with open(self._honeypot_state_path, "r", encoding="utf-8") as fh:
                    st = json.load(fh)
                    # ensure structure
                    return {"offset": int(st.get("offset", 0)), "processed_hashes": list(st.get("processed_hashes", []))}
        except Exception:
            pass
        return {"offset": 0, "processed_hashes": []}

    def _save_honeypot_state(self, state):
        try:
            with open(self._honeypot_state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
        except Exception:
            pass

    # -------------------------
    # GeoLite helpers
    # -------------------------
    def _ensure_geolite_db(self):
        if not maxminddb:
            return
        if self._geolite_reader:
            return
        path = self.geolite_path
        if not os.path.isfile(path):
            try:
                self._download_geolite_db(path)
            except (requests.RequestException, OSError, RuntimeError) as e:
                print(f"GeoLite download failed: {e}")
                return
        try:
            self._geolite_reader = maxminddb.open_database(path, mode=maxminddb.MODE_AUTO)
            print(f"Loaded GeoLite database from {path}")
        except (OSError, ValueError) as e:
            self._geolite_reader = None
            print(f"GeoLite open failed: {e}")

    def _download_geolite_db(self, path):
        url = self.geolite_url
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except OSError as e:
            print(f"Failed to create GeoLite directory: {e}")
            raise
        resp = requests.get(url, timeout=20, verify=True)
        if resp.status_code != 200:
            raise RuntimeError(f"GeoLite download HTTP {resp.status_code}")
        with open(path, "wb") as fh:
            fh.write(resp.content)

    def _geolite_lookup(self, ip):
        if not self._geolite_reader:
            return None
        try:
            data = self._geolite_reader.get(ip)
        except (ValueError, OSError, AttributeError) as e:
            print(f"GeoLite lookup failed for {ip}: {e}")
            return None
        if not data:
            return None

        country = None
        city = None
        lat = None
        lon = None
        isp = None
        asn_num = None
        try:
            country = data.get("country", {}).get("names", {}).get("en") or data.get("country", {}).get("iso_code")
            city = data.get("city", {}).get("names", {}).get("en")
            loc = data.get("location", {})
            lat = loc.get("latitude")
            lon = loc.get("longitude")
            traits = data.get("traits", {})
            isp = traits.get("isp") or traits.get("autonomous_system_organization")
            asn_num = traits.get("autonomous_system_number")
        except Exception:
            pass

        return {
            "country": country,
            "city": city,
            "isp": isp,
            "org": isp,
            "as": f"AS{asn_num} {isp}" if asn_num else None,
            "lat": lat,
            "lon": lon
        }

    # -------------------------
    # nginx access log watcher state helpers
    # -------------------------
    def _load_nginx_state(self):
        try:
            if os.path.isfile(self._nginx_state_path):
                with open(self._nginx_state_path, "r", encoding="utf-8") as fh:
                    st = json.load(fh)
                    return {"offset": int(st.get("offset", 0)), "processed_hashes": list(st.get("processed_hashes", []))}
        except Exception:
            pass
        return {"offset": 0, "processed_hashes": []}

    def _save_nginx_state(self, state):
        try:
            with open(self._nginx_state_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
        except Exception:
            pass

    # -------------------------
    # Public registry/company search (HTML-only, no paid APIs)
    # (unchanged)
    # -------------------------
    def search_company_registry(self, org_name):
        if not org_name:
            return None

        q = quote(org_name)
        headers = {"User-Agent": "IPMap/ForensicEngine (+https://example.local)"}

        # OpenCorporates
        try:
            oc_url = f"https://opencorporates.com/companies?q={q}"
            r = requests.get(oc_url, timeout=6, headers=headers)
            if r.status_code == 200 and r.text:
                html = r.text
                if _HAS_BS4:
                    soup = BeautifulSoup(html, "html.parser")
                    link = soup.find("a", href=re.compile(r"^/companies/[^/]+/\d+"))
                    if link:
                        href = link.get("href")
                        title = link.get_text(strip=True)
                        m = re.search(r"^/companies/([^/]+)/(\d+)", href)
                        jurisdiction, comp_no = (m.group(1), m.group(2)) if m else (None, None)
                        return {
                            "source": "opencorporates",
                            "name": title or org_name,
                            "matched_name": title or org_name,
                            "company_number": comp_no,
                            "jurisdiction_code": jurisdiction,
                            "company_url": "https://opencorporates.com" + href,
                            "additional": {}
                        }
                else:
                    m = re.search(r'href="(/companies/[^/]+/(\d+))".*?>([^<]+)<', html, re.IGNORECASE)
                    if m:
                        href = m.group(1)
                        comp_no = m.group(2)
                        title = m.group(3).strip()
                        jm = re.match(r"^/companies/([^/]+)/", href)
                        jurisdiction = jm.group(1) if jm else None
                        return {
                            "source": "opencorporates",
                            "name": title or org_name,
                            "matched_name": title or org_name,
                            "company_number": comp_no,
                            "jurisdiction_code": jurisdiction,
                            "company_url": "https://opencorporates.com" + href,
                            "additional": {}
                        }
        except Exception as e:
            print(f"OpenCorporates HTML search error for '{org_name}': {e}")

        # Companies House
        try:
            ch_url = f"https://find-and-update.company-information.service.gov.uk/search?q={q}"
            r = requests.get(ch_url, timeout=6, headers=headers)
            if r.status_code == 200 and r.text:
                html = r.text
                if _HAS_BS4:
                    soup = BeautifulSoup(html, "html.parser")
                    link = soup.find("a", href=re.compile(r"^/company/\d{8}"))
                    if link:
                        href = link.get("href")
                        title = link.get_text(strip=True)
                        m = re.search(r"^/company/(\d+)", href)
                        comp_no = m.group(1) if m else None
                        public_url = "https://find-and-update.company-information.service.gov.uk" + href
                        return {
                            "source": "companies_house",
                            "name": title or org_name,
                            "matched_name": title or org_name,
                            "company_number": comp_no,
                            "jurisdiction_code": "gb",
                            "company_url": public_url,
                            "additional": {}
                        }
                else:
                    m = re.search(r'href="(/company/(\d{8}))".*?>([^<]+)<', html, re.IGNORECASE)
                    if m:
                        href = m.group(1)
                        comp_no = m.group(2)
                        title = m.group(3).strip()
                        public_url = "https://find-and-update.company-information.service.gov.uk" + href
                        return {
                            "source": "companies_house",
                            "name": title or org_name,
                            "matched_name": title or org_name,
                            "company_number": comp_no,
                            "jurisdiction_code": "gb",
                            "company_url": public_url,
                            "additional": {}
                        }
        except Exception as e:
            print(f"Companies House public search error for '{org_name}': {e}")

        return None

    # -------------------------
    # Search helpers (DB)
    # -------------------------
    def search_organizations(self, query=None, fuzzy=False, limit=100):
        q = (query or "").strip()
        if not q:
            rows = self.db.query(Organization).limit(limit).all()
        else:
            if fuzzy:
                rows = self.db.query(Organization).filter(Organization.name.ilike(f"%{q}%")).limit(limit).all()
            else:
                norm = q.lower()
                rows = self.db.query(Organization).filter(
                    or_(Organization.name_normalized == norm, Organization.name == q)
                ).limit(limit).all()
        return [r.dict() for r in rows]

    def search_nodes(self, query=None, fuzzy=False, limit=100):
        q = (query or "").strip()
        if not q:
            rows = self.db.query(NetworkNode).limit(limit).all()
        else:
            if fuzzy:
                like = f"%{q}%"
                rows = self.db.query(NetworkNode).filter(
                    or_(
                        NetworkNode.ip.ilike(like),
                        NetworkNode.hostname.ilike(like),
                        NetworkNode.organization.ilike(like),
                        NetworkNode.city.ilike(like),
                        NetworkNode.country.ilike(like)
                    )
                ).limit(limit).all()
            else:
                rows = self.db.query(NetworkNode).filter(
                    or_(
                        NetworkNode.ip == q,
                        NetworkNode.hostname == q,
                        NetworkNode.organization == q
                    )
                ).limit(limit).all()
        return [r.dict() for r in rows]

    # -------------------------
    # Organization creation/refresh
    # -------------------------
    def get_or_create_organization(self, name, rdap=None, session=None):
        session = session or self.db
        if not name:
            return None
        norm = name.strip().lower()
        if not norm:
            return None

        org = session.query(Organization).filter_by(name_normalized=norm).first()
        if org:
            if rdap and (not org.rdap or org.rdap == {}):
                org.rdap = rdap
                try:
                    session.commit()
                except Exception:
                    session.rollback()
            # try to enrich if missing
            try:
                extra = org.extra_data or {}
                if 'company_search' not in extra:
                    registry = self.search_company_registry(name)
                    if registry:
                        extra['company_search'] = registry
                        org.extra_data = extra
                        try:
                            session.commit()
                        except Exception:
                            session.rollback()
            except Exception:
                try:
                    session.rollback()
                except Exception:
                    pass
            return org

        org = Organization(name=name.strip(), name_normalized=norm, rdap=rdap or {}, extra_data={})
        try:
            registry = self.search_company_registry(name)
            if registry:
                org.extra_data = org.extra_data or {}
                org.extra_data['company_search'] = registry
        except Exception:
            pass

        session.add(org)
        try:
            session.commit()
        except Exception:
            session.rollback()
            org = session.query(Organization).filter_by(name_normalized=norm).first()
        return org

    def get_or_create_isp(self, name, asn=None, session=None):
        """
        Get or create an ISP record by name.
        - name: ISP name
        - asn: Autonomous System Number (optional, e.g., "AS15169")
        """
        session = session or self.db
        if not name:
            return None
        norm = name.strip().lower()
        if not norm:
            return None

        isp = session.query(ISP).filter_by(name_normalized=norm).first()
        if isp:
            # Update ASN if provided and missing
            if asn and not isp.asn:
                isp.asn = asn
                try:
                    session.commit()
                except Exception:
                    session.rollback()
            return isp

        isp = ISP(name=name.strip(), name_normalized=norm, asn=asn, extra_data={})
        session.add(isp)
        try:
            session.commit()
        except Exception:
            session.rollback()
            isp = session.query(ISP).filter_by(name_normalized=norm).first()
        return isp

    def search_isps(self, query=None, fuzzy=False, limit=100):
        """Search ISP records by name or ASN."""
        q = (query or "").strip()
        if not q:
            rows = self.db.query(ISP).limit(limit).all()
        else:
            if fuzzy:
                rows = self.db.query(ISP).filter(
                    or_(ISP.name.ilike(f"%{q}%"), ISP.asn.ilike(f"%{q}%"))
                ).limit(limit).all()
            else:
                norm = q.lower()
                rows = self.db.query(ISP).filter(
                    or_(ISP.name_normalized == norm, ISP.name == q, ISP.asn == q)
                ).limit(limit).all()
        return [r.dict() for r in rows]

    def refresh_organization(self, identifier, force=True):
        if not identifier:
            return None

        org = None
        ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
        if ip_pattern.match(identifier):
            node = self.db.query(NetworkNode).filter_by(ip=identifier).first()
            if not node:
                print(f"No network node found for IP: {identifier}")
                return None
            if node.organization_id:
                org = self.db.query(Organization).filter_by(id=node.organization_id).first()
            elif node.organization:
                org = self.db.query(Organization).filter_by(name_normalized=(node.organization.strip().lower())).first()
            if not org:
                print(f"No organization record found for IP: {identifier}")
                return None
        else:
            try:
                oid = int(identifier)
                org = self.db.query(Organization).filter_by(id=oid).first()
            except Exception:
                norm = identifier.strip().lower()
                org = self.db.query(Organization).filter_by(name_normalized=norm).first()
                if not org:
                    org = Organization(name=identifier.strip(), name_normalized=norm, rdap={}, extra_data={})
                    self.db.add(org)
                    try:
                        self.db.commit()
                    except Exception:
                        self.db.rollback()
                        org = self.db.query(Organization).filter_by(name_normalized=norm).first()

        if not org:
            return None

        try:
            extra = org.extra_data or {}
            if ('company_search' in extra) and (not force):
                return org.dict()

            registry = self.search_company_registry(org.name)
            if registry:
                extra['company_search'] = registry
                org.extra_data = extra
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
                    return org.dict()
                return org.dict()
            else:
                return org.dict()
        except Exception as e:
            try:
                self.db.rollback()
            except Exception:
                pass
            print(f"Error during refresh_organization: {e}")
            return org.dict()

    # -------------------------
    # Node / IP enrichment and other existing methods
    # -------------------------
    def _recover_node_on_integrity_error(self, session, ip, seen_time=None):
        try:
            session.rollback()
        except SQLAlchemyError as e:
            logging.warning("Rollback failed during node recovery for %s: %s", ip, e)

        node = session.query(NetworkNode).filter_by(ip=ip).first()
        if node:
            if seen_time:
                node.last_seen = seen_time
                node.seen_count = (node.seen_count or 0) + 1
            return node

        if seen_time:
            try:
                node = NetworkNode(ip=ip, first_seen=seen_time, last_seen=seen_time, seen_count=1)
                session.add(node)
                session.flush()
            except IntegrityError as err:
                logging.warning("IntegrityError during recovery for NetworkNode %s", ip)
                try:
                    session.rollback()
                except SQLAlchemyError as e:
                    logging.warning("Rollback failed during recovery IntegrityError for %s: %s", ip, e)
                node = session.query(NetworkNode).filter_by(ip=ip).first()
                if not node:
                    raise err

        return node

    def get_node_from_db_or_web(self, ip, session=None):
        session = session or self.db
        if not ip:
            return None

        now = datetime.now(timezone.utc)
        node = session.query(NetworkNode).filter_by(ip=ip).first()

        needs_refresh = False
        if not node:
            needs_refresh = True
        else:
            last_seen_aware = self._ensure_aware(node.last_seen)
            if not last_seen_aware:
                needs_refresh = True
            else:
                if last_seen_aware < datetime.now(timezone.utc) - timedelta(days=7):
                    needs_refresh = True

        if needs_refresh:
            intel = self.get_passive_intel(ip)

            if not node:
                node = NetworkNode(ip=ip)
                node.first_seen = now
                node.seen_count = 0
                session.add(node)
                try:
                    session.flush()
                except IntegrityError:
                    self.logger.warning("IntegrityError creating NetworkNode %s; attempting recovery", ip)
                    node = self._recover_node_on_integrity_error(session, ip, seen_time=now)
                    if not node:
                        return None

            # Handle Organization (separate from ISP)
            org_name = intel.get('organization') or (intel.get('rdap') or {}).get('org_full_name')
            if org_name:
                org = self.get_or_create_organization(org_name, rdap=intel.get('rdap'), session=session)
                if org:
                    node.organization_id = org.id
                    node.organization = org.name

            # Handle ISP (separate table)
            isp_name = (intel.get('geo') or {}).get('isp')
            asn = (intel.get('geo') or {}).get('as')
            if isp_name:
                isp = self.get_or_create_isp(isp_name, asn=asn, session=session)
                if isp:
                    node.isp_id = isp.id
                    node.isp = isp.name

            node.hostname = intel.get('hostname') or node.hostname
            node.asn = asn or node.asn
            node.country = (intel.get('geo') or {}).get('country') or node.country
            node.city = (intel.get('geo') or {}).get('city') or node.city
            node.latitude = (intel.get('geo') or {}).get('lat') or node.latitude
            node.longitude = (intel.get('geo') or {}).get('lon') or node.longitude
            node.is_tor_exit = self.check_tor(ip)
            node.extra_data = intel.get('rdap') or node.extra_data or {}
            node.last_seen = now
            node.seen_count = (node.seen_count or 0) + 1

            session.commit()
        else:
            node.last_seen = now
            node.seen_count = (node.seen_count or 0) + 1
            session.commit()

        return node

    def ensure_node_minimal(self, ip, seen_time=None, session=None):
        session = session or self.db
        if not ip:
            return None
        node = session.query(NetworkNode).filter_by(ip=ip).first()
        now = seen_time or datetime.now(timezone.utc)
        if not node:
            node = NetworkNode(ip=ip, first_seen=now, last_seen=now, seen_count=1)
            session.add(node)
            try:
                session.flush()
            except IntegrityError:
                logging.warning("IntegrityError creating minimal NetworkNode %s; attempting recovery", ip)
                node = self._recover_node_on_integrity_error(session, ip, seen_time=now)
                if not node:
                    return None
        else:
            node.last_seen = now
            node.seen_count = (node.seen_count or 0) + 1
            session.flush()
        return node

    def get_passive_intel(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown-Node"

        rdap_data = self.get_org_rdap(ip)

        try:
            w = whois.whois(ip)
            org = getattr(w, "org", None) or getattr(w, "asn", None) or "Private/Internal"
        except Exception:
            org = rdap_data.get("org_full_name", "Unknown")

        geo = self.lookup(ip)

        return {
            "ip": ip,
            "hostname": hostname,
            "organization": org,
            "geo": geo,
            "rdap": rdap_data
        }

    def get_org_rdap(self, ip):
        try:
            res = requests.get(f"https://rdap.db.ripe.net/ip/{ip}", timeout=3)
            if res.status_code == 200:
                data = res.json()
                net_name = data.get('name', 'Unknown')

                details = {
                    "provider": net_name,
                    "org_full_name": "Unknown",
                    "abuse_email": None,
                    "registration_date": None
                }

                events = data.get('events', [])
                for event in events:
                    if event.get('eventAction') == 'registration':
                        details['registration_date'] = event.get('eventDate')

                entities = data.get('entities', [])
                for entity in entities:
                    vcard = entity.get('vcardArray', [None, []])[1] if entity.get('vcardArray') else []
                    roles = entity.get('roles', [])

                    if 'registrant' in roles or 'registrant' in [r.lower() for r in roles]:
                        for entry in vcard:
                            if entry and entry[0] == 'fn':
                                details['org_full_name'] = entry[-1] if len(entry) >= 4 else entry[-1]

                    sub_entities = entity.get('entities', [])
                    for sub in sub_entities:
                        if 'abuse' in sub.get('roles', []):
                            sub_vcard = sub.get('vcardArray', [None, []])[1] if sub.get('vcardArray') else []
                            for entry in sub_vcard:
                                if entry and entry[0] == 'email':
                                    details['abuse_email'] = entry[-1]

                return details
        except Exception as e:
            print(f"RDAP Error: {e}")

        return {"provider": "Unknown", "org_full_name": "Unknown", "abuse_email": None, "registration_date": None}

    def lookup(self, ip):
        try:
            geo = self._geolite_lookup(ip)
            if geo:
                return geo
        except (ValueError, OSError, AttributeError) as e:
            print(f"GeoLite lookup error for {ip}: {e}")
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            if res.get("status") == "success":
                return {
                    "country": res.get("country"),
                    "city": res.get("city"),
                    "isp": res.get("isp"),
                    "org": res.get("org"),
                    "as": res.get("as"),
                    "lat": res.get("lat"),
                    "lon": res.get("lon")
                }
        except Exception:
            pass
        return {"country": "Unknown", "city": "Unknown", "isp": None, "org": None, "as": None, "lat": None, "lon": None}

    def check_tor(self, ip):
        try:
            tor_list_url = "https://check.torproject.org/exit-addresses"
            response = requests.get(tor_list_url, timeout=5)
            return ip in response.text
        except Exception:
            return False

    def get_service_banners(self, ip, ports):
        banners = {}
        for port in ports:
            banner = self.get_service_banner(ip, port)
            if banner:
                banners[port] = banner
        return banners

    def get_service_banner(self, ip, port):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, int(port)))
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner
        except Exception:
            return None
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    def get_accesses_for_ip(self, ip, limit=100):
        """
        Return recent web access records for a given IP address.

        Returns a list of WebAccess.dict() objects ordered by timestamp desc.
        """
        if not ip:
            return []

        try:
            rows = (
                self.db.query(WebAccess)
                .filter(WebAccess.remote_addr == ip)
                .order_by(WebAccess.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [r.dict() for r in rows]
        except Exception as e:
            # Don't raise here; return an empty list to the API which can surface the error if needed.
            try:
                self.db.rollback()
            except Exception:
                pass
            print(f"Error fetching accesses for {ip}: {e}")
            return []

    def _ingest_nginx_access_event(self, ev: dict, session=None, enrich=True):
        if session is None:
            session = self.db

        ts = datetime.now(timezone.utc)
        raw_ts = ev.get("time_local") or ev.get("timestamp") or ev.get("time")
        if raw_ts:
            for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
                try:
                    ts = datetime.strptime(raw_ts, fmt)
                    ts = self._ensure_aware(ts)
                    break
                except Exception:
                    continue

        req = ev.get("request")
        method = ev.get("method")
        path = ev.get("path")
        if req:
            parts = req.split()
            if not method and len(parts) >= 1:
                method = parts[0]
            if not path and len(parts) >= 2:
                path = parts[1]

        def _to_int(val):
            try:
                return int(val)
            except Exception:
                return None

        def _to_float(val):
            try:
                return float(val)
            except Exception:
                return None

        wa = WebAccess(
            timestamp=ts or datetime.now(timezone.utc),
            remote_addr=ev.get("remote_addr"),
            remote_port=_to_int(ev.get("remote_port")),
            remote_user=ev.get("remote_user"),
            request=req,
            method=method,
            path=path,
            status=_to_int(ev.get("status")),
            body_bytes_sent=_to_int(ev.get("body_bytes_sent")),
            http_referer=ev.get("http_referer"),
            http_user_agent=ev.get("http_user_agent"),
            http_x_forwarded_for=ev.get("http_x_forwarded_for"),
            server_name=ev.get("server_name"),
            upstream_addr=ev.get("upstream_addr"),
            ssl_protocol=ev.get("ssl_protocol"),
            ssl_cipher=ev.get("ssl_cipher"),
            request_time=_to_float(ev.get("request_time")),
            raw=ev
        )

        if wa.remote_addr:
            try:
                node = self.get_node_from_db_or_web(wa.remote_addr, session=session) if enrich else self.ensure_node_minimal(wa.remote_addr, seen_time=ts, session=session)
                if node:
                    wa.node = node
            except Exception as e:
                logging.warning("Error resolving node for %s: %s", wa.remote_addr, e)
                try:
                    session.rollback()
                except SQLAlchemyError as rb_err:
                    logging.warning("Rollback failed after node resolution error for %s: %s", wa.remote_addr, rb_err)

        session.add(wa)
        session.flush()
        return wa

    # -------------------------
    # Honeypot ingestion helpers (used by manual ingestion endpoint)
    # -------------------------
    def ingest_cowrie_file(self, filepath, enrich=True, batch_size=200):
        """
        Ingest a Cowrie JSON log file (line-delimited JSON). Creates/updates HoneypotSession,
        HoneypotCommand, HoneypotFile entries. When enrich=True, will call get_node_from_db_or_web
        for the source IPs to attach passive intel.
        NOTE: this always reads the entire file and is intended for manual / one-shot ingestion.
        For periodic tail-ing use the built-in watcher (HONEY_AUTO_INGEST + HONEY_LOG_PATH).
        """
        processed = 0
        errors = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    processed += 1
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        errors += 1
                        continue

                    try:
                        # Reuse ingest_event to keep behaviour consistent
                        self._ingest_event(ev, session=self.db, enrich=enrich)
                    except Exception:
                        errors += 1
                        try:
                            self.db.rollback()
                        except Exception:
                            pass

                    if processed % batch_size == 0:
                        try:
                            self.db.commit()
                        except Exception:
                            self.db.rollback()
                # final commit
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
        except FileNotFoundError:
            return {"lines_processed": 0, "errors": 1, "message": f"File not found: {filepath}"}
        except Exception as e:
            return {"lines_processed": processed, "errors": errors + 1, "message": str(e)}

        return {"lines_processed": processed, "errors": errors}

    def ingest_nginx_access_file(self, filepath, enrich=True, batch_size=500):
        """
        Ingest a JSON-line formatted nginx access log. Each line should be a JSON object with keys
        matching the WebAccess columns. Enrichment is optional and uses get_node_from_db_or_web.
        """
        processed = 0
        errors = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    processed += 1
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        errors += 1
                        continue
                    try:
                        self._ingest_nginx_access_event(ev, session=self.db, enrich=enrich)
                    except Exception:
                        errors += 1
                        try:
                            self.db.rollback()
                        except Exception:
                            pass

                    if processed % batch_size == 0:
                        try:
                            self.db.commit()
                        except Exception:
                            self.db.rollback()
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
        except FileNotFoundError:
            return {"lines_processed": 0, "errors": 1, "message": f"File not found: {filepath}"}
        except Exception as e:
            return {"lines_processed": processed, "errors": errors + 1, "message": str(e)}

        return {"lines_processed": processed, "errors": errors}

    def _ingest_event(self, ev: dict, session=None, enrich=True):
        """
        Insert a single cowrie event dict into the DB using the provided SQLAlchemy session.
        This function assumes 'session' is a (new/independent) SQLAlchemy session object when used by the watcher.
        If session is None, uses self.db.
        """
        if session is None:
            session = self.db

        # identify session and src IP
        sess_key = ev.get("session") or ev.get("sessionid") or ev.get("cowrie_session")
        src_ip = ev.get("src_ip") or ev.get("src_addr") or ev.get("src")
        src_port = ev.get("src_port") or ev.get("src_port", None)
        username = ev.get("username") or ev.get("user") or None

        # find or create session (try cowrie_session first)
        hp_session = None
        if sess_key:
            hp_session = session.query(HoneypotSession).filter_by(cowrie_session=sess_key).first()
        if not hp_session and src_ip:
            hp_session = session.query(HoneypotSession).filter_by(src_ip=src_ip).order_by(HoneypotSession.start_ts.desc()).first()
        if not hp_session:
            hp_session = HoneypotSession(cowrie_session=sess_key, src_ip=src_ip or "UNKNOWN", src_port=src_port, username=username, raw_events=[])
            session.add(hp_session)
            session.flush()

        # append raw event (we avoid duplicates before calling this function at watcher level)
        raw = hp_session.raw_events or []
        raw.append(ev)
        hp_session.raw_events = raw

        # handle commands
        cmd = ev.get("input") or ev.get("command") or ev.get("cmd")
        if cmd:
            hc = HoneypotCommand(session_id=hp_session.id, command=cmd, raw=ev)
            session.add(hc)

        # handle file/download events
        filename = ev.get("outfile") or ev.get("filename") or None
        url = ev.get("url") or ev.get("download_url") or None
        file_b64 = ev.get("file_data_b64") or ev.get("file_contents_b64") or None
        direction = "download" if url or ev.get("direction") == "download" else ev.get("direction") or ("download" if filename else "unknown")
        saved_path = None
        sha256 = None
        size = None

        if file_b64:
            try:
                import base64
                b = base64.b64decode(file_b64)
                sha256 = _sha256_bytes(b)
                size = len(b)
                safe_name = f"{sha256}_{(filename or 'file')}"
                saved_path = os.path.join(self.honeypot_data_dir, "artifacts", safe_name)
                with open(saved_path, "wb") as fh:
                    fh.write(b)
            except Exception:
                pass

        if filename or url or file_b64:
            hf = HoneypotFile(session_id=hp_session.id, filename=filename or url or "unknown", direction=direction, size=size, sha256=sha256, saved_path=saved_path, raw=ev)
            session.add(hf)

        # session lifecycle events
        evtype = ev.get("event") or ev.get("message") or ev.get("type") or ""
        if evtype and "session.closed" in evtype:
            hp_session.end_ts = datetime.now(timezone.utc)
        if evtype and "login.success" in evtype:
            hp_session.auth_success = "success"
            hp_session.username = ev.get("username") or hp_session.username
        if evtype and "login.failed" in evtype:
            hp_session.auth_success = "failed"

        # enrichment (optional)
        if enrich and hp_session.src_ip:
            try:
                # Only trace public IPv4 addresses for map display
                # Internal/private IPs and IPv6 addresses don't need geolocation
                if _is_public_ipv4(hp_session.src_ip):
                    node = self.get_node_from_db_or_web(hp_session.src_ip, session=session)
                    hp_session.extra = hp_session.extra or {}
                    if node:
                        hp_session.extra["node_cached"] = {"ip": node.ip, "organization": node.organization, "asn": node.asn, "country": node.country}
            except Exception:
                pass

    # -------------------------
    # Watcher thread: tail a Cowrie log file and process only new unique events
    # -------------------------
    def _honeypot_watcher(self, filepath, interval=30):
        """
        Tail `filepath`, reading new lines periodically. Deduplicates lines by SHA-256 of the raw JSON string.
        State is stored in honeypot_state.json in honeypot_data_dir and contains:
          - offset: last read byte offset
          - processed_hashes: list of recently processed event hashes (bounded)
        The watcher's DB work uses a fresh SQLAlchemy session per run to avoid cross-thread session issues.
        """
        thread_name = threading.current_thread().name
        self.logger.info("[%s] Starting honeypot watcher for file: %s (interval=%ds)", thread_name, filepath, interval)
        
        try:
            state = self._load_honeypot_state()
            offset = int(state.get("offset", 0))
            processed_hashes = list(state.get("processed_hashes", []))
            processed_set = set(processed_hashes)
            MAX_HASH_HISTORY = 10000
            self.logger.info("[%s] Loaded state: offset=%d, processed_hashes=%d", thread_name, offset, len(processed_hashes))
        except Exception as e:
            self.logger.warning("[%s] Failed to load state, starting fresh: %s", thread_name, e)
            offset = 0
            processed_set = set()
            processed_hashes = []
            MAX_HASH_HISTORY = 10000

        events_processed = 0
        while True:
            try:
                if not os.path.isfile(filepath):
                    # file missing: reset offset and sleep
                    if offset > 0:
                        self.logger.info("[%s] File not found, resetting offset: %s", thread_name, filepath)
                    offset = 0
                    time.sleep(interval)
                    continue

                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    new_lines = fh.readlines()
                    new_count = 0
                    for line in new_lines:
                        line = line.strip()
                        offset = fh.tell()
                        if not line:
                            continue
                        # dedupe by raw line content
                        h = _sha256_text(line)
                        if h in processed_set:
                            continue
                        # parse event
                        try:
                            ev = json.loads(line)
                        except Exception:
                            # can't parse; mark as processed to avoid reattempt
                            processed_set.add(h)
                            processed_hashes.append(h)
                            if len(processed_hashes) > MAX_HASH_HISTORY:
                                processed_hashes = processed_hashes[-MAX_HASH_HISTORY:]
                                processed_set = set(processed_hashes)
                            continue

                        # process event using a fresh session
                        db_sess = self.Session()
                        try:
                            self._ingest_event(ev, session=db_sess, enrich=True)
                            db_sess.commit()
                            new_count += 1
                            events_processed += 1
                            # Log individual incoming connection details
                            src_ip = ev.get("src_ip") or ev.get("src_addr") or ev.get("src") or "unknown"
                            src_port = ev.get("src_port") or "N/A"
                            event_type = ev.get("event") or ev.get("message") or ev.get("type") or "unknown"
                            session_id = ev.get("session") or ev.get("sessionid") or ev.get("cowrie_session") or "N/A"
                            self.logger.info(
                                "[%s] New incoming connection: src=%s:%s, event=%s, session=%s",
                                thread_name, src_ip, src_port, event_type, session_id
                            )
                        except Exception as e:
                            try:
                                db_sess.rollback()
                            except Exception:
                                pass
                            self.logger.error("[%s] DB error processing event: %s\n%s", thread_name, e, traceback.format_exc())
                        finally:
                            db_sess.close()

                        # mark processed
                        processed_set.add(h)
                        processed_hashes.append(h)
                        if len(processed_hashes) > MAX_HASH_HISTORY:
                            processed_hashes = processed_hashes[-MAX_HASH_HISTORY:]
                            processed_set = set(processed_hashes)

                    if new_count > 0:
                        self.logger.info("[%s] Processed %d new honeypot events (total: %d)", thread_name, new_count, events_processed)

                # persist state
                state = {"offset": offset, "processed_hashes": processed_hashes}
                self._save_honeypot_state(state)
            except Exception as e:
                # Log and continue
                self.logger.error("[%s] Watcher error: %s\n%s", thread_name, e, traceback.format_exc())
            # sleep then loop
            time.sleep(interval)

    def _nginx_access_watcher(self, filepath, interval=30):
        """
        Tail an nginx access log (JSON lines) and insert new WebAccess rows.
        Deduplicates by raw line hash and persists offset in a small state file.
        """
        thread_name = threading.current_thread().name
        self.logger.info("[%s] Starting nginx access watcher for file: %s (interval=%ds)", thread_name, filepath, interval)
        
        try:
            state = self._load_nginx_state()
            offset = int(state.get("offset", 0))
            processed_hashes = list(state.get("processed_hashes", []))
            processed_set = set(processed_hashes)
            MAX_HASH_HISTORY = 10000
            self.logger.info("[%s] Loaded state: offset=%d, processed_hashes=%d", thread_name, offset, len(processed_hashes))
        except Exception as e:
            self.logger.warning("[%s] Failed to load state, starting fresh: %s", thread_name, e)
            offset = 0
            processed_set = set()
            processed_hashes = []
            MAX_HASH_HISTORY = 10000

        events_processed = 0
        while True:
            try:
                if not os.path.isfile(filepath):
                    if offset > 0:
                        self.logger.info("[%s] File not found, resetting offset: %s", thread_name, filepath)
                    offset = 0
                    time.sleep(interval)
                    continue

                with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    new_count = 0
                    while True:
                        line = fh.readline()
                        if not line:
                            break
                        line = line.strip()
                        offset = fh.tell()
                        if not line:
                            continue
                        h = _sha256_text(line)
                        if h in processed_set:
                            continue
                        try:
                            ev = json.loads(line)
                        except Exception:
                            processed_set.add(h)
                            processed_hashes.append(h)
                            if len(processed_hashes) > MAX_HASH_HISTORY:
                                processed_hashes = processed_hashes[-MAX_HASH_HISTORY:]
                                processed_set = set(processed_hashes)
                            continue

                        db_sess = self.Session()
                        try:
                            self._ingest_nginx_access_event(ev, session=db_sess, enrich=True)
                            db_sess.commit()
                            new_count += 1
                            events_processed += 1
                        except Exception as e:
                            try:
                                db_sess.rollback()
                            except Exception:
                                pass
                            self.logger.error("[%s] DB error processing event: %s\n%s", thread_name, e, traceback.format_exc())
                        finally:
                            db_sess.close()

                        processed_set.add(h)
                        processed_hashes.append(h)
                        if len(processed_hashes) > MAX_HASH_HISTORY:
                            processed_hashes = processed_hashes[-MAX_HASH_HISTORY:]
                            processed_set = set(processed_hashes)

                    if new_count > 0:
                        self.logger.info("[%s] Processed %d new nginx access events (total: %d)", thread_name, new_count, events_processed)

                state = {"offset": offset, "processed_hashes": processed_hashes}
                self._save_nginx_state(state)
            except Exception as e:
                self.logger.error("[%s] Watcher error: %s\n%s", thread_name, e, traceback.format_exc())
            time.sleep(interval)

    # -------------------------
    # Outgoing connection watcher state helpers
    # -------------------------
    def _load_outgoing_state(self):
        """Load state for outgoing connection tracking."""
        try:
            if os.path.isfile(self._outgoing_state_path):
                with open(self._outgoing_state_path, "r", encoding="utf-8") as fh:
                    st = json.load(fh)
                    return {"seen_connections": set(tuple(x) for x in st.get("seen_connections", []))}
        except Exception:
            pass
        return {"seen_connections": set()}

    def _save_outgoing_state(self, state):
        """Save state for outgoing connection tracking."""
        try:
            # Convert set of tuples to list of lists for JSON serialization
            # Note: we take a random sample since set ordering is undefined
            import random
            seen_list = [list(x) for x in state.get("seen_connections", set())]
            if len(seen_list) > 10000:
                random.shuffle(seen_list)
                seen_list = seen_list[:10000]
            data = {"seen_connections": seen_list}
            with open(self._outgoing_state_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except Exception:
            pass

    def _outgoing_connection_watcher(self, interval=30):
        """
        Monitor outgoing network connections using psutil.
        Records new outgoing connections in the OutgoingConnection table.
        """
        thread_name = threading.current_thread().name
        self.logger.info("[%s] Starting outgoing connection watcher (interval=%ds)", thread_name, interval)
        
        if not _HAS_PSUTIL:
            self.logger.error("[%s] psutil not available, cannot monitor outgoing connections", thread_name)
            return
        
        try:
            state = self._load_outgoing_state()
            seen_connections = state.get("seen_connections", set())
            self.logger.info("[%s] Loaded state: seen_connections=%d", thread_name, len(seen_connections))
        except Exception as e:
            self.logger.warning("[%s] Failed to load state, starting fresh: %s", thread_name, e)
            seen_connections = set()

        connections_logged = 0
        while True:
            try:
                new_count = 0
                now = datetime.now(timezone.utc)
                
                # Get all network connections
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        # Skip listening sockets and sockets without remote address
                        if conn.status == 'LISTEN' or not conn.raddr:
                            continue
                        
                        # Create a unique identifier for this connection
                        local_addr = conn.laddr.ip if conn.laddr else None
                        local_port = conn.laddr.port if conn.laddr else None
                        remote_addr = conn.raddr.ip if conn.raddr else None
                        remote_port = conn.raddr.port if conn.raddr else None
                        
                        # Determine connection type consistently
                        conn_type_str = conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                        conn_key = (local_addr, local_port, remote_addr, remote_port, conn_type_str)
                        
                        # Skip if we've already seen this connection
                        if conn_key in seen_connections:
                            continue
                        
                        # Determine if this is outgoing or internal
                        # Using RFC 1918 private IP ranges
                        direction = "outgoing"
                        if remote_addr:
                            # Check for RFC 1918 private addresses
                            if remote_addr.startswith('10.') or remote_addr.startswith('192.168.'):
                                direction = "internal"
                            # 172.16.0.0/12 = 172.16.0.0 - 172.31.255.255
                            elif remote_addr.startswith('172.'):
                                try:
                                    second_octet = int(remote_addr.split('.')[1])
                                    if 16 <= second_octet <= 31:
                                        direction = "internal"
                                except (ValueError, IndexError):
                                    pass
                            # Also check for localhost
                            elif remote_addr.startswith('127.') or remote_addr == '::1':
                                direction = "internal"
                        
                        # Get process info if available
                        pid = conn.pid
                        process_name = None
                        if pid:
                            try:
                                proc = psutil.Process(pid)
                                process_name = proc.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                        
                        # Get protocol type using consistent logic
                        proto = "tcp" if conn_type_str == 'SOCK_STREAM' else "udp" if conn_type_str == 'SOCK_DGRAM' else conn_type_str
                        
                        # Store the connection
                        db_sess = self.Session()
                        try:
                            # Trace public IPv4 addresses to create NetworkNode entries with geolocation
                            # This allows the map to show markers for these connections
                            self._trace_ipv4_address(remote_addr, db_sess, thread_name)
                            self._trace_ipv4_address(local_addr, db_sess, thread_name)
                            
                            outgoing_conn = OutgoingConnection(
                                timestamp=now,
                                local_addr=local_addr,
                                local_port=local_port,
                                remote_addr=remote_addr,
                                remote_port=remote_port,
                                proto=proto,
                                status=conn.status,
                                pid=pid,
                                process_name=process_name,
                                direction=direction,
                                extra_data={}
                            )
                            db_sess.add(outgoing_conn)
                            db_sess.commit()
                            new_count += 1
                            connections_logged += 1
                            # Log individual connection details
                            self.logger.info(
                                "[%s] New %s connection: %s:%s -> %s:%s (%s) [pid=%s, process=%s]",
                                thread_name, direction, local_addr, local_port,
                                remote_addr, remote_port, proto,
                                pid or 'N/A', process_name or 'N/A'
                            )
                        except Exception as e:
                            try:
                                db_sess.rollback()
                            except Exception:
                                pass
                            self.logger.error("[%s] DB error storing outgoing connection: %s", thread_name, e)
                        finally:
                            db_sess.close()
                        
                        # Mark as seen
                        seen_connections.add(conn_key)
                        
                        # Limit the size of seen_connections using random eviction
                        # (since we're storing in a set, order is not guaranteed)
                        if len(seen_connections) > 50000:
                            # Keep approximately 10000 random entries
                            import random
                            seen_list = list(seen_connections)
                            random.shuffle(seen_list)
                            seen_connections = set(seen_list[:10000])
                    
                    except Exception as conn_err:
                        self.logger.debug("[%s] Error processing connection: %s", thread_name, conn_err)
                        continue
                
                if new_count > 0:
                    self.logger.info("[%s] Logged %d new outgoing connections (total: %d)", thread_name, new_count, connections_logged)
                
                # Save state
                self._save_outgoing_state({"seen_connections": seen_connections})
                
            except Exception as e:
                self.logger.error("[%s] Watcher error: %s\n%s", thread_name, e, traceback.format_exc())
            
            time.sleep(interval)

    def get_outgoing_connections(self, limit=100, direction=None):
        """Get recent outgoing connections, optionally filtered by direction."""
        query = self.db.query(OutgoingConnection).order_by(OutgoingConnection.timestamp.desc())
        if direction:
            query = query.filter(OutgoingConnection.direction == direction)
        rows = query.limit(limit).all()
        return [r.dict() for r in rows]

    def ingest_pcap(self, pcap_path, filter_host=None):
        """
        Lightweight PCAP ingest using scapy.rdpcap. Aggregates packets into simple flows
        keyed by (src,dst,proto,srcport,dstport) and stores HoneypotNetworkFlow rows.
        filter_host: if provided, only aggregate flows where src==filter_host or dst==filter_host.
        """
        try:
            from scapy.all import rdpcap, IP, IPv6, TCP, UDP
        except Exception as e:
            return {"error": f"scapy not available: {e}"}

        try:
            pkts = rdpcap(pcap_path)
        except Exception as e:
            return {"error": f"Could not read pcap: {e}"}

        flows = {}
        for pkt in pkts:
            try:
                ip_layer = None
                if IP in pkt:
                    ip_layer = pkt[IP]
                    proto = "ip"
                elif IPv6 in pkt:
                    ip_layer = pkt[IPv6]
                    proto = "ipv6"
                else:
                    continue

                src = ip_layer.src
                dst = ip_layer.dst

                sport = None; dport = None; l4proto = None
                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    l4proto = "tcp"
                elif UDP in pkt:
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    l4proto = "udp"
                else:
                    l4proto = proto

                if filter_host and not (filter_host == src or filter_host == dst):
                    continue

                key = (src, dst, l4proto, sport, dport)
                entry = flows.setdefault(key, {"bytes": 0, "pkts": 0, "first_ts": None, "last_ts": None})
                pkt_len = len(pkt)
                entry["bytes"] += pkt_len
                entry["pkts"] += 1
                ts = getattr(pkt, "time", None)
                if ts:
                    if entry["first_ts"] is None:
                        entry["first_ts"] = datetime.fromtimestamp(ts, tz=timezone.utc)
                    entry["last_ts"] = datetime.fromtimestamp(ts, tz=timezone.utc)
            except Exception:
                continue

        # persist flows
        for (src, dst, proto, sport, dport), meta in flows.items():
            nf = HoneypotNetworkFlow(
                src_ip=src,
                dst_ip=dst,
                src_port=int(sport) if sport else None,
                dst_port=int(dport) if dport else None,
                proto=proto,
                bytes=meta["bytes"],
                packets=meta["pkts"],
                start_ts=meta["first_ts"],
                end_ts=meta["last_ts"]
            )
            self.db.add(nf)
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()

        return {"flows": len(flows)}

    def get_honeypot_sessions(self, limit=100):
        rows = self.db.query(HoneypotSession).order_by(HoneypotSession.start_ts.desc()).limit(limit).all()
        return [r.dict() for r in rows]

    def get_honeypot_session(self, session_id):
        s = self.db.query(HoneypotSession).filter_by(id=session_id).first()
        if not s:
            return None
        data = s.dict()
        data["commands"] = [c.dict() for c in s.commands]
        data["files"] = [f.dict() for f in s.files]
        return data

    # -------------------------
    # Existing traceroute & analysis (extended with fingerprints)
    # -------------------------
    def run_analysis(self, target_ip, deep_mode=False, maxttl=30):
        print(f"[*] Analysis started for {target_ip} (Mode: {'Deep' if deep_mode else 'Plain'})")

        target_node = self.get_node_from_db_or_web(target_ip)

        new_session = AnalysisSession(
            target_ip=target_ip,
            mode='Deep' if deep_mode else 'Plain',
            timestamp=datetime.now(timezone.utc)
        )

        self.db.add(new_session)
        self.db.flush()  # get session id

        ans, unans = traceroute(target_ip, maxttl=maxttl, verbose=False)

        hop_probes = {}
        for snd, rcv in ans:
            hop_num = None
            try:
                hop_num = getattr(snd, "ttl", None)
                if hop_num is None:
                    hop_num = getattr(getattr(snd, "payload", None), "ttl", None)
                if hop_num is None and hasattr(snd, "fields"):
                    hop_num = snd.fields.get("ttl")
            except Exception:
                hop_num = None

            if hop_num is None:
                hop_num = getattr(rcv, "ttl", None)

            if hop_num is None:
                continue

            hop_probes.setdefault(int(hop_num), []).append((snd, rcv))

        results = {"session_id": new_session.id, "target_ip": target_ip, "path": []}
        reached_target = False

        for ttl in range(1, maxttl + 1):
            probes = hop_probes.get(ttl, [])
            if not probes:
                hop = PathHop(
                    session=new_session,
                    ip=None,
                    hop_number=ttl,
                    probe_index=1,
                    rtt=None,
                    timestamp=datetime.now(timezone.utc),
                    node=None
                )
                self.db.add(hop)
                self.db.flush()
                results["path"].append({
                    "hop_number": ttl,
                    "probe_index": 1,
                    "ip": None,
                    "rtt": None,
                    "organization": None,
                    "country": None
                })
                continue

            for probe_idx, (snd, rcv) in enumerate(probes, start=1):
                hop_ip = getattr(rcv, "src", None)
                try:
                    rtt = None
                    if hasattr(rcv, "time") and hasattr(snd, "time"):
                        rtt = float(rcv.time - snd.time)
                except Exception:
                    rtt = None

                node = None
                org = None
                country = None
                if hop_ip:
                    node = self.get_node_from_db_or_web(hop_ip)
                    org = node.organization or (node.organization_obj.name if node.organization_obj else None)
                    country = node.country

                hop = PathHop(
                    session=new_session,
                    ip=hop_ip,
                    hop_number=ttl,
                    probe_index=probe_idx,
                    rtt=rtt,
                    timestamp=datetime.now(timezone.utc),
                    node=node
                )
                self.db.add(hop)
                self.db.flush()

                results["path"].append({
                    "hop_number": ttl,
                    "probe_index": probe_idx,
                    "ip": hop_ip,
                    "rtt": rtt,
                    "organization": org,
                    "country": country
                })

                if hop_ip == target_ip:
                    reached_target = True
                    break

            if reached_target:
                break

        self.db.commit()

        if deep_mode:
            try:
                # existing fast nmap scan
                self.nm.scan(target_ip, arguments='-F')
                if target_ip in self.nm.all_hosts():
                    result = self.nm[target_ip]
                    open_ports = list(result.get('tcp', {}).keys())
                    if not target_node.extra_data:
                        target_node.extra_data = {}

                    # keep existing banner logic
                    target_node.extra_data['banners'] = self.get_service_banners(target_ip, open_ports)
                    self.db.commit()
            except Exception as e:
                print(f"Deep scan error: {e}")

            # Conservative fingerprinting step (safe-by-default)
            try:
                fp = {}
                try:
                    fp['http'] = fetch_http_headers(target_ip, port=80, use_https=False)
                except Exception as e:
                    fp['http_error'] = str(e)

                try:
                    fp['https'] = fetch_tls_info(target_ip, port=443)
                except Exception as e:
                    fp['https_error'] = str(e)

                try:
                    fp['http_well_known'] = safe_http_enum_well_known(target_ip, port=80)
                except Exception as e:
                    fp['http_well_known_error'] = str(e)

                try:
                    sshb = ssh_banner(target_ip, port=22)
                    if sshb:
                        fp['ssh_banner'] = sshb
                except Exception:
                    pass

                try:
                    nm_out = nmap_service_scan(target_ip, ports=None, sudo_for_os=False)
                    fp['nmap'] = nm_out
                except Exception as e:
                    fp['nmap_error'] = str(e)

                # persist
                if not target_node.extra_data:
                    target_node.extra_data = {}
                target_node.extra_data = target_node.extra_data or {}
                target_node.extra_data['fingerprints'] = fp
                self.db.commit()
            except Exception as e:
                print(f"Deep fingerprinting error: {e}")

        print(f"[*] Analysis complete. Session ID: {new_session.id}")
        return results

    def get_entry(self, ip):
        entry = self.db.query(NetworkNode).filter_by(ip=ip).first()
        return entry.dict() if entry else None

    def get_analysis(self, session_id):
        session = self.db.query(AnalysisSession).filter_by(id=session_id).first()
        return session.dict() if session else None

    def get_organization_info(self, ip):
        node = self.db.query(NetworkNode).filter_by(ip=ip).first()
        if node and node.organization_obj:
            return node.organization_obj.dict()
        return None

    def get_organization(self, org_id):
        org = self.db.query(Organization).filter_by(id=org_id).first()
        return org.dict() if org else None

    # -------------------------
    # LLM Analysis Methods
    # -------------------------
    def analyze_session_with_llm(self, session_id: int, save_result: bool = True) -> dict:
        """
        Analyze a honeypot session using the LLM analyzer.
        
        Args:
            session_id: ID of the session to analyze
            save_result: Whether to save the analysis to the database
            
        Returns:
            Analysis results dictionary
        """
        if not self.llm_analyzer or not self.llm_analyzer.is_available():
            return {"error": "LLM analyzer not available"}
        
        session = self.get_honeypot_session(session_id)
        if not session:
            return {"error": "Session not found"}
        
        analysis = self.llm_analyzer.analyze_session(session)
        
        if save_result and analysis.get("analyzed"):
            try:
                threat = ThreatAnalysis(
                    source_type="session",
                    source_id=session_id,
                    source_ip=session.get("src_ip"),
                    model_used=self.llm_analyzer.model,
                    threat_type=analysis.get("threat_type"),
                    severity=analysis.get("severity"),
                    confidence=analysis.get("confidence"),
                    summary=analysis.get("summary"),
                    tactics=analysis.get("tactics", []),
                    techniques=analysis.get("techniques", []),
                    indicators=analysis.get("indicators", []),
                    attacker_profile=analysis.get("attacker_profile", {}),
                    raw_analysis=analysis
                )
                self.db.add(threat)
                self.db.flush()  # Get the threat ID without committing
                analysis["threat_analysis_id"] = threat.id
                
                # Index the threat for similarity search
                if self.vector_store and self.vector_store.is_available():
                    if self.vector_store.index_threat(analysis, threat.id):
                        threat.is_indexed = True
                
                # Single commit for both threat creation and indexing status
                self.db.commit()
            except Exception as e:
                self.logger.error("Failed to save threat analysis: %s", e)
                try:
                    self.db.rollback()
                except Exception:
                    pass
        
        return analysis

    def analyze_accesses_with_llm(self, ip: str = None, limit: int = 100, save_result: bool = True) -> dict:
        """
        Analyze web access logs using the LLM analyzer.
        
        Args:
            ip: Optional IP address to filter accesses
            limit: Maximum number of accesses to analyze
            save_result: Whether to save the analysis to the database
            
        Returns:
            Analysis results dictionary
        """
        if not self.llm_analyzer or not self.llm_analyzer.is_available():
            return {"error": "LLM analyzer not available"}
        
        if ip:
            accesses = self.get_accesses_for_ip(ip, limit=limit)
        else:
            rows = self.db.query(WebAccess).order_by(WebAccess.timestamp.desc()).limit(limit).all()
            accesses = [r.dict() for r in rows]
        
        if not accesses:
            return {"error": "No accesses found"}
        
        analysis = self.llm_analyzer.analyze_access_logs(accesses)
        
        if save_result and analysis.get("analyzed"):
            try:
                threat = ThreatAnalysis(
                    source_type="access",
                    source_ip=ip,
                    model_used=self.llm_analyzer.model,
                    threat_type=", ".join(analysis.get("attack_types", [])),
                    severity=analysis.get("severity"),
                    summary=analysis.get("summary"),
                    raw_analysis=analysis
                )
                self.db.add(threat)
                self.db.commit()
                analysis["threat_analysis_id"] = threat.id
            except Exception as e:
                self.logger.error("Failed to save access analysis: %s", e)
                try:
                    self.db.rollback()
                except Exception:
                    pass
        
        return analysis

    def analyze_connections_with_llm(self, direction: str = None, limit: int = 100, save_result: bool = True) -> dict:
        """
        Analyze network connections using the LLM analyzer.
        
        Args:
            direction: Optional direction filter ('outgoing' or 'internal')
            limit: Maximum number of connections to analyze
            save_result: Whether to save the analysis to the database
            
        Returns:
            Analysis results dictionary
        """
        if not self.llm_analyzer or not self.llm_analyzer.is_available():
            return {"error": "LLM analyzer not available"}
        
        connections = self.get_outgoing_connections(limit=limit, direction=direction)
        
        if not connections:
            return {"error": "No connections found"}
        
        analysis = self.llm_analyzer.analyze_connections(connections)
        
        if save_result and analysis.get("analyzed"):
            try:
                threat = ThreatAnalysis(
                    source_type="connection",
                    model_used=self.llm_analyzer.model,
                    severity=analysis.get("severity"),
                    summary=analysis.get("summary"),
                    raw_analysis=analysis
                )
                self.db.add(threat)
                self.db.commit()
                analysis["threat_analysis_id"] = threat.id
            except Exception as e:
                self.logger.error("Failed to save connection analysis: %s", e)
                try:
                    self.db.rollback()
                except Exception:
                    pass
        
        return analysis

    def plan_countermeasure(self, threat_analysis_id: int, context: dict = None) -> dict:
        """
        Generate countermeasure recommendations for a threat analysis.
        
        Args:
            threat_analysis_id: ID of the threat analysis to plan countermeasures for
            context: Additional context for countermeasure planning
            
        Returns:
            Countermeasure plan dictionary
        """
        if not self.llm_analyzer or not self.llm_analyzer.is_available():
            return {"error": "LLM analyzer not available"}
        
        threat = self.db.query(ThreatAnalysis).filter_by(id=threat_analysis_id).first()
        if not threat:
            return {"error": "Threat analysis not found"}
        
        threat_dict = threat.dict()
        plan = self.llm_analyzer.plan_countermeasure(threat_dict, context)
        
        if plan.get("planned"):
            try:
                threat.countermeasures = plan
                self.db.commit()
            except Exception as e:
                self.logger.error("Failed to save countermeasure plan: %s", e)
                try:
                    self.db.rollback()
                except Exception:
                    pass
        
        return plan

    def examine_artifact_with_llm(self, artifact_name: str) -> dict:
        """
        Examine a captured artifact using the LLM analyzer.
        
        Args:
            artifact_name: Name of the artifact file
            
        Returns:
            Examination results dictionary
        """
        if not self.llm_analyzer or not self.llm_analyzer.is_available():
            return {"error": "LLM analyzer not available"}
        
        artifacts_dir = os.path.join(self.honeypot_data_dir, "artifacts")
        artifact_path = os.path.abspath(os.path.join(artifacts_dir, artifact_name))
        
        # Security check: ensure path is within artifacts directory
        if not artifact_path.startswith(os.path.abspath(artifacts_dir)):
            return {"error": "Invalid artifact path"}
        
        if not os.path.isfile(artifact_path):
            return {"error": "Artifact not found"}
        
        return self.llm_analyzer.examine_artifact(artifact_path)

    def unify_threats(self, session_ids: list) -> dict:
        """
        Create a unified threat profile from multiple sessions.
        
        Args:
            session_ids: List of session IDs to unify
            
        Returns:
            Unified threat profile dictionary
        """
        if not self.llm_analyzer or not self.llm_analyzer.is_available():
            return {"error": "LLM analyzer not available"}
        
        sessions = []
        for sid in session_ids:
            session = self.get_honeypot_session(sid)
            if session:
                sessions.append(session)
        
        if not sessions:
            return {"error": "No valid sessions found"}
        
        # Get existing analyses if any
        analyses = []
        for sid in session_ids:
            threat = self.db.query(ThreatAnalysis).filter_by(source_type="session", source_id=sid).first()
            if threat:
                analyses.append(threat.dict())
        
        return self.llm_analyzer.unify_threat_profile(sessions, analyses)

    # -------------------------
    # Vector Search Methods
    # -------------------------
    def index_session_vector(self, session_id: int) -> bool:
        """
        Index a honeypot session for vector similarity search.
        
        Args:
            session_id: ID of the session to index
            
        Returns:
            True if successful
        """
        if not self.vector_store or not self.vector_store.is_available():
            return False
        
        session = self.get_honeypot_session(session_id)
        if not session:
            return False
        
        return self.vector_store.index_session(session, session_id)

    def index_node_vector(self, ip: str) -> bool:
        """
        Index a network node for vector similarity search.
        
        Args:
            ip: IP address of the node
            
        Returns:
            True if successful
        """
        if not self.vector_store or not self.vector_store.is_available():
            return False
        
        node = self.get_entry(ip)
        if not node:
            return False
        
        return self.vector_store.index_node(node, ip)

    def search_similar_sessions(self, query: str = None, session_id: int = None, limit: int = 10, filters: dict = None) -> list:
        """
        Search for similar honeypot sessions.
        
        Args:
            query: Text query to search for
            session_id: Session ID to find similar sessions to
            limit: Maximum number of results
            filters: Optional filters
            
        Returns:
            List of similar sessions with scores
        """
        if not self.vector_store or not self.vector_store.is_available():
            return []
        
        session = None
        if session_id:
            session = self.get_honeypot_session(session_id)
        
        return self.vector_store.search_similar_sessions(
            query_text=query,
            query_session=session,
            limit=limit,
            filters=filters
        )

    def search_similar_nodes(self, query: str = None, ip: str = None, limit: int = 10, filters: dict = None) -> list:
        """
        Search for similar network nodes.
        
        Args:
            query: Text query to search for
            ip: IP address to find similar nodes to
            limit: Maximum number of results
            filters: Optional filters
            
        Returns:
            List of similar nodes with scores
        """
        if not self.vector_store or not self.vector_store.is_available():
            return []
        
        node = None
        if ip:
            node = self.get_entry(ip)
        
        return self.vector_store.search_similar_nodes(
            query_text=query,
            query_node=node,
            limit=limit,
            filters=filters
        )

    def search_similar_threats(self, query: str, limit: int = 10, filters: dict = None) -> list:
        """
        Search for similar threat analyses.
        
        Args:
            query: Text query describing the threat
            limit: Maximum number of results
            filters: Optional filters
            
        Returns:
            List of similar threats with scores
        """
        if not self.vector_store or not self.vector_store.is_available():
            return []
        
        return self.vector_store.search_similar_threats(query, limit=limit, filters=filters)

    # -------------------------
    # Clustering Methods
    # -------------------------
    def create_attacker_cluster(self, session_ids: list, name: str = None) -> dict:
        """
        Create a cluster of related attackers from session IDs.
        
        Args:
            session_ids: List of session IDs to cluster
            name: Optional name for the cluster
            
        Returns:
            Cluster information dictionary
        """
        sessions = []
        ips = set()
        
        for sid in session_ids:
            session = self.get_honeypot_session(sid)
            if session:
                sessions.append(session)
                if session.get("src_ip"):
                    ips.add(session["src_ip"])
        
        if not sessions:
            return {"error": "No valid sessions found"}
        
        # Generate unified profile if LLM available
        unified_profile = {}
        if self.llm_analyzer and self.llm_analyzer.is_available():
            unified_profile = self.unify_threats(session_ids)
        
        # Create cluster record
        cluster = AttackerCluster(
            name=name or f"Cluster_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            member_ips=list(ips),
            member_session_ids=session_ids,
            unified_profile=unified_profile,
            member_count=len(sessions),
            common_tactics=unified_profile.get("common_patterns", []),
            overall_severity=unified_profile.get("threat_actor_profile", {}).get("sophistication")
        )
        
        self.db.add(cluster)
        try:
            self.db.commit()
            return cluster.dict()
        except Exception as e:
            self.db.rollback()
            return {"error": f"Failed to create cluster: {e}"}

    def find_similar_attackers(self, ip: str, threshold: float = 0.7, limit: int = 10) -> list:
        """
        Find attackers similar to the given IP based on behavior.
        
        Args:
            ip: IP address to find similar attackers for
            threshold: Similarity threshold (0-1)
            limit: Maximum number of results
            
        Returns:
            List of similar attackers with similarity scores
        """
        if not self.vector_store or not self.vector_store.is_available():
            return []
        
        # Get sessions for this IP
        sessions = self.db.query(HoneypotSession).filter_by(src_ip=ip).all()
        if not sessions:
            return []
        
        # Combine all sessions into query
        all_commands = []
        for sess in sessions:
            sess_dict = sess.dict()
            full_session = self.get_honeypot_session(sess.id)
            if full_session:
                for cmd in full_session.get("commands", []):
                    if cmd.get("command"):
                        all_commands.append(cmd["command"])
        
        query = f"IP: {ip} | Commands: {'; '.join(all_commands[:20])}"
        
        similar = self.vector_store.search_similar_sessions(
            query_text=query,
            limit=limit,
            score_threshold=threshold
        )
        
        # Group by IP
        by_ip = {}
        for s in similar:
            src_ip = s.get("src_ip")
            if src_ip and src_ip != ip:
                if src_ip not in by_ip or s["score"] > by_ip[src_ip]["score"]:
                    by_ip[src_ip] = s
        
        return sorted(by_ip.values(), key=lambda x: x["score"], reverse=True)

    def get_threat_analyses(self, source_type: str = None, limit: int = 100) -> list:
        """
        Get threat analyses, optionally filtered by source type.
        
        Args:
            source_type: Optional filter ('session', 'access', 'connection')
            limit: Maximum number of results
            
        Returns:
            List of threat analysis dictionaries
        """
        query = self.db.query(ThreatAnalysis).order_by(ThreatAnalysis.analyzed_at.desc())
        if source_type:
            query = query.filter_by(source_type=source_type)
        rows = query.limit(limit).all()
        return [r.dict() for r in rows]

    def get_attacker_clusters(self, limit: int = 100) -> list:
        """
        Get all attacker clusters.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of cluster dictionaries
        """
        rows = self.db.query(AttackerCluster).order_by(AttackerCluster.created_at.desc()).limit(limit).all()
        return [r.dict() for r in rows]

    def get_llm_status(self) -> dict:
        """Get the status of the LLM analyzer."""
        if not self.llm_analyzer:
            return {"available": False, "reason": "LLM analyzer not initialized"}
        
        return {
            "available": self.llm_analyzer.is_available(),
            **self.llm_analyzer.get_model_info()
        }

    def get_vector_store_status(self) -> dict:
        """Get the status of the vector store."""
        if not self.vector_store:
            return {"available": False, "reason": "Vector store not initialized"}
        
        status = {
            "available": self.vector_store.is_available()
        }
        
        if self.vector_store.is_available():
            status["collections"] = self.vector_store.get_collection_stats()
        
        return status


if __name__ == "__main__":
    engine = ForensicEngine()
    print("ForensicEngine ready.")
