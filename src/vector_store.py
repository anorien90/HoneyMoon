"""
Vector storage module for HoneyMoon using Qdrant and sentence-transformers.

Provides embedding generation and similarity search capabilities for:
- Honeypot sessions
- Network nodes
- Web accesses
- Connections
- Threat analyses
"""
import os
import logging
from functools import lru_cache
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timezone

# Optional imports for vector DB functionality
try:
    from sentence_transformers import SentenceTransformer
    _HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    SentenceTransformer = None
    _HAS_SENTENCE_TRANSFORMERS = False

try:
    from qdrant_client import QdrantClient
    from qdrant_client.http import models as qdrant_models
    from qdrant_client.http.models import Distance, VectorParams, PointStruct
    _HAS_QDRANT = True
except ImportError:
    QdrantClient = None
    qdrant_models = None
    Distance = None
    VectorParams = None
    PointStruct = None
    _HAS_QDRANT = False

logger = logging.getLogger(__name__)


class VectorStore:
    """
    Qdrant-based vector store for HoneyMoon data.
    
    Supports embedding and similarity search for honeypot sessions,
    network nodes, web accesses, and threat analyses.
    """
    
    # Collection names
    SESSIONS_COLLECTION = "honeypot_sessions"
    NODES_COLLECTION = "network_nodes"
    ACCESSES_COLLECTION = "web_accesses"
    CONNECTIONS_COLLECTION = "connections"
    THREATS_COLLECTION = "threat_analyses"
    
    # Default embedding model
    DEFAULT_MODEL = "all-MiniLM-L6-v2"  # Small, fast, good for semantic similarity
    
    def __init__(
        self,
        qdrant_host: Optional[str] = None,
        qdrant_port: Optional[int] = None,
        qdrant_path: Optional[str] = None,
        embedding_model: Optional[str] = None,
        vector_size: int = 384
    ):
        """
        Initialize the vector store.
        
        Args:
            qdrant_host: Qdrant server host (if using remote Qdrant)
            qdrant_port: Qdrant server port (if using remote Qdrant)
            qdrant_path: Path for local Qdrant persistence (if using local Qdrant)
            embedding_model: Name of the sentence-transformers model to use
            vector_size: Dimension of the embedding vectors
        """
        self.qdrant_host = qdrant_host or os.environ.get("QDRANT_HOST", "localhost")
        self.qdrant_port = int(qdrant_port or os.environ.get("QDRANT_PORT", "6333"))
        self.qdrant_path = qdrant_path or os.environ.get("QDRANT_PATH", "./data/qdrant")
        self.embedding_model_name = embedding_model or os.environ.get("EMBEDDING_MODEL", self.DEFAULT_MODEL)
        self.vector_size = vector_size
        
        self._client: Optional[QdrantClient] = None
        self._embedding_model: Optional[SentenceTransformer] = None
        
        # Initialize if libraries are available
        self._init_components()
    
    def _init_components(self):
        """Initialize Qdrant client and embedding model."""
        if not _HAS_QDRANT:
            logger.warning("qdrant-client not installed. Vector store functionality disabled.")
            return
        
        if not _HAS_SENTENCE_TRANSFORMERS:
            logger.warning("sentence-transformers not installed. Embedding functionality disabled.")
            return
        
        try:
            # Try to connect to remote Qdrant Docker container first, fall back to local
            # Default behavior: prefer Docker container at localhost:6333
            use_local = os.environ.get("QDRANT_USE_LOCAL", "false").lower() in ("true", "1", "yes")
            
            if not use_local:
                # Try Docker container connection first
                try:
                    self._client = QdrantClient(host=self.qdrant_host, port=self.qdrant_port, timeout=5)
                    # Test connection by listing collections
                    self._client.get_collections()
                    logger.info("Connected to Qdrant Docker container at %s:%s", self.qdrant_host, self.qdrant_port)
                except Exception as docker_err:
                    logger.info("Qdrant Docker container not available at %s:%s (%s), falling back to local storage", 
                               self.qdrant_host, self.qdrant_port, docker_err)
                    logger.info("💡 Hint: For better performance, start Qdrant with: docker-compose up qdrant")
                    self._client = None
            
            # Fall back to local storage if Docker not available or explicitly requested
            if self._client is None:
                os.makedirs(self.qdrant_path, exist_ok=True)
                self._client = QdrantClient(path=self.qdrant_path)
                logger.info("Connected to local Qdrant at %s", self.qdrant_path)
            
            # Initialize collections
            self._ensure_collections()
            
        except Exception as e:
            logger.error("Failed to initialize Qdrant client: %s", e)
            self._client = None
        
        try:
            self._embedding_model = SentenceTransformer(self.embedding_model_name)
            # Update vector size based on model
            self.vector_size = self._embedding_model.get_sentence_embedding_dimension()
            logger.info("Loaded embedding model: %s (dimension: %d)", 
                       self.embedding_model_name, self.vector_size)
        except Exception as e:
            logger.error("Failed to load embedding model: %s", e)
            self._embedding_model = None
    
    def _ensure_collections(self):
        """Create Qdrant collections if they don't exist."""
        if not self._client:
            return
        
        collections = [
            self.SESSIONS_COLLECTION,
            self.NODES_COLLECTION,
            self.ACCESSES_COLLECTION,
            self.CONNECTIONS_COLLECTION,
            self.THREATS_COLLECTION
        ]
        
        existing = {c.name for c in self._client.get_collections().collections}
        
        for collection in collections:
            if collection not in existing:
                self._client.create_collection(
                    collection_name=collection,
                    vectors_config=VectorParams(
                        size=self.vector_size,
                        distance=Distance.COSINE
                    )
                )
                logger.info("Created Qdrant collection: %s", collection)
    
    def is_available(self) -> bool:
        """Check if vector store is available and functional."""
        return self._client is not None and self._embedding_model is not None
    
    @lru_cache(maxsize=1000)
    def _cached_embed(self, text: str) -> Optional[tuple]:
        """
        Internal cached embedding function.
        Returns tuple instead of list for hashability with lru_cache.
        """
        if not self._embedding_model:
            return None
        
        try:
            embedding = self._embedding_model.encode(text, convert_to_numpy=True)
            return tuple(embedding.tolist())
        except Exception as e:
            logger.error("Failed to generate embedding: %s", e)
            return None
    
    def embed_text(self, text: str) -> Optional[List[float]]:
        """
        Generate embedding vector for text.
        Uses LRU cache for frequently similar texts to improve performance.
        
        Args:
            text: Text to embed
            
        Returns:
            List of floats representing the embedding, or None if unavailable
        """
        result = self._cached_embed(text)
        return list(result) if result else None
    
    def embed_texts(self, texts: List[str]) -> Optional[List[List[float]]]:
        """
        Generate embedding vectors for multiple texts.
        
        Args:
            texts: List of texts to embed
            
        Returns:
            List of embedding vectors, or None if unavailable
        """
        if not self._embedding_model:
            return None
        
        try:
            embeddings = self._embedding_model.encode(texts, convert_to_numpy=True)
            return [e.tolist() for e in embeddings]
        except Exception as e:
            logger.error("Failed to generate embeddings: %s", e)
            return None
    
    # Session embedding and search
    def _session_to_text(self, session: Dict[str, Any]) -> str:
        """Convert a honeypot session to text for embedding."""
        parts = []
        
        # Basic info
        parts.append(f"IP: {session.get('src_ip', 'unknown')}")
        if session.get('username'):
            parts.append(f"Username: {session['username']}")
        if session.get('auth_success'):
            parts.append(f"Auth: {session['auth_success']}")
        
        # Commands
        commands = session.get('commands', [])
        if commands:
            cmd_texts = [c.get('command', '') for c in commands if c.get('command')]
            if cmd_texts:
                parts.append(f"Commands: {'; '.join(cmd_texts[:20])}")
        
        # Files
        files = session.get('files', [])
        if files:
            file_texts = [f.get('filename', '') for f in files if f.get('filename')]
            if file_texts:
                parts.append(f"Files: {', '.join(file_texts[:10])}")
        
        # Extra metadata
        extra = session.get('extra', {})
        if extra.get('node_cached'):
            node = extra['node_cached']
            if node.get('organization'):
                parts.append(f"Organization: {node['organization']}")
            if node.get('country'):
                parts.append(f"Country: {node['country']}")
        
        # Analysis results if present
        if extra.get('llm_analysis'):
            analysis = extra['llm_analysis']
            if analysis.get('threat_type'):
                parts.append(f"Threat: {analysis['threat_type']}")
            if analysis.get('summary'):
                parts.append(f"Summary: {analysis['summary'][:200]}")
        
        return " | ".join(parts)
    
    def index_session(self, session: Dict[str, Any], session_id: int) -> bool:
        """
        Index a honeypot session for similarity search.
        
        Args:
            session: Session data dictionary
            session_id: Database ID of the session
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_available():
            return False
        
        try:
            text = self._session_to_text(session)
            embedding = self.embed_text(text)
            if not embedding:
                return False
            
            payload = {
                "session_id": session_id,
                "src_ip": session.get('src_ip'),
                "username": session.get('username'),
                "auth_success": session.get('auth_success'),
                "indexed_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Add extra metadata if available
            extra = session.get('extra', {})
            if extra.get('node_cached'):
                payload["organization"] = extra['node_cached'].get('organization')
                payload["country"] = extra['node_cached'].get('country')
            
            self._client.upsert(
                collection_name=self.SESSIONS_COLLECTION,
                points=[
                    PointStruct(
                        id=session_id,
                        vector=embedding,
                        payload=payload
                    )
                ]
            )
            return True
        except Exception as e:
            logger.error("Failed to index session %s: %s", session_id, e)
            return False
    
    def search_similar_sessions(
        self,
        query_text: Optional[str] = None,
        query_session: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        score_threshold: float = 0.5,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar honeypot sessions.
        
        Args:
            query_text: Text query to search for
            query_session: Session dict to find similar sessions to
            limit: Maximum number of results
            score_threshold: Minimum similarity score (0-1)
            filters: Additional filters for the search
            
        Returns:
            List of matching sessions with scores
        """
        if not self.is_available():
            return []
        
        try:
            if query_session:
                query_text = self._session_to_text(query_session)
            
            if not query_text:
                return []
            
            embedding = self.embed_text(query_text)
            if not embedding:
                return []
            
            # Build filter if provided
            qdrant_filter = None
            if filters:
                conditions = []
                for key, value in filters.items():
                    if isinstance(value, list):
                        conditions.append(
                            qdrant_models.FieldCondition(
                                key=key,
                                match=qdrant_models.MatchAny(any=value)
                            )
                        )
                    else:
                        conditions.append(
                            qdrant_models.FieldCondition(
                                key=key,
                                match=qdrant_models.MatchValue(value=value)
                            )
                        )
                if conditions:
                    qdrant_filter = qdrant_models.Filter(must=conditions)
            
            results = self._client.search(
                collection_name=self.SESSIONS_COLLECTION,
                query_vector=embedding,
                limit=limit,
                score_threshold=score_threshold,
                query_filter=qdrant_filter
            )
            
            return [
                {
                    "session_id": r.id,
                    "score": r.score,
                    **r.payload
                }
                for r in results
            ]
        except Exception as e:
            logger.error("Failed to search sessions: %s", e)
            return []
    
    # Node embedding and search
    def _node_to_text(self, node: Dict[str, Any]) -> str:
        """Convert a network node to text for embedding."""
        parts = []
        
        parts.append(f"IP: {node.get('ip', 'unknown')}")
        if node.get('hostname'):
            parts.append(f"Hostname: {node['hostname']}")
        if node.get('organization'):
            parts.append(f"Organization: {node['organization']}")
        if node.get('isp'):
            parts.append(f"ISP: {node['isp']}")
        if node.get('asn'):
            parts.append(f"ASN: {node['asn']}")
        if node.get('country'):
            parts.append(f"Country: {node['country']}")
        if node.get('city'):
            parts.append(f"City: {node['city']}")
        
        return " | ".join(parts)
    
    def index_node(self, node: Dict[str, Any], node_ip: str) -> bool:
        """
        Index a network node for similarity search.
        
        Args:
            node: Node data dictionary
            node_ip: IP address of the node
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_available():
            return False
        
        try:
            text = self._node_to_text(node)
            embedding = self.embed_text(text)
            if not embedding:
                return False
            
            # Generate a numeric ID from IP address
            # For IPv4: Convert to 32-bit integer using ipaddress module
            # For other formats: Use hash function with 32-bit mask
            try:
                import ipaddress
                numeric_id = int(ipaddress.IPv4Address(node_ip))
            except (ValueError, ipaddress.AddressValueError):
                # Fallback for non-IPv4 addresses
                numeric_id = hash(node_ip) & 0xFFFFFFFF
            
            payload = {
                "ip": node_ip,
                "hostname": node.get('hostname'),
                "organization": node.get('organization'),
                "isp": node.get('isp'),
                "asn": node.get('asn'),
                "country": node.get('country'),
                "city": node.get('city'),
                "indexed_at": datetime.now(timezone.utc).isoformat()
            }
            
            self._client.upsert(
                collection_name=self.NODES_COLLECTION,
                points=[
                    PointStruct(
                        id=numeric_id,
                        vector=embedding,
                        payload=payload
                    )
                ]
            )
            return True
        except Exception as e:
            logger.error("Failed to index node %s: %s", node_ip, e)
            return False
    
    def search_similar_nodes(
        self,
        query_text: Optional[str] = None,
        query_node: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        score_threshold: float = 0.5,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar network nodes.
        
        Args:
            query_text: Text query to search for
            query_node: Node dict to find similar nodes to
            limit: Maximum number of results
            score_threshold: Minimum similarity score (0-1)
            filters: Additional filters for the search
            
        Returns:
            List of matching nodes with scores
        """
        if not self.is_available():
            return []
        
        try:
            if query_node:
                query_text = self._node_to_text(query_node)
            
            if not query_text:
                return []
            
            embedding = self.embed_text(query_text)
            if not embedding:
                return []
            
            # Build filter if provided
            qdrant_filter = None
            if filters:
                conditions = []
                for key, value in filters.items():
                    if isinstance(value, list):
                        conditions.append(
                            qdrant_models.FieldCondition(
                                key=key,
                                match=qdrant_models.MatchAny(any=value)
                            )
                        )
                    else:
                        conditions.append(
                            qdrant_models.FieldCondition(
                                key=key,
                                match=qdrant_models.MatchValue(value=value)
                            )
                        )
                if conditions:
                    qdrant_filter = qdrant_models.Filter(must=conditions)
            
            results = self._client.search(
                collection_name=self.NODES_COLLECTION,
                query_vector=embedding,
                limit=limit,
                score_threshold=score_threshold,
                query_filter=qdrant_filter
            )
            
            return [
                {
                    "ip": r.payload.get("ip"),
                    "score": r.score,
                    **r.payload
                }
                for r in results
            ]
        except Exception as e:
            logger.error("Failed to search nodes: %s", e)
            return []
    
    # Web access embedding and search
    def _access_to_text(self, access: Dict[str, Any]) -> str:
        """Convert a web access to text for embedding."""
        parts = []
        
        parts.append(f"IP: {access.get('remote_addr', 'unknown')}")
        if access.get('method'):
            parts.append(f"Method: {access['method']}")
        if access.get('path'):
            parts.append(f"Path: {access['path']}")
        if access.get('status'):
            parts.append(f"Status: {access['status']}")
        if access.get('http_user_agent'):
            parts.append(f"User-Agent: {access['http_user_agent'][:100]}")
        
        return " | ".join(parts)
    
    def index_access(self, access: Dict[str, Any], access_id: int) -> bool:
        """
        Index a web access for similarity search.
        
        Args:
            access: Access data dictionary
            access_id: Database ID of the access
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_available():
            return False
        
        try:
            text = self._access_to_text(access)
            embedding = self.embed_text(text)
            if not embedding:
                return False
            
            payload = {
                "access_id": access_id,
                "remote_addr": access.get('remote_addr'),
                "method": access.get('method'),
                "path": access.get('path'),
                "status": access.get('status'),
                "indexed_at": datetime.now(timezone.utc).isoformat()
            }
            
            self._client.upsert(
                collection_name=self.ACCESSES_COLLECTION,
                points=[
                    PointStruct(
                        id=access_id,
                        vector=embedding,
                        payload=payload
                    )
                ]
            )
            return True
        except Exception as e:
            logger.error("Failed to index access %s: %s", access_id, e)
            return False
    
    def search_similar_accesses(
        self,
        query_text: Optional[str] = None,
        query_access: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        score_threshold: float = 0.5,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar web accesses.
        
        Args:
            query_text: Text query to search for
            query_access: Access dict to find similar accesses to
            limit: Maximum number of results
            score_threshold: Minimum similarity score (0-1)
            filters: Additional filters for the search
            
        Returns:
            List of matching accesses with scores
        """
        if not self.is_available():
            return []
        
        try:
            if query_access:
                query_text = self._access_to_text(query_access)
            
            if not query_text:
                return []
            
            embedding = self.embed_text(query_text)
            if not embedding:
                return []
            
            # Build filter if provided
            qdrant_filter = None
            if filters:
                conditions = []
                for key, value in filters.items():
                    if isinstance(value, list):
                        conditions.append(
                            qdrant_models.FieldCondition(
                                key=key,
                                match=qdrant_models.MatchAny(any=value)
                            )
                        )
                    else:
                        conditions.append(
                            qdrant_models.FieldCondition(
                                key=key,
                                match=qdrant_models.MatchValue(value=value)
                            )
                        )
                if conditions:
                    qdrant_filter = qdrant_models.Filter(must=conditions)
            
            results = self._client.search(
                collection_name=self.ACCESSES_COLLECTION,
                query_vector=embedding,
                limit=limit,
                score_threshold=score_threshold,
                query_filter=qdrant_filter
            )
            
            return [
                {
                    "access_id": r.id,
                    "score": r.score,
                    **r.payload
                }
                for r in results
            ]
        except Exception as e:
            logger.error("Failed to search accesses: %s", e)
            return []
    
    # Threat analysis embedding and search
    def index_threat(self, analysis: Dict[str, Any], threat_id: int) -> bool:
        """
        Index a threat analysis for similarity search.
        
        Args:
            analysis: Threat analysis data dictionary
            threat_id: Unique ID for the threat
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_available():
            return False
        
        try:
            # Build text representation of the threat
            parts = []
            if analysis.get('threat_type'):
                parts.append(f"Threat: {analysis['threat_type']}")
            if analysis.get('summary'):
                parts.append(f"Summary: {analysis['summary']}")
            if analysis.get('tactics'):
                parts.append(f"Tactics: {', '.join(analysis['tactics'])}")
            if analysis.get('techniques'):
                parts.append(f"Techniques: {', '.join(analysis['techniques'])}")
            if analysis.get('indicators'):
                parts.append(f"Indicators: {', '.join(str(i) for i in analysis['indicators'][:10])}")
            
            text = " | ".join(parts)
            if not text:
                return False
            
            embedding = self.embed_text(text)
            if not embedding:
                return False
            
            payload = {
                "threat_id": threat_id,
                "threat_type": analysis.get('threat_type'),
                "severity": analysis.get('severity'),
                "summary": analysis.get('summary', '')[:500],
                "indexed_at": datetime.now(timezone.utc).isoformat()
            }
            
            self._client.upsert(
                collection_name=self.THREATS_COLLECTION,
                points=[
                    PointStruct(
                        id=threat_id,
                        vector=embedding,
                        payload=payload
                    )
                ]
            )
            return True
        except Exception as e:
            logger.error("Failed to index threat %s: %s", threat_id, e)
            return False
    
    def search_similar_threats(
        self,
        query_text: str,
        limit: int = 10,
        score_threshold: float = 0.5,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar threat analyses.
        
        Args:
            query_text: Text query to search for
            limit: Maximum number of results
            score_threshold: Minimum similarity score (0-1)
            filters: Additional filters for the search
            
        Returns:
            List of matching threats with scores
        """
        if not self.is_available():
            return []
        
        try:
            embedding = self.embed_text(query_text)
            if not embedding:
                return []
            
            # Build filter if provided
            qdrant_filter = None
            if filters:
                conditions = []
                for key, value in filters.items():
                    if isinstance(value, list):
                        conditions.append(
                            qdrant_models.FieldCondition(
                                key=key,
                                match=qdrant_models.MatchAny(any=value)
                            )
                        )
                    else:
                        conditions.append(
                            qdrant_models.FieldCondition(
                                key=key,
                                match=qdrant_models.MatchValue(value=value)
                            )
                        )
                if conditions:
                    qdrant_filter = qdrant_models.Filter(must=conditions)
            
            results = self._client.search(
                collection_name=self.THREATS_COLLECTION,
                query_vector=embedding,
                limit=limit,
                score_threshold=score_threshold,
                query_filter=qdrant_filter
            )
            
            return [
                {
                    "threat_id": r.id,
                    "score": r.score,
                    **r.payload
                }
                for r in results
            ]
        except Exception as e:
            logger.error("Failed to search threats: %s", e)
            return []
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the vector collections."""
        if not self.is_available():
            return {"error": "Vector store not available"}
        
        try:
            stats = {}
            for collection in [
                self.SESSIONS_COLLECTION,
                self.NODES_COLLECTION,
                self.ACCESSES_COLLECTION,
                self.CONNECTIONS_COLLECTION,
                self.THREATS_COLLECTION
            ]:
                try:
                    info = self._client.get_collection(collection)
                    stats[collection] = {
                        "vectors_count": info.vectors_count,
                        "points_count": info.points_count
                    }
                except Exception:
                    stats[collection] = {"error": "Collection not found"}
            return stats
        except Exception as e:
            return {"error": str(e)}
