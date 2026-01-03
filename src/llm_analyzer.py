"""
LLM-based analysis module for HoneyMoon using local Granite models via Ollama.

Provides threat analysis, log examination, and counter-measure planning capabilities
for honeypot sessions, connections, and web access logs.
"""
import os
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

# Optional imports for LLM functionality
try:
    import ollama
    _HAS_OLLAMA = True
except ImportError:
    ollama = None
    _HAS_OLLAMA = False

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """
    LLM-based analyzer for honeypot and security data using local Granite models.
    
    Uses Ollama to run IBM Granite models locally for:
    - Honeypot session analysis and threat extraction
    - Attack pattern identification
    - Counter-measure planning
    - Log summarization and examination
    """
    
    # Default model - IBM Granite for code and security analysis
    DEFAULT_MODEL = "granite3.1-dense:8b"
    
    # Alternative models that can be used
    SUPPORTED_MODELS = [
        "granite3.1-dense:8b",
        "granite3.1-dense:2b",
        "granite-code:8b",
        "granite-code:3b",
        "llama3.2:3b",  # Fallback if Granite unavailable
        "mistral:7b"    # Another fallback
    ]
    
    def __init__(
        self,
        model: Optional[str] = None,
        ollama_host: Optional[str] = None,
        timeout: int = 120
    ):
        """
        Initialize the LLM analyzer.
        
        Args:
            model: Name of the Ollama model to use
            ollama_host: Ollama server host (default: localhost:11434)
            timeout: Request timeout in seconds
        """
        self.model = model or os.environ.get("LLM_MODEL", self.DEFAULT_MODEL)
        self.ollama_host = ollama_host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.timeout = timeout
        
        self._client = None
        self._model_available = False
        
        self._init_client()
    
    def _init_client(self):
        """Initialize the Ollama client."""
        if not _HAS_OLLAMA:
            logger.warning("ollama package not installed. LLM functionality disabled.")
            return
        
        try:
            # Configure Ollama host if provided
            if self.ollama_host and self.ollama_host != "http://localhost:11434":
                os.environ["OLLAMA_HOST"] = self.ollama_host
            
            # Test connection by listing models
            models = ollama.list()
            available_models = [m.get("name", "") for m in models.get("models", [])]
            
            # Check if our preferred model is available
            if self._find_matching_model(self.model, available_models):
                self._model_available = True
                logger.info("LLM model available: %s", self.model)
            else:
                # Try to find any supported model
                for fallback in self.SUPPORTED_MODELS:
                    if self._find_matching_model(fallback, available_models):
                        self.model = fallback
                        self._model_available = True
                        logger.info("Using fallback LLM model: %s", self.model)
                        break
                
                if not self._model_available:
                    logger.warning("No supported LLM model found. Available models: %s", available_models)
                    logger.info("To install Granite, run: ollama pull %s", self.DEFAULT_MODEL)
            
            self._client = ollama
            
        except Exception as e:
            logger.error("Failed to initialize Ollama client: %s", e)
            logger.info("Make sure Ollama is running (ollama serve) and has a model installed.")
    
    def _find_matching_model(self, target_model: str, available_models: List[str]) -> bool:
        """
        Check if a target model matches any of the available models.
        
        Matches both exact names and model family prefixes (e.g., 'granite3.1-dense' matches 'granite3.1-dense:8b').
        
        Args:
            target_model: Model name to search for
            available_models: List of available model names
            
        Returns:
            True if a match is found
        """
        # Exact match
        if target_model in available_models:
            return True
        
        # Extract model family (before the colon)
        target_family = target_model.split(":")[0]
        
        # Check if any available model starts with the target family
        for available in available_models:
            available_family = available.split(":")[0]
            if target_family == available_family:
                return True
        
        return False
    
    def is_available(self) -> bool:
        """Check if LLM analyzer is available."""
        return _HAS_OLLAMA and self._client is not None and self._model_available
    
    def _generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt for context
            
        Returns:
            Generated response text, or None on error
        """
        if not self.is_available():
            return None
        
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            response = self._client.chat(
                model=self.model,
                messages=messages,
                options={"temperature": 0.3}  # Lower temperature for more deterministic output
            )
            
            return response.get("message", {}).get("content", "")
            
        except Exception as e:
            logger.error("LLM generation failed: %s", e)
            return None
    
    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Try to parse JSON from LLM response."""
        if not response:
            return None
        
        # Try direct JSON parse
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON from markdown code blocks
        import re
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', response)
        if json_match:
            try:
                return json.loads(json_match.group(1).strip())
            except json.JSONDecodeError:
                pass
        
        # Try to find JSON object in response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass
        
        return None
    
    def analyze_session(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a honeypot session and extract threat information.
        
        Args:
            session: Session data dictionary with commands, files, etc.
            
        Returns:
            Analysis results with threat type, severity, tactics, etc.
        """
        if not self.is_available():
            return {"error": "LLM not available", "analyzed": False}
        
        # Build context from session data
        context_parts = []
        context_parts.append(f"Source IP: {session.get('src_ip', 'unknown')}")
        context_parts.append(f"Source Port: {session.get('src_port', 'unknown')}")
        context_parts.append(f"Username attempted: {session.get('username', 'none')}")
        context_parts.append(f"Authentication result: {session.get('auth_success', 'unknown')}")
        
        # Commands executed
        commands = session.get('commands', [])
        if commands:
            cmd_list = [c.get('command', '') for c in commands if c.get('command')]
            context_parts.append(f"\nCommands executed ({len(cmd_list)} total):")
            for cmd in cmd_list[:50]:  # Limit to first 50 commands
                context_parts.append(f"  $ {cmd}")
        
        # Files involved
        files = session.get('files', [])
        if files:
            context_parts.append(f"\nFiles involved ({len(files)} total):")
            for f in files[:20]:
                context_parts.append(f"  - {f.get('filename', 'unknown')} ({f.get('direction', 'unknown')})")
        
        # Extra metadata
        extra = session.get('extra', {})
        if extra.get('node_cached'):
            node = extra['node_cached']
            context_parts.append(f"\nAttacker info:")
            if node.get('organization'):
                context_parts.append(f"  Organization: {node['organization']}")
            if node.get('country'):
                context_parts.append(f"  Country: {node['country']}")
            if node.get('asn'):
                context_parts.append(f"  ASN: {node['asn']}")
        
        context = "\n".join(context_parts)
        
        system_prompt = """You are a cybersecurity analyst specializing in honeypot analysis and threat intelligence.
Analyze the provided honeypot session data and extract threat information.
Respond with a JSON object containing your analysis."""
        
        prompt = f"""Analyze this honeypot session and provide a structured threat assessment.

Session Data:
{context}

Provide your analysis as a JSON object with these fields:
- threat_type: string (e.g., "SSH Brute Force", "Malware Download", "Reconnaissance", "Botnet Activity", "Cryptominer", "Data Exfiltration", "Unknown")
- severity: string ("critical", "high", "medium", "low", "info")
- confidence: float (0.0 to 1.0)
- summary: string (2-3 sentence description of the attack)
- tactics: list of MITRE ATT&CK tactics observed (e.g., ["Initial Access", "Execution", "Persistence"])
- techniques: list of specific techniques used (e.g., ["T1110 - Brute Force", "T1059 - Command Line Interface"])
- indicators: list of IoCs (indicators of compromise) extracted
- attacker_profile: object with {{skill_level: string, likely_automated: boolean, potential_attribution: string}}
- recommendations: list of recommended actions"""
        
        response = self._generate(prompt, system_prompt)
        result = self._parse_json_response(response)
        
        if result:
            result["analyzed"] = True
            result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            result["raw_response"] = response
            return result
        
        # Fallback if JSON parsing failed
        return {
            "analyzed": True,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "threat_type": "Unknown",
            "severity": "medium",
            "confidence": 0.5,
            "summary": response[:500] if response else "Analysis failed",
            "raw_response": response,
            "parse_error": True
        }
    
    def analyze_access_logs(self, accesses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze web access logs for suspicious patterns.
        
        Args:
            accesses: List of web access records
            
        Returns:
            Analysis results with threat patterns and recommendations
        """
        if not self.is_available():
            return {"error": "LLM not available", "analyzed": False}
        
        # Build context from access logs
        context_parts = []
        context_parts.append(f"Total access records: {len(accesses)}")
        
        # Group by IP
        by_ip = {}
        for acc in accesses:
            ip = acc.get('remote_addr', 'unknown')
            by_ip.setdefault(ip, []).append(acc)
        
        context_parts.append(f"Unique IPs: {len(by_ip)}")
        context_parts.append("\nAccess details:")
        
        for ip, records in list(by_ip.items())[:20]:  # Limit to 20 IPs
            context_parts.append(f"\n  {ip} ({len(records)} requests):")
            for rec in records[:10]:  # Limit to 10 records per IP
                context_parts.append(f"    {rec.get('method', '?')} {rec.get('path', '?')} -> {rec.get('status', '?')}")
                if rec.get('http_user_agent'):
                    context_parts.append(f"      UA: {rec['http_user_agent'][:80]}")
        
        context = "\n".join(context_parts)
        
        system_prompt = """You are a web security analyst specializing in HTTP log analysis and intrusion detection.
Analyze the provided access logs for suspicious activity patterns."""
        
        prompt = f"""Analyze these web access logs and identify potential security threats.

Access Log Summary:
{context}

Provide your analysis as a JSON object with these fields:
- threat_patterns: list of identified suspicious patterns (e.g., "SQL Injection attempts", "Directory traversal", "Scanner activity")
- severity: string ("critical", "high", "medium", "low", "info")
- suspicious_ips: list of IPs exhibiting malicious behavior with reasons
- attack_types: list of attack types detected
- summary: string (2-3 sentence summary of findings)
- recommendations: list of recommended security actions"""
        
        response = self._generate(prompt, system_prompt)
        result = self._parse_json_response(response)
        
        if result:
            result["analyzed"] = True
            result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            return result
        
        return {
            "analyzed": True,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "severity": "medium",
            "summary": response[:500] if response else "Analysis failed",
            "raw_response": response,
            "parse_error": True
        }
    
    def analyze_connections(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze network connections for suspicious activity.
        
        Args:
            connections: List of connection records
            
        Returns:
            Analysis results with threat patterns and recommendations
        """
        if not self.is_available():
            return {"error": "LLM not available", "analyzed": False}
        
        # Build context from connections
        context_parts = []
        context_parts.append(f"Total connections: {len(connections)}")
        
        # Group by remote address
        by_remote = {}
        for conn in connections:
            remote = conn.get('remote_addr', 'unknown')
            by_remote.setdefault(remote, []).append(conn)
        
        context_parts.append(f"Unique remote hosts: {len(by_remote)}")
        context_parts.append("\nConnection details:")
        
        for remote, conns in list(by_remote.items())[:20]:
            context_parts.append(f"\n  {remote} ({len(conns)} connections):")
            for conn in conns[:5]:
                context_parts.append(
                    f"    {conn.get('local_addr', '?')}:{conn.get('local_port', '?')} -> "
                    f"{conn.get('remote_port', '?')} ({conn.get('proto', '?')}) "
                    f"[{conn.get('status', '?')}] {conn.get('process_name', '')}"
                )
        
        context = "\n".join(context_parts)
        
        system_prompt = """You are a network security analyst specializing in connection analysis and threat detection.
Analyze the provided network connections for suspicious activity."""
        
        prompt = f"""Analyze these network connections and identify potential security concerns.

Connection Summary:
{context}

Provide your analysis as a JSON object with these fields:
- suspicious_connections: list of connections that warrant investigation with reasons
- threat_indicators: list of threat indicators found
- severity: string ("critical", "high", "medium", "low", "info")
- summary: string (2-3 sentence summary of findings)
- potential_c2: boolean (indicates potential command and control activity)
- data_exfiltration_risk: boolean
- recommendations: list of recommended actions"""
        
        response = self._generate(prompt, system_prompt)
        result = self._parse_json_response(response)
        
        if result:
            result["analyzed"] = True
            result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
            return result
        
        return {
            "analyzed": True,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "severity": "medium",
            "summary": response[:500] if response else "Analysis failed",
            "raw_response": response,
            "parse_error": True
        }
    
    def plan_countermeasure(
        self,
        threat_analysis: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Plan countermeasures for an identified threat.
        
        Args:
            threat_analysis: Previous threat analysis results
            context: Additional context (e.g., infrastructure info)
            
        Returns:
            Countermeasure plan with immediate and long-term actions
        """
        if not self.is_available():
            return {"error": "LLM not available", "planned": False}
        
        # Build context
        context_parts = []
        context_parts.append(f"Threat Type: {threat_analysis.get('threat_type', 'Unknown')}")
        context_parts.append(f"Severity: {threat_analysis.get('severity', 'Unknown')}")
        context_parts.append(f"Summary: {threat_analysis.get('summary', 'No summary available')}")
        
        if threat_analysis.get('tactics'):
            context_parts.append(f"Tactics: {', '.join(threat_analysis['tactics'])}")
        if threat_analysis.get('techniques'):
            context_parts.append(f"Techniques: {', '.join(threat_analysis['techniques'])}")
        if threat_analysis.get('indicators'):
            context_parts.append(f"Indicators: {', '.join(str(i) for i in threat_analysis['indicators'][:10])}")
        
        if context:
            if context.get('source_ip'):
                context_parts.append(f"Attacker IP: {context['source_ip']}")
            if context.get('organization'):
                context_parts.append(f"Attacker Organization: {context['organization']}")
        
        threat_context = "\n".join(context_parts)
        
        system_prompt = """You are a cybersecurity incident responder and defense strategist.
Based on the threat analysis, provide actionable countermeasures.
Focus on practical, implementable defensive actions."""
        
        prompt = f"""Based on this threat analysis, provide a countermeasure plan.

Threat Analysis:
{threat_context}

Provide your countermeasure plan as a JSON object with these fields:
- immediate_actions: list of actions to take immediately (within minutes/hours)
- short_term_actions: list of actions to take within days
- long_term_actions: list of strategic improvements to prevent similar attacks
- firewall_rules: list of suggested firewall rules (as strings like "block 192.168.1.1")
- detection_rules: list of suggested detection/SIEM rules
- affected_systems: list of systems that may need investigation
- evidence_preservation: list of items to preserve for forensics
- risk_if_unaddressed: string describing consequences of inaction
- estimated_remediation_time: string (e.g., "2-4 hours")
- requires_external_notification: boolean (e.g., law enforcement, ISP abuse reports)"""
        
        response = self._generate(prompt, system_prompt)
        result = self._parse_json_response(response)
        
        if result:
            result["planned"] = True
            result["planned_at"] = datetime.now(timezone.utc).isoformat()
            return result
        
        return {
            "planned": True,
            "planned_at": datetime.now(timezone.utc).isoformat(),
            "summary": response[:500] if response else "Planning failed",
            "raw_response": response,
            "parse_error": True
        }
    
    def unify_threat_profile(
        self,
        sessions: List[Dict[str, Any]],
        analyses: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Create a unified threat profile from multiple sessions/analyses.
        
        This helps identify patterns across attacks and group related incidents.
        
        Args:
            sessions: List of related honeypot sessions
            analyses: Optional list of existing analyses for these sessions
            
        Returns:
            Unified threat profile
        """
        if not self.is_available():
            return {"error": "LLM not available", "unified": False}
        
        # Build context from sessions
        context_parts = []
        context_parts.append(f"Analyzing {len(sessions)} related sessions")
        
        # Extract unique IPs
        ips = set()
        usernames = set()
        all_commands = []
        all_files = []
        
        for sess in sessions:
            if sess.get('src_ip'):
                ips.add(sess['src_ip'])
            if sess.get('username'):
                usernames.add(sess['username'])
            for cmd in sess.get('commands', []):
                if cmd.get('command'):
                    all_commands.append(cmd['command'])
            for f in sess.get('files', []):
                if f.get('filename'):
                    all_files.append(f['filename'])
        
        context_parts.append(f"Unique IPs: {', '.join(list(ips)[:10])}")
        context_parts.append(f"Usernames tried: {', '.join(list(usernames)[:10])}")
        context_parts.append(f"Total commands: {len(all_commands)}")
        context_parts.append(f"Common commands: {', '.join(set(all_commands[:20]))}")
        context_parts.append(f"Files involved: {', '.join(set(all_files[:10]))}")
        
        if analyses:
            context_parts.append("\nPrevious analyses:")
            for i, analysis in enumerate(analyses[:5]):
                context_parts.append(f"  {i+1}. {analysis.get('threat_type', '?')} - {analysis.get('summary', '?')[:100]}")
        
        context = "\n".join(context_parts)
        
        system_prompt = """You are a threat intelligence analyst specializing in attack correlation and campaign analysis.
Create a unified threat profile from multiple related incidents."""
        
        prompt = f"""Create a unified threat profile from these related incidents.

Session Summary:
{context}

Provide your unified profile as a JSON object with these fields:
- campaign_name: string (descriptive name for this attack campaign)
- threat_actor_profile: object with {{sophistication: string, likely_origin: string, motivation: string}}
- common_patterns: list of attack patterns observed across sessions
- unique_identifiers: list of unique characteristics that identify this threat actor/campaign
- related_campaigns: list of potentially related known campaigns
- timeline_analysis: string describing attack progression
- infrastructure_used: list of infrastructure elements (IPs, domains, tools)
- recommended_tracking: list of indicators to track for this threat actor
- confidence: float (0.0 to 1.0)
- summary: string (comprehensive summary of the unified threat)"""
        
        response = self._generate(prompt, system_prompt)
        result = self._parse_json_response(response)
        
        if result:
            result["unified"] = True
            result["unified_at"] = datetime.now(timezone.utc).isoformat()
            result["sessions_analyzed"] = len(sessions)
            return result
        
        return {
            "unified": True,
            "unified_at": datetime.now(timezone.utc).isoformat(),
            "sessions_analyzed": len(sessions),
            "summary": response[:500] if response else "Unification failed",
            "raw_response": response,
            "parse_error": True
        }
    
    def examine_artifact(self, artifact_path: str, artifact_type: str = "unknown") -> Dict[str, Any]:
        """
        Examine a captured artifact (file) for threat indicators.
        
        Args:
            artifact_path: Path to the artifact file
            artifact_type: Type hint for the artifact
            
        Returns:
            Analysis of the artifact
        """
        if not self.is_available():
            return {"error": "LLM not available", "examined": False}
        
        try:
            # Read artifact content (limit size)
            with open(artifact_path, "rb") as f:
                content = f.read(10000)  # Limit to 10KB
            
            # Try to decode as text
            try:
                text_content = content.decode("utf-8", errors="replace")
                is_text = True
            except Exception:
                text_content = content.hex()[:2000]
                is_text = False
            
            import os
            file_size = os.path.getsize(artifact_path)
            filename = os.path.basename(artifact_path)
            
        except Exception as e:
            return {"error": f"Failed to read artifact: {e}", "examined": False}
        
        system_prompt = """You are a malware analyst specializing in examining captured files from honeypots.
Analyze the artifact content and identify potential threats."""
        
        prompt = f"""Examine this captured artifact from a honeypot.

Filename: {filename}
Type hint: {artifact_type}
Size: {file_size} bytes
Content type: {"text" if is_text else "binary (hex shown)"}

Content (first 10KB):
```
{text_content[:5000]}
```

Provide your analysis as a JSON object with these fields:
- file_type: string (your assessment of what type of file this is)
- malicious: boolean (whether this appears malicious)
- confidence: float (0.0 to 1.0)
- threat_type: string (e.g., "Script Malware", "Dropper", "Miner", "Backdoor", "Benign")
- indicators: list of indicators of compromise found in the file
- behavior_analysis: string describing what this file likely does
- static_strings: list of interesting strings extracted
- network_indicators: list of URLs, IPs, domains found
- recommendations: list of recommended actions"""
        
        response = self._generate(prompt, system_prompt)
        result = self._parse_json_response(response)
        
        if result:
            result["examined"] = True
            result["examined_at"] = datetime.now(timezone.utc).isoformat()
            result["artifact_path"] = artifact_path
            return result
        
        return {
            "examined": True,
            "examined_at": datetime.now(timezone.utc).isoformat(),
            "artifact_path": artifact_path,
            "summary": response[:500] if response else "Examination failed",
            "raw_response": response,
            "parse_error": True
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current LLM model."""
        return {
            "model": self.model,
            "available": self.is_available(),
            "ollama_host": self.ollama_host,
            "supported_models": self.SUPPORTED_MODELS
        }
