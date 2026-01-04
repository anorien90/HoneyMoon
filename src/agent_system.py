"""
Agent System for HoneyMoon.

Provides an autonomous agent framework that can:
- Execute background investigation tasks
- Perform active data analysis
- Recommend and execute countermeasures
- Run scheduled monitoring tasks

The agent system uses the MCP server for tool access and the LLM analyzer
for reasoning and decision making.
"""
import os
import json
import uuid
import logging
import threading
import time
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
from queue import Queue, Empty

logger = logging.getLogger(__name__)


class TaskType(Enum):
    """Types of agent tasks."""
    INVESTIGATION = "investigation"  # Active investigation of threats
    MONITORING = "monitoring"  # Background monitoring
    ANALYSIS = "analysis"  # Batch analysis tasks
    COUNTERMEASURE = "countermeasure"  # Counter-measure execution
    SCHEDULED = "scheduled"  # Recurring scheduled tasks


class TaskStatus(Enum):
    """Status of agent tasks."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class TaskPriority(Enum):
    """Priority levels for tasks."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AgentTask:
    """Definition of an agent task."""
    id: str
    task_type: TaskType
    name: str
    description: str
    priority: TaskPriority
    parameters: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    progress: float = 0.0  # 0.0 to 1.0
    requires_confirmation: bool = False
    confirmed: bool = False
    # For scheduled tasks
    schedule_interval: Optional[int] = None  # seconds
    next_run: Optional[datetime] = None
    run_count: int = 0
    # Natural language input/output support
    request_text: Optional[str] = None  # Original natural language request
    response_text: Optional[str] = None  # Natural language summary of results
    suggested_actions: Optional[List[str]] = None  # Suggested follow-up actions
    context_data: Optional[Dict[str, Any]] = None  # RAG context used for the task
    
    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "task_type": self.task_type.value,
            "name": self.name,
            "description": self.description,
            "priority": self.priority.value,
            "parameters": self.parameters,
            "status": self.status.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error": self.error,
            "progress": self.progress,
            "requires_confirmation": self.requires_confirmation,
            "confirmed": self.confirmed,
            "schedule_interval": self.schedule_interval,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "request_text": self.request_text,
            "response_text": self.response_text,
            "suggested_actions": self.suggested_actions,
            "context_data": self.context_data
        }


@dataclass
class AgentMessage:
    """Message from agent to user or system."""
    id: str
    task_id: Optional[str]
    message_type: str  # 'info', 'warning', 'error', 'finding', 'recommendation'
    content: str
    data: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "task_id": self.task_id,
            "message_type": self.message_type,
            "content": self.content,
            "data": self.data,
            "timestamp": self.timestamp.isoformat()
        }


class AgentSystem:
    """
    Agent system for autonomous security investigation and response.
    
    The agent can:
    - Run background tasks for continuous monitoring
    - Execute active investigations on demand
    - Provide recommendations for countermeasures
    - Execute approved countermeasures
    
    Tasks are persisted to the database for durability across restarts.
    """
    
    def __init__(self, mcp_server=None, forensic_engine=None, max_workers: int = 3):
        """
        Initialize the agent system.
        
        Args:
            mcp_server: Optional MCPServer instance for tool access
            forensic_engine: Optional ForensicEngine instance
            max_workers: Maximum concurrent task workers
        """
        self.mcp_server = mcp_server
        self.engine = forensic_engine
        self.max_workers = max_workers
        
        # Task management
        self._tasks: Dict[str, AgentTask] = {}
        self._task_queue: Queue = Queue()
        self._messages: List[AgentMessage] = []
        self._max_messages = 1000
        
        # Worker threads
        self._workers: List[threading.Thread] = []
        self._scheduler_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        
        # Pre-defined task templates
        self._task_templates = self._create_task_templates()
        
        # Load persisted tasks from database if engine is available
        self._load_persisted_tasks()
    
    def bind_mcp_server(self, mcp_server):
        """Bind an MCP server to the agent system."""
        self.mcp_server = mcp_server
    
    def bind_engine(self, engine):
        """Bind a forensic engine to the agent system."""
        self.engine = engine
        # Reload persisted tasks when engine is bound
        self._load_persisted_tasks()
    
    def _load_persisted_tasks(self):
        """Load persisted tasks from database on startup."""
        if not self.engine or not hasattr(self.engine, 'db'):
            return
        
        try:
            from src.entry import AgentTaskRecord
            
            # Load incomplete tasks (pending, running, paused)
            records = self.engine.db.query(AgentTaskRecord).filter(
                AgentTaskRecord.status.in_(['pending', 'running', 'paused'])
            ).all()
            
            for record in records:
                task = AgentTask(
                    id=record.id,
                    task_type=TaskType(record.task_type),
                    name=record.name,
                    description=record.description or "",
                    priority=TaskPriority(record.priority),
                    parameters=record.parameters or {},
                    status=TaskStatus(record.status),
                    created_at=record.created_at,
                    started_at=record.started_at,
                    completed_at=record.completed_at,
                    result=record.result,
                    error=record.error,
                    progress=record.progress or 0.0,
                    requires_confirmation=record.requires_confirmation,
                    confirmed=record.confirmed,
                    schedule_interval=record.schedule_interval,
                    next_run=record.next_run,
                    run_count=record.run_count or 0
                )
                
                with self._lock:
                    self._tasks[task.id] = task
                
                # Reset running tasks to pending (they were interrupted)
                if task.status == TaskStatus.RUNNING:
                    task.status = TaskStatus.PENDING
                    task.progress = 0.0
                    self._persist_task(task)
                
                logger.info("Loaded persisted task: %s (%s)", task.name, task.id)
            
            logger.info("Loaded %d persisted tasks from database", len(records))
        except Exception as e:
            logger.warning("Failed to load persisted tasks: %s", e)
    
    def _persist_task(self, task: AgentTask):
        """Persist a task to the database."""
        if not self.engine or not hasattr(self.engine, 'db'):
            return
        
        try:
            from src.entry import AgentTaskRecord
            
            record = self.engine.db.query(AgentTaskRecord).filter_by(id=task.id).first()
            
            if not record:
                record = AgentTaskRecord(
                    id=task.id,
                    task_type=task.task_type.value,
                    name=task.name,
                    description=task.description,
                    priority=task.priority.value,
                    parameters=task.parameters,
                    status=task.status.value,
                    created_at=task.created_at,
                    started_at=task.started_at,
                    completed_at=task.completed_at,
                    result=task.result,
                    error=task.error,
                    progress=task.progress,
                    requires_confirmation=task.requires_confirmation,
                    confirmed=task.confirmed,
                    schedule_interval=task.schedule_interval,
                    next_run=task.next_run,
                    run_count=task.run_count
                )
                self.engine.db.add(record)
            else:
                record.status = task.status.value
                record.started_at = task.started_at
                record.completed_at = task.completed_at
                record.result = task.result
                record.error = task.error
                record.progress = task.progress
                record.confirmed = task.confirmed
                record.next_run = task.next_run
                record.run_count = task.run_count
            
            self.engine.db.commit()
        except Exception as e:
            logger.error("Failed to persist task %s: %s", task.id, e)
            try:
                self.engine.db.rollback()
            except Exception:
                pass
    
    def _create_task_templates(self) -> Dict[str, Dict[str, Any]]:
        """Create pre-defined task templates."""
        return {
            "investigate_ip": {
                "task_type": TaskType.INVESTIGATION,
                "name": "IP Investigation",
                "description": "Comprehensive investigation of an IP address",
                "priority": TaskPriority.HIGH,
                "steps": [
                    {"tool": "get_ip_intel", "description": "Get IP intelligence"},
                    {"tool": "search_similar_attackers", "description": "Find similar attackers"},
                    {"tool": "get_web_accesses", "description": "Get web access history"},
                    {"tool": "list_honeypot_sessions", "description": "Get honeypot sessions"}
                ]
            },
            "investigate_session": {
                "task_type": TaskType.INVESTIGATION,
                "name": "Session Investigation",
                "description": "Deep investigation of a honeypot session",
                "priority": TaskPriority.HIGH,
                "steps": [
                    {"tool": "get_honeypot_session", "description": "Get session details"},
                    {"tool": "analyze_session", "description": "Analyze with LLM"},
                    {"tool": "search_similar_sessions", "description": "Find similar sessions"},
                    {"tool": "generate_threat_report", "description": "Generate report"}
                ]
            },
            "threat_hunting": {
                "task_type": TaskType.INVESTIGATION,
                "name": "Threat Hunting",
                "description": "Proactive threat hunting based on patterns",
                "priority": TaskPriority.NORMAL,
                "steps": [
                    {"tool": "search_similar_threats", "description": "Search for threats matching pattern"},
                    {"tool": "list_honeypot_sessions", "description": "Get recent sessions"},
                    {"tool": "get_live_connections", "description": "Check live connections"}
                ]
            },
            "monitor_live_activity": {
                "task_type": TaskType.MONITORING,
                "name": "Live Activity Monitor",
                "description": "Monitor live honeypot activity",
                "priority": TaskPriority.NORMAL,
                "schedule_interval": 60,  # Run every minute
                "steps": [
                    {"tool": "get_live_connections", "description": "Get live connections"}
                ]
            },
            "periodic_analysis": {
                "task_type": TaskType.SCHEDULED,
                "name": "Periodic Analysis",
                "description": "Periodic analysis of new sessions",
                "priority": TaskPriority.LOW,
                "schedule_interval": 300,  # Run every 5 minutes
                "steps": [
                    {"tool": "list_honeypot_sessions", "description": "Get recent sessions"},
                    {"tool": "analyze_session", "description": "Analyze unanalyzed sessions"}
                ]
            },
            "countermeasure_planning": {
                "task_type": TaskType.COUNTERMEASURE,
                "name": "Countermeasure Planning",
                "description": "Plan countermeasures for a threat",
                "priority": TaskPriority.HIGH,
                "requires_confirmation": True,
                "steps": [
                    {"tool": "get_threat_analysis", "description": "Get threat analysis"},
                    {"tool": "plan_countermeasures", "description": "Plan countermeasures"},
                    {"tool": "generate_detection_rules", "description": "Generate detection rules"}
                ]
            }
        }
    
    def start(self):
        """Start the agent system background workers."""
        if self._running:
            return
        
        self._running = True
        
        # Start worker threads
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"AgentWorker-{i}",
                daemon=True
            )
            worker.start()
            self._workers.append(worker)
        
        # Start scheduler thread
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name="AgentScheduler",
            daemon=True
        )
        self._scheduler_thread.start()
        
        logger.info("Agent system started with %d workers", self.max_workers)
    
    def stop(self):
        """Stop the agent system."""
        self._running = False
        
        # Wait for workers to finish
        for worker in self._workers:
            if worker.is_alive():
                worker.join(timeout=5)
        
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=5)
        
        self._workers = []
        self._scheduler_thread = None
        logger.info("Agent system stopped")
    
    def _worker_loop(self):
        """Main worker loop for processing tasks."""
        while self._running:
            try:
                task_id = self._task_queue.get(timeout=1)
                
                with self._lock:
                    task = self._tasks.get(task_id)
                    if not task or task.status != TaskStatus.PENDING:
                        continue
                    task.status = TaskStatus.RUNNING
                    task.started_at = datetime.now(timezone.utc)
                
                # Persist running status
                self._persist_task(task)
                
                try:
                    self._execute_task(task)
                    
                    with self._lock:
                        task.status = TaskStatus.COMPLETED
                        task.completed_at = datetime.now(timezone.utc)
                        task.progress = 1.0
                        # Generate natural language response
                        task.response_text = self.generate_task_response(task)
                        task.suggested_actions = self._generate_suggested_actions(task)
                    
                    # Persist completed status
                    self._persist_task(task)
                
                except Exception as e:
                    logger.error("Task %s failed: %s", task_id, e)
                    with self._lock:
                        task.status = TaskStatus.FAILED
                        task.error = str(e)
                        task.completed_at = datetime.now(timezone.utc)
                        task.response_text = f"Task failed: {str(e)}"
                    
                    # Persist failed status
                    self._persist_task(task)
                
            except Empty:
                continue
            except Exception as e:
                logger.error("Worker error: %s", e)
    
    def _scheduler_loop(self):
        """Scheduler loop for recurring tasks."""
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                
                with self._lock:
                    for task in self._tasks.values():
                        if task.schedule_interval and task.next_run:
                            if now >= task.next_run and task.status == TaskStatus.COMPLETED:
                                # Re-queue scheduled task
                                task.status = TaskStatus.PENDING
                                task.next_run = now + timedelta(seconds=task.schedule_interval)
                                task.run_count += 1
                                task.progress = 0.0
                                task.result = None
                                self._task_queue.put(task.id)
                
                time.sleep(1)
            except Exception as e:
                logger.error("Scheduler error: %s", e)
    
    def _execute_task(self, task: AgentTask):
        """Execute a task."""
        params = task.parameters
        
        # Check for task type-specific execution
        if task.task_type == TaskType.INVESTIGATION:
            self._execute_investigation(task)
        elif task.task_type == TaskType.MONITORING:
            self._execute_monitoring(task)
        elif task.task_type == TaskType.ANALYSIS:
            self._execute_analysis(task)
        elif task.task_type == TaskType.COUNTERMEASURE:
            self._execute_countermeasure(task)
        elif task.task_type == TaskType.SCHEDULED:
            self._execute_scheduled(task)
        else:
            # Generic execution using steps from parameters
            self._execute_generic(task)
    
    def _execute_investigation(self, task: AgentTask):
        """Execute an investigation task."""
        params = task.parameters
        results = {"findings": [], "recommendations": [], "tools_used": []}
        
        # Determine investigation target
        ip = params.get("ip")
        session_id = params.get("session_id")
        query = params.get("query")
        
        steps = params.get("steps", [])
        total_steps = len(steps)
        
        for i, step in enumerate(steps):
            tool_name = step.get("tool")
            tool_params = step.get("params", {})
            
            # Fill in parameters based on target - safely check if tool exists
            tool_def = self.mcp_server.get_tool(tool_name) if tool_name else None
            if tool_def:
                tool_properties = tool_def.get("parameters", {}).get("properties", {})
                if ip and "ip" in tool_properties:
                    tool_params["ip"] = ip
                if session_id and "session_id" in tool_properties:
                    tool_params["session_id"] = session_id
                if query and "query" in tool_properties:
                    tool_params["query"] = query
            
            # Execute tool
            result = self.mcp_server.execute_tool(tool_name, tool_params)
            results["tools_used"].append({
                "tool": tool_name,
                "success": result.success,
                "data": result.data if result.success else None,
                "error": result.error
            })
            
            # Update progress
            with self._lock:
                task.progress = (i + 1) / total_steps
            
            # Add findings based on results
            if result.success and result.data:
                self._extract_findings(task, result.data, results)
        
        # Generate summary using LLM if available
        if self.engine and self.engine.llm_analyzer and self.engine.llm_analyzer.is_available():
            summary = self._generate_investigation_summary(task, results)
            results["summary"] = summary
        
        with self._lock:
            task.result = results
    
    def _execute_monitoring(self, task: AgentTask):
        """Execute a monitoring task."""
        params = task.parameters
        
        # Get live connections
        result = self.mcp_server.execute_tool("get_live_connections", {
            "minutes": params.get("minutes", 15),
            "limit": params.get("limit", 100)
        })
        
        if result.success:
            data = result.data
            
            # Check for anomalies
            anomalies = self._detect_anomalies(data)
            
            if anomalies:
                self._add_message(
                    task.id,
                    "warning",
                    f"Detected {len(anomalies)} anomalies in live connections",
                    {"anomalies": anomalies}
                )
            
            with self._lock:
                task.result = {
                    "connections_checked": len(data.get("sessions", [])) + len(data.get("flows", [])),
                    "anomalies": anomalies
                }
    
    def _execute_analysis(self, task: AgentTask):
        """Execute an analysis task."""
        params = task.parameters
        session_ids = params.get("session_ids", [])
        
        results = {"analyses": [], "errors": []}
        
        for i, session_id in enumerate(session_ids):
            result = self.mcp_server.execute_tool("analyze_session", {"session_id": session_id})
            
            if result.success:
                results["analyses"].append(result.data)
            else:
                results["errors"].append({"session_id": session_id, "error": result.error})
            
            with self._lock:
                task.progress = (i + 1) / len(session_ids)
        
        with self._lock:
            task.result = results
    
    def _execute_countermeasure(self, task: AgentTask):
        """Execute a countermeasure task."""
        params = task.parameters
        
        # Countermeasures require confirmation
        if task.requires_confirmation and not task.confirmed:
            self._add_message(
                task.id,
                "warning",
                "This countermeasure task requires confirmation before execution",
                {"task_id": task.id, "action": "confirm_required"}
            )
            with self._lock:
                task.status = TaskStatus.PAUSED
            return
        
        steps = params.get("steps", [])
        results = {"actions": [], "rules_generated": []}
        
        for step in steps:
            tool_name = step.get("tool")
            tool_params = step.get("params", {})
            
            result = self.mcp_server.execute_tool(
                tool_name, 
                tool_params, 
                confirmed=task.confirmed
            )
            
            results["actions"].append({
                "tool": tool_name,
                "success": result.success,
                "data": result.data if result.success else None,
                "error": result.error
            })
        
        with self._lock:
            task.result = results
    
    def _execute_scheduled(self, task: AgentTask):
        """Execute a scheduled task."""
        # Scheduled tasks are similar to their underlying type
        params = task.parameters
        
        # Determine underlying type and execute
        if params.get("underlying_type") == "analysis":
            self._execute_analysis(task)
        elif params.get("underlying_type") == "monitoring":
            self._execute_monitoring(task)
        else:
            self._execute_generic(task)
    
    def _execute_generic(self, task: AgentTask):
        """Execute a generic task based on steps."""
        params = task.parameters
        steps = params.get("steps", [])
        results = {"steps": []}
        
        for i, step in enumerate(steps):
            tool_name = step.get("tool")
            tool_params = step.get("params", {})
            
            result = self.mcp_server.execute_tool(tool_name, tool_params)
            results["steps"].append({
                "tool": tool_name,
                "success": result.success,
                "data": result.data,
                "error": result.error
            })
            
            with self._lock:
                task.progress = (i + 1) / len(steps)
        
        with self._lock:
            task.result = results
    
    def _extract_findings(self, task: AgentTask, data: Any, results: Dict):
        """Extract findings from tool results."""
        if isinstance(data, dict):
            # Check for threats
            if data.get("threat_type"):
                results["findings"].append({
                    "type": "threat_detected",
                    "details": {
                        "threat_type": data.get("threat_type"),
                        "severity": data.get("severity"),
                        "summary": data.get("summary")
                    }
                })
            
            # Check for similar attackers
            if data.get("similar_attackers"):
                results["findings"].append({
                    "type": "similar_attackers_found",
                    "count": len(data["similar_attackers"]),
                    "details": data["similar_attackers"][:5]
                })
            
            # Check for node info
            if data.get("node"):
                node = data["node"]
                if node.get("is_tor_exit"):
                    results["findings"].append({
                        "type": "tor_exit_node",
                        "ip": node.get("ip")
                    })
    
    def _detect_anomalies(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in connection data."""
        anomalies = []
        
        sessions = data.get("sessions", [])
        flows = data.get("flows", [])
        
        # Check for high-frequency connections from same IP
        ip_counts = {}
        for session in sessions:
            ip = session.get("src_ip")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        for ip, count in ip_counts.items():
            if count > 10:
                anomalies.append({
                    "type": "high_frequency",
                    "ip": ip,
                    "count": count,
                    "message": f"IP {ip} has {count} connections in the time window"
                })
        
        return anomalies
    
    def _generate_investigation_summary(self, task: AgentTask, results: Dict) -> str:
        """Generate a summary of investigation findings.
        
        Creates a structured text summary of the investigation results.
        Note: Does not use LLM to avoid coupling with internal implementation.
        """
        findings = results.get("findings", [])
        tools_used = [t["tool"] for t in results.get("tools_used", [])]
        
        summary_parts = [f"Investigation: {task.name}"]
        
        if findings:
            summary_parts.append(f"Found {len(findings)} notable findings:")
            for finding in findings[:5]:  # Limit to first 5 findings
                finding_type = finding.get("type", "unknown")
                if finding_type == "threat_detected":
                    details = finding.get("details", {})
                    summary_parts.append(
                        f"  - Threat: {details.get('threat_type', 'Unknown')} "
                        f"(Severity: {details.get('severity', 'Unknown')})"
                    )
                elif finding_type == "similar_attackers_found":
                    summary_parts.append(f"  - Found {finding.get('count', 0)} similar attackers")
                elif finding_type == "tor_exit_node":
                    summary_parts.append(f"  - TOR exit node detected: {finding.get('ip')}")
                else:
                    summary_parts.append(f"  - {finding_type}")
        else:
            summary_parts.append("No notable findings.")
        
        if tools_used:
            summary_parts.append(f"Tools executed: {', '.join(tools_used)}")
        
        return "\n".join(summary_parts)
    
    def _add_message(self, task_id: Optional[str], msg_type: str, content: str, data: Optional[Dict] = None):
        """Add a message to the message queue."""
        message = AgentMessage(
            id=str(uuid.uuid4()),
            task_id=task_id,
            message_type=msg_type,
            content=content,
            data=data
        )
        
        with self._lock:
            self._messages.append(message)
            if len(self._messages) > self._max_messages:
                self._messages = self._messages[-self._max_messages:]
    
    # Public API methods
    
    def create_task(
        self,
        task_type: TaskType,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        requires_confirmation: bool = False,
        schedule_interval: Optional[int] = None
    ) -> AgentTask:
        """
        Create and queue a new task.
        
        Args:
            task_type: Type of task
            name: Task name
            description: Task description
            parameters: Task parameters
            priority: Task priority
            requires_confirmation: Whether task requires confirmation
            schedule_interval: Interval for recurring tasks (seconds)
            
        Returns:
            Created AgentTask
        """
        task = AgentTask(
            id=str(uuid.uuid4()),
            task_type=task_type,
            name=name,
            description=description,
            priority=priority,
            parameters=parameters,
            requires_confirmation=requires_confirmation,
            schedule_interval=schedule_interval
        )
        
        if schedule_interval:
            task.next_run = datetime.now(timezone.utc) + timedelta(seconds=schedule_interval)
        
        with self._lock:
            self._tasks[task.id] = task
        
        # Persist task to database
        self._persist_task(task)
        
        # Queue task immediately if not requiring confirmation
        if not requires_confirmation or task.confirmed:
            self._task_queue.put(task.id)
        
        self._add_message(
            task.id,
            "info",
            f"Task created: {name}",
            {"task_id": task.id, "task_type": task_type.value}
        )
        
        return task
    
    def create_task_from_template(
        self,
        template_name: str,
        parameters: Dict[str, Any],
        priority: Optional[TaskPriority] = None
    ) -> Optional[AgentTask]:
        """
        Create a task from a pre-defined template.
        
        Args:
            template_name: Name of the template
            parameters: Additional parameters
            priority: Override priority
            
        Returns:
            Created AgentTask or None if template not found
        """
        template = self._task_templates.get(template_name)
        if not template:
            return None
        
        # Merge template with provided parameters
        task_params = {**parameters}
        if template.get("steps"):
            task_params["steps"] = template["steps"]
        
        return self.create_task(
            task_type=template["task_type"],
            name=template["name"],
            description=template["description"],
            parameters=task_params,
            priority=priority or template["priority"],
            requires_confirmation=template.get("requires_confirmation", False),
            schedule_interval=template.get("schedule_interval")
        )
    
    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status and details."""
        with self._lock:
            task = self._tasks.get(task_id)
            return task.dict() if task else None
    
    def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        task_type: Optional[TaskType] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List tasks with optional filtering."""
        with self._lock:
            tasks = list(self._tasks.values())
        
        if status:
            tasks = [t for t in tasks if t.status == status]
        if task_type:
            tasks = [t for t in tasks if t.task_type == task_type]
        
        # Sort by priority (desc) then created_at (desc)
        tasks.sort(key=lambda t: (-t.priority.value, t.created_at), reverse=True)
        
        return [t.dict() for t in tasks[:limit]]
    
    def confirm_task(self, task_id: str) -> bool:
        """Confirm a task that requires confirmation."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            
            if task.requires_confirmation and not task.confirmed:
                task.confirmed = True
                if task.status == TaskStatus.PAUSED:
                    task.status = TaskStatus.PENDING
                    self._task_queue.put(task.id)
                return True
            
            return False
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            
            if task.status in (TaskStatus.PENDING, TaskStatus.PAUSED):
                task.status = TaskStatus.CANCELLED
                return True
            
            return False
    
    def get_messages(self, since: Optional[datetime] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get agent messages."""
        with self._lock:
            messages = self._messages.copy()
        
        if since:
            messages = [m for m in messages if m.timestamp > since]
        
        return [m.dict() for m in messages[-limit:]]
    
    def get_task_templates(self) -> List[Dict[str, Any]]:
        """Get available task templates."""
        return [
            {
                "name": name,
                "task_type": template["task_type"].value,
                "description": template["description"],
                "priority": template["priority"].value,
                "requires_confirmation": template.get("requires_confirmation", False),
                "schedule_interval": template.get("schedule_interval")
            }
            for name, template in self._task_templates.items()
        ]
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent system status."""
        with self._lock:
            tasks_by_status = {}
            for task in self._tasks.values():
                status = task.status.value
                tasks_by_status[status] = tasks_by_status.get(status, 0) + 1
        
        return {
            "running": self._running,
            "workers": len(self._workers),
            "total_tasks": len(self._tasks),
            "tasks_by_status": tasks_by_status,
            "pending_messages": len(self._messages),
            "mcp_server_bound": self.mcp_server is not None,
            "engine_bound": self.engine is not None
        }
    
    # ============================================
    # NATURAL LANGUAGE TASK PROCESSING
    # ============================================
    
    def create_task_from_natural_language(
        self,
        request_text: str,
        context_type: Optional[str] = None,
        context_id: Optional[str] = None
    ) -> Optional[AgentTask]:
        """
        Create a task from a natural language request.
        
        Uses LLM to interpret the user's intent and create appropriate task.
        
        Args:
            request_text: Natural language description of what the user wants
            context_type: Optional context type (session, node, threat, cluster)
            context_id: Optional context ID
            
        Returns:
            Created AgentTask with natural language response
        """
        if not self.mcp_server:
            return None
        
        # Parse the natural language request to determine task type and parameters
        parsed = self._parse_natural_language_request(request_text, context_type, context_id)
        
        if not parsed:
            return None
        
        # Create the task with NL fields
        task = AgentTask(
            id=str(uuid.uuid4()),
            task_type=parsed["task_type"],
            name=parsed["name"],
            description=parsed["description"],
            priority=parsed["priority"],
            parameters=parsed["parameters"],
            requires_confirmation=parsed.get("requires_confirmation", False),
            request_text=request_text,
            context_data=parsed.get("context_data")
        )
        
        with self._lock:
            self._tasks[task.id] = task
        
        # Persist task to database
        self._persist_task(task)
        
        # Queue task if not requiring confirmation
        if not task.requires_confirmation:
            self._task_queue.put(task.id)
        
        self._add_message(
            task.id,
            "info",
            f"Task created from request: {request_text[:100]}...",
            {"task_id": task.id, "task_type": task.task_type.value, "parsed": parsed}
        )
        
        return task
    
    def _parse_natural_language_request(
        self,
        request_text: str,
        context_type: Optional[str] = None,
        context_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a natural language request into task parameters.
        
        Uses pattern matching and optional LLM for complex requests.
        """
        request_lower = request_text.lower().strip()
        
        # Get RAG context if MCP server is available
        context_data = None
        if self.mcp_server:
            try:
                context_data = self.mcp_server.get_context_for_query(request_text, limit=3)
            except Exception:
                pass
        
        # Pattern matching for common request types
        parsed = None
        
        # Investigation patterns
        if any(kw in request_lower for kw in ['investigate', 'look into', 'examine', 'check out']):
            parsed = self._parse_investigation_request(request_text, request_lower)
        
        # Analysis patterns
        elif any(kw in request_lower for kw in ['analyze', 'analysis', 'assess', 'evaluate']):
            parsed = self._parse_analysis_request(request_text, request_lower)
        
        # Search/find patterns
        elif any(kw in request_lower for kw in ['find', 'search', 'look for', 'similar', 'like']):
            parsed = self._parse_search_request(request_text, request_lower)
        
        # Threat hunting patterns
        elif any(kw in request_lower for kw in ['hunt', 'threat hunt', 'proactive']):
            parsed = self._parse_threat_hunt_request(request_text, request_lower)
        
        # Monitoring patterns
        elif any(kw in request_lower for kw in ['monitor', 'watch', 'observe', 'track']):
            parsed = self._parse_monitoring_request(request_text, request_lower)
        
        # Countermeasure patterns
        elif any(kw in request_lower for kw in ['countermeasure', 'defend', 'protect', 'block', 'mitigate']):
            parsed = self._parse_countermeasure_request(request_text, request_lower)
        
        # Report generation patterns
        elif any(kw in request_lower for kw in ['report', 'summary', 'document', 'formal']):
            parsed = self._parse_report_request(request_text, request_lower)
        
        # Default to investigation if context provided
        elif context_type and context_id:
            parsed = self._parse_context_request(request_text, context_type, context_id)
        
        # Generic task as fallback
        if not parsed:
            parsed = {
                "task_type": TaskType.INVESTIGATION,
                "name": f"Custom Request: {request_text[:50]}",
                "description": request_text,
                "priority": TaskPriority.NORMAL,
                "parameters": {"query": request_text},
                "steps": [{"tool": "search_similar_sessions", "params": {"query": request_text}}]
            }
        
        # Add context data if available
        if context_data:
            parsed["context_data"] = context_data
            parsed["parameters"]["context"] = context_data
        
        return parsed
    
    def _parse_investigation_request(self, request_text: str, request_lower: str) -> Dict[str, Any]:
        """Parse investigation-related requests."""
        import re
        
        # Check for IP address
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', request_text)
        if ip_match:
            ip = ip_match.group(0)
            return {
                "task_type": TaskType.INVESTIGATION,
                "name": f"IP Investigation: {ip}",
                "description": f"Investigating IP address {ip}",
                "priority": TaskPriority.HIGH,
                "parameters": {"ip": ip},
                "steps": [
                    {"tool": "get_ip_intel", "params": {"ip": ip}},
                    {"tool": "search_similar_attackers", "params": {"ip": ip}},
                    {"tool": "get_web_accesses", "params": {"ip": ip}},
                    {"tool": "list_honeypot_sessions", "params": {"ip_filter": ip}}
                ]
            }
        
        # Check for session ID
        session_match = re.search(r'session\s*(?:#|id:?)?\s*(\d+)', request_lower)
        if session_match:
            session_id = int(session_match.group(1))
            return {
                "task_type": TaskType.INVESTIGATION,
                "name": f"Session Investigation: #{session_id}",
                "description": f"Investigating honeypot session {session_id}",
                "priority": TaskPriority.HIGH,
                "parameters": {"session_id": session_id},
                "steps": [
                    {"tool": "get_honeypot_session", "params": {"session_id": session_id}},
                    {"tool": "analyze_session", "params": {"session_id": session_id}},
                    {"tool": "search_similar_sessions", "params": {"session_id": session_id}}
                ]
            }
        
        # Generic investigation
        return {
            "task_type": TaskType.INVESTIGATION,
            "name": "General Investigation",
            "description": request_text,
            "priority": TaskPriority.NORMAL,
            "parameters": {"query": request_text},
            "steps": [{"tool": "search_similar_sessions", "params": {"query": request_text}}]
        }
    
    def _parse_analysis_request(self, request_text: str, request_lower: str) -> Dict[str, Any]:
        """Parse analysis-related requests."""
        import re
        
        session_match = re.search(r'session\s*(?:#|id:?)?\s*(\d+)', request_lower)
        if session_match:
            session_id = int(session_match.group(1))
            return {
                "task_type": TaskType.ANALYSIS,
                "name": f"Session Analysis: #{session_id}",
                "description": f"Analyzing honeypot session {session_id}",
                "priority": TaskPriority.NORMAL,
                "parameters": {"session_id": session_id},
                "steps": [
                    {"tool": "analyze_session", "params": {"session_id": session_id, "save_result": True}}
                ]
            }
        
        return {
            "task_type": TaskType.ANALYSIS,
            "name": "Custom Analysis",
            "description": request_text,
            "priority": TaskPriority.NORMAL,
            "parameters": {"query": request_text},
            "steps": []
        }
    
    def _parse_search_request(self, request_text: str, request_lower: str) -> Dict[str, Any]:
        """Parse search-related requests."""
        import re
        
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', request_text)
        if ip_match and 'similar' in request_lower:
            ip = ip_match.group(0)
            return {
                "task_type": TaskType.INVESTIGATION,
                "name": f"Find Similar Attackers: {ip}",
                "description": f"Finding attackers similar to {ip}",
                "priority": TaskPriority.NORMAL,
                "parameters": {"ip": ip},
                "steps": [{"tool": "search_similar_attackers", "params": {"ip": ip}}]
            }
        
        # Generic search
        query = request_text
        for prefix in ['find', 'search', 'search for', 'look for', 'similar to']:
            if request_lower.startswith(prefix):
                query = request_text[len(prefix):].strip()
                break
        
        return {
            "task_type": TaskType.INVESTIGATION,
            "name": f"Search: {query[:50]}",
            "description": f"Searching for: {query}",
            "priority": TaskPriority.NORMAL,
            "parameters": {"query": query},
            "steps": [
                {"tool": "search_similar_sessions", "params": {"query": query}},
                {"tool": "search_similar_threats", "params": {"query": query}}
            ]
        }
    
    def _parse_threat_hunt_request(self, request_text: str, request_lower: str) -> Dict[str, Any]:
        """Parse threat hunting requests."""
        query = request_text
        for prefix in ['hunt for', 'threat hunt', 'hunt']:
            if request_lower.startswith(prefix):
                query = request_text[len(prefix):].strip()
                break
        
        return {
            "task_type": TaskType.INVESTIGATION,
            "name": f"Threat Hunt: {query[:50]}",
            "description": f"Hunting for threats: {query}",
            "priority": TaskPriority.HIGH,
            "parameters": {"query": query},
            "steps": [
                {"tool": "search_similar_threats", "params": {"query": query}},
                {"tool": "list_honeypot_sessions", "params": {"limit": 50}},
                {"tool": "get_live_connections", "params": {"minutes": 30}}
            ]
        }
    
    def _parse_monitoring_request(self, request_text: str, request_lower: str) -> Dict[str, Any]:
        """Parse monitoring requests."""
        import re
        
        # Check for time specification
        minutes = 15
        time_match = re.search(r'(\d+)\s*(?:min(?:ute)?s?|hr?|hour)', request_lower)
        if time_match:
            val = int(time_match.group(1))
            if 'hour' in time_match.group(0) or 'hr' in time_match.group(0):
                minutes = val * 60
            else:
                minutes = val
        
        return {
            "task_type": TaskType.MONITORING,
            "name": "Live Activity Monitor",
            "description": f"Monitoring live activity for {minutes} minutes",
            "priority": TaskPriority.NORMAL,
            "parameters": {"minutes": minutes},
            "steps": [{"tool": "get_live_connections", "params": {"minutes": minutes}}]
        }
    
    def _parse_countermeasure_request(self, request_text: str, request_lower: str) -> Dict[str, Any]:
        """Parse countermeasure requests."""
        import re
        
        session_match = re.search(r'session\s*(?:#|id:?)?\s*(\d+)', request_lower)
        if session_match:
            session_id = int(session_match.group(1))
            return {
                "task_type": TaskType.COUNTERMEASURE,
                "name": f"Countermeasure Planning: Session #{session_id}",
                "description": f"Planning countermeasures for session {session_id}",
                "priority": TaskPriority.HIGH,
                "requires_confirmation": True,
                "parameters": {"session_id": session_id},
                "steps": [
                    {"tool": "analyze_session", "params": {"session_id": session_id}},
                    {"tool": "recommend_active_countermeasures", "params": {"session_id": session_id}},
                    {"tool": "generate_detection_rules", "params": {"session_id": session_id}}
                ]
            }
        
        return {
            "task_type": TaskType.COUNTERMEASURE,
            "name": "Countermeasure Planning",
            "description": request_text,
            "priority": TaskPriority.HIGH,
            "requires_confirmation": True,
            "parameters": {"query": request_text},
            "steps": []
        }
    
    def _parse_report_request(self, request_text: str, request_lower: str) -> Dict[str, Any]:
        """Parse report generation requests."""
        import re
        
        session_match = re.search(r'session\s*(?:#|id:?)?\s*(\d+)', request_lower)
        if session_match:
            session_id = int(session_match.group(1))
            return {
                "task_type": TaskType.ANALYSIS,
                "name": f"Formal Report: Session #{session_id}",
                "description": f"Generating formal report for session {session_id}",
                "priority": TaskPriority.NORMAL,
                "parameters": {"session_id": session_id},
                "steps": [
                    {"tool": "generate_threat_report", "params": {"session_id": session_id}}
                ]
            }
        
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', request_text)
        if ip_match:
            ip = ip_match.group(0)
            return {
                "task_type": TaskType.ANALYSIS,
                "name": f"Node Report: {ip}",
                "description": f"Generating report for node {ip}",
                "priority": TaskPriority.NORMAL,
                "parameters": {"ip": ip},
                "steps": [
                    {"tool": "generate_node_report", "params": {"ip": ip}}
                ]
            }
        
        return {
            "task_type": TaskType.ANALYSIS,
            "name": "Custom Report",
            "description": request_text,
            "priority": TaskPriority.NORMAL,
            "parameters": {"query": request_text},
            "steps": []
        }
    
    def _parse_context_request(
        self,
        request_text: str,
        context_type: str,
        context_id: str
    ) -> Dict[str, Any]:
        """Parse request with specific context."""
        if context_type == "session":
            session_id = int(context_id)
            return {
                "task_type": TaskType.INVESTIGATION,
                "name": f"Session Context: #{session_id}",
                "description": f"{request_text} (for session {session_id})",
                "priority": TaskPriority.NORMAL,
                "parameters": {"session_id": session_id, "query": request_text},
                "steps": [
                    {"tool": "get_honeypot_session", "params": {"session_id": session_id}},
                    {"tool": "analyze_session", "params": {"session_id": session_id}}
                ]
            }
        
        elif context_type == "node":
            return {
                "task_type": TaskType.INVESTIGATION,
                "name": f"Node Context: {context_id}",
                "description": f"{request_text} (for node {context_id})",
                "priority": TaskPriority.NORMAL,
                "parameters": {"ip": context_id, "query": request_text},
                "steps": [
                    {"tool": "get_ip_intel", "params": {"ip": context_id}},
                    {"tool": "search_similar_attackers", "params": {"ip": context_id}}
                ]
            }
        
        return {
            "task_type": TaskType.INVESTIGATION,
            "name": f"Context Request: {context_type}",
            "description": request_text,
            "priority": TaskPriority.NORMAL,
            "parameters": {"context_type": context_type, "context_id": context_id, "query": request_text},
            "steps": []
        }
    
    def generate_task_response(self, task: AgentTask) -> str:
        """
        Generate a natural language response for a completed task.
        
        Args:
            task: The completed task
            
        Returns:
            Natural language summary of task results
        """
        if task.status != TaskStatus.COMPLETED:
            return f"Task '{task.name}' is {task.status.value}."
        
        if not task.result:
            return f"Task '{task.name}' completed but produced no results."
        
        result = task.result
        response_parts = [f"**{task.name}** completed successfully."]
        
        # Generate response based on task type
        if task.task_type == TaskType.INVESTIGATION:
            response_parts.extend(self._format_investigation_response(result))
        elif task.task_type == TaskType.ANALYSIS:
            response_parts.extend(self._format_analysis_response(result))
        elif task.task_type == TaskType.MONITORING:
            response_parts.extend(self._format_monitoring_response(result))
        elif task.task_type == TaskType.COUNTERMEASURE:
            response_parts.extend(self._format_countermeasure_response(result))
        else:
            response_parts.append(f"Results: {len(result)} items.")
        
        # Add suggested actions
        suggested = self._generate_suggested_actions(task)
        if suggested:
            response_parts.append("\n**Suggested next steps:**")
            for action in suggested[:5]:
                response_parts.append(f"• {action}")
        
        return "\n".join(response_parts)
    
    def _format_investigation_response(self, result: Dict[str, Any]) -> List[str]:
        """Format investigation results for natural language response."""
        parts = []
        
        findings = result.get("findings", [])
        if findings:
            parts.append(f"\n**Findings ({len(findings)}):**")
            for finding in findings[:5]:
                finding_type = finding.get("type", "unknown")
                if finding_type == "threat_detected":
                    details = finding.get("details", {})
                    parts.append(f"• Threat detected: {details.get('threat_type', 'Unknown')} (Severity: {details.get('severity', 'Unknown')})")
                elif finding_type == "similar_attackers_found":
                    parts.append(f"• Found {finding.get('count', 0)} similar attackers")
                elif finding_type == "tor_exit_node":
                    parts.append(f"• TOR exit node detected: {finding.get('ip')}")
                else:
                    parts.append(f"• {finding_type}")
        
        recommendations = result.get("recommendations", [])
        if recommendations:
            parts.append(f"\n**Recommendations:**")
            for rec in recommendations[:3]:
                parts.append(f"• {rec}")
        
        tools_used = result.get("tools_used", [])
        if tools_used:
            successful = [t for t in tools_used if t.get("success")]
            parts.append(f"\nExecuted {len(successful)}/{len(tools_used)} tools successfully.")
        
        if result.get("summary"):
            parts.append(f"\n**Summary:**\n{result['summary']}")
        
        return parts
    
    def _format_analysis_response(self, result: Dict[str, Any]) -> List[str]:
        """Format analysis results for natural language response."""
        parts = []
        
        if result.get("threat_type"):
            parts.append(f"\n**Threat Type:** {result['threat_type']}")
        if result.get("severity"):
            parts.append(f"**Severity:** {result['severity']}")
        if result.get("confidence"):
            parts.append(f"**Confidence:** {int(result['confidence'] * 100)}%")
        if result.get("summary"):
            parts.append(f"\n**Summary:**\n{result['summary']}")
        
        tactics = result.get("tactics", [])
        if tactics:
            parts.append(f"\n**MITRE ATT&CK Tactics:** {', '.join(tactics)}")
        
        techniques = result.get("techniques", [])
        if techniques:
            parts.append(f"**Techniques:** {', '.join(techniques[:5])}")
        
        return parts
    
    def _format_monitoring_response(self, result: Dict[str, Any]) -> List[str]:
        """Format monitoring results for natural language response."""
        parts = []
        
        connections = result.get("connections_checked", 0)
        if connections:
            parts.append(f"\n**Connections Checked:** {connections}")
        
        anomalies = result.get("anomalies", [])
        if anomalies:
            parts.append(f"\n**⚠️ Anomalies Detected ({len(anomalies)}):**")
            for anomaly in anomalies[:5]:
                parts.append(f"• {anomaly.get('message', anomaly.get('type', 'Unknown anomaly'))}")
        else:
            parts.append("\nNo anomalies detected.")
        
        return parts
    
    def _format_countermeasure_response(self, result: Dict[str, Any]) -> List[str]:
        """Format countermeasure results for natural language response."""
        parts = []
        
        actions = result.get("actions", [])
        if actions:
            successful = [a for a in actions if a.get("success")]
            parts.append(f"\n**Actions Executed:** {len(successful)}/{len(actions)} successful")
        
        rules = result.get("rules_generated", [])
        if rules:
            parts.append(f"**Detection Rules Generated:** {len(rules)}")
        
        return parts
    
    def _generate_suggested_actions(self, task: AgentTask) -> List[str]:
        """Generate suggested follow-up actions based on task results."""
        suggestions = []
        result = task.result or {}
        
        # Investigation suggestions
        if task.task_type == TaskType.INVESTIGATION:
            findings = result.get("findings", [])
            for finding in findings[:3]:
                if finding.get("type") == "threat_detected":
                    suggestions.append("Generate a formal threat report")
                    suggestions.append("Plan countermeasures for this threat")
                elif finding.get("type") == "similar_attackers_found":
                    suggestions.append("Investigate similar attackers in detail")
                    suggestions.append("Create an attacker cluster for tracking")
        
        # Analysis suggestions
        elif task.task_type == TaskType.ANALYSIS:
            if result.get("severity") in ["critical", "high"]:
                suggestions.append("Immediately review and plan countermeasures")
                suggestions.append("Generate detection rules to prevent similar attacks")
            if result.get("indicators"):
                suggestions.append("Add indicators to blocklist")
        
        # Monitoring suggestions
        elif task.task_type == TaskType.MONITORING:
            anomalies = result.get("anomalies", [])
            if anomalies:
                suggestions.append("Investigate anomalous IPs")
                for anomaly in anomalies[:2]:
                    if anomaly.get("ip"):
                        suggestions.append(f"Investigate IP {anomaly['ip']}")
        
        # General suggestions
        if not suggestions:
            suggestions = [
                "Search for similar patterns",
                "Generate a detailed report",
                "Set up monitoring for this threat type"
            ]
        
        return suggestions
    
    def update_task_response(self, task_id: str) -> bool:
        """
        Update a task's natural language response after completion.
        
        Args:
            task_id: ID of the task to update
            
        Returns:
            True if updated successfully
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            
            if task.status == TaskStatus.COMPLETED:
                task.response_text = self.generate_task_response(task)
                task.suggested_actions = self._generate_suggested_actions(task)
                return True
        
        return False
