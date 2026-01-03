"""
Tests for src/agent_system.py Agent System.
"""
import pytest
import time
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta


class TestAgentSystem:
    """Tests for the Agent System."""

    @pytest.fixture
    def mock_mcp_server(self):
        """Create a mock MCP server."""
        server = MagicMock()
        server.get_tool.return_value = {
            "name": "get_ip_intel",
            "parameters": {"properties": {"ip": {"type": "string"}}}
        }
        server.execute_tool.return_value = MagicMock(
            success=True,
            data={"result": "test"},
            error=None,
            metadata={}
        )
        return server

    @pytest.fixture
    def mock_engine(self):
        """Create a mock forensic engine."""
        engine = MagicMock()
        engine.llm_analyzer = MagicMock()
        engine.llm_analyzer.is_available.return_value = False
        return engine

    @pytest.fixture
    def agent_system(self, mock_mcp_server, mock_engine):
        """Create an agent system with mocked dependencies."""
        from src.agent_system import AgentSystem
        system = AgentSystem(mcp_server=mock_mcp_server, forensic_engine=mock_engine)
        return system

    def test_agent_system_initialization(self, agent_system):
        """Test agent system initializes correctly."""
        assert agent_system.mcp_server is not None
        assert agent_system.engine is not None
        assert agent_system._running is False
        assert len(agent_system._task_templates) > 0

    def test_agent_system_start_stop(self, agent_system):
        """Test starting and stopping the agent system."""
        agent_system.start()
        assert agent_system._running is True
        assert len(agent_system._workers) > 0
        
        agent_system.stop()
        assert agent_system._running is False

    def test_get_status(self, agent_system):
        """Test getting agent system status."""
        status = agent_system.get_status()
        
        assert "running" in status
        assert "workers" in status
        assert "total_tasks" in status
        assert "tasks_by_status" in status
        assert "mcp_server_bound" in status
        assert "engine_bound" in status

    def test_get_task_templates(self, agent_system):
        """Test getting task templates."""
        templates = agent_system.get_task_templates()
        
        assert len(templates) > 0
        
        # Check for expected templates by name (the template key/identifier)
        template_names = [t["name"] for t in templates]
        assert "investigate_ip" in template_names
        assert "investigate_session" in template_names
        assert "threat_hunting" in template_names

    def test_create_task(self, agent_system):
        """Test creating a task."""
        from src.agent_system import TaskType, TaskPriority
        
        task = agent_system.create_task(
            task_type=TaskType.INVESTIGATION,
            name="Test Task",
            description="A test task",
            parameters={"ip": "8.8.8.8"},
            priority=TaskPriority.HIGH
        )
        
        assert task is not None
        assert task.name == "Test Task"
        assert task.task_type == TaskType.INVESTIGATION
        assert task.priority == TaskPriority.HIGH
        assert task.parameters == {"ip": "8.8.8.8"}
        assert task.id is not None

    def test_create_task_from_template(self, agent_system):
        """Test creating a task from a template."""
        task = agent_system.create_task_from_template(
            template_name="investigate_ip",
            parameters={"ip": "8.8.8.8"}
        )
        
        assert task is not None
        assert task.name == "IP Investigation"
        assert "ip" in task.parameters

    def test_create_task_from_invalid_template(self, agent_system):
        """Test creating task from non-existent template."""
        task = agent_system.create_task_from_template(
            template_name="nonexistent_template",
            parameters={}
        )
        
        assert task is None

    def test_get_task(self, agent_system):
        """Test getting a task by ID."""
        from src.agent_system import TaskType, TaskPriority
        
        task = agent_system.create_task(
            task_type=TaskType.INVESTIGATION,
            name="Test Task",
            description="Test",
            parameters={},
            priority=TaskPriority.NORMAL
        )
        
        retrieved = agent_system.get_task(task.id)
        
        assert retrieved is not None
        assert retrieved["id"] == task.id
        assert retrieved["name"] == "Test Task"

    def test_get_task_not_found(self, agent_system):
        """Test getting non-existent task."""
        task = agent_system.get_task("nonexistent-id")
        assert task is None

    def test_list_tasks(self, agent_system):
        """Test listing tasks."""
        from src.agent_system import TaskType, TaskPriority
        
        # Create some tasks
        agent_system.create_task(
            task_type=TaskType.INVESTIGATION,
            name="Task 1",
            description="Test",
            parameters={},
            priority=TaskPriority.NORMAL
        )
        agent_system.create_task(
            task_type=TaskType.ANALYSIS,
            name="Task 2",
            description="Test",
            parameters={},
            priority=TaskPriority.HIGH
        )
        
        tasks = agent_system.list_tasks()
        
        assert len(tasks) == 2

    def test_list_tasks_with_filter(self, agent_system):
        """Test listing tasks with filters."""
        from src.agent_system import TaskType, TaskStatus, TaskPriority
        
        # Create tasks of different types
        agent_system.create_task(
            task_type=TaskType.INVESTIGATION,
            name="Investigation Task",
            description="Test",
            parameters={},
            priority=TaskPriority.NORMAL
        )
        agent_system.create_task(
            task_type=TaskType.ANALYSIS,
            name="Analysis Task",
            description="Test",
            parameters={},
            priority=TaskPriority.NORMAL
        )
        
        # Filter by type
        investigation_tasks = agent_system.list_tasks(task_type=TaskType.INVESTIGATION)
        
        assert len(investigation_tasks) == 1
        assert investigation_tasks[0]["task_type"] == "investigation"

    def test_cancel_task(self, agent_system):
        """Test cancelling a task."""
        from src.agent_system import TaskType, TaskPriority, TaskStatus
        
        task = agent_system.create_task(
            task_type=TaskType.INVESTIGATION,
            name="Test Task",
            description="Test",
            parameters={},
            priority=TaskPriority.NORMAL
        )
        
        result = agent_system.cancel_task(task.id)
        
        assert result is True
        
        retrieved = agent_system.get_task(task.id)
        assert retrieved["status"] == TaskStatus.CANCELLED.value

    def test_cancel_nonexistent_task(self, agent_system):
        """Test cancelling non-existent task."""
        result = agent_system.cancel_task("nonexistent-id")
        assert result is False

    def test_confirm_task(self, agent_system):
        """Test confirming a task that requires confirmation."""
        from src.agent_system import TaskType, TaskPriority
        
        task = agent_system.create_task(
            task_type=TaskType.COUNTERMEASURE,
            name="Countermeasure Task",
            description="Test",
            parameters={},
            priority=TaskPriority.HIGH,
            requires_confirmation=True
        )
        
        result = agent_system.confirm_task(task.id)
        
        assert result is True
        
        retrieved = agent_system.get_task(task.id)
        assert retrieved["confirmed"] is True

    def test_confirm_nonexistent_task(self, agent_system):
        """Test confirming non-existent task."""
        result = agent_system.confirm_task("nonexistent-id")
        assert result is False

    def test_get_messages(self, agent_system):
        """Test getting agent messages."""
        from src.agent_system import TaskType, TaskPriority
        
        # Creating a task should add a message
        agent_system.create_task(
            task_type=TaskType.INVESTIGATION,
            name="Test Task",
            description="Test",
            parameters={},
            priority=TaskPriority.NORMAL
        )
        
        messages = agent_system.get_messages()
        
        assert len(messages) > 0
        assert "task_id" in messages[0]
        assert "content" in messages[0]

    def test_get_messages_with_since(self, agent_system):
        """Test getting messages filtered by timestamp."""
        from src.agent_system import TaskType, TaskPriority
        
        # Record current time
        before_time = datetime.now(timezone.utc)
        
        # Create task (adds message)
        agent_system.create_task(
            task_type=TaskType.INVESTIGATION,
            name="Test Task",
            description="Test",
            parameters={},
            priority=TaskPriority.NORMAL
        )
        
        # Get messages since before the task was created
        messages = agent_system.get_messages(since=before_time)
        
        assert len(messages) >= 1

    def test_scheduled_task_creation(self, agent_system):
        """Test creating a scheduled task."""
        from src.agent_system import TaskType, TaskPriority
        
        task = agent_system.create_task(
            task_type=TaskType.SCHEDULED,
            name="Scheduled Task",
            description="Test",
            parameters={},
            priority=TaskPriority.LOW,
            schedule_interval=60  # Every minute
        )
        
        assert task.schedule_interval == 60
        assert task.next_run is not None

    def test_bind_mcp_server(self):
        """Test binding MCP server."""
        from src.agent_system import AgentSystem
        
        system = AgentSystem()
        assert system.mcp_server is None
        
        mock_server = MagicMock()
        system.bind_mcp_server(mock_server)
        
        assert system.mcp_server is mock_server

    def test_bind_engine(self):
        """Test binding forensic engine."""
        from src.agent_system import AgentSystem
        
        system = AgentSystem()
        assert system.engine is None
        
        mock_engine = MagicMock()
        system.bind_engine(mock_engine)
        
        assert system.engine is mock_engine


class TestAgentTask:
    """Tests for AgentTask dataclass."""

    def test_agent_task_creation(self):
        """Test creating an AgentTask."""
        from src.agent_system import AgentTask, TaskType, TaskStatus, TaskPriority
        
        task = AgentTask(
            id="test-id",
            task_type=TaskType.INVESTIGATION,
            name="Test Task",
            description="Test description",
            priority=TaskPriority.HIGH,
            parameters={"key": "value"}
        )
        
        assert task.id == "test-id"
        assert task.task_type == TaskType.INVESTIGATION
        assert task.name == "Test Task"
        assert task.status == TaskStatus.PENDING
        assert task.progress == 0.0

    def test_agent_task_dict(self):
        """Test AgentTask.dict() method."""
        from src.agent_system import AgentTask, TaskType, TaskStatus, TaskPriority
        
        task = AgentTask(
            id="test-id",
            task_type=TaskType.INVESTIGATION,
            name="Test Task",
            description="Test description",
            priority=TaskPriority.HIGH,
            parameters={"key": "value"}
        )
        
        task_dict = task.dict()
        
        assert task_dict["id"] == "test-id"
        assert task_dict["task_type"] == "investigation"
        assert task_dict["priority"] == 3  # HIGH value
        assert task_dict["status"] == "pending"


class TestAgentMessage:
    """Tests for AgentMessage dataclass."""

    def test_agent_message_creation(self):
        """Test creating an AgentMessage."""
        from src.agent_system import AgentMessage
        
        message = AgentMessage(
            id="msg-id",
            task_id="task-id",
            message_type="info",
            content="Test message"
        )
        
        assert message.id == "msg-id"
        assert message.task_id == "task-id"
        assert message.message_type == "info"
        assert message.content == "Test message"

    def test_agent_message_dict(self):
        """Test AgentMessage.dict() method."""
        from src.agent_system import AgentMessage
        
        message = AgentMessage(
            id="msg-id",
            task_id="task-id",
            message_type="warning",
            content="Warning message",
            data={"extra": "info"}
        )
        
        msg_dict = message.dict()
        
        assert msg_dict["id"] == "msg-id"
        assert msg_dict["message_type"] == "warning"
        assert msg_dict["data"]["extra"] == "info"


class TestTaskEnums:
    """Tests for task-related enums."""

    def test_task_type_values(self):
        """Test TaskType enum values."""
        from src.agent_system import TaskType
        
        assert TaskType.INVESTIGATION.value == "investigation"
        assert TaskType.MONITORING.value == "monitoring"
        assert TaskType.ANALYSIS.value == "analysis"
        assert TaskType.COUNTERMEASURE.value == "countermeasure"
        assert TaskType.SCHEDULED.value == "scheduled"

    def test_task_status_values(self):
        """Test TaskStatus enum values."""
        from src.agent_system import TaskStatus
        
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.CANCELLED.value == "cancelled"
        assert TaskStatus.PAUSED.value == "paused"

    def test_task_priority_values(self):
        """Test TaskPriority enum values."""
        from src.agent_system import TaskPriority
        
        assert TaskPriority.LOW.value == 1
        assert TaskPriority.NORMAL.value == 2
        assert TaskPriority.HIGH.value == 3
        assert TaskPriority.CRITICAL.value == 4
