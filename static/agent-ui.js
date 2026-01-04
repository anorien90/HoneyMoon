// Agent System UI module
// Provides interface for agent tasks, templates, and messages

import { apiGet, apiPost } from './api.js';
import { escapeHtml } from './util.js';
import * as ui from './ui.js';

const $ = id => document.getElementById(id);

// ============================================
// CONSTANTS
// ============================================

const MAX_MESSAGES_DISPLAY = 20;
const DEFAULT_TASK_LIMIT = 50;
const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds

// ============================================
// AGENT STATUS
// ============================================

export async function refreshAgentStatus() {
  try {
    const res = await apiGet('/api/v1/agent/status');
    if (!res.ok) {
      updateAgentStatusUI(null, res.error);
      return;
    }
    updateAgentStatusUI(res.data);
  } catch (err) {
    console.error('Failed to refresh agent status:', err);
    updateAgentStatusUI(null, 'Connection error');
  }
}

function updateAgentStatusUI(status, error = null) {
  const runningEl = $('agentRunningStatus');
  const workersEl = $('agentWorkerCount');
  const tasksEl = $('agentTaskCount');
  
  if (error || !status) {
    if (runningEl) runningEl.innerHTML = `<span style="color: #ef4444;">❌ ${escapeHtml(error || 'Unavailable')}</span>`;
    if (workersEl) workersEl.textContent = '—';
    if (tasksEl) tasksEl.textContent = '—';
    return;
  }
  
  if (runningEl) {
    runningEl.innerHTML = status.running 
      ? '<span style="color: #10b981;">✅ Running</span>'
      : '<span style="color: #f59e0b;">⚠️ Stopped</span>';
  }
  if (workersEl) workersEl.textContent = status.workers || 0;
  if (tasksEl) {
    const total = status.total_tasks || 0;
    const byStatus = status.tasks_by_status || {};
    const pending = byStatus.pending || 0;
    const running = byStatus.running || 0;
    tasksEl.textContent = `${total} (${pending} pending, ${running} running)`;
  }
}

// ============================================
// AGENT TASKS
// ============================================

export async function listAgentTasks(limit = 50) {
  try {
    const res = await apiGet(`/api/v1/agent/tasks?limit=${limit}`);
    if (!res.ok) {
      ui.toast(res.error || 'Failed to list tasks');
      return;
    }
    renderTasksList(res.data.tasks || []);
  } catch (err) {
    console.error('Failed to list agent tasks:', err);
    ui.toast('Failed to list tasks');
  }
}

function renderTasksList(tasks) {
  const container = $('agentTasksList');
  if (!container) return;
  
  if (!tasks.length) {
    container.innerHTML = '<div class="muted">No tasks</div>';
    return;
  }
  
  const frag = document.createDocumentFragment();
  tasks.forEach(task => {
    const div = document.createElement('div');
    div.className = 'py-1 border-b clickable task-row';
    div.dataset.taskId = task.id;
    
    const statusIcon = getStatusIcon(task.status);
    const priorityBadge = getPriorityBadge(task.priority);
    const progress = task.progress ? `${Math.round(task.progress * 100)}%` : '';
    
    div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          <span>${statusIcon}</span>
          <strong>${escapeHtml(task.name)}</strong>
          ${priorityBadge}
        </div>
        <span class="muted">${escapeHtml(task.task_type)}</span>
      </div>
      <div class="muted small">${escapeHtml(task.description || '')} ${progress ? `• ${progress}` : ''}</div>
      ${task.requires_confirmation && !task.confirmed ? '<button class="confirm-task-btn small" style="background: #f59e0b; color: white; margin-top: 4px;">Confirm</button>' : ''}
    `;
    frag.appendChild(div);
  });
  
  container.innerHTML = '';
  container.appendChild(frag);
}

function getStatusIcon(status) {
  switch (status) {
    case 'pending': return '⏳';
    case 'running': return '🔄';
    case 'completed': return '✅';
    case 'failed': return '❌';
    case 'cancelled': return '🚫';
    case 'paused': return '⏸️';
    default: return '❓';
  }
}

function getPriorityBadge(priority) {
  switch (priority) {
    case 4: return '<span style="background: #ef4444; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">CRITICAL</span>';
    case 3: return '<span style="background: #f59e0b; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">HIGH</span>';
    case 2: return '';
    case 1: return '<span style="background: #6b7280; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">LOW</span>';
    default: return '';
  }
}

export async function getTaskDetails(taskId) {
  try {
    const res = await apiGet(`/api/v1/agent/task?id=${encodeURIComponent(taskId)}`);
    if (!res.ok) {
      ui.toast(res.error || 'Failed to get task details');
      return null;
    }
    return res.data.task;
  } catch (err) {
    console.error('Failed to get task details:', err);
    ui.toast('Failed to get task details');
    return null;
  }
}

export async function confirmTask(taskId) {
  try {
    const res = await apiPost('/api/v1/agent/task/confirm', { task_id: taskId });
    if (!res.ok) {
      ui.toast(res.error || 'Failed to confirm task');
      return false;
    }
    ui.toast('Task confirmed');
    listAgentTasks();
    return true;
  } catch (err) {
    console.error('Failed to confirm task:', err);
    ui.toast('Failed to confirm task');
    return false;
  }
}

export async function cancelTask(taskId) {
  try {
    const res = await apiPost('/api/v1/agent/task/cancel', { task_id: taskId });
    if (!res.ok) {
      ui.toast(res.error || 'Failed to cancel task');
      return false;
    }
    ui.toast('Task cancelled');
    listAgentTasks();
    return true;
  } catch (err) {
    console.error('Failed to cancel task:', err);
    ui.toast('Failed to cancel task');
    return false;
  }
}

// ============================================
// TASK TEMPLATES
// ============================================

export async function listTaskTemplates() {
  try {
    const res = await apiGet('/api/v1/agent/templates');
    if (!res.ok) {
      ui.toast(res.error || 'Failed to list templates');
      return;
    }
    renderTemplatesList(res.data.templates || []);
  } catch (err) {
    console.error('Failed to list task templates:', err);
    ui.toast('Failed to list templates');
  }
}

function renderTemplatesList(templates) {
  const container = $('agentTemplatesList');
  if (!container) return;
  
  if (!templates.length) {
    container.innerHTML = '<div class="muted">No templates available</div>';
    return;
  }
  
  const frag = document.createDocumentFragment();
  templates.forEach(template => {
    const div = document.createElement('div');
    div.className = 'py-1 border-b clickable template-row';
    div.dataset.templateName = template.name;
    
    const scheduleInfo = template.schedule_interval 
      ? ` (every ${template.schedule_interval}s)` 
      : '';
    
    div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <strong>${escapeHtml(template.name)}</strong>
        <span class="muted small">${escapeHtml(template.task_type)}${scheduleInfo}</span>
      </div>
      <div class="muted small">${escapeHtml(template.description)}</div>
    `;
    frag.appendChild(div);
  });
  
  container.innerHTML = '';
  container.appendChild(frag);
}

export async function createTaskFromTemplate(templateName, parameters = {}, priority = null) {
  try {
    const body = { template: templateName, parameters };
    if (priority) body.priority = priority;
    
    const res = await apiPost('/api/v1/agent/task/template', body);
    if (!res.ok) {
      ui.toast(res.error || 'Failed to create task');
      return null;
    }
    ui.toast(`Task created: ${res.data.task?.name || templateName}`);
    listAgentTasks();
    return res.data.task;
  } catch (err) {
    console.error('Failed to create task from template:', err);
    ui.toast('Failed to create task');
    return null;
  }
}

// ============================================
// AGENT MESSAGES
// ============================================

export async function getAgentMessages(limit = 50) {
  try {
    const res = await apiGet(`/api/v1/agent/messages?limit=${limit}`);
    if (!res.ok) {
      return [];
    }
    renderMessagesList(res.data.messages || []);
    return res.data.messages || [];
  } catch (err) {
    console.error('Failed to get agent messages:', err);
    return [];
  }
}

function renderMessagesList(messages) {
  const container = $('agentMessagesList');
  if (!container) return;
  
  if (!messages.length) {
    container.innerHTML = '<div class="muted">No messages</div>';
    return;
  }
  
  const frag = document.createDocumentFragment();
  messages.slice(0, MAX_MESSAGES_DISPLAY).reverse().forEach(msg => {
    const div = document.createElement('div');
    div.className = `py-1 border-b message-row message-${msg.message_type}`;
    
    const icon = getMessageIcon(msg.message_type);
    const time = new Date(msg.timestamp).toLocaleTimeString();
    
    div.innerHTML = `
      <div style="display: flex; gap: 4px; align-items: center;">
        <span>${icon}</span>
        <span class="muted small">${time}</span>
      </div>
      <div class="small">${escapeHtml(msg.content)}</div>
    `;
    frag.appendChild(div);
  });
  
  container.innerHTML = '';
  container.appendChild(frag);
}

function getMessageIcon(type) {
  switch (type) {
    case 'info': return 'ℹ️';
    case 'warning': return '⚠️';
    case 'error': return '❌';
    case 'finding': return '🔍';
    case 'recommendation': return '💡';
    default: return '📝';
  }
}

// ============================================
// QUICK ACTIONS
// ============================================

export async function investigateIP(ip) {
  if (!ip) {
    ip = prompt('Enter IP address to investigate:');
    if (!ip) return;
  }
  
  try {
    const res = await apiPost('/api/v1/agent/task/template', {
      template: 'investigate_ip',
      parameters: { ip },
      priority: 'high'
    });
    
    if (!res.ok) {
      ui.toast(res.error || 'Failed to start investigation');
      return;
    }
    
    ui.toast(`Started investigation of ${ip}`);
    listAgentTasks();
  } catch (err) {
    console.error('Failed to start investigation:', err);
    ui.toast('Failed to start investigation');
  }
}

export async function startThreatHunt(query) {
  if (!query) {
    query = prompt('Enter threat pattern to hunt (e.g., "brute force", "cryptominer"):');
    if (!query) return;
  }
  
  try {
    const res = await apiPost('/api/v1/agent/task/template', {
      template: 'threat_hunting',
      parameters: { query },
      priority: 'normal'
    });
    
    if (!res.ok) {
      ui.toast(res.error || 'Failed to start threat hunt');
      return;
    }
    
    ui.toast(`Started threat hunting for: ${query}`);
    listAgentTasks();
  } catch (err) {
    console.error('Failed to start threat hunt:', err);
    ui.toast('Failed to start threat hunt');
  }
}

export async function startLiveMonitor(minutes = 15) {
  try {
    const res = await apiPost('/api/v1/agent/task/template', {
      template: 'monitor_live_activity',
      parameters: { minutes },
      priority: 'normal'
    });
    
    if (!res.ok) {
      ui.toast(res.error || 'Failed to start monitor');
      return;
    }
    
    ui.toast('Started live activity monitor');
    listAgentTasks();
  } catch (err) {
    console.error('Failed to start monitor:', err);
    ui.toast('Failed to start monitor');
  }
}

// ============================================
// INITIALIZATION
// ============================================

export function initAgentUI() {
  // Refresh button
  $('agentRefreshBtn')?.addEventListener('click', async () => {
    await refreshAgentStatus();
    await listAgentTasks();
    await getAgentMessages();
  });
  
  // Quick action buttons
  $('agentInvestigateBtn')?.addEventListener('click', () => {
    const ip = $('ipInput')?.value?.trim() || '';
    investigateIP(ip);
  });
  
  $('agentThreatHuntBtn')?.addEventListener('click', () => {
    startThreatHunt();
  });
  
  $('agentMonitorBtn')?.addEventListener('click', () => {
    startLiveMonitor();
  });
  
  // Natural language task button - add dynamically to the quick actions
  const quickActionsDiv = document.querySelector('#agentCard .card-body > div:nth-child(3)');
  if (quickActionsDiv) {
    const nlBtn = document.createElement('button');
    nlBtn.id = 'agentNaturalTaskBtn';
    nlBtn.className = 'small';
    nlBtn.style.cssText = 'background: #6366f1; color: white;';
    nlBtn.innerHTML = '🤖 Ask Agent';
    nlBtn.title = 'Create task from natural language';
    nlBtn.addEventListener('click', () => showNaturalLanguageTaskModal());
    quickActionsDiv.appendChild(nlBtn);
  }
  
  // Task row click handler
  document.addEventListener('click', async (e) => {
    // Confirm button
    const confirmBtn = e.target.closest('.confirm-task-btn');
    if (confirmBtn) {
      const taskRow = confirmBtn.closest('.task-row');
      if (taskRow?.dataset.taskId) {
        await confirmTask(taskRow.dataset.taskId);
      }
      return;
    }
    
    // Task row click (show details)
    const taskRow = e.target.closest('.task-row');
    if (taskRow?.dataset.taskId) {
      const task = await getTaskDetails(taskRow.dataset.taskId);
      if (task) {
        showTaskDetailsModal(task);
      }
      return;
    }
    
    // Template row click (create task)
    const templateRow = e.target.closest('.template-row');
    if (templateRow?.dataset.templateName) {
      showCreateTaskModal(templateRow.dataset.templateName);
      return;
    }
  });
  
  // Initial load
  refreshAgentStatus();
  listTaskTemplates();
  listAgentTasks();
  getAgentMessages();
  
  // Auto-refresh
  setInterval(() => {
    refreshAgentStatus();
    listAgentTasks();
    getAgentMessages();
  }, AUTO_REFRESH_INTERVAL);
}

function showTaskDetailsModal(task) {
  // Check if we have natural language response
  const hasNaturalResponse = task.response_text || task.suggested_actions?.length;
  
  let resultHtml = '';
  if (task.response_text) {
    // Format the natural language response with markdown-like formatting
    let formatted = escapeHtml(task.response_text);
    formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    formatted = formatted.replace(/\n/g, '<br>');
    resultHtml = `
      <div class="task-response" style="background: var(--glass); padding: 12px; border-radius: var(--radius); margin-bottom: 12px;">
        <div class="small muted" style="margin-bottom: 8px;">🤖 Agent Response:</div>
        <div style="font-size: 13px; line-height: 1.6;">${formatted}</div>
      </div>
    `;
  }
  
  let suggestionsHtml = '';
  if (task.suggested_actions?.length) {
    suggestionsHtml = `
      <div class="task-suggestions" style="margin-bottom: 12px;">
        <div class="small muted" style="margin-bottom: 6px;">💡 Suggested Next Steps:</div>
        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
          ${task.suggested_actions.map(action => 
            `<button class="suggestion-btn small" data-action="${escapeHtml(action)}" style="background: var(--glass); border: 1px solid var(--border); border-radius: var(--radius); padding: 4px 10px; cursor: pointer; font-size: 11px;">
              ${escapeHtml(action)}
            </button>`
          ).join('')}
        </div>
      </div>
    `;
  }
  
  const html = `
    <div class="task-details">
      <div class="task-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border);">
        <div>
          <div style="font-size: 16px; font-weight: 600;">${getStatusIcon(task.status)} ${escapeHtml(task.name)}</div>
          <div class="small muted">${escapeHtml(task.task_type)} • Priority: ${task.priority}</div>
        </div>
        <div style="text-align: right;">
          <div class="small">${Math.round((task.progress || 0) * 100)}% complete</div>
          <div class="progress-bar" style="width: 100px; height: 4px; background: var(--glass); border-radius: 2px; overflow: hidden;">
            <div style="width: ${(task.progress || 0) * 100}%; height: 100%; background: ${task.status === 'completed' ? '#10b981' : task.status === 'failed' ? '#ef4444' : '#3b82f6'};"></div>
          </div>
        </div>
      </div>
      
      ${task.request_text ? `
        <div class="task-request" style="background: #3b82f620; padding: 10px; border-radius: var(--radius); margin-bottom: 12px; border-left: 3px solid #3b82f6;">
          <div class="small muted" style="margin-bottom: 4px;">📝 Original Request:</div>
          <div style="font-size: 13px;">${escapeHtml(task.request_text)}</div>
        </div>
      ` : ''}
      
      ${resultHtml}
      ${suggestionsHtml}
      
      <details style="margin-bottom: 12px;">
        <summary class="small muted" style="cursor: pointer;">📋 Task Details</summary>
        <div style="padding: 10px; background: var(--glass); border-radius: var(--radius); margin-top: 8px; font-size: 12px;">
          <div class="mb-1"><strong>ID:</strong> <code style="font-size: 10px;">${escapeHtml(task.id)}</code></div>
          <div class="mb-1"><strong>Created:</strong> ${escapeHtml(formatTimestamp(task.created_at))}</div>
          ${task.started_at ? `<div class="mb-1"><strong>Started:</strong> ${escapeHtml(formatTimestamp(task.started_at))}</div>` : ''}
          ${task.completed_at ? `<div class="mb-1"><strong>Completed:</strong> ${escapeHtml(formatTimestamp(task.completed_at))}</div>` : ''}
          ${task.error ? `<div class="mb-1" style="color: #ef4444;"><strong>Error:</strong> ${escapeHtml(task.error)}</div>` : ''}
        </div>
      </details>
      
      ${task.result ? `
        <details>
          <summary class="small muted" style="cursor: pointer;">🔍 Raw Result Data</summary>
          <pre style="white-space: pre-wrap; font-size: 10px; max-height: 200px; overflow: auto; background: var(--glass); padding: 10px; border-radius: var(--radius); margin-top: 8px;">${escapeHtml(JSON.stringify(task.result, null, 2))}</pre>
        </details>
      ` : ''}
    </div>
    <div class="mt-3" style="display: flex; gap: 8px; flex-wrap: wrap;">
      ${task.status === 'pending' ? '<button id="modalCancelTaskBtn" class="border rounded px-2 py-1 small" style="background: #ef4444; color: white;">Cancel Task</button>' : ''}
      <button id="modalPinTaskBtn" class="border rounded px-2 py-1 small" style="background: var(--glass);">📌 Pin</button>
      ${task.status === 'completed' ? '<button id="modalNewFromTaskBtn" class="border rounded px-2 py-1 small" style="background: #8b5cf6; color: white;">🔄 New Similar Task</button>' : ''}
    </div>
  `;
  
  ui.showModal({
    title: '',
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Task: ${task.name}`, html)
  });
  
  $('modalCancelTaskBtn')?.addEventListener('click', async () => {
    await cancelTask(task.id);
    ui.hideModal();
  });
  
  $('modalPinTaskBtn')?.addEventListener('click', () => {
    ui.addPinnedCard(`Task: ${task.name}`, html);
    ui.toast('Task pinned');
  });
  
  $('modalNewFromTaskBtn')?.addEventListener('click', () => {
    ui.hideModal();
    showNaturalLanguageTaskModal(task.request_text || `Similar to: ${task.name}`);
  });
  
  // Handle suggestion button clicks
  document.querySelectorAll('.suggestion-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const action = btn.dataset.action;
      ui.hideModal();
      showNaturalLanguageTaskModal(action);
    });
  });
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString();
  } catch (e) {
    return ts;
  }
}

function showCreateTaskModal(templateName) {
  const html = `
    <div class="create-task-form">
      <div class="mb-2">
        <label class="small muted">Template: ${escapeHtml(templateName)}</label>
      </div>
      <div class="mb-2">
        <label class="small muted">IP (if applicable):</label>
        <input id="modalTaskIp" type="text" placeholder="IP address" style="width: 100%;" />
      </div>
      <div class="mb-2">
        <label class="small muted">Session ID (if applicable):</label>
        <input id="modalTaskSessionId" type="number" placeholder="Session ID" style="width: 100%;" />
      </div>
      <div class="mb-2">
        <label class="small muted">Query (if applicable):</label>
        <input id="modalTaskQuery" type="text" placeholder="Search query" style="width: 100%;" />
      </div>
      <div class="mb-2">
        <label class="small muted">Priority:</label>
        <select id="modalTaskPriority" style="width: 100%;">
          <option value="">Default</option>
          <option value="low">Low</option>
          <option value="normal">Normal</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>
      <button id="modalCreateTaskBtn" class="border rounded px-2 py-1" style="background: #3b82f6; color: white; width: 100%; margin-top: 8px;">Create Task</button>
    </div>
  `;
  
  ui.showModal({
    title: `Create Task from Template`,
    html
  });
  
  $('modalCreateTaskBtn')?.addEventListener('click', async () => {
    const ip = $('modalTaskIp')?.value?.trim();
    const sessionId = $('modalTaskSessionId')?.value?.trim();
    const query = $('modalTaskQuery')?.value?.trim();
    const priority = $('modalTaskPriority')?.value || null;
    
    const parameters = {};
    if (ip) parameters.ip = ip;
    if (sessionId) parameters.session_id = parseInt(sessionId, 10);
    if (query) parameters.query = query;
    
    await createTaskFromTemplate(templateName, parameters, priority);
    ui.hideModal();
  });
}

// ============================================
// NATURAL LANGUAGE TASK CREATION
// ============================================

export async function createNaturalLanguageTask(requestText, contextType = null, contextId = null, priority = null) {
  try {
    const body = { request: requestText };
    if (contextType) body.context_type = contextType;
    if (contextId) body.context_id = contextId;
    if (priority) body.priority = priority;
    
    const res = await apiPost('/api/v1/agent/task/natural', body);
    
    if (!res.ok) {
      ui.toast(res.error || 'Failed to create task');
      return null;
    }
    
    const { task, interpretation, message } = res.data;
    ui.toast(message || `Task created: ${task?.name || 'Unknown'}`);
    listAgentTasks();
    return task;
  } catch (err) {
    console.error('Failed to create natural language task:', err);
    ui.toast('Failed to create task');
    return null;
  }
}

export function showNaturalLanguageTaskModal(prefillText = '') {
  const html = `
    <div class="natural-task-form">
      <div class="mb-3">
        <div class="small muted" style="margin-bottom: 8px;">🤖 Describe what you want to do in natural language:</div>
        <textarea 
          id="naturalTaskRequest" 
          placeholder="Examples:
• Investigate IP 192.168.1.100
• Analyze session #123 and find similar attacks
• Search for brute force attempts
• Generate a report for session 45
• Find attackers similar to 10.0.0.1
• Monitor live activity for 30 minutes
• Plan countermeasures for session #78"
          style="width: 100%; min-height: 120px; padding: 10px; border: 1px solid var(--border); border-radius: var(--radius); resize: vertical;"
        >${escapeHtml(prefillText)}</textarea>
      </div>
      
      <details style="margin-bottom: 12px;">
        <summary class="small muted" style="cursor: pointer;">⚙️ Advanced Options</summary>
        <div style="padding: 10px; background: var(--glass); border-radius: var(--radius); margin-top: 8px;">
          <div class="mb-2">
            <label class="small muted">Context Type (optional):</label>
            <select id="naturalTaskContext" style="width: 100%;">
              <option value="">None</option>
              <option value="session">Session</option>
              <option value="node">Node/IP</option>
              <option value="threat">Threat</option>
            </select>
          </div>
          <div class="mb-2">
            <label class="small muted">Context ID (session ID, IP, etc.):</label>
            <input id="naturalTaskContextId" type="text" placeholder="e.g., 123 or 192.168.1.1" style="width: 100%;" />
          </div>
          <div class="mb-2">
            <label class="small muted">Priority:</label>
            <select id="naturalTaskPriority" style="width: 100%;">
              <option value="">Auto-detect</option>
              <option value="low">Low</option>
              <option value="normal">Normal</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>
      </details>
      
      <div style="display: flex; gap: 8px;">
        <button id="modalNaturalTaskBtn" class="border rounded px-2 py-1" style="background: #6366f1; color: white; flex: 1;">
          🚀 Create Task
        </button>
        <button id="modalNaturalChatBtn" class="border rounded px-2 py-1" style="background: var(--glass); flex: 1;">
          💬 Chat Instead
        </button>
      </div>
      
      <div class="small muted" style="margin-top: 12px; text-align: center;">
        Tasks run in background • Results include natural language summaries
      </div>
    </div>
  `;
  
  ui.showModal({
    title: '🤖 Create Task from Natural Language',
    html
  });
  
  // Focus the textarea
  setTimeout(() => $('naturalTaskRequest')?.focus(), 100);
  
  $('modalNaturalTaskBtn')?.addEventListener('click', async () => {
    const request = $('naturalTaskRequest')?.value?.trim();
    if (!request) {
      ui.toast('Please enter a request');
      return;
    }
    
    const contextType = $('naturalTaskContext')?.value || null;
    const contextId = $('naturalTaskContextId')?.value?.trim() || null;
    const priority = $('naturalTaskPriority')?.value || null;
    
    ui.hideModal();
    await createNaturalLanguageTask(request, contextType, contextId, priority);
  });
  
  $('modalNaturalChatBtn')?.addEventListener('click', () => {
    const request = $('naturalTaskRequest')?.value?.trim();
    ui.hideModal();
    // Import and show chat modal from chat-ui
    import('./chat-ui.js').then(module => {
      module.showChatModal();
      // Pre-fill the chat input if we have a request
      setTimeout(() => {
        const chatInput = document.getElementById('chatInput');
        if (chatInput && request) {
          chatInput.value = request;
          chatInput.focus();
        }
      }, 200);
    });
  });
  
  // Handle Enter key
  $('naturalTaskRequest')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.ctrlKey) {
      e.preventDefault();
      $('modalNaturalTaskBtn')?.click();
    }
  });
}
