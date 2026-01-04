// Chat UI module for agent integration
// Provides chat interface with access to all agent tools
// Enhanced with rich UI component rendering

import { apiGet, apiPost } from './api.js';
import * as honeypotApi from './honeypot.js';
import * as ui from './ui.js';
import { escapeHtml } from './util.js';
import { 
  renderSessionCard, renderSessionsList,
  renderNodeCard, renderNodesList, summarizeNode,
  renderThreatCard, renderThreatsList, summarizeThreat,
  formatDataResponse, injectComponentStyles
} from './components/index.js';

const $ = id => document.getElementById(id);

// Chat state
let currentConversationId = null;
let chatHistory = [];
let availableTools = [];
let isTyping = false;

// Quick commands for the chat
const QUICK_COMMANDS = [
  { cmd: '/help', desc: 'Show available commands', icon: '❓' },
  { cmd: '/sessions', desc: 'List recent honeypot sessions', icon: '📋' },
  { cmd: '/analyze [id]', desc: 'Analyze a session', icon: '🔍' },
  { cmd: '/ip [address]', desc: 'Get IP intelligence', icon: '🌐' },
  { cmd: '/threats', desc: 'List recent threats', icon: '⚠️' },
  { cmd: '/similar [query]', desc: 'Search similar sessions', icon: '🔗' },
  { cmd: '/status', desc: 'Get system status', icon: '📊' },
  { cmd: '/clear', desc: 'Clear chat history', icon: '🗑️' }
];

// ============================================
// API FUNCTIONS
// ============================================

async function sendChatMessage(message) {
  return honeypotApi.agentChat(message, currentConversationId);
}

async function executeTool(toolName, params = {}) {
  return honeypotApi.agentExecuteTool(toolName, params, currentConversationId);
}

async function fetchAvailableTools() {
  const res = await apiGet('/api/v1/mcp/tools');
  if (res.ok && res.data) {
    availableTools = res.data.tools || [];
  }
  return availableTools;
}

// ============================================
// UI RENDERING
// ============================================

function renderChatMessage(message, role, metadata = {}) {
  const container = $('chatMessages');
  if (!container) return;
  
  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-message chat-${role}`;
  
  // Role-specific styling
  const roleConfig = {
    user: { icon: '👤', label: 'You', bgClass: 'chat-user-bg' },
    assistant: { icon: '🤖', label: 'Agent', bgClass: 'chat-assistant-bg' },
    system: { icon: 'ℹ️', label: 'System', bgClass: 'chat-system-bg' },
    error: { icon: '❌', label: 'Error', bgClass: 'chat-error-bg' },
    tool: { icon: '🔧', label: 'Tool Result', bgClass: 'chat-tool-bg' }
  };
  
  const config = roleConfig[role] || roleConfig.assistant;
  const timestamp = new Date().toLocaleTimeString();
  
  msgDiv.innerHTML = `
    <div class="chat-message-header">
      <span class="chat-role-icon">${config.icon}</span>
      <span class="chat-role-label">${config.label}</span>
      <span class="chat-timestamp">${timestamp}</span>
    </div>
    <div class="chat-content ${config.bgClass}">${formatChatContent(message, role)}</div>
    ${metadata.toolName ? `<div class="chat-tool-info">Tool: ${escapeHtml(metadata.toolName)}</div>` : ''}
  `;
  
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
  
  // Animate entry
  msgDiv.style.opacity = '0';
  msgDiv.style.transform = 'translateY(10px)';
  requestAnimationFrame(() => {
    msgDiv.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    msgDiv.style.opacity = '1';
    msgDiv.style.transform = 'translateY(0)';
  });
}

function formatChatContent(content, role, metadata = {}) {
  // Handle rich data objects with UI components
  if (typeof content === 'object' && content !== null) {
    return formatRichContent(content, metadata);
  }
  
  if (typeof content !== 'string') {
    content = JSON.stringify(content, null, 2);
  }
  
  // Escape HTML but preserve some formatting
  let formatted = escapeHtml(content);
  
  // Convert markdown-style code blocks with syntax highlighting hint
  formatted = formatted.replace(/```(\w*)\n([\s\S]*?)```/g, (match, lang, code) => {
    return `<pre class="code-block" data-lang="${lang || 'text'}"><code>${code}</code></pre>`;
  });
  
  // Convert inline code
  formatted = formatted.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');
  
  // Convert **bold**
  formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  
  // Convert *italic*
  formatted = formatted.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  
  // Convert URLs to links
  formatted = formatted.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
  
  // Convert newlines to breaks
  formatted = formatted.replace(/\n/g, '<br>');
  
  return formatted;
}

/**
 * Format rich data objects into UI components
 * @param {Object} data - Data object from API
 * @param {Object} metadata - Additional metadata
 * @returns {string} HTML string
 */
function formatRichContent(data, metadata = {}) {
  const toolName = metadata.toolName || '';
  
  // Detect data type and render appropriate component
  
  // Session data
  if (data.session || (data.id && data.src_ip && data.commands !== undefined)) {
    const session = data.session || data;
    const naturalLang = formatSessionNaturalLanguage(session);
    return `
      <div class="rich-response">
        <div class="rich-response__natural">${escapeHtml(naturalLang)}</div>
        ${renderSessionCard(session, { showActions: true, compact: false })}
      </div>
    `;
  }
  
  // Sessions list
  if (data.sessions && Array.isArray(data.sessions)) {
    const count = data.sessions.length;
    const naturalLang = `Found **${count}** honeypot sessions.${count > 10 ? ' Showing the most recent ones.' : ''}`;
    return `
      <div class="rich-response">
        <div class="rich-response__natural">${formatChatContent(naturalLang, 'assistant')}</div>
        ${renderSessionsList(data.sessions, { maxItems: 5, compact: true, title: '🍯 Sessions' })}
      </div>
    `;
  }
  
  // Node data
  if (data.node || (data.ip && (data.organization || data.isp))) {
    const node = data.node || data;
    const naturalLang = summarizeNode(node);
    return `
      <div class="rich-response">
        <div class="rich-response__natural">${formatChatContent(naturalLang, 'assistant')}</div>
        ${renderNodeCard(node, { showActions: true, compact: false })}
      </div>
    `;
  }
  
  // Nodes list (similar attackers, search results)
  if (data.similar_attackers || (data.results && data.results[0]?.ip)) {
    const nodes = data.similar_attackers || data.results;
    const naturalLang = `Found **${nodes.length}** similar ${data.similar_attackers ? 'attackers' : 'nodes'}.`;
    return `
      <div class="rich-response">
        <div class="rich-response__natural">${formatChatContent(naturalLang, 'assistant')}</div>
        ${renderNodesList(nodes, { maxItems: 5, compact: true, title: '🔗 Similar' })}
      </div>
    `;
  }
  
  // Threat data
  if (data.threat || (data.threat_type && data.severity)) {
    const threat = data.threat || data;
    const naturalLang = summarizeThreat(threat);
    return `
      <div class="rich-response">
        <div class="rich-response__natural">${formatChatContent(naturalLang, 'assistant')}</div>
        ${renderThreatCard(threat, { showActions: true, compact: false })}
      </div>
    `;
  }
  
  // Threats list
  if (data.threats && Array.isArray(data.threats)) {
    const naturalLang = formatDataResponse('threats', data.threats);
    return `
      <div class="rich-response">
        <div class="rich-response__natural">${formatChatContent(naturalLang, 'assistant')}</div>
        ${renderThreatsList(data.threats, { maxItems: 3, compact: true, title: '⚠️ Threats' })}
      </div>
    `;
  }
  
  // Analysis result
  if (data.analyzed && (data.summary || data.threat_type)) {
    const naturalLang = summarizeThreat(data);
    return `
      <div class="rich-response">
        <div class="rich-response__natural">${formatChatContent(naturalLang, 'assistant')}</div>
        ${renderThreatCard(data, { showActions: true, compact: false })}
      </div>
    `;
  }
  
  // Formal report
  if (data.report_sections || data.iocs || data.mitre_tactics) {
    return formatFormalReportContent(data);
  }
  
  // Countermeasures
  if (data.recommendations || data.cowrie_actions || data.immediate_actions) {
    return formatCountermeasuresContent(data);
  }
  
  // Detection rules
  if (data.rules || data.sigma_rules || data.firewall_rules) {
    return formatDetectionRulesContent(data);
  }
  
  // Status data
  if (data.services || data.status === 'healthy' || data.status === 'degraded') {
    return formatStatusContent(data);
  }
  
  // Default: pretty print JSON with collapsible view
  return `
    <div class="rich-response rich-response--json">
      <details>
        <summary class="json-summary">📋 View Raw Data</summary>
        <pre class="json-content">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
      </details>
    </div>
  `;
}

function formatSessionNaturalLanguage(session) {
  let response = `Session **#${session.id}** from **${session.src_ip}**`;
  
  if (session.username) {
    response += ` (user: ${session.username})`;
  }
  
  if (session.city && session.country) {
    response += ` in **${session.city}, ${session.country}**`;
  }
  
  if (session.commands?.length) {
    response += `. Executed **${session.commands.length}** commands`;
  }
  
  if (session.duration) {
    response += ` over ${session.duration.toFixed(1)}s`;
  }
  
  return response + '.';
}

function formatFormalReportContent(report) {
  let html = '<div class="rich-response rich-response--report">';
  
  // Header
  html += `
    <div class="report-header">
      <span class="report-icon">📋</span>
      <span class="report-title">Formal Forensic Report</span>
      ${report.severity ? `<span class="report-severity severity-${report.severity.toLowerCase()}">${escapeHtml(report.severity)}</span>` : ''}
    </div>
  `;
  
  // Summary
  if (report.summary) {
    html += `<div class="report-summary">${escapeHtml(report.summary)}</div>`;
  }
  
  // MITRE mapping
  if (report.mitre_tactics?.length || report.mitre_techniques?.length) {
    html += '<div class="report-mitre">';
    html += '<div class="report-section-title">🎯 MITRE ATT&CK</div>';
    if (report.mitre_tactics?.length) {
      html += `<div class="mitre-tags">${report.mitre_tactics.map(t => `<span class="mitre-tactic">${escapeHtml(t)}</span>`).join('')}</div>`;
    }
    if (report.mitre_techniques?.length) {
      html += `<div class="mitre-tags">${report.mitre_techniques.map(t => `<span class="mitre-technique">${escapeHtml(t)}</span>`).join('')}</div>`;
    }
    html += '</div>';
  }
  
  // IOCs
  if (report.iocs) {
    html += '<div class="report-iocs">';
    html += '<div class="report-section-title">🚨 Indicators of Compromise</div>';
    const iocs = report.iocs;
    if (iocs.network_iocs?.length) {
      html += `<div class="ioc-group"><span class="ioc-label">Network:</span> ${iocs.network_iocs.slice(0, 3).map(i => `<code>${escapeHtml(i)}</code>`).join(' ')}</div>`;
    }
    if (iocs.host_iocs?.length) {
      html += `<div class="ioc-group"><span class="ioc-label">Host:</span> ${iocs.host_iocs.slice(0, 3).map(i => `<code>${escapeHtml(i)}</code>`).join(' ')}</div>`;
    }
    html += '</div>';
  }
  
  // Recommendations
  if (report.recommended_actions?.length) {
    html += '<div class="report-recommendations">';
    html += '<div class="report-section-title">✅ Recommendations</div>';
    html += `<ol class="recommendations-list">${report.recommended_actions.slice(0, 5).map(a => `<li>${escapeHtml(a)}</li>`).join('')}</ol>`;
    html += '</div>';
  }
  
  html += '</div>';
  return html;
}

function formatCountermeasuresContent(data) {
  let html = '<div class="rich-response rich-response--countermeasures">';
  
  html += `
    <div class="countermeasures-header">
      <span class="cm-icon">🛡️</span>
      <span class="cm-title">Countermeasure Recommendations</span>
    </div>
  `;
  
  if (data.recommendations) {
    const recs = typeof data.recommendations === 'string' ? [data.recommendations] : 
                 Array.isArray(data.recommendations) ? data.recommendations :
                 Object.values(data.recommendations);
    
    html += '<div class="countermeasures-list">';
    recs.slice(0, 5).forEach((rec, i) => {
      html += `<div class="cm-item"><span class="cm-num">${i + 1}</span><span>${escapeHtml(typeof rec === 'string' ? rec : JSON.stringify(rec))}</span></div>`;
    });
    html += '</div>';
  }
  
  if (data.cowrie_actions?.length) {
    html += '<div class="countermeasures-section">';
    html += '<div class="cm-section-title">🍯 Cowrie Actions</div>';
    html += data.cowrie_actions.slice(0, 3).map(a => `<code class="cm-action">${escapeHtml(a)}</code>`).join('');
    html += '</div>';
  }
  
  html += '</div>';
  return html;
}

function formatDetectionRulesContent(data) {
  let html = '<div class="rich-response rich-response--rules">';
  
  html += `
    <div class="rules-header">
      <span class="rules-icon">📜</span>
      <span class="rules-title">Detection Rules</span>
    </div>
  `;
  
  if (data.sigma_rules) {
    html += '<div class="rules-section">';
    html += '<div class="rules-section-title">Sigma Rules</div>';
    html += `<pre class="rules-content">${escapeHtml(typeof data.sigma_rules === 'string' ? data.sigma_rules : JSON.stringify(data.sigma_rules, null, 2))}</pre>`;
    html += '</div>';
  }
  
  if (data.firewall_rules?.length) {
    html += '<div class="rules-section">';
    html += '<div class="rules-section-title">Firewall Rules</div>';
    html += `<pre class="rules-content">${data.firewall_rules.map(r => escapeHtml(r)).join('\n')}</pre>`;
    html += '</div>';
  }
  
  if (data.rules && typeof data.rules === 'object') {
    html += '<div class="rules-section">';
    html += '<div class="rules-section-title">Generated Rules</div>';
    html += `<pre class="rules-content">${escapeHtml(JSON.stringify(data.rules, null, 2))}</pre>`;
    html += '</div>';
  }
  
  html += '</div>';
  return html;
}

function formatStatusContent(status) {
  const isHealthy = status.status === 'healthy';
  
  let html = `<div class="rich-response rich-response--status">
    <div class="status-header">
      <span class="status-icon">${isHealthy ? '✅' : '⚠️'}</span>
      <span class="status-title">System Status: ${isHealthy ? 'Healthy' : 'Degraded'}</span>
    </div>
  `;
  
  if (status.services) {
    html += '<div class="status-services">';
    Object.entries(status.services).forEach(([name, svc]) => {
      const available = svc.available;
      html += `
        <div class="status-service ${available ? 'status-service--ok' : 'status-service--error'}">
          <span class="service-status">${available ? '✓' : '✗'}</span>
          <span class="service-name">${escapeHtml(name.replace(/_/g, ' '))}</span>
        </div>
      `;
    });
    html += '</div>';
  }
  
  if (status.hints?.length) {
    html += '<div class="status-hints">';
    html += '<div class="hints-title">💡 Hints</div>';
    status.hints.forEach(hint => {
      html += `<div class="status-hint">${escapeHtml(hint)}</div>`;
    });
    html += '</div>';
  }
  
  html += '</div>';
  return html;
}

function showTypingIndicator() {
  const container = $('chatMessages');
  if (!container) return;
  
  // Remove existing typing indicator
  hideTypingIndicator();
  
  const typingDiv = document.createElement('div');
  typingDiv.id = 'typingIndicator';
  typingDiv.className = 'chat-typing';
  typingDiv.innerHTML = `
    <div class="typing-dots">
      <span></span><span></span><span></span>
    </div>
    <span class="typing-text">Agent is thinking...</span>
  `;
  
  container.appendChild(typingDiv);
  container.scrollTop = container.scrollHeight;
}

function hideTypingIndicator() {
  const indicator = $('typingIndicator');
  if (indicator) indicator.remove();
}

function renderSuggestedTools(tools) {
  const container = $('suggestedTools');
  if (!container || !tools.length) {
    if (container) container.innerHTML = '';
    return;
  }
  
  container.innerHTML = `
    <div class="suggested-tools-header">
      <span class="text-xs muted">💡 Suggested actions:</span>
    </div>
    <div class="suggested-tools-list"></div>
  `;
  
  const listEl = container.querySelector('.suggested-tools-list');
  
  tools.slice(0, 6).forEach(tool => {
    const btn = document.createElement('button');
    btn.className = 'suggested-tool-btn';
    btn.innerHTML = `<span class="tool-icon">🔧</span> ${escapeHtml(tool)}`;
    btn.title = `Execute ${tool}`;
    btn.dataset.tool = tool;
    listEl.appendChild(btn);
  });
}

function renderToolsList() {
  const container = $('toolsList');
  if (!container) return;
  
  if (!availableTools.length) {
    container.innerHTML = '<div class="muted small text-center py-2">No tools available</div>';
    return;
  }
  
  // Group by category
  const byCategory = {};
  availableTools.forEach(tool => {
    const cat = tool.category || 'other';
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(tool);
  });
  
  let html = '';
  Object.entries(byCategory).forEach(([category, tools]) => {
    const categoryIcon = getCategoryIcon(category);
    html += `
      <div class="tool-category">
        <div class="tool-category-header">
          <span>${categoryIcon}</span>
          <span>${escapeHtml(category.toUpperCase())}</span>
          <span class="tool-count">(${tools.length})</span>
        </div>
        <div class="tool-category-items">
    `;
    
    tools.forEach(tool => {
      html += `
        <div class="tool-item" data-tool="${escapeHtml(tool.name)}" title="${escapeHtml(tool.description || '')}">
          <div class="tool-name">${escapeHtml(tool.name)}</div>
          <div class="tool-desc">${escapeHtml((tool.description || '').substring(0, 60))}${(tool.description?.length > 60) ? '...' : ''}</div>
        </div>
      `;
    });
    
    html += '</div></div>';
  });
  
  container.innerHTML = html;
}

function getCategoryIcon(category) {
  const icons = {
    investigation: '🔍',
    analysis: '🧠',
    search: '🔎',
    countermeasure: '🛡️',
    monitoring: '📡',
    reporting: '📋',
    other: '🔧'
  };
  return icons[category.toLowerCase()] || '🔧';
}

function renderQuickCommands() {
  const container = $('quickCommands');
  if (!container) return;
  
  container.innerHTML = QUICK_COMMANDS.map(cmd => `
    <button class="quick-cmd-btn" data-cmd="${escapeHtml(cmd.cmd)}" title="${escapeHtml(cmd.desc)}">
      <span>${cmd.icon}</span>
      <span>${escapeHtml(cmd.cmd.split(' ')[0])}</span>
    </button>
  `).join('');
}

// ============================================
// COMMAND PROCESSING
// ============================================

async function processCommand(input) {
  const trimmed = input.trim();
  
  // Check for quick commands
  if (trimmed.startsWith('/')) {
    const parts = trimmed.split(' ');
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1).join(' ');
    
    switch (cmd) {
      case '/help':
        showHelpMessage();
        return true;
      case '/clear':
        handleNewConversation();
        return true;
      case '/sessions':
        await handleToolClick('list_honeypot_sessions');
        return true;
      case '/analyze':
        if (args) {
          const sessionId = parseInt(args, 10);
          if (isNaN(sessionId)) {
            renderChatMessage('Invalid session ID. Usage: /analyze [session_id]', 'error');
          } else {
            await handleToolClick('analyze_session', { session_id: sessionId });
          }
        } else {
          renderChatMessage('Usage: /analyze [session_id]', 'system');
        }
        return true;
      case '/ip':
        if (args) {
          await handleToolClick('get_ip_intel', { ip: args });
        } else {
          renderChatMessage('Usage: /ip [address]', 'system');
        }
        return true;
      case '/threats':
        await handleToolClick('list_recent_threats');
        return true;
      case '/similar':
        if (args) {
          await handleToolClick('search_similar_sessions', { query: args });
        } else {
          renderChatMessage('Usage: /similar [query]', 'system');
        }
        return true;
      case '/status':
        await handleToolClick('get_system_status');
        return true;
    }
  }
  
  return false;
}

function showHelpMessage() {
  let helpText = '**Available Commands:**\n\n';
  QUICK_COMMANDS.forEach(cmd => {
    helpText += `${cmd.icon} \`${cmd.cmd}\` - ${cmd.desc}\n`;
  });
  helpText += '\n**Tips:**\n';
  helpText += '• Type naturally to ask questions about sessions, threats, IPs\n';
  helpText += '• Click tools in the sidebar to execute them directly\n';
  helpText += '• Use Shift+Enter for multiline messages';
  
  renderChatMessage(helpText, 'system');
}

// ============================================
// EVENT HANDLERS
// ============================================

async function handleSendMessage() {
  const input = $('chatInput');
  if (!input || isTyping) return;
  
  const message = input.value.trim();
  if (!message) return;
  
  input.value = '';
  
  // Check for commands first
  const isCommand = await processCommand(message);
  if (isCommand) return;
  
  // Add user message to UI
  renderChatMessage(message, 'user');
  chatHistory.push({ role: 'user', content: message });
  
  isTyping = true;
  showTypingIndicator();
  
  try {
    const res = await sendChatMessage(message);
    hideTypingIndicator();
    isTyping = false;
    
    if (res.ok && res.data) {
      currentConversationId = res.data.conversation_id;
      
      const response = res.data.response || 'No response generated';
      renderChatMessage(response, 'assistant');
      chatHistory.push({ role: 'assistant', content: response });
      
      // Show quick actions if available
      if (res.data.quick_actions?.length) {
        renderQuickActionsFromResponse(res.data.quick_actions);
      }
      
      // Show suggested tools
      if (res.data.suggested_tools?.length) {
        renderSuggestedTools(res.data.suggested_tools);
      }
      
      // Show auto-execute result if available
      if (res.data.auto_execute_result?.success) {
        const autoResult = res.data.auto_execute_result;
        renderChatMessage(`**Auto-executed:** ${autoResult.tool}`, 'system');
        renderChatMessage(autoResult.data, 'tool', { toolName: autoResult.tool });
      }
      
      // Show RAG context summary if meaningful
      const rag = res.data.rag_context;
      if (rag && (rag.similar_sessions_count > 0 || rag.similar_threats_count > 0 || rag.similar_nodes_count > 0)) {
        const contextInfo = `📚 Context found: ${rag.similar_sessions_count || 0} sessions, ${rag.similar_threats_count || 0} threats, ${rag.similar_nodes_count || 0} nodes`;
        renderChatMessage(contextInfo, 'system');
      }
    } else {
      renderChatMessage(res.error || 'Failed to send message', 'error');
    }
  } catch (err) {
    hideTypingIndicator();
    isTyping = false;
    console.error('Chat error:', err);
    renderChatMessage('Error: ' + err.message, 'error');
  }
}

function renderQuickActionsFromResponse(actions) {
  const container = $('suggestedTools');
  if (!container || !actions.length) return;
  
  // Clear existing and add quick actions
  container.innerHTML = `
    <div class="quick-actions-header">
      <span class="text-xs muted">⚡ Quick actions:</span>
    </div>
    <div class="quick-actions-list" style="display: flex; flex-wrap: wrap; gap: 6px;"></div>
  `;
  
  const listEl = container.querySelector('.quick-actions-list');
  
  actions.slice(0, 5).forEach(action => {
    const btn = document.createElement('button');
    btn.className = 'quick-action-btn';
    btn.style.cssText = 'display: flex; align-items: center; gap: 4px; padding: 6px 10px; font-size: 11px; background: var(--accent); color: white; border: none; border-radius: var(--radius); cursor: pointer;';
    btn.innerHTML = escapeHtml(action.label);
    btn.title = `Execute ${action.tool}`;
    btn.dataset.tool = action.tool;
    btn.dataset.params = JSON.stringify(action.params || {});
    btn.addEventListener('click', () => handleToolClick(action.tool, action.params));
    listEl.appendChild(btn);
  });
}

async function handleToolClick(toolName, presetParams = null) {
  isTyping = true;
  showTypingIndicator();
  
  try {
    // For tools that need parameters, show a dialog
    const tool = availableTools.find(t => t.name === toolName);
    const params = presetParams || {};
    
    // Handle common tools with parameter prompts
    if (!presetParams) {
      const needsParams = await promptForToolParams(toolName, params);
      if (needsParams === false) {
        hideTypingIndicator();
        isTyping = false;
        return;
      }
    }
    
    // Show what we're doing
    renderChatMessage(`Executing tool: **${toolName}**${Object.keys(params).length ? `\nParams: ${JSON.stringify(params)}` : ''}`, 'system');
    
    const res = await executeTool(toolName, params);
    hideTypingIndicator();
    isTyping = false;
    
    if (res.ok && res.data) {
      const resultData = res.data.data || res.data;
      renderChatMessage(resultData, 'tool', { toolName });
    } else {
      renderChatMessage(`Tool ${toolName} failed: ${res.error || 'Unknown error'}`, 'error');
    }
  } catch (err) {
    hideTypingIndicator();
    isTyping = false;
    console.error('Tool execution error:', err);
    renderChatMessage(`Error executing ${toolName}: ${err.message}`, 'error');
  }
}

async function promptForToolParams(toolName, params) {
  // Define parameter requirements for common tools
  const toolParams = {
    'list_honeypot_sessions': { defaults: { limit: 20 } },
    'get_system_status': { defaults: {} },
    'get_ip_intel': { required: ['ip'], prompt: 'Enter IP address:' },
    'search_similar_sessions': { required: ['query'], prompt: 'Enter search query:' },
    'analyze_session': { required: ['session_id'], prompt: 'Enter session ID:', type: 'number' },
    'get_honeypot_session': { required: ['session_id'], prompt: 'Enter session ID:', type: 'number' },
    'generate_node_report': { required: ['ip'], prompt: 'Enter IP address:' },
    'generate_detection_rules': { required: ['session_id'], prompt: 'Enter session ID:', type: 'number' },
    'search_similar_attackers': { required: ['ip'], prompt: 'Enter IP address:' }
  };
  
  const config = toolParams[toolName];
  
  if (!config) {
    // Unknown tool - try executing without params
    return true;
  }
  
  // Apply defaults
  if (config.defaults) {
    Object.assign(params, config.defaults);
  }
  
  // Prompt for required params
  if (config.required && config.prompt) {
    const value = prompt(config.prompt);
    if (!value) return false;
    
    const paramName = config.required[0];
    if (config.type === 'number') {
      const numValue = parseInt(value, 10);
      if (isNaN(numValue)) {
        renderChatMessage(`Invalid number: "${value}". Please enter a valid number.`, 'error');
        return false;
      }
      params[paramName] = numValue;
    } else {
      params[paramName] = value;
    }
  }
  
  return true;
}

function handleNewConversation() {
  currentConversationId = null;
  chatHistory = [];
  
  const container = $('chatMessages');
  if (container) {
    container.innerHTML = `
      <div class="chat-welcome">
        <div class="welcome-icon">🤖</div>
        <div class="welcome-title">Agent Chat</div>
        <div class="welcome-subtitle">Ask questions about honeypot sessions, threats, IPs, or use commands</div>
        <div class="welcome-hint">Type <code>/help</code> to see available commands</div>
      </div>
    `;
  }
  
  const suggestedTools = $('suggestedTools');
  if (suggestedTools) {
    suggestedTools.innerHTML = '';
  }
}

function setupEventHandlers() {
  // Send button
  $('chatSendBtn')?.addEventListener('click', handleSendMessage);
  
  // Enter key to send (Shift+Enter for newline)
  $('chatInput')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  });
  
  // Focus input on modal open
  $('chatInput')?.focus();
  
  // New conversation button
  $('newConversationBtn')?.addEventListener('click', handleNewConversation);
  
  // Tool clicks from suggested tools
  document.addEventListener('click', (e) => {
    const suggestedTool = e.target.closest('.suggested-tool-btn');
    if (suggestedTool?.dataset.tool) {
      handleToolClick(suggestedTool.dataset.tool);
    }
    
    const toolItem = e.target.closest('.tool-item');
    if (toolItem?.dataset.tool) {
      handleToolClick(toolItem.dataset.tool);
    }
    
    const quickCmd = e.target.closest('.quick-cmd-btn');
    if (quickCmd?.dataset.cmd) {
      const input = $('chatInput');
      if (input) {
        input.value = quickCmd.dataset.cmd + ' ';
        input.focus();
      }
    }
  });
  
  // Refresh tools button
  $('refreshToolsBtn')?.addEventListener('click', async () => {
    await fetchAvailableTools();
    renderToolsList();
    ui.toast('Tools refreshed');
  });
  
  // Export chat button
  $('exportChatBtn')?.addEventListener('click', exportChatHistory);
}

function exportChatHistory() {
  if (!chatHistory.length) {
    ui.toast('No chat history to export');
    return;
  }
  
  const data = {
    conversationId: currentConversationId,
    exportedAt: new Date().toISOString(),
    messages: chatHistory
  };
  
  const dataStr = JSON.stringify(data, null, 2);
  const dataBlob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(dataBlob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `chat-export-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(url);
  ui.toast('Chat exported');
}

// ============================================
// MODAL DISPLAY
// ============================================

export function showChatModal() {
  const html = `
    <div class="chat-container">
      <div class="chat-header">
        <div class="chat-header-left">
          <span class="chat-logo">🤖</span>
          <div>
            <div class="chat-title">Agent Chat</div>
            <div class="chat-subtitle">Natural language interface to forensic tools</div>
          </div>
        </div>
        <div class="chat-header-actions">
          <button id="exportChatBtn" class="chat-action-btn" title="Export chat">📥</button>
          <button id="newConversationBtn" class="chat-action-btn" title="New chat">🔄</button>
          <button id="refreshToolsBtn" class="chat-action-btn" title="Refresh tools">↻</button>
        </div>
      </div>
      
      <div class="chat-body">
        <div class="chat-main">
          <div id="chatMessages" class="chat-messages">
            <div class="chat-welcome">
              <div class="welcome-icon">🤖</div>
              <div class="welcome-title">Agent Chat</div>
              <div class="welcome-subtitle">Ask questions about honeypot sessions, threats, IPs, or use commands</div>
              <div class="welcome-hint">Type <code>/help</code> to see available commands</div>
            </div>
          </div>
          
          <div id="suggestedTools" class="suggested-tools"></div>
          
          <div id="quickCommands" class="quick-commands"></div>
          
          <div class="chat-input-area">
            <textarea 
              id="chatInput" 
              placeholder="Ask about sessions, threats, IPs, or type /help for commands..." 
              rows="2"
            ></textarea>
            <button id="chatSendBtn" class="chat-send-btn">
              <span>Send</span>
              <span class="send-icon">→</span>
            </button>
          </div>
        </div>
        
        <div class="chat-sidebar">
          <div class="sidebar-section">
            <div class="sidebar-title">🔧 Available Tools</div>
            <div id="toolsList" class="tools-list">Loading...</div>
          </div>
        </div>
      </div>
    </div>
    
    <style>
      .chat-container {
        height: 70vh;
        display: flex;
        flex-direction: column;
        background: var(--bg-primary);
        border-radius: var(--radius);
      }
      
      .chat-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem 1rem;
        background: var(--bg-secondary);
        border-bottom: 1px solid var(--border);
        border-radius: var(--radius) var(--radius) 0 0;
      }
      
      .chat-header-left {
        display: flex;
        align-items: center;
        gap: 0.75rem;
      }
      
      .chat-logo {
        font-size: 1.5rem;
      }
      
      .chat-title {
        font-weight: 600;
        font-size: 1rem;
      }
      
      .chat-subtitle {
        font-size: 0.7rem;
        color: var(--text-muted);
      }
      
      .chat-header-actions {
        display: flex;
        gap: 0.5rem;
      }
      
      .chat-action-btn {
        padding: 0.4rem 0.6rem;
        border-radius: var(--radius);
        background: var(--glass);
        border: 1px solid var(--border);
        cursor: pointer;
        transition: background 0.2s;
      }
      
      .chat-action-btn:hover {
        background: var(--bg-hover);
      }
      
      .chat-body {
        display: flex;
        flex: 1;
        overflow: hidden;
      }
      
      .chat-main {
        flex: 1;
        display: flex;
        flex-direction: column;
        padding: 0.75rem;
        min-width: 0;
      }
      
      .chat-messages {
        flex: 1;
        overflow-y: auto;
        padding: 0.75rem;
        background: var(--glass);
        border-radius: var(--radius);
        margin-bottom: 0.5rem;
      }
      
      .chat-welcome {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 100%;
        text-align: center;
        color: var(--text-muted);
      }
      
      .welcome-icon {
        font-size: 3rem;
        margin-bottom: 1rem;
      }
      
      .welcome-title {
        font-size: 1.25rem;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 0.5rem;
      }
      
      .welcome-subtitle {
        font-size: 0.85rem;
        margin-bottom: 0.5rem;
      }
      
      .welcome-hint {
        font-size: 0.75rem;
      }
      
      .welcome-hint code {
        background: var(--bg-secondary);
        padding: 0.2rem 0.4rem;
        border-radius: 3px;
      }
      
      .chat-message {
        margin-bottom: 0.75rem;
        animation: fadeIn 0.3s ease;
      }
      
      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(5px); }
        to { opacity: 1; transform: translateY(0); }
      }
      
      .chat-message-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 0.25rem;
        font-size: 0.7rem;
      }
      
      .chat-role-icon {
        font-size: 0.9rem;
      }
      
      .chat-role-label {
        font-weight: 600;
        color: var(--text-primary);
      }
      
      .chat-timestamp {
        color: var(--text-muted);
        font-size: 0.65rem;
      }
      
      .chat-content {
        padding: 0.6rem 0.8rem;
        border-radius: var(--radius);
        font-size: 0.85rem;
        line-height: 1.5;
        word-wrap: break-word;
      }
      
      .chat-user-bg {
        background: var(--accent);
        color: white;
        margin-left: 2rem;
      }
      
      .chat-assistant-bg {
        background: var(--bg-secondary);
        border: 1px solid var(--border);
        margin-right: 2rem;
      }
      
      .chat-system-bg {
        background: #3b82f622;
        border: 1px solid #3b82f6;
        font-size: 0.75rem;
        color: var(--text-muted);
      }
      
      .chat-error-bg {
        background: #ef444422;
        border: 1px solid #ef4444;
        color: #ef4444;
      }
      
      .chat-tool-bg {
        background: #10b98122;
        border: 1px solid #10b981;
        font-family: monospace;
        font-size: 0.75rem;
        max-height: 200px;
        overflow-y: auto;
      }
      
      .chat-tool-info {
        font-size: 0.65rem;
        color: var(--text-muted);
        margin-top: 0.25rem;
      }
      
      .chat-typing {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem;
        color: var(--text-muted);
        font-size: 0.75rem;
      }
      
      .typing-dots {
        display: flex;
        gap: 0.2rem;
      }
      
      .typing-dots span {
        width: 6px;
        height: 6px;
        background: var(--text-muted);
        border-radius: 50%;
        animation: bounce 1.4s infinite ease-in-out both;
      }
      
      .typing-dots span:nth-child(1) { animation-delay: -0.32s; }
      .typing-dots span:nth-child(2) { animation-delay: -0.16s; }
      
      @keyframes bounce {
        0%, 80%, 100% { transform: scale(0); }
        40% { transform: scale(1); }
      }
      
      .suggested-tools {
        margin-bottom: 0.5rem;
      }
      
      .suggested-tools-header {
        margin-bottom: 0.25rem;
      }
      
      .suggested-tools-list {
        display: flex;
        flex-wrap: wrap;
        gap: 0.35rem;
      }
      
      .suggested-tool-btn {
        display: flex;
        align-items: center;
        gap: 0.25rem;
        padding: 0.3rem 0.6rem;
        font-size: 0.7rem;
        background: var(--glass);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        cursor: pointer;
        transition: all 0.2s;
      }
      
      .suggested-tool-btn:hover {
        background: var(--accent);
        color: white;
        border-color: var(--accent);
      }
      
      .quick-commands {
        display: flex;
        flex-wrap: wrap;
        gap: 0.35rem;
        margin-bottom: 0.5rem;
      }
      
      .quick-cmd-btn {
        display: flex;
        align-items: center;
        gap: 0.25rem;
        padding: 0.25rem 0.5rem;
        font-size: 0.65rem;
        background: transparent;
        border: 1px solid var(--border);
        border-radius: var(--radius);
        cursor: pointer;
        color: var(--text-muted);
        transition: all 0.2s;
      }
      
      .quick-cmd-btn:hover {
        background: var(--glass);
        color: var(--text-primary);
      }
      
      .chat-input-area {
        display: flex;
        gap: 0.5rem;
      }
      
      .chat-input-area textarea {
        flex: 1;
        padding: 0.6rem;
        border: 1px solid var(--border);
        border-radius: var(--radius);
        background: var(--bg-primary);
        color: var(--text-primary);
        resize: none;
        font-family: inherit;
        font-size: 0.85rem;
      }
      
      .chat-input-area textarea:focus {
        outline: none;
        border-color: var(--accent);
      }
      
      .chat-send-btn {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.6rem 1rem;
        background: var(--accent);
        color: white;
        border: none;
        border-radius: var(--radius);
        cursor: pointer;
        font-weight: 500;
        transition: background 0.2s;
      }
      
      .chat-send-btn:hover {
        background: var(--accent-hover, #4f46e5);
      }
      
      .chat-sidebar {
        width: 220px;
        border-left: 1px solid var(--border);
        padding: 0.75rem;
        overflow-y: auto;
        background: var(--bg-secondary);
      }
      
      .sidebar-section {
        margin-bottom: 1rem;
      }
      
      .sidebar-title {
        font-size: 0.75rem;
        font-weight: 600;
        color: var(--text-muted);
        margin-bottom: 0.5rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }
      
      .tools-list {
        font-size: 0.75rem;
      }
      
      .tool-category {
        margin-bottom: 0.75rem;
      }
      
      .tool-category-header {
        display: flex;
        align-items: center;
        gap: 0.3rem;
        font-size: 0.7rem;
        font-weight: 600;
        color: var(--text-muted);
        margin-bottom: 0.35rem;
      }
      
      .tool-count {
        font-weight: normal;
        font-size: 0.6rem;
      }
      
      .tool-item {
        padding: 0.4rem;
        border-radius: var(--radius);
        cursor: pointer;
        transition: background 0.2s;
        margin-bottom: 0.2rem;
      }
      
      .tool-item:hover {
        background: var(--glass);
      }
      
      .tool-name {
        font-weight: 500;
        font-size: 0.7rem;
        color: var(--text-primary);
      }
      
      .tool-desc {
        font-size: 0.6rem;
        color: var(--text-muted);
        line-height: 1.3;
      }
      
      .code-block {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        overflow-x: auto;
        margin: 0.5rem 0;
      }
      
      .inline-code {
        background: var(--bg-secondary);
        padding: 0.15rem 0.35rem;
        border-radius: 3px;
        font-size: 0.8em;
      }
      
      /* Rich response styles */
      .rich-response {
        margin: 0;
      }
      
      .rich-response__natural {
        margin-bottom: 8px;
        font-size: 0.85rem;
        line-height: 1.5;
      }
      
      .rich-response--json .json-summary {
        cursor: pointer;
        font-size: 0.75rem;
        color: var(--text-muted);
      }
      
      .rich-response--json .json-content {
        font-size: 0.7rem;
        max-height: 200px;
        overflow-y: auto;
        margin-top: 0.5rem;
      }
      
      /* Report styles */
      .rich-response--report {
        padding: 8px;
        background: var(--glass);
        border-radius: 6px;
      }
      
      .report-header {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
      }
      
      .report-icon { font-size: 16px; }
      .report-title { font-weight: 600; font-size: 13px; }
      .report-severity {
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 10px;
        text-transform: uppercase;
      }
      .report-severity.severity-critical { background: #ef4444; color: white; }
      .report-severity.severity-high { background: #f59e0b; color: white; }
      .report-severity.severity-medium { background: #eab308; color: black; }
      .report-severity.severity-low { background: #22c55e; color: white; }
      
      .report-summary { font-size: 12px; line-height: 1.5; margin-bottom: 8px; }
      .report-section-title { font-size: 11px; font-weight: 600; margin-bottom: 4px; color: var(--text-muted); }
      
      .report-mitre, .report-iocs, .report-recommendations {
        margin-top: 8px;
        padding: 6px;
        background: var(--bg-secondary);
        border-radius: 4px;
      }
      
      .mitre-tags { display: flex; flex-wrap: wrap; gap: 4px; }
      .mitre-tactic { font-size: 9px; padding: 2px 6px; background: rgba(59, 130, 246, 0.2); color: #3b82f6; border-radius: 3px; }
      .mitre-technique { font-size: 9px; padding: 2px 6px; background: rgba(234, 179, 8, 0.2); color: #eab308; border-radius: 3px; }
      
      .ioc-group { font-size: 10px; margin-bottom: 4px; }
      .ioc-label { color: var(--text-muted); margin-right: 4px; }
      .ioc-group code { background: rgba(239, 68, 68, 0.1); padding: 1px 4px; border-radius: 2px; color: #f87171; }
      
      .recommendations-list { font-size: 11px; margin: 0; padding-left: 20px; }
      .recommendations-list li { margin-bottom: 4px; }
      
      /* Countermeasures styles */
      .rich-response--countermeasures {
        padding: 8px;
        background: var(--glass);
        border-radius: 6px;
        border-left: 3px solid #22c55e;
      }
      
      .countermeasures-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
      .cm-icon { font-size: 16px; }
      .cm-title { font-weight: 600; font-size: 13px; }
      
      .countermeasures-list { }
      .cm-item { display: flex; gap: 8px; font-size: 11px; margin-bottom: 6px; align-items: flex-start; }
      .cm-num { background: #22c55e; color: white; width: 18px; height: 18px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 10px; flex-shrink: 0; }
      
      .countermeasures-section { margin-top: 8px; }
      .cm-section-title { font-size: 10px; font-weight: 600; color: var(--text-muted); margin-bottom: 4px; }
      .cm-action { font-size: 10px; padding: 2px 6px; background: rgba(234, 179, 8, 0.1); border-radius: 3px; margin-right: 4px; }
      
      /* Detection rules styles */
      .rich-response--rules {
        padding: 8px;
        background: var(--glass);
        border-radius: 6px;
        border-left: 3px solid #3b82f6;
      }
      
      .rules-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
      .rules-icon { font-size: 16px; }
      .rules-title { font-weight: 600; font-size: 13px; }
      
      .rules-section { margin-top: 8px; }
      .rules-section-title { font-size: 10px; font-weight: 600; color: var(--text-muted); margin-bottom: 4px; }
      .rules-content { font-size: 10px; background: #1e1e1e; color: #d4d4d4; padding: 8px; border-radius: 4px; overflow-x: auto; max-height: 150px; }
      
      /* Status styles */
      .rich-response--status {
        padding: 8px;
        background: var(--glass);
        border-radius: 6px;
      }
      
      .status-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
      .status-icon { font-size: 16px; }
      .status-title { font-weight: 600; font-size: 13px; }
      
      .status-services { display: grid; grid-template-columns: repeat(2, 1fr); gap: 4px; margin-bottom: 8px; }
      .status-service { display: flex; align-items: center; gap: 4px; font-size: 11px; padding: 4px 6px; border-radius: 4px; }
      .status-service--ok { background: rgba(34, 197, 94, 0.1); }
      .status-service--error { background: rgba(239, 68, 68, 0.1); }
      .service-status { font-size: 10px; }
      
      .status-hints { margin-top: 8px; }
      .hints-title { font-size: 10px; font-weight: 600; color: var(--text-muted); margin-bottom: 4px; }
      .status-hint { font-size: 10px; padding: 4px; background: rgba(234, 179, 8, 0.1); border-radius: 3px; margin-bottom: 2px; }
    </style>
  `;
  
  ui.showModal({
    title: '',
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => {
      ui.addPinnedCard('Agent Chat', '<div class="muted small">Chat pinned - click to reopen full interface</div>');
    }
  });
  
  // Setup after modal is shown
  setTimeout(() => {
    setupEventHandlers();
    renderQuickCommands();
    fetchAvailableTools().then(renderToolsList);
    $('chatInput')?.focus();
  }, 100);
}

// ============================================
// INITIALIZATION
// ============================================

export function initChatUI() {
  // Inject component styles for rich rendering
  injectComponentStyles();
  
  // Add chat button to agent panel
  const agentCard = document.getElementById('agentCard');
  if (agentCard) {
    // Find the Quick Actions section and add chat button
    const quickActionsDiv = agentCard.querySelector('.card-body > div:nth-child(3)');
    if (quickActionsDiv) {
      const chatBtn = document.createElement('button');
      chatBtn.id = 'agentChatBtn';
      chatBtn.className = 'small';
      chatBtn.style.cssText = 'background: #6366f1; color: white;';
      chatBtn.innerHTML = '💬 Chat';
      chatBtn.title = 'Open chat with agent';
      chatBtn.addEventListener('click', showChatModal);
      quickActionsDiv.appendChild(chatBtn);
    }
  }
}

// Export for use in other modules
export {
  sendChatMessage,
  executeTool,
  fetchAvailableTools,
  handleNewConversation
};
