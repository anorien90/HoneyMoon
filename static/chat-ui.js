// Chat UI module for agent integration
// Provides chat interface with access to all agent tools

import { apiGet, apiPost } from './api.js';
import * as honeypotApi from './honeypot.js';
import * as ui from './ui.js';
import { escapeHtml } from './util.js';

const $ = id => document.getElementById(id);

// Chat state
let currentConversationId = null;
let chatHistory = [];
let availableTools = [];

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

function renderChatMessage(message, role) {
  const container = $('chatMessages');
  if (!container) return;
  
  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-message chat-${role}`;
  
  const roleLabel = role === 'user' ? '👤 You' : '🤖 Agent';
  
  msgDiv.innerHTML = `
    <div class="chat-role">${roleLabel}</div>
    <div class="chat-content">${formatChatContent(message)}</div>
  `;
  
  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

function formatChatContent(content) {
  if (typeof content !== 'string') {
    content = JSON.stringify(content, null, 2);
  }
  
  // Escape HTML but preserve some formatting
  let formatted = escapeHtml(content);
  
  // Convert markdown-style code blocks
  formatted = formatted.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre class="code-block"><code>$2</code></pre>');
  
  // Convert inline code
  formatted = formatted.replace(/`([^`]+)`/g, '<code>$1</code>');
  
  // Convert newlines to breaks
  formatted = formatted.replace(/\n/g, '<br>');
  
  return formatted;
}

function renderSuggestedTools(tools) {
  const container = $('suggestedTools');
  if (!container || !tools.length) return;
  
  container.innerHTML = '<div class="text-xs muted mb-1">Suggested tools:</div>';
  
  tools.slice(0, 5).forEach(tool => {
    const btn = document.createElement('button');
    btn.className = 'small border rounded px-2 py-1 mr-1 mb-1 suggested-tool';
    btn.textContent = tool;
    btn.title = `Execute ${tool}`;
    btn.dataset.tool = tool;
    container.appendChild(btn);
  });
}

function renderToolsList() {
  const container = $('toolsList');
  if (!container) return;
  
  if (!availableTools.length) {
    container.innerHTML = '<div class="muted small">No tools available</div>';
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
    html += `<div class="tool-category mb-2">
      <div class="text-xs font-medium muted mb-1">${category.toUpperCase()}</div>`;
    
    tools.forEach(tool => {
      html += `<div class="tool-item py-1 border-b clickable" data-tool="${escapeHtml(tool.name)}">
        <div class="text-sm font-medium">${escapeHtml(tool.name)}</div>
        <div class="text-xs muted">${escapeHtml(tool.description?.substring(0, 80) || '')}...</div>
      </div>`;
    });
    
    html += '</div>';
  });
  
  container.innerHTML = html;
}

// ============================================
// EVENT HANDLERS
// ============================================

async function handleSendMessage() {
  const input = $('chatInput');
  if (!input) return;
  
  const message = input.value.trim();
  if (!message) return;
  
  input.value = '';
  
  // Add user message to UI
  renderChatMessage(message, 'user');
  chatHistory.push({ role: 'user', content: message });
  
  ui.setLoading(true, 'Processing...');
  
  try {
    const res = await sendChatMessage(message);
    ui.setLoading(false);
    
    if (res.ok && res.data) {
      currentConversationId = res.data.conversation_id;
      
      const response = res.data.response || 'No response generated';
      renderChatMessage(response, 'assistant');
      chatHistory.push({ role: 'assistant', content: response });
      
      // Show suggested tools
      if (res.data.suggested_tools?.length) {
        renderSuggestedTools(res.data.suggested_tools);
      }
      
      // Show RAG context summary
      const rag = res.data.rag_context;
      if (rag && (rag.similar_sessions_count || rag.similar_threats_count)) {
        const contextInfo = `Found context: ${rag.similar_sessions_count} sessions, ${rag.similar_threats_count} threats, ${rag.similar_nodes_count} nodes`;
        renderChatMessage(contextInfo, 'system');
      }
    } else {
      renderChatMessage(res.error || 'Failed to send message', 'error');
    }
  } catch (err) {
    ui.setLoading(false);
    console.error('Chat error:', err);
    renderChatMessage('Error: ' + err.message, 'error');
  }
}

async function handleToolClick(toolName) {
  ui.setLoading(true, `Executing ${toolName}...`);
  
  try {
    // For tools that need parameters, show a dialog
    const tool = availableTools.find(t => t.name === toolName);
    const params = {};
    
    // Handle common tools with default parameters
    if (toolName === 'list_honeypot_sessions') {
      params.limit = 20;
    } else if (toolName === 'get_system_status') {
      // No params needed
    } else if (toolName === 'get_ip_intel') {
      const ip = prompt('Enter IP address:');
      if (!ip) {
        ui.setLoading(false);
        return;
      }
      params.ip = ip;
    } else if (toolName === 'search_similar_sessions') {
      const query = prompt('Enter search query:');
      if (!query) {
        ui.setLoading(false);
        return;
      }
      params.query = query;
    } else if (toolName === 'analyze_session') {
      const sid = prompt('Enter session ID:');
      if (!sid) {
        ui.setLoading(false);
        return;
      }
      params.session_id = parseInt(sid, 10);
    } else if (toolName === 'get_honeypot_session') {
      const sid = prompt('Enter session ID:');
      if (!sid) {
        ui.setLoading(false);
        return;
      }
      params.session_id = parseInt(sid, 10);
    } else if (toolName === 'generate_node_report') {
      const ip = prompt('Enter IP address:');
      if (!ip) {
        ui.setLoading(false);
        return;
      }
      params.ip = ip;
    } else if (toolName === 'generate_detection_rules') {
      const sid = prompt('Enter session ID:');
      if (!sid) {
        ui.setLoading(false);
        return;
      }
      params.session_id = parseInt(sid, 10);
    }
    
    const res = await executeTool(toolName, params);
    ui.setLoading(false);
    
    if (res.ok && res.data) {
      const resultText = JSON.stringify(res.data.data || res.data, null, 2);
      renderChatMessage(`Tool: ${toolName}\nResult:\n${resultText}`, 'assistant');
    } else {
      renderChatMessage(`Tool ${toolName} failed: ${res.error || 'Unknown error'}`, 'error');
    }
  } catch (err) {
    ui.setLoading(false);
    console.error('Tool execution error:', err);
    renderChatMessage(`Error executing ${toolName}: ${err.message}`, 'error');
  }
}

function handleNewConversation() {
  currentConversationId = null;
  chatHistory = [];
  
  const container = $('chatMessages');
  if (container) {
    container.innerHTML = '<div class="muted small text-center py-4">Start a new conversation by typing a message...</div>';
  }
  
  const suggestedTools = $('suggestedTools');
  if (suggestedTools) {
    suggestedTools.innerHTML = '';
  }
}

function setupEventHandlers() {
  // Send button
  $('chatSendBtn')?.addEventListener('click', handleSendMessage);
  
  // Enter key to send
  $('chatInput')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  });
  
  // New conversation button
  $('newConversationBtn')?.addEventListener('click', handleNewConversation);
  
  // Tool clicks from suggested tools
  document.addEventListener('click', (e) => {
    const suggestedTool = e.target.closest('.suggested-tool');
    if (suggestedTool?.dataset.tool) {
      handleToolClick(suggestedTool.dataset.tool);
    }
    
    const toolItem = e.target.closest('.tool-item');
    if (toolItem?.dataset.tool) {
      handleToolClick(toolItem.dataset.tool);
    }
  });
  
  // Refresh tools button
  $('refreshToolsBtn')?.addEventListener('click', async () => {
    await fetchAvailableTools();
    renderToolsList();
  });
}

// ============================================
// MODAL DISPLAY
// ============================================

export function showChatModal() {
  const html = `
    <div class="chat-container" style="height: 60vh; display: flex; flex-direction: column;">
      <div class="chat-header" style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; border-bottom: 1px solid var(--border);">
        <div>
          <strong>🤖 Agent Chat</strong>
          <span class="text-xs muted ml-2">Access all agent tools via natural language</span>
        </div>
        <div>
          <button id="newConversationBtn" class="small border rounded px-2 py-1">New Chat</button>
          <button id="refreshToolsBtn" class="small border rounded px-2 py-1">↻ Tools</button>
        </div>
      </div>
      
      <div style="display: flex; flex: 1; overflow: hidden;">
        <div class="chat-main" style="flex: 1; display: flex; flex-direction: column; padding: 0.5rem;">
          <div id="chatMessages" class="chat-messages" style="flex: 1; overflow-y: auto; padding: 0.5rem; background: var(--glass); border-radius: var(--radius);">
            <div class="muted small text-center py-4">Start a new conversation by typing a message...</div>
          </div>
          
          <div id="suggestedTools" style="min-height: 40px; padding: 0.25rem 0;"></div>
          
          <div class="chat-input-area" style="display: flex; gap: 0.5rem; padding-top: 0.5rem;">
            <textarea id="chatInput" placeholder="Ask about sessions, threats, IPs, or request analysis..." 
              style="flex: 1; resize: none; min-height: 60px; padding: 0.5rem; border-radius: var(--radius);"></textarea>
            <button id="chatSendBtn" style="background: var(--accent); color: white; padding: 0.5rem 1rem; border-radius: var(--radius);">Send</button>
          </div>
        </div>
        
        <div class="tools-sidebar" style="width: 200px; border-left: 1px solid var(--border); padding: 0.5rem; overflow-y: auto;">
          <div class="text-xs font-medium muted mb-2">AVAILABLE TOOLS</div>
          <div id="toolsList" class="text-xs">Loading...</div>
        </div>
      </div>
    </div>
  `;
  
  ui.showModal({
    title: '🤖 Agent Chat Interface',
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => {
      ui.addPinnedCard('Agent Chat', '<div class="muted small">Chat pinned - reopen for full interface</div>');
    }
  });
  
  // Setup after modal is shown
  setTimeout(() => {
    setupEventHandlers();
    fetchAvailableTools().then(renderToolsList);
  }, 100);
}

// ============================================
// INITIALIZATION
// ============================================

export function initChatUI() {
  // Add chat button to agent panel
  const agentCard = document.getElementById('agentCard');
  if (agentCard) {
    const actionsDiv = agentCard.querySelector('.card-body > div:first-of-type + div');
    if (actionsDiv) {
      const chatBtn = document.createElement('button');
      chatBtn.id = 'agentChatBtn';
      chatBtn.className = 'small';
      chatBtn.style.cssText = 'background: #6366f1; color: white;';
      chatBtn.textContent = '💬 Chat';
      chatBtn.title = 'Open chat with agent';
      chatBtn.addEventListener('click', showChatModal);
      actionsDiv.appendChild(chatBtn);
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
