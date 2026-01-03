// AI Analysis UI module
// Provides interface for LLM analysis, similarity search, and threat analysis

import { apiGet, apiPost } from './api.js';
import { escapeHtml } from './util.js';
import * as ui from './ui.js';

const $ = id => document.getElementById(id);

// ============================================
// CONSTANTS
// ============================================

const SUMMARY_TRUNCATE_LENGTH = 100;
const DEFAULT_THREAT_LIMIT = 20;
const DEFAULT_SEARCH_LIMIT = 10;
const AUTO_REFRESH_INTERVAL = 60000; // 60 seconds

// ============================================
// STATUS
// ============================================

export async function refreshAnalysisStatus() {
  try {
    // LLM Status
    const llmRes = await apiGet('/api/v1/llm/status');
    updateLLMStatusUI(llmRes.ok ? llmRes.data : null, llmRes.error);
    
    // Vector Store Status
    const vectorRes = await apiGet('/api/v1/vector/status');
    updateVectorStatusUI(vectorRes.ok ? vectorRes.data : null, vectorRes.error);
  } catch (err) {
    console.error('Failed to refresh analysis status:', err);
  }
}

function updateLLMStatusUI(status, error = null) {
  const availableEl = $('llmAvailableStatus');
  const modelEl = $('llmModelName');
  
  if (error || !status) {
    if (availableEl) availableEl.innerHTML = `<span style="color: #ef4444;">❌ ${escapeHtml(error || 'Unavailable')}</span>`;
    if (modelEl) modelEl.textContent = '—';
    return;
  }
  
  if (availableEl) {
    availableEl.innerHTML = status.available 
      ? '<span style="color: #10b981;">✅ Available</span>'
      : '<span style="color: #f59e0b;">⚠️ Not Available</span>';
  }
  if (modelEl) modelEl.textContent = status.model || '—';
}

function updateVectorStatusUI(status, error = null) {
  const statusEl = $('vectorStoreStatus');
  
  if (error || !status) {
    if (statusEl) statusEl.innerHTML = `<span style="color: #ef4444;">❌ ${escapeHtml(error || 'Unavailable')}</span>`;
    return;
  }
  
  if (statusEl) {
    if (status.available) {
      const collections = status.collections || {};
      const counts = Object.entries(collections).map(([name, info]) => 
        `${name}: ${info?.points_count || 0}`
      ).join(', ');
      statusEl.innerHTML = `<span style="color: #10b981;">✅ Available</span>${counts ? ` (${counts})` : ''}`;
    } else {
      statusEl.innerHTML = '<span style="color: #f59e0b;">⚠️ Not Available</span>';
    }
  }
}

// ============================================
// SESSION ANALYSIS
// ============================================

export async function analyzeSession(sessionId) {
  if (!sessionId) {
    ui.toast('Provide a session ID');
    return null;
  }
  
  ui.setLoading(true, 'Analyzing session...');
  
  try {
    const res = await apiPost('/api/v1/llm/analyze/session', { session_id: sessionId }, { timeout: 120000 });
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Analysis failed');
      return null;
    }
    
    showAnalysisResultModal(res.data, `Session ${sessionId} Analysis`);
    listThreatAnalyses();
    return res.data;
  } catch (err) {
    ui.setLoading(false);
    console.error('Session analysis failed:', err);
    ui.toast('Analysis failed');
    return null;
  }
}

export async function generateFormalReport(sessionId) {
  if (!sessionId) {
    ui.toast('Provide a session ID');
    return null;
  }
  
  ui.setLoading(true, 'Generating formal report...');
  
  try {
    const res = await apiPost('/api/v1/llm/formal_report', { session_id: sessionId }, { timeout: 180000 });
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Report generation failed');
      return null;
    }
    
    showFormalReportModal(res.data, sessionId);
    return res.data;
  } catch (err) {
    ui.setLoading(false);
    console.error('Formal report generation failed:', err);
    ui.toast('Report generation failed');
    return null;
  }
}

export async function getCountermeasures(sessionId) {
  if (!sessionId) {
    ui.toast('Provide a session ID');
    return null;
  }
  
  ui.setLoading(true, 'Getting countermeasures...');
  
  try {
    const res = await apiPost('/api/v1/llm/countermeasures', { session_id: sessionId }, { timeout: 120000 });
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Countermeasure request failed');
      return null;
    }
    
    showCountermeasuresModal(res.data, sessionId);
    return res.data;
  } catch (err) {
    ui.setLoading(false);
    console.error('Countermeasures request failed:', err);
    ui.toast('Request failed');
    return null;
  }
}

export async function generateDetectionRules(sessionId) {
  if (!sessionId) {
    ui.toast('Provide a session ID');
    return null;
  }
  
  ui.setLoading(true, 'Generating detection rules...');
  
  try {
    const res = await apiPost('/api/v1/llm/detection_rules', { session_id: sessionId }, { timeout: 120000 });
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Rule generation failed');
      return null;
    }
    
    showDetectionRulesModal(res.data, sessionId);
    return res.data;
  } catch (err) {
    ui.setLoading(false);
    console.error('Detection rule generation failed:', err);
    ui.toast('Rule generation failed');
    return null;
  }
}

// ============================================
// SIMILARITY SEARCH
// ============================================

export async function searchSimilarSessions(query, sessionId = null, limit = 10) {
  ui.setLoading(true, 'Searching similar sessions...');
  
  try {
    let url = `/api/v1/vector/search/sessions?limit=${limit}`;
    if (query) url += `&q=${encodeURIComponent(query)}`;
    if (sessionId) url += `&session_id=${sessionId}`;
    
    const res = await apiGet(url);
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Search failed');
      return [];
    }
    
    showSimilarResultsModal(res.data.results || [], 'Similar Sessions', 'session');
    return res.data.results || [];
  } catch (err) {
    ui.setLoading(false);
    console.error('Similar sessions search failed:', err);
    ui.toast('Search failed');
    return [];
  }
}

export async function searchSimilarNodes(query, ip = null, limit = 10) {
  ui.setLoading(true, 'Searching similar nodes...');
  
  try {
    let url = `/api/v1/vector/search/nodes?limit=${limit}`;
    if (query) url += `&q=${encodeURIComponent(query)}`;
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    
    const res = await apiGet(url);
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Search failed');
      return [];
    }
    
    showSimilarResultsModal(res.data.results || [], 'Similar Nodes', 'node');
    return res.data.results || [];
  } catch (err) {
    ui.setLoading(false);
    console.error('Similar nodes search failed:', err);
    ui.toast('Search failed');
    return [];
  }
}

export async function searchSimilarThreats(query, limit = 10) {
  if (!query) {
    ui.toast('Provide a search query');
    return [];
  }
  
  ui.setLoading(true, 'Searching similar threats...');
  
  try {
    const url = `/api/v1/vector/search/threats?q=${encodeURIComponent(query)}&limit=${limit}`;
    const res = await apiGet(url);
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Search failed');
      return [];
    }
    
    showSimilarResultsModal(res.data.results || [], 'Similar Threats', 'threat');
    return res.data.results || [];
  } catch (err) {
    ui.setLoading(false);
    console.error('Similar threats search failed:', err);
    ui.toast('Search failed');
    return [];
  }
}

export async function searchSimilarAttackers(ip, threshold = 0.7, limit = 10) {
  if (!ip) {
    ui.toast('Provide an IP address');
    return [];
  }
  
  ui.setLoading(true, 'Searching similar attackers...');
  
  try {
    const url = `/api/v1/similar/attackers?ip=${encodeURIComponent(ip)}&threshold=${threshold}&limit=${limit}`;
    const res = await apiGet(url);
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Search failed');
      return [];
    }
    
    showSimilarAttackersModal(ip, res.data.similar_attackers || []);
    return res.data.similar_attackers || [];
  } catch (err) {
    ui.setLoading(false);
    console.error('Similar attackers search failed:', err);
    ui.toast('Search failed');
    return [];
  }
}

// ============================================
// THREAT ANALYSES LIST
// ============================================

export async function listThreatAnalyses(limit = 20) {
  try {
    const res = await apiGet(`/api/v1/threats?limit=${limit}`);
    if (!res.ok) {
      return;
    }
    renderThreatAnalysesList(res.data.threats || []);
  } catch (err) {
    console.error('Failed to list threat analyses:', err);
  }
}

function renderThreatAnalysesList(threats) {
  const container = $('threatAnalysesList');
  if (!container) return;
  
  if (!threats.length) {
    container.innerHTML = '<div class="muted">No threat analyses yet</div>';
    return;
  }
  
  const frag = document.createDocumentFragment();
  threats.forEach(threat => {
    const div = document.createElement('div');
    div.className = 'py-1 border-b clickable threat-row';
    div.dataset.threatId = threat.id;
    
    const severityBadge = getSeverityBadge(threat.severity);
    const time = threat.analyzed_at ? new Date(threat.analyzed_at).toLocaleString() : '';
    
    div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          ${severityBadge}
          <span>${escapeHtml(threat.threat_type || 'Unknown')}</span>
        </div>
        <span class="muted small">${escapeHtml(threat.source_type || '')}</span>
      </div>
      <div class="muted small">${escapeHtml(threat.summary?.substring(0, SUMMARY_TRUNCATE_LENGTH) || '')}${threat.summary?.length > SUMMARY_TRUNCATE_LENGTH ? '...' : ''}</div>
      <div class="muted small">${time} • ${escapeHtml(threat.source_ip || '')}</div>
    `;
    frag.appendChild(div);
  });
  
  container.innerHTML = '';
  container.appendChild(frag);
}

function getSeverityBadge(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return '<span style="background: #ef4444; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">CRITICAL</span>';
    case 'high': return '<span style="background: #f59e0b; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">HIGH</span>';
    case 'medium': return '<span style="background: #f59e0b; color: black; padding: 1px 4px; border-radius: 3px; font-size: 10px;">MEDIUM</span>';
    case 'low': return '<span style="background: #6b7280; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">LOW</span>';
    default: return '<span style="background: #9ca3af; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">UNKNOWN</span>';
  }
}

// ============================================
// MODALS
// ============================================

function showAnalysisResultModal(analysis, title) {
  const html = `
    <div class="analysis-result">
      ${analysis.analyzed ? `
        <div class="mb-2"><strong>Threat Type:</strong> ${escapeHtml(analysis.threat_type || 'Unknown')}</div>
        <div class="mb-2"><strong>Severity:</strong> ${getSeverityBadge(analysis.severity)} ${escapeHtml(analysis.severity || '')}</div>
        <div class="mb-2"><strong>Confidence:</strong> ${analysis.confidence ? Math.round(analysis.confidence * 100) + '%' : '—'}</div>
        <div class="mb-2"><strong>Summary:</strong><br/>${escapeHtml(analysis.summary || '—')}</div>
        ${analysis.tactics?.length ? `<div class="mb-2"><strong>Tactics:</strong> ${analysis.tactics.map(t => escapeHtml(t)).join(', ')}</div>` : ''}
        ${analysis.techniques?.length ? `<div class="mb-2"><strong>Techniques:</strong> ${analysis.techniques.map(t => escapeHtml(t)).join(', ')}</div>` : ''}
        ${analysis.indicators?.length ? `<div class="mb-2"><strong>Indicators:</strong><pre style="font-size: 11px; max-height: 150px; overflow: auto;">${escapeHtml(JSON.stringify(analysis.indicators, null, 2))}</pre></div>` : ''}
        ${analysis.attacker_profile ? `<div class="mb-2"><strong>Attacker Profile:</strong><pre style="font-size: 11px; max-height: 150px; overflow: auto;">${escapeHtml(JSON.stringify(analysis.attacker_profile, null, 2))}</pre></div>` : ''}
      ` : `
        <div class="muted">Analysis not available: ${escapeHtml(analysis.error || 'Unknown error')}</div>
      `}
    </div>
  `;
  
  ui.showModal({
    title,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(title, html)
  });
}

function showFormalReportModal(report, sessionId) {
  const html = `
    <div class="formal-report">
      ${report.report ? `
        <pre style="white-space: pre-wrap; font-size: 12px; max-height: 500px; overflow: auto; font-family: monospace;">${escapeHtml(report.report)}</pre>
      ` : `
        <div class="muted">Report generation failed: ${escapeHtml(report.error || 'Unknown error')}</div>
      `}
    </div>
  `;
  
  ui.showModal({
    title: `Formal Report - Session ${sessionId}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Report: Session ${sessionId}`, html)
  });
}

function showCountermeasuresModal(data, sessionId) {
  const html = `
    <div class="countermeasures">
      ${data.recommendations ? `
        <div class="mb-2"><strong>Recommendations:</strong></div>
        <pre style="white-space: pre-wrap; font-size: 12px; max-height: 400px; overflow: auto;">${escapeHtml(JSON.stringify(data.recommendations, null, 2))}</pre>
      ` : `
        <div class="muted">No countermeasures available: ${escapeHtml(data.error || 'Unknown error')}</div>
      `}
    </div>
  `;
  
  ui.showModal({
    title: `Countermeasures - Session ${sessionId}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Countermeasures: Session ${sessionId}`, html)
  });
}

function showDetectionRulesModal(data, sessionId) {
  const html = `
    <div class="detection-rules">
      ${data.rules ? `
        <div class="mb-2"><strong>Generated Detection Rules:</strong></div>
        <pre style="white-space: pre-wrap; font-size: 11px; max-height: 400px; overflow: auto; background: #1e1e1e; color: #d4d4d4; padding: 8px; border-radius: 4px;">${escapeHtml(JSON.stringify(data.rules, null, 2))}</pre>
      ` : data.sigma_rules ? `
        <div class="mb-2"><strong>Sigma Rules:</strong></div>
        <pre style="white-space: pre-wrap; font-size: 11px; max-height: 400px; overflow: auto; background: #1e1e1e; color: #d4d4d4; padding: 8px; border-radius: 4px;">${escapeHtml(data.sigma_rules)}</pre>
      ` : `
        <div class="muted">No detection rules generated: ${escapeHtml(data.error || 'Unknown error')}</div>
      `}
    </div>
  `;
  
  ui.showModal({
    title: `Detection Rules - Session ${sessionId}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Rules: Session ${sessionId}`, html)
  });
}

function showSimilarResultsModal(results, title, type) {
  if (!results.length) {
    ui.toast('No similar items found');
    return;
  }
  
  let html = `<div class="similar-results">`;
  
  results.forEach(item => {
    const score = item.score ? ` (${Math.round(item.score * 100)}% similar)` : '';
    
    if (type === 'session') {
      html += `
        <div class="py-2 border-b clickable similar-item" data-type="session" data-id="${item.session_id || ''}">
          <div class="font-medium">Session ${item.session_id || '—'}${score}</div>
          <div class="text-xs muted">${escapeHtml(item.src_ip || '')} • ${escapeHtml(item.username || '')}</div>
        </div>
      `;
    } else if (type === 'node') {
      html += `
        <div class="py-2 border-b clickable similar-item" data-type="node" data-ip="${item.ip || ''}">
          <div class="font-medium">${escapeHtml(item.ip || '—')}${score}</div>
          <div class="text-xs muted">${escapeHtml(item.organization || '')} • ${escapeHtml(item.country || '')}</div>
        </div>
      `;
    } else {
      html += `
        <div class="py-2 border-b similar-item">
          <div class="font-medium">${escapeHtml(item.threat_type || 'Unknown')}${score}</div>
          <div class="text-xs muted">${escapeHtml(item.summary?.substring(0, 100) || '')}</div>
        </div>
      `;
    }
  });
  
  html += `</div>`;
  
  ui.showModal({
    title: `${title} (${results.length} results)`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(title, html)
  });
}

function showSimilarAttackersModal(originalIp, attackers) {
  if (!attackers.length) {
    ui.toast('No similar attackers found');
    return;
  }
  
  let html = `<div class="similar-attackers">
    <div class="text-sm muted mb-2">Attackers similar to ${escapeHtml(originalIp)}:</div>`;
  
  attackers.forEach(a => {
    const score = a.score ? ` (${Math.round(a.score * 100)}% similar)` : '';
    const location = [a.city, a.country].filter(Boolean).join(', ');
    html += `<div class="py-2 border-b clickable similar-attacker-row" data-ip="${escapeHtml(a.src_ip || a.ip || '')}">
      <div class="font-medium">${escapeHtml(a.src_ip || a.ip || '—')}${score}</div>
      <div class="text-xs muted">${escapeHtml(a.organization || '')} ${location ? `• ${escapeHtml(location)}` : ''}</div>
    </div>`;
  });
  
  html += `</div>`;
  
  ui.showModal({
    title: `🔍 Similar Attackers`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Similar to ${originalIp}`, html)
  });
}

// ============================================
// SYSTEM STATUS
// ============================================

export async function showSystemStatus() {
  ui.setLoading(true, 'Getting system status...');
  
  try {
    const res = await apiGet('/api/v1/status');
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Failed to get status');
      return;
    }
    
    showSystemStatusModal(res.data);
  } catch (err) {
    ui.setLoading(false);
    console.error('Failed to get system status:', err);
    ui.toast('Failed to get system status');
  }
}

function showSystemStatusModal(status) {
  const services = status.services || {};
  
  let servicesHtml = '';
  Object.entries(services).forEach(([name, svc]) => {
    const icon = svc.available ? '✅' : '❌';
    const details = [];
    
    if (name === 'llm') {
      if (svc.model) details.push(`Model: ${svc.model}`);
      if (svc.host) details.push(`Host: ${svc.host}`);
    } else if (name === 'vector_store') {
      if (svc.collections) {
        const counts = Object.entries(svc.collections).map(([n, i]) => `${n}: ${i?.points_count || 0}`).join(', ');
        if (counts) details.push(`Collections: ${counts}`);
      }
    } else if (name === 'agent_system') {
      if (svc.workers) details.push(`Workers: ${svc.workers}`);
      if (svc.total_tasks) details.push(`Tasks: ${svc.total_tasks}`);
    } else if (name === 'mcp_server') {
      if (svc.tools_count) details.push(`Tools: ${svc.tools_count}`);
    }
    
    if (svc.error) details.push(`Error: ${svc.error}`);
    if (svc.reason) details.push(`Reason: ${svc.reason}`);
    
    servicesHtml += `
      <div class="py-2 border-b">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong>${escapeHtml(name.replace(/_/g, ' ').toUpperCase())}</strong>
          <span>${icon} ${svc.available ? 'Available' : 'Unavailable'}</span>
        </div>
        ${details.length ? `<div class="muted small">${details.map(d => escapeHtml(d)).join('<br/>')}</div>` : ''}
      </div>
    `;
  });
  
  let hintsHtml = '';
  if (status.hints?.length) {
    hintsHtml = `
      <div class="mt-3">
        <strong>💡 Hints:</strong>
        <ul class="small muted" style="margin: 4px 0; padding-left: 20px;">
          ${status.hints.map(h => `<li>${escapeHtml(h)}</li>`).join('')}
        </ul>
      </div>
    `;
  }
  
  const statusBadge = status.status === 'healthy' 
    ? '<span style="background: #10b981; color: white; padding: 2px 8px; border-radius: 4px;">HEALTHY</span>'
    : '<span style="background: #f59e0b; color: white; padding: 2px 8px; border-radius: 4px;">DEGRADED</span>';
  
  const html = `
    <div class="system-status">
      <div class="mb-3" style="text-align: center;">
        <strong>Overall Status:</strong> ${statusBadge}
      </div>
      <div class="services-list">
        ${servicesHtml}
      </div>
      ${hintsHtml}
    </div>
  `;
  
  ui.showModal({
    title: '🔧 System Status',
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard('System Status', html)
  });
}

// ============================================
// INITIALIZATION
// ============================================

export function initAnalysisUI() {
  // Analyze session button
  $('analyzeSessionBtn')?.addEventListener('click', () => {
    const sessionId = $('analysisSessionId')?.value?.trim();
    if (sessionId) analyzeSession(parseInt(sessionId, 10));
  });
  
  // Formal report button
  $('formalReportBtn')?.addEventListener('click', () => {
    const sessionId = $('analysisSessionId')?.value?.trim();
    if (sessionId) generateFormalReport(parseInt(sessionId, 10));
  });
  
  // Countermeasures button
  $('countermeasuresBtn')?.addEventListener('click', () => {
    const sessionId = $('analysisSessionId')?.value?.trim();
    if (sessionId) getCountermeasures(parseInt(sessionId, 10));
  });
  
  // Detection rules button
  $('detectionRulesBtn')?.addEventListener('click', () => {
    const sessionId = $('analysisSessionId')?.value?.trim();
    if (sessionId) generateDetectionRules(parseInt(sessionId, 10));
  });
  
  // Similarity search buttons
  $('searchSimilarBtn')?.addEventListener('click', () => {
    const query = $('similarityQuery')?.value?.trim();
    if (query) searchSimilarSessions(query);
  });
  
  $('searchSimilarSessionsBtn')?.addEventListener('click', () => {
    const query = $('similarityQuery')?.value?.trim();
    searchSimilarSessions(query || null);
  });
  
  $('searchSimilarNodesBtn')?.addEventListener('click', () => {
    const query = $('similarityQuery')?.value?.trim();
    searchSimilarNodes(query || null);
  });
  
  $('searchSimilarThreatsBtn')?.addEventListener('click', () => {
    const query = $('similarityQuery')?.value?.trim();
    if (query) searchSimilarThreats(query);
  });
  
  $('searchSimilarAttackersBtn')?.addEventListener('click', () => {
    const query = $('similarityQuery')?.value?.trim();
    if (query) searchSimilarAttackers(query);
  });
  
  // System status button
  $('systemStatusBtn')?.addEventListener('click', showSystemStatus);
  
  // Threat analysis row click handler
  document.addEventListener('click', async (e) => {
    const threatRow = e.target.closest('.threat-row');
    if (threatRow?.dataset.threatId) {
      const res = await apiGet(`/api/v1/threat?id=${threatRow.dataset.threatId}`);
      if (res.ok && res.data?.threat) {
        showAnalysisResultModal(res.data.threat, `Threat Analysis #${threatRow.dataset.threatId}`);
      }
    }
  });
  
  // Initial load
  refreshAnalysisStatus();
  listThreatAnalyses();
  
  // Auto-refresh
  setInterval(() => {
    refreshAnalysisStatus();
    listThreatAnalyses();
  }, AUTO_REFRESH_INTERVAL);
}
