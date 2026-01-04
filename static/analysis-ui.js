// AI Analysis UI module
// Provides interface for LLM analysis, similarity search, and threat analysis

import { apiGet, apiPost } from './api.js';
import { escapeHtml, getSeverityBadge } from './util.js';
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

export function showFormalReportModal(report, sessionId) {
  // Check if we have a structured report or raw text
  if (report.error) {
    const html = `<div class="muted">Report generation failed: ${escapeHtml(report.error || 'Unknown error')}</div>`;
    ui.showModal({
      title: `Formal Report - Session ${sessionId}`,
      html,
      allowPin: true,
      onPin: () => ui.addPinnedCard(`Report: Session ${sessionId}`, html)
    });
    return;
  }
  
  // Build structured HTML for the formal report
  let html = '<div class="formal-report" style="max-height: 600px; overflow-y: auto; padding: 8px;">';
  
  // Report metadata header
  html += `
    <div style="background: var(--bg-secondary); padding: 12px; border-radius: 6px; margin-bottom: 16px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <strong style="font-size: 14px;">📋 Formal Forensic Analysis Report</strong>
        <span class="small muted">${report.generated_at ? new Date(report.generated_at).toLocaleString() : ''}</span>
      </div>
      ${report.severity ? `<div class="mb-1"><strong>Severity:</strong> ${getSeverityBadge(report.severity)} ${escapeHtml(report.severity)}</div>` : ''}
      ${report.confidence ? `<div class="mb-1"><strong>Confidence:</strong> ${Math.round(report.confidence * 100)}%</div>` : ''}
      ${report.session_id ? `<div class="small muted">Session ID: ${report.session_id}</div>` : ''}
    </div>
  `;
  
  // Executive summary (highlighted)
  if (report.summary) {
    html += `
      <div style="background: #f0f9ff; border-left: 4px solid #3b82f6; padding: 12px; margin-bottom: 16px; border-radius: 4px;">
        <strong style="color: #1e40af;">Executive Summary</strong>
        <p style="margin: 8px 0 0 0; line-height: 1.5;">${escapeHtml(report.summary)}</p>
      </div>
    `;
  }
  
  // MITRE ATT&CK mapping (if available)
  if (report.mitre_tactics?.length || report.mitre_techniques?.length) {
    html += '<div style="margin-bottom: 16px;">';
    html += '<strong style="font-size: 13px;">🎯 MITRE ATT&CK Mapping</strong>';
    
    if (report.mitre_tactics?.length) {
      html += '<div style="margin: 8px 0;"><strong class="small">Tactics:</strong> ';
      html += report.mitre_tactics.map(t => `<span style="background: #dbeafe; color: #1e40af; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin-right: 4px;">${escapeHtml(t)}</span>`).join('');
      html += '</div>';
    }
    
    if (report.mitre_techniques?.length) {
      html += '<div style="margin: 8px 0;"><strong class="small">Techniques:</strong> ';
      html += report.mitre_techniques.map(t => `<span style="background: #fef3c7; color: #92400e; padding: 2px 6px; border-radius: 3px; font-size: 11px; margin-right: 4px;">${escapeHtml(t)}</span>`).join('');
      html += '</div>';
    }
    
    html += '</div>';
  }
  
  // Report sections
  if (report.report_sections) {
    html += '<div style="margin-bottom: 16px;">';
    
    Object.entries(report.report_sections).forEach(([sectionTitle, sectionContent]) => {
      html += `
        <div style="margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 12px;">
          <h3 style="font-size: 14px; font-weight: 600; margin-bottom: 8px; color: var(--text-primary);">${escapeHtml(sectionTitle)}</h3>
          <div style="font-size: 12px; line-height: 1.6;">
      `;
      
      // Handle different content types
      if (typeof sectionContent === 'string') {
        html += `<div style="white-space: pre-wrap;">${escapeHtml(sectionContent)}</div>`;
      } else if (typeof sectionContent === 'object' && sectionContent !== null) {
        // Render object as formatted key-value pairs
        Object.entries(sectionContent).forEach(([key, value]) => {
          html += `<div style="margin-bottom: 8px;"><strong>${escapeHtml(key)}:</strong> `;
          if (typeof value === 'string') {
            html += escapeHtml(value);
          } else {
            html += `<pre style="font-size: 11px; margin: 4px 0; padding: 4px; background: var(--bg-secondary); border-radius: 3px;">${escapeHtml(JSON.stringify(value, null, 2))}</pre>`;
          }
          html += '</div>';
        });
      }
      
      html += '</div></div>';
    });
    
    html += '</div>';
  }
  
  // IOCs (Indicators of Compromise)
  if (report.iocs) {
    html += '<div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 12px; margin-bottom: 16px; border-radius: 4px;">';
    html += '<strong style="color: #991b1b;">🚨 Indicators of Compromise (IOCs)</strong>';
    
    if (report.iocs.network_iocs?.length) {
      html += '<div style="margin-top: 8px;"><strong class="small">Network IOCs:</strong><ul style="margin: 4px 0; padding-left: 20px; font-size: 11px;">';
      report.iocs.network_iocs.forEach(ioc => {
        html += `<li>${escapeHtml(ioc)}</li>`;
      });
      html += '</ul></div>';
    }
    
    if (report.iocs.host_iocs?.length) {
      html += '<div style="margin-top: 8px;"><strong class="small">Host IOCs:</strong><ul style="margin: 4px 0; padding-left: 20px; font-size: 11px;">';
      report.iocs.host_iocs.forEach(ioc => {
        html += `<li>${escapeHtml(ioc)}</li>`;
      });
      html += '</ul></div>';
    }
    
    if (report.iocs.behavioral_iocs?.length) {
      html += '<div style="margin-top: 8px;"><strong class="small">Behavioral IOCs:</strong><ul style="margin: 4px 0; padding-left: 20px; font-size: 11px;">';
      report.iocs.behavioral_iocs.forEach(ioc => {
        html += `<li>${escapeHtml(ioc)}</li>`;
      });
      html += '</ul></div>';
    }
    
    html += '</div>';
  }
  
  // Recommended actions
  if (report.recommended_actions?.length) {
    html += '<div style="background: #ecfdf5; border-left: 4px solid #10b981; padding: 12px; margin-bottom: 16px; border-radius: 4px;">';
    html += '<strong style="color: #065f46;">✅ Recommended Actions</strong>';
    html += '<ol style="margin: 8px 0; padding-left: 20px; font-size: 12px; line-height: 1.6;">';
    report.recommended_actions.forEach(action => {
      html += `<li>${escapeHtml(action)}</li>`;
    });
    html += '</ol></div>';
  }
  
  // Threat actor profile
  if (report.threat_actor_profile) {
    html += '<div style="background: var(--bg-secondary); padding: 12px; margin-bottom: 16px; border-radius: 4px;">';
    html += '<strong style="font-size: 13px;">👤 Threat Actor Profile</strong>';
    html += '<div style="margin-top: 8px; font-size: 12px;">';
    
    if (report.threat_actor_profile.skill_level) {
      html += `<div><strong>Skill Level:</strong> ${escapeHtml(report.threat_actor_profile.skill_level)}</div>`;
    }
    if (report.threat_actor_profile.automation) {
      html += `<div><strong>Automation:</strong> ${escapeHtml(report.threat_actor_profile.automation)}</div>`;
    }
    if (report.threat_actor_profile.motivation) {
      html += `<div><strong>Motivation:</strong> ${escapeHtml(report.threat_actor_profile.motivation)}</div>`;
    }
    
    html += '</div></div>';
  }
  
  // Download/export button
  html += `
    <div style="text-align: center; padding-top: 12px; border-top: 1px solid var(--border);">
      <button class="small" id="downloadReportBtn" style="background: #3b82f6; color: white; padding: 6px 12px;">
        💾 Download JSON
      </button>
      <button class="small" id="copyReportBtn" style="background: #6b7280; color: white; padding: 6px 12px; margin-left: 8px;">
        📋 Copy to Clipboard
      </button>
    </div>
  `;
  
  html += '</div>';
  
  ui.showModal({
    title: `📋 Formal Forensic Report - Session ${sessionId}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Report: Session ${sessionId}`, html),
    onShow: () => {
      // Add event listeners after modal is shown (more reliable than setTimeout)
      const downloadBtn = document.getElementById('downloadReportBtn');
      const copyBtn = document.getElementById('copyReportBtn');
      
      if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
          const dataStr = JSON.stringify(report, null, 2);
          const dataBlob = new Blob([dataStr], { type: 'application/json' });
          const url = URL.createObjectURL(dataBlob);
          const link = document.createElement('a');
          link.href = url;
          link.download = `forensic-report-session-${sessionId}-${Date.now()}.json`;
          link.click();
          URL.revokeObjectURL(url);
          ui.toast('Report downloaded');
        });
      }
      
      if (copyBtn) {
        copyBtn.addEventListener('click', () => {
          const dataStr = JSON.stringify(report, null, 2);
          navigator.clipboard.writeText(dataStr).then(() => {
            ui.toast('Report copied to clipboard');
          }).catch(err => {
            console.error('Failed to copy:', err);
            ui.toast('Failed to copy report');
          });
        });
      }
    }
  });
}

function showCountermeasuresModal(data, sessionId) {
  // Handle error case
  if (data.error) {
    const html = `<div class="muted">Countermeasure generation failed: ${escapeHtml(data.error)}</div>`;
    ui.showModal({
      title: `Countermeasures - Session ${sessionId}`,
      html,
      allowPin: true
    });
    return;
  }

  const priorityColors = {
    immediate: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a'
  };
  const priorityColor = priorityColors[data.priority?.toLowerCase()] || '#6b7280';

  let html = `<div class="countermeasures" style="max-height: 70vh; overflow-y: auto;">`;

  // Header
  html += `
    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--glass); border-radius: var(--radius); border-left: 4px solid ${priorityColor};">
      <div>
        <div class="font-medium">⚔️ Active Countermeasure Recommendations</div>
        <div class="text-xs muted">Session ${sessionId}</div>
        ${data.priority ? `<div class="text-xs mt-1">Priority: <span style="color: ${priorityColor}; font-weight: 600;">${escapeHtml(data.priority)}</span></div>` : ''}
      </div>
    </div>`;

  // Recommended Capability
  if (data.recommended_capability) {
    const capabilityDescriptions = {
      json_tail: '📊 JSON Tail - Real-time command monitoring via cowrie.json',
      manhole: '🔧 Manhole - Direct Python REPL access to session objects',
      output_plugin: '⚡ Output Plugin - Automated response triggers',
      proxy_mode: '🖥️ Proxy Mode - Pass-through to real backend VM',
      playlog: '🎬 Playlog - Terminal session replay'
    };
    html += `<div class="mt-2"><strong>🎯 Recommended Capability</strong>
      <div class="text-sm mt-1 p-2 border rounded" style="background: var(--glass);">
        ${capabilityDescriptions[data.recommended_capability] || escapeHtml(data.recommended_capability)}
      </div>
    </div>`;
  }

  // Response Actions
  if (data.response_actions?.length) {
    html += `<div class="mt-3"><strong>🎭 Recommended Response Actions</strong><div class="text-xs mt-1" style="display: flex; gap: 0.25rem; flex-wrap: wrap;">`;
    const actionColors = {
      observe: '#6b7280', delay: '#ca8a04', fake_data: '#8b5cf6',
      tarpit: '#ea580c', disconnect: '#dc2626', alert: '#dc2626',
      capture: '#2563eb', deception: '#8b5cf6'
    };
    data.response_actions.forEach(action => {
      const color = actionColors[action] || '#6b7280';
      html += `<span style="padding: 0.25rem 0.75rem; background: ${color}22; border: 1px solid ${color}; border-radius: 4px; color: ${color};">${escapeHtml(action)}</span>`;
    });
    html += `</div></div>`;
  }

  // Recommendations (if present as array or object)
  if (data.recommendations) {
    html += `<div class="mt-3"><strong>📝 Recommendations</strong>`;
    if (Array.isArray(data.recommendations)) {
      html += `<ol class="text-xs mt-1" style="margin-left: 1rem;">`;
      data.recommendations.forEach(rec => {
        html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(typeof rec === 'string' ? rec : JSON.stringify(rec))}</li>`;
      });
      html += `</ol>`;
    } else if (typeof data.recommendations === 'object') {
      html += `<div class="text-xs mt-1 p-2 border rounded" style="background: var(--glass);">`;
      Object.entries(data.recommendations).forEach(([key, value]) => {
        html += `<div style="margin-bottom: 0.25rem;"><strong>${escapeHtml(key)}:</strong> ${escapeHtml(typeof value === 'string' ? value : JSON.stringify(value))}</div>`;
      });
      html += `</div>`;
    } else {
      html += `<div class="text-sm mt-1">${escapeHtml(String(data.recommendations))}</div>`;
    }
    html += `</div>`;
  }

  // Implementation Steps
  if (data.implementation_steps?.length) {
    html += `<div class="mt-3"><strong>📋 Implementation Steps</strong><ol class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.implementation_steps.forEach(step => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(step)}</li>`;
    });
    html += `</ol></div>`;
  }

  // Manhole Commands
  if (data.manhole_commands?.length) {
    html += `<div class="mt-3"><strong>🔧 Manhole Commands</strong>
      <div class="text-xs mt-1 muted">SSH to Manhole: <code>ssh -p 2500 -l cowrie localhost</code></div>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.75rem; overflow-x: auto;">`;
    data.manhole_commands.forEach(cmd => {
      html += `>>> ${escapeHtml(cmd)}\n`;
    });
    html += `</pre></div>`;
  }

  // Monitoring Queries
  if (data.monitoring_queries?.length) {
    html += `<div class="mt-3"><strong>📊 Monitoring Queries (jq)</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.75rem; overflow-x: auto;">`;
    data.monitoring_queries.forEach(query => {
      html += `tail -f cowrie.json | jq '${escapeHtml(query)}'\n`;
    });
    html += `</pre></div>`;
  }

  // Risk Assessment
  if (data.risk_assessment) {
    html += `<div class="mt-3"><strong>⚠️ Risk Assessment</strong><div class="text-xs mt-1" style="white-space: pre-wrap;">${escapeHtml(data.risk_assessment)}</div></div>`;
  }

  // Timing and Expected Outcome
  if (data.timing) {
    html += `<div class="mt-2"><strong>⏱️ Timing:</strong> <span class="text-xs">${escapeHtml(data.timing)}</span></div>`;
  }
  if (data.expected_outcome) {
    html += `<div class="mt-2"><strong>🎯 Expected Outcome:</strong> <span class="text-xs">${escapeHtml(data.expected_outcome)}</span></div>`;
  }

  html += `</div>`;

  ui.showModal({
    title: `⚔️ Countermeasures - Session ${sessionId}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Countermeasures: Session ${sessionId}`, html)
  });
}

function showDetectionRulesModal(data, sessionId) {
  // Handle error case
  if (data.error) {
    const html = `<div class="muted">Detection rule generation failed: ${escapeHtml(data.error)}</div>`;
    ui.showModal({
      title: `Detection Rules - Session ${sessionId}`,
      html,
      allowPin: true
    });
    return;
  }

  let html = `<div class="detection-rules" style="max-height: 70vh; overflow-y: auto;">`;

  html += `
    <div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--glass); border-radius: var(--radius);">
      <div class="font-medium">🛡️ Detection Rules</div>
      <div class="text-xs muted">Generated from Session ${sessionId}</div>
      ${data.deployment_priority ? `<div class="text-xs mt-1">Priority: <strong>${escapeHtml(data.deployment_priority)}</strong></div>` : ''}
    </div>`;

  // Detection Logic
  if (data.detection_logic) {
    html += `<div class="mt-2"><strong>📋 Detection Strategy</strong><div class="text-sm mt-1" style="white-space: pre-wrap;">${escapeHtml(data.detection_logic)}</div></div>`;
  }

  // Sigma Rules
  if (data.sigma_rules?.length || (typeof data.sigma_rules === 'string' && data.sigma_rules)) {
    html += `<div class="mt-3"><strong>📊 Sigma Rules (SIEM)</strong>`;
    const sigmaRules = Array.isArray(data.sigma_rules) ? data.sigma_rules : [data.sigma_rules];
    sigmaRules.forEach((rule, i) => {
      html += `<details class="mt-1"><summary class="text-xs cursor-pointer" style="cursor: pointer;">Rule ${i + 1}</summary>
        <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto; margin-top: 0.5rem;">${escapeHtml(typeof rule === 'string' ? rule : JSON.stringify(rule, null, 2))}</pre>
      </details>`;
    });
    html += `</div>`;
  }

  // Firewall Rules
  if (data.firewall_rules?.length) {
    html += `<div class="mt-3"><strong>🔥 Firewall Rules</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto;">`;
    data.firewall_rules.forEach(rule => {
      html += `${escapeHtml(rule)}\n`;
    });
    html += `</pre></div>`;
  }

  // Cowrie Filter
  if (data.cowrie_filter) {
    html += `<div class="mt-3"><strong>🍯 Cowrie Command Filter</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto;">${escapeHtml(JSON.stringify(data.cowrie_filter, null, 2))}</pre>
    </div>`;
  }

  // YARA Rules
  if (data.yara_rules?.length) {
    html += `<div class="mt-3"><strong>🔬 YARA Rules</strong>`;
    data.yara_rules.forEach((rule, i) => {
      html += `<details class="mt-1"><summary class="text-xs" style="cursor: pointer;">Rule ${i + 1}</summary>
        <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto; margin-top: 0.5rem;">${escapeHtml(rule)}</pre>
      </details>`;
    });
    html += `</div>`;
  }

  // Snort Rules
  if (data.snort_rules?.length) {
    html += `<div class="mt-3"><strong>🦈 Snort/Suricata Rules</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto;">`;
    data.snort_rules.forEach(rule => {
      html += `${escapeHtml(rule)}\n`;
    });
    html += `</pre></div>`;
  }

  // Generic rules object fallback
  if (data.rules && !data.sigma_rules && !data.firewall_rules && !data.yara_rules && !data.snort_rules) {
    html += `<div class="mt-3"><strong>📜 Generated Rules</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto; max-height: 300px;">${escapeHtml(JSON.stringify(data.rules, null, 2))}</pre>
    </div>`;
  }

  // False Positive Notes
  if (data.false_positive_notes) {
    html += `<div class="mt-3"><strong>⚠️ False Positive Guidance</strong><div class="text-xs mt-1" style="white-space: pre-wrap;">${escapeHtml(data.false_positive_notes)}</div></div>`;
  }

  // Command patterns
  if (data.command_patterns?.length) {
    html += `<div class="mt-3"><strong>📋 Command Patterns</strong><div class="text-xs mt-1" style="display: flex; gap: 0.25rem; flex-wrap: wrap;">`;
    data.command_patterns.forEach(pattern => {
      html += `<span style="padding: 0.125rem 0.5rem; background: var(--glass); border-radius: 4px; border: 1px solid var(--border); font-family: monospace;">${escapeHtml(pattern)}</span>`;
    });
    html += `</div></div>`;
  }

  // Export buttons
  html += `
    <div class="mt-3 pt-3 border-t" style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
      <button id="downloadRulesBtn" class="small" style="background: #3b82f6; color: white; padding: 6px 12px;">
        💾 Download JSON
      </button>
      <button id="copyRulesBtn" class="small" style="background: #6b7280; color: white; padding: 6px 12px;">
        📋 Copy to Clipboard
      </button>
    </div>`;

  html += `</div>`;

  ui.showModal({
    title: `🛡️ Detection Rules - Session ${sessionId}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Rules: Session ${sessionId}`, html),
    onShow: () => {
      const downloadBtn = document.getElementById('downloadRulesBtn');
      const copyBtn = document.getElementById('copyRulesBtn');

      if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
          const dataStr = JSON.stringify(data, null, 2);
          const dataBlob = new Blob([dataStr], { type: 'application/json' });
          const url = URL.createObjectURL(dataBlob);
          const link = document.createElement('a');
          link.href = url;
          link.download = `detection-rules-session-${sessionId}-${Date.now()}.json`;
          link.click();
          URL.revokeObjectURL(url);
          ui.toast('Rules downloaded');
        });
      }

      if (copyBtn) {
        copyBtn.addEventListener('click', () => {
          const dataStr = JSON.stringify(data, null, 2);
          navigator.clipboard.writeText(dataStr).then(() => {
            ui.toast('Rules copied to clipboard');
          }).catch(err => {
            console.error('Clipboard write failed:', err);
            // Provide more specific feedback based on error type
            const reason = err.name === 'NotAllowedError' ? ' (permission denied)' : '';
            ui.toast(`Copy failed${reason} - try selecting text manually`);
          });
        });
      }
    }
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
// NODE REPORT DISPLAY
// ============================================

/**
 * Display a generated node report in a modal
 * @param {Object} report - Node report data from LLM
 * @param {string} ip - The IP address for the report
 */
export function showNodeReportResult(report, ip) {
  if (report.error) {
    const html = `<div class="muted">Report generation failed: ${escapeHtml(report.error || 'Unknown error')}</div>`;
    ui.showModal({
      title: `Node Intelligence - ${ip}`,
      html,
      allowPin: true
    });
    return;
  }
  
  let html = '<div class="node-report" style="max-height: 600px; overflow-y: auto; padding: 8px;">';
  
  // Header
  html += `
    <div style="background: var(--bg-secondary); padding: 12px; border-radius: 6px; margin-bottom: 16px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <strong style="font-size: 14px;">🖥️ Node Intelligence Report</strong>
        <span class="small muted">${new Date().toLocaleString()}</span>
      </div>
      <div class="mb-1"><strong>IP:</strong> <code>${escapeHtml(ip)}</code></div>
      ${report.threat_level ? `<div class="mb-1"><strong>Threat Level:</strong> ${getSeverityBadge(report.threat_level)}</div>` : ''}
    </div>
  `;
  
  // Summary
  if (report.summary || report.assessment) {
    html += `
      <div style="background: #f0f9ff; border-left: 4px solid #3b82f6; padding: 12px; margin-bottom: 16px; border-radius: 4px;">
        <strong style="color: #1e40af;">Assessment</strong>
        <p style="margin: 8px 0 0 0; line-height: 1.5;">${escapeHtml(report.summary || report.assessment)}</p>
      </div>
    `;
  }
  
  // Organization/ISP info
  if (report.organization || report.isp) {
    html += `<div style="margin-bottom: 12px;">`;
    html += `<strong style="color: var(--accent);">🏢 Network Information</strong>`;
    html += `<div style="margin-top: 8px; font-size: 13px;">`;
    if (report.organization) html += `<div><strong>Organization:</strong> ${escapeHtml(report.organization)}</div>`;
    if (report.isp) html += `<div><strong>ISP:</strong> ${escapeHtml(report.isp)}</div>`;
    if (report.asn) html += `<div><strong>ASN:</strong> ${escapeHtml(report.asn)}</div>`;
    if (report.location) html += `<div><strong>Location:</strong> ${escapeHtml(report.location)}</div>`;
    html += `</div></div>`;
  }
  
  // Threat indicators
  if (report.indicators?.length || report.threat_indicators?.length) {
    const indicators = report.indicators || report.threat_indicators;
    html += `<div style="margin-bottom: 12px;">`;
    html += `<strong style="color: #ef4444;">🚨 Threat Indicators</strong>`;
    html += `<ul style="margin: 8px 0; padding-left: 20px; font-size: 12px;">`;
    indicators.slice(0, 10).forEach(ind => {
      html += `<li>${escapeHtml(typeof ind === 'string' ? ind : JSON.stringify(ind))}</li>`;
    });
    html += `</ul></div>`;
  }
  
  // Activity history
  if (report.activity_history?.length || report.history?.length) {
    const history = report.activity_history || report.history;
    html += `<div style="margin-bottom: 12px;">`;
    html += `<strong style="color: var(--accent);">📅 Activity History</strong>`;
    html += `<ul style="margin: 8px 0; padding-left: 20px; font-size: 12px;">`;
    history.slice(0, 5).forEach(item => {
      html += `<li>${escapeHtml(typeof item === 'string' ? item : JSON.stringify(item))}</li>`;
    });
    html += `</ul></div>`;
  }
  
  // Recommendations
  if (report.recommendations?.length) {
    html += `<div style="margin-bottom: 12px;">`;
    html += `<strong style="color: #22c55e;">✅ Recommendations</strong>`;
    html += `<ol style="margin: 8px 0; padding-left: 20px; font-size: 12px;">`;
    report.recommendations.slice(0, 5).forEach(rec => {
      html += `<li>${escapeHtml(rec)}</li>`;
    });
    html += `</ol></div>`;
  }
  
  // Raw data fallback
  if (!report.summary && !report.assessment) {
    html += `<details style="margin-top: 16px;">`;
    html += `<summary class="small muted" style="cursor: pointer;">View raw data</summary>`;
    html += `<pre style="margin-top: 8px; font-size: 11px; overflow-x: auto;">${escapeHtml(JSON.stringify(report, null, 2))}</pre>`;
    html += `</details>`;
  }
  
  html += '</div>';
  
  ui.showModal({
    title: `Node Intelligence - ${ip}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Intel: ${ip}`, html)
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
