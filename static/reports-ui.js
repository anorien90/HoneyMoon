// Reports UI module
// Provides interface for viewing and managing forensic reports

import { apiGet, apiPost } from './api.js';
import { escapeHtml, getSeverityBadge } from './util.js';
import * as ui from './ui.js';
import { generateFormalReport } from './analysis-ui.js';
import * as honeypotApi from './honeypot.js';

const $ = id => document.getElementById(id);

// Store for generated reports (in-memory cache)
let reportsCache = [];

// ============================================
// API FUNCTIONS
// ============================================

async function fetchReports() {
  try {
    // Get threat analyses which may contain formal reports
    const res = await apiGet('/api/v1/threats?limit=100');
    if (!res.ok) {
      console.error('Failed to fetch reports:', res.error);
      return [];
    }
    
    // Filter for formal reports or threat analyses that can be used to generate reports
    const threats = res.data.threats || [];
    reportsCache = threats.map(threat => ({
      id: threat.id,
      // Use source_id for session_id (ThreatAnalysis model uses source_id, not session_id)
      session_id: threat.source_id,
      source_type: threat.source_type,
      threat_type: threat.threat_type,
      severity: threat.severity,
      analyzed_at: threat.analyzed_at,
      source_ip: threat.source_ip,
      summary: threat.summary,
      report_available: !!threat.formal_report
    }));
    
    return reportsCache;
  } catch (err) {
    console.error('Error fetching reports:', err);
    return [];
  }
}

async function generateReportForSession(sessionId) {
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
    
    ui.toast('Report generated successfully');
    await refreshReportsList();
    return res.data;
  } catch (err) {
    ui.setLoading(false);
    console.error('Report generation failed:', err);
    ui.toast('Report generation failed');
    return null;
  }
}

async function exportReportsAsJSON(reports) {
  const dataStr = JSON.stringify(reports, null, 2);
  const dataBlob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(dataBlob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `forensic-reports-export-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(url);
  ui.toast(`Exported ${reports.length} report${reports.length !== 1 ? 's' : ''}`);
}

// ============================================
// UI RENDERING
// ============================================

async function refreshReportsList() {
  const reports = await fetchReports();
  renderReportsList(reports);
}

function renderReportsList(reports) {
  const container = $('reportsList');
  if (!container) return;
  
  if (!reports.length) {
    container.innerHTML = '<div class="muted">No reports generated yet</div>';
    return;
  }
  
  const frag = document.createDocumentFragment();
  
  reports.forEach(report => {
    const div = document.createElement('div');
    div.className = 'py-2 border-b clickable report-row';
    div.dataset.reportId = report.id;
    // Only set session_id if it exists and source_type is 'session'
    if (report.session_id && report.source_type === 'session') {
      div.dataset.sessionId = report.session_id;
    }
    div.dataset.sourceType = report.source_type || '';
    div.dataset.sourceIp = report.source_ip || '';
    
    const severityBadge = getSeverityBadge(report.severity);
    const time = report.analyzed_at ? new Date(report.analyzed_at).toLocaleString() : '';
    const reportIcon = report.report_available ? '✅' : '📄';
    
    // Display source info based on source_type
    let sourceInfo = '';
    if (report.source_type === 'session' && report.session_id) {
      sourceInfo = `Session ${report.session_id}`;
    } else if (report.source_type === 'node' && report.source_ip) {
      sourceInfo = `Node ${report.source_ip}`;
    } else if (report.source_type === 'access') {
      sourceInfo = `Access ${report.source_ip || ''}`;
    } else if (report.source_type === 'connection') {
      sourceInfo = 'Connection Analysis';
    } else {
      sourceInfo = report.source_ip ? `IP: ${report.source_ip}` : '—';
    }
    
    div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          ${reportIcon} ${severityBadge}
          <span>${escapeHtml(report.threat_type || 'Unknown')}</span>
        </div>
        <span class="muted small">${escapeHtml(sourceInfo)}</span>
      </div>
      <div class="muted small">${escapeHtml(report.summary?.substring(0, 100) || '')}${report.summary?.length > 100 ? '...' : ''}</div>
      <div class="muted small">${time} • ${escapeHtml(report.source_ip || '—')}</div>
    `;
    
    frag.appendChild(div);
  });
  
  container.innerHTML = '';
  container.appendChild(frag);
}

// ============================================
// EXPORT FUNCTIONALITY
// ============================================

/**
 * Export multiple reports as JSON with concurrent API calls
 * @param {Array} reportsList - List of report objects to export
 */
async function exportReports(reportsList) {
  if (!reportsList.length) {
    ui.toast('No reports to export');
    return;
  }
  
  ui.setLoading(true, `Exporting ${reportsList.length} report${reportsList.length !== 1 ? 's' : ''}...`);
  
  // Use Promise.allSettled for concurrent requests with error handling
  const promises = reportsList
    .filter(report => report.session_id)
    .map(report => 
      apiPost('/api/v1/llm/formal_report', { session_id: report.session_id }, { timeout: 180000 })
        .then(res => res.ok ? res.data : null)
        .catch(err => {
          console.error(`Failed to fetch report for session ${report.session_id}:`, err);
          return null;
        })
    );
  
  const results = await Promise.allSettled(promises);
  const fullReports = results
    .filter(result => result.status === 'fulfilled' && result.value)
    .map(result => result.value);
  
  ui.setLoading(false);
  
  if (fullReports.length) {
    exportReportsAsJSON(fullReports);
  } else {
    ui.toast('No reports could be exported');
  }
}

// ============================================
// EVENT HANDLERS
// ============================================

function setupEventHandlers() {
  // Generate report button
  $('generateReportBtn')?.addEventListener('click', async () => {
    const sessionId = $('reportSessionId')?.value?.trim();
    if (sessionId) {
      // Generate report and show it directly without a second API call
      ui.setLoading(true, 'Generating formal report...');
      
      try {
        const res = await apiPost('/api/v1/llm/formal_report', { session_id: sessionId }, { timeout: 180000 });
        ui.setLoading(false);
        
        if (!res.ok) {
          ui.toast(res.error || 'Report generation failed');
          return;
        }
        
        ui.toast('Report generated successfully');
        await refreshReportsList();
        
        // Import and show the report modal with the generated data
        const { showFormalReportModal } = await import('./analysis-ui.js');
        showFormalReportModal(res.data, parseInt(sessionId, 10));
      } catch (err) {
        ui.setLoading(false);
        console.error('Report generation failed:', err);
        ui.toast('Report generation failed');
      }
    }
  });
  
  // Generate node report button
  $('generateNodeReportBtn')?.addEventListener('click', async () => {
    const ip = $('reportNodeIp')?.value?.trim();
    if (!ip) {
      ui.toast('Enter an IP address');
      return;
    }
    
    ui.setLoading(true, 'Generating node intelligence report...');
    
    try {
      const res = await honeypotApi.generateNodeReport(ip);
      ui.setLoading(false);
      
      if (!res.ok) {
        ui.toast(res.error || 'Node report generation failed');
        return;
      }
      
      ui.toast('Node report generated successfully');
      showNodeReportModal(res.data, ip);
    } catch (err) {
      ui.setLoading(false);
      console.error('Node report generation failed:', err);
      ui.toast('Node report generation failed');
    }
  });
  
  // Generate HTTP activity report button
  $('generateHttpReportBtn')?.addEventListener('click', async () => {
    const ip = $('reportHttpIp')?.value?.trim();
    
    ui.setLoading(true, 'Generating HTTP activity report...');
    
    try {
      const res = await honeypotApi.generateHttpReport(ip || null, 100);
      ui.setLoading(false);
      
      if (!res.ok) {
        ui.toast(res.error || 'HTTP report generation failed');
        return;
      }
      
      ui.toast('HTTP activity report generated successfully');
      showHttpReportModal(res.data, ip);
    } catch (err) {
      ui.setLoading(false);
      console.error('HTTP report generation failed:', err);
      ui.toast('HTTP activity report generation failed');
    }
  });
  
  // Refresh reports button
  $('refreshReportsBtn')?.addEventListener('click', refreshReportsList);
  
  // Export all reports
  $('exportAllReportsBtn')?.addEventListener('click', async () => {
    await exportReports(reportsCache);
  });
  
  // Export recent reports
  $('exportRecentReportsBtn')?.addEventListener('click', async () => {
    const recentReports = reportsCache.slice(0, 10);
    await exportReports(recentReports);
  });
  
  // Report row click handler - view report based on source type
  document.addEventListener('click', async (e) => {
    const reportRow = e.target.closest('.report-row');
    if (!reportRow) return;
    
    const sourceType = reportRow.dataset.sourceType;
    const sessionId = reportRow.dataset.sessionId ? parseInt(reportRow.dataset.sessionId, 10) : null;
    const sourceIp = reportRow.dataset.sourceIp;
    
    ui.setLoading(true, 'Loading report...');
    
    try {
      let res;
      
      // Generate report based on source type
      if (sourceType === 'session' && sessionId) {
        res = await apiPost('/api/v1/llm/formal_report', { session_id: sessionId }, { timeout: 180000 });
        ui.setLoading(false);
        
        if (!res.ok) {
          ui.toast(res.error || 'Failed to load report');
          return;
        }
        
        const { showFormalReportModal } = await import('./analysis-ui.js');
        showFormalReportModal(res.data, sessionId);
      } else if (sourceType === 'node' && sourceIp) {
        res = await honeypotApi.generateNodeReport(sourceIp);
        ui.setLoading(false);
        
        if (!res.ok) {
          ui.toast(res.error || 'Failed to load node report');
          return;
        }
        
        showNodeReportModal(res.data, sourceIp);
      } else if (sourceType === 'access' && sourceIp) {
        res = await honeypotApi.generateHttpReport(sourceIp, 100);
        ui.setLoading(false);
        
        if (!res.ok) {
          ui.toast(res.error || 'Failed to load HTTP report');
          return;
        }
        
        showHttpReportModal(res.data, sourceIp);
      } else if (sessionId) {
        // Fallback: try to generate session report if session_id exists
        res = await apiPost('/api/v1/llm/formal_report', { session_id: sessionId }, { timeout: 180000 });
        ui.setLoading(false);
        
        if (!res.ok) {
          ui.toast(res.error || 'Failed to load report');
          return;
        }
        
        const { showFormalReportModal } = await import('./analysis-ui.js');
        showFormalReportModal(res.data, sessionId);
      } else {
        ui.setLoading(false);
        ui.toast('Unable to determine report source');
      }
    } catch (err) {
      ui.setLoading(false);
      console.error('Failed to load report:', err);
      ui.toast('Failed to load report');
    }
  });
}

// ============================================
// NODE REPORT MODAL
// ============================================

function showNodeReportModal(data, ip) {
  const severityColors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    benign: '#10b981'
  };
  
  const threatLevel = data.threat_assessment?.threat_level?.toLowerCase() || 'unknown';
  const severityColor = severityColors[threatLevel] || '#6b7280';
  
  let html = `<div class="node-report" style="max-height: 70vh; overflow-y: auto;">
    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--glass); border-radius: var(--radius); border-left: 4px solid ${severityColor};">
      <div>
        <div class="font-medium">🌐 Node Intelligence Report: ${escapeHtml(ip)}</div>
        <div class="text-xs muted">Threat Level: <span style="color: ${severityColor}; font-weight: 600; text-transform: uppercase;">${escapeHtml(threatLevel)}</span> • Confidence: ${data.threat_assessment?.confidence ? Math.round(data.threat_assessment.confidence * 100) + '%' : '—'}</div>
      </div>
    </div>`;
  
  if (data.summary) {
    html += `<div class="mt-2"><strong>📝 Executive Summary</strong><div class="text-sm mt-1" style="line-height: 1.5;">${escapeHtml(data.summary)}</div></div>`;
  }
  
  if (data.activity_patterns?.length) {
    html += `<div class="mt-3"><strong>🔍 Activity Patterns</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.activity_patterns.forEach(pattern => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(pattern)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  if (data.behavioral_indicators?.length) {
    html += `<div class="mt-3"><strong>⚠️ Behavioral Indicators</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.behavioral_indicators.forEach(indicator => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(indicator)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  if (data.attribution_analysis) {
    const attr = data.attribution_analysis;
    html += `<div class="mt-3"><strong>🎯 Attribution Analysis</strong><div class="text-xs mt-1" style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">`;
    if (attr.organization_assessment) {
      html += `<div><span class="muted">Organization:</span> ${escapeHtml(attr.organization_assessment)}</div>`;
    }
    if (attr.geographic_analysis) {
      html += `<div><span class="muted">Geography:</span> ${escapeHtml(attr.geographic_analysis)}</div>`;
    }
    if (attr.infrastructure_type) {
      html += `<div><span class="muted">Infrastructure:</span> ${escapeHtml(attr.infrastructure_type)}</div>`;
    }
    html += `</div></div>`;
  }
  
  if (data.mitre_tactics?.length) {
    html += `<div class="mt-3"><strong>🎯 MITRE ATT&CK Tactics</strong><div class="text-xs mt-1" style="display: flex; gap: 0.25rem; flex-wrap: wrap;">`;
    data.mitre_tactics.forEach(t => {
      html += `<span style="padding: 0.125rem 0.5rem; background: #3b82f622; border-radius: 4px; border: 1px solid #3b82f6;">${escapeHtml(t)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.recommendations?.length) {
    html += `<div class="mt-3"><strong>✅ Recommendations</strong><ol class="text-xs mt-1" style="margin-left: 1rem; padding-left: 0.5rem;">`;
    data.recommendations.forEach(rec => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(rec)}</li>`;
    });
    html += `</ol></div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `🌐 Node Intelligence Report - ${ip}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Node Report ${ip}`, html)
  });
}

// ============================================
// HTTP REPORT MODAL
// ============================================

function showHttpReportModal(data, ip) {
  const severityColors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    benign: '#10b981'
  };
  
  const threatLevel = data.threat_assessment?.threat_level?.toLowerCase() || 'unknown';
  const severityColor = severityColors[threatLevel] || '#6b7280';
  
  let html = `<div class="http-report" style="max-height: 70vh; overflow-y: auto;">
    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--glass); border-radius: var(--radius); border-left: 4px solid ${severityColor};">
      <div>
        <div class="font-medium">🌐 HTTP Activity Report${ip ? `: ${escapeHtml(ip)}` : ''}</div>
        <div class="text-xs muted">Threat Level: <span style="color: ${severityColor}; font-weight: 600; text-transform: uppercase;">${escapeHtml(threatLevel)}</span> • Analyzed ${data.access_count || 0} requests</div>
      </div>
    </div>`;
  
  // Handle summary - can be string or object
  if (data.summary) {
    html += `<div class="mt-2"><strong>📝 Summary</strong>`;
    if (typeof data.summary === 'object') {
      html += `<div class="text-sm mt-1" style="line-height: 1.5;">`;
      if (data.summary.activity) {
        html += `<div><strong>Activity:</strong> ${escapeHtml(data.summary.activity)}</div>`;
      }
      if (data.summary.source) {
        html += `<div><strong>Source:</strong> ${escapeHtml(data.summary.source)}</div>`;
      }
      if (data.summary.user_agent) {
        html += `<div><strong>User Agent:</strong> ${escapeHtml(data.summary.user_agent)}</div>`;
      }
      html += `</div>`;
    } else {
      html += `<div class="text-sm mt-1" style="line-height: 1.5;">${escapeHtml(data.summary)}</div>`;
    }
    html += `</div>`;
  }
  
  // Anomalies section
  if (data.anomalies?.length) {
    html += `<div class="mt-3"><strong>⚠️ Anomalies</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.anomalies.forEach(anomaly => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(anomaly)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  if (data.attack_patterns?.length) {
    html += `<div class="mt-3"><strong>⚔️ Attack Patterns Detected</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.attack_patterns.forEach(pattern => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(pattern)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  if (data.scanner_detection) {
    const scanner = data.scanner_detection;
    html += `<div class="mt-3"><strong>🔎 Scanner Detection</strong><div class="text-xs mt-1 p-2 border rounded" style="background: var(--glass);">`;
    html += `<div>Scanner Detected: <strong>${scanner.is_scanner ? 'Yes' : 'No'}</strong></div>`;
    if (scanner.scanner_type) {
      html += `<div>Type: ${escapeHtml(scanner.scanner_type)}</div>`;
    }
    if (scanner.evidence) {
      html += `<div class="muted mt-1">${escapeHtml(scanner.evidence)}</div>`;
    }
    html += `</div></div>`;
  }
  
  // Threat assessment details
  if (data.threat_assessment) {
    const ta = data.threat_assessment;
    const taLevel = (ta.threat_level || 'unknown').toLowerCase();
    const taColor = severityColors[taLevel] || '#6b7280';
    html += `<div class="mt-3"><strong>🎯 Threat Assessment</strong><div class="text-xs mt-1 p-2 border rounded" style="background: var(--glass);">`;
    html += `<div><strong>Threat Level:</strong> <span style="color: ${taColor}; font-weight: 600;">${escapeHtml(ta.threat_level || 'Unknown')}</span></div>`;
    if (ta.confidence != null) {
      html += `<div><strong>Confidence:</strong> ${Math.round(ta.confidence * 100)}%</div>`;
    }
    if (ta.reasoning) {
      html += `<div class="muted mt-1">${escapeHtml(ta.reasoning)}</div>`;
    }
    html += `</div></div>`;
  }
  
  // Vulnerability probes
  if (data.vulnerability_probes?.length) {
    html += `<div class="mt-3"><strong>🔓 Vulnerability Probes</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.vulnerability_probes.forEach(probe => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(probe)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  if (data.suspicious_paths?.length) {
    html += `<div class="mt-3"><strong>🚨 Suspicious Paths</strong><div class="text-xs mt-1" style="display: flex; gap: 0.25rem; flex-wrap: wrap;">`;
    data.suspicious_paths.slice(0, 20).forEach(path => {
      html += `<span style="padding: 0.125rem 0.5rem; background: #dc262622; border-radius: 4px; border: 1px solid #dc2626; font-family: monospace;">${escapeHtml(path)}</span>`;
    });
    if (data.suspicious_paths.length > 20) {
      html += `<span class="muted">...and ${data.suspicious_paths.length - 20} more</span>`;
    }
    html += `</div></div>`;
  }
  
  // Suspicious user agents
  if (data.suspicious_user_agents?.length) {
    html += `<div class="mt-3"><strong>🕵️ Suspicious User Agents</strong><div class="text-xs mt-1" style="display: flex; flex-direction: column; gap: 0.25rem;">`;
    data.suspicious_user_agents.forEach(ua => {
      html += `<span style="padding: 0.25rem 0.5rem; background: #f59e0b22; border-radius: 4px; border: 1px solid #f59e0b; font-family: monospace; font-size: 0.65rem;">${escapeHtml(ua)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.mitre_techniques?.length) {
    html += `<div class="mt-3"><strong>🔧 MITRE ATT&CK Techniques</strong><div class="text-xs mt-1" style="display: flex; gap: 0.25rem; flex-wrap: wrap;">`;
    data.mitre_techniques.forEach(t => {
      html += `<span style="padding: 0.125rem 0.5rem; background: #8b5cf622; border-radius: 4px; border: 1px solid #8b5cf6;">${escapeHtml(t)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.blocking_rules?.length) {
    html += `<div class="mt-3"><strong>🛡️ Suggested Blocking Rules</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto; margin-top: 0.5rem;">`;
    data.blocking_rules.forEach(rule => {
      html += `${escapeHtml(rule)}\n`;
    });
    html += `</pre></div>`;
  }
  
  if (data.recommendations?.length) {
    html += `<div class="mt-3"><strong>✅ Recommendations</strong><ol class="text-xs mt-1" style="margin-left: 1rem; padding-left: 0.5rem;">`;
    data.recommendations.forEach(rec => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(rec)}</li>`;
    });
    html += `</ol></div>`;
  }
  
  // Report metadata
  if (data.generated_at) {
    html += `<div class="mt-3 text-xs muted" style="text-align: right;">Generated: ${new Date(data.generated_at).toLocaleString()}</div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `🌐 HTTP Activity Report${ip ? ` - ${ip}` : ''}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`HTTP Report${ip ? ` ${ip}` : ''}`, html)
  });
}

// ============================================
// INITIALIZATION
// ============================================

export function initReportsUI() {
  setupEventHandlers();
  refreshReportsList();
}

// Export functions for use in other modules
export {
  refreshReportsList,
  generateReportForSession
};
