// Reports UI module
// Provides interface for viewing and managing forensic reports

import { apiGet, apiPost } from './api.js';
import { escapeHtml, getSeverityBadge } from './util.js';
import * as ui from './ui.js';
import { generateFormalReport } from './analysis-ui.js';

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
      session_id: threat.session_id,
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
    div.dataset.sessionId = report.session_id;
    
    const severityBadge = getSeverityBadge(report.severity);
    const time = report.analyzed_at ? new Date(report.analyzed_at).toLocaleString() : '';
    const reportIcon = report.report_available ? '✅' : '📄';
    
    div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
          ${reportIcon} ${severityBadge}
          <span>${escapeHtml(report.threat_type || 'Unknown')}</span>
        </div>
        <span class="muted small">Session ${report.session_id || '—'}</span>
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
  
  // Report row click handler - view report
  document.addEventListener('click', async (e) => {
    const reportRow = e.target.closest('.report-row');
    if (reportRow?.dataset.sessionId) {
      const sessionId = parseInt(reportRow.dataset.sessionId, 10);
      
      // Fetch and display the report (cached on backend, so efficient)
      ui.setLoading(true, 'Loading report...');
      
      try {
        const res = await apiPost('/api/v1/llm/formal_report', { session_id: sessionId }, { timeout: 180000 });
        ui.setLoading(false);
        
        if (!res.ok) {
          ui.toast(res.error || 'Failed to load report');
          return;
        }
        
        // Import and show the report modal
        const { showFormalReportModal } = await import('./analysis-ui.js');
        showFormalReportModal(res.data, sessionId);
      } catch (err) {
        ui.setLoading(false);
        console.error('Failed to load report:', err);
        ui.toast('Failed to load report');
      }
    }
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
