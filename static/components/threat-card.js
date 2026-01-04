/**
 * Threat Card Component
 * Renders threat analyses as rich UI cards instead of raw JSON
 */

import { escapeHtml } from '../util.js';
import { getSeverityBadge } from '../util.js';

/**
 * Render a threat analysis as a UI card
 * @param {Object} threat - Threat analysis data
 * @param {Object} options - Rendering options
 * @returns {string} HTML string for the threat card
 */
export function renderThreatCard(threat, options = {}) {
  if (!threat) return '<div class="muted">No threat data</div>';
  
  const {
    showActions = true,
    showDetails = true,
    compact = false
  } = options;
  
  const severityColor = getSeverityColor(threat.severity);
  const threatIcon = getThreatIcon(threat.threat_type);
  
  if (compact) {
    return renderCompactThreatCard(threat, threatIcon, severityColor);
  }
  
  return renderFullThreatCard(threat, options, threatIcon, severityColor);
}

function renderCompactThreatCard(threat, threatIcon, severityColor) {
  return `
    <div class="threat-card threat-card--compact" data-threat-id="${threat.id || ''}" style="border-left: 3px solid ${severityColor};">
      <div class="threat-card__header">
        <span class="threat-card__icon">${threatIcon}</span>
        <strong class="threat-card__type">${escapeHtml(threat.threat_type || 'Unknown')}</strong>
        ${getSeverityBadge(threat.severity)}
      </div>
      <div class="threat-card__summary muted">${escapeHtml((threat.summary || '').substring(0, 100))}${threat.summary?.length > 100 ? '...' : ''}</div>
    </div>
  `;
}

function renderFullThreatCard(threat, options, threatIcon, severityColor) {
  const { showActions, showDetails } = options;
  
  const analyzedAt = threat.analyzed_at ? new Date(threat.analyzed_at).toLocaleString() : '—';
  const confidence = threat.confidence ? `${Math.round(threat.confidence * 100)}%` : '—';
  
  // MITRE ATT&CK section
  let mitreHtml = '';
  if (threat.tactics?.length || threat.techniques?.length) {
    mitreHtml = `
      <div class="threat-card__mitre">
        <div class="threat-card__mitre-header">🎯 MITRE ATT&CK</div>
        ${threat.tactics?.length ? `
          <div class="threat-card__mitre-row">
            <span class="threat-card__mitre-label">Tactics:</span>
            <div class="threat-card__tags">
              ${threat.tactics.map(t => `<span class="threat-card__tag threat-card__tag--tactic">${escapeHtml(t)}</span>`).join('')}
            </div>
          </div>
        ` : ''}
        ${threat.techniques?.length ? `
          <div class="threat-card__mitre-row">
            <span class="threat-card__mitre-label">Techniques:</span>
            <div class="threat-card__tags">
              ${threat.techniques.map(t => `<span class="threat-card__tag threat-card__tag--technique">${escapeHtml(t)}</span>`).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    `;
  }
  
  // Indicators section
  let indicatorsHtml = '';
  if (showDetails && threat.indicators?.length) {
    indicatorsHtml = `
      <div class="threat-card__indicators">
        <div class="threat-card__indicators-header">🚨 Indicators of Compromise (${threat.indicators.length})</div>
        <div class="threat-card__indicators-list">
          ${threat.indicators.slice(0, 5).map(ioc => `
            <div class="threat-card__indicator"><code>${escapeHtml(typeof ioc === 'string' ? ioc : JSON.stringify(ioc))}</code></div>
          `).join('')}
          ${threat.indicators.length > 5 ? `<div class="threat-card__more muted">...and ${threat.indicators.length - 5} more</div>` : ''}
        </div>
      </div>
    `;
  }
  
  // Actions section
  let actionsHtml = '';
  if (showActions) {
    actionsHtml = `
      <div class="threat-card__actions">
        <button class="threat-action-btn" data-action="countermeasure" data-threat-id="${threat.id}" title="Get Countermeasures">
          🛡️ Countermeasures
        </button>
        <button class="threat-action-btn" data-action="rules" data-threat-id="${threat.id}" title="Generate Detection Rules">
          📜 Rules
        </button>
        <button class="threat-action-btn" data-action="similar" data-threat-id="${threat.id}" title="Find Similar Threats">
          🔗 Similar
        </button>
      </div>
    `;
  }
  
  return `
    <div class="threat-card" data-threat-id="${threat.id || ''}" style="border-left: 4px solid ${severityColor};">
      <div class="threat-card__header">
        <div class="threat-card__title">
          <span class="threat-card__icon">${threatIcon}</span>
          <strong class="threat-card__type">${escapeHtml(threat.threat_type || 'Unknown Threat')}</strong>
          ${getSeverityBadge(threat.severity)}
        </div>
        <div class="threat-card__meta muted">
          <span>Confidence: ${confidence}</span>
          <span>•</span>
          <span>${analyzedAt}</span>
        </div>
      </div>
      
      <div class="threat-card__summary-section">
        <div class="threat-card__summary">${escapeHtml(threat.summary || 'No summary available.')}</div>
      </div>
      
      ${mitreHtml}
      ${indicatorsHtml}
      
      ${threat.attacker_profile ? renderAttackerProfile(threat.attacker_profile) : ''}
      
      ${actionsHtml}
    </div>
  `;
}

function renderAttackerProfile(profile) {
  if (!profile || typeof profile !== 'object') return '';
  
  const profileItems = [];
  
  if (profile.skill_level) {
    profileItems.push(`<span class="attacker-profile__item">🎓 ${escapeHtml(profile.skill_level)}</span>`);
  }
  if (profile.automation) {
    profileItems.push(`<span class="attacker-profile__item">🤖 ${escapeHtml(profile.automation)}</span>`);
  }
  if (profile.motivation) {
    profileItems.push(`<span class="attacker-profile__item">💭 ${escapeHtml(profile.motivation)}</span>`);
  }
  
  if (profileItems.length === 0) return '';
  
  return `
    <div class="threat-card__attacker-profile">
      <div class="attacker-profile__header">👤 Attacker Profile</div>
      <div class="attacker-profile__items">${profileItems.join('')}</div>
    </div>
  `;
}

/**
 * Render multiple threats as a list
 * @param {Array} threats - Array of threat objects
 * @param {Object} options - Rendering options
 * @returns {string} HTML string for threats list
 */
export function renderThreatsList(threats, options = {}) {
  if (!threats || threats.length === 0) {
    return '<div class="threats-list threats-list--empty muted">No threats found</div>';
  }
  
  const { maxItems = 5, compact = true, title = null } = options;
  const displayThreats = threats.slice(0, maxItems);
  
  let html = '<div class="threats-list">';
  
  if (title) {
    html += `<div class="threats-list__header">${escapeHtml(title)} (${threats.length})</div>`;
  }
  
  html += displayThreats.map(threat => 
    renderThreatCard(threat, { ...options, compact })
  ).join('');
  
  if (threats.length > maxItems) {
    html += `<div class="threats-list__more muted">...and ${threats.length - maxItems} more threats</div>`;
  }
  
  html += '</div>';
  return html;
}

/**
 * Render a threat summary for natural language response
 * @param {Object} threat - Threat analysis data
 * @returns {string} Natural language summary
 */
export function summarizeThreat(threat) {
  if (!threat) return 'No threat analysis available.';
  
  const parts = [];
  
  if (threat.threat_type) {
    parts.push(`This appears to be a **${threat.threat_type}** attack`);
  }
  
  if (threat.severity) {
    parts.push(`with **${threat.severity}** severity`);
  }
  
  if (threat.confidence) {
    parts.push(`(${Math.round(threat.confidence * 100)}% confidence)`);
  }
  
  parts.push('.');
  
  if (threat.summary) {
    parts.push(`\n\n${threat.summary}`);
  }
  
  if (threat.tactics?.length) {
    parts.push(`\n\n**MITRE ATT&CK Tactics:** ${threat.tactics.join(', ')}`);
  }
  
  if (threat.techniques?.length) {
    parts.push(`\n**Techniques:** ${threat.techniques.join(', ')}`);
  }
  
  return parts.join(' ');
}

function getSeverityColor(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return '#ef4444';
    case 'high': return '#f59e0b';
    case 'medium': return '#eab308';
    case 'low': return '#22c55e';
    default: return '#6b7280';
  }
}

function getThreatIcon(threatType) {
  const type = (threatType || '').toLowerCase();
  if (type.includes('brute')) return '🔑';
  if (type.includes('scan')) return '🔍';
  if (type.includes('malware')) return '🦠';
  if (type.includes('bot')) return '🤖';
  if (type.includes('crypto')) return '⛏️';
  if (type.includes('exploit')) return '💥';
  if (type.includes('recon')) return '👁️';
  return '⚠️';
}

// Export component styles
export const threatCardStyles = `
  .threat-card {
    background: var(--glass, rgba(255,255,255,0.05));
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 8px;
    transition: all 0.2s ease;
  }
  
  .threat-card:hover {
    background: var(--bg-hover, rgba(255,255,255,0.1));
  }
  
  .threat-card--compact {
    padding: 8px 12px;
  }
  
  .threat-card__header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 8px;
  }
  
  .threat-card__title {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  
  .threat-card__icon {
    font-size: 16px;
  }
  
  .threat-card__type {
    font-size: 13px;
  }
  
  .threat-card__meta {
    font-size: 10px;
    display: flex;
    gap: 4px;
  }
  
  .threat-card__summary-section {
    margin-bottom: 12px;
  }
  
  .threat-card__summary {
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-secondary, #ccc);
  }
  
  .threat-card__mitre {
    margin-bottom: 12px;
    padding: 8px;
    background: var(--bg-secondary, rgba(255,255,255,0.03));
    border-radius: 4px;
  }
  
  .threat-card__mitre-header {
    font-size: 11px;
    font-weight: 600;
    margin-bottom: 6px;
    color: var(--text-muted, #888);
  }
  
  .threat-card__mitre-row {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    margin-bottom: 4px;
  }
  
  .threat-card__mitre-label {
    font-size: 10px;
    color: var(--text-muted, #888);
    white-space: nowrap;
    min-width: 70px;
  }
  
  .threat-card__tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  
  .threat-card__tag {
    font-size: 9px;
    padding: 2px 6px;
    border-radius: 3px;
  }
  
  .threat-card__tag--tactic {
    background: rgba(59, 130, 246, 0.2);
    color: #3b82f6;
    border: 1px solid rgba(59, 130, 246, 0.3);
  }
  
  .threat-card__tag--technique {
    background: rgba(234, 179, 8, 0.2);
    color: #eab308;
    border: 1px solid rgba(234, 179, 8, 0.3);
  }
  
  .threat-card__indicators {
    margin-bottom: 12px;
  }
  
  .threat-card__indicators-header {
    font-size: 11px;
    font-weight: 600;
    margin-bottom: 4px;
    color: #ef4444;
  }
  
  .threat-card__indicator {
    font-size: 10px;
    padding: 2px 6px;
    background: rgba(239, 68, 68, 0.1);
    border-radius: 3px;
    margin-bottom: 2px;
  }
  
  .threat-card__indicator code {
    font-family: monospace;
    color: #f87171;
  }
  
  .threat-card__attacker-profile {
    margin-bottom: 12px;
    padding: 8px;
    background: var(--bg-secondary, rgba(255,255,255,0.03));
    border-radius: 4px;
  }
  
  .attacker-profile__header {
    font-size: 11px;
    font-weight: 600;
    margin-bottom: 6px;
    color: var(--text-muted, #888);
  }
  
  .attacker-profile__items {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  
  .attacker-profile__item {
    font-size: 11px;
    padding: 2px 6px;
    background: rgba(99, 102, 241, 0.1);
    border-radius: 3px;
  }
  
  .threat-card__actions {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border, rgba(255,255,255,0.1));
  }
  
  .threat-action-btn {
    font-size: 11px;
    padding: 4px 8px;
    border: 1px solid var(--border, rgba(255,255,255,0.2));
    border-radius: 4px;
    background: transparent;
    cursor: pointer;
    transition: all 0.2s;
    color: inherit;
  }
  
  .threat-action-btn:hover {
    background: var(--accent, #6366f1);
    color: white;
    border-color: var(--accent, #6366f1);
  }
  
  .threats-list__header {
    font-size: 12px;
    font-weight: 600;
    margin-bottom: 8px;
    color: var(--text-primary, #fff);
  }
  
  .threats-list__more {
    font-size: 11px;
    padding: 8px;
    text-align: center;
  }
`;
