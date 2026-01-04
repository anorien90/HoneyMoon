/**
 * Session Card Component
 * Renders honeypot sessions as rich UI cards instead of raw JSON
 */

import { escapeHtml } from '../util.js';
import { getSeverityBadge } from '../util.js';

/**
 * Render a honeypot session as a UI card
 * @param {Object} session - Honeypot session data
 * @param {Object} options - Rendering options
 * @returns {string} HTML string for the session card
 */
export function renderSessionCard(session, options = {}) {
  if (!session) return '<div class="muted">No session data</div>';
  
  const {
    showActions = true,
    showCommands = true,
    maxCommands = 5,
    compact = false
  } = options;
  
  const severityColor = getSeverityColor(session.severity);
  const statusIcon = getSessionStatusIcon(session);
  
  if (compact) {
    return renderCompactSessionCard(session, statusIcon, severityColor);
  }
  
  return renderFullSessionCard(session, options, statusIcon, severityColor);
}

function renderCompactSessionCard(session, statusIcon, severityColor) {
  const location = [session.city, session.country].filter(Boolean).join(', ');
  
  return `
    <div class="session-card session-card--compact" data-session-id="${session.id || ''}" style="border-left: 3px solid ${severityColor};">
      <div class="session-card__header">
        <span class="session-card__icon">${statusIcon}</span>
        <strong class="session-card__ip">${escapeHtml(session.src_ip || '—')}</strong>
        <span class="session-card__id muted">#${session.id || '—'}</span>
      </div>
      <div class="session-card__meta muted">
        ${escapeHtml(session.username || 'unknown')}@${escapeHtml(session.dst_port || '22')}
        ${location ? ` • ${escapeHtml(location)}` : ''}
      </div>
    </div>
  `;
}

function renderFullSessionCard(session, options, statusIcon, severityColor) {
  const { showActions, showCommands, maxCommands } = options;
  
  const location = [session.city, session.country].filter(Boolean).join(', ');
  const duration = session.duration ? `${session.duration.toFixed(1)}s` : '—';
  const startTime = session.start_ts ? new Date(session.start_ts).toLocaleString() : '—';
  
  // Commands section
  let commandsHtml = '';
  if (showCommands && session.commands && session.commands.length > 0) {
    const displayCommands = session.commands.slice(0, maxCommands);
    commandsHtml = `
      <div class="session-card__commands">
        <div class="session-card__commands-header">
          <span>📜 Commands (${session.commands.length})</span>
        </div>
        <div class="session-card__commands-list">
          ${displayCommands.map(cmd => `
            <div class="session-card__command">
              <code>${escapeHtml(cmd.command || cmd)}</code>
            </div>
          `).join('')}
          ${session.commands.length > maxCommands ? `
            <div class="session-card__more muted">...and ${session.commands.length - maxCommands} more</div>
          ` : ''}
        </div>
      </div>
    `;
  }
  
  // Actions section
  let actionsHtml = '';
  if (showActions) {
    actionsHtml = `
      <div class="session-card__actions">
        <button class="session-action-btn" data-action="analyze" data-session-id="${session.id}" title="Analyze with AI">
          🔍 Analyze
        </button>
        <button class="session-action-btn" data-action="report" data-session-id="${session.id}" title="Generate Report">
          📋 Report
        </button>
        <button class="session-action-btn" data-action="similar" data-session-id="${session.id}" title="Find Similar">
          🔗 Similar
        </button>
        <button class="session-action-btn" data-action="countermeasures" data-session-id="${session.id}" title="Get Countermeasures">
          🛡️ Defend
        </button>
      </div>
    `;
  }
  
  return `
    <div class="session-card" data-session-id="${session.id || ''}" style="border-left: 4px solid ${severityColor};">
      <div class="session-card__header">
        <div class="session-card__title">
          <span class="session-card__icon">${statusIcon}</span>
          <strong class="session-card__ip">${escapeHtml(session.src_ip || '—')}</strong>
          <span class="session-card__id muted">#${session.id || '—'}</span>
          ${session.severity ? getSeverityBadge(session.severity) : ''}
        </div>
        <div class="session-card__time muted">${startTime}</div>
      </div>
      
      <div class="session-card__details">
        <div class="session-card__detail">
          <span class="session-card__label">User:</span>
          <span>${escapeHtml(session.username || '—')}</span>
        </div>
        <div class="session-card__detail">
          <span class="session-card__label">Port:</span>
          <span>${escapeHtml(session.dst_port || '22')}</span>
        </div>
        <div class="session-card__detail">
          <span class="session-card__label">Duration:</span>
          <span>${duration}</span>
        </div>
        ${location ? `
          <div class="session-card__detail">
            <span class="session-card__label">Location:</span>
            <span>${escapeHtml(location)}</span>
          </div>
        ` : ''}
        ${session.organization ? `
          <div class="session-card__detail">
            <span class="session-card__label">Org:</span>
            <span>${escapeHtml(session.organization)}</span>
          </div>
        ` : ''}
      </div>
      
      ${commandsHtml}
      ${actionsHtml}
    </div>
  `;
}

/**
 * Render multiple sessions as a list
 * @param {Array} sessions - Array of session objects
 * @param {Object} options - Rendering options
 * @returns {string} HTML string for sessions list
 */
export function renderSessionsList(sessions, options = {}) {
  if (!sessions || sessions.length === 0) {
    return '<div class="sessions-list sessions-list--empty muted">No sessions found</div>';
  }
  
  const { maxItems = 10, compact = true, title = null } = options;
  const displaySessions = sessions.slice(0, maxItems);
  
  let html = '<div class="sessions-list">';
  
  if (title) {
    html += `<div class="sessions-list__header">${escapeHtml(title)} (${sessions.length})</div>`;
  }
  
  html += displaySessions.map(session => 
    renderSessionCard(session, { ...options, compact })
  ).join('');
  
  if (sessions.length > maxItems) {
    html += `<div class="sessions-list__more muted">...and ${sessions.length - maxItems} more sessions</div>`;
  }
  
  html += '</div>';
  return html;
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

function getSessionStatusIcon(session) {
  if (session.success === false) return '❌';
  if (session.commands?.length > 5) return '⚠️';
  if (session.duration && session.duration > 60) return '⏱️';
  return '🍯';
}

// Export component styles
export const sessionCardStyles = `
  .session-card {
    background: var(--glass, rgba(255,255,255,0.05));
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 8px;
    transition: all 0.2s ease;
  }
  
  .session-card:hover {
    background: var(--bg-hover, rgba(255,255,255,0.1));
  }
  
  .session-card--compact {
    padding: 8px 12px;
  }
  
  .session-card__header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }
  
  .session-card__title {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  
  .session-card__icon {
    font-size: 14px;
  }
  
  .session-card__ip {
    font-family: monospace;
    font-size: 13px;
  }
  
  .session-card__id {
    font-size: 11px;
  }
  
  .session-card__time {
    font-size: 11px;
  }
  
  .session-card__details {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 6px;
    font-size: 12px;
    margin-bottom: 8px;
  }
  
  .session-card__detail {
    display: flex;
    gap: 4px;
  }
  
  .session-card__label {
    color: var(--text-muted, #888);
  }
  
  .session-card__commands {
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border, rgba(255,255,255,0.1));
  }
  
  .session-card__commands-header {
    font-size: 11px;
    margin-bottom: 4px;
    color: var(--text-muted, #888);
  }
  
  .session-card__command {
    background: var(--bg-secondary, #1e1e1e);
    padding: 4px 8px;
    border-radius: 3px;
    font-size: 11px;
    margin-bottom: 2px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  
  .session-card__command code {
    color: var(--accent, #6366f1);
  }
  
  .session-card__more {
    font-size: 10px;
    padding: 4px;
  }
  
  .session-card__actions {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border, rgba(255,255,255,0.1));
  }
  
  .session-action-btn {
    font-size: 11px;
    padding: 4px 8px;
    border: 1px solid var(--border, rgba(255,255,255,0.2));
    border-radius: 4px;
    background: transparent;
    cursor: pointer;
    transition: all 0.2s;
    color: inherit;
  }
  
  .session-action-btn:hover {
    background: var(--accent, #6366f1);
    color: white;
    border-color: var(--accent, #6366f1);
  }
  
  .sessions-list__header {
    font-size: 12px;
    font-weight: 600;
    margin-bottom: 8px;
    color: var(--text-primary, #fff);
  }
  
  .sessions-list__more {
    font-size: 11px;
    padding: 8px;
    text-align: center;
  }
`;
