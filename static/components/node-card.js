/**
 * Node Card Component
 * Renders network nodes as rich UI cards instead of raw JSON
 */

import { escapeHtml } from '../util.js';

/**
 * Render a network node as a UI card
 * @param {Object} node - Network node data
 * @param {Object} options - Rendering options
 * @returns {string} HTML string for the node card
 */
export function renderNodeCard(node, options = {}) {
  if (!node) return '<div class="muted">No node data</div>';
  
  const {
    showActions = true,
    showExtras = true,
    compact = false
  } = options;
  
  const threatColor = getThreatColor(node);
  const nodeIcon = getNodeIcon(node);
  
  if (compact) {
    return renderCompactNodeCard(node, nodeIcon, threatColor);
  }
  
  return renderFullNodeCard(node, options, nodeIcon, threatColor);
}

function renderCompactNodeCard(node, nodeIcon, threatColor) {
  const location = [node.city, node.country].filter(Boolean).join(', ');
  
  return `
    <div class="node-card node-card--compact" data-ip="${escapeHtml(node.ip || '')}" style="border-left: 3px solid ${threatColor};">
      <div class="node-card__header">
        <span class="node-card__icon">${nodeIcon}</span>
        <strong class="node-card__ip">${escapeHtml(node.ip || '—')}</strong>
      </div>
      <div class="node-card__meta muted">
        ${escapeHtml(node.organization || node.isp || '—')}
        ${location ? ` • ${escapeHtml(location)}` : ''}
      </div>
    </div>
  `;
}

function renderFullNodeCard(node, options, nodeIcon, threatColor) {
  const { showActions, showExtras } = options;
  
  const location = [node.city, node.country].filter(Boolean).join(', ');
  const lastSeen = node.last_seen ? new Date(node.last_seen).toLocaleString() : '—';
  
  // Extra data section
  let extrasHtml = '';
  if (showExtras && node.extra_data) {
    const fingerprints = node.extra_data.fingerprints || {};
    const extras = [];
    
    if (fingerprints.http?.server) {
      extras.push(`<div class="node-card__extra"><span>🌐</span> ${escapeHtml(fingerprints.http.server)}</div>`);
    }
    if (fingerprints.nmap?.osmatch?.[0]?.name) {
      extras.push(`<div class="node-card__extra"><span>💻</span> ${escapeHtml(fingerprints.nmap.osmatch[0].name)}</div>`);
    }
    if (node.is_tor_exit) {
      extras.push(`<div class="node-card__extra node-card__extra--warning"><span>🧅</span> TOR Exit Node</div>`);
    }
    
    if (extras.length > 0) {
      extrasHtml = `<div class="node-card__extras">${extras.join('')}</div>`;
    }
  }
  
  // Actions section
  let actionsHtml = '';
  if (showActions) {
    actionsHtml = `
      <div class="node-card__actions">
        <button class="node-action-btn" data-action="intel" data-ip="${escapeHtml(node.ip)}" title="Get Intelligence">
          🔍 Intel
        </button>
        <button class="node-action-btn" data-action="report" data-ip="${escapeHtml(node.ip)}" title="Generate Report">
          📋 Report
        </button>
        <button class="node-action-btn" data-action="similar" data-ip="${escapeHtml(node.ip)}" title="Find Similar">
          🔗 Similar
        </button>
        <button class="node-action-btn" data-action="trace" data-ip="${escapeHtml(node.ip)}" title="Trace Route">
          🛤️ Trace
        </button>
      </div>
    `;
  }
  
  return `
    <div class="node-card" data-ip="${escapeHtml(node.ip || '')}" style="border-left: 4px solid ${threatColor};">
      <div class="node-card__header">
        <div class="node-card__title">
          <span class="node-card__icon">${nodeIcon}</span>
          <strong class="node-card__ip">${escapeHtml(node.ip || '—')}</strong>
          ${node.hostname ? `<span class="node-card__hostname muted">${escapeHtml(node.hostname)}</span>` : ''}
        </div>
        <div class="node-card__seen muted">Last seen: ${lastSeen}</div>
      </div>
      
      <div class="node-card__details">
        ${node.organization ? `
          <div class="node-card__detail">
            <span class="node-card__label">🏢 Organization:</span>
            <span>${escapeHtml(node.organization)}</span>
          </div>
        ` : ''}
        ${node.isp ? `
          <div class="node-card__detail">
            <span class="node-card__label">📡 ISP:</span>
            <span>${escapeHtml(node.isp)}${node.asn ? ` (${escapeHtml(node.asn)})` : ''}</span>
          </div>
        ` : ''}
        ${location ? `
          <div class="node-card__detail">
            <span class="node-card__label">📍 Location:</span>
            <span>${escapeHtml(location)}</span>
          </div>
        ` : ''}
        ${node.seen_count ? `
          <div class="node-card__detail">
            <span class="node-card__label">👁️ Seen:</span>
            <span>${node.seen_count} times</span>
          </div>
        ` : ''}
      </div>
      
      ${extrasHtml}
      ${actionsHtml}
    </div>
  `;
}

/**
 * Render multiple nodes as a list
 * @param {Array} nodes - Array of node objects
 * @param {Object} options - Rendering options
 * @returns {string} HTML string for nodes list
 */
export function renderNodesList(nodes, options = {}) {
  if (!nodes || nodes.length === 0) {
    return '<div class="nodes-list nodes-list--empty muted">No nodes found</div>';
  }
  
  const { maxItems = 10, compact = true, title = null } = options;
  const displayNodes = nodes.slice(0, maxItems);
  
  let html = '<div class="nodes-list">';
  
  if (title) {
    html += `<div class="nodes-list__header">${escapeHtml(title)} (${nodes.length})</div>`;
  }
  
  html += displayNodes.map(node => 
    renderNodeCard(node, { ...options, compact })
  ).join('');
  
  if (nodes.length > maxItems) {
    html += `<div class="nodes-list__more muted">...and ${nodes.length - maxItems} more nodes</div>`;
  }
  
  html += '</div>';
  return html;
}

/**
 * Render a node summary for natural language response
 * @param {Object} node - Network node data
 * @returns {string} Natural language summary
 */
export function summarizeNode(node) {
  if (!node) return 'No node information available.';
  
  const parts = [];
  
  parts.push(`IP address **${node.ip}**`);
  
  if (node.organization) {
    parts.push(`belongs to **${node.organization}**`);
  }
  
  if (node.city && node.country) {
    parts.push(`located in **${node.city}, ${node.country}**`);
  } else if (node.country) {
    parts.push(`located in **${node.country}**`);
  }
  
  if (node.isp) {
    parts.push(`using ISP **${node.isp}**`);
  }
  
  if (node.is_tor_exit) {
    parts.push('⚠️ This is a **TOR exit node**');
  }
  
  if (node.seen_count > 1) {
    parts.push(`(seen ${node.seen_count} times)`);
  }
  
  return parts.join(' ') + '.';
}

function getThreatColor(node) {
  if (node.is_tor_exit) return '#ef4444';
  if (node.seen_count > 10) return '#f59e0b';
  if (node.seen_count > 5) return '#eab308';
  return '#22c55e';
}

function getNodeIcon(node) {
  if (node.is_tor_exit) return '🧅';
  if (node.hostname?.includes('scan')) return '🔍';
  if (node.organization?.toLowerCase().includes('cloud')) return '☁️';
  if (node.isp?.toLowerCase().includes('mobile')) return '📱';
  return '🖥️';
}

// Export component styles
export const nodeCardStyles = `
  .node-card {
    background: var(--glass, rgba(255,255,255,0.05));
    border-radius: 6px;
    padding: 12px;
    margin-bottom: 8px;
    transition: all 0.2s ease;
  }
  
  .node-card:hover {
    background: var(--bg-hover, rgba(255,255,255,0.1));
  }
  
  .node-card--compact {
    padding: 8px 12px;
  }
  
  .node-card__header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 8px;
  }
  
  .node-card__title {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  
  .node-card__icon {
    font-size: 14px;
  }
  
  .node-card__ip {
    font-family: monospace;
    font-size: 13px;
  }
  
  .node-card__hostname {
    font-size: 11px;
  }
  
  .node-card__seen {
    font-size: 10px;
    white-space: nowrap;
  }
  
  .node-card__details {
    font-size: 12px;
    margin-bottom: 8px;
  }
  
  .node-card__detail {
    display: flex;
    gap: 4px;
    margin-bottom: 4px;
  }
  
  .node-card__label {
    color: var(--text-muted, #888);
    white-space: nowrap;
  }
  
  .node-card__extras {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border, rgba(255,255,255,0.1));
  }
  
  .node-card__extra {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 11px;
    padding: 2px 6px;
    background: var(--bg-secondary, rgba(255,255,255,0.05));
    border-radius: 3px;
  }
  
  .node-card__extra--warning {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
  }
  
  .node-card__actions {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border, rgba(255,255,255,0.1));
  }
  
  .node-action-btn {
    font-size: 11px;
    padding: 4px 8px;
    border: 1px solid var(--border, rgba(255,255,255,0.2));
    border-radius: 4px;
    background: transparent;
    cursor: pointer;
    transition: all 0.2s;
    color: inherit;
  }
  
  .node-action-btn:hover {
    background: var(--accent, #6366f1);
    color: white;
    border-color: var(--accent, #6366f1);
  }
  
  .nodes-list__header {
    font-size: 12px;
    font-weight: 600;
    margin-bottom: 8px;
    color: var(--text-primary, #fff);
  }
  
  .nodes-list__more {
    font-size: 11px;
    padding: 8px;
    text-align: center;
  }
`;
