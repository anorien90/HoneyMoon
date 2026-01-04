/**
 * Component Index
 * Re-exports all UI components for easy importing
 */

// Session components
export { renderSessionCard, renderSessionsList, sessionCardStyles } from './session-card.js';

// Node components
export { renderNodeCard, renderNodesList, summarizeNode, nodeCardStyles } from './node-card.js';

// Threat components
export { renderThreatCard, renderThreatsList, summarizeThreat, threatCardStyles } from './threat-card.js';

/**
 * Inject all component styles into the document head
 * Call this once during app initialization
 */
export function injectComponentStyles() {
  // Import styles from each component
  import('./session-card.js').then(m => appendStyles('session-card', m.sessionCardStyles));
  import('./node-card.js').then(m => appendStyles('node-card', m.nodeCardStyles));
  import('./threat-card.js').then(m => appendStyles('threat-card', m.threatCardStyles));
}

function appendStyles(id, css) {
  const existingStyle = document.getElementById(`component-styles-${id}`);
  if (existingStyle) return;
  
  const style = document.createElement('style');
  style.id = `component-styles-${id}`;
  style.textContent = css;
  document.head.appendChild(style);
}

/**
 * Format data for natural language response based on type
 * @param {string} type - Data type (session, sessions, node, nodes, threat, threats)
 * @param {*} data - Data to format
 * @returns {string} Formatted response
 */
export function formatDataResponse(type, data) {
  if (!data) return 'No data available.';
  
  switch (type) {
    case 'session':
      return formatSessionResponse(data);
    case 'sessions':
      return formatSessionsResponse(data);
    case 'node':
      return formatNodeResponse(data);
    case 'nodes':
      return formatNodesResponse(data);
    case 'threat':
      return formatThreatResponse(data);
    case 'threats':
      return formatThreatsResponse(data);
    default:
      return JSON.stringify(data, null, 2);
  }
}

function formatSessionResponse(session) {
  let response = `Found session **#${session.id}** from IP **${session.src_ip}**`;
  
  if (session.username) {
    response += ` (user: ${session.username})`;
  }
  
  if (session.city && session.country) {
    response += ` located in **${session.city}, ${session.country}**`;
  }
  
  response += '.';
  
  if (session.commands?.length) {
    response += `\n\nThe attacker executed **${session.commands.length} commands**`;
    if (session.commands.length <= 3) {
      response += `:\n${session.commands.map(c => `- \`${c.command || c}\``).join('\n')}`;
    }
  }
  
  if (session.duration) {
    response += `\n\nSession lasted **${session.duration.toFixed(1)} seconds**.`;
  }
  
  return response;
}

function formatSessionsResponse(sessions) {
  if (!sessions.length) return 'No sessions found.';
  
  let response = `Found **${sessions.length} sessions**:\n\n`;
  
  // Group by source IP
  const byIp = {};
  sessions.forEach(s => {
    const ip = s.src_ip || 'unknown';
    if (!byIp[ip]) byIp[ip] = [];
    byIp[ip].push(s);
  });
  
  const ipCount = Object.keys(byIp).length;
  response += `• **${ipCount}** unique source IPs\n`;
  
  // Top attackers
  const topIps = Object.entries(byIp)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 3);
  
  if (topIps.length) {
    response += `• Top attacker IPs:\n`;
    topIps.forEach(([ip, sess]) => {
      response += `  - ${ip}: ${sess.length} sessions\n`;
    });
  }
  
  return response;
}

function formatNodeResponse(node) {
  let response = `Information for IP **${node.ip}**:\n\n`;
  
  if (node.organization) {
    response += `• **Organization:** ${node.organization}\n`;
  }
  if (node.isp) {
    response += `• **ISP:** ${node.isp}${node.asn ? ` (${node.asn})` : ''}\n`;
  }
  if (node.city || node.country) {
    response += `• **Location:** ${[node.city, node.country].filter(Boolean).join(', ')}\n`;
  }
  if (node.is_tor_exit) {
    response += `\n⚠️ **Warning:** This is a TOR exit node.\n`;
  }
  if (node.seen_count > 1) {
    response += `\nThis IP has been seen **${node.seen_count} times** in our data.`;
  }
  
  return response;
}

function formatNodesResponse(nodes) {
  if (!nodes.length) return 'No nodes found.';
  
  let response = `Found **${nodes.length} nodes**:\n\n`;
  
  // Group by country
  const byCountry = {};
  nodes.forEach(n => {
    const country = n.country || 'Unknown';
    if (!byCountry[country]) byCountry[country] = 0;
    byCountry[country]++;
  });
  
  const countries = Object.entries(byCountry)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  
  if (countries.length) {
    response += `**By country:**\n`;
    countries.forEach(([country, count]) => {
      response += `- ${country}: ${count} nodes\n`;
    });
  }
  
  // Check for TOR nodes
  const torNodes = nodes.filter(n => n.is_tor_exit);
  if (torNodes.length) {
    response += `\n⚠️ **${torNodes.length}** TOR exit nodes detected.`;
  }
  
  return response;
}

function formatThreatResponse(threat) {
  let response = `**${threat.threat_type || 'Unknown'} Threat** (${threat.severity || 'unknown'} severity):\n\n`;
  
  if (threat.summary) {
    response += `${threat.summary}\n\n`;
  }
  
  if (threat.confidence) {
    response += `**Confidence:** ${Math.round(threat.confidence * 100)}%\n`;
  }
  
  if (threat.tactics?.length) {
    response += `**MITRE Tactics:** ${threat.tactics.join(', ')}\n`;
  }
  
  if (threat.techniques?.length) {
    response += `**Techniques:** ${threat.techniques.join(', ')}\n`;
  }
  
  if (threat.indicators?.length) {
    response += `\n**Indicators of Compromise:** ${threat.indicators.length} found`;
  }
  
  return response;
}

function formatThreatsResponse(threats) {
  if (!threats.length) return 'No threats found.';
  
  let response = `Found **${threats.length} threat analyses**:\n\n`;
  
  // Group by severity
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  threats.forEach(t => {
    const sev = (t.severity || 'unknown').toLowerCase();
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
  });
  
  response += `**By severity:**\n`;
  if (bySeverity.critical) response += `- 🔴 Critical: ${bySeverity.critical}\n`;
  if (bySeverity.high) response += `- 🟠 High: ${bySeverity.high}\n`;
  if (bySeverity.medium) response += `- 🟡 Medium: ${bySeverity.medium}\n`;
  if (bySeverity.low) response += `- 🟢 Low: ${bySeverity.low}\n`;
  
  // Group by threat type
  const byType = {};
  threats.forEach(t => {
    const type = t.threat_type || 'Unknown';
    if (!byType[type]) byType[type] = 0;
    byType[type]++;
  });
  
  const types = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  
  if (types.length) {
    response += `\n**By type:**\n`;
    types.forEach(([type, count]) => {
      response += `- ${type}: ${count}\n`;
    });
  }
  
  return response;
}
