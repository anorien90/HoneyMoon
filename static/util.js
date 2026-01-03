export function escapeHtml(str) {
  if (!str) return '';
  const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return str.replace(/[&<>"']/g, m => escapeMap[m]);
}

export function truncate(str = '', len = 80) {
  if (str.length <= len) return str;
  return str.slice(0, len - 1) + '…';
}

/**
 * Get a severity badge HTML for display
 * @param {string} severity - Severity level (critical, high, medium, low)
 * @returns {string} HTML for severity badge
 */
export function getSeverityBadge(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return '<span style="background: #ef4444; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">CRITICAL</span>';
    case 'high': return '<span style="background: #f59e0b; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">HIGH</span>';
    case 'medium': return '<span style="background: #f59e0b; color: black; padding: 1px 4px; border-radius: 3px; font-size: 10px;">MEDIUM</span>';
    case 'low': return '<span style="background: #6b7280; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">LOW</span>';
    default: return '<span style="background: #9ca3af; color: white; padding: 1px 4px; border-radius: 3px; font-size: 10px;">UNKNOWN</span>';
  }
}

/**
 * Get pointer coordinates from a mouse or pointer event.
 * Uses PointerEvent properties when available, falls back to MouseEvent.
 * This avoids Firefox deprecation warnings about mozPressure and mozInputSource.
 * @param {MouseEvent|PointerEvent} event - The event object
 * @returns {{ clientX: number, clientY: number, pressure: number, pointerType: string }}
 */
export function getPointerCoords(event) {
  return {
    clientX: event.clientX,
    clientY: event.clientY,
    // Use PointerEvent.pressure instead of deprecated MouseEvent.mozPressure
    pressure: 'pressure' in event ? event.pressure : ('mozPressure' in event ? 0.5 : 0),
    // Use PointerEvent.pointerType instead of deprecated MouseEvent.mozInputSource
    pointerType: 'pointerType' in event ? event.pointerType : 'mouse'
  };
}

export function summarizeNodeDetails(node = {}) {
  const extra = node.extra_data || {};
  const fp = extra.fingerprints || {};

  const portFromBanners = extra.banners && Object.keys(extra.banners).length
    ? Object.entries(extra.banners).slice(0, 5).map(([p, b]) => `${p}${b ? ` (${truncate(String(b), 40)})` : ''}`).join(', ')
    : '';

  const nmapServices = fp.nmap && fp.nmap.services && Object.keys(fp.nmap.services).length
    ? Object.entries(fp.nmap.services).slice(0, 5).map(([p, info]) => {
      const svc = info?.name || info?.product || info?._name;
      return `${p}${svc ? ` ${svc}` : ''}`;
    }).join(', ')
    : '';

  const ports = portFromBanners || nmapServices;

  const osMatch = Array.isArray(fp.nmap?.osmatch) && fp.nmap.osmatch.length ? fp.nmap.osmatch[0] : null;
  const os = osMatch ? `${osMatch.name || 'Unknown'}${osMatch.accuracy ? ` (${osMatch.accuracy}%)` : ''}` : '';

  const httpServer = fp.http?.server || fp.http?.headers?.Server || '';
  const httpsIssuer = fp.https?.cert_subject?.commonName || fp.https?.cert_subject?.CN || '';
  const cipher = Array.isArray(fp.https?.cipher) ? fp.https.cipher[0] : (fp.https?.cipher || '');
  const http = [httpServer, cipher, httpsIssuer].filter(Boolean).map(v => truncate(String(v), 50)).join(' • ');

  const tags = [];
  if (node.is_tor_exit) tags.push('TOR exit');
  if (fp.http_well_known?.['/.git/config']?.status_code === 200) tags.push('Exposed .git');

  return { ports, os, http, tags: tags.join(', ') };
}
