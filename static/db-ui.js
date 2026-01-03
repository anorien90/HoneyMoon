// Optimized DB UI:  consistent error handling, UI updates, and map interactions. 
// Merged:  combines both old and new version features

import { apiGet, apiPost } from './api.js';
import * as ui from './ui.js';
import * as mapModule from './map.js';
import * as honeypotApi from './honeypot.js';
import { updateMarkerCount } from './state.js';

const DB_PANEL_ID = 'dbResultsDatabase';
const refreshMarkerCount = () => updateMarkerCount(() => mapModule.getMarkerCount ? mapModule.getMarkerCount() : 0);

function el(q) { return document.getElementById(q); }

function buildSearchForm() {
  const container = el(DB_PANEL_ID);
  if (!container) return;

  container.innerHTML = `
    <div class="mb-3">
      <div class="flex gap-2 items-center">
        <select id="dbPanelType" class="border rounded px-2 py-1" aria-label="Search type">
          <option value="node">Node / IP</option>
          <option value="org">Organization</option>
          <option value="isp">ISP / ASN</option>
          <option value="analysis">Analysis / Trace</option>
          <option value="honeypot">Honeypot Sessions</option>
          <option value="access">Web Access</option>
          <option value="flow">Flows</option>
          <option value="outgoing">Outgoing Connections</option>
          <option value="threat">Threat Analyses</option>
          <option value="cluster">Attacker Clusters</option>
        </select>
        <input id="dbPanelQuery" type="text" placeholder="Search query (ip, hostname, org, id... )" class="flex-1 border rounded px-3 py-1" aria-label="Search query" />
        <label class="inline-flex items-center gap-2 small ml-2">
          <input id="dbPanelFuzzy" type="checkbox" aria-label="Enable fuzzy search" /> <span class="small muted">Fuzzy</span>
        </label>
        <input id="dbPanelLimit" type="number" value="100" min="1" max="1000" class="w-20 border rounded px-2 py-1" aria-label="Result limit" />
        <button id="dbPanelSearchBtn" class="ml-2 bg-sky-600 text-white rounded px-3 py-1 small" aria-label="Run search">Search</button>
      </div>
    </div>
    <div id="dbPanelResults" class="text-sm muted small compact-scroll" role="region" aria-label="Search results"></div>
    <div id="dbPanelDetail" class="mt-3 text-sm muted small compact-scroll" role="region" aria-label="Search details"></div>
  `;

  el('dbPanelSearchBtn').addEventListener('click', runSearch);
  el('dbPanelQuery').addEventListener('keydown', (e) => { if (e.key === 'Enter') runSearch(); });
}

export async function initDatabasePanel() {
  buildSearchForm();
}

function showMessage(msg, targetId = 'dbPanelResults') {
  const t = el(targetId);
  if (t) t.innerHTML = `<div class="muted small">${msg}</div>`;
}

export async function runSearch() {
  const type = (el('dbPanelType')?.value || 'node');
  const q = (el('dbPanelQuery')?.value || '').trim();
  const fuzzy = el('dbPanelFuzzy')?.checked ? 1 : 0;
  const limit = parseInt(el('dbPanelLimit')?.value || '100', 10) || 100;

  // Some types don't require a search query
  const requiresQuery = !['threat', 'cluster'].includes(type);
  if (requiresQuery && !q) return ui.toast('Enter a search term');
  
  if (q) ui.pushSearchHistory(q);
  ui.setLoading(true, 'Searching DB…');
  
  try {
    let res;
    
    // Handle special types that use different endpoints
    if (type === 'threat') {
      // Use vector search for threats if query provided, otherwise list threats
      if (q) {
        res = await apiGet(`/api/v1/vector/search/threats?q=${encodeURIComponent(q)}&limit=${limit}`, { retries: 2 });
      } else {
        res = await apiGet(`/api/v1/threats?limit=${limit}`, { retries: 2 });
        // Transform response to match expected format
        if (res.ok && res.data?.threats) {
          res.data.results = res.data.threats;
        }
      }
    } else if (type === 'cluster') {
      // List clusters
      res = await apiGet(`/api/v1/clusters?limit=${limit}`, { retries: 2 });
      // Transform response to match expected format
      if (res.ok && res.data?.clusters) {
        res.data.results = res.data.clusters;
      }
    } else {
      // Standard DB search
      res = await apiGet(`/api/v1/db/search?type=${encodeURIComponent(type)}&q=${encodeURIComponent(q)}&fuzzy=${fuzzy}&limit=${limit}`, { retries: 2 });
    }
    
    ui.setLoading(false);
    if (!res.ok) {
      showMessage(res.error || `Search failed: ${res.status}`);
      return;
    }
    renderSearchResults(res.data.results || [], type);
  } catch (err) {
    ui.setLoading(false);
    showMessage('Search error, please retry');
    console.error('runSearch error:', err);
  }
}

export function renderSearchResults(results, type) {
  const listEl = el('dbPanelResults');
  const detailEl = el('dbPanelDetail');
  if (detailEl) detailEl.innerHTML = '';
  if (! listEl) return;
  if (! results || ! results.length) {
    listEl.innerHTML = '<div class="muted small">No results</div>';
    mapModule.clearMap();
    refreshMarkerCount();
    return;
  }

  const frag = document.createDocumentFragment();
  results.forEach(r => {
    const row = document.createElement('div');
    row.className = 'py-2 px-2 result-row border-b small clickable';
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');
    if (type === 'node' || (! type && r.ip)) {
      const ip = r.ip || (r.node && r.node.ip) || '(no ip)';
      const host = r.hostname ?  ` — ${r.hostname}` : (r.node && r.node. hostname ?  ` — ${r.node.hostname}` : '');
      const org = (r.organization_obj && r.organization_obj.name) || r.organization || (r.node && ((r.node.organization_obj && r.node.organization_obj. name) || r.node.organization)) || '';
      row.innerHTML = `<div class="font-medium">${ip} <span class="muted">${host}</span></div>
                       <div class="text-xs muted mt-1">${org} ${r.city ?  ' — ' + r.city : ''} ${r.country ? r.country : ''}</div>`;
      row.addEventListener('click', () => viewNodeDetail(ip));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewNodeDetail(ip); });
    } else if (type === 'org') {
      const name = r.name || '(no name)';
      row.innerHTML = `<div class="font-medium">${name} <span class="muted">[#${r.id || ''}]</span></div>
                       <div class="text-xs muted mt-1">${r.rdap && r.rdap.provider ? r.rdap.provider :  ''}</div>`;
      row.addEventListener('click', () => viewOrgDetail(r));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewOrgDetail(r); });
    } else if (type === 'honeypot') {
      row.innerHTML = `<div class="font-medium">Session ${r.id} — ${r.src_ip || '—'} ${r.username ?  ' • ' + r.username : ''}</div>
                       <div class="text-xs muted mt-1">${r.start_ts || ''} ${r.end_ts ?  ' • ' + r.end_ts : ''} • ${r.raw_events_count || 0} events</div>`;
      row.addEventListener('click', () => viewHoneypotFromSearch(r. id));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewHoneypotFromSearch(r.id); });
    } else if (type === 'analysis') {
      row.innerHTML = `<div class="font-medium">Analysis ${r.id} — ${r. target_ip || '—'}</div>
                       <div class="text-xs muted mt-1">${r.timestamp || ''} • ${r.mode || ''} • ${r.hops ?  r.hops.length : 0} hops</div>`;
      row.addEventListener('click', () => viewAnalysisDetail(r));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewAnalysisDetail(r); });
    } else if (type === 'access') {
      row.innerHTML = `<div class="font-medium">${r.remote_addr || '(no ip)'} ${r.method ?  ' • ' + r.method :  ''} ${r.path || ''}</div>
                       <div class="text-xs muted mt-1">${r.timestamp || ''} • ${r.http_user_agent || ''}</div>`;
      row.addEventListener('click', () => viewAccessDetail(r));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewAccessDetail(r); });
    } else if (type === 'flow') {
      row.innerHTML = `<div class="font-medium">${r.src_ip || ''}:${r.src_port || ''} → ${r.dst_ip || ''}:${r.dst_port || ''}</div>
                       <div class="text-xs muted mt-1">${r.start_ts || ''} • ${r.packets || 0} pkts • ${r.bytes || 0} bytes</div>`;
      row.addEventListener('click', () => viewFlowDetail(r));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewFlowDetail(r); });
    } else if (type === 'isp') {
      const name = r.name || r.asn || '(no name)';
      row.innerHTML = `<div class="font-medium">${name} <span class="muted">${r.asn ? `[${r.asn}]` : ''}</span></div>
                       <div class="text-xs muted mt-1">${r.country || ''} • ${r.node_count || 0} nodes</div>`;
      row.addEventListener('click', () => viewIspDetail(r));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewIspDetail(r); });
    } else if (type === 'outgoing') {
      const direction = r.direction || '';
      const status = r.status || '';
      row.innerHTML = `<div class="font-medium">${r.local_addr || ''}:${r.local_port || ''} → ${r.remote_addr || ''}:${r.remote_port || ''} <span class="muted">[${direction}]</span></div>
                       <div class="text-xs muted mt-1">${r.timestamp || ''} • ${r.process_name || 'unknown'} • ${status}</div>`;
      row.addEventListener('click', () => viewOutgoingDetail(r));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewOutgoingDetail(r); });
    } else if (type === 'threat') {
      const threatType = r.threat_type || 'Unknown';
      const severity = r.severity || 'unknown';
      const severityBadge = getSeverityBadge(severity);
      row.innerHTML = `<div class="font-medium">${severityBadge} ${threatType}</div>
                       <div class="text-xs muted mt-1">${r.source_type || ''} • ${r.timestamp || ''} • ${r.confidence ? Math.round(r.confidence * 100) + '%' : ''}</div>`;
      row.addEventListener('click', () => viewThreatDetail(r));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewThreatDetail(r); });
    } else if (type === 'cluster') {
      const name = r.name || `Cluster ${r.id}`;
      row.innerHTML = `<div class="font-medium">🎯 ${name}</div>
                       <div class="text-xs muted mt-1">${r.session_count || 0} sessions • ${r.created_at || ''}</div>`;
      row.addEventListener('click', () => viewClusterDetail(r));
      row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') viewClusterDetail(r); });
    } else {
      row.innerText = JSON.stringify(r);
    }
    frag.appendChild(row);
  });
  listEl.innerHTML = '';
  listEl.appendChild(frag);

  // Plot on map consistently
  try {
    mapModule.clearMap();
    const coords = [];
    results.forEach((r, idx) => {
      const nodeObj = r.node || r;
      const lat = nodeObj && (nodeObj.latitude || nodeObj. lat || nodeObj.location?. latitude);
      const lon = nodeObj && (nodeObj.longitude || nodeObj.lon || nodeObj.location?.longitude);
      const ip = nodeObj && (nodeObj.ip || r.ip || (r.node && r.node.ip));
      if (lat != null && lon != null && ! isNaN(parseFloat(lat)) && !isNaN(parseFloat(lon))) {
        const n = Object.assign({}, nodeObj, { ip:  ip || (r.ip || ''), latitude: lat, longitude: lon });
        mapModule.addMarkerForNode(n, 'middle');
        coords.push({ lat: parseFloat(lat), lon: parseFloat(lon), hop: idx });
      }
    });
    if (coords.length) {
      mapModule.drawPath(coords);
      mapModule.fitToMarkers();
    }
    refreshMarkerCount();
  } catch (e) {
    console.error('Error plotting search results on map', e);
  }
}

export async function viewNodeDetail(ip) {
  if (!ip) return;
  ui.setLoading(true, 'Loading node…');
  try {
    const res = await apiGet(`/api/v1/db/node?ip=${encodeURIComponent(ip)}&limit=50`, { timeout: 30000, retries: 2 });
    ui.setLoading(false);
    if (!res.ok) {
      ui.showModal({ title: `Node ${ip}`, text: res.error || `Error:  ${res.status}`, allowPin: false });
      return;
    }
    const data = res.data;
    const html = renderNodeHtml(data);
    ui.showModal({
      title: `Node ${ip}`,
      html,
      allowPin: true,
      onPin: () => ui.addPinnedCard(`Node ${ip}`, html)
    });

    setTimeout(() => {
      const modal = el('modalContainer');
      if (!modal) return;
      const plotBtns = modal.querySelectorAll('[data-action="plot-analysis"]');
      plotBtns.forEach(btn => {
        try {
          const sessEncoded = btn.getAttribute('data-session') || '';
          const jsonStr = decodeURIComponent(sessEncoded);
          const session = JSON.parse(jsonStr);
          btn.addEventListener('click', () => {
            plotAnalysisHops(session);
            ui.hideModal();
          });
          btn.style.cursor = 'pointer';
        } catch (e) {}
      });

      const hpBtns = modal.querySelectorAll('[data-action="view-honeypot"]');
      hpBtns.forEach(btn => {
        const id = btn.getAttribute('data-id');
        if (!id) return;
        btn.addEventListener('click', () => {
          window.dispatchEvent(new CustomEvent('honeypot:view', { detail: { id } }));
          ui.hideModal();
        });
        btn.style.cursor = 'pointer';
      });
    }, 120);

    if (data.node && data.node.latitude != null && data.node.longitude != null) {
      mapModule.clearMap();
      mapModule.addMarkerForNode(data.node, 'middle');
      if (mapModule.getMarkerCount && mapModule.getMarkerCount() > 0) mapModule.fitToMarkers();
      refreshMarkerCount();
    }
  } catch (err) {
    ui.setLoading(false);
    ui.showModal({ title: `Node ${ip}`, text: 'Loading failed, please retry', allowPin: false });
    console.error('viewNodeDetail error:', err);
  }
}

function renderNodeHtml(data) {
  const node = data.node || {};
  const accesses = data.recent_accesses || [];
  const analyses = data.analyses || [];
  const sessions = data.honeypot_sessions || [];

  let html = `<div class="font-medium">Node ${node.ip || '—'}</div>
              <div class="mt-1 text-xs muted">Host: ${node.hostname || '—'} • Org: ${(node.organization_obj && node. organization_obj.name) || node.organization || '—'}</div>
              <div class="mt-2">
                <strong>Location</strong><div class="text-xs muted">${node.city || ''} ${node.country || ''} ${node.latitude && node.longitude ? `• ${node.latitude}, ${node.longitude}` : ''}</div>
              </div>
              <div class="mt-2">
                <strong>ASN / ISP</strong><div class="text-xs muted">${node.asn || node.isp || '—'}</div>
              </div>`;

  const reg = (node.organization_obj && node.organization_obj.extra_data && node.organization_obj.extra_data.company_search) ||
              (node.extra_data && node.extra_data.company_search);
  if (reg) {
    html += `<div class="mt-2"><strong>Company registry</strong><div class="text-xs muted">${(reg.matched_name || reg.name) || ''} ${reg.company_number ?  ' • ' + reg.company_number : ''} ${reg.company_url ? `<a href="${reg.company_url}" target="_blank" rel="noopener noreferrer">view</a>` : ''}</div></div>`;
  }

  html += `<div class="mt-3"><strong>Recent Accesses (${accesses.length})</strong>`;
  if (! accesses.length) {
    html += `<div class="text-xs muted">No recent accesses</div>`;
  } else {
    html += '<div class="mt-1 small">';
    accesses.slice(0, 50).forEach(a => {
      html += `<div class="border-b py-1"><div class="font-medium">${a.timestamp || ''} • ${a.method || ''} ${a.path || ''} <span class="muted">[${a.status || ''}]</span></div><div class="muted text-xs">${a. http_user_agent || ''}</div></div>`;
    });
    html += '</div>';
  }
  html += '</div>';

  html += `<div class="mt-3"><strong>Analyses (${analyses.length})</strong>`;
  if (!analyses.length) html += `<div class="text-xs muted">No analysis sessions</div>`;
  else {
    html += '<div class="mt-1 small">';
    analyses.forEach(a => {
      const sessEncoded = encodeURIComponent(JSON.stringify(a));
      html += `<div class="py-1 border-b"><div><strong>Analysis ${a.id}</strong> • ${a.timestamp || ''} • ${a.mode || ''} • ${a.hops ? a. hops.length : 0} hops</div>
               <div class="mt-1"><button class="border rounded px-2 py-1 small" data-action="plot-analysis" data-session='${sessEncoded}'>Plot hops on map</button></div></div>`;
    });
    html += '</div>';
  }
  html += `</div>`;

  html += `<div class="mt-3"><strong>Honeypot sessions (${sessions.length})</strong>`;
  if (!sessions.length) html += `<div class="text-xs muted">No honeypot sessions</div>`;
  else {
    html += '<div class="mt-1 small">';
    sessions.forEach(s => {
      html += `<div class="py-1 border-b"><div class="font-medium">Session ${s.id} — ${s.src_ip || ''} ${s.username ? ' • ' + s.username : ''}</div>
               <div class="muted text-xs">${s. start_ts || ''} ${s.end_ts ? ' • ' + s.end_ts :  ''}</div>
               <div class="mt-1"><button class="border rounded px-2 py-1 small" data-action="view-honeypot" data-id="${s.id}">View session</button></div></div>`;
    });
    html += '</div>';
  }
  html += `</div>`;

  return html;
}

export async function plotAnalysisHops(session) {
  if (!session || !session.hops) return;
  const hops = session.hops;
  const nodes = {};
  const coords = [];
  for (const h of hops) {
    const ip = h.ip;
    if (! ip) continue;
    try {
      const res = await apiGet(`/api/v1/locate?ip=${encodeURIComponent(ip)}`, { retries: 2 });
      if (res.ok && res.data && res.data.node) {
        nodes[ip] = res.data.node;
        if (res.data.node.latitude != null && res.data.node.longitude != null) {
          coords.push({ ip, lat: parseFloat(res.data.node.latitude), lon: parseFloat(res.data.node. longitude), hop: h. hop_number });
        }
      } else if (h.latitude != null && h.longitude != null) {
        coords.push({ ip, lat: parseFloat(h.latitude), lon: parseFloat(h.longitude), hop: h.hop_number });
      }
    } catch (e) {}
  }

  if (! coords.length) {
    ui.toast('No geolocation available for hops');
    return;
  }

  mapModule.clearMap();
  coords.forEach((c, i) => {
    const role = i === 0 ? 'first' : (i === coords.length - 1 ? 'last' : 'middle');
    const node = nodes[c.ip] || { ip: c.ip, latitude: c.lat, longitude: c.lon };
    mapModule.addMarkerForNode(node, role);
  });
  mapModule.drawPath(coords.map(c => ({ lat: c.lat, lon: c.lon, hop: c.hop })));
  mapModule.fitToMarkers();
  ui.toast('Analysis hops plotted');
  refreshMarkerCount();

  // Add pinned cards for each hop node (from old version)
  for (const ip in nodes) {
    const node = nodes[ip];
    const html = renderNodeHtml({ node });
    ui.addPinnedCard(`Hop Node ${ip}`, html);
  }
}

export function viewOrgDetail(org) {
  if (!org) return;
  let html = `<div class="font-medium">${org.name || '—'} <span class="muted">[#${org.id || ''}]</span></div>`;
  if (org.rdap && org.rdap.provider) {
    html += `<div class="mt-1 text-xs muted">Provider: ${org.rdap.provider}</div>`;
  }
  if (org.extra_data && org.extra_data.company_search) {
    const cs = org.extra_data.company_search;
    html += `<div class="mt-2 text-xs muted">Registry: ${(cs.matched_name || cs. name) || ''} ${cs.company_number ? ' • ' + cs.company_number : ''} ${cs.company_url ? `<a href="${cs.company_url}" target="_blank" rel="noopener noreferrer">view</a>` : ''}</div>`;
  }
  html += `<div class="mt-3"><button id="dbShowNodesForOrg" class="border rounded px-2 py-1 small">Show nodes for this organization</button></div>`;
  ui.showModal({
    title: `Organization ${org.name || ''}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Org ${org.name || ''}`, html)
  });
  el('dbShowNodesForOrg')?.addEventListener('click', async () => {
    const name = org.name || '';
    if (!name) return;
    el('dbPanelQuery').value = name;
    el('dbPanelType').value = 'node';
    await runSearch();
  });
}

export function viewHoneypotFromSearch(id) {
  window.dispatchEvent(new CustomEvent('honeypot:view', { detail: { id } }));
}

export function viewAnalysisDetail(session) {
  const html = (() => {
    let out = `<div class="font-medium">Analysis ${session.id} • ${session.target_ip || ''}</div>`;
    out += `<div class="text-xs muted">${session.timestamp || ''} • ${session.mode || ''}</div>`;
    out += '<div class="mt-2"><strong>Hops</strong><div class="mt-1 small">';
    if (! session.hops || ! session.hops.length) out += '<div class="muted">No hops available</div>';
    else {
      session.hops.forEach(h => {
        out += `<div class="py-1 border-b">${h.hop_number} • ${h.ip || '(no reply)'} ${h.rtt ?  '• ' + (h.rtt * 1000).toFixed(1) + ' ms' : ''}</div>`;
      });
    }
    out += '</div></div>';
    out += `<div class="mt-3"><button id="plotAnalysisBtn" class="border rounded px-2 py-1 small">Plot analysis hops</button></div>`;
    return out;
  })();

  ui.showModal({
    title: `Analysis ${session.id}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Analysis ${session.id}`, html)
  });

  setTimeout(() => {
    el('plotAnalysisBtn')?.addEventListener('click', () => {
      plotAnalysisHops(session);
      ui.hideModal();
    });
  }, 150);
}

export function viewAccessDetail(access) {
  let html = `<div class="font-medium">Access ${access.id || ''}</div>`;
  html += `<div class="text-xs muted">${access. timestamp || ''} • ${access. method || ''} ${access.path || ''} • ${access.status || ''}</div>`;
  html += `<div class="mt-2 text-xs muted">User agent: ${access.http_user_agent || ''}</div>`;
  if (access.remote_addr) {
    html += `<div class="mt-2"><button id="dbLocateAccess" class="border rounded px-2 py-1 small">Locate remote IP</button></div>`;
  }
  html += '</div>';
  ui.showModal({
    title: `Access ${access.id || ''}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Access ${access.id || ''}`, html)
  });
  setTimeout(() => {
    el('dbLocateAccess')?.addEventListener('click', () => {
      if (access.remote_addr) {
        const ev = new CustomEvent('ui:switchTab', { detail: { name: 'map' } });
        window.dispatchEvent(ev);
        setTimeout(() => {
          el('dbPanelQuery').value = access.remote_addr;
          el('dbPanelType').value = 'node';
          runSearch().then(() => viewNodeDetail(access.remote_addr));
        }, 100);
      }
    });
  }, 200);
}

export function viewFlowDetail(flow) {
  let html = `<div class="font-medium">Flow ${flow. id || ''}</div>`;
  html += `<div class="text-xs muted">${flow.start_ts || ''} • ${flow.packets || 0} pkts • ${flow.bytes || 0} bytes</div>`;
  html += `<div class="mt-2 text-xs muted">Proto: ${flow.proto || ''}</div>`;
  html += `<div class="mt-2"><button id="dbLocateFlowSrc" class="border rounded px-2 py-1 small">Locate source IP</button> <button id="dbLocateFlowDst" class="border rounded px-2 py-1 small">Locate dest IP</button></div>`;
  ui.showModal({
    title: `Flow ${flow.id || ''}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Flow ${flow.id || ''}`, html)
  });
  setTimeout(() => {
    el('dbLocateFlowSrc')?.addEventListener('click', () => {
      if (flow.src_ip) {
        el('dbPanelQuery').value = flow.src_ip;
        el('dbPanelType').value = 'node';
        runSearch().then(() => viewNodeDetail(flow.src_ip));
      }
    });
    el('dbLocateFlowDst')?.addEventListener('click', () => {
      if (flow.dst_ip) {
        el('dbPanelQuery').value = flow.dst_ip;
        el('dbPanelType').value = 'node';
        runSearch().then(() => viewNodeDetail(flow.dst_ip));
      }
    });
  }, 200);
}

// Helper function to get severity badge
function getSeverityBadge(severity) {
  const badges = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    info: '🔵',
    unknown: '⚪'
  };
  return badges[severity?.toLowerCase()] || badges.unknown;
}

// ISP detail view
export function viewIspDetail(isp) {
  if (!isp) return;
  let html = `<div class="font-medium">${isp.name || '—'} <span class="muted">${isp.asn ? `[${isp.asn}]` : ''}</span></div>`;
  html += `<div class="mt-1 text-xs muted">Country: ${isp.country || '—'}</div>`;
  html += `<div class="mt-1 text-xs muted">Nodes: ${isp.node_count || 0}</div>`;
  if (isp.extra_data) {
    html += `<div class="mt-2"><strong>Extra Data</strong><pre class="text-xs mt-1 overflow-auto" style="max-height: 200px;">${JSON.stringify(isp.extra_data, null, 2)}</pre></div>`;
  }
  html += `<div class="mt-3"><button id="dbShowNodesForIsp" class="border rounded px-2 py-1 small">Show nodes for this ISP</button></div>`;
  ui.showModal({
    title: `ISP ${isp.name || isp.asn || ''}`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`ISP ${isp.name || isp.asn || ''}`, html)
  });
  el('dbShowNodesForIsp')?.addEventListener('click', async () => {
    const query = isp.name || isp.asn || '';
    if (!query) return;
    el('dbPanelQuery').value = query;
    el('dbPanelType').value = 'node';
    await runSearch();
  });
}

// Outgoing connection detail view
export function viewOutgoingDetail(conn) {
  if (!conn) return;
  let html = `<div class="font-medium">${conn.local_addr || ''}:${conn.local_port || ''} → ${conn.remote_addr || ''}:${conn.remote_port || ''}</div>`;
  html += `<div class="mt-1 text-xs muted">Direction: ${conn.direction || '—'} • Status: ${conn.status || '—'}</div>`;
  html += `<div class="mt-1 text-xs muted">Process: ${conn.process_name || '—'} (PID: ${conn.pid || '—'})</div>`;
  html += `<div class="mt-1 text-xs muted">Timestamp: ${conn.timestamp || '—'}</div>`;
  if (conn.remote_node) {
    html += `<div class="mt-2"><strong>Remote Node</strong></div>`;
    html += `<div class="text-xs muted">${conn.remote_node.city || ''} ${conn.remote_node.country || ''} • ${conn.remote_node.organization || ''}</div>`;
  }
  html += `<div class="mt-3"><button id="dbLocateOutgoingRemote" class="border rounded px-2 py-1 small">Locate remote IP</button></div>`;
  ui.showModal({
    title: `Outgoing Connection`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Outgoing ${conn.remote_addr || ''}`, html)
  });
  setTimeout(() => {
    el('dbLocateOutgoingRemote')?.addEventListener('click', () => {
      if (conn.remote_addr) {
        el('dbPanelQuery').value = conn.remote_addr;
        el('dbPanelType').value = 'node';
        runSearch().then(() => viewNodeDetail(conn.remote_addr));
      }
    });
  }, 200);
}

// Threat analysis detail view
export async function viewThreatDetail(threat) {
  if (!threat) return;
  
  // If we only have a partial threat object, fetch the full details
  let fullThreat = threat;
  if (threat.id && !threat.summary) {
    try {
      const res = await apiGet(`/api/v1/threat?id=${threat.id}`, { retries: 2 });
      if (res.ok && res.data?.threat) {
        fullThreat = res.data.threat;
      }
    } catch (e) {
      console.error('Failed to fetch threat details:', e);
    }
  }
  
  const severityBadge = getSeverityBadge(fullThreat.severity);
  let html = `<div class="threat-detail">
    <div class="threat-header" style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem;">
      <span style="font-size: 1.5rem;">${severityBadge}</span>
      <div>
        <div class="font-medium">${fullThreat.threat_type || 'Unknown Threat'}</div>
        <div class="text-xs muted">Severity: ${fullThreat.severity || 'unknown'} • Confidence: ${fullThreat.confidence ? Math.round(fullThreat.confidence * 100) + '%' : '—'}</div>
      </div>
    </div>`;
  
  if (fullThreat.summary) {
    html += `<div class="mt-2"><strong>Summary</strong><div class="text-sm mt-1">${fullThreat.summary}</div></div>`;
  }
  
  if (fullThreat.tactics?.length) {
    html += `<div class="mt-2"><strong>MITRE ATT&CK Tactics</strong><div class="text-xs mt-1">${fullThreat.tactics.join(', ')}</div></div>`;
  }
  
  if (fullThreat.techniques?.length) {
    html += `<div class="mt-2"><strong>MITRE ATT&CK Techniques</strong><div class="text-xs mt-1">${fullThreat.techniques.join(', ')}</div></div>`;
  }
  
  if (fullThreat.indicators?.length) {
    html += `<div class="mt-2"><strong>Indicators</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    fullThreat.indicators.slice(0, 10).forEach(ind => {
      html += `<li>${ind}</li>`;
    });
    html += `</ul></div>`;
  }
  
  if (fullThreat.recommendations?.length) {
    html += `<div class="mt-2"><strong>Recommendations</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    fullThreat.recommendations.slice(0, 10).forEach(rec => {
      html += `<li>${rec}</li>`;
    });
    html += `</ul></div>`;
  }
  
  html += `<div class="mt-3 threat-actions" style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
    <button id="threatViewSource" class="border rounded px-2 py-1 small">View Source</button>
    <button id="threatCountermeasure" class="border rounded px-2 py-1 small">Generate Countermeasure</button>
    <button id="threatFindSimilar" class="border rounded px-2 py-1 small">Find Similar Threats</button>
  </div></div>`;
  
  ui.showModal({
    title: `🔍 Threat Analysis #${fullThreat.id || ''}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Threat ${fullThreat.id || ''}`, html),
    onPinLeft: () => ui.addPanelToZone(`Threat ${fullThreat.id || ''}`, html, 'left'),
    onPinMiddle: () => ui.addPanelToZone(`Threat ${fullThreat.id || ''}`, html, 'middle'),
    onPinRight: () => ui.addPanelToZone(`Threat ${fullThreat.id || ''}`, html, 'right')
  });
  
  setTimeout(() => {
    el('threatViewSource')?.addEventListener('click', () => {
      if (fullThreat.source_type === 'session' && fullThreat.source_id) {
        window.dispatchEvent(new CustomEvent('honeypot:view', { detail: { id: fullThreat.source_id } }));
      } else if (fullThreat.source_ip) {
        viewNodeDetail(fullThreat.source_ip);
      }
      ui.hideModal();
    });
    
    el('threatCountermeasure')?.addEventListener('click', async () => {
      if (!fullThreat.id) return;
      ui.setLoading(true, 'Generating countermeasure plan...');
      try {
        const res = await apiPost('/api/v1/llm/countermeasure', { threat_analysis_id: fullThreat.id });
        ui.setLoading(false);
        if (res.ok && res.data) {
          viewCountermeasure(res.data, fullThreat);
        } else {
          ui.toast(res.error || 'Failed to generate countermeasure');
        }
      } catch (e) {
        ui.setLoading(false);
        ui.toast('Countermeasure generation failed');
      }
    });
    
    el('threatFindSimilar')?.addEventListener('click', async () => {
      ui.setLoading(true, 'Finding similar threats...');
      try {
        const query = fullThreat.threat_type || fullThreat.summary || '';
        const res = await apiGet(`/api/v1/vector/search/threats?q=${encodeURIComponent(query)}&limit=10`, { retries: 2 });
        ui.setLoading(false);
        if (res.ok && res.data?.results) {
          renderSearchResults(res.data.results, 'threat');
          ui.toast(`Found ${res.data.results.length} similar threats`);
        } else {
          ui.toast(res.error || 'No similar threats found');
        }
      } catch (e) {
        ui.setLoading(false);
        ui.toast('Search failed');
      }
      ui.hideModal();
    });
  }, 200);
}

// Countermeasure view
function viewCountermeasure(data, threat) {
  let html = `<div class="countermeasure-detail">
    <div class="font-medium">Countermeasure Plan for: ${threat?.threat_type || 'Threat'}</div>`;
  
  if (data.plan) {
    html += `<div class="mt-2"><strong>Plan</strong><div class="text-sm mt-1 whitespace-pre-wrap">${data.plan}</div></div>`;
  }
  
  if (data.steps?.length) {
    html += `<div class="mt-2"><strong>Implementation Steps</strong><ol class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.steps.forEach(step => {
      html += `<li style="margin-bottom: 0.5rem;">${step}</li>`;
    });
    html += `</ol></div>`;
  }
  
  if (data.tools?.length) {
    html += `<div class="mt-2"><strong>Recommended Tools</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.tools.forEach(tool => {
      html += `<li>${tool}</li>`;
    });
    html += `</ul></div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `🛡️ Countermeasure Plan`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard('Countermeasure', html)
  });
}

// Cluster detail view
export async function viewClusterDetail(cluster) {
  if (!cluster) return;
  
  // If we only have a partial cluster object, fetch the full details
  let fullCluster = cluster;
  if (cluster.id && !cluster.sessions) {
    try {
      const res = await apiGet(`/api/v1/cluster?id=${cluster.id}`, { retries: 2 });
      if (res.ok && res.data?.cluster) {
        fullCluster = res.data.cluster;
      }
    } catch (e) {
      console.error('Failed to fetch cluster details:', e);
    }
  }
  
  let html = `<div class="cluster-detail">
    <div class="font-medium">🎯 ${fullCluster.name || `Cluster #${fullCluster.id}`}</div>
    <div class="text-xs muted mt-1">Created: ${fullCluster.created_at || '—'} • Sessions: ${fullCluster.session_count || fullCluster.sessions?.length || 0}</div>`;
  
  if (fullCluster.description) {
    html += `<div class="mt-2"><strong>Description</strong><div class="text-sm mt-1">${fullCluster.description}</div></div>`;
  }
  
  if (fullCluster.unified_profile) {
    html += `<div class="mt-2"><strong>Unified Threat Profile</strong><div class="text-sm mt-1">${fullCluster.unified_profile}</div></div>`;
  }
  
  if (fullCluster.sessions?.length) {
    html += `<div class="mt-2"><strong>Related Sessions</strong><div class="text-xs mt-1 compact-scroll" style="max-height: 200px;">`;
    fullCluster.sessions.forEach(s => {
      html += `<div class="py-1 border-b clickable" data-session-id="${s.id || s}">
        Session ${s.id || s} ${s.src_ip ? `— ${s.src_ip}` : ''} ${s.start_ts ? `• ${s.start_ts}` : ''}
      </div>`;
    });
    html += `</div></div>`;
  }
  
  if (fullCluster.source_ips?.length) {
    html += `<div class="mt-2"><strong>Source IPs</strong><div class="text-xs mt-1">`;
    fullCluster.source_ips.forEach(ip => {
      html += `<span class="inline-block mr-2 mb-1 px-2 py-1 border rounded">${ip}</span>`;
    });
    html += `</div></div>`;
  }
  
  html += `<div class="mt-3 cluster-actions" style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
    <button id="clusterShowOnMap" class="border rounded px-2 py-1 small">Show on Map</button>
    <button id="clusterUnify" class="border rounded px-2 py-1 small">Unify Threat Profile</button>
  </div></div>`;
  
  ui.showModal({
    title: `🎯 Attacker Cluster #${fullCluster.id || ''}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Cluster ${fullCluster.id || ''}`, html),
    onPinLeft: () => ui.addPanelToZone(`Cluster ${fullCluster.id || ''}`, html, 'left'),
    onPinMiddle: () => ui.addPanelToZone(`Cluster ${fullCluster.id || ''}`, html, 'middle'),
    onPinRight: () => ui.addPanelToZone(`Cluster ${fullCluster.id || ''}`, html, 'right')
  });
  
  setTimeout(() => {
    // Handle session clicks within the cluster detail
    const modalContainer = el('modalContainer');
    modalContainer?.querySelectorAll('[data-session-id]').forEach(el => {
      el.addEventListener('click', () => {
        const sessionId = el.dataset.sessionId;
        if (sessionId) {
          window.dispatchEvent(new CustomEvent('honeypot:view', { detail: { id: sessionId } }));
          ui.hideModal();
        }
      });
    });
    
    el('clusterShowOnMap')?.addEventListener('click', async () => {
      if (!fullCluster.source_ips?.length) {
        ui.toast('No source IPs to show on map');
        return;
      }
      
      ui.setLoading(true, 'Locating cluster IPs...');
      mapModule.clearMap();
      
      for (const ip of fullCluster.source_ips.slice(0, 50)) {
        try {
          const res = await apiGet(`/api/v1/locate?ip=${encodeURIComponent(ip)}`, { retries: 1 });
          if (res.ok && res.data?.node) {
            mapModule.addMarkerForNode(res.data.node, 'first');
          }
        } catch (e) {
          console.warn(`Failed to locate IP ${ip}`);
        }
      }
      
      ui.setLoading(false);
      mapModule.fitToMarkers();
      refreshMarkerCount();
      ui.toast(`Showing ${fullCluster.source_ips.length} cluster IPs on map`);
      ui.hideModal();
    });
    
    el('clusterUnify')?.addEventListener('click', async () => {
      if (!fullCluster.sessions?.length) {
        ui.toast('No sessions to unify');
        return;
      }
      
      ui.setLoading(true, 'Generating unified threat profile...');
      try {
        const sessionIds = fullCluster.sessions.map(s => s.id || s);
        const res = await apiPost('/api/v1/llm/unify', { session_ids: sessionIds });
        ui.setLoading(false);
        if (res.ok && res.data) {
          viewUnifiedProfile(res.data, fullCluster);
        } else {
          ui.toast(res.error || 'Failed to unify threats');
        }
      } catch (e) {
        ui.setLoading(false);
        ui.toast('Unification failed');
      }
    });
  }, 200);
}

// Unified profile view
function viewUnifiedProfile(data, cluster) {
  let html = `<div class="unified-profile">
    <div class="font-medium">Unified Threat Profile for ${cluster?.name || `Cluster #${cluster?.id}`}</div>`;
  
  if (data.unified_profile) {
    html += `<div class="mt-2 text-sm whitespace-pre-wrap">${data.unified_profile}</div>`;
  }
  
  if (data.common_tactics?.length) {
    html += `<div class="mt-2"><strong>Common Tactics</strong><div class="text-xs mt-1">${data.common_tactics.join(', ')}</div></div>`;
  }
  
  if (data.common_techniques?.length) {
    html += `<div class="mt-2"><strong>Common Techniques</strong><div class="text-xs mt-1">${data.common_techniques.join(', ')}</div></div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `🎯 Unified Threat Profile`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard('Unified Profile', html)
  });
}

// Function to analyze session with LLM
export async function analyzeSessionWithLLM(sessionId) {
  if (!sessionId) return;
  
  ui.setLoading(true, 'Analyzing session with AI...');
  try {
    const res = await apiPost('/api/v1/llm/analyze/session', { session_id: sessionId, save: true });
    ui.setLoading(false);
    if (res.ok && res.data) {
      viewThreatDetail(res.data);
      ui.toast('Session analyzed successfully');
    } else {
      ui.toast(res.error || 'Analysis failed');
    }
  } catch (e) {
    ui.setLoading(false);
    ui.toast('Analysis failed');
    console.error('analyzeSessionWithLLM error:', e);
  }
}

// Function to find similar attackers
export async function findSimilarAttackers(ip) {
  if (!ip) return;
  
  ui.setLoading(true, 'Finding similar attackers...');
  try {
    const res = await apiGet(`/api/v1/similar/attackers?ip=${encodeURIComponent(ip)}&limit=10`, { retries: 2 });
    ui.setLoading(false);
    if (res.ok && res.data?.similar_attackers) {
      renderSearchResults(res.data.similar_attackers.map(a => ({ ...a, ip: a.ip })), 'node');
      ui.toast(`Found ${res.data.similar_attackers.length} similar attackers`);
    } else {
      ui.toast(res.error || 'No similar attackers found');
    }
  } catch (e) {
    ui.setLoading(false);
    ui.toast('Search failed');
    console.error('findSimilarAttackers error:', e);
  }
}

export { runSearch as searchDB, getSeverityBadge };
