// Optimized DB UI:  consistent error handling, UI updates, and map interactions. 
// Merged:  combines both old and new version features

import { apiGet } from './api.js';
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
          <option value="analysis">Analysis / Trace</option>
          <option value="honeypot">Honeypot Sessions</option>
          <option value="access">Web Access</option>
          <option value="flow">Flows</option>
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

  if (!q) return ui.toast('Enter a search term');
  ui.pushSearchHistory(q);
  ui.setLoading(true, 'Searching DB…');
  try {
    const res = await apiGet(`/api/v1/db/search?type=${encodeURIComponent(type)}&q=${encodeURIComponent(q)}&fuzzy=${fuzzy}&limit=${limit}`, { retries: 2 });
    ui.setLoading(false);
    if (! res.ok) {
      showMessage(res.error || `Search failed: ${res.status}`);
      return;
    }
    renderSearchResults(res.data. results || [], type);
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
  mapModule.drawPath(coords. map(c => ({ lat: c.lat, lon: c.lon, hop: c.hop })));
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

export { runSearch as searchDB };
