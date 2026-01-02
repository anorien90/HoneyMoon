// Optimized entry bootstrap: consistent error handling, state management, and event dispatching.
// Introduced a simple global state for IP and session data to ensure consistency across modules.
// Enhanced keyboard shortcuts and event listeners for better usability.
// Added loading indicators and error recovery.

import { apiGet } from './api.js';
import * as mapModule from './map.js';
import * as ui from './ui.js';
import * as honeypotUI from './honeypot-ui.js';
import * as dbUI from './db-ui.js';
import * as honeypotApi from './honeypot.js';

const $ = id => document.getElementById(id);

// Global state for consistency
const appState = {
  currentIP: '',
  lastSession: null,
  gridMode: false,
  activeTab: 'map'
};

// DOM refs
const ipInput = $('ipInput');
const locateBtn = $('locateBtn');
const traceBtn = $('traceBtn');
const deepToggle = $('deepToggle');
const maxttlEl = $('maxttl');
const clearMapBtn = $('clearMapBtn');
const fitMarkersBtn = $('fitMarkersBtn');
const accessesBtn = $('accessesBtn');
const refreshOrgBtn = $('refreshOrgBtn');
const themeToggle = $('themeToggle');
const toggleLeft = $('toggleLeft');
const toggleRight = $('toggleRight');
const closeAllPinsBtn = $('closeAllPinsBtn');
const toggleLayoutBtn = $('toggleLayoutBtn');

// --- TAB WIRING ---
function initTabs() {
  const tabButtons = Array.from(document.querySelectorAll('[data-tab-btn]'));
  const panels = Array.from(document.querySelectorAll('.tab-panel'));

  function switchTab(name) {
    appState.activeTab = name;
    tabButtons.forEach(btn => {
      const active = btn.getAttribute('data-tab-btn') === name;
      btn.classList.toggle('tab-active', active);
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    panels.forEach(p => {
      const id = p.id.replace('panel-', '');
      p.classList.toggle('hidden', id !== name);
    });
    if (name === 'honeypot') {
      $('honeypotFilter')?.focus();
    } else if (name === 'database') {
      $('dbPanelQuery')?.focus();
    }
    // Trigger map resize if map is visible
    if (name === 'map') {
      setTimeout(() => mapModule.invalidateSize(), 100);
    }
  }

  tabButtons.forEach(btn => btn.addEventListener('click', () => switchTab(btn.getAttribute('data-tab-btn'))));
  window.addEventListener('ui:switchTab', (ev) => {
    const name = ev.detail?.name;
    if (name) switchTab(name);
  });
  switchTab('map'); // Default to map
}

// Map selection callback -> update UI consistently
mapModule.onSelect(node => {
  ui.setSelectedNodeUI(node);
  updateMarkerCount();
});

// Update marker count consistently
function updateMarkerCount() {
  const markerCountEl = $('markerCount');
  if (markerCountEl) markerCountEl.innerText = String(mapModule.getMarkerCount ? mapModule.getMarkerCount() : 0);
}

// Core actions with consistent error handling and recovery
export async function locateIP() {
  const ip = (ipInput?.value || '').trim();
  if (!ip) return ui.toast('Provide an IP');
  appState.currentIP = ip;
  ui.setLoading(true, 'Locating…');
  try {
    const res = await apiGet(`/api/v1/locate?ip=${encodeURIComponent(ip)}`, { retries: 2 });
    ui.setLoading(false);
    if (!res.ok) {
      ui.toast(res.error || 'Not found');
      return;
    }
    const node = res.data.node;
    mapModule.clearMap();
    if (node) mapModule.addMarkerForNode(node, 'middle');
    ui.setSelectedNodeUI(node);
    ui.renderHopListFromNode ? ui.renderHopListFromNode(node) : null;
    if (mapModule.getMarkerCount && mapModule.getMarkerCount() > 0) mapModule.fitToMarkers();
    updateMarkerCount();
  } catch (err) {
    ui.setLoading(false);
    ui.toast('Location failed, please retry');
    console.error('locateIP error:', err);
  }
}

export async function traceIP() {
  const ip = (ipInput?.value || '').trim();
  if (!ip) return ui.toast('Provide an IP');
  appState.currentIP = ip;
  const deep = deepToggle?.checked ? 1 : 0;
  const maxttl = parseInt(maxttlEl?.value || '30') || 30;
  ui.setLoading(true, 'Tracing…');
  try {
    const res = await apiGet(`/api/v1/trace?ip=${encodeURIComponent(ip)}&deep=${deep}&maxttl=${maxttl}`, { timeout: 600000, retries: 1 });
    ui.setLoading(false);
    if (!res.ok) {
      ui.toast(res.error || 'Trace failed');
      return;
    }
    appState.lastSession = res.data.session;
    const hops = appState.lastSession.path || [];
    const nodes = res.data.nodes || {};

    $('lastSessionId') && ($('lastSessionId').innerText = appState.lastSession.session_id || '—');
    $('lastHopCount') && ($('lastHopCount').innerText = hops.length || 0);
    $('sessionSummary') && ($('sessionSummary').innerText = `${hops.length} hops • ${Object.keys(nodes).length} nodes`);

    mapModule.clearMap();
    const coords = [];
    hops.forEach(h => {
      const hopNum = h.hop_number;
      const ipAddr = h.ip;
      if (ipAddr && nodes[ipAddr] && nodes[ipAddr].latitude != null && nodes[ipAddr].longitude != null) {
        const lat = parseFloat(nodes[ipAddr].latitude);
        const lon = parseFloat(nodes[ipAddr].longitude);
        if (!Number.isNaN(lat) && !Number.isNaN(lon)) coords.push({ ip: ipAddr, lat, lon, hop: hopNum });
      } else if (h.latitude != null && h.longitude != null) {
        const lat = parseFloat(h.latitude);
        const lon = parseFloat(h.longitude);
        if (!Number.isNaN(lat) && !Number.isNaN(lon)) coords.push({ ip: ipAddr || '(no ip)', lat, lon, hop: hopNum });
      }
    });

    for (let i = 0; i < coords.length; i++) {
      const role = (i === 0) ? 'first' : (i === coords.length - 1) ? 'last' : 'middle';
      const n = nodes[coords[i].ip] || { ip: coords[i].ip, latitude: coords[i].lat, longitude: coords[i].lon };
      mapModule.addMarkerForNode(n, role);
    }
    mapModule.drawPath(coords.map(c => ({ lat: c.lat, lon: c.lon, hop: c.hop })));
    ui.renderHopList(hops, nodes);
    if (coords.length) mapModule.fitToMarkers();
    updateMarkerCount();
  } catch (err) {
    ui.setLoading(false);
    ui.toast('Trace failed, please retry');
    console.error('traceIP error:', err);
  }
}

async function showAccesses() {
  const ip = appState.currentIP || (ipInput?.value || '').trim();
  if (!ip) return ui.toast('Provide an IP');
  ui.setLoading(true, 'Fetching accesses…');
  try {
    const res = await apiGet(`/api/v1/accesses?ip=${encodeURIComponent(ip)}&limit=200`, { retries: 2 });
    ui.setLoading(false);
    if (!res.ok) {
      ui.toast(res.error || 'Failed to fetch accesses');
      return;
    }
    const accesses = res.data.accesses || [];
    const recentAccesses = $('recentAccesses');
    if (!recentAccesses) return;
    recentAccesses.innerHTML = '';
    if (!accesses.length) {
      recentAccesses.innerHTML = '<div class="muted small">No recent accesses for this IP.</div>';
      return;
    }
    const frag = document.createDocumentFragment();
    accesses.slice(0, 50).forEach(a => {
      const row = document.createElement('div');
      row.className = 'py-1 border-b small';
      row.innerHTML = `<div class="font-medium small">${a.timestamp} — ${a.method || ''} ${a.path || ''} <span class="muted">[${a.status || ''}]</span></div>
                     <div class="muted small">${a.http_user_agent || ''} ${a.server_name ? ' @ ' + a.server_name : ''}</div>`;
      frag.appendChild(row);
    });
    recentAccesses.appendChild(frag);
  } catch (err) {
    ui.setLoading(false);
    ui.toast('Fetching accesses failed');
    console.error('showAccesses error:', err);
  }
}

// Wire UI events
(async function init() {
  try {
    await mapModule.initMap();
    initTabs();
    ui.initUI();
    dbUI.initDatabasePanel();
    ui.enableFloatButtons();
    ui.restorePinnedCards();

    // Load and apply saved layout mode preference
    const savedGrid = ui.loadGridMode();
    if (savedGrid) {
      appState.gridMode = true;
      ui.setGridMode(true);
      if (toggleLayoutBtn) toggleLayoutBtn.innerText = 'Grid';
    }

    // main buttons
    locateBtn && locateBtn.addEventListener('click', locateIP);
    traceBtn && traceBtn.addEventListener('click', traceIP);
    clearMapBtn && clearMapBtn.addEventListener('click', () => {
      mapModule.clearMap();
      ui.resetSelectedUI();
      updateMarkerCount();
      appState.lastSession = null;
      $('lastSessionId') && ($('lastSessionId').innerText = '—');
      $('lastHopCount') && ($('lastHopCount').innerText = '—');
      $('sessionSummary') && ($('sessionSummary').innerText = '');
    });
    fitMarkersBtn && fitMarkersBtn.addEventListener('click', () => mapModule.fitToMarkers());

    accessesBtn && accessesBtn.addEventListener('click', showAccesses);

    refreshOrgBtn && refreshOrgBtn.addEventListener('click', async () => {
      const sel = window.selectedNode;
      if (!sel || !sel.ip) return ui.toast('Select a node with an IP first.');
      const identifier = encodeURIComponent(sel.ip);
      ui.setLoading(true, 'Refreshing org info…');
      const r = await apiGet(`/api/v1/organization/refresh?id=${identifier}&force=1`, { retries: 2 });
      ui.setLoading(false);
      if (!r.ok) {
        ui.toast(r.error || 'Refresh failed');
        return;
      }
      const r2 = await apiGet(`/api/v1/locate?ip=${identifier}`);
      if (r2.ok && r2.data && r2.data.node) {
        ui.setSelectedNodeUI(r2.data.node);
        ui.toast('Organization refreshed');
      } else {
        ui.toast('Refreshed but failed to reload node details.');
      }
    });

    // theme toggle
    themeToggle && themeToggle.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      if (current === 'dark') {
        document.documentElement.removeAttribute('data-theme');
        themeToggle.innerText = '🌙';
      } else {
        document.documentElement.setAttribute('data-theme', 'dark');
        themeToggle.innerText = '☀️';
      }
    });

    // sidebars
    toggleLeft && toggleLeft.addEventListener('click', () => {
      const leftSidebar = $('leftSidebar');
      if (!leftSidebar) return;
      const collapsed = leftSidebar.classList.toggle('sidebar-collapsed');
      toggleLeft.setAttribute('aria-pressed', (!collapsed).toString());
      setTimeout(() => mapModule.invalidateSize(), 150);
    });
    toggleRight && toggleRight.addEventListener('click', () => {
      const rightSidebar = $('rightSidebar');
      if (!rightSidebar) return;
      const collapsed = rightSidebar.classList.toggle('sidebar-collapsed');
      toggleRight.setAttribute('aria-pressed', (!collapsed).toString());
      setTimeout(() => mapModule.invalidateSize(), 150);
    });

    // close all pins
    closeAllPinsBtn?.addEventListener('click', () => {
      ui.closeAllPinnedCards();
    });

    // layout toggle
    toggleLayoutBtn?.addEventListener('click', () => {
      appState.gridMode = !appState.gridMode;
      ui.setGridMode(appState.gridMode);
      toggleLayoutBtn.innerText = appState.gridMode ? 'Grid' : 'Free';
    });

    // global card collapses
    document.querySelectorAll('.card-toggle').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const card = btn.closest('.card');
        if (!card) return;
        card.classList.toggle('card-collapsed');
        btn.textContent = card.classList.contains('card-collapsed') ? '▸' : '▾';
      });
    });
    $('toggleMapCard')?.addEventListener('click', () => {
      const mapCard = $('mapCard');
      if (!mapCard) return;
      mapCard.classList.toggle('card-collapsed');
      $('toggleMapCard').textContent = mapCard.classList.contains('card-collapsed') ? '▸' : '▾';
      setTimeout(() => mapModule.invalidateSize(), 200);
    });

    // keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return;
      const k = e.key.toLowerCase();
      if (k === 'l') { locateIP(); }
      if (k === 't') { traceIP(); }
      if (k === 'm') { mapModule.fitToMarkers(); }
      if (k === 'c') {
        clearMapBtn.click();
      }
    });

    // custom events
    window.addEventListener('honeypot:view', (ev) => {
      const id = ev.detail?.id;
      if (!id) return;
      const btn = Array.from(document.querySelectorAll('[data-tab-btn]')).find(b => b.getAttribute('data-tab-btn') === 'honeypot');
      if (btn) btn.click();
      honeypotUI.viewHoneypotSession(id);
    });

    window.addEventListener('honeypot:locate', (ev) => {
      const ip = ev.detail?.ip;
      if (ip) locateAttacker(ip, ev.detail);
    });
    window.addEventListener('honeypot:list', () => honeypotUI.listHoneypotSessions(100));
    window.addEventListener('ui:switchTab', (ev) => {
      const name = ev.detail?.name;
      if (name) {
        const btn = Array.from(document.querySelectorAll('[data-tab-btn]')).find(b => b.getAttribute('data-tab-btn') === name);
        if (btn) btn.click();
      }
    });

    // honeypot buttons
    $('honeypotListBtn')?.addEventListener('click', () => honeypotUI.listHoneypotSessions(100));
    $('honeypotFlowsBtn')?.addEventListener('click', () => honeypotUI.listHoneypotFlows(100));
    $('honeypotIngestBtn')?.addEventListener('click', () => honeypotUI.ingestCowrieHandler());
    $('honeypotIngestPcapBtn')?.addEventListener('click', () => honeypotUI.ingestPcapHandler());
    $('honeypotArtifactBtn')?.addEventListener('click', () => {
      const name = ($('honeypotArtifactName')?.value || '').trim();
      if (!name) return ui.toast('Provide artifact name');
      const url = honeypotApi.artifactDownloadUrl(name);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
    });

    // search DB event
    window.addEventListener('searchDB', () => dbUI.runSearch());

    // auto refresh honeypot
    setInterval(() => {
      try {
        const activeTab = appState.activeTab;
        if (activeTab === 'honeypot') {
          honeypotUI.listHoneypotSessions(100);
          honeypotUI.listHoneypotFlows(100);
        }
      } catch (e) {
        console.error('Auto-refresh honeypot error', e);
      }
    }, 30000);

    // locate attacker helper
    async function locateAttacker(ip, opts = { silent: false }) {
      if (!ip) return;
      ui.setLoading(true, 'Locating attacker…');
      const loc = await apiGet(`/api/v1/locate?ip=${encodeURIComponent(ip)}`, { retries: 2 });
      ui.setLoading(false);
      if (!loc.ok || !loc.data || !loc.data.node) {
        if (!opts.silent) ui.toast('Attacker node not found in DB');
        return false;
      }
      const node = loc.data.node;
      mapModule.clearMap();
      mapModule.addMarkerForNode(node, 'last');
      ui.setSelectedNodeUI(node);
      if (mapModule.getMarkerCount && mapModule.getMarkerCount() > 0) mapModule.fitToMarkers();
      if (!opts.silent) {
        const ev = new CustomEvent('ui:switchTab', { detail: { name: 'map' } });
        window.dispatchEvent(ev);
      }
      if (!opts.silent) ui.toast(`Attacker ${ip} highlighted`);
      updateMarkerCount();
      return true;
    }

    // Float primary panels into the pinned workspace
    floatPrimaryPanels();

    // Reflow map when pinned cards move/resize
    const reflowMap = ui.debounce(() => mapModule.invalidateSize(), 150);
    window.addEventListener('pinned:layout-changed', reflowMap);
    window.addEventListener('resize', reflowMap);
    setTimeout(reflowMap, 250); // initial reflow after float
  } catch (err) {
    console.error('Init error:', err);
    ui.toast('Application initialization failed');
  }
})();
// ...existing imports and code above...

function floatPrimaryPanels() {
  // Move live card nodes into the pinned workspace and persist their layout/position.
  // We store a stable source selector so we can re-float and restore geometry on reload.
  ui.floatCardToPinned('#mapCard', 'Map', {
    persist: true,
    className: 'map-panel',
    id: 'panel-map',
    sourceSelector: '#mapCard'
  });
  ui.floatCardToPinned('#exploreCard', 'Explore / Database', {
    persist: true,
    id: 'panel-explore',
    sourceSelector: '#exploreCard'
  });
  ui.floatCardToPinned('#honeypotCard', 'Honeypot', {
    persist: true,
    id: 'panel-honeypot',
    sourceSelector: '#honeypotCard'
  });
  ui.floatCardToPinned('#selectedNodeCard', 'Selected Node / Org', {
    persist: true,
    id: 'panel-selected',
    sourceSelector: '#selectedNodeCard'
  });
  ui.floatCardToPinned('#hopCard', 'Traceroute Hops', {
    persist: true,
    id: 'panel-hops',
    sourceSelector: '#hopCard'
  });
}

