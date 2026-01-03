// Clean application bootstrap with unified panel and event management
// Merged:  combines old version's pinned workspace with new panel system

import { apiGet } from './api.js';
import * as mapModule from './map.js';
import * as ui from './ui.js';
import { escapeHtml } from './util.js';
import * as honeypotUI from './honeypot-ui.js';
import * as dbUI from './db-ui.js';
import * as honeypotApi from './honeypot.js';
import * as liveView from './live-view.js';
import {
  applySavedInputs,
  getState,
  setActiveTab,
  setCurrentIP,
  setGridMode,
  setLastSession,
  setTracePrefs,
  updateMarkerCount
} from './state.js';

const $ = id => document.getElementById(id);

// Application state
const state = getState();
const refreshMarkerCount = () => updateMarkerCount(() => mapModule.getMarkerCount?.() || 0);

const summarizeNode = ui.summarizeNodeDetails;

function buildPinnedNodeHtml(node = {}) {
  const summary = summarizeNode(node);
  const org = node.organization_obj?.name || node.organization || '';
  const location = [node.city, node.country].filter(Boolean).join(', ');
  return `<div class="small">
    <div class="font-medium">${escapeHtml(node.ip || 'Unknown')}${node.hostname ? ` • ${escapeHtml(node.hostname)}` : ''}</div>
    <div class="muted">${escapeHtml(org)}${location ? ` • ${escapeHtml(location)}` : ''}</div>
    <div class="mt-1"><div class="muted small">Open ports</div><div>${escapeHtml(summary.ports || '—')}</div></div>
    <div class="mt-1"><div class="muted small">OS / Fingerprint</div><div>${escapeHtml(summary.os || '—')}</div></div>
    <div class="mt-1"><div class="muted small">HTTP/TLS</div><div>${escapeHtml(summary.http || '—')}</div></div>
    ${summary.tags ? `<div class="mt-1 muted small">Tags: ${escapeHtml(summary.tags)}</div>` : ''}
  </div>`;
}

// DOM references
const elements = {
  ipInput: () => $('ipInput'),
  locateBtn: () => $('locateBtn'),
  traceBtn: () => $('traceBtn'),
  deepToggle: () => $('deepToggle'),
  maxttl: () => $('maxttl'),
  clearMapBtn: () => $('clearMapBtn'),
  fitMarkersBtn: () => $('fitMarkersBtn'),
  accessesBtn: () => $('accessesBtn'),
  refreshOrgBtn: () => $('refreshOrgBtn'),
  themeToggle: () => $('themeToggle'),
  toggleLeft: () => $('toggleLeft'),
  toggleRight: () => $('toggleRight'),
  toggleLayoutBtn: () => $('toggleLayoutBtn'),
  closeAllPinsBtn: () => $('closeAllPinsBtn'),
  addPanelBtn: () => $('addPanelBtn')
};

// ============================================
// CORE ACTIONS
// ============================================

export async function locateIP() {
  const ip = (elements.ipInput()?.value || '').trim();
  if (!ip) return ui.toast('Provide an IP');
  
  setCurrentIP(ip);
  setTracePrefs(elements.maxttl()?.value, elements.deepToggle()?.checked);
  ui.setLoading(true, 'Locating…');
  
  try {
    const res = await apiGet(`/api/v1/locate?ip=${encodeURIComponent(ip)}`, { retries: 2 });
    ui.setLoading(false);
    
    if (! res.ok) {
      ui.toast(res.error || 'Not found');
      return;
    }
    
    const node = res.data. node;
    
    ui.ensurePanelOpen('map');
    
    mapModule.clearMap();
    if (node) mapModule.addMarkerForNode(node, 'middle');
    ui.setSelectedNodeUI(node);
    ui.renderHopListFromNode?.(node);
    
    if (mapModule.getMarkerCount() > 0) mapModule.fitToMarkers();
    refreshMarkerCount();
  } catch (err) {
    ui.setLoading(false);
    ui.toast('Location failed, please retry');
    console.error('locateIP error:', err);
  }
}

export async function traceIP() {
  const ip = (elements.ipInput()?.value || '').trim();
  if (!ip) return ui.toast('Provide an IP');
  
  setCurrentIP(ip);
  const deep = elements.deepToggle()?.checked ? 1 : 0;
  const maxttl = parseInt(elements.maxttl()?.value || '30') || 30;
  setTracePrefs(maxttl, !!deep);
  
  ui.setLoading(true, 'Tracing…');
  
  try {
    const res = await apiGet(`/api/v1/trace?ip=${encodeURIComponent(ip)}&deep=${deep}&maxttl=${maxttl}`, { 
      timeout: 600000, 
      retries: 1 
    });
    ui.setLoading(false);
    
    if (!res.ok) {
      ui.toast(res.error || 'Trace failed');
      return;
    }
    
    ui.ensurePanelOpen('map');
    ui.ensurePanelOpen('hops');
    
    setLastSession(res.data.session);
    const hops = state.lastSession.path || [];
    const nodes = res.data.nodes || {};
    
    // Update session info
    const lastSessionIdEl = $('lastSessionId');
    const lastHopCountEl = $('lastHopCount');
    const summaryEl = $('sessionSummary');
    
    if (lastSessionIdEl) lastSessionIdEl.textContent = state.lastSession. session_id || '—';
    if (lastHopCountEl) lastHopCountEl.textContent = hops.length || 0;
    if (summaryEl) summaryEl.textContent = `${hops.length} hops • ${Object.keys(nodes).length} nodes`;
    
    mapModule.clearMap();
    const coords = [];
    
    hops.forEach(h => {
      const hopIp = h.ip;
      const nodeData = nodes[hopIp];
      
      if (hopIp && nodeData?. latitude != null && nodeData?.longitude != null) {
        const lat = parseFloat(nodeData.latitude);
        const lon = parseFloat(nodeData.longitude);
        if (!isNaN(lat) && !isNaN(lon)) {
          coords.push({ ip: hopIp, lat, lon, hop: h. hop_number });
        }
      } else if (h.latitude != null && h.longitude != null) {
        const lat = parseFloat(h.latitude);
        const lon = parseFloat(h. longitude);
        if (!isNaN(lat) && !isNaN(lon)) {
          coords.push({ ip: hopIp || '(no ip)', lat, lon, hop: h.hop_number });
        }
      }
    });
    
    coords.forEach((c, i) => {
      const role = i === 0 ? 'first' : i === coords.length - 1 ? 'last' : 'middle';
      const n = nodes[c.ip] || { ip: c.ip, latitude: c.lat, longitude: c.lon };
      mapModule.addMarkerForNode(n, role);
    });
    
    mapModule.drawPath(coords. map(c => ({ lat: c.lat, lon: c.lon, hop: c.hop })));
    ui.renderHopList(hops, nodes);
    
    if (coords.length) mapModule.fitToMarkers();
    refreshMarkerCount();
  } catch (err) {
    ui.setLoading(false);
    ui.toast('Trace failed, please retry');
    console.error('traceIP error:', err);
  }
}

function clearMap() {
  mapModule.clearMap();
  ui.resetSelectedUI();
  refreshMarkerCount();
  setLastSession(null);
  
  const lastSessionIdEl = $('lastSessionId');
  const lastHopCountEl = $('lastHopCount');
  const summaryEl = $('sessionSummary');
  
  if (lastSessionIdEl) lastSessionIdEl.textContent = '—';
  if (lastHopCountEl) lastHopCountEl.textContent = '—';
  if (summaryEl) summaryEl.textContent = '';
}

async function showAccesses() {
  const ip = state.currentIP || (elements.ipInput()?.value || '').trim();
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
    if (! recentAccesses) return;
    
    recentAccesses.innerHTML = '';
    if (! accesses.length) {
      recentAccesses.innerHTML = '<div class="muted small">No recent accesses for this IP. </div>';
      return;
    }
    
    const frag = document.createDocumentFragment();
    accesses.slice(0, 50).forEach(a => {
      const row = document.createElement('div');
      row.className = 'py-1 border-b small';
      row.innerHTML = `<div class="font-medium small">${a.timestamp} — ${a.method || ''} ${a.path || ''} <span class="muted">[${a.status || ''}]</span></div>
                       <div class="muted small">${a.http_user_agent || ''} ${a.server_name ?  ' @ ' + a.server_name :  ''}</div>`;
      frag.appendChild(row);
    });
    recentAccesses.appendChild(frag);
  } catch (err) {
    ui.setLoading(false);
    ui.toast('Fetching accesses failed');
    console.error('showAccesses error:', err);
  }
}

async function refreshOrg() {
  const sel = window.selectedNode;
  if (!sel?. ip) return ui.toast('Select a node with an IP first.');
  
  ui.setLoading(true, 'Refreshing org info…');
  
  const r = await apiGet(`/api/v1/organization/refresh?id=${encodeURIComponent(sel.ip)}&force=1`, { retries: 2 });
  ui.setLoading(false);
  
  if (!r.ok) {
    ui.toast(r.error || 'Refresh failed');
    return;
  }
  
  const r2 = await apiGet(`/api/v1/locate?ip=${encodeURIComponent(sel.ip)}`);
  if (r2.ok && r2.data?. node) {
    ui.setSelectedNodeUI(r2.data.node);
    ui.toast('Organization refreshed');
  } else {
    ui.toast('Refreshed but failed to reload node details.');
  }
}

async function locateAttacker(ip, opts = {}) {
  if (!ip) return false;
  
  ui.setLoading(true, 'Locating attacker…');
  const loc = await apiGet(`/api/v1/locate?ip=${encodeURIComponent(ip)}`, { retries: 2 });
  ui.setLoading(false);
  
  if (!loc.ok || !loc.data?.node) {
    if (! opts.silent) ui.toast('Attacker node not found in DB');
    return false;
  }
  
  const node = loc.data.node;
  
  ui.ensurePanelOpen('map');
  mapModule.clearMap();
  mapModule.addMarkerForNode(node, 'last');
  ui.setSelectedNodeUI(node);
  
  if (mapModule.getMarkerCount() > 0) mapModule.fitToMarkers();
  refreshMarkerCount();
  
  if (!opts.silent) {
    window.dispatchEvent(new CustomEvent('ui:switchTab', { detail: { name: 'map' } }));
    ui.toast(`Attacker ${ip} highlighted`);
  }
  return true;
}

async function resolveNodeForAction(ip) {
  if (window.selectedNode && (!ip || window.selectedNode.ip === ip)) return window.selectedNode;
  if (!ip) return null;
  try {
    const res = await apiGet(`/api/v1/locate?ip=${encodeURIComponent(ip)}`, { retries: 1 });
    if (res.ok && res.data?.node) return res.data.node;
  } catch (e) {
    console.error('resolveNodeForAction error:', e);
  }
  return window.selectedNode || null;
}

function initPopupActionDelegates() {
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.popup-action[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const ip = btn.dataset.ip || '';
    const node = await resolveNodeForAction(ip);
    if (!node) {
      ui.toast('Node details unavailable');
      return;
    }
    if (action === 'panel') {
      ui.ensurePanelOpen('selectedNode');
      ui.setSelectedNodeUI(node);
      ui.toast('Node opened in panel');
    } else if (action === 'pin') {
      ui.addPinnedCard(`Node ${node.ip || ''}`, buildPinnedNodeHtml(node));
      ui.toast('Pinned node details');
    } else if (action === 'pin-left') {
      ui.addPanelToZone(`Node ${node.ip || ''}`, buildPinnedNodeHtml(node), 'left');
      ui.toast('Added to left sidebar');
    } else if (action === 'pin-middle') {
      ui.addPanelToZone(`Node ${node.ip || ''}`, buildPinnedNodeHtml(node), 'middle');
      ui.toast('Added to middle overlay');
    } else if (action === 'pin-right') {
      ui.addPanelToZone(`Node ${node.ip || ''}`, buildPinnedNodeHtml(node), 'right');
      ui.toast('Added to right sidebar');
    }
  });
}

// ============================================
// TAB MANAGEMENT
// ============================================

function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn[data-tab]');
  
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    setActiveTab(tab);
    
    tabBtns.forEach(b => {
      b.classList.toggle('active', b === btn);
        b.setAttribute('aria-selected', b === btn ?  'true' : 'false');
      });
      
      if (tab === 'honeypot') {
        ui.ensurePanelOpen('honeypot');
        $('honeypotFilter')?.focus();
      } else if (tab === 'explore') {
        ui.ensurePanelOpen('explore');
        $('dbPanelQuery')?.focus();
      }
      
      // Trigger map resize if map is visible
      if (tab === 'map' || tab === 'explore') {
        setTimeout(() => mapModule.invalidateSize(), 100);
      }
    });
  });
  
  const savedTab = state.activeTab;
  if (savedTab) {
    const savedBtn = document.querySelector(`.tab-btn[data-tab="${savedTab}"]`);
    if (savedBtn && !savedBtn.classList.contains('active')) {
      savedBtn.click();
    }
  }
  
  // Listen for external tab switch requests
  window.addEventListener('ui:switchTab', (ev) => {
    const name = ev.detail?.name;
    if (name) {
      const btn = document.querySelector(`.tab-btn[data-tab="${name}"]`);
      btn?.click();
    }
  });
}

// ============================================
// THEME & SIDEBAR TOGGLES
// ============================================

function initThemeToggle() {
  elements.themeToggle()?.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    const btn = elements.themeToggle();
    
    if (current === 'dark') {
      document.documentElement.removeAttribute('data-theme');
      if (btn) btn.textContent = '🌙';
    } else {
      document.documentElement. setAttribute('data-theme', 'dark');
      if (btn) btn.textContent = '☀️';
    }
  });
}

function initSidebarToggles() {
  elements.toggleLeft()?.addEventListener('click', () => {
    const zone = $('leftZone');
    if (zone) {
      zone.classList.toggle('hidden');
      setTimeout(() => mapModule.invalidateSize(), 150);
    }
  });
  
  elements.toggleRight()?.addEventListener('click', () => {
    const zone = $('rightZone');
    if (zone) {
      zone.classList. toggle('hidden');
      setTimeout(() => mapModule.invalidateSize(), 150);
    }
  });
  
  // Toggle middle zone (overlay)
  $('toggleMiddle')?.addEventListener('click', () => {
    // Create the zone if it doesn't exist, then toggle its visibility
    const zone = ui.getOrCreateMiddleZone();
    if (zone) {
      zone.classList.toggle('hidden');
      setTimeout(() => mapModule.invalidateSize(), 150);
    }
  });
}

// ============================================
// LAYOUT TOGGLE (from old version)
// ============================================

function initLayoutToggle() {
  const toggleLayoutBtn = elements.toggleLayoutBtn();
  
  // Load and apply saved layout mode preference
  const savedGrid = ui.loadGridMode();
  if (savedGrid) {
    setGridMode(true);
    ui.setGridMode(true);
    if (toggleLayoutBtn) toggleLayoutBtn.textContent = 'Grid';
  }
  
  toggleLayoutBtn?.addEventListener('click', () => {
    const next = !state.gridMode;
    setGridMode(next);
    ui.setGridMode(state.gridMode);
    toggleLayoutBtn.textContent = state.gridMode ? 'Grid' : 'Free';
  });
}

// ============================================
// CLOSE ALL PINS (from old version)
// ============================================

function initCloseAllPins() {
  elements.closeAllPinsBtn()?.addEventListener('click', () => {
    ui.closeAllPinnedCards();
  });
}

// ============================================
// KEYBOARD SHORTCUTS
// ============================================

function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    
    const key = e.key. toLowerCase();
    
    switch (key) {
      case 'l':
        locateIP();
        break;
      case 't':
        traceIP();
        break;
      case 'm':
        mapModule.fitToMarkers();
        break;
      case 'c':
        clearMap();
        break;
      case 'escape':
        ui.hideModal();
        break;
    }
  });
}

function initIpInputShortcuts() {
  const ipEl = elements.ipInput();
  if (!ipEl) return;
  ipEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey || e.ctrlKey || e.metaKey) {
        traceIP();
      } else {
        locateIP();
      }
    }
  });
}

// ============================================
// HONEYPOT HANDLERS
// ============================================

function initHoneypotHandlers() {
  $('honeypotListBtn')?.addEventListener('click', () => honeypotUI.listHoneypotSessions(100));
  $('honeypotFlowsBtn')?.addEventListener('click', () => honeypotUI.listHoneypotFlows(100));
  $('honeypotIngestBtn')?.addEventListener('click', () => honeypotUI.ingestCowrieHandler());
  $('honeypotIngestPcapBtn')?.addEventListener('click', () => honeypotUI.ingestPcapHandler());
  
  $('honeypotArtifactBtn')?.addEventListener('click', () => {
    const name = ($('honeypotArtifactName')?.value || '').trim();
    if (! name) return ui.toast('Provide artifact name');
    
    const url = honeypotApi.artifactDownloadUrl(name);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
  });
}

// ============================================
// CUSTOM EVENTS
// ============================================

function initCustomEvents() {
  window.addEventListener('honeypot:view', (ev) => {
    const id = ev.detail?. id;
    if (id) {
      ui.ensurePanelOpen('honeypot');
      honeypotUI.viewHoneypotSession(id);
    }
  });
  
  window.addEventListener('honeypot:locate', (ev) => {
    const ip = ev.detail?.ip;
    if (ip) locateAttacker(ip, ev.detail);
  });
  
  window.addEventListener('honeypot:list', () => honeypotUI.listHoneypotSessions(100));
  
  window.addEventListener('searchDB', () => dbUI.runSearch());
  
  window.addEventListener('panels:layout-changed', () => {
    setTimeout(() => mapModule.invalidateSize(), 150);
  });
  
  // From old version:  pinned layout changes
  window.addEventListener('pinned:layout-changed', () => {
    setTimeout(() => mapModule.invalidateSize(), 150);
  });
  
  // Quick actions from panel system
  window.addEventListener('quickAction', (ev) => {
    const action = ev.detail?.action;
    switch (action) {
      case 'locate':  locateIP(); break;
      case 'trace': traceIP(); break;
      case 'clear': clearMap(); break;
      case 'fit': mapModule.fitToMarkers(); break;
    }
  });
}

// ============================================
// MAP SELECTION CALLBACK
// ============================================

function initMapSelection() {
  mapModule.onSelect(node => {
    ui.setSelectedNodeUI(node);
    refreshMarkerCount();
  });
}

// ============================================
// AUTO REFRESH
// ============================================

function initAutoRefresh() {
  setInterval(() => {
    try {
      if (state.activeTab === 'honeypot') {
        honeypotUI.listHoneypotSessions(100);
        honeypotUI.listHoneypotFlows(100);
      }
    } catch (e) {
      console.error('Auto-refresh honeypot error', e);
    }
  }, 30000);
}

// ============================================
// CARD COLLAPSE HANDLERS (from old version)
// ============================================

function initCardCollapseHandlers() {
  document.querySelectorAll('.card-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const card = btn. closest('.card');
      if (!card) return;
      card.classList.toggle('card-collapsed');
      btn.textContent = card.classList. contains('card-collapsed') ? '▸' : '▾';
    });
  });
  
  $('toggleMapCard')?.addEventListener('click', () => {
    const mapCard = $('mapCard');
    if (! mapCard) return;
    mapCard.classList.toggle('card-collapsed');
    $('toggleMapCard').textContent = mapCard.classList. contains('card-collapsed') ? '▸' : '▾';
    setTimeout(() => mapModule.invalidateSize(), 200);
  });
}

// ============================================
// MAIN INITIALIZATION
// ============================================

async function init() {
  try {
    await mapModule.initMap();
    
    ui.initUI();
    dbUI.initDatabasePanel();
    liveView.initLiveView();
    applySavedInputs({
      ipInput: elements.ipInput(),
      maxttlInput: elements.maxttl(),
      deepToggle: elements.deepToggle()
    });
    
    initTabs();
    initMapSelection();
    
    // Main buttons
    elements.locateBtn()?.addEventListener('click', locateIP);
    elements.traceBtn()?.addEventListener('click', traceIP);
    $('clearMapBtn')?.addEventListener('click', clearMap);
    $('fitMarkersBtn')?.addEventListener('click', () => mapModule.fitToMarkers());
    $('accessesBtn')?.addEventListener('click', showAccesses);
    $('refreshOrgBtn')?.addEventListener('click', refreshOrg);
    
    initThemeToggle();
    initSidebarToggles();
    initLayoutToggle();
    initCloseAllPins();
    initKeyboardShortcuts();
    initIpInputShortcuts();
    initHoneypotHandlers();
    initCustomEvents();
    initPopupActionDelegates();
    initCardCollapseHandlers();
    initAutoRefresh();
    
    // Resize handler
    window.addEventListener('resize', ui.debounce(() => {
      mapModule.invalidateSize();
    }, 150));
    
    // Initial map resize
    setTimeout(() => mapModule.invalidateSize(), 300);
    
    console.log('HoneyMoon initialized');
  } catch (err) {
    console.error('Init error:', err);
    ui.toast('Application initialization failed');
  }
}

init();
