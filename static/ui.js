// Optimized UI module with unified panel management system

import * as mapModule from './map.js';

// Storage keys
const STORAGE_KEYS = {
  searchHistory: 'ipExplorer. searchHistory. v2',
  panels: 'ipExplorer. panels.v2',
  gridMode: 'ipExplorer. gridMode.v2'
};

// Panel zones
const ZONES = {
  LEFT: 'left',
  MAIN: 'main',
  RIGHT: 'right'
};

// Base panel definitions
const BASE_PANELS = {
  map: {
    id: 'panel-map',
    title: 'Map',
    icon: '🗺️',
    defaultZone: ZONES. MAIN,
    required: true,
    minWidth: 300,
    minHeight: 240,
    sourceSelector: '#mapCard'
  },
  explore: {
    id: 'panel-explore',
    title:  'Database Explorer',
    icon: '🔍',
    defaultZone: ZONES.LEFT,
    required: false,
    minWidth: 280,
    minHeight: 200,
    sourceSelector: '#exploreCard'
  },
  honeypot: {
    id: 'panel-honeypot',
    title: 'Honeypot',
    icon:  '🍯',
    defaultZone:  ZONES.LEFT,
    required: false,
    minWidth: 280,
    minHeight: 180,
    sourceSelector: '#honeypotCard'
  },
  selectedNode: {
    id: 'panel-selected',
    title: 'Selected Node',
    icon: '📊',
    defaultZone:  ZONES.RIGHT,
    required: false,
    minWidth: 260,
    minHeight: 150,
    sourceSelector: '#selectedNodeCard'
  },
  hops: {
    id: 'panel-hops',
    title: 'Traceroute Hops',
    icon: '🛤️',
    defaultZone:  ZONES.RIGHT,
    required: false,
    minWidth: 260,
    minHeight: 150,
    sourceSelector: '#hopCard'
  }
};

// Panel state management
const panelState = new Map();
let gridMode = false;

// DOM cache
const domCache = new Map();
function $(id) {
  if (!domCache.has(id)) {
    domCache.set(id, document.getElementById(id));
  }
  return domCache.get(id);
}

function clearDomCache() {
  domCache.clear();
}

// Utilities
export function debounce(fn, ms = 100) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}

function throttle(fn, ms = 16) {
  let lastCall = 0;
  return (...args) => {
    const now = Date.now();
    if (now - lastCall >= ms) {
      lastCall = now;
      fn. apply(this, args);
    }
  };
}

function escapeHtml(str) {
  if (!str) return '';
  const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'":  '&#39;' };
  return str.replace(/[&<>"']/g, m => escapeMap[m]);
}

// Toast notifications
export function toast(msg, timeout = 4000) {
  const container = $('toast');
  if (!container) {
    console.log('Toast:', msg);
    return;
  }
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  t.setAttribute('role', 'alert');
  container.appendChild(t);
  
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transition = 'opacity 0.3s ease';
    setTimeout(() => t.remove(), 300);
  }, timeout);
}

// Loading state
export function setLoading(on, text = null) {
  const loadingEl = $('loading');
  const statusEl = $('status');
  if (loadingEl) loadingEl.classList.toggle('hidden', !on);
  if (statusEl) statusEl.textContent = on ? (text || 'Working...') : 'Ready';
}

// Search history
export function pushSearchHistory(q) {
  if (! q) return;
  try {
    const arr = JSON.parse(localStorage.getItem(STORAGE_KEYS. searchHistory) || '[]');
    const filtered = [q, ...arr.filter(x => x !== q)].slice(0, 20);
    localStorage.setItem(STORAGE_KEYS.searchHistory, JSON.stringify(filtered));
    requestAnimationFrame(renderSearchHistory);
  } catch (e) {
    console.error('Failed to save search history:', e);
  }
}

export function renderSearchHistory() {
  const searchHistoryEl = $('searchHistory');
  if (!searchHistoryEl) return;
  
  try {
    const arr = JSON. parse(localStorage.getItem(STORAGE_KEYS.searchHistory) || '[]');
    if (! arr.length) {
      searchHistoryEl.innerHTML = '';
      return;
    }
    
    const frag = document.createDocumentFragment();
    arr.slice(0, 10).forEach(q => {
      const b = document.createElement('button');
      b.className = 'history-btn';
      b.textContent = q;
      b.dataset.query = q;
      frag.appendChild(b);
    });
    
    searchHistoryEl.innerHTML = '';
    searchHistoryEl.appendChild(frag);
  } catch (e) {
    searchHistoryEl.innerHTML = '';
  }
}

// Node selection UI
export function resetSelectedUI() {
  ['selIp', 'selHost', 'selOrg', 'selASN', 'selCC', 'selFirst', 'selLast', 'selCount'].forEach(id => {
    const el = $(id);
    if (el) el.textContent = '—';
  });
  const selRegistryEl = $('selRegistry');
  if (selRegistryEl) selRegistryEl.innerHTML = '—';
}

export function setSelectedNodeUI(node) {
  node = node || {};
  window.selectedNode = node;
  
  ensurePanelOpen('selectedNode');
  
  requestAnimationFrame(() => {
    const setText = (id, text) => {
      const el = $(id);
      if (el) el.textContent = text;
    };
    
    setText('selIp', node.ip || '—');
    setText('selHost', node.hostname || '—');
    setText('selOrg', node.organization_obj?. name || node.organization || '—');
    setText('selASN', node. asn || node.isp || '—');
    setText('selCC', [node.city, node.country]. filter(Boolean).join(', ') || '—');
    setText('selFirst', node.first_seen || '—');
    setText('selLast', node.last_seen || '—');
    setText('selCount', node.seen_count ??  '—');

    const reg = node.organization_obj?.extra_data?.company_search || node.extra_data?.company_search;
    const selRegistryEl = $('selRegistry');
    if (selRegistryEl) {
      if (reg) {
        const title = reg.matched_name || reg.name || '';
        const url = reg.company_url || '';
        const num = reg.company_number ?  ` (${reg.company_number})` : '';
        const src = reg.source ?  `[${reg.source}] ` : '';
        selRegistryEl.innerHTML = `${src}<strong>${escapeHtml(title)}${escapeHtml(num)}</strong> ${url ?  `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">view</a>` : ''}`;
      } else {
        selRegistryEl.innerHTML = '—';
      }
    }
  });
}

// Hop list rendering
export function renderHopList(hops, nodes) {
  ensurePanelOpen('hops');
  
  const hopList = $('hopList');
  if (!hopList) return;
  
  if (! hops?. length) {
    hopList.innerHTML = '<div class="muted">No hops recorded</div>';
    return;
  }

  const frag = document.createDocumentFragment();
  hops.forEach(h => {
    const ip = h.ip || '(no reply)';
    const node = h.ip ? (nodes[h.ip] || null) : null;
    const row = document.createElement('div');
    row.className = 'hop-row clickable';
    row.dataset.ip = ip;
    
    const rttDisplay = h.rtt ? `${(h.rtt * 1000).toFixed(1)} ms` : '';
    row.innerHTML = `
      <div class="hop-main">
        <strong>#${h.hop_number}</strong>
        <span>${escapeHtml(ip)}</span>
        <span class="muted">${rttDisplay}</span>
      </div>
      <div class="hop-org muted">${escapeHtml(node?.organization || '')}</div>`;
    
    if (node) row._nodeData = node;
    frag.appendChild(row);
  });
  
  hopList.innerHTML = '';
  hopList.appendChild(frag);
}

export function renderHopListFromNode(node) {
  const hopList = $('hopList');
  if (!hopList) return;
  
  if (!node?.path_hops?.length) {
    hopList.innerHTML = '<div class="muted">No traceroute hops for this node. </div>';
    return;
  }
  
  const frag = document.createDocumentFragment();
  node.path_hops.forEach(h => {
    const div = document.createElement('div');
    div.className = 'hop-row';
    div.innerHTML = `<strong>#${h.hop_number}</strong> ${escapeHtml(h. ip || '(no reply)')}`;
    frag.appendChild(div);
  });
  
  hopList.innerHTML = '';
  hopList. appendChild(frag);
}

// ============================================
// PANEL MANAGEMENT SYSTEM
// ============================================

function getZoneContainer(zone) {
  switch (zone) {
    case ZONES.LEFT:  return $('leftZone');
    case ZONES.MAIN: return $('mainZone');
    case ZONES.RIGHT: return $('rightZone');
    default: return $('mainZone');
  }
}

function createPanelElement(config, contentNode = null) {
  const panel = document.createElement('div');
  panel.className = 'panel-card';
  panel.id = config.id;
  panel.dataset.panelKey = config.key || config.id;
  panel.dataset.zone = config.zone || config.defaultZone;
  
  if (config.minWidth) panel.style.minWidth = `${config.minWidth}px`;
  if (config.minHeight) panel.style.minHeight = `${config.minHeight}px`;
  
  panel.innerHTML = `
    <div class="panel-header">
      <div class="panel-title">
        <span class="panel-icon">${config.icon || '📋'}</span>
        <span>${escapeHtml(config. title)}</span>
      </div>
      <div class="panel-controls">
        <button class="panel-btn" data-action="move-left" title="Move to left" aria-label="Move to left sidebar">◀</button>
        <button class="panel-btn" data-action="move-right" title="Move to right" aria-label="Move to right sidebar">▶</button>
        <button class="panel-btn" data-action="collapse" title="Collapse" aria-label="Collapse panel">▾</button>
        ${! config.required ? '<button class="panel-btn" data-action="close" title="Close" aria-label="Close panel">✕</button>' : ''}
      </div>
    </div>
    <div class="panel-body"></div>
    <div class="panel-resize"></div>
  `;
  
  const body = panel.querySelector('.panel-body');
  if (contentNode) {
    body.appendChild(contentNode);
  }
  
  return panel;
}

function initBasePanel(key) {
  const config = BASE_PANELS[key];
  if (!config) return null;
  
  const savedState = loadPanelState(key);
  const zone = savedState?.zone || config. defaultZone;
  const container = getZoneContainer(zone);
  if (!container) return null;
  
  // Get source content
  const sourceEl = document.querySelector(config.sourceSelector);
  let contentNode = null;
  
  if (sourceEl) {
    const body = sourceEl.querySelector('.card-body') || sourceEl;
    contentNode = body;
    sourceEl.classList.add('panel-source-hidden');
  }
  
  const panelConfig = { ...config, key, zone };
  const panel = createPanelElement(panelConfig, contentNode);
  
  // Apply saved state
  if (savedState) {
    if (savedState.collapsed) panel.classList.add('panel-collapsed');
    if (savedState.width) panel.style.width = `${savedState.width}px`;
    if (savedState.height) panel.style.height = `${savedState.height}px`;
    if (savedState.order != null) panel.style.order = savedState.order;
  }
  
  container.appendChild(panel);
  panelState.set(key, { panel, config:  panelConfig, zone });
  
  return panel;
}

export function ensurePanelOpen(key) {
  const existing = panelState.get(key);
  if (existing && existing.panel && document.body.contains(existing.panel)) {
    existing.panel. classList.remove('panel-collapsed');
    return existing.panel;
  }
  
  return initBasePanel(key);
}

export function closePanel(key) {
  const state = panelState.get(key);
  if (!state) return;
  
  const config = BASE_PANELS[key];
  if (config?.required) {
    toast(`${config.title} cannot be closed`);
    return;
  }
  
  state.panel.remove();
  panelState.delete(key);
  savePanelStates();
}

export function movePanelToZone(key, targetZone) {
  const state = panelState.get(key);
  if (!state) return;
  
  const container = getZoneContainer(targetZone);
  if (!container) return;
  
  state.panel.dataset.zone = targetZone;
  state.zone = targetZone;
  container.appendChild(state.panel);
  
  savePanelStates();
  dispatchLayoutEvent();
  toast(`Moved to ${targetZone}`);
}

export function togglePanelCollapse(key) {
  const state = panelState.get(key);
  if (!state) return;
  
  state.panel.classList.toggle('panel-collapsed');
  savePanelStates();
}

function loadPanelState(key) {
  try {
    const all = JSON.parse(localStorage.getItem(STORAGE_KEYS. panels) || '{}');
    return all[key] || null;
  } catch (e) {
    return null;
  }
}

const savePanelStates = debounce(() => {
  const states = {};
  panelState. forEach((state, key) => {
    const panel = state.panel;
    states[key] = {
      zone: state.zone,
      collapsed: panel.classList.contains('panel-collapsed'),
      width: panel.style.width ?  parseInt(panel.style.width, 10) : null,
      height: panel.style.height ?  parseInt(panel.style.height, 10) : null,
      order: panel.style.order ?  parseInt(panel.style.order, 10) : null
    };
  });
  
  try {
    localStorage.setItem(STORAGE_KEYS.panels, JSON.stringify(states));
  } catch (e) {
    console.error('Failed to save panel states:', e);
  }
}, 300);

export function initPanels() {
  Object.keys(BASE_PANELS).forEach(key => {
    const savedState = loadPanelState(key);
    if (BASE_PANELS[key]. required || savedState) {
      initBasePanel(key);
    }
  });
}

export function showPanelPicker() {
  const closedPanels = Object.entries(BASE_PANELS).filter(([key]) => !panelState.has(key));
  
  if (! closedPanels.length) {
    toast('All panels are open');
    return;
  }
  
  const picker = document.createElement('div');
  picker.className = 'panel-picker-overlay';
  picker.innerHTML = `
    <div class="panel-picker">
      <h3>Add Panel</h3>
      <div class="panel-picker-list">
        ${closedPanels.map(([key, config]) => `
          <button class="panel-picker-btn" data-panel-key="${key}">
            <span>${config.icon}</span>
            <span>${config.title}</span>
          </button>
        `).join('')}
      </div>
      <button class="panel-picker-cancel">Cancel</button>
    </div>
  `;
  
  document.body.appendChild(picker);
  
  picker.addEventListener('click', (e) => {
    const btn = e.target.closest('.panel-picker-btn');
    if (btn) {
      const key = btn.dataset.panelKey;
      initBasePanel(key);
      savePanelStates();
      picker.remove();
      toast(`${BASE_PANELS[key].title} opened`);
    } else if (e.target.closest('.panel-picker-cancel') || e.target === picker) {
      picker.remove();
    }
  });
}

function initPanelEventListeners() {
  document.addEventListener('click', (e) => {
    const panel = e.target.closest('.panel-card');
    if (!panel) return;
    
    const key = panel.dataset.panelKey;
    const action = e.target.closest('[data-action]')?.dataset.action;
    
    if (action === 'collapse') {
      togglePanelCollapse(key);
    } else if (action === 'close') {
      closePanel(key);
    } else if (action === 'move-left') {
      movePanelToZone(key, ZONES.LEFT);
    } else if (action === 'move-right') {
      movePanelToZone(key, ZONES.RIGHT);
    }
  });
  
  // Resize handling
  document.addEventListener('mousedown', (e) => {
    const resizeHandle = e.target.closest('.panel-resize');
    if (! resizeHandle) return;
    
    const panel = resizeHandle.closest('.panel-card');
    if (!panel) return;
    
    e.preventDefault();
    startPanelResize(panel, e);
  });
  
  // Search history delegation
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.history-btn[data-query]');
    if (btn) {
      const queryInput = $('dbPanelQuery');
      if (queryInput) queryInput.value = btn.dataset. query;
      window.dispatchEvent(new Event('searchDB'));
    }
  });
  
  // Hop row delegation
  document.addEventListener('click', (e) => {
    const row = e.target.closest('#hopList .hop-row');
    if (row) {
      const node = row._nodeData || { ip: row.dataset.ip };
      setSelectedNodeUI(node);
      if (node.latitude && node.longitude) {
        mapModule.panToLatLng(node.latitude, node.longitude);
      }
    }
  });
}

function startPanelResize(panel, startEvent) {
  const startRect = panel.getBoundingClientRect();
  const startW = startRect.width;
  const startH = startRect.height;
  const startX = startEvent.clientX;
  const startY = startEvent.clientY;
  
  const onMove = throttle((e) => {
    const newW = Math.max(200, startW + (e.clientX - startX));
    const newH = Math. max(100, startH + (e.clientY - startY));
    panel.style.width = `${newW}px`;
    panel.style.height = `${newH}px`;
  }, 16);
  
  function onUp() {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    savePanelStates();
    dispatchLayoutEvent();
  }
  
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

function dispatchLayoutEvent() {
  window.dispatchEvent(new CustomEvent('panels: layout-changed'));
}

// Modal system
let previousActiveElement = null;

export function showModal({ title = '', html = '', text = '', allowPin = false, onPin = null } = {}) {
  const container = $('modalContainer');
  if (!container) return;
  
  previousActiveElement = document.activeElement;
  
  container.innerHTML = '';
  container.classList.remove('modal-hidden');
  container.classList.add('modal-visible');
  container.setAttribute('aria-hidden', 'false');

  const modal = document.createElement('div');
  modal.className = 'modal-card card';
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.setAttribute('tabindex', '-1');
  
  modal.innerHTML = `
    <div class="modal-header">
      <h3>${escapeHtml(title)}</h3>
      <div class="modal-controls">
        ${allowPin ? '<button id="modalPinBtn" class="modal-btn">Pin</button>' : ''}
        <button id="modalCloseBtn" class="modal-btn">✕</button>
      </div>
    </div>
    <div class="modal-body"></div>
  `;

  container.appendChild(modal);
  
  const contentEl = modal.querySelector('.modal-body');
  if (html) contentEl.innerHTML = html;
  else contentEl.textContent = text || '';

  $('modalCloseBtn')?.addEventListener('click', hideModal);
  $('modalPinBtn')?.addEventListener('click', () => {
    onPin?. ();
    hideModal();
  });

  modal.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hideModal();
  });
  modal.focus();
}

export function hideModal() {
  const container = $('modalContainer');
  if (! container) return;
  
  container.classList.remove('modal-visible');
  container.classList. add('modal-hidden');
  container.setAttribute('aria-hidden', 'true');
  container.innerHTML = '';
  
  previousActiveElement?. focus();
}

// Grid mode
export function setGridMode(enabled) {
  gridMode = enabled;
  
  [ZONES.LEFT, ZONES. MAIN, ZONES.RIGHT].forEach(zone => {
    const container = getZoneContainer(zone);
    if (container) {
      container.classList.toggle('grid-mode', enabled);
    }
  });
  
  try {
    localStorage.setItem(STORAGE_KEYS.gridMode, enabled ?  '1' : '0');
  } catch (e) {}
  
  dispatchLayoutEvent();
}

export function loadGridMode() {
  try {
    return localStorage.getItem(STORAGE_KEYS.gridMode) === '1';
  } catch (e) {
    return false;
  }
}

// Main initialization
export function initUI() {
  renderSearchHistory();
  initPanelEventListeners();
  initPanels();
  
  // Copy IP button
  $('copyIpBtn')?.addEventListener('click', () => {
    const ip = window.selectedNode?. ip || $('selIp')?.textContent || '';
    if (! ip || ip === '—') return toast('No IP to copy');
    navigator.clipboard?. writeText(ip)
      .then(() => toast('Copied IP'))
      .catch(() => toast('Failed to copy'));
  });
  
  // Add panel button
  $('addPanelBtn')?.addEventListener('click', showPanelPicker);
  
  // Load grid mode preference
  if (loadGridMode()) {
    setGridMode(true);
  }
}

export { escapeHtml, ZONES, BASE_PANELS };
