// Optimized UI module with unified panel management system
// Merged: combines old version's pinned workspace with new panel system

import * as mapModule from './map.js';
import { escapeHtml, truncate, summarizeNodeDetails } from './util.js';

export { summarizeNodeDetails } from './util.js';

// Storage keys
const STORAGE_KEYS = {
  searchHistory: 'ipExplorer.searchHistory.v2',
  panels: 'ipExplorer.panels.v2',
  gridMode: 'ipExplorer.gridMode.v2',
  pinned: 'ipExplorer.pinned.v2',
  pinnedGrid: 'ipExplorer.pinned.grid.v2'
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
    defaultZone: ZONES.MAIN,
    required: true,
    minWidth: 300,
    minHeight: 240,
    sourceSelector: '#mapCard'
  },
  explore: {
    id: 'panel-explore',
    title: 'Database Explorer',
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
    icon: '🍯',
    defaultZone: ZONES.LEFT,
    required: false,
    minWidth: 280,
    minHeight: 180,
    sourceSelector: '#honeypotCard'
  },
  selectedNode: {
    id: 'panel-selected',
    title: 'Selected Node',
    icon: '📊',
    defaultZone: ZONES.RIGHT,
    required: false,
    minWidth: 260,
    minHeight: 150,
    sourceSelector: '#selectedNodeCard'
  },
  hops: {
    id: 'panel-hops',
    title: 'Traceroute Hops',
    icon: '🛤️',
    defaultZone: ZONES.RIGHT,
    required: false,
    minWidth: 260,
    minHeight: 150,
    sourceSelector: '#hopCard'
  }
};

// Panel state management
const panelState = new Map();
// Pinned card cache (from old version)
const pinnedCardCache = new Map();
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

// ============================================
// UTILITIES
// ============================================

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
      fn.apply(this, args);
    }
  };
}

// ============================================
// TOAST NOTIFICATIONS
// ============================================

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
  t.setAttribute('aria-live', 'assertive');
  container.appendChild(t);
  
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transition = 'opacity 0.3s ease';
    setTimeout(() => t.remove(), 300);
  }, timeout);
}

// ============================================
// LOADING STATE
// ============================================

export function setLoading(on, text = null) {
  const loadingEl = $('loading');
  const statusEl = $('status');
  if (loadingEl) loadingEl.classList.toggle('hidden', !on);
  if (statusEl) statusEl.textContent = on ? (text || 'Working...') : 'Ready';
}

// ============================================
// SEARCH HISTORY
// ============================================

export function pushSearchHistory(q) {
  if (!q) return;
  try {
    const arr = JSON.parse(localStorage.getItem(STORAGE_KEYS.searchHistory) || '[]');
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
    const arr = JSON.parse(localStorage.getItem(STORAGE_KEYS.searchHistory) || '[]');
    if (!arr.length) {
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

// ============================================
// NODE SELECTION UI
// ============================================

export function resetSelectedUI() {
  [
    'selIp',
    'selHost',
    'selOrg',
    'selASN',
    'selCC',
    'selPorts',
    'selOs',
    'selHttp',
    'selTags',
    'selFirst',
    'selLast',
    'selCount'
  ].forEach(id => {
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
    setText('selOrg', node.organization_obj?.name || node.organization || '—');
    setText('selASN', node.asn || node.isp || '—');
    setText('selCC', [node.city, node.country].filter(Boolean).join(', ') || '—');
    const summary = summarizeNodeDetails(node);
    setText('selPorts', summary.ports || '—');
    setText('selOs', summary.os || '—');
    setText('selHttp', summary.http || '—');
    setText('selTags', summary.tags || '—');
    setText('selFirst', node.first_seen || '—');
    setText('selLast', node.last_seen || '—');
    setText('selCount', node.seen_count ?? '—');

    const reg = node.organization_obj?.extra_data?.company_search || node.extra_data?.company_search;
    const selRegistryEl = $('selRegistry');
    if (selRegistryEl) {
      if (reg) {
        const title = reg.matched_name || reg.name || '';
        const url = reg.company_url || '';
        const num = reg.company_number ?` (${reg.company_number})` : '';
        const src = reg.source ?`[${reg.source}] ` : '';
        selRegistryEl.innerHTML = `${src}<strong>${escapeHtml(title)}${escapeHtml(num)}</strong> ${url ?`<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">view</a>` : ''}`;
      } else {
        selRegistryEl.innerHTML = '—';
      }
    }
  });
}

// ============================================
// HOP LIST RENDERING
// ============================================

export function renderHopList(hops, nodes) {
  ensurePanelOpen('hops');
  
  const hopList = $('hopList');
  if (!hopList) return;
  
  if (!hops?.length) {
    hopList.innerHTML = '<div class="muted">No hops recorded</div>';
    return;
  }

  const frag = document.createDocumentFragment();
  hops.forEach(h => {
    const ip = h.ip || '(no reply)';
    const node = h.ip ? (nodes[h.ip] || null) : null;
    const row = document.createElement('div');
    row.className = 'hop-row clickable';
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');
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
    hopList.innerHTML = '<div class="muted">No traceroute hops for this node.</div>';
    return;
  }
  
  const frag = document.createDocumentFragment();
  node.path_hops.forEach(h => {
    const div = document.createElement('div');
    div.className = 'hop-row';
    div.innerHTML = `<strong>#${h.hop_number}</strong> ${escapeHtml(h.ip || '(no reply)')}`;
    frag.appendChild(div);
  });
  
  hopList.innerHTML = '';
  hopList.appendChild(frag);
}

// ============================================
// PANEL MANAGEMENT SYSTEM
// ============================================

function getZoneContainer(zone) {
  switch (zone) {
    case ZONES.LEFT: return $('leftZone');
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
        <span>${escapeHtml(config.title)}</span>
      </div>
      <div class="panel-controls">
        <button class="panel-btn" data-action="move-left" title="Move to left" aria-label="Move to left sidebar">◀</button>
        <button class="panel-btn" data-action="move-right" title="Move to right" aria-label="Move to right sidebar">▶</button>
        <button class="panel-btn" data-action="collapse" title="Collapse" aria-label="Collapse panel">▾</button>
        ${!config.required ? '<button class="panel-btn" data-action="close" title="Close" aria-label="Close panel">✕</button>' : ''}
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
  const zone = savedState?.zone || config.defaultZone;
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
  panelState.set(key, { panel, config:panelConfig, zone });
  
  return panel;
}

export function ensurePanelOpen(key) {
  const existing = panelState.get(key);
  if (existing && existing.panel && document.body.contains(existing.panel)) {
    existing.panel.classList.remove('panel-collapsed');
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
    const all = JSON.parse(localStorage.getItem(STORAGE_KEYS.panels) || '{}');
    return all[key] || null;
  } catch (e) {
    return null;
  }
}

const savePanelStates = debounce(() => {
  const states = {};
  panelState.forEach((state, key) => {
    const panel = state.panel;
    states[key] = {
      zone: state.zone,
      collapsed: panel.classList.contains('panel-collapsed'),
      width: panel.style.width ?parseInt(panel.style.width, 10) : null,
      height: panel.style.height ? parseInt(panel.style.height, 10) : null,
      order: panel.style.order ? parseInt(panel.style.order, 10) : null
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
    if (BASE_PANELS[key].required || savedState) {
      initBasePanel(key);
    }
  });
}

export function showPanelPicker() {
  const closedPanels = Object.entries(BASE_PANELS).filter(([key]) => !panelState.has(key));
  
  if (!closedPanels.length) {
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

// Add a custom panel directly to a specific zone (left or right)
export function addPanelToZone(title, html, targetZone) {
  const zone = targetZone === 'left' ? ZONES.LEFT : ZONES.RIGHT;
  const container = getZoneContainer(zone);
  if (!container) {
    toast(`Cannot add to ${zone} zone`);
    return null;
  }
  
  const id = `custom-panel-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  
  const panel = document.createElement('div');
  panel.className = 'panel-card';
  panel.id = id;
  panel.dataset.panelKey = id;
  panel.dataset.zone = zone;
  panel.style.minWidth = '260px';
  panel.style.minHeight = '150px';
  
  panel.innerHTML = `
    <div class="panel-header">
      <div class="panel-title">
        <span class="panel-icon">📌</span>
        <span>${escapeHtml(title)}</span>
      </div>
      <div class="panel-controls">
        <button class="panel-btn" data-action="move-left" title="Move to left" aria-label="Move to left sidebar">◀</button>
        <button class="panel-btn" data-action="move-right" title="Move to right" aria-label="Move to right sidebar">▶</button>
        <button class="panel-btn" data-action="collapse" title="Collapse" aria-label="Collapse panel">▾</button>
        <button class="panel-btn" data-action="close" title="Close" aria-label="Close panel">✕</button>
      </div>
    </div>
    <div class="panel-body">${html || ''}</div>
    <div class="panel-resize"></div>
  `;
  
  container.appendChild(panel);
  
  // Store in panel state for proper management
  panelState.set(id, {
    panel,
    config: {
      id,
      title,
      icon: '📌',
      required: false,
      zone: zone
    },
    zone: zone
  });
  
  savePanelStates();
  dispatchLayoutEvent();
  return panel;
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
    if (!resizeHandle) return;
    
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
      if (queryInput) queryInput.value = btn.dataset.query;
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
    const newH = Math.max(100, startH + (e.clientY - startY));
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
  window.dispatchEvent(new CustomEvent('pinned:layout-changed'));
}

// ============================================
// PINNED CARDS SYSTEM (from old version)
// ============================================

function genId() {
  return `pin-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

function getCardOrder(card) {
  const v = card.dataset.order ??card.style.order;
  const parsed = parseInt(v, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}

function setCardOrder(card, order) {
  const safe = Number.isFinite(order) ? order : 0;
  card.dataset.order = String(safe);
  card.style.order = String(safe);
}

function nextCardOrder(area) {
  let maxOrder = 0;
  area?.querySelectorAll('.pinned-card').forEach(c => {
    maxOrder = Math.max(maxOrder, getCardOrder(c));
  });
  return maxOrder + 1;
}

export function addPinnedCard(title, html, opts = {}) {
  const area = $('pinnedArea');
  if (!area) return null;
  
  const savedState = opts.state || null;
  const id = savedState?.id || genId();
  const persist = opts.persist !== false;
  
  const wrapper = document.createElement('div');
  wrapper.className = 'pinned-card';
  wrapper.id = id;
  wrapper.dataset.pinnedId = id;
  wrapper.dataset.persist = persist ? '1' : '0';
  setCardOrder(wrapper, savedState?.order ?? nextCardOrder(area));

  wrapper.innerHTML = `
    <div class="pin-header">
      <div><strong>${escapeHtml(title)}</strong></div>
      <div class="pin-controls">
        <button class="pin-move-left" title="Move to left" aria-label="Move to left sidebar">◀</button>
        <button class="pin-move-right" title="Move to right" aria-label="Move to right sidebar">▶</button>
        <button class="pin-collapse" title="Collapse" aria-label="Collapse">▾</button>
        <button class="pin-dock" title="Dock/Float" aria-label="Toggle dock">⇱</button>
        <button class="pin-close" title="Close" aria-label="Close">✕</button>
      </div>
    </div>
    <div class="pin-body">${html || ''}</div>
    <div class="resize-handle" aria-label="Resize"></div>`;

  if (opts.className) {
    wrapper.classList.add(...opts.className.split(' ').filter(Boolean));
  }

  area.appendChild(wrapper);
  
  // Apply saved state
  applyPinnedCardState(wrapper, savedState, area);
  
  // Cache for quick access
  pinnedCardCache.set(id, wrapper);
  
  debouncedSavePinnedCards();
  return wrapper;
}

function applyPinnedCardState(wrapper, state, area) {
  const areaRect = area.getBoundingClientRect();
  const defaultLeft = Math.max(10, (areaRect.width - 320) / 2);
  const defaultTop = Math.max(10, (areaRect.height - 220) / 2);

  if (state) {
    setCardOrder(wrapper, state.order);
    if (state.docked) {
      wrapper.classList.add('docked');
      wrapper.style.position = 'relative';
      wrapper.style.left = '';
      wrapper.style.top = '';
      if (state.width) wrapper.style.width = `${state.width}px`;
      if (state.height) wrapper.style.height = `${state.height}px`;
    } else {
      wrapper.classList.remove('docked');
      wrapper.style.position = 'absolute';
      wrapper.style.left = `${state.left ??defaultLeft}px`;
      wrapper.style.top = `${state.top ?? defaultTop}px`;
      if (state.width) wrapper.style.width = `${state.width}px`;
      if (state.height) wrapper.style.height = `${state.height}px`;
    }
    if (state.z) wrapper.style.zIndex = state.z;
    if (state.collapsed) wrapper.classList.add('card-collapsed');
  } else {
    wrapper.style.position = 'absolute';
    wrapper.style.left = `${defaultLeft}px`;
    wrapper.style.top = `${defaultTop}px`;
  }
}

// Move pinned card to a specific zone (left or right sidebar)
function movePinnedCardToZone(pinnedCard, targetZone) {
  if (!pinnedCard) return;
  
  const targetContainer = getZoneContainer(targetZone);
  if (!targetContainer) {
    toast(`Cannot move to ${targetZone} zone`);
    return;
  }
  
  // Convert pinned card to a panel-style card in the target zone
  const title = pinnedCard.querySelector('.pin-header strong')?.textContent || 'Card';
  const bodyContent = pinnedCard.querySelector('.pin-body')?.innerHTML || '';
  
  // Create a new panel-style element for the zone
  const panel = document.createElement('div');
  panel.className = 'panel-card';
  panel.dataset.panelKey = pinnedCard.dataset.pinnedId || genId();
  panel.dataset.zone = targetZone;
  panel.style.minWidth = '260px';
  panel.style.minHeight = '150px';
  
  panel.innerHTML = `
    <div class="panel-header">
      <div class="panel-title">
        <span class="panel-icon">📌</span>
        <span>${escapeHtml(title)}</span>
      </div>
      <div class="panel-controls">
        <button class="panel-btn" data-action="move-left" title="Move to left" aria-label="Move to left sidebar">◀</button>
        <button class="panel-btn" data-action="move-right" title="Move to right" aria-label="Move to right sidebar">▶</button>
        <button class="panel-btn" data-action="collapse" title="Collapse" aria-label="Collapse panel">▾</button>
        <button class="panel-btn" data-action="close" title="Close" aria-label="Close panel">✕</button>
      </div>
    </div>
    <div class="panel-body">${bodyContent}</div>
    <div class="panel-resize"></div>
  `;
  
  // Add the panel to the target zone
  targetContainer.appendChild(panel);
  
  // Remove the original pinned card
  pinnedCardCache.delete(pinnedCard.dataset.pinnedId);
  pinnedCard.remove();
  
  debouncedSavePinnedCards();
  dispatchLayoutEvent();
  toast(`Moved to ${targetZone === ZONES.LEFT ? 'left' : 'right'} sidebar`);
}

// Event delegation for pinned cards
function initPinnedCardEventListeners() {
  document.addEventListener('click', (e) => {
    const pinnedCard = e.target.closest('.pinned-card');
    if (!pinnedCard) return;
    
    if (e.target.closest('.pin-move-left')) {
      e.stopPropagation();
      movePinnedCardToZone(pinnedCard, ZONES.LEFT);
    } else if (e.target.closest('.pin-move-right')) {
      e.stopPropagation();
      movePinnedCardToZone(pinnedCard, ZONES.RIGHT);
    } else if (e.target.closest('.pin-collapse')) {
      e.stopPropagation();
      pinnedCard.classList.toggle('card-collapsed');
      debouncedSavePinnedCards();
      dispatchLayoutEvent();
    } else if (e.target.closest('.pin-close')) {
      pinnedCardCache.delete(pinnedCard.dataset.pinnedId);
      pinnedCard.remove();
      debouncedSavePinnedCards();
      dispatchLayoutEvent();
    } else if (e.target.closest('.pin-dock')) {
      e.stopPropagation();
      togglePinnedCardDock(pinnedCard);
    } else {
      bringToFront(pinnedCard);
    }
  });

  // Drag handling for pinned cards (free mode)
  document.addEventListener('mousedown', (e) => {
    const header = e.target.closest('.pinned-card .pin-header');
    const area = $('pinnedArea');
    const isGrid = area?.classList.contains('grid-mode');
    if (header && !e.target.closest('.pin-controls') && !isGrid) {
      const card = header.closest('.pinned-card');
      bringToFront(card);
      if (!card.classList.contains('docked')) {
        e.preventDefault();
        startDrag(card, e);
      }
    }
    
    const resizeHandle = e.target.closest('.pinned-card .resize-handle');
    if (resizeHandle) {
      const card = resizeHandle.closest('.pinned-card');
      bringToFront(card);
      if (!card.classList.contains('docked')) {
        e.preventDefault();
        startResize(card, e);
      }
    }
  });
  
  // Grid drag-and-drop (swap order)
  initGridDragDrop();
}

let dragSrcId = null;

function initGridDragDrop() {
  document.addEventListener('dragstart', (e) => {
    const area = $('pinnedArea');
    if (!area?.classList.contains('grid-mode')) return;
    const card = e.target.closest('.pinned-card');
    if (!card) return;
    dragSrcId = card.dataset.pinnedId;
    card.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
  });

  document.addEventListener('dragover', (e) => {
    const area = $('pinnedArea');
    if (!area?.classList.contains('grid-mode')) return;
    const card = e.target.closest('.pinned-card');
    if (!card) return;
    e.preventDefault();
    card.classList.add('drag-over');
  });

  document.addEventListener('dragleave', (e) => {
    const area = $('pinnedArea');
    if (!area?.classList.contains('grid-mode')) return;
    const card = e.target.closest('.pinned-card');
    card?.classList.remove('drag-over');
  });

  document.addEventListener('drop', (e) => {
    const area = $('pinnedArea');
    if (!area?.classList.contains('grid-mode')) return;
    const target = e.target.closest('.pinned-card');
    if (!target || !dragSrcId) return;
    e.preventDefault();

    const src = area.querySelector(`.pinned-card[data-pinned-id="${dragSrcId}"]`);
    if (!src || src === target) {
      dragCleanup();
      return;
    }
    const srcOrder = getCardOrder(src);
    const tgtOrder = getCardOrder(target);
    setCardOrder(src, tgtOrder);
    setCardOrder(target, srcOrder);
    dragCleanup();
    debouncedSavePinnedCards();
    dispatchLayoutEvent();
  });

  document.addEventListener('dragend', () => dragCleanup());
}

function dragCleanup() {
  document.querySelectorAll('.pinned-card.dragging, .pinned-card.drag-over').forEach(c => {
    c.classList.remove('dragging', 'drag-over');
  });
  dragSrcId = null;
}

function togglePinnedCardDock(card) {
  const area = $('pinnedArea');
  const isDocked = card.classList.toggle('docked');
  
  if (isDocked) {
    card.style.left = '';
    card.style.top = '';
    card.style.zIndex = '';
    card.style.position = 'relative';
  } else {
    card.style.position = 'absolute';
    const rect = card.getBoundingClientRect();
    const areaRect = area.getBoundingClientRect();
    card.style.left = `${Math.max(8, rect.left - areaRect.left)}px`;
    card.style.top = `${Math.max(8, rect.top - areaRect.top)}px`;
  }
  debouncedSavePinnedCards();
  dispatchLayoutEvent();
}

function startDrag(el, startEvent) {
  const area = $('pinnedArea');
  if (!area) return;
  
  const areaRect = area.getBoundingClientRect();
  const rect = el.getBoundingClientRect();
  const offsetX = startEvent.clientX - rect.left;
  const offsetY = startEvent.clientY - rect.top;

  const onMove = throttle((e) => {
    let left = e.clientX - areaRect.left - offsetX;
    let top = e.clientY - areaRect.top - offsetY;
    left = Math.max(6, Math.min(left, areaRect.width - rect.width - 6));
    top = Math.max(6, Math.min(top, areaRect.height - rect.height - 6));
    el.style.left = `${left}px`;
    el.style.top = `${top}px`;
  }, 16);

  function onUp() {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    debouncedSavePinnedCards();
    dispatchLayoutEvent();
  }
  
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

function startResize(el, startEvent) {
  const area = $('pinnedArea');
  if (!area) return;
  
  const areaRect = area.getBoundingClientRect();
  const startRect = el.getBoundingClientRect();
  const startW = startRect.width;
  const startH = startRect.height;
  const startX = startEvent.clientX;
  const startY = startEvent.clientY;
  const elLeft = parseInt(el.style.left || '6', 10);
  const elTop = parseInt(el.style.top || '6', 10);

  const onMove = throttle((e) => {
    let newW = Math.max(240, startW + (e.clientX - startX));
    let newH = Math.max(140, startH + (e.clientY - startY));
    newW = Math.min(newW, areaRect.width - elLeft);
    newH = Math.min(newH, areaRect.height - elTop);
    el.style.width = `${newW}px`;
    el.style.height = `${newH}px`;
  }, 16);

  function onUp() {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    debouncedSavePinnedCards();
    dispatchLayoutEvent();
  }
  
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

function bringToFront(el) {
  const area = $('pinnedArea');
  if (!area) return;
  
  const children = area.querySelectorAll('.pinned-card');
  let maxZ = 10;
  
  children.forEach(c => {
    const z = parseInt(c.style.zIndex || '0', 10);
    if (!isNaN(z)) maxZ = Math.max(maxZ, z);
    c.classList.remove('active');
  });
  
  el.style.zIndex = maxZ + 1;
  el.classList.add('active');
  setTimeout(() => el.classList.remove('active'), 400);
}

// Debounced save to reduce localStorage writes
const debouncedSavePinnedCards = debounce(savePinnedCards, 300);

function currentPinnedStorageKey() {
  const area = $('pinnedArea');
  const isGrid = area?.classList.contains('grid-mode');
  return isGrid ?STORAGE_KEYS.pinnedGrid : STORAGE_KEYS.pinned;
}

export function savePinnedCards(mode = null) {
  const area = $('pinnedArea');
  if (!area) return;
  
  const isGrid = mode ?mode === 'grid' : area.classList.contains('grid-mode');
  const key = isGrid ?STORAGE_KEYS.pinnedGrid : STORAGE_KEYS.pinned;

  const cards = area.querySelectorAll('.pinned-card');
  const out = Array.from(cards).flatMap(c => {
    const shouldPersist = c.dataset.persist !== '0';
    if (!shouldPersist) return [];
    const titleEl = c.querySelector('.pin-header strong');
    const bodyEl = c.querySelector('.pin-body');
    const docked = c.classList.contains('docked');
    
    return [{
      id: c.dataset.pinnedId || c.id,
      title: titleEl?.textContent || '',
      html: bodyEl?.innerHTML || '',
      docked,
      collapsed: c.classList.contains('card-collapsed'),
      left: docked ? null : parseInt(c.style.left || '0', 10),
      top: docked ? null : parseInt(c.style.top || '0', 10),
      width: c.style.width ?parseInt(c.style.width, 10) : null,
      height: c.style.height ? parseInt(c.style.height, 10) : null,
      z: c.style.zIndex ? parseInt(c.style.zIndex, 10) : null,
      order: getCardOrder(c)
    }];
  });
  
  try {
    localStorage.setItem(key, JSON.stringify(out));
  } catch (e) {
    console.error('Failed to save pinned cards:', e);
  }
}

function loadPinnedState(mode = null) {
  const isGrid = mode === 'grid';
  const key = isGrid ? STORAGE_KEYS.pinnedGrid : STORAGE_KEYS.pinned;
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    console.error('Failed to read pinned cards:', e);
    return [];
  }
}

export function restorePinnedCards(mode = null) {
  const area = $('pinnedArea');
  if (!area) return;
  
  const isGrid = mode ?mode === 'grid' : area.classList.contains('grid-mode');
  const states = loadPinnedState(isGrid ?'grid' : 'free');
  if (!states.length) return;
  
  // Clear existing persisted cards only
  area.querySelectorAll('.pinned-card[data-pinned-id]').forEach(c => {
    if (c.dataset.persist === '1') c.remove();
  });
  pinnedCardCache.clear();
  
  states.forEach(state => {
    addPinnedCard(state.title || 'Pinned', state.html || '', { state });
  });
}

export function closeAllPinnedCards() {
  const area = $('pinnedArea');
  if (!area) return;
  
  area.querySelectorAll('.pinned-card').forEach(c => c.remove());
  pinnedCardCache.clear();
  
  try {
    localStorage.removeItem(STORAGE_KEYS.pinned);
    localStorage.removeItem(STORAGE_KEYS.pinnedGrid);
  } catch (e) {
    console.error('Failed to clear pinned cards:', e);
  }
}

// ============================================
// MODAL SYSTEM
// ============================================

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
    onPin?.();
    hideModal();
  });

  modal.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hideModal();
  });
  modal.focus();
}

export function hideModal() {
  const container = $('modalContainer');
  if (!container) return;
  
  container.classList.remove('modal-visible');
  container.classList.add('modal-hidden');
  container.setAttribute('aria-hidden', 'true');
  container.innerHTML = '';
  
  previousActiveElement?.focus();
}

// ============================================
// GRID MODE
// ============================================

export function setGridMode(enabled) {
  gridMode = enabled;
  
  // Apply to panel zones
  [ZONES.LEFT, ZONES.MAIN, ZONES.RIGHT].forEach(zone => {
    const container = getZoneContainer(zone);
    if (container) {
      container.classList.toggle('grid-mode', enabled);
    }
  });
  
  // Apply to pinned area
  const pinnedArea = $('pinnedArea');
  if (pinnedArea) {
    pinnedArea.classList.toggle('grid-mode', enabled);
    pinnedArea.querySelectorAll('.pinned-card').forEach((c, i) => {
      if (enabled) {
        c.classList.add('docked');
        c.style.position = 'relative';
        c.style.left = '';
        c.style.top = '';
        if (!c.dataset.order) setCardOrder(c, i);
        c.setAttribute('draggable', 'true');
      } else {
        c.removeAttribute('draggable');
        c.classList.remove('docked');
        c.style.position = 'absolute';
        if (!c.style.left || !c.style.top) {
          const areaWidth = pinnedArea.getBoundingClientRect().width;
          const left = 10 + (i * 30) % Math.max(120, areaWidth - 320);
          const top = 10 + Math.floor(i / 6) * 30;
          c.style.left = `${left}px`;
          c.style.top = `${top}px`;
        }
      }
    });
  }
  
  saveGridMode(enabled);
  dispatchLayoutEvent();
}

export function saveGridMode(enabled) {
  try {
    localStorage.setItem(STORAGE_KEYS.gridMode, enabled ?'1' : '0');
  } catch (e) {
    console.error('Failed to save grid mode', e);
  }
}

export function loadGridMode() {
  try {
    return localStorage.getItem(STORAGE_KEYS.gridMode) === '1';
  } catch (e) {
    return false;
  }
}

// ============================================
// FLOAT BUTTONS (from old version)
// ============================================

export function enableFloatButtons() {
  document.querySelectorAll('.card:not([data-floatable])').forEach(card => {
    const header = card.querySelector('.card-header');
    if (!header || card.classList.contains('pinned-card')) return;
    
    // Check if float button already exists
    if (header.querySelector('.card-float')) return;
    
    const btn = document.createElement('button');
    btn.className = 'card-float small';
    btn.title = 'Float card';
    btn.setAttribute('aria-label', 'Float this card');
    btn.textContent = 'Float';
    btn.dataset.action = 'float';
    
    const controls = header.querySelector('.card-toggle, .pin-controls');
    if (controls?.parentNode) {
      controls.parentNode.insertBefore(btn, controls.nextSibling);
    } else {
      header.appendChild(btn);
    }
    
    card.dataset.floatable = '1';
  });
}

// Event delegation for float buttons
function initFloatButtonListeners() {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.card-float[data-action="float"]');
    if (!btn) return;
    
    const card = btn.closest('.card');
    const header = card?.querySelector('.card-header');
    if (!card || !header) return;
    
    let title = 'Card';
    const strong = header.querySelector('strong');
    const heading = header.querySelector('h2, h3');
    title = strong?.textContent?.trim() || heading?.textContent?.trim() || title;
    
    floatCardToPinned(card, title, { persist: false });
    toast(`${title} floated`);
  });
}

// Float an existing card into the pinned area (moving the live node)
export function floatCardToPinned(cardOrSelector, title = null, opts = {}) {
  const card = typeof cardOrSelector === 'string' ? document.querySelector(cardOrSelector) : cardOrSelector;
  if (!card) return null;
  const header = card.querySelector('.card-header');
  const resolvedTitle = title || header?.querySelector('h2, h3, strong')?.textContent?.trim() || 'Panel';
  const clonedCard = card;
  clonedCard.classList.add('hidden-placeholder');
  const body = clonedCard.querySelector('.card-body');
  const container = body ? body : clonedCard;
  return addPinnedCardNode(resolvedTitle, container, { persist: opts.persist !== false, className: opts.className });
}

// Move an existing DOM node into a pinned card (keeps live content like map)
export function addPinnedCardNode(title, node, opts = {}) {
  if (!node) return null;
  const card = addPinnedCard(title, '', opts);
  if (!card) return null;
  const body = card.querySelector('.pin-body');
  if (body) {
    body.innerHTML = '';
    body.appendChild(node);
  }
  return card;
}

// ============================================
// MAIN INITIALIZATION
// ============================================

export function initUI() {
  renderSearchHistory();
  initPanelEventListeners();
  initPinnedCardEventListeners();
  initFloatButtonListeners();
  initPanels();
  restorePinnedCards();
  
  // Copy IP button
  $('copyIpBtn')?.addEventListener('click', () => {
    const ip = window.selectedNode?.ip || $('selIp')?.textContent || '';
    if (!ip || ip === '—') return toast('No IP to copy');
    navigator.clipboard?.writeText(ip)
      .then(() => toast('Copied IP'))
      .catch(() => toast('Failed to copy'));
  });
  
  // Add panel button
  $('addPanelBtn')?.addEventListener('click', showPanelPicker);
  
  // Load grid mode preference
  if (loadGridMode()) {
    setGridMode(true);
  }
  
  // Enable float buttons on existing cards
  enableFloatButtons();
}

export { ZONES, BASE_PANELS };
