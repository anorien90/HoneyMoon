// Optimized UI helpers with debouncing, event delegation, and memory management. 

import * as mapModule from './map.js';

export const HISTORY_KEY = 'ipExplorer. searchHistory. v1';
const PINNED_KEY = 'ipExplorer. pinned.v1';
const PINNED_KEY_FREE = PINNED_KEY;
const PINNED_KEY_GRID = 'ipExplorer.pinned.grid.v1';
const GRID_MODE_KEY = 'ipExplorer.gridMode.v1';

// Cached DOM references for performance
const domCache = new Map();

function $(id) {
  if (!domCache.has(id)) {
    domCache.set(id, document.getElementById(id));
  }
  return domCache.get(id);
}

// Debounce utility for expensive operations
function debounce(fn, ms = 100) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}

// Throttle utility for frequent events
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
  
  // Use requestAnimationFrame for smoother removal
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transition = 'opacity 0.3s ease';
    setTimeout(() => t.remove(), 300);
  }, timeout);
}

export function setLoading(on, text = null) {
  const loadingEl = $('loading');
  const statusEl = $('status');
  if (loadingEl) loadingEl.classList.toggle('hidden', !on);
  if (statusEl) statusEl.textContent = on ? (text || 'Working...') : 'Ready';
}

export function safeSetText(el, text) {
  if (el) el.textContent = text;
}

// Batched DOM updates for search history
export function pushSearchHistory(q) {
  if (! q) return;
  try {
    const arr = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    const filtered = [q, ...arr.filter(x => x !== q)].slice(0, 20);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(filtered));
    requestAnimationFrame(renderSearchHistory);
  } catch (e) {
    console.error('Failed to save search history:', e);
  }
}

export function renderSearchHistory() {
  const searchHistoryEl = $('searchHistory');
  if (!searchHistoryEl) return;
  
  try {
    const arr = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    if (! arr.length) {
      searchHistoryEl.innerHTML = '';
      return;
    }
    
    // Use DocumentFragment for batch DOM insertion
    const frag = document.createDocumentFragment();
    const header = document.createElement('div');
    header.className = 'text-xs muted';
    header.textContent = 'Recent searches: ';
    frag.appendChild(header);
    
    arr.forEach(q => {
      const b = document.createElement('button');
      b.className = 'small border rounded px-2 py-1 mr-1 mb-1';
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

// Event delegation for search history clicks
document.addEventListener('click', (e) => {
  const btn = e.target.closest('#searchHistory button[data-query]');
  if (btn) {
    const queryInput = $('dbPanelQuery');
    if (queryInput) queryInput.value = btn.dataset.query;
    window.dispatchEvent(new Event('searchDB'));
  }
});

// Optimized node selection with cached elements
const nodeUIElements = ['selIp', 'selHost', 'selOrg', 'selASN', 'selCC', 'selFirst', 'selLast', 'selCount'];

export function resetSelectedUI() {
  nodeUIElements.forEach(id => safeSetText($(id), '—'));
  const selRegistryEl = $('selRegistry');
  if (selRegistryEl) selRegistryEl.innerHTML = '—';
}

export function setSelectedNodeUI(node) {
  node = node || {};
  window.selectedNode = node;
  
  // Batch updates using requestAnimationFrame
  requestAnimationFrame(() => {
    safeSetText($('selIp'), node.ip || '—');
    safeSetText($('selHost'), node.hostname || '—');
    safeSetText($('selOrg'), (node.organization_obj?. name) || node.organization || '—');
    safeSetText($('selASN'), node.asn || node.isp || '—');
    safeSetText($('selCC'), [node.city, node.country].filter(Boolean).join(', ') || '—');
    safeSetText($('selFirst'), node.first_seen || '—');
    safeSetText($('selLast'), node.last_seen || '—');
    safeSetText($('selCount'), node.seen_count ?? '—');

    const reg = node.organization_obj?.extra_data?.company_search || node.extra_data?.company_search;
    const selRegistryEl = $('selRegistry');
    if (selRegistryEl) {
      if (reg) {
        const title = reg.matched_name || reg.name || '';
        const url = reg.company_url || '';
        const num = reg.company_number ? ` (${reg.company_number})` : '';
        const src = reg.source ? `[${reg.source}] ` : '';
        selRegistryEl.innerHTML = `${src}<strong>${escapeHtml(title)}${escapeHtml(num)}</strong> ${url ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" class="text-blue-600">view</a>` : ''}`;
      } else {
        selRegistryEl.innerHTML = '—';
      }
    }
  });
}

export function renderHopList(hops, nodes) {
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
    row.className = 'py-2 px-2 hop-row border-b small clickable';
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');
    row.dataset.ip = ip;
    row.dataset.hasNode = node ? '1' : '0';
    
    const rttDisplay = h.rtt ? `${(h.rtt * 1000).toFixed(1)} ms` : '';
    row.innerHTML = `
      <div class="flex justify-between items-center">
        <div><strong>#${h.hop_number}</strong> <span class="ml-2">${escapeHtml(ip)}</span></div>
        <div class="muted">${rttDisplay}</div>
      </div>
      <div class="text-xs muted mt-1">${escapeHtml(node?.organization || '')}</div>`;
    
    // Store node data for event delegation
    if (node) row._nodeData = node;
    frag.appendChild(row);
  });
  
  hopList.innerHTML = '';
  hopList.appendChild(frag);
}

// Event delegation for hop list
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
    div.className = 'py-2 px-2 border-b small';
    div.innerHTML = `<div><strong>#${h.hop_number}</strong> ${escapeHtml(h.ip || '(no reply)')}</div>`;
    frag.appendChild(div);
  });
  
  hopList.innerHTML = '';
  hopList.appendChild(frag);
}

export function initUI() {
  renderSearchHistory();
  
  $('copyIpBtn')?.addEventListener('click', () => {
    const ip = window.selectedNode?.ip || $('selIp')?.textContent || '';
    if (! ip || ip === '—') return toast('No IP to copy');
    navigator.clipboard?.writeText(ip)
      .then(() => toast('Copied IP'))
      .catch(() => toast('Failed to copy'));
  });
  
  // Initialize card resize handlers with event delegation
  initCardResizeHandlers();
}

function initCardResizeHandlers() {
  document.querySelectorAll('.card:not(.pinned-card)').forEach(card => {
    if (card.querySelector('.resize-handle')) return;
    
    const resizeHandle = document.createElement('div');
    resizeHandle.className = 'resize-handle';
    resizeHandle.setAttribute('aria-label', 'Resize handle');
    card.appendChild(resizeHandle);
  });
  
  // Single event listener for all resize handles
  document.addEventListener('mousedown', (e) => {
    const handle = e.target.closest('.resize-handle');
    if (handle) {
      const parentCard = handle.closest('.card:not(.pinned-card)');
      if (parentCard) {
        e.preventDefault();
        startResizeCard(parentCard, e);
      }
    }
  });
}

// Throttled resize handler
function startResizeCard(card, startEvent) {
  const startRect = card.getBoundingClientRect();
  const startW = startRect.width;
  const startH = startRect.height;
  const startX = startEvent.clientX;
  const startY = startEvent.clientY;

  const onMove = throttle((e) => {
    const newW = Math.max(200, startW + (e.clientX - startX));
    const newH = Math.max(100, startH + (e.clientY - startY));
    card.style.width = `${newW}px`;
    card.style.height = `${newH}px`;
  }, 16);

  function onUp() {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
  }
  
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

// Modal with focus trap for accessibility
let previousActiveElement = null;

export function showModal({ title = '', html = '', text = '', allowPin = true, onPin = null } = {}) {
  const container = $('modalContainer');
  if (!container) return;
  
  previousActiveElement = document.activeElement;
  
  container.innerHTML = '';
  container.classList.remove('modal-hidden');
  container.classList.add('modal-visible');
  container.setAttribute('aria-hidden', 'false');

  const modal = document.createElement('div');
  modal.className = 'modal-card card p-4';
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.setAttribute('aria-labelledby', 'modal-title');
  modal.setAttribute('tabindex', '-1');
  
  modal.innerHTML = `
    <div class="flex items-start justify-between">
      <h3 id="modal-title" class="text-lg font-semibold">${escapeHtml(title)}</h3>
      <div class="flex gap-2">
        ${allowPin ? '<button id="modalPinBtn" class="border rounded px-2 py-1 small">Add as card</button>' : ''}
        <button id="modalCloseBtn" class="border rounded px-2 py-1 small">Close</button>
      </div>
    </div>
    <div class="mt-3 modal-content text-sm muted" style="max-height: 60vh;overflow:auto;"></div>`;

  container.appendChild(modal);
  
  const contentEl = modal.querySelector('.modal-content');
  if (html) contentEl.innerHTML = html;
  else contentEl.textContent = text || '';

  $('modalCloseBtn')?.addEventListener('click', hideModal);
  $('modalPinBtn')?.addEventListener('click', () => {
    onPin?.();
    hideModal();
  });

  // Focus trap and keyboard handling
  modal.addEventListener('keydown', handleModalKeydown);
  modal.focus();
}

function handleModalKeydown(e) {
  if (e.key === 'Escape') {
    hideModal();
  } else if (e.key === 'Tab') {
    const modal = e.currentTarget;
    const focusable = modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last?.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first?.focus();
    }
  }
}

export function hideModal() {
  const container = $('modalContainer');
  if (! container) return;
  
  container.classList.remove('modal-visible');
  container.classList.add('modal-hidden');
  container.setAttribute('aria-hidden', 'true');
  container.innerHTML = '';
  
  previousActiveElement?.focus();
}

// Optimized pinned card management
const pinnedCardCache = new Map();

function genId() {
  return `pin-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

function getCardOrder(card) {
  const v = card.dataset.order ?? card.style.order;
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
  const persist = opts.persist !== false; // default true unless explicitly false
  
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
      wrapper.style.left = `${state.left ?? defaultLeft}px`;
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

// Event delegation for pinned cards
document.addEventListener('click', (e) => {
  const pinnedCard = e.target.closest('.pinned-card');
  if (! pinnedCard) return;
  
  if (e.target.closest('.pin-collapse')) {
    e.stopPropagation();
    pinnedCard.classList.toggle('card-collapsed');
    debouncedSavePinnedCards();
    dispatchLayoutChanged();
  } else if (e.target.closest('.pin-close')) {
    pinnedCardCache.delete(pinnedCard.dataset.pinnedId);
    pinnedCard.remove();
    debouncedSavePinnedCards();
    dispatchLayoutChanged();
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
    if (! card.classList.contains('docked')) {
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
let dragSrcId = null;

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
  dispatchLayoutChanged();
});

document.addEventListener('dragend', () => dragCleanup());

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
  dispatchLayoutChanged();
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
    dispatchLayoutChanged();
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
    dispatchLayoutChanged();
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
    if (! isNaN(z)) maxZ = Math.max(maxZ, z);
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
  return isGrid ? PINNED_KEY_GRID : PINNED_KEY_FREE;
}

export function savePinnedCards(mode = null) {
  const area = $('pinnedArea');
  if (!area) return;
  
  const isGrid = mode ? mode === 'grid' : area.classList.contains('grid-mode');
  const key = isGrid ? PINNED_KEY_GRID : PINNED_KEY_FREE;

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
      width: c.style.width ? parseInt(c.style.width, 10) : null,
      height: c.style.height ? parseInt(c.style.height, 10) : null,
      z: c.style.zIndex ? parseInt(c.style.zIndex, 10) : null,
      order: getCardOrder(c)
    }];
  });
  
  try {
    localStorage.setItem(key, JSON.stringify(out));
    // Backward compatibility: also keep old key for free mode
    if (!isGrid) localStorage.setItem(PINNED_KEY, JSON.stringify(out));
  } catch (e) {
    console.error('Failed to save pinned cards:', e);
  }
}

function loadPinnedState(mode = null) {
  const isGrid = mode === 'grid';
  const key = isGrid ? PINNED_KEY_GRID : PINNED_KEY_FREE;
  try {
    const raw = localStorage.getItem(key) || (!isGrid ? localStorage.getItem(PINNED_KEY) : null);
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    console.error('Failed to read pinned cards:', e);
    return [];
  }
}

export function restorePinnedCards(mode = null) {
  const area = $('pinnedArea');
  if (!area) return;
  
  const isGrid = mode ? mode === 'grid' : area.classList.contains('grid-mode');
  const states = loadPinnedState(isGrid ? 'grid' : 'free');
  if (!states.length) return;
  
  // Clear existing persisted cards only; keep non-persist (live) intact
  area.querySelectorAll('.pinned-card[data-pinned-id]').forEach(c => {
    if (c.dataset.persist === '1') c.remove();
  });
  pinnedCardCache.clear();
  
  states.forEach(state => {
    addPinnedCard(state.title || 'Pinned', state.html || '', { state });
  });
}

function applySavedLayout(targetMode) {
  const area = $('pinnedArea');
  if (!area) return;
  const states = loadPinnedState(targetMode);
  if (!states.length) return;

  const existing = new Map(Array.from(area.querySelectorAll('.pinned-card')).map(c => [c.dataset.pinnedId, c]));
  states.forEach(state => {
    const card = existing.get(state.id);
    if (card) {
      applyPinnedCardState(card, state, area);
      setCardOrder(card, state.order);
      existing.delete(state.id);
    } else {
      addPinnedCard(state.title || 'Pinned', state.html || '', { state });
    }
  });
}

export function closeAllPinnedCards() {
  const area = $('pinnedArea');
  if (!area) return;
  
  area.querySelectorAll('.pinned-card').forEach(c => c.remove());
  pinnedCardCache.clear();
  
  try {
    localStorage.removeItem(PINNED_KEY_FREE);
    localStorage.removeItem(PINNED_KEY_GRID);
    localStorage.removeItem(PINNED_KEY);
  } catch (e) {
    console.error('Failed to clear pinned cards:', e);
  }
}

export function enableFloatButtons() {
  document.querySelectorAll('.card:not([data-floatable])').forEach(card => {
    const header = card.querySelector('.card-header');
    if (!header || card.classList.contains('pinned-card')) return;
    
    // Check if float button already exists
    if (header.querySelector('.card-float')) return;
    
    const btn = document.createElement('button');
    btn.className = 'card-float small border rounded px-2 py-1';
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

// Workspace grid toggle with per-mode persistence
export function setGridMode(enabled) {
  const area = $('pinnedArea');
  if (!area) return;
  
  const wasGrid = area.classList.contains('grid-mode');
  const currentMode = wasGrid ? 'grid' : 'free';
  savePinnedCards(currentMode); // save outgoing mode

  area.classList.toggle('grid-mode', enabled);
  area.querySelectorAll('.pinned-card').forEach((c, i) => {
    if (enabled) {
      c.classList.add('docked');
      c.style.position = 'relative';
      c.style.left = '';
      c.style.top = '';
      // preserve width/height if previously set
      if (!c.style.width) c.style.width = '';
      if (!c.style.height) c.style.height = '';
      if (!c.dataset.order) setCardOrder(c, i);
      c.setAttribute('draggable', 'true');
    } else {
      c.removeAttribute('draggable');
      c.classList.remove('docked');
      c.style.position = 'absolute';
      if (!c.style.left || !c.style.top) {
        const areaWidth = area.getBoundingClientRect().width;
        const left = 10 + (i * 30) % Math.max(120, areaWidth - 320);
        const top = 10 + Math.floor(i / 6) * 30;
        c.style.left = `${left}px`;
        c.style.top = `${top}px`;
      }
    }
  });

  applySavedLayout(enabled ? 'grid' : 'free');
  saveGridMode(enabled);
  dispatchLayoutChanged();
}

function setGridDragEnabled(enabled) {
  const area = $('pinnedArea');
  if (!area) return;
  area.querySelectorAll('.pinned-card').forEach(c => {
    if (enabled) c.setAttribute('draggable', 'true');
    else c.removeAttribute('draggable');
  });
}

function dispatchLayoutChanged() {
  window.dispatchEvent(new CustomEvent('pinned:layout-changed'));
}

export function saveGridMode(enabled) {
  try {
    localStorage.setItem(GRID_MODE_KEY, enabled ? '1' : '0');
  } catch (e) {
    console.error('Failed to save grid mode', e);
  }
}

export function loadGridMode() {
  try {
    return localStorage.getItem(GRID_MODE_KEY) === '1';
  } catch (e) {
    return false;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return str.replace(/[&<>"']/g, m => escapeMap[m]);
}

// Export for use in other modules
export { escapeHtml, debounce, throttle };

