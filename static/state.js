// Centralized client-side state and small persistence helpers

const STORAGE_KEYS = {
  lastIp: 'honeymoon.last_ip',
  lastTtl: 'honeymoon.last_ttl',
  deepMode: 'honeymoon.deep_mode',
  activeTab: 'honeymoon.active_tab'
};

function readStorage(key) {
  try {
    return localStorage.getItem(key);
  } catch (e) {
    return null;
  }
}

function writeStorage(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (e) {
    /* ignore */
  }
}

function readInt(key, fallback) {
  const raw = readStorage(key);
  const n = parseInt(raw || '', 10);
  return Number.isFinite(n) ? n : fallback;
}

const state = {
  currentIP: readStorage(STORAGE_KEYS.lastIp) || '',
  maxttl: readInt(STORAGE_KEYS.lastTtl, 30),
  deepMode: readStorage(STORAGE_KEYS.deepMode) === '1',
  activeTab: readStorage(STORAGE_KEYS.activeTab) || 'explore',
  lastSession: null,
  gridMode: false
};

export function getState() {
  return state;
}

export function setCurrentIP(ip) {
  state.currentIP = ip || '';
  writeStorage(STORAGE_KEYS.lastIp, state.currentIP);
}

export function setTracePrefs(maxttl, deep) {
  const ttl = Math.min(128, Math.max(1, parseInt(maxttl || '30', 10) || 30));
  state.maxttl = ttl;
  state.deepMode = !!deep;
  writeStorage(STORAGE_KEYS.lastTtl, String(ttl));
  writeStorage(STORAGE_KEYS.deepMode, state.deepMode ? '1' : '0');
}

export function setLastSession(session) {
  state.lastSession = session || null;
}

export function setActiveTab(tab) {
  state.activeTab = tab || 'explore';
  writeStorage(STORAGE_KEYS.activeTab, state.activeTab);
}

export function setGridMode(on) {
  state.gridMode = !!on;
}

export function applySavedInputs({ ipInput, maxttlInput, deepToggle }) {
  if (ipInput && state.currentIP) {
    ipInput.value = state.currentIP;
  }
  if (maxttlInput) {
    maxttlInput.value = state.maxttl;
  }
  if (deepToggle) {
    deepToggle.checked = !!state.deepMode;
  }
}

export function updateMarkerCount(countOrFn) {
  const el = document.getElementById('markerCount');
  if (!el) return;
  const val = typeof countOrFn === 'function' ? countOrFn() : countOrFn;
  const num = Number.isFinite(val) ? val : 0;
  el.textContent = String(num);
}
