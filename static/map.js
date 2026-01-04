// Optimized Map module with marker clustering, lazy loading, and better memory management
// Merged: combines marker pool from old version with cleaner new version structure

import { escapeHtml, summarizeNodeDetails } from './util.js';

let map = null;
let markers = [];
let arcsLayer = null;
let selectCallbacks = [];
let isInitialized = false;

// Marker pool for reuse (from old version)
const markerPool = [];
const MAX_POOL_SIZE = 100;

// Toggleable layers for different marker types
let layerGroups = {
  attackers: null,
  outgoing: null,
  paths: null,
  nodes: null,
  liveConnections: null
};

// Layer visibility state
const layerVisibility = {
  attackers: true,
  outgoing: true,
  paths: true,
  nodes: true,
  liveConnections: true
};

export function initMap() {
  if (isInitialized) return Promise.resolve();
  
  return new Promise((resolve, reject) => {
    const checkLeaflet = () => {
      if (typeof L === 'undefined') {
        requestAnimationFrame(checkLeaflet);
        return;
      }
      
      try {
        const mapContainer = document.getElementById('map');
        if (!mapContainer) {
          reject(new Error('Map container not found'));
          return;
        }
        
        map = L. map('map', {
          center: [20, 0],
          zoom:  2,
          preferCanvas: true, // Better performance for many markers
          zoomControl: true,
          attributionControl: true
        });
        
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          maxZoom: 19,
          attribution: '&copy; OpenStreetMap contributors',
          updateWhenIdle: true,
          updateWhenZooming: false
        }).addTo(map);
        
        // Initialize layer groups
        arcsLayer = L.layerGroup().addTo(map);
        layerGroups.paths = arcsLayer;
        layerGroups.attackers = L.layerGroup().addTo(map);
        layerGroups.outgoing = L.layerGroup().addTo(map);
        layerGroups.nodes = L.layerGroup().addTo(map);
        layerGroups.liveConnections = L.layerGroup().addTo(map);
        
        isInitialized = true;
        
        // Delayed resize for proper initialization
        requestAnimationFrame(() => {
          try { map.invalidateSize(); } catch (e) {}
        });
        
        resolve();
      } catch (err) {
        reject(err);
      }
    };
    
    checkLeaflet();
  });
}

export function onSelect(callback) {
  if (typeof callback === 'function') {
    selectCallbacks.push(callback);
  }
}

function emitSelect(node) {
  selectCallbacks.forEach(cb => {
    try { cb(node); } catch (e) { console.error('Select callback error:', e); }
  });
}

// Toggle layer visibility
export function toggleLayer(layerName, visible = null) {
  if (!map || !layerGroups[layerName]) return false;
  
  // If visible is null, toggle the current state
  const newState = visible !== null ? visible : !layerVisibility[layerName];
  layerVisibility[layerName] = newState;
  
  if (newState) {
    if (!map.hasLayer(layerGroups[layerName])) {
      layerGroups[layerName].addTo(map);
    }
  } else {
    if (map.hasLayer(layerGroups[layerName])) {
      map.removeLayer(layerGroups[layerName]);
    }
  }
  
  return newState;
}

// Get layer visibility state
export function getLayerVisibility() {
  return { ...layerVisibility };
}

// Get available layer names
export function getLayerNames() {
  return Object.keys(layerGroups);
}

export function clearMap() {
  if (!map) return false;
  
  // Return markers to pool for reuse (from old version)
  markers.forEach(m => {
    try {
      map.removeLayer(m);
      if (markerPool.length < MAX_POOL_SIZE) {
        m.off(); // Remove event listeners
        markerPool.push(m);
      }
    } catch (e) {}
  });
  markers = [];
  
  // Clear all layer groups
  Object.values(layerGroups).forEach(layer => {
    if (layer) {
      try { layer.clearLayers(); } catch (e) {}
    }
  });
  
  return true;
}

export function getMarkerCount() {
  return markers.length;
}

// Cached popup template (from old version)
const popupTemplate = (node) => {
  const orgName = node.organization_obj?.name || node.organization || '';
  const location = [node.city, node.country].filter(Boolean).join(', ');
  const summary = summarizeNodeDetails(node);
  const ports = summary.ports ? escapeHtml(summary.ports) : '';
  const os = summary.os ? escapeHtml(summary.os) : '';
  const http = summary.http ? escapeHtml(summary.http) : '';
  const tags = summary.tags ? summary.tags.split(',').map(t => t.trim()).filter(Boolean) : [];
  
  // Check for extra live data
  const extra = node.extra_data || {};
  const liveSessions = extra.live_sessions || 0;
  const liveFlows = extra.live_flows || 0;
  const outgoingConnections = extra.outgoing_connections || 0;
  const threatLevel = extra.threat_level || '';
  
  // Build threat indicator if present
  let threatBadge = '';
  if (threatLevel) {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#ca8a04',
      low: '#16a34a'
    };
    const color = colors[threatLevel.toLowerCase()] || '#6b7280';
    threatBadge = `<span style="padding:2px 8px;background:${color};color:white;border-radius:4px;font-size:11px;font-weight:600;">${threatLevel.toUpperCase()}</span>`;
  }
  
  // Build live stats if present
  let liveStats = '';
  if (liveSessions > 0 || liveFlows > 0 || outgoingConnections > 0) {
    const stats = [];
    if (liveSessions > 0) stats.push(`${liveSessions} sessions`);
    if (liveFlows > 0) stats.push(`${liveFlows} flows`);
    if (outgoingConnections > 0) stats.push(`${outgoingConnections} outgoing`);
    liveStats = `<div class="small muted" style="margin-top:0.25rem;">🔴 Live: ${stats.join(' • ')}</div>`;
  }
  
  return `<div class="map-popup" style="min-width:240px">
    <div class="font-medium">${escapeHtml(node.ip || 'Unknown')}${node.hostname ? ` • ${escapeHtml(node.hostname)}` : ''} ${threatBadge}</div>
    <div class="small muted">${orgName ? escapeHtml(orgName) : ''}${location ? ` • ${escapeHtml(location)}` : ''}</div>
    ${liveStats}
    <div class="map-popup-grid" style="margin-top:0.4rem; display:grid; grid-template-columns:repeat(1,1fr); gap:0.35rem;">
      <div><div class="muted small">Open ports</div><div>${ports || '—'}</div></div>
      <div><div class="muted small">OS / Fingerprint</div><div>${os || '—'}</div></div>
      <div><div class="muted small">HTTP/TLS</div><div>${http || '—'}</div></div>
    </div>
    ${tags.length ? `<div class="map-popup-tags" style="margin-top:0.35rem; display:flex; gap:0.25rem; flex-wrap:wrap;">${tags.map(t => `<span style="padding:2px 6px;border:1px solid var(--border, #e5e7eb);border-radius:6px;font-size:12px;">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    <div class="map-popup-actions" style="margin-top:0.5rem; display:flex; gap:0.4rem; flex-wrap:wrap;">
      <button class="small popup-action" data-action="panel" data-ip="${escapeHtml(node.ip || '')}" title="Open in right panel">◀ Panel</button>
      <button class="small popup-action" data-action="pin-left" data-ip="${escapeHtml(node.ip || '')}" title="Pin to left sidebar">◀ Left</button>
      <button class="small popup-action" data-action="pin-middle" data-ip="${escapeHtml(node.ip || '')}" title="Pin to middle (overlay)">● Middle</button>
      <button class="small popup-action" data-action="pin-right" data-ip="${escapeHtml(node.ip || '')}" title="Pin to right sidebar">▶ Right</button>
      <button class="small popup-action" data-action="pin" data-ip="${escapeHtml(node.ip || '')}" title="Pin to workspace">📌 Pin</button>
      <button class="small popup-action" data-action="analyze" data-ip="${escapeHtml(node.ip || '')}" title="Find similar attackers">🔍 Similar</button>
    </div>
  </div>`;
};

export function formatPopup(node) {
  return node ?  popupTemplate(node) : '';
}

const MARKER_STYLES = {
  first: { stroke: '#0f172a', fill: '#2563eb', radius: 10 },
  last: { stroke: '#0f172a', fill: '#2563eb', radius: 10 },
  middle: { stroke: '#7a2e00', fill: '#ff7b00', radius: 7 },
  outgoing: { stroke: '#0f172a', fill: '#10b981', radius: 8 },  // Green for outgoing connections
  attacker: { stroke: '#7f1d1d', fill: '#dc2626', radius: 10 },  // Red for attackers
  threat_critical: { stroke: '#7f1d1d', fill: '#dc2626', radius: 12 },  // Large red for critical threats
  threat_high: { stroke: '#7c2d12', fill: '#ea580c', radius: 10 },  // Orange for high threats
  threat_medium: { stroke: '#713f12', fill: '#ca8a04', radius: 8 },  // Yellow for medium threats
  threat_low: { stroke: '#14532d', fill: '#16a34a', radius: 7 },  // Green for low threats
  cluster: { stroke: '#581c87', fill: '#9333ea', radius: 9 }  // Purple for cluster members
};

export function addMarkerForNode(node, role = 'middle') {
  if (!map || !node) return null;
  
  const lat = parseFloat(node.latitude);
  const lon = parseFloat(node. longitude);
  if (! isFinite(lat) || !isFinite(lon)) return null;
  
  const style = MARKER_STYLES[role] || MARKER_STYLES.middle;
  
  // Determine target layer group based on role
  let targetLayer = layerGroups.nodes;
  if (role === 'attacker' || role.startsWith('threat_')) {
    targetLayer = layerGroups.attackers;
  } else if (role === 'outgoing') {
    targetLayer = layerGroups.outgoing;
  } else if (role === 'live') {
    targetLayer = layerGroups.liveConnections;
  }
  
  // Try to reuse marker from pool (from old version)
  let m = markerPool.pop();
  if (m) {
    m.setLatLng([lat, lon]);
    m.setStyle({
      radius: style.radius,
      color: style.stroke,
      fillColor: style. fill,
      fillOpacity: 0.95,
      weight: 1
    });
    // Add to appropriate layer
    if (targetLayer) {
      m.addTo(targetLayer);
    } else {
      m.addTo(map);
    }
  } else {
    m = L.circleMarker([lat, lon], {
      radius: style.radius,
      color: style.stroke,
      fillColor: style.fill,
      fillOpacity: 0.95,
      weight: 1
    });
    // Add to appropriate layer
    if (targetLayer) {
      m.addTo(targetLayer);
    } else {
      m.addTo(map);
    }
  }
  
  m.nodeIp = node.ip;
  m._nodeData = node;
  m._markerRole = role;  // Store role for filtering
  
  try {
    m.bindPopup(formatPopup(node), { closeButton: true, autoPan: true });
  } catch (e) {}
  
  m.on('click', () => {
    emitSelect(node);
    try { m.openPopup(); } catch (e) {}
  });
  
  markers.push(m);
  return m;
}

export function drawPath(coords) {
  if (!map || !coords || coords.length < 2) return;
  
  if (! arcsLayer) {
    arcsLayer = L.layerGroup().addTo(map);
  }
  arcsLayer.clearLayers();
  
  // Sort by hop number
  const sortedCoords = [... coords].sort((a, b) => (a. hop || 0) - (b.hop || 0));
  const latlngs = sortedCoords.map(c => [parseFloat(c.lat), parseFloat(c.lon)]);
  
  // Main path line
  const poly = L.polyline(latlngs, {
    color:  '#ff7b00',
    weight:  2,
    dashArray: '6,6',
    opacity: 0.8
  });
  arcsLayer.addLayer(poly);
  
  // Direction indicators at midpoints
  for (let i = 0; i < latlngs.length - 1; i++) {
    const mid = [
      (latlngs[i][0] + latlngs[i + 1][0]) / 2,
      (latlngs[i][1] + latlngs[i + 1][1]) / 2
    ];
    const arrow = L.circleMarker(mid, {
      radius: 2,
      color: '#ff7b00',
      fillOpacity: 1
    });
    arcsLayer.addLayer(arrow);
  }
}

// Debounced invalidateSize
let resizeTimer;
export function invalidateSize() {
  if (! map) return;
  
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    try { map.invalidateSize(); } catch (e) {}
  }, 100);
}

export function fitToMarkers() {
  if (!map || ! markers.length) return;
  
  try { map.invalidateSize(); } catch (e) {}
  
  try {
    const group = L.featureGroup(markers);
    const bounds = group.getBounds();
    
    if (bounds.isValid()) {
      map.fitBounds(bounds. pad(0.4), {
        maxZoom: 12,
        animate: true,
        duration: 0.3
      });
    }
  } catch (e) {
    // Fallback:  center on first marker
    if (markers[0]?.getLatLng) {
      const ll = markers[0].getLatLng();
      map.setView([ll.lat, ll.lng], Math.max(map.getZoom(), 3));
    }
  }
}

export function panToLatLng(lat, lon) {
  if (!map) return;
  
  const parsedLat = parseFloat(lat);
  const parsedLon = parseFloat(lon);
  
  if (isFinite(parsedLat) && isFinite(parsedLon)) {
    map.panTo([parsedLat, parsedLon], { animate: true, duration: 0.3 });
  }
}

// Cleanup function for memory management (from old version)
export function dispose() {
  clearMap();
  markerPool.length = 0;
  selectCallbacks = [];
  
  if (map) {
    map.remove();
    map = null;
  }
  
  isInitialized = false;
}
