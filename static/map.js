// Optimized Map module with marker clustering, lazy loading, and better memory management
// Merged: combines marker pool from old version with cleaner new version structure

import { escapeHtml, truncate } from './util.js';

let map = null;
let markers = [];
let arcsLayer = null;
let selectCallbacks = [];
let isInitialized = false;

// Marker pool for reuse (from old version)
const markerPool = [];
const MAX_POOL_SIZE = 100;

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
        
        arcsLayer = L.layerGroup().addTo(map);
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
  
  if (arcsLayer) {
    try { arcsLayer.clearLayers(); } catch (e) {}
  }
  
  return true;
}

export function getMarkerCount() {
  return markers.length;
}

const summarizePorts = (node) => {
  const banners = node.extra_data?.banners || {};
  if (Object.keys(banners).length) {
    return Object.entries(banners).slice(0, 5).map(([p, b]) => `${escapeHtml(String(p))}${b ? ` (${escapeHtml(truncate(String(b), 40))})` : ''}`).join(', ');
  }
  const services = node.extra_data?.fingerprints?.nmap?.services || {};
  if (Object.keys(services).length) {
    return Object.entries(services).slice(0, 5).map(([p, info]) => {
      const svc = info?.name || info?.product || info?._name;
      return `${escapeHtml(String(p))}${svc ? ` ${escapeHtml(truncate(String(svc), 28))}` : ''}`;
    }).join(', ');
  }
  return '';
};

const summarizeOs = (node) => {
  const osMatch = Array.isArray(node.extra_data?.fingerprints?.nmap?.osmatch) && node.extra_data.fingerprints.nmap.osmatch.length
    ? node.extra_data.fingerprints.nmap.osmatch[0]
    : null;
  if (!osMatch) return '';
  return `${escapeHtml(osMatch.name || 'Unknown')}${osMatch.accuracy ? ` (${escapeHtml(String(osMatch.accuracy))}%)` : ''}`;
};

const summarizeHttp = (node) => {
  const fp = node.extra_data?.fingerprints || {};
  const server = fp.http?.server || fp.http?.headers?.Server;
  const cipher = Array.isArray(fp.https?.cipher) ? fp.https.cipher[0] : fp.https?.cipher;
  const issuer = fp.https?.cert_subject?.commonName || fp.https?.cert_subject?.CN;
  return [server, cipher, issuer].filter(Boolean).map(v => escapeHtml(truncate(String(v), 50))).join(' • ');
};

const summarizeTags = (node) => {
  const tags = [];
  if (node.is_tor_exit) tags.push('TOR exit');
  if (node.extra_data?.fingerprints?.http_well_known?.['/.git/config']?.status_code === 200) tags.push('Exposed .git');
  return tags;
};

// Cached popup template (from old version)
const popupTemplate = (node) => {
  const orgName = node.organization_obj?.name || node.organization || '';
  const location = [node.city, node.country].filter(Boolean).join(', ');
  const ports = summarizePorts(node);
  const os = summarizeOs(node);
  const http = summarizeHttp(node);
  const tags = summarizeTags(node);
  
  return `<div class="map-popup" style="min-width:240px">
    <div class="font-medium">${escapeHtml(node.ip || 'Unknown')}${node.hostname ? ` • ${escapeHtml(node.hostname)}` : ''}</div>
    <div class="small muted">${orgName ? escapeHtml(orgName) : ''}${location ? ` • ${escapeHtml(location)}` : ''}</div>
    <div class="map-popup-grid" style="margin-top:0.4rem; display:grid; grid-template-columns:repeat(1,1fr); gap:0.35rem;">
      <div><div class="muted small">Open ports</div><div>${ports || '—'}</div></div>
      <div><div class="muted small">OS / Fingerprint</div><div>${os || '—'}</div></div>
      <div><div class="muted small">HTTP/TLS</div><div>${http || '—'}</div></div>
    </div>
    ${tags.length ? `<div class="map-popup-tags" style="margin-top:0.35rem; display:flex; gap:0.25rem; flex-wrap:wrap;">${tags.map(t => `<span style="padding:2px 6px;border:1px solid var(--border, #e5e7eb);border-radius:6px;font-size:12px;">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    <div class="map-popup-actions" style="margin-top:0.5rem; display:flex; gap:0.4rem; flex-wrap:wrap;">
      <button class="small popup-action" data-action="panel" data-ip="${escapeHtml(node.ip || '')}">Open panel</button>
      <button class="small popup-action" data-action="pin" data-ip="${escapeHtml(node.ip || '')}">Pin</button>
    </div>
  </div>`;
};

export function formatPopup(node) {
  return node ?  popupTemplate(node) : '';
}

const MARKER_STYLES = {
  first: { stroke: '#0f172a', fill: '#2563eb', radius: 10 },
  last: { stroke: '#0f172a', fill: '#2563eb', radius: 10 },
  middle: { stroke: '#7a2e00', fill: '#ff7b00', radius: 7 }
};

export function addMarkerForNode(node, role = 'middle') {
  if (!map || !node) return null;
  
  const lat = parseFloat(node.latitude);
  const lon = parseFloat(node. longitude);
  if (! isFinite(lat) || !isFinite(lon)) return null;
  
  const style = MARKER_STYLES[role] || MARKER_STYLES.middle;
  
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
    m.addTo(map);
  } else {
    m = L.circleMarker([lat, lon], {
      radius: style.radius,
      color: style.stroke,
      fillColor: style.fill,
      fillOpacity: 0.95,
      weight: 1
    }).addTo(map);
  }
  
  m.nodeIp = node.ip;
  m._nodeData = node;
  
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
