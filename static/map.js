// Optimized Map module with marker management

let map = null;
let markers = [];
let arcsLayer = null;
let selectCallbacks = [];
let isInitialized = false;

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
          preferCanvas: true,
          zoomControl: true,
          attributionControl: true
        });
        
        L. tileLayer('https://{s}.tile.openstreetmap. org/{z}/{x}/{y}. png', {
          maxZoom: 19,
          attribution: '&copy; OpenStreetMap contributors',
          updateWhenIdle: true,
          updateWhenZooming: false
        }).addTo(map);
        
        arcsLayer = L.layerGroup().addTo(map);
        isInitialized = true;
        
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
  
  markers.forEach(m => {
    try { map.removeLayer(m); } catch (e) {}
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

const MARKER_STYLES = {
  first: { stroke: '#0f172a', fill: '#2563eb', radius: 10 },
  last: { stroke: '#0f172a', fill: '#2563eb', radius:  10 },
  middle:  { stroke: '#7a2e00', fill: '#ff7b00', radius: 7 }
};

function formatPopup(node) {
  if (!node) return '';
  
  const orgName = node.organization_obj?.name || node.organization || '';
  const location = [node.city, node.country]. filter(Boolean).join(', ');
  
  return `
    <div style="min-width: 180px">
      <strong>${node.ip || 'Unknown'}</strong>
      ${node.hostname ?  `<div>Host: ${node.hostname}</div>` : ''}
      ${orgName ? `<div>Org: ${orgName}</div>` : ''}
      ${node.isp ? `<div>ISP: ${node.isp}</div>` : ''}
      ${location ? `<div>Location: ${location}</div>` : ''}
    </div>
  `;
}

export function addMarkerForNode(node, role = 'middle') {
  if (!map || !node) return null;
  
  const lat = parseFloat(node.latitude);
  const lon = parseFloat(node.longitude);
  if (! isFinite(lat) || !isFinite(lon)) return null;
  
  const style = MARKER_STYLES[role] || MARKER_STYLES.middle;
  
  const m = L.circleMarker([lat, lon], {
    radius: style.radius,
    color: style.stroke,
    fillColor: style. fill,
    fillOpacity:  0.95,
    weight: 1
  }).addTo(map);
  
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
  if (!map || ! coords || coords.length < 2) return;
  
  if (! arcsLayer) {
    arcsLayer = L. layerGroup().addTo(map);
  }
  arcsLayer.clearLayers();
  
  const sortedCoords = [... coords].sort((a, b) => (a. hop || 0) - (b.hop || 0));
  const latlngs = sortedCoords.map(c => [parseFloat(c.lat), parseFloat(c.lon)]);
  
  const poly = L.polyline(latlngs, {
    color:  '#ff7b00',
    weight:  2,
    dashArray: '6,6',
    opacity: 0.8
  });
  arcsLayer.addLayer(poly);
  
  // Direction indicators
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

let resizeTimer;
export function invalidateSize() {
  if (! map) return;
  
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    try { map.invalidateSize(); } catch (e) {}
  }, 100);
}

export function fitToMarkers() {
  if (!map || !markers.length) return;
  
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

export function dispose() {
  clearMap();
  selectCallbacks = [];
  
  if (map) {
    map.remove();
    map = null;
  }
  
  isInitialized = false;
}
