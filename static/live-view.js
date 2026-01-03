// Live View module for real-time connection visualization on the map
// Shows incoming and outgoing connections from the last X minutes

import { apiGet } from './api.js';
import * as mapModule from './map.js';
import * as ui from './ui.js';
import { escapeHtml } from './util.js';

// Live view state
let isLiveMode = false;
let showOutgoing = false;
let liveRefreshInterval = null;
let currentMinutes = 15;
let liveMarkers = [];
let liveArcsLayer = null;

// Storage keys for persistence
const STORAGE_KEY = 'honeymoon.live_view.minutes';
const STORAGE_KEY_OUTGOING = 'honeymoon.live_view.outgoing';

// DOM references
const $ = id => document.getElementById(id);

/**
 * Initialize the live view module
 */
export function initLiveView() {
  // Load saved minutes preference
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = parseInt(saved, 10);
      if (parsed >= 1 && parsed <= 1440) {
        currentMinutes = parsed;
      }
    }
  } catch (e) {
    // Ignore localStorage errors
  }

  // Load saved outgoing preference
  try {
    const savedOutgoing = localStorage.getItem(STORAGE_KEY_OUTGOING);
    if (savedOutgoing === '1' || savedOutgoing === 'true') {
      showOutgoing = true;
    }
  } catch (e) {
    // Ignore localStorage errors
  }

  // Set initial value in the input
  const minutesInput = $('liveMinutes');
  if (minutesInput) {
    minutesInput.value = currentMinutes;
  }

  // Set initial value for outgoing toggle
  const outgoingToggle = $('liveOutgoingToggle');
  if (outgoingToggle) {
    outgoingToggle.checked = showOutgoing;
  }

  // Set up event listeners
  setupEventListeners();
}

/**
 * Set up event listeners for live view controls
 */
function setupEventListeners() {
  // Live toggle button
  const liveToggle = $('liveToggleBtn');
  if (liveToggle) {
    liveToggle.addEventListener('click', toggleLiveMode);
  }

  // Minutes input change
  const minutesInput = $('liveMinutes');
  if (minutesInput) {
    minutesInput.addEventListener('change', (e) => {
      const val = parseInt(e.target.value, 10);
      if (val >= 1 && val <= 1440) {
        currentMinutes = val;
        try {
          localStorage.setItem(STORAGE_KEY, String(currentMinutes));
        } catch (e) {
          // Ignore
        }
        if (isLiveMode) {
          // Refresh immediately with new time window
          fetchAndRenderLiveData();
        }
      }
    });
  }

  // Outgoing toggle checkbox
  const outgoingToggle = $('liveOutgoingToggle');
  if (outgoingToggle) {
    outgoingToggle.addEventListener('change', (e) => {
      showOutgoing = e.target.checked;
      try {
        localStorage.setItem(STORAGE_KEY_OUTGOING, showOutgoing ? '1' : '0');
      } catch (e) {
        // Ignore
      }
      if (isLiveMode) {
        // Refresh immediately with new setting
        fetchAndRenderLiveData();
      }
    });
  }

  // Refresh button
  const refreshBtn = $('liveRefreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      if (isLiveMode) {
        fetchAndRenderLiveData();
      }
    });
  }
}

/**
 * Toggle live mode on/off
 */
export function toggleLiveMode() {
  isLiveMode = !isLiveMode;
  
  const liveToggle = $('liveToggleBtn');
  const liveControls = $('liveControls');
  const liveStatus = $('liveStatus');
  
  if (isLiveMode) {
    // Enable live mode
    if (liveToggle) {
      liveToggle.classList.add('active');
      liveToggle.textContent = '🔴 Live';
    }
    if (liveControls) {
      liveControls.classList.remove('hidden');
    }
    if (liveStatus) {
      liveStatus.textContent = 'Fetching...';
    }
    
    // Clear existing map and fetch live data
    mapModule.clearMap();
    fetchAndRenderLiveData();
    
    // Start auto-refresh interval (every 30 seconds)
    liveRefreshInterval = setInterval(fetchAndRenderLiveData, 30000);
    
    ui.toast('Live view enabled');
  } else {
    // Disable live mode
    if (liveToggle) {
      liveToggle.classList.remove('active');
      liveToggle.textContent = '⚪ Live';
    }
    if (liveControls) {
      liveControls.classList.add('hidden');
    }
    if (liveStatus) {
      liveStatus.textContent = '';
    }
    
    // Stop auto-refresh
    if (liveRefreshInterval) {
      clearInterval(liveRefreshInterval);
      liveRefreshInterval = null;
    }
    
    // Clear live markers and arcs
    clearLiveVisualization();
    
    ui.toast('Live view disabled');
  }
}

/**
 * Check if live mode is currently active
 */
export function isLiveModeActive() {
  return isLiveMode;
}

/**
 * Get current time window in minutes
 */
export function getCurrentMinutes() {
  return currentMinutes;
}

/**
 * Fetch live connection data and render on map
 */
async function fetchAndRenderLiveData() {
  const liveStatus = $('liveStatus');
  const liveCount = $('liveCount');
  
  if (liveStatus) {
    liveStatus.textContent = 'Updating...';
  }
  
  try {
    // Fetch incoming connections (honeypot sessions and flows)
    const incomingRes = await apiGet(`/api/v1/live/connections?minutes=${currentMinutes}&limit=100`, {
      timeout: 30000,
      retries: 1
    });
    
    if (!incomingRes.ok) {
      if (liveStatus) {
        liveStatus.textContent = `Error: ${incomingRes.error || 'Failed to fetch'}`;
      }
      return;
    }
    
    const incomingData = incomingRes.data;
    
    // Fetch outgoing connections if toggle is enabled
    let outgoingData = { connections: [] };
    if (showOutgoing) {
      const outgoingRes = await apiGet(`/api/v1/outgoing/live?minutes=${currentMinutes}&limit=100`, {
        timeout: 30000,
        retries: 1
      });
      
      if (outgoingRes.ok) {
        outgoingData = outgoingRes.data;
      } else {
        console.warn('Failed to fetch outgoing connections:', outgoingRes.error);
      }
    }
    
    renderLiveData(incomingData, outgoingData);
    
    // Update status
    const totalConnections = (incomingData.sessions?.length || 0) + 
                             (incomingData.flows?.length || 0) + 
                             (outgoingData.connections?.length || 0);
    if (liveStatus) {
      const now = new Date().toLocaleTimeString();
      liveStatus.textContent = `Updated ${now}`;
    }
    if (liveCount) {
      liveCount.textContent = totalConnections;
    }
    
  } catch (err) {
    console.error('Live view fetch error:', err);
    if (liveStatus) {
      liveStatus.textContent = 'Fetch failed';
    }
  }
}

/**
 * Render live connection data on the map
 */
function renderLiveData(incomingData, outgoingData = { connections: [] }) {
  // Clear previous live visualization
  clearLiveVisualization();
  
  const sessions = incomingData.sessions || [];
  const flows = incomingData.flows || [];
  const honeypotLocation = incomingData.honeypot_location;
  const outgoingConnections = outgoingData.connections || [];
  
  // Track unique source IPs to avoid duplicate markers
  const sourceIPs = new Map();
  
  // Add honeypot location marker if available
  if (honeypotLocation && honeypotLocation.latitude && honeypotLocation.longitude) {
    const hpMarker = mapModule.addMarkerForNode({
      ip: honeypotLocation.ip,
      latitude: honeypotLocation.latitude,
      longitude: honeypotLocation.longitude,
      city: honeypotLocation.city,
      country: honeypotLocation.country,
      organization: 'Honeypot'
    }, 'last');
    if (hpMarker) {
      liveMarkers.push(hpMarker);
    }
  }
  
  // Process honeypot sessions - add markers for attackers
  sessions.forEach(session => {
    const node = session.node;
    if (node && node.latitude && node.longitude) {
      const ip = node.ip;
      if (!sourceIPs.has(ip)) {
        sourceIPs.set(ip, {
          ...node,
          sessionCount: 1,
          type: 'attacker'
        });
      } else {
        sourceIPs.get(ip).sessionCount++;
      }
    }
  });
  
  // Process network flows - add markers for flow endpoints
  flows.forEach(flow => {
    // Source node
    const srcNode = flow.src_node;
    if (srcNode && srcNode.latitude && srcNode.longitude) {
      const ip = srcNode.ip;
      if (!sourceIPs.has(ip)) {
        sourceIPs.set(ip, {
          ...srcNode,
          flowCount: 1,
          type: 'flow_src'
        });
      } else {
        const existing = sourceIPs.get(ip);
        existing.flowCount = (existing.flowCount || 0) + 1;
      }
    }
    
    // Destination node (usually the honeypot)
    const dstNode = flow.dst_node;
    if (dstNode && dstNode.latitude && dstNode.longitude) {
      const ip = dstNode.ip;
      if (!sourceIPs.has(ip)) {
        sourceIPs.set(ip, {
          ...dstNode,
          flowCount: 1,
          type: 'flow_dst'
        });
      }
    }
  });
  
  // Process outgoing connections - add markers for remote endpoints
  outgoingConnections.forEach(conn => {
    const remoteNode = conn.remote_node;
    if (remoteNode && remoteNode.latitude && remoteNode.longitude) {
      const ip = remoteNode.ip;
      if (!sourceIPs.has(ip)) {
        sourceIPs.set(ip, {
          ...remoteNode,
          outgoingCount: 1,
          type: 'outgoing_dest'
        });
      } else {
        const existing = sourceIPs.get(ip);
        existing.outgoingCount = (existing.outgoingCount || 0) + 1;
      }
    }
  });
  
  // Add markers for all unique source IPs
  sourceIPs.forEach((nodeData, ip) => {
    // Determine marker role based on type
    let role = 'middle';
    if (nodeData.type === 'attacker') {
      role = 'first';  // Red marker for attackers
    } else if (nodeData.type === 'outgoing_dest') {
      role = 'outgoing';  // Different marker for outgoing destinations
    }
    
    const marker = mapModule.addMarkerForNode({
      ip: ip,
      latitude: nodeData.latitude,
      longitude: nodeData.longitude,
      city: nodeData.city,
      country: nodeData.country,
      organization: nodeData.organization,
      extra_data: {
        live_sessions: nodeData.sessionCount || 0,
        live_flows: nodeData.flowCount || 0,
        outgoing_connections: nodeData.outgoingCount || 0
      }
    }, role);
    
    if (marker) {
      liveMarkers.push(marker);
    }
  });
  
  // Draw connection arcs from attackers to honeypot and from honeypot to outgoing destinations
  drawLiveArcs(sessions, flows, honeypotLocation, outgoingConnections);
  
  // Fit map to show all markers
  if (liveMarkers.length > 0) {
    mapModule.fitToMarkers();
  }
  
  // Update marker count in UI
  const markerCountEl = $('markerCount');
  if (markerCountEl) {
    markerCountEl.textContent = mapModule.getMarkerCount();
  }
}

/**
 * Draw arcs showing connections from attackers to honeypot and from honeypot to outgoing destinations
 */
function drawLiveArcs(sessions, flows, honeypotLocation, outgoingConnections = []) {
  // Check if Leaflet is available
  if (typeof L === 'undefined') return;
  
  // Collect coordinates for connection lines
  const arcs = [];
  
  // Add arcs for honeypot sessions
  if (honeypotLocation && honeypotLocation.latitude && honeypotLocation.longitude) {
    sessions.forEach(session => {
      const node = session.node;
      if (node && node.latitude && node.longitude) {
        arcs.push({
          from: [parseFloat(node.latitude), parseFloat(node.longitude)],
          to: [parseFloat(honeypotLocation.latitude), parseFloat(honeypotLocation.longitude)],
          type: 'session',
          ip: node.ip
        });
      }
    });
    
    // Add arcs for outgoing connections (from honeypot to remote)
    outgoingConnections.forEach(conn => {
      const remoteNode = conn.remote_node;
      if (remoteNode && remoteNode.latitude && remoteNode.longitude) {
        arcs.push({
          from: [parseFloat(honeypotLocation.latitude), parseFloat(honeypotLocation.longitude)],
          to: [parseFloat(remoteNode.latitude), parseFloat(remoteNode.longitude)],
          type: 'outgoing',
          ip: remoteNode.ip,
          process: conn.process_name,
          port: conn.remote_port
        });
      }
    });
  }
  
  // Add arcs for network flows
  flows.forEach(flow => {
    const srcNode = flow.src_node;
    const dstNode = flow.dst_node;
    
    if (srcNode?.latitude && srcNode?.longitude && dstNode?.latitude && dstNode?.longitude) {
      arcs.push({
        from: [parseFloat(srcNode.latitude), parseFloat(srcNode.longitude)],
        to: [parseFloat(dstNode.latitude), parseFloat(dstNode.longitude)],
        type: 'flow',
        proto: flow.proto
      });
    }
  });
  
  // Draw the arcs using mapModule's drawPath
  // For multiple arcs, draw each one separately by calling drawPath for each
  // The first arc uses drawPath which clears and redraws the arcs layer
  arcs.forEach((arc, index) => {
    const coords = [
      { lat: arc.from[0], lon: arc.from[1], hop: 0 },
      { lat: arc.to[0], lon: arc.to[1], hop: 1 }
    ];
    
    if (index === 0) {
      // First arc - use drawPath which clears the layer
      mapModule.drawPath(coords);
    }
    // Note: For multiple arcs, we would need to extend the map module
    // to support adding additional arcs without clearing the layer.
    // Currently only the first arc is drawn for simplicity.
  });
}

/**
 * Clear live visualization (markers and arcs)
 */
function clearLiveVisualization() {
  // Clear the liveMarkers tracking array
  // Note: The actual markers on the map are cleared by mapModule.clearMap()
  // which is called when toggling live mode off
  liveMarkers = [];
}

/**
 * Get live view statistics
 */
export function getLiveStats() {
  return {
    isActive: isLiveMode,
    minutes: currentMinutes,
    markerCount: liveMarkers.length,
    showOutgoing: showOutgoing
  };
}

/**
 * Check if outgoing connections are enabled
 */
export function isOutgoingEnabled() {
  return showOutgoing;
}
