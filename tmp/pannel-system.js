// New modular panel system for complete layout customization

export class PanelManager {
  constructor() {
    this.panels = new Map();
    this.layouts = this.loadLayouts();
    this.currentLayout = localStorage.getItem('ipExplorer.activeLayout') || 'default';
    this.dockZones = ['left', 'right', 'bottom', 'center', 'float'];
    this.initPanelRegistry();
  }

  // Register all available panels
  initPanelRegistry() {
    this.registerPanel({
      id: 'map',
      title: 'Interactive Map',
      icon: '🗺️',
      category: 'core',
      defaultZone: 'center',
      minWidth: 300,
      minHeight: 240,
      resizable: true,
      collapsible: true,
      closable: false, // core panel
      content: () => document.getElementById('map')?.parentElement
    });

    this.registerPanel({
      id: 'explore-db',
      title: 'Database Explorer',
      icon: '🔍',
      category: 'tools',
      defaultZone: 'left',
      minWidth: 280,
      minHeight: 200,
      resizable: true,
      collapsible: true,
      closable: true,
      content: () => document.getElementById('panel-explore')
    });

    this.registerPanel({
      id: 'honeypot-control',
      title: 'Honeypot Control',
      icon: '🍯',
      category: 'honeypot',
      defaultZone: 'left',
      minWidth: 280,
      minHeight: 180,
      resizable: true,
      collapsible: true,
      closable: true,
      content: () => document.getElementById('panel-honeypot-left')
    });

    this.registerPanel({
      id: 'node-details',
      title: 'Node Details',
      icon: '📊',
      category: 'info',
      defaultZone: 'right',
      minWidth: 260,
      minHeight: 150,
      resizable: true,
      collapsible: true,
      closable: true,
      content: () => document.querySelector('.card:has(#selectedInfo)')
    });

    this.registerPanel({
      id: 'traceroute-hops',
      title: 'Traceroute Hops',
      icon: '🛤️',
      category: 'info',
      defaultZone: 'right',
      minWidth: 260,
      minHeight: 150,
      resizable: true,
      collapsible: true,
      closable: true,
      content: () => document.querySelector('.card:has(#hopList)')
    });

    // Add more panels as needed
    this.registerPanel({
      id: 'timeline',
      title: 'Activity Timeline',
      icon: '📈',
      category: 'analytics',
      defaultZone: 'bottom',
      minWidth: 400,
      minHeight: 120,
      resizable: true,
      collapsible: true,
      closable: true,
      content: () => this.createTimelinePanel()
    });

    this.registerPanel({
      id: 'quick-actions',
      title: 'Quick Actions',
      icon: '⚡',
      category: 'tools',
      defaultZone: 'float',
      minWidth: 200,
      minHeight: 100,
      resizable: true,
      collapsible: true,
      closable: true,
      content: () => this.createQuickActionsPanel()
    });
  }

  registerPanel(config) {
    this.panels.set(config.id, {
      ...config,
      visible: true,
      zone: config.defaultZone,
      position: null,
      size: { width: null, height: null },
      collapsed: false,
      order: this.panels.size
    });
  }

  // Layout management
  saveLayout(name) {
    const layout = {
      name,
      timestamp: new Date().toISOString(),
      panels: Array.from(this.panels.entries()).map(([id, panel]) => ({
        id,
        visible: panel.visible,
        zone: panel.zone,
        position: panel.position,
        size: panel.size,
        collapsed: panel.collapsed,
        order: panel.order
      }))
    };
    
    this.layouts.set(name, layout);
    localStorage.setItem('ipExplorer.layouts', JSON.stringify(Array.from(this.layouts.entries())));
    return layout;
  }

  loadLayout(name) {
    const layout = this.layouts.get(name);
    if (!layout) return false;

    layout.panels.forEach(savedPanel => {
      const panel = this.panels.get(savedPanel.id);
      if (panel) {
        Object.assign(panel, savedPanel);
      }
    });

    this.currentLayout = name;
    localStorage.setItem('ipExplorer.activeLayout', name);
    this.renderLayout();
    return true;
  }

  loadLayouts() {
    try {
      const stored = localStorage.getItem('ipExplorer.layouts');
      return stored ? new Map(JSON.parse(stored)) : this.getDefaultLayouts();
    } catch (e) {
      return this.getDefaultLayouts();
    }
  }

  getDefaultLayouts() {
    const layouts = new Map();
    
    // Analyst layout: focus on data exploration
    layouts.set('analyst', {
      name: 'Analyst',
      description: 'Optimized for threat intelligence and data analysis',
      panels: [
        { id: 'explore-db', visible: true, zone: 'left', order: 0 },
        { id: 'map', visible: true, zone: 'center', order: 0 },
        { id: 'node-details', visible: true, zone: 'right', order: 0 },
        { id: 'traceroute-hops', visible: true, zone: 'right', order: 1 },
        { id: 'timeline', visible: true, zone: 'bottom', order: 0 }
      ]
    });

    // Honeypot monitor: focus on intrusion detection
    layouts.set('honeypot', {
      name: 'Honeypot Monitor',
      description: 'Real-time honeypot monitoring and incident response',
      panels: [
        { id: 'honeypot-control', visible: true, zone: 'left', order: 0 },
        { id: 'map', visible: true, zone: 'center', order: 0 },
        { id: 'node-details', visible: true, zone: 'right', order: 0 },
        { id: 'timeline', visible: true, zone: 'bottom', order: 0 }
      ]
    });

    // Network explorer: focus on topology
    layouts.set('explorer', {
      name: 'Network Explorer',
      description: 'Large map view with minimal side panels',
      panels: [
        { id: 'quick-actions', visible: true, zone: 'float', position: { x: 20, y: 20 }, order: 0 },
        { id: 'map', visible: true, zone: 'center', order: 0 },
        { id: 'traceroute-hops', visible: true, zone: 'right', collapsed: true, order: 0 }
      ]
    });

    return layouts;
  }

  renderLayout() {
    // Group panels by zone
    const zones = {
      left: [],
      right: [],
      bottom: [],
      center: [],
      float: []
    };

    this.panels.forEach(panel => {
      if (panel.visible) {
        zones[panel.zone].push(panel);
      }
    });

    // Sort by order
    Object.values(zones).forEach(zone => {
      zone.sort((a, b) => a.order - b.order);
    });

    // Render each zone
    this.renderZone('left', zones.left);
    this.renderZone('right', zones.right);
    this.renderZone('bottom', zones.bottom);
    this.renderZone('center', zones.center);
    this.renderFloatingPanels(zones.float);
  }

  renderZone(zoneName, panels) {
    // Implementation for rendering panels in specific zones
    const zoneEl = document.getElementById(`zone-${zoneName}`) || this.createZone(zoneName);
    zoneEl.innerHTML = '';
    
    panels.forEach(panel => {
      const panelEl = this.createPanelElement(panel);
      zoneEl.appendChild(panelEl);
    });
  }

  createPanelElement(panel) {
    const wrapper = document.createElement('div');
    wrapper.className = 'custom-panel';
    wrapper.dataset.panelId = panel.id;
    wrapper.setAttribute('role', 'region');
    wrapper.setAttribute('aria-label', panel.title);

    if (panel.size.width) wrapper.style.width = panel.size.width + 'px';
    if (panel.size.height) wrapper.style.height = panel.size.height + 'px';
    if (panel.collapsed) wrapper.classList.add('panel-collapsed');

    const header = document.createElement('div');
    header.className = 'panel-header';
    header.innerHTML = `
      <div class="panel-title">
        <span class="panel-icon">${panel.icon}</span>
        <span>${panel.title}</span>
      </div>
      <div class="panel-controls">
        ${panel.collapsible ? '<button class="panel-btn-collapse" title="Collapse" aria-label="Collapse panel">▾</button>' : ''}
        <button class="panel-btn-move" title="Move panel" aria-label="Move panel to another zone">⇱</button>
        ${panel.closable ? '<button class="panel-btn-close" title="Close" aria-label="Close panel">✕</button>' : ''}
      </div>
    `;

    const body = document.createElement('div');
    body.className = 'panel-body';
    
    const content = panel.content();
    if (content) {
      body.appendChild(content);
    }

    wrapper.appendChild(header);
    wrapper.appendChild(body);

    if (panel.resizable) {
      const resizeHandle = document.createElement('div');
      resizeHandle.className = 'panel-resize-handle';
      wrapper.appendChild(resizeHandle);
      this.attachResizeHandler(wrapper, panel);
    }

    this.attachPanelEvents(wrapper, panel);

    return wrapper;
  }

  attachPanelEvents(el, panel) {
    const header = el.querySelector('.panel-header');
    const collapseBtn = el.querySelector('.panel-btn-collapse');
    const moveBtn = el.querySelector('.panel-btn-move');
    const closeBtn = el.querySelector('.panel-btn-close');

    collapseBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      panel.collapsed = !panel.collapsed;
      el.classList.toggle('panel-collapsed');
      this.saveCurrentLayout();
    });

    moveBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      this.showZonePicker(panel);
    });

    closeBtn?.addEventListener('click', () => {
      panel.visible = false;
      el.remove();
      this.saveCurrentLayout();
      this.updatePanelMenu();
    });

    // Drag to reorder within zone
    if (panel.zone !== 'float') {
      header.addEventListener('mousedown', (e) => {
        if (e.target.closest('.panel-controls')) return;
        this.startPanelDrag(el, panel, e);
      });
    }
  }

  showZonePicker(panel) {
    const picker = document.createElement('div');
    picker.className = 'zone-picker-overlay';
    picker.innerHTML = `
      <div class="zone-picker-dialog">
        <h3>Move "${panel.title}" to:</h3>
        <div class="zone-picker-grid">
          ${this.dockZones.map(zone => `
            <button class="zone-option" data-zone="${zone}">
              <span class="zone-icon">${this.getZoneIcon(zone)}</span>
              <span>${this.getZoneName(zone)}</span>
            </button>
          `).join('')}
        </div>
        <button class="zone-picker-cancel">Cancel</button>
      </div>
    `;

    document.body.appendChild(picker);

    picker.querySelectorAll('.zone-option').forEach(btn => {
      btn.addEventListener('click', () => {
        const newZone = btn.dataset.zone;
        panel.zone = newZone;
        panel.position = newZone === 'float' ? { x: 100, y: 100 } : null;
        this.renderLayout();
        this.saveCurrentLayout();
        picker.remove();
      });
    });

    picker.querySelector('.zone-picker-cancel')?.addEventListener('click', () => {
      picker.remove();
    });
  }

  getZoneIcon(zone) {
    const icons = {
      left: '←',
      right: '→',
      bottom: '↓',
      center: '⊞',
      float: '⊡'
    };
    return icons[zone] || '□';
  }

  getZoneName(zone) {
    const names = {
      left: 'Left Sidebar',
      right: 'Right Sidebar',
      bottom: 'Bottom Panel',
      center: 'Center',
      float: 'Floating'
    };
    return names[zone] || zone;
  }

  saveCurrentLayout() {
    this.saveLayout(this.currentLayout);
  }

  // Create layout management UI
  createLayoutManager() {
    const manager = document.createElement('div');
    manager.className = 'layout-manager';
    manager.innerHTML = `
      <div class="layout-manager-header">
        <h3>Layout Manager</h3>
        <button class="layout-manager-close" aria-label="Close layout manager">✕</button>
      </div>
      <div class="layout-manager-body">
        <div class="layout-presets">
          <h4>Presets</h4>
          <div id="layoutPresetList"></div>
        </div>
        <div class="layout-custom">
          <h4>Your Layouts</h4>
          <div id="layoutCustomList"></div>
          <button id="saveCurrentLayout" class="btn-primary">Save Current Layout</button>
        </div>
        <div class="panel-visibility">
          <h4>Panel Visibility</h4>
          <div id="panelVisibilityList"></div>
        </div>
      </div>
    `;

    this.populateLayoutManager(manager);
    return manager;
  }

  populateLayoutManager(manager) {
    // Populate preset layouts
    const presetList = manager.querySelector('#layoutPresetList');
    ['analyst', 'honeypot', 'explorer'].forEach(preset => {
      const layout = this.layouts.get(preset);
      const btn = document.createElement('button');
      btn.className = 'layout-preset-btn';
      btn.textContent = layout.name;
      btn.title = layout.description;
      btn.addEventListener('click', () => {
        this.loadLayout(preset);
        this.showToast(`Loaded ${layout.name} layout`);
      });
      presetList.appendChild(btn);
    });

    // Panel visibility toggles
    const visibilityList = manager.querySelector('#panelVisibilityList');
    this.panels.forEach(panel => {
      const toggle = document.createElement('label');
      toggle.className = 'panel-visibility-toggle';
      toggle.innerHTML = `
        <input type="checkbox" ${panel.visible ? 'checked' : ''} data-panel-id="${panel.id}">
        <span>${panel.icon} ${panel.title}</span>
      `;
      toggle.querySelector('input').addEventListener('change', (e) => {
        panel.visible = e.target.checked;
        this.renderLayout();
        this.saveCurrentLayout();
      });
      visibilityList.appendChild(toggle);
    });

    // Save current layout
    manager.querySelector('#saveCurrentLayout')?.addEventListener('click', () => {
      const name = prompt('Enter layout name:');
      if (name) {
        this.saveLayout(name);
        this.showToast(`Saved layout: ${name}`);
      }
    });
  }

  createTimelinePanel() {
    const panel = document.createElement('div');
    panel.className = 'timeline-panel';
    panel.innerHTML = `
      <div class="timeline-controls">
        <button class="timeline-play">▶</button>
        <input type="range" class="timeline-slider" min="0" max="100" value="0">
        <span class="timeline-time">00:00</span>
      </div>
      <canvas class="timeline-canvas"></canvas>
    `;
    return panel;
  }

  createQuickActionsPanel() {
    const panel = document.createElement('div');
    panel.className = 'quick-actions-panel';
    panel.innerHTML = `
      <button class="quick-action" data-action="locate" title="Locate IP (L)">
        <span class="quick-action-icon">📍</span>
        <span>Locate</span>
      </button>
      <button class="quick-action" data-action="trace" title="Trace Route (T)">
        <span class="quick-action-icon">🛤️</span>
        <span>Trace</span>
      </button>
      <button class="quick-action" data-action="clear" title="Clear Map (C)">
        <span class="quick-action-icon">🗑️</span>
        <span>Clear</span>
      </button>
      <button class="quick-action" data-action="fit" title="Fit to Markers (M)">
        <span class="quick-action-icon">🎯</span>
        <span>Fit</span>
      </button>
    `;

    panel.querySelectorAll('.quick-action').forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.dataset.action;
        window.dispatchEvent(new CustomEvent('quickAction', { detail: { action } }));
      });
    });

    return panel;
  }

  showToast(message) {
    // Reuse existing toast system
    if (window.toast) {
      window.toast(message);
    }
  }
}

// Initialize the panel system
export function initPanelSystem() {
  const manager = new PanelManager();
  
  // Add layout manager button to toolbar
  const layoutBtn = document.createElement('button');
  layoutBtn.className = 'border rounded px-2 py-1 small';
  layoutBtn.textContent = '⚙️ Layout';
  layoutBtn.title = 'Manage layout';
  layoutBtn.addEventListener('click', () => {
    const managerUI = manager.createLayoutManager();
    document.body.appendChild(managerUI);
  });

  const toolbar = document.querySelector('.toolbar');
  if (toolbar) {
    toolbar.appendChild(layoutBtn);
  }

  // Load saved or default layout
  manager.loadLayout(manager.currentLayout);

  return manager;
}
