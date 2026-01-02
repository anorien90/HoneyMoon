// Optimized Honeypot UI:  consistent error handling and UI updates. 
// Merged:  combines old and new version features with keyboard navigation and accessibility

import * as honeypotApi from './honeypot.js';
import * as ui from './ui.js';

export async function listHoneypotSessions(limit = 100) {
  ui.setLoading(true, 'Loading honeypot sessions…');
  try {
    const res = await honeypotApi. listSessions(limit);
    ui.setLoading(false);
    const listEl = document.getElementById('honeypotSessionsList');
    if (!listEl) return;
    if (! res.ok) {
      listEl.innerHTML = `<div class="muted small">${res.error || 'Error loading sessions'}</div>`;
      return;
    }
    const sessions = res.data.sessions || [];
    const filterVal = (document.getElementById('honeypotFilter')?.value || '').trim();
    const filtered = filterVal ? sessions.filter(s => (s.src_ip && s.src_ip.includes(filterVal)) || (s.username && s.username.includes(filterVal))) : sessions;
    if (! filtered.length) {
      listEl.innerHTML = '<div class="muted small">No sessions</div>';
      return;
    }
    const frag = document.createDocumentFragment();
    filtered.forEach(s => {
      const div = document.createElement('div');
      div.className = 'hp-row clickable';
      div.setAttribute('role', 'button');
      div.setAttribute('tabindex', '0');
      const nodeCached = s.extra && s.extra.node_cached ?  ` • ${s.extra.node_cached. organization || ''}` : '';
      div.innerHTML = `<div><strong>${s.id}</strong> — ${s.src_ip} ${s.username ? ' • ' + s.username : ''}${nodeCached}</div>
                     <div class="meta">${s.start_ts ?  s.start_ts :  ''} ${s.end_ts ? ' • ' + s.end_ts :  ''} ${s.auth_success ? ' • ' + s.auth_success : ''} • ${s.raw_events_count || 0} events</div>`;
      div.addEventListener('click', () => {
        window.dispatchEvent(new CustomEvent('honeypot:view', { detail: { id: s.id } }));
      });
      div.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') window.dispatchEvent(new CustomEvent('honeypot:view', { detail: { id: s.id } })); });
      frag.appendChild(div);
    });
    listEl.innerHTML = '';
    listEl.appendChild(frag);
  } catch (err) {
    ui.setLoading(false);
    const listEl = document.getElementById('honeypotSessionsList');
    if (listEl) listEl.innerHTML = '<div class="muted small">Loading failed, please retry</div>';
    console.error('listHoneypotSessions error:', err);
  }
}

export async function viewHoneypotSession(id) {
  if (!id) return;
  ui.setLoading(true, 'Loading session…');
  try {
    const res = await honeypotApi.viewSession(id);
    ui.setLoading(false);
    if (!res.ok) {
      ui.showModal({ title: `Session ${id}`, text: res.error || 'Error loading session', allowPin: false });
      return;
    }
    const s = res.data.session;
    
    // Build improved honeypot session HTML with better styling
    let html = `
      <div class="honeypot-session-info">
        <div class="honeypot-session-header">
          <span class="honeypot-session-ip">${escapeHtml(s.src_ip || '—')}</span>
          ${s.username ? `<span class="honeypot-session-badge">👤 ${escapeHtml(s.username)}</span>` : ''}
          ${s.auth_success ? `<span class="honeypot-session-badge">${s.auth_success === 'true' || s.auth_success === true ? '✅ Auth' : '❌ Auth'}</span>` : ''}
        </div>
        <div class="honeypot-session-meta">
          ${s.start_ts ? `<span>🕐 ${escapeHtml(s.start_ts)}</span>` : ''}
          ${s.end_ts ? `<span>→ ${escapeHtml(s.end_ts)}</span>` : ''}
          ${s.raw_events ? `<span>📊 ${s.raw_events.length || 0} events</span>` : ''}
        </div>
      </div>`;

    if (s.commands && s.commands.length) {
      html += `
        <div class="honeypot-section">
          <div class="honeypot-section-title">⌨️ Commands (${s.commands.length})</div>
          <div class="honeypot-section-content">`;
      s.commands.slice(0, 100).forEach(c => {
        html += `
            <div class="honeypot-command-row">
              <span class="honeypot-command-time">${escapeHtml(c.timestamp || '')}</span>
              <span class="honeypot-command-text">${escapeHtml(c.command || '')}</span>
            </div>`;
      });
      if (s.commands.length > 100) {
        html += `<div class="small muted" style="padding: 0.5rem;">... and ${s.commands.length - 100} more</div>`;
      }
      html += `</div></div>`;
    }

    if (s.files && s.files.length) {
      html += `
        <div class="honeypot-section">
          <div class="honeypot-section-title">📁 Files (${s.files.length})</div>
          <div class="honeypot-section-content">`;
      s.files.slice(0, 100).forEach(f => {
        const downloadUrl = f.saved_path ? honeypotApi.artifactDownloadUrl(f.saved_path.split('/').pop()) : '';
        html += `
            <div class="honeypot-file-row">
              <div>
                <div class="honeypot-file-name">${escapeHtml(f.filename || '—')}</div>
                ${f.sha256 ? `<div class="honeypot-file-hash">${escapeHtml(f.sha256)}</div>` : ''}
              </div>
              ${downloadUrl ? `<a href="${escapeHtml(downloadUrl)}" target="_blank" rel="noopener noreferrer" class="popup-action">Download</a>` : ''}
            </div>`;
      });
      html += `</div></div>`;
    }

    if (s.raw_events && s.raw_events.length) {
      html += `
        <div class="honeypot-section">
          <details>
            <summary class="honeypot-section-title" style="cursor: pointer;">📜 Raw Events (${s.raw_events.length})</summary>
            <div class="honeypot-section-content" style="margin-top: 0.5rem;">
              <pre style="white-space: pre-wrap; font-size: 0.75rem; margin: 0;">${escapeHtml(JSON.stringify(s.raw_events.slice(0, 200), null, 2))}</pre>
            </div>
          </details>
        </div>`;
    }

    // Create a simplified HTML for pinning
    const pinnedHtml = `
      <div class="small">
        <div class="font-medium">${escapeHtml(s.src_ip || '—')} ${s.username ? `• ${escapeHtml(s.username)}` : ''}</div>
        <div class="muted">${escapeHtml(s.start_ts || '')} ${s.end_ts ? `→ ${escapeHtml(s.end_ts)}` : ''}</div>
        ${s.commands?.length ? `<div class="mt-1"><strong>Commands:</strong> ${s.commands.length}</div>` : ''}
        ${s.files?.length ? `<div><strong>Files:</strong> ${s.files.length}</div>` : ''}
        ${s.raw_events?.length ? `<div><strong>Events:</strong> ${s.raw_events.length}</div>` : ''}
      </div>`;

    ui.showModal({
      title: `🍯 Honeypot Session ${s.id}`,
      html,
      allowPin: true,
      allowPinToSidebar: true,
      sessionData: s,
      pinnedHtml,
      onPin: () => {
        ui.addPinnedCard(`Honeypot ${s.id}`, pinnedHtml);
      },
      onPinLeft: () => {
        ui.addPanelToZone(`Honeypot ${s.id}`, pinnedHtml, 'left');
      },
      onPinRight: () => {
        ui.addPanelToZone(`Honeypot ${s.id}`, pinnedHtml, 'right');
      }
    });

    if (s.src_ip) {
      window.dispatchEvent(new CustomEvent('honeypot:locate', { detail: { ip: s.src_ip, silent: true }}));
    }
  } catch (err) {
    ui.setLoading(false);
    ui.showModal({ title: `Session ${id}`, text: 'Loading failed, please retry', allowPin: false });
    console.error('viewHoneypotSession error:', err);
  }
}

export async function listHoneypotFlows(limit = 100) {
  ui.setLoading(true, 'Loading flows…');
  try {
    const res = await honeypotApi. listFlows(limit);
    ui.setLoading(false);
    const flowsEl = document.getElementById('honeypotFlowsList');
    if (!flowsEl) return;
    if (!res.ok) {
      flowsEl.innerHTML = `<div class="muted small">${res.error || 'Error loading flows'}</div>`;
      return;
    }
    const flows = res.data.flows || [];
    if (!flows.length) {
      flowsEl.innerHTML = '<div class="muted small">No flows</div>';
      return;
    }
    const frag = document.createDocumentFragment();
    flows.slice(0,100).forEach(f => {
      const d = document.createElement('div');
      d.className = 'hp-row';
      d.innerHTML = `<div><strong>${f.src_ip}: ${f.src_port || ''}</strong> → ${f.dst_ip}:${f.dst_port || ''} <span class="meta">(${f.proto || ''})</span></div>
                   <div class="meta">${f.start_ts || ''} • ${f.packets || 0} pkts • ${f.bytes || 0} bytes</div>`;
      frag.appendChild(d);
    });
    flowsEl.innerHTML = '';
    flowsEl. appendChild(frag);
  } catch (err) {
    ui.setLoading(false);
    const flowsEl = document.getElementById('honeypotFlowsList');
    if (flowsEl) flowsEl.innerHTML = '<div class="muted small">Loading failed, please retry</div>';
    console.error('listHoneypotFlows error:', err);
  }
}

export async function ingestCowrieHandler() {
  const path = (document.getElementById('honeypotIngestPath')?.value || '').trim();
  if (!path) return ui.toast('Provide a path to cowrie JSON file');
  const statusEl = document.getElementById('honeypotIngestStatus');
  if (statusEl) statusEl.innerText = 'Ingesting…';
  try {
    const res = await honeypotApi.ingestCowrie(path);
    if (!res.ok) {
      if (statusEl) statusEl.innerText = res.error || 'Error ingesting';
      return;
    }
    if (statusEl) statusEl.innerText = `Done:  ${JSON.stringify(res.data)}`;
    await listHoneypotSessions(50);
    setTimeout(() => { if (statusEl) statusEl.innerText = ''; }, 4000);
  } catch (err) {
    if (statusEl) statusEl.innerText = 'Ingestion failed';
    console. error('ingestCowrieHandler error:', err);
  }
}

export async function ingestPcapHandler() {
  const path = (document.getElementById('pcapPath')?.value || '').trim();
  if (!path) return ui.toast('Provide a path to pcap file');
  const filter_host = (document.getElementById('pcapFilterHost')?.value || '').trim() || null;
  const statusEl = document.getElementById('honeypotIngestStatus');
  if (statusEl) statusEl.innerText = 'Ingesting PCAP…';
  try {
    const res = await honeypotApi.ingestPcap(path, filter_host);
    if (!res.ok) {
      if (statusEl) statusEl.innerText = res.error || 'Error ingesting PCAP';
      return;
    }
    if (statusEl) statusEl.innerText = `Done: ${JSON.stringify(res.data)}`;
    await listHoneypotFlows(100);
    setTimeout(() => { if (statusEl) statusEl.innerText = ''; }, 4000);
  } catch (err) {
    if (statusEl) statusEl.innerText = 'PCAP ingestion failed';
    console.error('ingestPcapHandler error:', err);
  }
}

function escapeHtml(str) {
  return (str || '').replace(/[&<>"']/g, (m) => {
    return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'":  '&#39;' })[m];
  });
}
