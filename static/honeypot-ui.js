// Optimized Honeypot UI:  consistent error handling and UI updates. 
// Merged:  combines old and new version features with keyboard navigation and accessibility

import * as honeypotApi from './honeypot.js';
import * as ui from './ui.js';
import { escapeHtml } from './util.js';

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
      </div>
      
      <div class="honeypot-session-actions" style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 0.75rem 0; padding: 0.75rem; background: var(--glass); border-radius: var(--radius);">
        <button id="hpAnalyzeBtn" class="small border rounded px-2 py-1" title="Analyze session with AI">🤖 Analyze with AI</button>
        <button id="hpFormalReportBtn" class="small border rounded px-2 py-1" title="Generate formal forensic report">📋 Formal Report</button>
        <button id="hpCountermeasuresBtn" class="small border rounded px-2 py-1" title="Get active countermeasure recommendations">⚔️ Countermeasures</button>
        <button id="hpDetectionRulesBtn" class="small border rounded px-2 py-1" title="Generate detection rules">🛡️ Detection Rules</button>
        <button id="hpFindSimilarBtn" class="small border rounded px-2 py-1" title="Find similar attackers">🔍 Find Similar</button>
        <button id="hpIndexBtn" class="small border rounded px-2 py-1" title="Index for similarity search">📊 Index Session</button>
        ${s.src_ip ? `<button id="hpLocateBtn" class="small border rounded px-2 py-1" title="Locate attacker on map">📍 Locate Attacker</button>` : ''}
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
        const artifactName = f.saved_path ? f.saved_path.split('/').pop() : '';
        html += `
            <div class="honeypot-file-row">
              <div>
                <div class="honeypot-file-name">${escapeHtml(f.filename || '—')}</div>
                ${f.sha256 ? `<div class="honeypot-file-hash">${escapeHtml(f.sha256)}</div>` : ''}
              </div>
              <div style="display: flex; gap: 0.25rem;">
                ${downloadUrl ? `<a href="${escapeHtml(downloadUrl)}" target="_blank" rel="noopener noreferrer" class="popup-action">Download</a>` : ''}
                ${artifactName ? `<button class="popup-action hp-examine-artifact" data-artifact="${escapeHtml(artifactName)}">🔍 Examine</button>` : ''}
              </div>
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
      onPin: () => {
        ui.addPinnedCard(`Honeypot ${s.id}`, pinnedHtml);
      },
      onPinLeft: () => {
        ui.addPanelToZone(`Honeypot ${s.id}`, pinnedHtml, 'left');
      },
      onPinMiddle: () => {
        ui.addPanelToZone(`Honeypot ${s.id}`, pinnedHtml, 'middle');
      },
      onPinRight: () => {
        ui.addPanelToZone(`Honeypot ${s.id}`, pinnedHtml, 'right');
      }
    });

    // Set up action button handlers
    setTimeout(() => {
      document.getElementById('hpAnalyzeBtn')?.addEventListener('click', async () => {
        ui.setLoading(true, 'Analyzing session with AI...');
        try {
          const analysisRes = await honeypotApi.analyzeSession(s.id);
          ui.setLoading(false);
          if (analysisRes.ok && analysisRes.data) {
            showThreatAnalysisResult(analysisRes.data, s);
          } else {
            ui.toast(analysisRes.error || 'Analysis failed');
          }
        } catch (e) {
          ui.setLoading(false);
          ui.toast('Analysis failed');
          console.error('Session analysis error:', e);
        }
      });

      document.getElementById('hpFindSimilarBtn')?.addEventListener('click', async () => {
        ui.setLoading(true, 'Finding similar sessions...');
        try {
          const similarRes = await honeypotApi.findSimilarSessions(s.id);
          ui.setLoading(false);
          if (similarRes.ok && similarRes.data?.results?.length) {
            showSimilarSessions(similarRes.data.results, s);
          } else {
            ui.toast('No similar sessions found');
          }
        } catch (e) {
          ui.setLoading(false);
          ui.toast('Search failed');
        }
      });

      document.getElementById('hpIndexBtn')?.addEventListener('click', async () => {
        ui.setLoading(true, 'Indexing session...');
        try {
          const indexRes = await honeypotApi.indexSession(s.id);
          ui.setLoading(false);
          if (indexRes.ok) {
            ui.toast('Session indexed for similarity search');
          } else {
            ui.toast(indexRes.error || 'Indexing failed');
          }
        } catch (e) {
          ui.setLoading(false);
          ui.toast('Indexing failed');
        }
      });

      document.getElementById('hpLocateBtn')?.addEventListener('click', () => {
        if (s.src_ip) {
          window.dispatchEvent(new CustomEvent('honeypot:locate', { detail: { ip: s.src_ip } }));
          ui.hideModal();
        }
      });

      // NEW: Formal Report button handler
      document.getElementById('hpFormalReportBtn')?.addEventListener('click', async () => {
        ui.setLoading(true, 'Generating formal forensic report...');
        try {
          const reportRes = await honeypotApi.generateFormalReport(s.id);
          ui.setLoading(false);
          if (reportRes.ok && reportRes.data) {
            showFormalReport(reportRes.data, s);
          } else {
            ui.toast(reportRes.error || 'Report generation failed');
          }
        } catch (e) {
          ui.setLoading(false);
          ui.toast('Report generation failed');
          console.error('Formal report error:', e);
        }
      });

      // NEW: Countermeasures button handler
      document.getElementById('hpCountermeasuresBtn')?.addEventListener('click', async () => {
        ui.setLoading(true, 'Getting countermeasure recommendations...');
        try {
          const cmRes = await honeypotApi.getActiveCountermeasures(s.id);
          ui.setLoading(false);
          if (cmRes.ok && cmRes.data) {
            showCountermeasures(cmRes.data, s);
          } else {
            ui.toast(cmRes.error || 'Countermeasure recommendation failed');
          }
        } catch (e) {
          ui.setLoading(false);
          ui.toast('Countermeasure recommendation failed');
          console.error('Countermeasures error:', e);
        }
      });

      // NEW: Detection Rules button handler
      document.getElementById('hpDetectionRulesBtn')?.addEventListener('click', async () => {
        ui.setLoading(true, 'Generating detection rules...');
        try {
          const rulesRes = await honeypotApi.generateDetectionRules(s.id);
          ui.setLoading(false);
          if (rulesRes.ok && rulesRes.data) {
            showDetectionRules(rulesRes.data, s);
          } else {
            ui.toast(rulesRes.error || 'Detection rule generation failed');
          }
        } catch (e) {
          ui.setLoading(false);
          ui.toast('Detection rule generation failed');
          console.error('Detection rules error:', e);
        }
      });

      // Handle examine artifact buttons
      document.querySelectorAll('.hp-examine-artifact').forEach(btn => {
        btn.addEventListener('click', async () => {
          const artifactName = btn.dataset.artifact;
          if (!artifactName) return;
          ui.setLoading(true, 'Examining artifact...');
          try {
            const examRes = await honeypotApi.examineArtifact(artifactName);
            ui.setLoading(false);
            if (examRes.ok && examRes.data) {
              showArtifactExamination(examRes.data, artifactName);
            } else {
              ui.toast(examRes.error || 'Examination failed');
            }
          } catch (e) {
            ui.setLoading(false);
            ui.toast('Examination failed');
          }
        });
      });
    }, 200);

    if (s.src_ip) {
      window.dispatchEvent(new CustomEvent('honeypot:locate', { detail: { ip: s.src_ip, silent: true }}));
    }
  } catch (err) {
    ui.setLoading(false);
    ui.showModal({ title: `Session ${id}`, text: 'Loading failed, please retry', allowPin: false });
    console.error('viewHoneypotSession error:', err);
  }
}

// Show threat analysis result
function showThreatAnalysisResult(data, session) {
  const severityColors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    info: '#2563eb'
  };
  const severityColor = severityColors[data.severity?.toLowerCase()] || '#6b7280';
  
  let html = `<div class="threat-analysis-result">
    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--glass); border-radius: var(--radius); border-left: 4px solid ${severityColor};">
      <div>
        <div class="font-medium">${escapeHtml(data.threat_type || 'Unknown Threat')}</div>
        <div class="text-xs muted">Severity: <span style="color: ${severityColor}; font-weight: 600;">${escapeHtml(data.severity || 'unknown')}</span> • Confidence: ${data.confidence ? Math.round(data.confidence * 100) + '%' : '—'}</div>
      </div>
    </div>`;
  
  if (data.summary) {
    html += `<div class="mt-2"><strong>Summary</strong><div class="text-sm mt-1">${escapeHtml(data.summary)}</div></div>`;
  }
  
  if (data.tactics?.length) {
    html += `<div class="mt-2"><strong>MITRE ATT&CK Tactics</strong><div class="text-xs mt-1" style="display: flex; gap: 0.25rem; flex-wrap: wrap;">`;
    data.tactics.forEach(t => {
      html += `<span style="padding: 0.125rem 0.5rem; background: var(--glass); border-radius: 4px; border: 1px solid var(--border);">${escapeHtml(t)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.techniques?.length) {
    html += `<div class="mt-2"><strong>MITRE ATT&CK Techniques</strong><div class="text-xs mt-1" style="display: flex; gap: 0.25rem; flex-wrap: wrap;">`;
    data.techniques.forEach(t => {
      html += `<span style="padding: 0.125rem 0.5rem; background: var(--glass); border-radius: 4px; border: 1px solid var(--border);">${escapeHtml(t)}</span>`;
    });
    html += `</div></div>`;
  }
  
  if (data.indicators?.length) {
    html += `<div class="mt-2"><strong>Indicators</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.indicators.slice(0, 10).forEach(ind => {
      html += `<li>${escapeHtml(ind)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  if (data.recommendations?.length) {
    html += `<div class="mt-2"><strong>Recommendations</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.recommendations.slice(0, 10).forEach(rec => {
      html += `<li>${escapeHtml(rec)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `🔍 Threat Analysis - Session ${session.id}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Threat ${session.id}`, html),
    onPinLeft: () => ui.addPanelToZone(`Threat ${session.id}`, html, 'left'),
    onPinMiddle: () => ui.addPanelToZone(`Threat ${session.id}`, html, 'middle'),
    onPinRight: () => ui.addPanelToZone(`Threat ${session.id}`, html, 'right')
  });
}

// Show similar sessions
function showSimilarSessions(results, originalSession) {
  let html = `<div class="similar-sessions">
    <div class="text-sm muted mb-2">Sessions similar to ${originalSession.src_ip || `Session ${originalSession.id}`}:</div>`;
  
  results.forEach(r => {
    const session = r.session || r;
    const score = r.score ? ` (${Math.round(r.score * 100)}% similar)` : '';
    html += `<div class="py-2 border-b clickable similar-session-row" data-session-id="${session.id}">
      <div class="font-medium">Session ${session.id} — ${escapeHtml(session.src_ip || '—')}${score}</div>
      <div class="text-xs muted">${escapeHtml(session.start_ts || '')} ${session.username ? `• ${escapeHtml(session.username)}` : ''}</div>
    </div>`;
  });
  
  html += `</div>`;
  
  ui.showModal({
    title: `🔍 Similar Sessions`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard('Similar Sessions', html)
  });
  
  // Set up click handlers for similar sessions
  setTimeout(() => {
    document.querySelectorAll('.similar-session-row').forEach(row => {
      row.addEventListener('click', () => {
        const sessionId = row.dataset.sessionId;
        if (sessionId) {
          ui.hideModal();
          viewHoneypotSession(sessionId);
        }
      });
    });
  }, 200);
}

// Show artifact examination result
function showArtifactExamination(data, artifactName) {
  let html = `<div class="artifact-examination">
    <div class="font-medium">📄 ${escapeHtml(artifactName)}</div>`;
  
  if (data.file_type) {
    html += `<div class="text-xs muted mt-1">Type: ${escapeHtml(data.file_type)}</div>`;
  }
  
  if (data.analysis) {
    html += `<div class="mt-2"><strong>Analysis</strong><div class="text-sm mt-1 whitespace-pre-wrap">${escapeHtml(data.analysis)}</div></div>`;
  }
  
  if (data.indicators?.length) {
    html += `<div class="mt-2"><strong>Indicators of Compromise</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.indicators.forEach(ind => {
      html += `<li>${escapeHtml(ind)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  if (data.recommendations?.length) {
    html += `<div class="mt-2"><strong>Recommendations</strong><ul class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.recommendations.forEach(rec => {
      html += `<li>${escapeHtml(rec)}</li>`;
    });
    html += `</ul></div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `🔍 Artifact Examination`,
    html,
    allowPin: true,
    onPin: () => ui.addPinnedCard(`Artifact ${artifactName}`, html)
  });
}

// Show formal forensic report
function showFormalReport(data, session) {
  let html = `<div class="formal-report" style="max-height: 70vh; overflow-y: auto;">`;
  
  // Header with severity badge
  const severityColors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a',
    info: '#2563eb'
  };
  const severityColor = severityColors[data.severity?.toLowerCase()] || '#6b7280';
  
  html += `
    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--glass); border-radius: var(--radius); border-left: 4px solid ${severityColor};">
      <div>
        <div class="font-medium">📋 Formal Forensic Analysis Report</div>
        <div class="text-xs muted">Session ${session.id} | ${escapeHtml(session.src_ip || '—')} | Generated: ${data.generated_at || 'now'}</div>
        <div class="text-xs mt-1">Severity: <span style="color: ${severityColor}; font-weight: 600;">${escapeHtml(data.severity || 'unknown')}</span> | Confidence: ${data.confidence ? Math.round(data.confidence * 100) + '%' : '—'}</div>
      </div>
    </div>`;
  
  // Executive Summary
  if (data.summary) {
    html += `<div class="mt-3"><strong>📝 Executive Summary</strong><div class="text-sm mt-1" style="white-space: pre-wrap;">${escapeHtml(data.summary)}</div></div>`;
  }
  
  // Report sections
  if (data.report_sections) {
    Object.entries(data.report_sections).forEach(([section, content]) => {
      const sectionTitle = section.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      html += `<div class="mt-3"><strong>${escapeHtml(sectionTitle)}</strong><div class="text-sm mt-1" style="white-space: pre-wrap;">${escapeHtml(content || '')}</div></div>`;
    });
  }
  
  // MITRE ATT&CK Mapping
  if (data.mitre_tactics?.length || data.mitre_techniques?.length) {
    html += `<div class="mt-3"><strong>🎯 MITRE ATT&CK Mapping</strong>`;
    if (data.mitre_tactics?.length) {
      html += `<div class="text-xs mt-1"><strong>Tactics:</strong> <span style="display: inline-flex; gap: 0.25rem; flex-wrap: wrap;">`;
      data.mitre_tactics.forEach(t => {
        html += `<span style="padding: 0.125rem 0.5rem; background: var(--glass); border-radius: 4px; border: 1px solid var(--border);">${escapeHtml(t)}</span>`;
      });
      html += `</span></div>`;
    }
    if (data.mitre_techniques?.length) {
      html += `<div class="text-xs mt-1"><strong>Techniques:</strong> <span style="display: inline-flex; gap: 0.25rem; flex-wrap: wrap;">`;
      data.mitre_techniques.forEach(t => {
        html += `<span style="padding: 0.125rem 0.5rem; background: var(--glass); border-radius: 4px; border: 1px solid var(--border);">${escapeHtml(t)}</span>`;
      });
      html += `</span></div>`;
    }
    html += `</div>`;
  }
  
  // IOCs
  if (data.iocs) {
    html += `<div class="mt-3"><strong>🔍 Indicators of Compromise</strong>`;
    if (data.iocs.network_iocs?.length) {
      html += `<div class="text-xs mt-1"><strong>Network:</strong><ul style="margin-left: 1rem;">`;
      data.iocs.network_iocs.slice(0, 10).forEach(ioc => html += `<li>${escapeHtml(ioc)}</li>`);
      html += `</ul></div>`;
    }
    if (data.iocs.host_iocs?.length) {
      html += `<div class="text-xs mt-1"><strong>Host:</strong><ul style="margin-left: 1rem;">`;
      data.iocs.host_iocs.slice(0, 10).forEach(ioc => html += `<li>${escapeHtml(ioc)}</li>`);
      html += `</ul></div>`;
    }
    if (data.iocs.behavioral_iocs?.length) {
      html += `<div class="text-xs mt-1"><strong>Behavioral:</strong><ul style="margin-left: 1rem;">`;
      data.iocs.behavioral_iocs.slice(0, 10).forEach(ioc => html += `<li>${escapeHtml(ioc)}</li>`);
      html += `</ul></div>`;
    }
    html += `</div>`;
  }
  
  // Recommended Actions
  if (data.recommended_actions?.length) {
    html += `<div class="mt-3"><strong>✅ Recommended Actions</strong><ol class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.recommended_actions.forEach(action => {
      html += `<li>${escapeHtml(action)}</li>`;
    });
    html += `</ol></div>`;
  }
  
  // Threat Actor Profile
  if (data.threat_actor_profile) {
    const profile = data.threat_actor_profile;
    html += `<div class="mt-3"><strong>👤 Threat Actor Profile</strong><div class="text-xs mt-1">`;
    if (profile.skill_level) html += `<div>Skill Level: ${escapeHtml(profile.skill_level)}</div>`;
    if (profile.automation !== undefined) html += `<div>Automation: ${profile.automation ? 'Likely Automated' : 'Manual'}</div>`;
    if (profile.motivation) html += `<div>Motivation: ${escapeHtml(profile.motivation)}</div>`;
    html += `</div></div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `📋 Formal Forensic Report - Session ${session.id}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Report ${session.id}`, html),
    onPinLeft: () => ui.addPanelToZone(`Report ${session.id}`, html, 'left'),
    onPinMiddle: () => ui.addPanelToZone(`Report ${session.id}`, html, 'middle'),
    onPinRight: () => ui.addPanelToZone(`Report ${session.id}`, html, 'right')
  });
}

// Show active countermeasure recommendations
function showCountermeasures(data, session) {
  const priorityColors = {
    immediate: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#16a34a'
  };
  const priorityColor = priorityColors[data.priority?.toLowerCase()] || '#6b7280';
  
  let html = `<div class="countermeasures" style="max-height: 70vh; overflow-y: auto;">`;
  
  // Header
  html += `
    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--glass); border-radius: var(--radius); border-left: 4px solid ${priorityColor};">
      <div>
        <div class="font-medium">⚔️ Active Countermeasure Recommendations</div>
        <div class="text-xs muted">Session ${session.id} | ${session.end_ts ? 'Closed' : '🔴 Active'}</div>
        <div class="text-xs mt-1">Priority: <span style="color: ${priorityColor}; font-weight: 600;">${escapeHtml(data.priority || 'unknown')}</span></div>
      </div>
    </div>`;
  
  // Recommended Capability
  if (data.recommended_capability) {
    const capabilityDescriptions = {
      json_tail: '📊 JSON Tail - Real-time command monitoring via cowrie.json',
      manhole: '🔧 Manhole - Direct Python REPL access to session objects',
      output_plugin: '⚡ Output Plugin - Automated response triggers',
      proxy_mode: '🖥️ Proxy Mode - Pass-through to real backend VM',
      playlog: '🎬 Playlog - Terminal session replay'
    };
    html += `<div class="mt-2"><strong>🎯 Recommended Capability</strong>
      <div class="text-sm mt-1 p-2 border rounded" style="background: var(--glass);">
        ${capabilityDescriptions[data.recommended_capability] || escapeHtml(data.recommended_capability)}
      </div>
    </div>`;
  }
  
  // Response Actions
  if (data.response_actions?.length) {
    html += `<div class="mt-3"><strong>🎭 Recommended Response Actions</strong><div class="text-xs mt-1" style="display: flex; gap: 0.25rem; flex-wrap: wrap;">`;
    data.response_actions.forEach(action => {
      const actionColors = {
        observe: '#6b7280',
        delay: '#ca8a04',
        fake_data: '#8b5cf6',
        tarpit: '#ea580c',
        disconnect: '#dc2626',
        alert: '#dc2626',
        capture: '#2563eb',
        deception: '#8b5cf6'
      };
      const color = actionColors[action] || '#6b7280';
      html += `<span style="padding: 0.25rem 0.75rem; background: ${color}22; border: 1px solid ${color}; border-radius: 4px; color: ${color};">${escapeHtml(action)}</span>`;
    });
    html += `</div></div>`;
  }
  
  // Implementation Steps
  if (data.implementation_steps?.length) {
    html += `<div class="mt-3"><strong>📝 Implementation Steps</strong><ol class="text-xs mt-1" style="margin-left: 1rem;">`;
    data.implementation_steps.forEach(step => {
      html += `<li style="margin-bottom: 0.25rem;">${escapeHtml(step)}</li>`;
    });
    html += `</ol></div>`;
  }
  
  // Manhole Commands (if recommended)
  if (data.manhole_commands?.length) {
    html += `<div class="mt-3"><strong>🔧 Manhole Commands</strong>
      <div class="text-xs mt-1 muted">SSH to Manhole: <code>ssh -p 2500 -l cowrie localhost</code></div>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.75rem; overflow-x: auto;">`;
    data.manhole_commands.forEach(cmd => {
      html += `>>> ${escapeHtml(cmd)}\n`;
    });
    html += `</pre></div>`;
  }
  
  // Monitoring Queries (for JSON tail)
  if (data.monitoring_queries?.length) {
    html += `<div class="mt-3"><strong>📊 Monitoring Queries (jq)</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.75rem; overflow-x: auto;">`;
    data.monitoring_queries.forEach(query => {
      html += `tail -f cowrie.json | jq '${escapeHtml(query)}'\n`;
    });
    html += `</pre></div>`;
  }
  
  // Output Plugin Config
  if (data.output_plugin_config) {
    html += `<div class="mt-3"><strong>⚡ Output Plugin Configuration</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.75rem; overflow-x: auto;">${escapeHtml(JSON.stringify(data.output_plugin_config, null, 2))}</pre>
    </div>`;
  }
  
  // Risk Assessment
  if (data.risk_assessment) {
    html += `<div class="mt-3"><strong>⚠️ Risk Assessment</strong><div class="text-xs mt-1" style="white-space: pre-wrap;">${escapeHtml(data.risk_assessment)}</div></div>`;
  }
  
  // Timing and Expected Outcome
  if (data.timing) {
    html += `<div class="mt-2"><strong>⏱️ Timing:</strong> <span class="text-xs">${escapeHtml(data.timing)}</span></div>`;
  }
  if (data.expected_outcome) {
    html += `<div class="mt-2"><strong>🎯 Expected Outcome:</strong> <span class="text-xs">${escapeHtml(data.expected_outcome)}</span></div>`;
  }
  if (data.rollback_plan) {
    html += `<div class="mt-2"><strong>↩️ Rollback Plan:</strong> <span class="text-xs">${escapeHtml(data.rollback_plan)}</span></div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `⚔️ Active Countermeasures - Session ${session.id}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Countermeasures ${session.id}`, html),
    onPinLeft: () => ui.addPanelToZone(`CM ${session.id}`, html, 'left'),
    onPinMiddle: () => ui.addPanelToZone(`CM ${session.id}`, html, 'middle'),
    onPinRight: () => ui.addPanelToZone(`CM ${session.id}`, html, 'right')
  });
}

// Show detection rules
function showDetectionRules(data, session) {
  let html = `<div class="detection-rules" style="max-height: 70vh; overflow-y: auto;">`;
  
  html += `
    <div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--glass); border-radius: var(--radius);">
      <div class="font-medium">🛡️ Detection Rules</div>
      <div class="text-xs muted">Generated from Session ${session.id} | ${escapeHtml(session.src_ip || '—')}</div>
      ${data.deployment_priority ? `<div class="text-xs mt-1">Priority: <strong>${escapeHtml(data.deployment_priority)}</strong></div>` : ''}
    </div>`;
  
  // Detection Logic
  if (data.detection_logic) {
    html += `<div class="mt-2"><strong>📋 Detection Strategy</strong><div class="text-sm mt-1" style="white-space: pre-wrap;">${escapeHtml(data.detection_logic)}</div></div>`;
  }
  
  // Sigma Rules
  if (data.sigma_rules?.length) {
    html += `<div class="mt-3"><strong>📊 Sigma Rules (SIEM)</strong>`;
    data.sigma_rules.forEach((rule, i) => {
      html += `<details class="mt-1"><summary class="text-xs cursor-pointer">Rule ${i + 1}</summary>
        <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto; margin-top: 0.5rem;">${escapeHtml(rule)}</pre>
      </details>`;
    });
    html += `</div>`;
  }
  
  // Firewall Rules
  if (data.firewall_rules?.length) {
    html += `<div class="mt-3"><strong>🔥 Firewall Rules</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto;">`;
    data.firewall_rules.forEach(rule => {
      html += `${escapeHtml(rule)}\n`;
    });
    html += `</pre></div>`;
  }
  
  // Cowrie Filter
  if (data.cowrie_filter) {
    html += `<div class="mt-3"><strong>🍯 Cowrie Command Filter</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto;">${escapeHtml(JSON.stringify(data.cowrie_filter, null, 2))}</pre>
    </div>`;
  }
  
  // YARA Rules
  if (data.yara_rules?.length) {
    html += `<div class="mt-3"><strong>🔬 YARA Rules</strong>`;
    data.yara_rules.forEach((rule, i) => {
      html += `<details class="mt-1"><summary class="text-xs cursor-pointer">Rule ${i + 1}</summary>
        <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto; margin-top: 0.5rem;">${escapeHtml(rule)}</pre>
      </details>`;
    });
    html += `</div>`;
  }
  
  // Snort Rules
  if (data.snort_rules?.length) {
    html += `<div class="mt-3"><strong>🦈 Snort/Suricata Rules</strong>
      <pre style="background: #1e1e1e; color: #d4d4d4; padding: 0.75rem; border-radius: var(--radius); font-size: 0.7rem; overflow-x: auto;">`;
    data.snort_rules.forEach(rule => {
      html += `${escapeHtml(rule)}\n`;
    });
    html += `</pre></div>`;
  }
  
  // False Positive Notes
  if (data.false_positive_notes) {
    html += `<div class="mt-3"><strong>⚠️ False Positive Guidance</strong><div class="text-xs mt-1" style="white-space: pre-wrap;">${escapeHtml(data.false_positive_notes)}</div></div>`;
  }
  
  html += `</div>`;
  
  ui.showModal({
    title: `🛡️ Detection Rules - Session ${session.id}`,
    html,
    allowPin: true,
    allowPinToSidebar: true,
    onPin: () => ui.addPinnedCard(`Rules ${session.id}`, html),
    onPinLeft: () => ui.addPanelToZone(`Rules ${session.id}`, html, 'left'),
    onPinMiddle: () => ui.addPanelToZone(`Rules ${session.id}`, html, 'middle'),
    onPinRight: () => ui.addPanelToZone(`Rules ${session.id}`, html, 'right')
  });
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
