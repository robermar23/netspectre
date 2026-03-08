import { api } from '../api.js';
import { state } from '../state.js';

let _openDetailsPanel = null;
export function setOpenDetailsPanelRef(fn) { _openDetailsPanel = fn; }

function escapeHtml(unsafe) {
  if (unsafe == null) return '';
  return String(unsafe)
       .replace(/&/g, "&amp;")
       .replace(/</g, "&lt;")
       .replace(/>/g, "&gt;")
       .replace(/"/g, "&quot;")
       .replace(/'/g, "&#039;");
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// Panel open/close helpers
function openPanelHelper(panelEl, sidebarResizerEl) {
  panelEl.style.display = 'flex';
  setTimeout(() => panelEl.classList.add('open'), 10);
  if (sidebarResizerEl) sidebarResizerEl.style.display = 'block';
}

function closePanelHelper(panelEl, sidebarResizerEl) {
  panelEl.classList.remove('open');
  setTimeout(() => {
    panelEl.style.display = 'none';
    if (sidebarResizerEl) sidebarResizerEl.style.display = 'none';
  }, 300);
}

// --- Element references ---
const hardeningPanel         = document.getElementById('hardening-panel');
const hardeningResizer       = document.getElementById('hardening-resizer');
const btnHardeningOpen       = document.getElementById('btn-hardening-open');
const btnCloseHardening      = document.getElementById('btn-close-hardening-panel');
const btnHardeningStart      = document.getElementById('btn-hardening-start');
const btnHardeningStop       = document.getElementById('btn-hardening-stop');
const btnSetBaseline         = document.getElementById('btn-hardening-set-baseline');
const btnClearAlerts         = document.getElementById('btn-hardening-clear-alerts');
const btnHardeningExport     = document.getElementById('btn-hardening-export');
const hardeningSubnetInput   = document.getElementById('hardening-subnet');
const hardeningIntervalSel   = document.getElementById('hardening-interval');
const hardeningCustomGroup   = document.getElementById('hardening-custom-interval-group');
const hardeningCustomMinutes = document.getElementById('hardening-custom-minutes');
const hardeningDeepScan      = document.getElementById('hardening-deep-scan');
const hardeningStatusDot     = document.getElementById('hardening-status-dot');
const hardeningLastScanText  = document.getElementById('hardening-last-scan-text');
const hardeningNextScanText  = document.getElementById('hardening-next-scan-text');
const hardeningHostCount     = document.getElementById('hardening-host-count');
const hardeningErrorBanner   = document.getElementById('hardening-error-banner');
const hardeningAlertsList    = document.getElementById('hardening-alerts-list');
const hardeningNoAlerts      = document.getElementById('hardening-no-alerts');
const hardeningAlertCount    = document.getElementById('hardening-alert-count');
const hardeningAlertBadge    = document.getElementById('hardening-alert-badge');
const hardeningBaselineSummary = document.getElementById('hardening-baseline-summary');
const hardeningFooterText    = document.getElementById('hardening-footer-text');

// --- Internal state ---
let hardeningMonitorActive = false;
let hardeningNextRunTs     = null;
let hardeningCountdownId   = null;
let hardeningEvents        = [];

// --- Cross-module refs ---
let _debouncedRenderAllHosts = null;
let _updateSecurityBadgeDOM = null;
let _updateMonitorDotDOM = null;

// --- Helpers ---
function openHardeningPanel(subnet) {
  if (subnet && hardeningSubnetInput) hardeningSubnetInput.value = subnet;
  if (hardeningPanel) openPanelHelper(hardeningPanel, hardeningResizer);
  // Refresh baseline summary whenever panel is opened
  refreshBaselineSummary();
}

function closeHardeningPanel() {
  if (hardeningPanel) closePanelHelper(hardeningPanel, hardeningResizer);
}

function showHardeningError(msg) {
  if (!hardeningErrorBanner) return;
  hardeningErrorBanner.textContent = msg;
  hardeningErrorBanner.style.display = 'block';
}

function clearHardeningError() {
  if (hardeningErrorBanner) hardeningErrorBanner.style.display = 'none';
}

function setHardeningRunning(active) {
  hardeningMonitorActive = active;
  if (btnHardeningStart) btnHardeningStart.disabled = active;
  if (btnHardeningStop)  btnHardeningStop.disabled  = !active;
  if (btnHardeningOpen) {
    btnHardeningOpen.classList.toggle('hardening-active', active);
  }
  setStatusDot(active ? 'active' : 'idle');
  if (hardeningFooterText) {
    hardeningFooterText.textContent = active ? 'Monitoring active…' : 'Idle';
  }
  if (!active) {
    stopHardeningCountdown();
    if (hardeningNextScanText) hardeningNextScanText.textContent = '';
  }
}

function setStatusDot(dotState) {
  if (!hardeningStatusDot) return;
  hardeningStatusDot.className = 'hardening-status-dot';
  if (dotState === 'scanning') {
    hardeningStatusDot.classList.add('hardening-dot-scanning');
    hardeningStatusDot.title = 'Scanning…';
  } else if (dotState === 'active') {
    hardeningStatusDot.classList.add('hardening-dot-active');
    hardeningStatusDot.title = 'Monitoring active';
  } else if (dotState === 'error') {
    hardeningStatusDot.classList.add('hardening-dot-error');
    hardeningStatusDot.title = 'Error';
  } else {
    hardeningStatusDot.classList.add('hardening-dot-idle');
    hardeningStatusDot.title = 'Idle';
  }
}

function startHardeningCountdown(nextRunTs) {
  hardeningNextRunTs = nextRunTs;
  stopHardeningCountdown();
  hardeningCountdownId = setInterval(() => {
    if (!hardeningNextScanText || !hardeningNextRunTs) return;
    const remaining = Math.max(0, hardeningNextRunTs - Date.now());
    if (remaining === 0) {
      hardeningNextScanText.textContent = 'Scanning now…';
      return;
    }
    const mins = Math.floor(remaining / 60000);
    const secs = Math.floor((remaining % 60000) / 1000);
    hardeningNextScanText.textContent = `Next scan in ${mins}m ${secs}s`;
  }, 1000);
}

function stopHardeningCountdown() {
  if (hardeningCountdownId) {
    clearInterval(hardeningCountdownId);
    hardeningCountdownId = null;
  }
}

function updateAlertBadge() {
  const count = hardeningEvents.length;
  if (hardeningAlertBadge) {
    hardeningAlertBadge.textContent = count;
    hardeningAlertBadge.style.display = count > 0 ? 'inline-block' : 'none';
  }
  if (hardeningAlertCount) {
    hardeningAlertCount.textContent = count;
    hardeningAlertCount.style.display = count > 0 ? 'inline-block' : 'none';
  }
}

function getIntervalMs() {
  const val = hardeningIntervalSel?.value;
  if (val === 'custom') {
    const mins = parseInt(hardeningCustomMinutes?.value, 10) || 15;
    return Math.max(1, mins) * 60 * 1000;
  }
  return parseInt(val, 10) || 15 * 60 * 1000;
}

/** Build an alert card DOM element for a delta object */
function buildAlertCard(delta, alertId) {
  const card = document.createElement('div');
  const sev = delta.severity || 'info';
  card.className = `hardening-alert-card alert-${sev}`;

  const icon = sev === 'critical' ? '🔴' : sev === 'warning' ? '🟡' : '🔵';
  const sevLabelSpan = document.createElement('span');
  sevLabelSpan.className = `severity-pill severity-${sev}`;
  sevLabelSpan.textContent = sev.toUpperCase();

  const titleDiv = document.createElement('div');
  titleDiv.className = 'hardening-alert-title';
  titleDiv.innerHTML = `${icon} `;
  titleDiv.appendChild(sevLabelSpan);
  titleDiv.insertAdjacentHTML('beforeend', `
    <span style="flex:1;"></span>
    <span style="color:var(--text-muted); font-size:10px; font-weight:400;">${fmtTime(delta.timestamp)}</span>
  `);

  const detailDiv = document.createElement('div');
  detailDiv.className = 'hardening-alert-detail';

  // Summarise what changed
  const lines = [];
  if (delta.newHosts?.length) {
    lines.push(`<b>${delta.newHosts.length}</b> new host${delta.newHosts.length > 1 ? 's' : ''}: ${delta.newHosts.map(h => escapeHtml(h.ip)).join(', ')}`);
  }
  if (delta.removedHosts?.length) {
    lines.push(`<b>${delta.removedHosts.length}</b> host${delta.removedHosts.length > 1 ? 's' : ''} disappeared: ${delta.removedHosts.map(h => escapeHtml(h.ip)).join(', ')}`);
  }
  if (delta.changedHosts?.length) {
    for (const ch of delta.changedHosts) {
      const parts = [];
      if (ch.newPorts?.length)    parts.push(`+ports ${ch.newPorts.join(', ')}`);
      if (ch.closedPorts?.length) parts.push(`-ports ${ch.closedPorts.join(', ')}`);
      if (ch.hostnameChanged)     parts.push(`hostname: ${escapeHtml(ch.prevHostname)} → ${escapeHtml(ch.currHostname)}`);
      if (ch.macChanged)          parts.push(`MAC changed`);
      if (parts.length) lines.push(`<b>${escapeHtml(ch.ip)}</b>: ${parts.join('; ')}`);
    }
  }

  detailDiv.innerHTML = lines.map(l => `<div>${l}</div>`).join('') || 'Network state change detected.';

  const actionDiv = document.createElement('div');
  actionDiv.className = 'hardening-alert-actions';

  if (delta.newHosts?.length) {
    const btnInvestigate = document.createElement('button');
    btnInvestigate.className = 'btn secondary btn-investigate';
    btnInvestigate.dataset.ip = delta.newHosts[0].ip;
    btnInvestigate.textContent = '🔍 Investigate';
    actionDiv.appendChild(btnInvestigate);

    const btnAddScope = document.createElement('button');
    btnAddScope.className = 'btn secondary btn-add-scope';
    btnAddScope.textContent = '➕ Add to Scope';
    actionDiv.appendChild(btnAddScope);
  }

  const btnPromote = document.createElement('button');
  btnPromote.className = 'btn secondary btn-promote-baseline';
  btnPromote.textContent = '📌 Promote to Baseline';
  actionDiv.appendChild(btnPromote);

  const btnDismiss = document.createElement('button');
  btnDismiss.className = 'btn secondary btn-acknowledge';
  btnDismiss.textContent = '✓ Dismiss';
  actionDiv.appendChild(btnDismiss);

  card.appendChild(titleDiv);
  card.appendChild(detailDiv);
  card.appendChild(actionDiv);

  // Wire action buttons
  btnDismiss.addEventListener('click', () => {
    card.style.opacity = '0';
    card.style.transition = 'opacity 0.3s';
    setTimeout(() => card.remove(), 300);
    const eventIdx = hardeningEvents.findIndex(e => e.alertId === alertId);
    if (eventIdx !== -1) hardeningEvents.splice(eventIdx, 1);
    updateAlertBadge();
    if (hardeningAlertsList && hardeningAlertsList.querySelectorAll('.hardening-alert-card').length === 0) {
      if (hardeningNoAlerts) hardeningNoAlerts.style.display = 'block';
    }
  });

  actionDiv.querySelector('.btn-investigate')?.addEventListener('click', (e) => {
    const ip = e.currentTarget.dataset.ip;
    if (ip && typeof _openDetailsPanel === 'function') {
      const host = state.hosts.find(h => h.ip === ip) || {
        ip, mac: '', hostname: '', vendor: '', os: '',
        ports: [], source: 'monitor', monitorStatus: 'online',
      };
      _openDetailsPanel(host);
    }
  });

  actionDiv.querySelector('.btn-add-scope')?.addEventListener('click', (btn => () => {
    const newHosts = delta.newHosts || [];
    let added = 0;
    for (const h of newHosts) {
      if (!h?.ip) continue;
      const alreadyKnown = state.hosts.some(x => x.ip === h.ip);
      if (!alreadyKnown) {
        state.hosts.push({
          ip: h.ip,
          mac: h.mac || '',
          hostname: h.hostname || '',
          vendor: '',
          os: '',
          ports: h.ports || [],
          source: 'monitor',
          routing: [],
          processes: [],
          monitorStatus: 'online',
          monitorLastSeen: h.lastSeen || Date.now(),
        });
        added++;
      }
    }
    if (added > 0) {
      if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();
      btn.textContent = `✓ Added ${added}`;
      btn.disabled = true;
    } else {
      btn.textContent = '✓ Already in scope';
      btn.disabled = true;
    }
  })(actionDiv.querySelector('.btn-add-scope')));

  btnPromote.addEventListener('click', async () => {
    const subnet = hardeningSubnetInput?.value.trim();
    if (!subnet) return;
    const event = hardeningEvents.find(e => e.alertId === alertId);
    const report = event?.report;
    if (report?.currentHosts) {
      await api.hardeningMonitor.setBaseline(subnet, report.currentHosts);
      refreshBaselineSummary();
      btnPromote.textContent = '✓ Promoted';
      btnPromote.disabled = true;
    }
  });

  return card;
}

function appendAlert(delta, report) {
  const alertId = (delta && delta.timestamp) || (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`);

  hardeningEvents.push({ delta, report: report || null, alertId });
  updateAlertBadge();

  // Hide the "no alerts" placeholder
  if (hardeningNoAlerts) hardeningNoAlerts.style.display = 'none';

  if (hardeningAlertsList) {
    const card = buildAlertCard(delta, alertId);
    hardeningAlertsList.prepend(card); // newest at top
  }
}

async function refreshBaselineSummary() {
  const subnet = hardeningSubnetInput?.value.trim();
  if (!subnet || !hardeningBaselineSummary) return;

  try {
    const result = await api.hardeningMonitor.getBaseline(subnet);
    if (result?.hosts?.length > 0) {
      const setAt = result.setAt ? new Date(result.setAt).toLocaleString() : '—';
      hardeningBaselineSummary.innerHTML = '';

      const containerDiv = document.createElement('div');
      containerDiv.style.cssText = 'display:flex; flex-direction:column; gap:4px;';

      const subnetDiv = document.createElement('div');
      subnetDiv.style.color = 'var(--text-main)';
      subnetDiv.innerHTML = `Subnet: <b>${escapeHtml(subnet)}</b>`;

      const countDiv = document.createElement('div');
      countDiv.innerHTML = `<b>${result.hosts.length}</b> hosts · Set: ${escapeHtml(setAt)}`;

      const listDiv = document.createElement('div');
      listDiv.style.cssText = 'font-size:10px; color:var(--text-muted);';
      listDiv.textContent = result.hosts.slice(0, 5).map(h => h.ip).join(', ') + (result.hosts.length > 5 ? ` +${result.hosts.length - 5} more` : '');

      containerDiv.appendChild(subnetDiv);
      containerDiv.appendChild(countDiv);
      containerDiv.appendChild(listDiv);

      hardeningBaselineSummary.appendChild(containerDiv);
    } else {
      hardeningBaselineSummary.textContent = 'No baseline set. Click "Set Baseline" after a scan to establish the reference state.';
    }
  } catch {
    // Baseline retrieval failed silently
  }
}

export function init({ debouncedRenderAllHosts, updateSecurityBadgeDOM, updateMonitorDotDOM } = {}) {
  _debouncedRenderAllHosts = debouncedRenderAllHosts || null;
  _updateSecurityBadgeDOM = updateSecurityBadgeDOM || null;
  _updateMonitorDotDOM = updateMonitorDotDOM || null;

  // Resizer
  let activeResize = null;
  document.addEventListener('mousemove', (e) => {
    if (!activeResize) return;
    const { panelEl, startX, startWidth } = activeResize;
    const newWidth = startWidth - (e.clientX - startX);
    if (newWidth > 300 && newWidth < Math.min(800, window.innerWidth - 100)) {
      panelEl.style.width = `${newWidth}px`;
    }
  });
  document.addEventListener('mouseup', () => {
    if (!activeResize) return;
    activeResize.resizerEl.classList.remove('is-resizing');
    document.body.style.cursor = '';
    activeResize = null;
  });
  if (hardeningResizer && hardeningPanel) {
    hardeningResizer.addEventListener('mousedown', (e) => {
      const startWidth = parseInt(document.defaultView.getComputedStyle(hardeningPanel).width, 10);
      activeResize = { resizerEl: hardeningResizer, panelEl: hardeningPanel, startX: e.clientX, startWidth };
      hardeningResizer.classList.add('is-resizing');
      document.body.style.cursor = 'col-resize';
      e.preventDefault();
    });
  }

  // --- Button event handlers ---
  btnHardeningOpen?.addEventListener('click', () => {
    if (hardeningPanel?.style.display !== 'none') {
      closeHardeningPanel();
    } else {
      openHardeningPanel();
    }
  });

  btnCloseHardening?.addEventListener('click', closeHardeningPanel);

  // Interval selector — show/hide custom input
  hardeningIntervalSel?.addEventListener('change', () => {
    if (hardeningCustomGroup) {
      hardeningCustomGroup.style.display = hardeningIntervalSel.value === 'custom' ? 'block' : 'none';
    }
  });

  btnHardeningStart?.addEventListener('click', async () => {
    const subnet = hardeningSubnetInput?.value.trim();
    if (!subnet) {
      showHardeningError('Please enter a target subnet in CIDR notation (e.g. 192.168.1.0/24).');
      return;
    }
    clearHardeningError();
    const intervalMs = getIntervalMs();
    const deepScan   = hardeningDeepScan?.checked !== false;
    setHardeningRunning(true);
    setStatusDot('scanning');
    if (hardeningFooterText) hardeningFooterText.textContent = 'Starting first scan…';
    try {
      await api.hardeningMonitor.start(subnet, { intervalMs, deepScan });
    } catch (err) {
      showHardeningError(`Failed to start: ${err.message}`);
      setHardeningRunning(false);
    }
  });

  btnHardeningStop?.addEventListener('click', async () => {
    const subnet = hardeningSubnetInput?.value.trim();
    if (!subnet) return;
    try {
      await api.hardeningMonitor.stop(subnet);
    } catch { /* ignore */ }
    setHardeningRunning(false);
    stopHardeningCountdown();
    if (hardeningNextScanText) hardeningNextScanText.textContent = '';
    if (hardeningFooterText) hardeningFooterText.textContent = 'Stopped';
  });

  btnSetBaseline?.addEventListener('click', async () => {
    const subnet = hardeningSubnetInput?.value.trim();
    if (!subnet) {
      showHardeningError('Enter a subnet first.');
      return;
    }
    // Use the hosts from the most recent report if available, otherwise current state.hosts
    const lastEvent = hardeningEvents[hardeningEvents.length - 1];
    const hosts = lastEvent?.report?.currentHosts || state.hosts?.map(h => ({
      ip: h.ip,
      mac: h.mac || '',
      hostname: h.hostname || '',
      ports: h.ports?.map(p => p.port || p) || [],
      firstSeen: Date.now(),
      lastSeen: Date.now(),
    })) || [];

    if (hosts.length === 0) {
      showHardeningError('No hosts to baseline. Run a scan first or add hosts to the scope.');
      return;
    }
    try {
      await api.hardeningMonitor.setBaseline(subnet, hosts);
      clearHardeningError();
      refreshBaselineSummary();
      if (btnSetBaseline) {
        const orig = btnSetBaseline.textContent;
        btnSetBaseline.textContent = '✓ Baseline Saved';
        setTimeout(() => { if (btnSetBaseline) btnSetBaseline.textContent = orig; }, 2000);
      }
    } catch (err) {
      showHardeningError(`Failed to set baseline: ${err.message}`);
    }
  });

  btnClearAlerts?.addEventListener('click', () => {
    hardeningEvents = [];
    updateAlertBadge();
    if (hardeningAlertsList) hardeningAlertsList.innerHTML = '';
    if (hardeningNoAlerts) {
      hardeningNoAlerts.style.display = 'block';
      hardeningAlertsList?.appendChild(hardeningNoAlerts);
    }
    if (btnHardeningExport) btnHardeningExport.disabled = true;
  });

  btnHardeningExport?.addEventListener('click', () => {
    const exportData = hardeningEvents.map(e => e.report).filter(r => r);
    if (exportData.length === 0) return;
    const data = JSON.stringify(exportData, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hardening_report_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // --- IPC event listeners ---

  // Merge monitor-discovered hosts into the core state.hosts[]
  window.electronAPI.hardeningMonitor?.onHostUpdate((hostData) => {
    const existingIdx = state.hosts.findIndex(h => h.ip === hostData.ip);

    if (existingIdx >= 0) {
      const existing = state.hosts[existingIdx];
      state.hosts[existingIdx] = {
        ...existing,
        // Promote port data when the monitor found open ports and we have none (or more)
        ports: (hostData.ports?.length > 0 && hostData.ports.length >= (existing.ports?.length || 0))
          ? hostData.ports
          : (existing.ports || []),
        // Enrich hostname/mac only if we don't already have richer data
        hostname: (hostData.hostname && !existing.hostname) ? hostData.hostname : existing.hostname,
        mac:      (hostData.mac      && !existing.mac)      ? hostData.mac      : existing.mac,
        // Always overwrite monitor-specific fields
        monitorStatus:   hostData.monitorStatus,
        monitorLastSeen: hostData.monitorLastSeen,
        // Accumulate alerts; avoid duplicates (same delta timestamp)
        monitorAlerts: hostData.monitorAlerts
          ? [...(existing.monitorAlerts || []).filter(a => a.timestamp !== hostData.monitorAlerts[0]?.timestamp), ...hostData.monitorAlerts]
          : (existing.monitorAlerts || []),
      };
      // Refresh the card in-place (update badge + monitor dot)
      const card = document.getElementById(`host-${hostData.ip.replace(/\./g, '-')}`);
      if (card) {
        const badgeContainer = card.querySelector('.security-badge-container');
        if (badgeContainer && _updateSecurityBadgeDOM) {
          badgeContainer.innerHTML = '';
          _updateSecurityBadgeDOM(state.hosts[existingIdx], badgeContainer);
        }
        if (_updateMonitorDotDOM) _updateMonitorDotDOM(state.hosts[existingIdx], card);
      }
    } else if (hostData.monitorStatus === 'online') {
      // Brand-new host discovered by the monitor — add it to scope
      state.hosts.push({
        ip:              hostData.ip,
        mac:             hostData.mac      || '',
        hostname:        hostData.hostname  || '',
        vendor:          '',
        os:              '',
        ports:           hostData.ports    || [],
        source:          'monitor',
        routing:         [],
        processes:       [],
        monitorStatus:   'online',
        monitorLastSeen: hostData.monitorLastSeen,
        monitorAlerts:   hostData.monitorAlerts || [],
        firstSeen:       hostData.firstSeen || Date.now(),
        lastSeen:        Date.now(),
      });
      if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();
    }
  });

  window.electronAPI.hardeningMonitor?.onStatus((status) => {
    const { subnet, state: monState, lastRun, nextRun, hostCount, error } = status;

    if (monState === 'scanning') {
      setStatusDot('scanning');
      if (hardeningFooterText) hardeningFooterText.textContent = `Scanning ${escapeHtml(subnet)}…`;
      if (hardeningLastScanText) hardeningLastScanText.textContent = 'Scanning now…';
    } else if (monState === 'idle' || monState === 'started') {
      setStatusDot(hardeningMonitorActive ? 'active' : 'idle');
      if (lastRun && hardeningLastScanText) {
        hardeningLastScanText.textContent = `Last scan: ${fmtTime(lastRun)}`;
      }
      if (nextRun) startHardeningCountdown(nextRun);
      if (hostCount != null && hardeningHostCount) {
        hardeningHostCount.textContent = `${hostCount} host${hostCount !== 1 ? 's' : ''} live`;
      }
      if (hardeningFooterText) hardeningFooterText.textContent = 'Monitoring active';
    } else if (monState === 'error') {
      setStatusDot('error');
      showHardeningError(error || 'Monitor error');
      setHardeningRunning(false);
    }
  });

  window.electronAPI.hardeningMonitor?.onDeltaAlert((delta) => {
    // Lightweight alert — append card, show badge. Full report comes via onDeltaReport.
    appendAlert(delta, null);
  });

  window.electronAPI.hardeningMonitor?.onDeltaReport((report) => {
    // Patch the last alert entry with the full report data
    if (hardeningEvents.length > 0) {
      hardeningEvents[hardeningEvents.length - 1].report = report;
    }
    if (btnHardeningExport) btnHardeningExport.disabled = false;
  });

  return { openPanel: openHardeningPanel, setOpenDetailsPanelRef };
}
