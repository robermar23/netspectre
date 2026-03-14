/**
 * Feature 5C — Container & Cloud Enumeration — Renderer Module
 *
 * Manages the #cloudenum-panel side panel, all IPC event listeners,
 * and host-details integration badges.
 */

import { api }   from '../api.js';
import { state } from '../state.js';

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEVERITY_META = {
  critical: { label: 'CRITICAL', icon: '🔴', color: 'var(--cloudenum-critical)', borderVar: '--cloudenum-critical' },
  warning:  { label: 'WARNING',  icon: '🟡', color: 'var(--cloudenum-warning)',  borderVar: '--cloudenum-warning'  },
  info:     { label: 'INFO',     icon: '🔵', color: 'var(--cloudenum-info)',     borderVar: '--cloudenum-info'     },
};

function severityMeta(s) {
  return SEVERITY_META[s] || SEVERITY_META.info;
}

function fmtTime(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ─── Panel open/close helpers ─────────────────────────────────────────────────

function openPanelHelper(panel, resizer) {
  if (!panel) return;
  panel.style.display = 'flex';
  setTimeout(() => panel.classList.add('open'), 10);
  if (resizer) resizer.style.display = 'block';
}

function closePanelHelper(panel, resizer) {
  if (!panel) return;
  panel.classList.remove('open');
  setTimeout(() => {
    panel.style.display = 'none';
    if (resizer) resizer.style.display = 'none';
  }, 300);
}

// ─── UI element cache ─────────────────────────────────────────────────────────

const ui = {
  panel:             document.getElementById('cloudenum-panel'),
  resizer:           document.getElementById('cloudenum-resizer'),
  btnOpen:           document.getElementById('btn-cloudenum-open'),
  btnClose:          document.getElementById('btn-close-cloudenum-panel'),
  btnStart:          document.getElementById('btn-cloudenum-start'),
  btnStop:           document.getElementById('btn-cloudenum-stop'),
  btnClear:          document.getElementById('btn-cloudenum-clear'),
  btnExport:         document.getElementById('btn-cloudenum-export'),
  targetMode:        document.getElementById('cloudenum-target-mode'),
  targetIp:          document.getElementById('cloudenum-target-ip'),
  targetIpGroup:     document.getElementById('cloudenum-single-ip-group'),
  concurrencySlider: document.getElementById('cloudenum-concurrency'),
  concurrencyLabel:  document.getElementById('cloudenum-concurrency-label'),
  probeCbs:          () => document.querySelectorAll('.cloudenum-probe-cb'),
  progressBar:       document.getElementById('cloudenum-progress-bar'),
  progressText:      document.getElementById('cloudenum-progress-text'),
  progressPct:       document.getElementById('cloudenum-progress-pct'),
  progressContainer: document.getElementById('cloudenum-progress-container'),
  errorBanner:       document.getElementById('cloudenum-error-banner'),
  findingsList:      document.getElementById('cloudenum-findings-list'),
  statsRow:          document.getElementById('cloudenum-stats-row'),
  statsCritical:     document.getElementById('cloudenum-stats-critical'),
  statsWarning:      document.getElementById('cloudenum-stats-warning'),
  statsInfo:         document.getElementById('cloudenum-stats-info'),
  footerText:        document.getElementById('cloudenum-footer-text'),
  noFindings:        document.getElementById('cloudenum-no-findings'),
};

// ─── ViewModel ────────────────────────────────────────────────────────────────

const vm = {
  setRunning(isRunning) {
    state.isCloudEnumRunning = isRunning;
    if (ui.btnStart) ui.btnStart.disabled = isRunning;
    if (ui.btnStop)  ui.btnStop.disabled  = !isRunning;
    if (ui.progressContainer) ui.progressContainer.style.display = isRunning ? 'flex' : 'none';
  },

  updateProgress(data) {
    const { completed, total, percent, currentIp } = data;
    if (ui.progressBar) ui.progressBar.style.width = `${percent}%`;
    if (ui.progressPct) ui.progressPct.textContent  = `${percent}%`;
    if (ui.progressText) {
      ui.progressText.textContent = currentIp
        ? `Scanning ${completed}/${total} — ${currentIp}`
        : `Scanned ${completed} of ${total} hosts`;
    }
  },

  showError(msg) {
    if (!ui.errorBanner) return;
    ui.errorBanner.textContent = msg || '';
    ui.errorBanner.style.display = msg ? 'block' : 'none';
  },

  updateStats() {
    const critical = state.cloudFindings.filter(f => f.severity === 'critical').length;
    const warning  = state.cloudFindings.filter(f => f.severity === 'warning').length;
    const info     = state.cloudFindings.filter(f => f.severity === 'info').length;

    if (ui.statsCritical) ui.statsCritical.textContent = critical;
    if (ui.statsWarning)  ui.statsWarning.textContent  = warning;
    if (ui.statsInfo)     ui.statsInfo.textContent     = info;

    const total = critical + warning + info;
    if (ui.statsRow) ui.statsRow.style.display = total > 0 ? 'flex' : 'none';
    if (ui.btnExport) ui.btnExport.disabled = total === 0;
    if (ui.footerText) {
      ui.footerText.textContent = total > 0
        ? `${total} finding${total !== 1 ? 's' : ''} — ${critical} critical`
        : 'No findings';
    }
  },

  clearFindings() {
    state.cloudFindings = [];
    if (ui.findingsList) ui.findingsList.innerHTML = '';
    if (ui.noFindings) {
      ui.noFindings.style.display = 'block';
      ui.findingsList?.appendChild(ui.noFindings);
    }
    this.updateStats();
    // Remove host badges
    document.querySelectorAll('.cloudenum-host-badge').forEach(b => b.remove());
  },

  appendFinding(finding) {
    state.cloudFindings.push(finding);
    this.updateStats();

    if (ui.noFindings) ui.noFindings.style.display = 'none';

    const meta = severityMeta(finding.severity);
    const card = document.createElement('div');
    card.className = `cloudenum-finding-card finding-${finding.severity}`;
    card.dataset.ip = finding.ip;

    // Header row
    const header = document.createElement('div');
    header.style.cssText = 'display:flex; align-items:center; gap:8px; margin-bottom:6px;';

    const badge = document.createElement('span');
    badge.className = 'severity-badge ' + finding.severity;
    badge.textContent = meta.label;

    const titleEl = document.createElement('span');
    titleEl.style.cssText = 'font-weight:600; font-size:12px; flex:1;';
    titleEl.textContent = finding.title;

    const ipEl = document.createElement('span');
    ipEl.style.cssText = 'font-size:11px; color:var(--text-muted); font-family:monospace;';
    ipEl.textContent = `${finding.ip}:${finding.port}`;

    header.append(badge, titleEl, ipEl);

    // Evidence
    const evidenceEl = document.createElement('div');
    evidenceEl.style.cssText = 'font-size:11px; color:var(--text-muted); margin-bottom:5px; font-family:monospace; word-break:break-all;';
    evidenceEl.textContent = finding.evidence;

    // Description (collapsed)
    const descWrap = document.createElement('details');
    descWrap.style.cssText = 'font-size:11px; margin-bottom:6px;';
    const descSummary = document.createElement('summary');
    descSummary.style.cssText = 'cursor:pointer; color:var(--text-muted); user-select:none;';
    descSummary.textContent = 'Description & Remediation';
    const descBody = document.createElement('div');
    descBody.style.cssText = 'padding:6px 0; color:var(--text-secondary); line-height:1.5;';
    descBody.textContent = finding.description;

    const remLabel = document.createElement('div');
    remLabel.style.cssText = 'margin-top:6px; font-weight:600; color:var(--cloudenum-warning);';
    remLabel.textContent = 'REMEDIATION:';
    const remEl = document.createElement('div');
    remEl.style.cssText = 'color:var(--text-muted); line-height:1.5;';
    remEl.textContent = finding.remediation;
    descBody.append(remLabel, remEl);

    descWrap.append(descSummary, descBody);

    // Action row
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex; gap:6px; flex-wrap:wrap; margin-top:4px;';

    const btnCopy = document.createElement('button');
    btnCopy.className = 'btn-action';
    btnCopy.style.cssText = 'font-size:10px; padding:2px 8px;';
    btnCopy.textContent = '📋 Copy Evidence';
    btnCopy.addEventListener('click', () => {
      const text = `[${meta.label}] ${finding.title}\nHost: ${finding.ip}:${finding.port}\nEvidence: ${finding.evidence}\nRemediation: ${finding.remediation}`;
      navigator.clipboard.writeText(text).catch(() => {});
    });

    const btnScan = document.createElement('button');
    btnScan.className = 'btn-action';
    btnScan.style.cssText = 'font-size:10px; padding:2px 8px;';
    btnScan.textContent = '🔍 Scan Host';
    btnScan.addEventListener('click', () => {
      if (window.__openDetailsPanel) window.__openDetailsPanel(finding.ip);
    });

    const timeEl = document.createElement('span');
    timeEl.style.cssText = 'font-size:10px; color:var(--text-muted); margin-left:auto; align-self:center;';
    timeEl.textContent = fmtTime(finding.timestamp);

    actions.append(btnCopy, btnScan, timeEl);
    card.append(header, evidenceEl, descWrap, actions);

    ui.findingsList?.prepend(card);

    // Update host badge on card (if visible in main grid)
    _updateHostBadge(finding.ip, finding.severity);
  },
};

// ─── Host badge integration ───────────────────────────────────────────────────

/**
 * Update or create the container-risk badge on a host card in the main grid.
 * Badge severity escalates (critical > warning > info), never de-escalates.
 */
function _updateHostBadge(ip, severity) {
  const hostCard = document.querySelector(`.host-card[data-ip="${ip}"]`);
  if (!hostCard) return;

  let badge = hostCard.querySelector('.cloudenum-host-badge');
  if (!badge) {
    badge = document.createElement('span');
    badge.className = 'cloudenum-host-badge';
    badge.title = 'Container / Cloud Risk — click to view findings';
    badge.style.cssText = 'position:absolute; top:6px; right:6px; font-size:10px; padding:2px 6px; border-radius:10px; cursor:pointer; z-index:5; font-weight:700;';
    badge.addEventListener('click', (e) => {
      e.stopPropagation();
      openCloudEnumPanel(ip);
    });
    hostCard.style.position = 'relative';
    hostCard.appendChild(badge);
  }

  // Severity escalation: critical > warning > info
  const rank = { critical: 2, warning: 1, info: 0 };
  const current = badge.dataset.severity || 'info';
  if ((rank[severity] || 0) >= (rank[current] || 0)) {
    badge.dataset.severity = severity;
    const meta = severityMeta(severity);
    badge.textContent = `🐳 ${meta.label}`;
    badge.style.background = severity === 'critical' ? 'rgba(239,68,68,0.2)'
      : severity === 'warning' ? 'rgba(249,115,22,0.2)' : 'rgba(59,130,246,0.15)';
    badge.style.color = meta.color;
    badge.style.border = `1px solid ${meta.color}`;
  }
}

// ─── Panel open/close ─────────────────────────────────────────────────────────

let _singleIpFilter = null;

function openCloudEnumPanel(prefilledIp) {
  if (prefilledIp) {
    _singleIpFilter = prefilledIp;
    if (ui.targetMode) ui.targetMode.value = 'single';
    if (ui.targetIp) ui.targetIp.value = prefilledIp;
    if (ui.targetIpGroup) ui.targetIpGroup.style.display = 'block';
    // Filter visible findings to this IP
    _applyFindingsFilter(prefilledIp);
  } else {
    _singleIpFilter = null;
    _applyFindingsFilter(null);
  }
  if (ui.panel) openPanelHelper(ui.panel, ui.resizer);
}

function closeCloudEnumPanel() {
  if (ui.panel) closePanelHelper(ui.panel, ui.resizer);
}

function _applyFindingsFilter(ip) {
  if (!ui.findingsList) return;
  const cards = ui.findingsList.querySelectorAll('.cloudenum-finding-card');
  cards.forEach(c => {
    c.style.display = (!ip || c.dataset.ip === ip) ? '' : 'none';
  });
}

// ─── Build probe config from checkboxes ───────────────────────────────────────

const PROBE_CHECKBOX_MAP = {
  'probe-docker':    ['docker', 'docker-tls'],
  'probe-k8s':       ['kubernetes', 'kube-api'],
  'probe-etcd':      ['etcd'],
  'probe-consul':    ['consul', 'vault'],
  'probe-metadata':  ['cloud-metadata'],
  'probe-prometheus':['prometheus'],
  'probe-portainer': ['portainer', 'grafana'],
};

function getEnabledProbes() {
  const probes = [];
  ui.probeCbs().forEach(cb => {
    if (cb.checked) {
      const keys = PROBE_CHECKBOX_MAP[cb.value] || [];
      probes.push(...keys);
    }
  });
  return probes; // empty = all probes enabled
}

// ─── Start enumeration ────────────────────────────────────────────────────────

async function runCloudEnum() {
  vm.showError(null);

  const mode = ui.targetMode?.value || 'all';
  const targetIpValue = ui.targetIp?.value?.trim();

  if (mode === 'single' && !targetIpValue) {
    vm.showError('Enter a target IP for single-host scan.');
    return;
  }

  const targets = mode === 'single'
    ? [targetIpValue]
    : state.hosts.map(h => h.ip).filter(Boolean);

  if (targets.length === 0) {
    vm.showError('No targets available. Add hosts to scope first, or use single-host mode.');
    return;
  }

  const concurrency = parseInt(ui.concurrencySlider?.value || '10', 10);
  const probes = getEnabledProbes();

  vm.setRunning(true);
  if (ui.progressText) ui.progressText.textContent = 'Starting enumeration…';

  try {
    await api.cloudEnum.start({ targets, probes, concurrency });
  } catch (err) {
    vm.showError(`Failed to start: ${err.message}`);
    vm.setRunning(false);
  }
}

// ─── Export helpers ───────────────────────────────────────────────────────────

function exportFindingsJson() {
  if (state.cloudFindings.length === 0) return;
  const json = JSON.stringify(state.cloudFindings, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cloud_enum_${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── init() ──────────────────────────────────────────────────────────────────

export function init() {
  // Panel resize handle
  if (ui.resizer && ui.panel) {
    let startX, startWidth;
    ui.resizer.addEventListener('mousedown', (e) => {
      startX = e.clientX;
      startWidth = ui.panel.offsetWidth;
      const onMove = (ev) => {
        const dx = startX - ev.clientX;
        const newW = Math.max(380, Math.min(960, startWidth + dx));
        ui.panel.style.width = newW + 'px';
      };
      const onUp = () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  }

  // Header button toggle
  ui.btnOpen?.addEventListener('click', () => {
    if (ui.panel?.classList.contains('open')) closeCloudEnumPanel();
    else openCloudEnumPanel('');
  });

  ui.btnClose?.addEventListener('click', closeCloudEnumPanel);

  // Target mode toggle
  ui.targetMode?.addEventListener('change', () => {
    const isSingle = ui.targetMode.value === 'single';
    if (ui.targetIpGroup) ui.targetIpGroup.style.display = isSingle ? 'block' : 'none';
    if (!isSingle) {
      _singleIpFilter = null;
      _applyFindingsFilter(null);
    }
  });

  // Concurrency slider label sync
  ui.concurrencySlider?.addEventListener('input', () => {
    if (ui.concurrencyLabel) ui.concurrencyLabel.textContent = ui.concurrencySlider.value;
  });

  // Start
  ui.btnStart?.addEventListener('click', () => {
    if (!state.isCloudEnumRunning) runCloudEnum();
  });

  // Stop
  ui.btnStop?.addEventListener('click', async () => {
    try { await api.cloudEnum.stop(); } catch { /* ignore */ }
    vm.setRunning(false);
    if (ui.progressText) ui.progressText.textContent = 'Stopped';
  });

  // Clear
  ui.btnClear?.addEventListener('click', () => {
    if (state.isCloudEnumRunning) return;
    vm.clearFindings();
  });

  // Export
  ui.btnExport?.addEventListener('click', exportFindingsJson);

  // ── IPC listeners ──

  window.electronAPI.cloudEnum?.onFinding?.((finding) => {
    vm.appendFinding(finding);
  });

  window.electronAPI.cloudEnum?.onProgress?.((data) => {
    vm.updateProgress(data);
  });

  window.electronAPI.cloudEnum?.onComplete?.((data) => {
    vm.setRunning(false);
    if (ui.progressBar) ui.progressBar.style.width = '100%';
    if (ui.progressPct) ui.progressPct.textContent = '100%';
    const secs = (data.elapsed / 1000).toFixed(1);
    const aborted = data.aborted ? ' (stopped)' : '';
    if (ui.progressText) {
      ui.progressText.textContent = `Finished in ${secs}s — ${data.findings} finding${data.findings !== 1 ? 's' : ''}${aborted}`;
    }
  });

  window.electronAPI.cloudEnum?.onError?.((data) => {
    vm.setRunning(false);
    vm.showError(data.message || 'Enumeration error occurred');
  });

  // Expose for external callers (host details integration)
  window.__openCloudEnumPanel = openCloudEnumPanel;

  return { openPanel: openCloudEnumPanel };
}
