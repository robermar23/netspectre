import { api } from '../api.js';
import { state } from '../state.js';
import { getPentestConsentAccepted, setPendingBfConfig } from './bruteForce.js';

// =============================================
// === CREDENTIAL SPRAY UI MODULE ===
// =============================================

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleTimeString();
}

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

// UI Elements
const ui = {
  panel: document.getElementById('credspray-panel'),
  resizer: document.getElementById('credspray-resizer'),
  btnOpen: document.getElementById('btn-credspray-open'),
  btnClose: document.getElementById('btn-close-credspray'),
  targetMode: document.getElementById('credspray-target-mode'),
  targetIp: document.getElementById('credspray-target-ip'),
  targetIpGroup: document.getElementById('credspray-single-ip-group'),
  protoCbs: document.querySelectorAll('.credspray-proto-cb'),
  stopOnHitCb: document.getElementById('credspray-stop-on-hit'),
  btnStart: document.getElementById('btn-credspray-start'),
  btnStop: document.getElementById('btn-credspray-stop'),
  btnClear: document.getElementById('btn-credspray-clear'),
  btnExport: document.getElementById('btn-credspray-export'),
  progressContainer: document.getElementById('credspray-progress-container'),
  progressBar: document.getElementById('credspray-progress-bar'),
  progressText: document.getElementById('credspray-progress-text'),
  progressPct: document.getElementById('credspray-progress-pct'),
  currentTargetDisplay: document.getElementById('credspray-current-target'),
  errorBanner: document.getElementById('credspray-error-banner'),
  resultsTbody: document.getElementById('credspray-results-tbody'),
  statsText: document.getElementById('credspray-stats-text'),
  footerHits: document.getElementById('credspray-footer-hits'),
};

/**
 * Centralized Cred Spray View-Model
 */
const credSprayView = {
  setRunning(isRunning) {
    state.isCredSprayRunning = isRunning;
    if (ui.btnStart) {
      ui.btnStart.disabled = isRunning;
      ui.btnStart.classList.toggle('credspray-running', isRunning);
    }
    if (ui.btnStop) ui.btnStop.disabled = !isRunning;
    if (ui.progressContainer) ui.progressContainer.style.display = isRunning ? 'flex' : 'none';
    if (!isRunning && ui.currentTargetDisplay) ui.currentTargetDisplay.style.display = 'none';
  },

  updateProgress(data) {
    const { tested, total, percent, currentIp, currentProtocol, currentPort } = data;
    if (ui.progressBar) ui.progressBar.style.width = `${percent}%`;
    if (ui.progressPct) ui.progressPct.textContent = `${percent}%`;
    if (ui.progressText) ui.progressText.textContent = `Testing ${tested} / ${total}...`;

    if (currentIp && ui.currentTargetDisplay) {
      ui.currentTargetDisplay.textContent = `[${currentProtocol.toUpperCase()}] ${currentIp}:${currentPort}`;
      ui.currentTargetDisplay.style.display = 'block';
    }
  },

  showError(msg) {
    if (!ui.errorBanner) return;
    ui.errorBanner.textContent = msg;
    ui.errorBanner.style.display = msg ? 'block' : 'none';
  },

  clearResults() {
    state.credSprayHits = [];
    if (ui.resultsTbody) {
      ui.resultsTbody.innerHTML = '';
      const empty = document.createElement('tr');
      empty.id = 'credspray-empty-row';
      empty.innerHTML = '<td colspan="4" style="text-align:center;color:var(--text-muted);padding:32px;">No findings recorded.</td>';
      ui.resultsTbody.appendChild(empty);
    }
    this.updateStats();
    if (ui.btnExport) ui.btnExport.disabled = true;
  },

  updateStats() {
    const hitsCount = state.credSprayHits.length;
    if (ui.statsText) ui.statsText.textContent = `${hitsCount} hit${hitsCount !== 1 ? 's' : ''}`;
    if (ui.footerHits) ui.footerHits.textContent = `${hitsCount} hits`;
  },

  appendHit(hit) {
    const emptyRow = document.getElementById('credspray-empty-row');
    if (emptyRow) emptyRow.remove();

    state.credSprayHits.push(hit);
    this.updateStats();

    const row = document.createElement('tr');
    row.className = 'hit-row animate-in';

    // XSS-Safe DOM Manipulation
    const tdTarget = document.createElement('td');
    tdTarget.style.cssText = 'color:var(--accent-primary);font-weight:600;';
    tdTarget.textContent = hit.target;

    const tdProto = document.createElement('td');
    const protoSpan = document.createElement('span');
    protoSpan.className = 'tag-protocol';
    protoSpan.textContent = hit.protocol.toUpperCase();
    tdProto.appendChild(protoSpan);

    const tdCreds = document.createElement('td');
    const credsCode = document.createElement('code');
    credsCode.style.color = 'var(--success)';
    credsCode.textContent = `${hit.user}:${hit.pass}`;
    tdCreds.appendChild(credsCode);

    const tdTime = document.createElement('td');
    tdTime.style.cssText = 'font-size:11px;color:var(--text-muted);';
    tdTime.textContent = fmtTime(hit.time);

    row.append(tdTarget, tdProto, tdCreds, tdTime);
    ui.resultsTbody?.prepend(row);

    if (ui.btnExport) ui.btnExport.disabled = false;
  }
};

/**
 * Creates a quick-action block for host cards.
 */
export function createCredSprayQuickAction(ip) {
  const container = document.createElement('div');
  container.style.cssText = 'margin-top: 10px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;';

  const label = document.createElement('span');
  label.style.cssText = 'font-size: 11px; color: var(--text-muted);';
  label.textContent = '🔑 Default Creds:';

  const btn = document.createElement('button');
  btn.className = 'btn-action pentest-action';
  btn.style.cssText = 'font-size: 10px; padding: 3px 8px;';
  btn.textContent = 'Spray Known Defaults';
  btn.title = `Launch credential spray against ${ip}`;
  btn.addEventListener('click', () => {
    openCredSprayPanel(ip);
  });

  container.append(label, btn);
  return container;
}

function openCredSprayPanel(prefilledIp) {
  if (prefilledIp && ui.targetIp) {
    ui.targetIp.value = prefilledIp;
    if (ui.targetMode) ui.targetMode.value = 'single';
    if (ui.targetIpGroup) ui.targetIpGroup.style.display = 'block';
  }
  if (ui.panel) openPanelHelper(ui.panel, ui.resizer);
}

function closeCredSprayPanel() {
  if (ui.panel) closePanelHelper(ui.panel, ui.resizer);
}

export function init() {
  // Resizer
  if (ui.resizer && ui.panel) {
    let startX, startWidth;
    ui.resizer.addEventListener('mousedown', (e) => {
      startX = e.clientX;
      startWidth = ui.panel.offsetWidth;
      const onMove = (ev) => {
        const dx = startX - ev.clientX;
        const newWidth = Math.max(320, Math.min(900, startWidth + dx));
        ui.panel.style.width = newWidth + 'px';
      };
      const onUp = () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  }

  ui.btnOpen?.addEventListener('click', () => {
    if (ui.panel?.classList.contains('open')) closeCredSprayPanel();
    else openCredSprayPanel('');
  });

  ui.btnClose?.addEventListener('click', closeCredSprayPanel);

  ui.targetMode?.addEventListener('change', () => {
    if (ui.targetIpGroup) {
      ui.targetIpGroup.style.display = ui.targetMode.value === 'single' ? 'block' : 'none';
    }
  });

  ui.btnStart?.addEventListener('click', async () => {
    if (state.isCredSprayRunning) return;

    const mode = ui.targetMode?.value || 'all';
    const targetIp = mode === 'single' ? ui.targetIp?.value?.trim() : null;

    if (mode === 'single' && !targetIp) {
      credSprayView.showError('Target IP is required for single mode.');
      return;
    }

    const selectedProtos = [];
    ui.protoCbs.forEach(cb => { if (cb.checked) selectedProtos.push(cb.value); });

    if (selectedProtos.length === 0) {
      credSprayView.showError('Select at least one protocol.');
      return;
    }

    // Pentest Consent Check
    if (!getPentestConsentAccepted()) {
      setPendingBfConfig({
        _type: 'credspray',
        mode,
        targetIp,
        protocols: selectedProtos,
        stopOnHit: !!ui.stopOnHitCb?.checked
      });
      document.getElementById('pentest-consent-overlay')?.classList.remove('hidden');
      return;
    }

    credSprayView.showError(null);
    credSprayView.setRunning(true);

    if (ui.progressText) ui.progressText.textContent = 'Starting...';

    const opts = {
      targets: mode === 'single' ? [targetIp] : state.hosts.map(h => h.ip),
      protocols: selectedProtos,
      stopOnFirstHit: !!ui.stopOnHitCb?.checked,
      delayMs: 200
    };

    try {
      await api.startCredSpray(opts);
    } catch (err) {
      credSprayView.showError(`Failed to start: ${err.message}`);
      credSprayView.setRunning(false);
    }
  });

  ui.btnStop?.addEventListener('click', async () => {
    try {
      await api.stopCredSpray();
    } catch { /* ignore */ }
    credSprayView.setRunning(false);
    if (ui.progressText) ui.progressText.textContent = 'Stopped';
  });

  ui.btnClear?.addEventListener('click', () => {
    if (state.isCredSprayRunning) return;
    credSprayView.clearResults();
  });

  ui.btnExport?.addEventListener('click', () => {
    if (state.credSprayHits.length === 0) return;
    const header = 'Target,Protocol,User,Password,Time\n';
    const csvRows = state.credSprayHits.map(h =>
      `"${h.target}","${h.protocol}","${h.user}","${h.pass}","${fmtTime(h.time)}"`
    ).join('\n');

    const blob = new Blob([header + csvRows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `credspray_hits_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // --- IPC Listeners ---

  window.electronAPI.onCredSprayHit?.((hit) => {
    credSprayView.appendHit(hit);
  });

  window.electronAPI.onCredSprayProgress?.((data) => {
    credSprayView.updateProgress(data);
  });

  window.electronAPI.onCredSprayComplete?.((data) => {
    credSprayView.setRunning(false);
    if (ui.progressBar) ui.progressBar.style.width = '100%';
    if (ui.progressPct) ui.progressPct.textContent = '100%';
    const secs = (data.elapsed / 1000).toFixed(1);
    if (ui.progressText) ui.progressText.textContent = `Finished in ${secs}s (${data.hits} hits)`;
  });

  window.electronAPI.onCredSprayError?.((data) => {
    credSprayView.setRunning(false);
    credSprayView.showError(data.message || 'Spray error occurred');
  });

  return { openPanel: openCredSprayPanel };
}
