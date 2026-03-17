import { api } from '../api.js';

function escapeHtml(unsafe) {
  if (unsafe == null) return '';
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ---- Shared consent state (exported so other modules can use it) ----
export let pentestConsentAccepted = false;
export let pendingBfConfig = null;

// ---- Panel helpers (same pattern as dirFuzz / credSpray) ----
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

// ---- Brute-Force Panel elements ----
const pentestConsentOverlay = document.getElementById('pentest-consent-overlay');
const btnClosePentestConsent = document.getElementById('btn-close-pentest-consent');
const btnPentestConsentReject = document.getElementById('btn-pentest-consent-reject');
const btnPentestConsentAccept = document.getElementById('btn-pentest-consent-accept');

const bfPanel   = document.getElementById('bruteforce-panel');
const bfResizer = document.getElementById('bruteforce-resizer');
const bfTargetIp = document.getElementById('bf-target-ip');
const btnCloseBfPanel = document.getElementById('btn-close-bruteforce-panel');
const bfPort = document.getElementById('bf-port');
const bfProtocol = document.getElementById('bf-protocol');
const bfUsername = document.getElementById('bf-username');
const bfWordlistPath = document.getElementById('bf-wordlist-path');
const btnBfBrowseWordlist = document.getElementById('btn-bf-browse-wordlist');
const bfThreads = document.getElementById('bf-threads');
const bfThreadsVal = document.getElementById('bf-threads-val');
const bfDelay = document.getElementById('bf-delay');
const bfMaxAttempts = document.getElementById('bf-max-attempts');
const btnBfStart = document.getElementById('btn-bf-start');
const btnBfStop = document.getElementById('btn-bf-stop');
const bfProgressContainer = document.getElementById('bf-progress-container');
const bfProgressFill = document.getElementById('bf-progress-fill');
const bfProgressText = document.getElementById('bf-progress-text');
const bfResultsBody = document.getElementById('bf-results-body');
const bfErrorDisplay = document.getElementById('bf-error-display');

// Protocol → default port map
const protocolPortMap = {
  'ssh': 22, 'ftp': 21, 'smb': 445, 'rdp': 3389,
  'http-get': 80, 'http-post': 80, 'telnet': 23,
  'mysql': 3306, 'mssql': 1433, 'postgres': 5432, 'vnc': 5900
};

let isBfRunning = false;
let bfAttemptCount = 0;

// Callback to be set by the caller when consent is accepted and a pending action needs to run
let _onConsentAcceptedCallback = null;

export function setPendingBfConfig(cfg) {
  pendingBfConfig = cfg;
}

export function getPentestConsentAccepted() {
  return pentestConsentAccepted;
}

function closePentestConsent() {
  pentestConsentOverlay?.classList.add('hidden');
  pendingBfConfig = null;
}

function showBruteForcePanel(ip, port, protocol) {
  resetBfModal();
  if (bfTargetIp) bfTargetIp.value = ip || '';
  if (bfPort) bfPort.value = port || 22;
  if (bfProtocol) bfProtocol.value = protocol || 'ssh';
  openPanelHelper(bfPanel, bfResizer);
}

export function openBruteForcePanel(ip, port, protocol) {
  if (!pentestConsentAccepted) {
    pendingBfConfig = { ip, port, protocol };
    pentestConsentOverlay?.classList.remove('hidden');
    return;
  }
  showBruteForcePanel(ip, port, protocol);
}

/** Alias kept for backward compatibility with any callers using `openModal` */
export function openBruteForceModal(ip, port, protocol) {
  return openBruteForcePanel(ip, port, protocol);
}

export function openModal(ip, port, protocol) {
  return openBruteForcePanel(ip, port, protocol);
}

function closeBfPanel() {
  closePanelHelper(bfPanel, bfResizer);
}

function resetBfModal() {
  isBfRunning = false;
  bfAttemptCount = 0;
  if (btnBfStart) { btnBfStart.disabled = false; btnBfStart.classList.remove('pulsing'); }
  if (btnBfStop) btnBfStop.disabled = true;
  if (bfProgressContainer) bfProgressContainer.style.display = 'none';
  if (bfProgressFill) bfProgressFill.style.width = '0%';
  if (bfProgressText) bfProgressText.textContent = '0 attempts';
  if (bfResultsBody) bfResultsBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted); padding: 16px;">Configure and start an attack above</td></tr>';
  if (bfErrorDisplay) { bfErrorDisplay.style.display = 'none'; bfErrorDisplay.textContent = ''; }
}

function resetBfState() {
  isBfRunning = false;
  if (btnBfStart) { btnBfStart.disabled = false; btnBfStart.classList.remove('pulsing'); }
  if (btnBfStop) btnBfStop.disabled = true;
}

function showBfError(msg) {
  if (bfErrorDisplay) {
    bfErrorDisplay.textContent = msg;
    bfErrorDisplay.style.display = 'block';
  }
}

function hideBfError() {
  if (bfErrorDisplay) {
    bfErrorDisplay.textContent = '';
    bfErrorDisplay.style.display = 'none';
  }
}

function formatBfTime(isoString) {
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return '--:--:--'; }
}

export function init() {
  // Check persisted consent on load
  api.settings.get('pentestConsentAccepted').then(val => {
    pentestConsentAccepted = !!val;
  });

  // Consent flow
  btnClosePentestConsent?.addEventListener('click', closePentestConsent);
  btnPentestConsentReject?.addEventListener('click', closePentestConsent);

  btnPentestConsentAccept?.addEventListener('click', async () => {
    pentestConsentAccepted = true;
    await api.settings.set('pentestConsentAccepted', true);
    pentestConsentOverlay?.classList.add('hidden');
    if (pendingBfConfig) {
      const cfg = pendingBfConfig;
      pendingBfConfig = null;
      if (_onConsentAcceptedCallback) {
        _onConsentAcceptedCallback(cfg);
      } else if (cfg._type !== 'dirfuzz' && cfg._type !== 'credspray') {
        showBruteForcePanel(cfg.ip, cfg.port, cfg.protocol);
      }
    }
  });

  // Brute-Force Panel close
  btnCloseBfPanel?.addEventListener('click', closeBfPanel);

  bfThreads?.addEventListener('input', () => {
    if (bfThreadsVal) bfThreadsVal.textContent = bfThreads.value;
  });

  bfProtocol?.addEventListener('change', () => {
    const defaultPort = protocolPortMap[bfProtocol.value];
    if (defaultPort && bfPort) bfPort.value = defaultPort;
  });

  btnBfBrowseWordlist?.addEventListener('click', async () => {
    try {
      const result = await api.browseFile({
        title: 'Select Password Wordlist',
        filters: [
          { name: 'Text Files', extensions: ['txt', 'lst', 'dict'] },
          { name: 'All Files', extensions: ['*'] }
        ],
      });
      if (result.status === 'selected' && result.path) {
        if (bfWordlistPath) bfWordlistPath.value = result.path;
      }
    } catch (err) {
      showBfError(`Failed to open file dialog: ${err.message}`);
    }
  });

  btnBfStart?.addEventListener('click', async () => {
    const targetIp = bfTargetIp?.value?.trim();
    const port = parseInt(bfPort?.value, 10);
    const protocol = bfProtocol?.value;
    const username = bfUsername?.value?.trim();
    const wordlistPath = bfWordlistPath?.value?.trim();
    const threads = parseInt(bfThreads?.value, 10) || 4;
    const delay = parseInt(bfDelay?.value, 10) || 0;
    const maxAttempts = parseInt(bfMaxAttempts?.value, 10) || 10000;

    if (!targetIp) { showBfError('Target IP is required'); return; }
    if (!port || port < 1 || port > 65535) { showBfError('Invalid port (1-65535)'); return; }
    if (!username) { showBfError('Username is required'); return; }
    if (!wordlistPath) { showBfError('Wordlist path is required'); return; }

    hideBfError();
    bfAttemptCount = 0;
    isBfRunning = true;

    btnBfStart.disabled = true;
    btnBfStart.classList.add('pulsing');
    btnBfStop.disabled = false;
    bfProgressContainer.style.display = 'block';
    bfProgressFill.style.width = '0%';
    bfProgressText.textContent = 'Starting...';
    bfResultsBody.innerHTML = '';

    try {
      await api.startBruteForce({
        targetIp, port, protocol, username, wordlistPath, threads, delay, maxAttempts,
      });
    } catch (err) {
      showBfError(`Failed to start: ${err.message}`);
      resetBfState();
    }
  });

  btnBfStop?.addEventListener('click', async () => {
    try {
      await api.stopBruteForce();
    } catch (_) { /* ignore */ }
    resetBfState();
  });

  // IPC Event Listeners
  window.electronAPI.onBruteForceAttempt((data) => {
    bfAttemptCount = data.attemptNumber || (bfAttemptCount + 1);
    if (bfProgressText) {
      bfProgressText.textContent = `${bfAttemptCount} attempts`;
    }
    if (bfAttemptCount % 10 === 0 || bfAttemptCount <= 5) {
      const row = document.createElement('tr');
      row.className = 'bf-attempt-row';
      row.innerHTML = `<td>${formatBfTime(data.timestamp)}</td><td colspan="2" style="font-family: monospace; font-size: 10px;">${escapeHtml(data.line?.substring(0, 80) || '...')}</td><td style="color: var(--text-muted);">⏳</td>`;
      bfResultsBody?.appendChild(row);
      const container = document.getElementById('bf-results-container');
      if (container) container.scrollTop = container.scrollHeight;
    }
  });

  window.electronAPI.onBruteForceResult((data) => {
    const row = document.createElement('tr');
    row.className = 'bf-credential-hit';
    row.innerHTML = `<td>${formatBfTime(data.timestamp)}</td><td><strong>${escapeHtml(data.user)}</strong></td><td><strong>${escapeHtml(data.password)}</strong> <span class="bf-copy-btn" title="Copy credential">📋</span></td><td style="color: var(--success);">✅</td>`;

    const copyBtn = row.querySelector('.bf-copy-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(`${data.user}:${data.password}`);
        copyBtn.textContent = '✔️';
        setTimeout(() => { copyBtn.textContent = '📋'; }, 2000);
      });
    }

    bfResultsBody?.prepend(row);
  });

  window.electronAPI.onBruteForceProgress((data) => {
    if (bfProgressText) {
      bfProgressText.textContent = `${data.attemptCount || bfAttemptCount} attempts | ${data.foundCount || 0} found | ${data.statusText || ''}`;
    }
    const max = parseInt(bfMaxAttempts?.value, 10) || 10000;
    const pct = Math.min(((data.attemptCount || bfAttemptCount) / max) * 100, 100);
    if (bfProgressFill) bfProgressFill.style.width = `${pct}%`;
  });

  window.electronAPI.onBruteForceError((data) => {
    showBfError(data.message || 'Unknown brute-force error');
  });

  window.electronAPI.onBruteForceComplete((data) => {
    resetBfState();
    if (bfProgressFill) bfProgressFill.style.width = '100%';

    const found = data.credentialsFound?.length || 0;
    const summary = `Complete — ${data.totalAttempts || 0} attempts, ${found} credential${found !== 1 ? 's' : ''} found (exit code ${data.exitCode})`;
    if (bfProgressText) bfProgressText.textContent = summary;

    if (data.stderr && data.exitCode !== 0) {
      showBfError(`Hydra stderr: ${data.stderr.substring(0, 200)}`);
    }
  });

  // Resizer drag (same pattern as dirFuzz)
  if (bfResizer && bfPanel) {
    let activeResize = null;
    bfResizer.addEventListener('mousedown', (e) => {
      const startWidth = parseInt(document.defaultView.getComputedStyle(bfPanel).width, 10);
      activeResize = { startX: e.clientX, startWidth };
      bfResizer.classList.add('is-resizing');
      document.body.style.cursor = 'col-resize';
      e.preventDefault();
    });
    document.addEventListener('mousemove', (e) => {
      if (!activeResize) return;
      const newWidth = activeResize.startWidth - (e.clientX - activeResize.startX);
      if (newWidth > 320 && newWidth < Math.min(900, window.innerWidth - 100)) {
        bfPanel.style.width = `${newWidth}px`;
      }
    });
    document.addEventListener('mouseup', () => {
      if (!activeResize) return;
      bfResizer.classList.remove('is-resizing');
      document.body.style.cursor = '';
      activeResize = null;
    });
  }

  return { openModal, openBruteForceModal, openBruteForcePanel, closeBfPanel, setConsentCallback };
}

function setConsentCallback(fn) {
  _onConsentAcceptedCallback = fn;
}
