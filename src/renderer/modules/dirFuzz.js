import { api } from '../api.js';
import { getPentestConsentAccepted, setPendingBfConfig } from './bruteForce.js';

function escapeHtml(unsafe) {
  if (unsafe == null) return '';
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

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

const dirfuzzPanel      = document.getElementById('dirfuzz-panel');
const dirfuzzResizer    = document.getElementById('dirfuzz-resizer');
const btnDirfuzzOpen    = document.getElementById('btn-dirfuzz-open');
const btnCloseDirfuzz   = document.getElementById('btn-close-dirfuzz-panel');
const btnDirfuzzStart   = document.getElementById('btn-dirfuzz-start');
const btnDirfuzzStop    = document.getElementById('btn-dirfuzz-stop');
const btnDirfuzzClear   = document.getElementById('btn-dirfuzz-clear');
const btnDirfuzzExport  = document.getElementById('btn-dirfuzz-export');
const dirfuzzTargetUrl  = document.getElementById('dirfuzz-target-url');
const dirfuzzWordlistMode = document.getElementById('dirfuzz-wordlist-mode');
const dirfuzzWordlistFileGroup = document.getElementById('dirfuzz-wordlist-file-group');
const dirfuzzWordlistPath = document.getElementById('dirfuzz-wordlist-path');
const btnDirfuzzBrowse  = document.getElementById('btn-dirfuzz-browse-wordlist');
const dirfuzzExtensions = document.getElementById('dirfuzz-extensions');
const dirfuzzConcurrency = document.getElementById('dirfuzz-concurrency');
const dirfuzzConcurrencyVal = document.getElementById('dirfuzz-concurrency-val');
const dirfuzzTimeout    = document.getElementById('dirfuzz-timeout');
const dirfuzzProgressText = document.getElementById('dirfuzz-progress-text');
const dirfuzzProgressBar  = document.getElementById('dirfuzz-progress-bar');
const dirfuzzStatsText  = document.getElementById('dirfuzz-stats-text');
const dirfuzzErrorBanner = document.getElementById('dirfuzz-error-banner');
const dirfuzzResultsTbody = document.getElementById('dirfuzz-results-tbody');
const dirfuzzFooterHits = document.getElementById('dirfuzz-footer-hits');

let dirfuzzRunning = false;
let dirfuzzHits = [];

export function openPanel(prefilledUrl) {
  if (prefilledUrl && dirfuzzTargetUrl) dirfuzzTargetUrl.value = prefilledUrl;
  if (dirfuzzPanel) openPanelHelper(dirfuzzPanel, dirfuzzResizer);
}

function closeDirFuzzPanel() {
  if (dirfuzzPanel) closePanelHelper(dirfuzzPanel, dirfuzzResizer);
}

function showDirFuzzError(msg) {
  if (!dirfuzzErrorBanner) return;
  dirfuzzErrorBanner.textContent = msg;
  dirfuzzErrorBanner.style.display = 'block';
}

function clearDirFuzzError() {
  if (dirfuzzErrorBanner) dirfuzzErrorBanner.style.display = 'none';
}

function setDirFuzzRunning(running) {
  dirfuzzRunning = running;
  if (btnDirfuzzStart) {
    btnDirfuzzStart.disabled = running;
    btnDirfuzzStart.classList.toggle('dirfuzz-running', running);
  }
  if (btnDirfuzzStop) btnDirfuzzStop.disabled = !running;
}

function resetDirFuzzUI() {
  dirfuzzHits = [];
  if (dirfuzzResultsTbody) {
    dirfuzzResultsTbody.innerHTML = '';
    const empty = document.createElement('tr');
    empty.id = 'dirfuzz-empty-row';
    empty.innerHTML = '<td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">Enter a URL and click Start to begin fuzzing</td>';
    dirfuzzResultsTbody.appendChild(empty);
  }
  if (dirfuzzProgressBar) dirfuzzProgressBar.style.width = '0%';
  if (dirfuzzProgressText) dirfuzzProgressText.textContent = 'Idle';
  if (dirfuzzStatsText) dirfuzzStatsText.textContent = '';
  if (dirfuzzFooterHits) dirfuzzFooterHits.textContent = '0 hits';
  if (btnDirfuzzExport) btnDirfuzzExport.disabled = true;
  clearDirFuzzError();
}

function statusClass(code) {
  if (code >= 200 && code < 300) return '2xx';
  if (code >= 300 && code < 400) return '3xx';
  if (code >= 400 && code < 500) return '4xx';
  return '5xx';
}

function formatBytes(n) {
  if (!n || n === 0) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function shortMime(ct) {
  if (!ct) return '—';
  return ct.split(';')[0].split('/').pop().slice(0, 12);
}

function appendDirFuzzHit(hit) {
  const existingEmpty = dirfuzzResultsTbody?.querySelector('#dirfuzz-empty-row');
  if (existingEmpty) existingEmpty.remove();

  dirfuzzHits.push(hit);

  const row = document.createElement('tr');
  row.className = `dirfuzz-row-${hit.statusCode}`;
  const sc = statusClass(hit.statusCode);
  const path = escapeHtml(hit.path);
  const redirect = hit.redirectUrl ? ` → ${escapeHtml(hit.redirectUrl)}` : '';
  row.innerHTML = `
    <td class="dirfuzz-status-cell dirfuzz-status-${sc}">${hit.statusCode}</td>
    <td class="col-path" title="${path}${redirect}">${path}</td>
    <td style="text-align:right;">${formatBytes(hit.contentLength)}</td>
    <td title="${escapeHtml(hit.contentType)}">${escapeHtml(shortMime(hit.contentType))}</td>
    <td style="text-align:right;">${hit.responseTime}</td>
  `;
  dirfuzzResultsTbody?.appendChild(row);

  const tableWrap = dirfuzzResultsTbody?.closest('div[style*="overflow-y"]');
  if (tableWrap) tableWrap.scrollTop = tableWrap.scrollHeight;

  if (dirfuzzFooterHits) dirfuzzFooterHits.textContent = `${dirfuzzHits.length} hit${dirfuzzHits.length !== 1 ? 's' : ''}`;
  if (btnDirfuzzExport) btnDirfuzzExport.disabled = false;
}

function getSelectedStatusCodes() {
  const checkboxes = document.querySelectorAll('.dirfuzz-status-cb:checked');
  return Array.from(checkboxes).map(cb => parseInt(cb.value, 10));
}

async function runDirFuzz() {
  if (dirfuzzRunning) return;

  const url = dirfuzzTargetUrl?.value.trim();
  if (!url) {
    showDirFuzzError('Please enter a target URL.');
    return;
  }

  // Require consent before running
  if (!getPentestConsentAccepted()) {
    setPendingBfConfig({ _type: 'dirfuzz' });
    const pentestConsentOverlay = document.getElementById('pentest-consent-overlay');
    pentestConsentOverlay?.classList.remove('hidden');
    return;
  }

  clearDirFuzzError();
  resetDirFuzzUI();
  setDirFuzzRunning(true);
  if (dirfuzzProgressText) dirfuzzProgressText.textContent = 'Starting…';

  const wordlistMode = dirfuzzWordlistMode?.value || 'builtin';
  const wordlistPath = (wordlistMode === 'custom') ? (dirfuzzWordlistPath?.value.trim() || null) : null;

  const rawExts = dirfuzzExtensions?.value.trim() || '';
  const extensions = rawExts
    ? rawExts.split(',').map(e => e.trim()).filter(Boolean)
    : [];

  const statusFilter = getSelectedStatusCodes();
  const concurrency = parseInt(dirfuzzConcurrency?.value, 10) || 10;
  const timeout = parseInt(dirfuzzTimeout?.value, 10) || 3000;

  const opts = {
    targetUrl: url,
    wordlistPath,
    extensions,
    statusFilter,
    concurrency,
    timeout,
    followRedirects: false,
  };

  try {
    await api.startDirFuzz(opts);
  } catch (err) {
    showDirFuzzError(`Failed to start: ${err.message}`);
    setDirFuzzRunning(false);
  }
}

function initResizer(resizerEl, panelEl) {
  if (!resizerEl || !panelEl) return;
  let activeResize = null;

  resizerEl.addEventListener('mousedown', (e) => {
    const startWidth = parseInt(document.defaultView.getComputedStyle(panelEl).width, 10);
    activeResize = { resizerEl, panelEl, startX: e.clientX, startWidth };
    resizerEl.classList.add('is-resizing');
    document.body.style.cursor = 'col-resize';
    e.preventDefault();
  });

  document.addEventListener('mousemove', (e) => {
    if (!activeResize) return;
    const { startX, startWidth } = activeResize;
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
}

export function init() {
  _initWebAppPanel();
  _registerWebAppIpc();
  initResizer(dirfuzzResizer, dirfuzzPanel);

  if (dirfuzzConcurrency) {
    dirfuzzConcurrency.addEventListener('input', () => {
      if (dirfuzzConcurrencyVal) dirfuzzConcurrencyVal.textContent = dirfuzzConcurrency.value;
    });
  }

  if (dirfuzzWordlistMode) {
    dirfuzzWordlistMode.addEventListener('change', () => {
      const isCustom = dirfuzzWordlistMode.value === 'custom';
      if (dirfuzzWordlistFileGroup) {
        dirfuzzWordlistFileGroup.style.display = isCustom ? 'flex' : 'none';
      }
    });
  }

  if (btnDirfuzzBrowse) {
    btnDirfuzzBrowse.addEventListener('click', async () => {
      const result = await api.browseFile({
        title: 'Select Wordlist File',
        filters: [
          { name: 'Text Files', extensions: ['txt', 'lst', 'wordlist'] },
          { name: 'All Files', extensions: ['*'] },
        ],
      });
      if (result?.status === 'selected' && dirfuzzWordlistPath) {
        dirfuzzWordlistPath.value = result.path;
      }
    });
  }

  btnDirfuzzOpen?.addEventListener('click', () => {
    if (dirfuzzPanel?.classList.contains('open')) {
      closeDirFuzzPanel();
    } else {
      openPanel('');
    }
  });

  btnCloseDirfuzz?.addEventListener('click', closeDirFuzzPanel);

  btnDirfuzzStart?.addEventListener('click', runDirFuzz);

  btnDirfuzzStop?.addEventListener('click', async () => {
    try {
      await api.stopDirFuzz();
    } catch { /* ignore */ }
    setDirFuzzRunning(false);
    if (dirfuzzProgressText) dirfuzzProgressText.textContent = 'Stopped';
  });

  btnDirfuzzClear?.addEventListener('click', () => {
    if (dirfuzzRunning) return;
    resetDirFuzzUI();
  });

  btnDirfuzzExport?.addEventListener('click', () => {
    if (dirfuzzHits.length === 0) return;
    const header = 'Status,Path,Size,ContentType,ResponseTime(ms),Redirect\n';
    const rows = dirfuzzHits.map(h =>
      [h.statusCode, `"${h.path}"`, h.contentLength, `"${h.contentType}"`, h.responseTime, `"${h.redirectUrl || ''}"`].join(',')
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dirfuzz_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // IPC event listeners
  window.electronAPI.onDirFuzzHit?.((hit) => {
    appendDirFuzzHit(hit);
  });

  window.electronAPI.onDirFuzzProgress?.((data) => {
    const { tested, total, percent } = data;
    if (dirfuzzProgressBar) dirfuzzProgressBar.style.width = `${percent}%`;
    if (dirfuzzProgressText) dirfuzzProgressText.textContent = `${tested} / ${total} paths`;
    if (dirfuzzStatsText) dirfuzzStatsText.textContent = `${dirfuzzHits.length} hit${dirfuzzHits.length !== 1 ? 's' : ''}`;
  });

  window.electronAPI.onDirFuzzComplete?.((data) => {
    setDirFuzzRunning(false);
    if (dirfuzzProgressBar) dirfuzzProgressBar.style.width = '100%';
    const secs = (data.elapsed / 1000).toFixed(1);
    if (dirfuzzProgressText) dirfuzzProgressText.textContent = `Complete — ${data.hits} hit${data.hits !== 1 ? 's' : ''} in ${secs}s`;
    if (dirfuzzStatsText) dirfuzzStatsText.textContent = `${data.total} paths tested`;
    if (dirfuzzFooterHits) dirfuzzFooterHits.textContent = `${data.hits} hit${data.hits !== 1 ? 's' : ''}`;
  });

  window.electronAPI.onDirFuzzError?.((err) => {
    setDirFuzzRunning(false);
    showDirFuzzError(err.message || 'Fuzzing error');
    if (dirfuzzProgressText) dirfuzzProgressText.textContent = 'Error';
  });

  return { openPanel };
}

// ─── Web App Embedded Panel ────────────────────────────────────────────────────
// Renders a self-contained Dir Fuzz UI inside #webapp-panel-dirfuzz.
// Shares the same IPC backend; IPC events update both panels when visible.

let wdfTargetUrl, wdfWordlistMode, wdfWordlistFileGroup, wdfWordlistPath;
let wdfBrowse, wdfExtensions, wdfConcurrency, wdfConcurrencyVal, wdfTimeout;
let wdfStart, wdfStop, wdfClear, wdfExport;
let wdfProgressBar, wdfProgressText, wdfStatsText, wdfErrorBanner;
let wdfResultsTbody;
let wdfRunning = false;
let wdfHits = [];

function _initWebAppPanel() {
  const container = document.getElementById('webapp-panel-dirfuzz');
  if (!container) return;

  container.innerHTML = `
    <div style="display:flex;flex-direction:column;flex:1;min-height:0;overflow:hidden;">

      <!-- Config bar -->
      <div style="padding:12px 16px;border-bottom:1px solid var(--border-glass);flex-shrink:0;display:flex;flex-direction:column;gap:10px;">
        <div style="display:flex;gap:8px;align-items:flex-end;">
          <div class="form-group" style="flex:1;margin:0;">
            <label class="form-label">Target URL</label>
            <input type="text" id="wdf-target-url" class="text-input full-width"
              placeholder="https://target.example.com/path">
          </div>
          <button id="wdf-start" class="btn pentest" style="white-space:nowrap;">
            <span class="icon">▶</span> Start
          </button>
          <button id="wdf-stop" class="btn danger-outline" disabled style="white-space:nowrap;">
            <span class="icon">⏹</span> Stop
          </button>
        </div>

        <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
          <div class="form-group" style="margin:0;">
            <label class="form-label">Wordlist</label>
            <select id="wdf-wordlist-mode" class="dropdown-select">
              <option value="builtin">Built-in (50 paths)</option>
              <option value="custom">Custom file…</option>
            </select>
          </div>
          <div class="form-group" style="flex:1;margin:0;display:none;" id="wdf-wordlist-file-group">
            <label class="form-label">Wordlist Path</label>
            <div style="display:flex;gap:6px;">
              <input type="text" id="wdf-wordlist-path" class="text-input" style="flex:1;" placeholder="/path/to/wordlist.txt" readonly>
              <button id="wdf-browse" class="btn secondary">Browse</button>
            </div>
          </div>
          <div class="form-group" style="margin:0;">
            <label class="form-label">Extensions</label>
            <input type="text" id="wdf-extensions" class="text-input" style="width:140px;" placeholder=".php,.html,.js">
          </div>
          <div class="form-group" style="margin:0;">
            <label class="form-label">Concurrency: <span id="wdf-concurrency-val">10</span></label>
            <input type="range" id="wdf-concurrency" min="1" max="50" value="10" style="width:100px;">
          </div>
          <div class="form-group" style="margin:0;">
            <label class="form-label">Timeout (ms)</label>
            <input type="number" id="wdf-timeout" class="text-input" style="width:80px;" value="3000" min="500" max="30000" step="500">
          </div>
        </div>

        <!-- Status filter checkboxes -->
        <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
          <span style="font-size:11px;color:var(--text-muted);">Show:</span>
          <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;">
            <input type="checkbox" class="wdf-status-cb" value="2xx" checked> 2xx
          </label>
          <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;">
            <input type="checkbox" class="wdf-status-cb" value="3xx"> 3xx
          </label>
          <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;">
            <input type="checkbox" class="wdf-status-cb" value="401"> 401
          </label>
          <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;">
            <input type="checkbox" class="wdf-status-cb" value="403"> 403
          </label>
          <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;">
            <input type="checkbox" class="wdf-status-cb" value="5xx"> 5xx
          </label>
        </div>
      </div>

      <!-- Progress -->
      <div style="padding:8px 16px;border-bottom:1px solid var(--border-glass);flex-shrink:0;display:flex;align-items:center;gap:12px;">
        <div style="flex:1;background:rgba(0,0,0,0.4);border-radius:3px;height:6px;overflow:hidden;">
          <div id="wdf-progress-bar" style="height:100%;width:0%;background:var(--primary);transition:width 0.2s ease;"></div>
        </div>
        <span id="wdf-progress-text" style="font-size:11px;color:var(--text-muted);white-space:nowrap;">Idle</span>
        <span id="wdf-stats-text" style="font-size:11px;color:var(--success);font-weight:600;white-space:nowrap;"></span>
      </div>

      <!-- Error banner -->
      <div id="wdf-error-banner" style="display:none;background:rgba(235,94,94,0.1);border-left:3px solid var(--danger);color:var(--danger);font-size:11px;padding:8px 16px;flex-shrink:0;"></div>

      <!-- Results table -->
      <div style="flex:1;overflow:auto;min-height:0;">
        <table class="data-table" style="width:100%;font-size:12px;">
          <thead style="position:sticky;top:0;background:#1a1a24;z-index:1;">
            <tr>
              <th style="width:60px;">Status</th>
              <th>Path</th>
              <th style="width:70px;">Size</th>
              <th style="width:70px;">Type</th>
              <th style="width:70px;">Time</th>
            </tr>
          </thead>
          <tbody id="wdf-results-tbody">
            <tr id="wdf-empty-row">
              <td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted);">
                Enter a URL and click Start to begin fuzzing
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Footer -->
      <div style="display:flex;gap:8px;padding:10px 16px;border-top:1px solid var(--border-glass);flex-shrink:0;align-items:center;">
        <button id="wdf-clear" class="btn secondary" style="flex:1;">Clear</button>
        <button id="wdf-export" class="btn info" style="flex:1;" disabled>Export CSV</button>
      </div>

    </div>
  `;

  // Bind DOM refs
  wdfTargetUrl        = document.getElementById('wdf-target-url');
  wdfWordlistMode     = document.getElementById('wdf-wordlist-mode');
  wdfWordlistFileGroup = document.getElementById('wdf-wordlist-file-group');
  wdfWordlistPath     = document.getElementById('wdf-wordlist-path');
  wdfBrowse           = document.getElementById('wdf-browse');
  wdfExtensions       = document.getElementById('wdf-extensions');
  wdfConcurrency      = document.getElementById('wdf-concurrency');
  wdfConcurrencyVal   = document.getElementById('wdf-concurrency-val');
  wdfTimeout          = document.getElementById('wdf-timeout');
  wdfStart            = document.getElementById('wdf-start');
  wdfStop             = document.getElementById('wdf-stop');
  wdfClear            = document.getElementById('wdf-clear');
  wdfExport           = document.getElementById('wdf-export');
  wdfProgressBar      = document.getElementById('wdf-progress-bar');
  wdfProgressText     = document.getElementById('wdf-progress-text');
  wdfStatsText        = document.getElementById('wdf-stats-text');
  wdfErrorBanner      = document.getElementById('wdf-error-banner');
  wdfResultsTbody     = document.getElementById('wdf-results-tbody');

  // Wire events
  wdfConcurrency?.addEventListener('input', () => {
    if (wdfConcurrencyVal) wdfConcurrencyVal.textContent = wdfConcurrency.value;
  });

  wdfWordlistMode?.addEventListener('change', () => {
    const isCustom = wdfWordlistMode.value === 'custom';
    if (wdfWordlistFileGroup) wdfWordlistFileGroup.style.display = isCustom ? 'flex' : 'none';
  });

  wdfBrowse?.addEventListener('click', async () => {
    const result = await api.browseFile({
      title: 'Select Wordlist File',
      filters: [
        { name: 'Text Files', extensions: ['txt', 'lst', 'wordlist'] },
        { name: 'All Files', extensions: ['*'] },
      ],
    });
    if (result?.status === 'selected' && wdfWordlistPath) {
      wdfWordlistPath.value = result.path;
    }
  });

  wdfStart?.addEventListener('click', _runWebAppDirFuzz);

  wdfStop?.addEventListener('click', async () => {
    try { await api.stopDirFuzz(); } catch { /* ignore */ }
    _setWdfRunning(false);
    if (wdfProgressText) wdfProgressText.textContent = 'Stopped';
  });

  wdfClear?.addEventListener('click', () => {
    if (wdfRunning) return;
    _resetWdfUI();
  });

  wdfExport?.addEventListener('click', () => {
    if (!wdfHits.length) return;
    const header = 'Status,Path,Size,ContentType,ResponseTime(ms),Redirect\n';
    const rows = wdfHits.map(h =>
      [h.statusCode, `"${h.path}"`, h.contentLength, `"${h.contentType}"`, h.responseTime, `"${h.redirectUrl || ''}"`].join(',')
    ).join('\n');
    const blob = new Blob([header + rows], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `dirfuzz_webapp_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Pre-fill URL from webapp-target-url when the panel becomes active
  document.addEventListener('webapp:targetChanged', (e) => {
    if (wdfTargetUrl && e.detail?.url) wdfTargetUrl.value = e.detail.url;
  });
}

function _getWdfStatusCodes() {
  const codes = [];
  document.querySelectorAll('.wdf-status-cb:checked').forEach(cb => codes.push(cb.value));
  return codes;
}

function _setWdfRunning(running) {
  wdfRunning = running;
  if (wdfStart) { wdfStart.disabled = running; }
  if (wdfStop)  { wdfStop.disabled  = !running; }
}

function _resetWdfUI() {
  wdfHits = [];
  if (wdfResultsTbody) {
    wdfResultsTbody.innerHTML = '';
    const empty = document.createElement('tr');
    empty.id = 'wdf-empty-row';
    empty.innerHTML = '<td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted);">Enter a URL and click Start to begin fuzzing</td>';
    wdfResultsTbody.appendChild(empty);
  }
  if (wdfProgressBar)  wdfProgressBar.style.width = '0%';
  if (wdfProgressText) wdfProgressText.textContent = 'Idle';
  if (wdfStatsText)    wdfStatsText.textContent = '';
  if (wdfErrorBanner)  wdfErrorBanner.style.display = 'none';
  if (wdfExport)       wdfExport.disabled = true;
}

function _appendWdfHit(hit) {
  const existingEmpty = wdfResultsTbody?.querySelector('#wdf-empty-row');
  if (existingEmpty) existingEmpty.remove();

  wdfHits.push(hit);

  const row  = document.createElement('tr');
  const sc   = statusClass(hit.statusCode);
  const path = escapeHtml(hit.path);
  const redirect = hit.redirectUrl ? ` → ${escapeHtml(hit.redirectUrl)}` : '';
  row.innerHTML = `
    <td><span class="dirfuzz-status-badge status-${sc}">${hit.statusCode}</span></td>
    <td style="font-family:monospace;font-size:11px;word-break:break-all;">${path}${redirect}</td>
    <td style="font-size:11px;">${formatBytes(hit.contentLength)}</td>
    <td style="font-size:11px;">${shortMime(hit.contentType)}</td>
    <td style="font-size:11px;">${hit.responseTime}ms</td>
  `;
  wdfResultsTbody?.appendChild(row);
  if (wdfExport) wdfExport.disabled = false;
}

async function _runWebAppDirFuzz() {
  const url = wdfTargetUrl?.value.trim() || '';
  if (!url) {
    if (wdfErrorBanner) { wdfErrorBanner.textContent = 'Please enter a target URL.'; wdfErrorBanner.style.display = 'block'; }
    return;
  }

  if (!getPentestConsentAccepted()) {
    setPendingBfConfig({ _type: 'dirfuzz' });
    document.getElementById('pentest-consent-overlay')?.classList.remove('hidden');
    return;
  }

  if (wdfErrorBanner) wdfErrorBanner.style.display = 'none';
  _resetWdfUI();
  _setWdfRunning(true);
  if (wdfProgressText) wdfProgressText.textContent = 'Starting…';

  const wordlistMode = wdfWordlistMode?.value || 'builtin';
  const wordlistPath = (wordlistMode === 'custom') ? (wdfWordlistPath?.value.trim() || null) : null;
  const rawExts  = wdfExtensions?.value.trim() || '';
  const extensions = rawExts ? rawExts.split(',').map(e => e.trim()).filter(Boolean) : [];
  const concurrency = parseInt(wdfConcurrency?.value, 10) || 10;
  const timeout     = parseInt(wdfTimeout?.value, 10) || 3000;
  const statusFilter = _getWdfStatusCodes();

  const opts = { targetUrl: url, wordlistPath, extensions, statusFilter, concurrency, timeout, followRedirects: false };

  try {
    await api.startDirFuzz(opts);
  } catch (err) {
    if (wdfErrorBanner) { wdfErrorBanner.textContent = `Failed to start: ${err.message}`; wdfErrorBanner.style.display = 'block'; }
    _setWdfRunning(false);
  }
}

// Register IPC events for the webapp panel (same IPC as the network panel)
function _registerWebAppIpc() {
  window.electronAPI?.onDirFuzzHit?.((hit) => {
    // Update webapp panel if it is visible
    const panel = document.getElementById('webapp-panel-dirfuzz');
    if (panel && panel.style.display !== 'none') _appendWdfHit(hit);
  });

  window.electronAPI?.onDirFuzzProgress?.((data) => {
    const panel = document.getElementById('webapp-panel-dirfuzz');
    if (panel && panel.style.display !== 'none') {
      const { tested, total, percent } = data;
      if (wdfProgressBar)  wdfProgressBar.style.width = `${percent}%`;
      if (wdfProgressText) wdfProgressText.textContent = `${tested} / ${total} paths`;
      if (wdfStatsText)    wdfStatsText.textContent = `${wdfHits.length} hit${wdfHits.length !== 1 ? 's' : ''}`;
    }
  });

  window.electronAPI?.onDirFuzzComplete?.((data) => {
    const panel = document.getElementById('webapp-panel-dirfuzz');
    if (panel && panel.style.display !== 'none') {
      _setWdfRunning(false);
      if (wdfProgressBar)  wdfProgressBar.style.width = '100%';
      const secs = (data.elapsed / 1000).toFixed(1);
      if (wdfProgressText) wdfProgressText.textContent = `Complete — ${data.hits} hit${data.hits !== 1 ? 's' : ''} in ${secs}s`;
    }
  });

  window.electronAPI?.onDirFuzzError?.((err) => {
    const panel = document.getElementById('webapp-panel-dirfuzz');
    if (panel && panel.style.display !== 'none') {
      _setWdfRunning(false);
      if (wdfErrorBanner) { wdfErrorBanner.textContent = err.message || 'Fuzzing error'; wdfErrorBanner.style.display = 'block'; }
      if (wdfProgressText) wdfProgressText.textContent = 'Error';
    }
  });
}
