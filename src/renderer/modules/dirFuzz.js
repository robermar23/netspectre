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
