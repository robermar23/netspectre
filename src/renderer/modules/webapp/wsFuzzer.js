/**
 * wsFuzzer.js — WebSocket Fuzzer Renderer Module (Feature 7E)
 *
 * Provides:
 *   - Target WS URL input (ws:// or wss://)
 *   - Payload list: manual textarea or file-based wordlist
 *   - Concurrency slider + timeout input
 *   - Extra headers key/value pairs
 *   - Live results table: index, payload, response excerpt, duration, anomaly badge
 *   - Progress bar + stats (sent/total, anomalies)
 *   - CSV export, Clear button
 *   - Anomaly filter toggle
 *
 * Network→WebApp pivot: window.__openWsFuzzerPanel(wsUrl) switches workspace
 * and pre-fills the URL input.
 */

import { api } from '../../api.js';

// ─── State ────────────────────────────────────────────────────────────────────

let _results   = [];
let _fuzzing   = false;
let _total     = 0;
let _done      = 0;
let _hits      = 0;
let _filterAnomalies = false;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function _badge(text, color) {
  return `<span style="display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600;background:${color};color:#fff;">${_esc(text)}</span>`;
}

function _anomalyBadge(r) {
  if (!r.upgraded)  return _badge('NO UPGRADE', '#9e9e9e');
  if (r.timedOut)   return _badge('TIMEOUT', '#f97316');
  if (r.errorType)  return _badge(r.errorType, '#ef4444');
  return _badge('OK', '#22c55e');
}

// ─── Render ───────────────────────────────────────────────────────────────────

function _render() {
  const container = document.getElementById('webapp-panel-wsfuzzer');
  if (!container) return;

  container.innerHTML = `
<div class="wsfuzz-layout">
  <!-- ── Config strip ── -->
  <div class="wsfuzz-config glass-panel" style="padding:14px 16px; flex-shrink:0; display:flex; flex-direction:column; gap:10px;">
    <div style="display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
      <div style="flex:1; min-width:220px;">
        <label class="form-label">Target WebSocket URL</label>
        <input id="wsf-url" type="text" class="text-input full-width"
          placeholder="ws://target.com/ws  or  wss://target.com/chat" />
      </div>
      <button id="wsf-start-btn" class="btn pentest" style="white-space:nowrap;">▶ Start Fuzz</button>
      <button id="wsf-stop-btn"  class="btn danger-outline" disabled style="white-space:nowrap;">⏹ Stop</button>
    </div>

    <!-- Payload source -->
    <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
      <label class="form-label" style="margin:0;">Payload source:</label>
      <label style="display:flex;align-items:center;gap:5px;cursor:pointer;">
        <input type="radio" name="wsf-src" value="manual" checked id="wsf-src-manual" /> Manual
      </label>
      <label style="display:flex;align-items:center;gap:5px;cursor:pointer;">
        <input type="radio" name="wsf-src" value="file" id="wsf-src-file" /> Wordlist file
      </label>
    </div>

    <!-- Manual payloads -->
    <div id="wsf-manual-group">
      <label class="form-label">Payloads (one per line)</label>
      <textarea id="wsf-payloads" class="text-input full-width" rows="4"
        placeholder="' OR 1=1\n{&quot;__typename&quot;:1}\n../../etc/passwd\n&lt;script&gt;alert(1)&lt;/script&gt;"></textarea>
    </div>

    <!-- File wordlist -->
    <div id="wsf-file-group" style="display:none; gap:8px; align-items:center;">
      <input id="wsf-file-path" class="text-input" style="flex:1;" readonly placeholder="(no file selected)" />
      <button id="wsf-browse-btn" class="btn secondary icon-only" title="Browse">📂</button>
    </div>

    <!-- Options row -->
    <div style="display:flex; gap:14px; flex-wrap:wrap; align-items:flex-end;">
      <div>
        <label class="form-label">Concurrency: <span id="wsf-conc-val">5</span></label>
        <input type="range" id="wsf-conc" min="1" max="20" value="5"
          style="width:100px; vertical-align:middle;" />
      </div>
      <div>
        <label class="form-label">Timeout (ms)</label>
        <input id="wsf-timeout" type="number" class="text-input" style="width:80px;" value="8000" min="500" max="60000" />
      </div>
      <div style="flex:1; min-width:180px;">
        <label class="form-label">Extra Headers (JSON, optional)</label>
        <input id="wsf-headers" type="text" class="text-input full-width"
          placeholder='{"Authorization":"Bearer token"}' />
      </div>
    </div>
  </div>

  <!-- ── Progress bar ── -->
  <div style="padding:6px 16px; flex-shrink:0; display:flex; align-items:center; gap:12px;">
    <div style="flex:1; height:6px; background:rgba(255,255,255,0.08); border-radius:3px; overflow:hidden;">
      <div id="wsf-progress-bar" style="height:100%; width:0%; background:var(--pentest,#f97316); transition:width .2s;"></div>
    </div>
    <span id="wsf-progress-label" style="font-size:11px; color:var(--text-muted); white-space:nowrap;">Idle</span>
    <span id="wsf-anomaly-count" style="font-size:11px; color:#ef4444; font-weight:600;"></span>
  </div>

  <!-- ── Error banner ── -->
  <div id="wsf-error" style="display:none; margin:0 16px; padding:8px 12px;
    background:rgba(239,68,68,0.15); border:1px solid #ef4444; border-radius:6px;
    color:#ef4444; font-size:12px;"></div>

  <!-- ── Toolbar ── -->
  <div style="padding:4px 16px 6px; display:flex; gap:8px; align-items:center; flex-shrink:0;">
    <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer;color:var(--text-muted);">
      <input type="checkbox" id="wsf-filter-anomalies" /> Show anomalies only
    </label>
    <div style="flex:1;"></div>
    <button id="wsf-clear-btn" class="btn secondary" style="font-size:11px;padding:3px 10px;">Clear</button>
    <button id="wsf-export-btn" class="btn secondary" style="font-size:11px;padding:3px 10px;">⬇ Export CSV</button>
  </div>

  <!-- ── Results table ── -->
  <div style="flex:1; min-height:0; overflow:auto; padding:0 16px 16px;">
    <table class="data-table" style="width:100%; font-size:11px; table-layout:fixed;">
      <colgroup>
        <col style="width:48px;" />
        <col style="width:30%;" />
        <col style="width:auto;" />
        <col style="width:70px;" />
        <col style="width:100px;" />
      </colgroup>
      <thead>
        <tr>
          <th>#</th>
          <th>Payload</th>
          <th>Response</th>
          <th>ms</th>
          <th>Result</th>
        </tr>
      </thead>
      <tbody id="wsf-tbody">
        <tr id="wsf-empty-row">
          <td colspan="5" style="text-align:center; color:var(--text-muted); padding:24px;">
            No results yet. Configure a WS URL and payload list, then click Start Fuzz.
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</div>`;

  _bindEvents();
  _subscribeIpc();
}

// ─── Events ───────────────────────────────────────────────────────────────────

function _bindEvents() {
  // Payload source radio
  document.querySelectorAll('input[name="wsf-src"]').forEach(radio => {
    radio.addEventListener('change', () => {
      const isFile = document.getElementById('wsf-src-file')?.checked;
      document.getElementById('wsf-manual-group').style.display = isFile ? 'none' : '';
      document.getElementById('wsf-file-group').style.display   = isFile ? 'flex' : 'none';
    });
  });

  // Browse wordlist file
  document.getElementById('wsf-browse-btn')?.addEventListener('click', async () => {
    const result = await api.browseFile?.();
    if (result?.filePath) {
      document.getElementById('wsf-file-path').value = result.filePath;
    }
  });

  // Concurrency slider
  document.getElementById('wsf-conc')?.addEventListener('input', (e) => {
    document.getElementById('wsf-conc-val').textContent = e.target.value;
  });

  // Filter anomalies
  document.getElementById('wsf-filter-anomalies')?.addEventListener('change', (e) => {
    _filterAnomalies = e.target.checked;
    _refreshTable();
  });

  // Start
  document.getElementById('wsf-start-btn')?.addEventListener('click', _startFuzz);

  // Stop
  document.getElementById('wsf-stop-btn')?.addEventListener('click', () => {
    api.wsFuzzer?.stop?.();
    _setRunning(false);
  });

  // Clear
  document.getElementById('wsf-clear-btn')?.addEventListener('click', () => {
    _results = [];
    _done = _total = _hits = 0;
    _refreshTable();
    _updateProgress(0, 0, 0);
    document.getElementById('wsf-error').style.display = 'none';
  });

  // Export CSV
  document.getElementById('wsf-export-btn')?.addEventListener('click', _exportCsv);
}

function _subscribeIpc() {
  api.wsFuzzer?.onResult?.(_onResult);
  api.wsFuzzer?.onProgress?.(_onProgress);
  api.wsFuzzer?.onComplete?.(_onComplete);
  api.wsFuzzer?.onError?.(_onError);
}

// ─── Fuzz start ───────────────────────────────────────────────────────────────

async function _startFuzz() {
  const url = document.getElementById('wsf-url')?.value?.trim();
  if (!url || !url.startsWith('ws')) {
    _showError('URL must start with ws:// or wss://');
    return;
  }

  // Collect payloads
  let payloads = [];
  const isFile = document.getElementById('wsf-src-file')?.checked;
  if (isFile) {
    const filePath = document.getElementById('wsf-file-path')?.value?.trim();
    if (!filePath) { _showError('Select a wordlist file first.'); return; }
    const r = await api.intruder?.readWordlist?.(filePath);
    if (!r?.success) { _showError(r?.error ?? 'Failed to read wordlist'); return; }
    payloads = r.lines ?? [];
  } else {
    const raw = document.getElementById('wsf-payloads')?.value ?? '';
    payloads = raw.split('\n').map(l => l.trim()).filter(Boolean);
  }

  if (!payloads.length) { _showError('Add at least one payload.'); return; }

  // Parse extra headers
  let extraHeaders = {};
  const hdrsRaw = document.getElementById('wsf-headers')?.value?.trim();
  if (hdrsRaw) {
    try { extraHeaders = JSON.parse(hdrsRaw); }
    catch { _showError('Extra Headers must be valid JSON.'); return; }
  }

  const concurrency = parseInt(document.getElementById('wsf-conc')?.value ?? '5', 10);
  const timeoutMs   = parseInt(document.getElementById('wsf-timeout')?.value ?? '8000', 10);

  _results = [];
  _done = 0; _hits = 0;
  _total = payloads.length;
  _refreshTable();
  _updateProgress(0, _total, 0);
  _showError('');
  _setRunning(true);

  const result = await api.wsFuzzer?.start?.({ url, payloads, concurrency, timeoutMs, extraHeaders });
  if (result && !result.success) {
    _showError(result.error ?? 'Failed to start');
    _setRunning(false);
  }
}

// ─── IPC callbacks ────────────────────────────────────────────────────────────

function _onResult(r) {
  _results.push(r);
  _done++;
  if (r.anomaly) _hits++;

  // Append row directly if filter allows
  if (!_filterAnomalies || r.anomaly) {
    _appendRow(r);
  }
}

function _onProgress({ done, total, hits, pct }) {
  _updateProgress(done, total, hits);
}

function _onComplete({ total, done, hits }) {
  _setRunning(false);
  _updateProgress(done, total, hits);
}

function _onError({ message }) {
  _showError(message);
  _setRunning(false);
}

// ─── Table helpers ────────────────────────────────────────────────────────────

function _appendRow(r) {
  const tbody = document.getElementById('wsf-tbody');
  if (!tbody) return;

  const empty = document.getElementById('wsf-empty-row');
  if (empty) empty.remove();

  const responseExcerpt = (r.response ?? '').replace(/\n/g, ' ').substring(0, 120);
  const tr = document.createElement('tr');
  if (r.anomaly) tr.style.background = 'rgba(239,68,68,0.07)';
  tr.innerHTML = `
    <td style="color:var(--text-muted);">${r.index + 1}</td>
    <td style="font-family:monospace;word-break:break-all;">${_esc(r.payload?.substring(0, 80))}</td>
    <td style="font-family:monospace;color:var(--text-muted);word-break:break-all;">${_esc(responseExcerpt)}</td>
    <td style="text-align:right;">${r.durationMs ?? 0}</td>
    <td>${_anomalyBadge(r)}</td>`;
  tbody.appendChild(tr);
}

function _refreshTable() {
  const tbody = document.getElementById('wsf-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const visible = _filterAnomalies ? _results.filter(r => r.anomaly) : _results;
  if (!visible.length) {
    tbody.innerHTML = `<tr id="wsf-empty-row"><td colspan="5" style="text-align:center;color:var(--text-muted);padding:24px;">No results yet.</td></tr>`;
    return;
  }
  visible.forEach(r => _appendRow(r));
}

function _updateProgress(done, total, hits) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  const bar = document.getElementById('wsf-progress-bar');
  if (bar) bar.style.width = `${pct}%`;

  const lbl = document.getElementById('wsf-progress-label');
  if (lbl) lbl.textContent = total > 0 ? `${done} / ${total} (${pct}%)` : 'Idle';

  const anomaly = document.getElementById('wsf-anomaly-count');
  if (anomaly) anomaly.textContent = hits > 0 ? `⚠ ${hits} anomal${hits === 1 ? 'y' : 'ies'}` : '';
}

function _setRunning(running) {
  _fuzzing = running;
  const startBtn = document.getElementById('wsf-start-btn');
  const stopBtn  = document.getElementById('wsf-stop-btn');
  if (startBtn) startBtn.disabled = running;
  if (stopBtn)  stopBtn.disabled  = !running;
}

function _showError(msg) {
  const el = document.getElementById('wsf-error');
  if (!el) return;
  el.style.display = msg ? '' : 'none';
  el.textContent   = msg;
}

// ─── CSV export ───────────────────────────────────────────────────────────────

function _exportCsv() {
  if (!_results.length) return;
  const header = ['Index', 'Payload', 'Response', 'DurationMs', 'Upgraded', 'ErrorType', 'Anomaly'];
  const rows = _results.map(r => [
    r.index + 1,
    `"${(r.payload ?? '').replace(/"/g, '""')}"`,
    `"${(r.response ?? '').replace(/\n/g, ' ').replace(/"/g, '""').substring(0, 500)}"`,
    r.durationMs ?? 0,
    r.upgraded ? 'true' : 'false',
    r.errorType ?? '',
    r.anomaly   ? 'true' : 'false',
  ]);
  const csv = [header, ...rows].map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ws-fuzz-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function init() {
  _render();
}

/**
 * Pre-fill the WS URL from a network workspace pivot.
 * Converts http(s):// URLs to ws(s):// automatically.
 */
export function openWithUrl(rawUrl) {
  const input = document.getElementById('wsf-url');
  if (!input || !rawUrl) return;
  try {
    const u   = new URL(rawUrl);
    const ws  = u.protocol === 'https:' ? 'wss:' : 'ws:';
    input.value = `${ws}//${u.host}${u.pathname}`;
  } catch {
    input.value = rawUrl;
  }
}
