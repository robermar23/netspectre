/**
 * intruder.js — Intruder Renderer Module (Feature 7D)
 *
 * Provides:
 *   - Raw request template editor with §position marker§ workflow
 *   - Attack type selector (Sniper / BatteringRam / Pitchfork / ClusterBomb)
 *   - Payload list editors (one per position for Pitchfork/ClusterBomb)
 *   - Built-in wordlist shortcuts
 *   - Results table: sortable, color-coded, right-click "Send to Repeater"
 *   - Progress bar and live stats
 */

// ─── State ────────────────────────────────────────────────────────────────────

let _container   = null;
let _running     = false;
let _results     = [];
let _total       = 0;
let _completed   = 0;

let _attackType  = 'sniper';
let _payloadLists = [[]];  // one list per position
let _positions   = [];     // parsed from template when user clicks "Mark"

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function _statusBadge(code) {
  if (!code) return `<span class="intruder-status intruder-status-err">ERR</span>`;
  if (code < 300) return `<span class="intruder-status intruder-status-2xx">${code}</span>`;
  if (code < 400) return `<span class="intruder-status intruder-status-3xx">${code}</span>`;
  if (code < 500) return `<span class="intruder-status intruder-status-4xx">${code}</span>`;
  return `<span class="intruder-status intruder-status-5xx">${code}</span>`;
}

function _countPositions(template) {
  const matches = (template ?? '').match(/§[^§]*§/g);
  return matches ? matches.length : 0;
}

// ─── Render ───────────────────────────────────────────────────────────────────

function _render() {
  if (!_container) return;

  const posCount = _attackType === 'sniper' || _attackType === 'battering-ram'
    ? 1
    : _payloadLists.length;

  _container.innerHTML = `
    <div class="intruder-layout">
      <!-- Config panel -->
      <div class="intruder-config">

        <!-- Template editor -->
        <div class="intruder-section">
          <div class="intruder-section-header">
            <span class="intruder-section-title">Request Template</span>
            <div class="intruder-template-actions">
              <button class="btn intruder-mark-btn" id="intruder-mark-btn" title="Wrap selected text with §markers§">Mark §§</button>
              <button class="btn intruder-clear-marks-btn" id="intruder-clear-marks" title="Remove all §§ markers">Clear Marks</button>
            </div>
          </div>
          <textarea
            class="intruder-template-editor"
            id="intruder-template"
            spellcheck="false"
            placeholder="POST /login HTTP/1.1&#10;Host: target.com&#10;Content-Type: application/x-www-form-urlencoded&#10;&#10;username=§admin§&amp;password=§password§"
          ></textarea>
          <div class="intruder-template-hint" id="intruder-pos-hint">
            Detected <strong>0</strong> position(s). Wrap text with § to mark injection points.
          </div>
        </div>

        <!-- Target URL -->
        <div class="intruder-section intruder-section-row">
          <label class="intruder-label">Target URL</label>
          <input class="intruder-url-input" id="intruder-target-url" placeholder="https://target.com" />
        </div>

        <!-- Attack type -->
        <div class="intruder-section intruder-section-row">
          <label class="intruder-label">Attack Type</label>
          <select class="intruder-select" id="intruder-attack-type">
            <option value="sniper"       ${_attackType==='sniper'?'selected':''}>Sniper</option>
            <option value="battering-ram"${_attackType==='battering-ram'?'selected':''}>Battering Ram</option>
            <option value="pitchfork"    ${_attackType==='pitchfork'?'selected':''}>Pitchfork</option>
            <option value="cluster-bomb" ${_attackType==='cluster-bomb'?'selected':''}>Cluster Bomb</option>
          </select>
          <span class="intruder-attack-desc" id="intruder-attack-desc">${_attackDesc(_attackType)}</span>
        </div>

        <!-- Options row -->
        <div class="intruder-section intruder-section-row">
          <label class="intruder-label">Concurrency</label>
          <input type="range" min="1" max="50" value="10" id="intruder-concurrency" class="intruder-slider">
          <span id="intruder-concurrency-val">10</span>
          <label class="intruder-label" style="margin-left:16px">Delay (ms)</label>
          <input type="number" min="0" max="10000" value="0" id="intruder-delay" class="intruder-num-input" style="width:70px">
          <label class="intruder-label" style="margin-left:16px">Timeout (ms)</label>
          <input type="number" min="1000" max="60000" value="15000" id="intruder-timeout" class="intruder-num-input" style="width:80px">
        </div>

        <!-- Payload lists -->
        <div class="intruder-section">
          <div class="intruder-section-header">
            <span class="intruder-section-title">Payload Lists</span>
            ${_attackType === 'pitchfork' || _attackType === 'cluster-bomb'
              ? `<button class="btn intruder-add-list-btn" id="intruder-add-list">+ Add List</button>` : ''}
          </div>
          <div id="intruder-payload-lists">
            ${_payloadLists.slice(0, _attackType === 'sniper' || _attackType === 'battering-ram' ? 1 : _payloadLists.length).map((list, i) => `
              <div class="intruder-payload-list-block" data-list="${i}">
                <div class="intruder-payload-list-header">
                  <span class="intruder-payload-list-label">Position ${i + 1} — ${list.length} item(s)</span>
                  <div class="intruder-payload-list-actions">
                    <button class="btn intruder-builtin-btn" data-list="${i}" data-builtin="passwords">Top Passwords</button>
                    <button class="btn intruder-builtin-btn" data-list="${i}" data-builtin="usernames">Usernames</button>
                    <button class="btn intruder-builtin-btn" data-list="${i}" data-builtin="sqli">SQLi</button>
                    <button class="btn intruder-builtin-btn" data-list="${i}" data-builtin="xss">XSS</button>
                    <button class="btn intruder-load-btn" data-list="${i}">📂 Load File</button>
                    <button class="btn intruder-clear-list-btn" data-list="${i}">Clear</button>
                  </div>
                </div>
                <textarea
                  class="intruder-payload-textarea"
                  data-list="${i}"
                  placeholder="One payload per line…"
                  spellcheck="false"
                >${_esc(list.join('\n'))}</textarea>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Payload transforms -->
        <div class="intruder-section intruder-section-row">
          <label class="intruder-label">Transforms</label>
          <select class="intruder-select" id="intruder-transform" multiple style="height:60px;width:200px">
            <option value="url-encode">URL Encode</option>
            <option value="base64-encode">Base64 Encode</option>
            <option value="uppercase">Uppercase</option>
            <option value="lowercase">Lowercase</option>
            <option value="html-encode">HTML Encode</option>
          </select>
          <span class="intruder-hint-small">Ctrl+click to select multiple</span>
        </div>

      </div><!-- end .intruder-config -->

      <!-- Results panel -->
      <div class="intruder-results-panel">
        <!-- Toolbar -->
        <div class="intruder-results-toolbar">
          <button class="btn webapp" id="intruder-start-btn" ${_running ? 'disabled' : ''}>
            ${_running ? 'Running…' : '▶ Start Attack'}
          </button>
          <button class="btn intruder-stop-btn" id="intruder-stop-btn" ${!_running ? 'disabled' : ''}>⏹ Stop</button>
          <button class="btn intruder-clear-btn" id="intruder-clear-results-btn" ${_running ? 'disabled' : ''}>Clear</button>
          <div class="intruder-progress-wrap">
            <div class="intruder-progress-bar">
              <div class="intruder-progress-fill" id="intruder-progress-fill" style="width:${_total ? (_completed/_total*100).toFixed(1) : 0}%"></div>
            </div>
            <span class="intruder-progress-label" id="intruder-progress-label">
              ${_total ? `${_completed} / ${_total}` : 'Ready'}
            </span>
          </div>
        </div>

        <!-- Results table -->
        <div class="intruder-table-container">
          <table class="intruder-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Payload(s)</th>
                <th>Status</th>
                <th>Length</th>
                <th>Duration</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody id="intruder-results-body">
              ${_results.length === 0
                ? `<tr><td colspan="6" class="intruder-empty-row">No results yet. Configure and start an attack.</td></tr>`
                : _results.map(r => `
                  <tr class="intruder-result-row" data-index="${r.index}">
                    <td class="intruder-td-num">${r.index + 1}</td>
                    <td class="intruder-td-payload" title="${_esc(r.payloads?.join(' | '))}">${_esc(r.payloads?.join(' | ')?.slice(0, 60))}</td>
                    <td>${_statusBadge(r.statusCode)}</td>
                    <td class="intruder-td-num">${r.length?.toLocaleString() ?? '—'}</td>
                    <td class="intruder-td-num">${r.durationMs ?? '—'}ms</td>
                    <td class="intruder-td-error">${_esc(r.error ?? '')}</td>
                  </tr>
                `).join('')
              }
            </tbody>
          </table>
        </div>
      </div><!-- end .intruder-results-panel -->
    </div>
  `;

  _bindEvents();
}

function _attackDesc(type) {
  const descs = {
    'sniper':       'One position at a time through the payload list.',
    'battering-ram':'Same payload into all positions simultaneously.',
    'pitchfork':    'One payload list per position, iterated in parallel.',
    'cluster-bomb': 'Every combination of every payload (cartesian product).',
  };
  return descs[type] ?? '';
}

// ─── Events ───────────────────────────────────────────────────────────────────

function _bindEvents() {
  // Template change — update position hint
  const tmplEl = document.getElementById('intruder-template');
  const hintEl = document.getElementById('intruder-pos-hint');
  tmplEl?.addEventListener('input', () => {
    const n = _countPositions(tmplEl.value);
    if (hintEl) hintEl.innerHTML = `Detected <strong>${n}</strong> position(s).`;
  });

  // Mark position
  document.getElementById('intruder-mark-btn')?.addEventListener('click', () => {
    if (!tmplEl) return;
    const start = tmplEl.selectionStart;
    const end   = tmplEl.selectionEnd;
    if (start === end) return;
    const selected = tmplEl.value.slice(start, end);
    tmplEl.value = tmplEl.value.slice(0, start) + '§' + selected + '§' + tmplEl.value.slice(end);
    tmplEl.selectionStart = start;
    tmplEl.selectionEnd   = end + 2;
    const n = _countPositions(tmplEl.value);
    if (hintEl) hintEl.innerHTML = `Detected <strong>${n}</strong> position(s).`;
  });

  // Clear marks
  document.getElementById('intruder-clear-marks')?.addEventListener('click', () => {
    if (!tmplEl) return;
    tmplEl.value = tmplEl.value.replace(/§/g, '');
    if (hintEl) hintEl.innerHTML = `Detected <strong>0</strong> position(s).`;
  });

  // Attack type
  document.getElementById('intruder-attack-type')?.addEventListener('change', (e) => {
    _attackType = e.target.value;
    const descEl = document.getElementById('intruder-attack-desc');
    if (descEl) descEl.textContent = _attackDesc(_attackType);
    // Ensure enough lists for pitchfork/cluster-bomb
    if (_attackType === 'pitchfork' || _attackType === 'cluster-bomb') {
      const needed = _countPositions(tmplEl?.value ?? '');
      while (_payloadLists.length < Math.max(2, needed)) _payloadLists.push([]);
    }
    _syncPayloadTextareas();
    _render();
  });

  // Concurrency slider
  const concEl = document.getElementById('intruder-concurrency');
  const concVal = document.getElementById('intruder-concurrency-val');
  concEl?.addEventListener('input', () => { if (concVal) concVal.textContent = concEl.value; });

  // Payload textarea changes
  document.querySelectorAll('.intruder-payload-textarea[data-list]').forEach(ta => {
    ta.addEventListener('change', () => {
      const i = Number(ta.dataset.list);
      _payloadLists[i] = ta.value.split('\n').map(l => l.trim()).filter(Boolean);
      const header = document.querySelector(`.intruder-payload-list-block[data-list="${i}"] .intruder-payload-list-label`);
      if (header) header.textContent = `Position ${i + 1} — ${_payloadLists[i].length} item(s)`;
    });
  });

  // Built-in wordlists
  document.querySelectorAll('.intruder-builtin-btn[data-builtin]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const i       = Number(btn.dataset.list);
      const builtin = btn.dataset.builtin;
      const lines   = await _loadBuiltinWordlist(builtin);
      if (lines.length === 0) return;
      _payloadLists[i] = lines;
      const ta = document.querySelector(`.intruder-payload-textarea[data-list="${i}"]`);
      if (ta) ta.value = lines.join('\n');
      const header = document.querySelector(`.intruder-payload-list-block[data-list="${i}"] .intruder-payload-list-label`);
      if (header) header.textContent = `Position ${i + 1} — ${lines.length} item(s)`;
    });
  });

  // Load file
  document.querySelectorAll('.intruder-load-btn[data-list]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const i = Number(btn.dataset.list);
      const browseResult = await window.electronAPI.browseFile({ filters: [{ name: 'Text', extensions: ['txt','csv','lst'] }] });
      if (!browseResult?.path) return;
      const lines = await _readWordlistFile(browseResult.path);
      if (!lines) return;
      _payloadLists[i] = lines;
      const ta = document.querySelector(`.intruder-payload-textarea[data-list="${i}"]`);
      if (ta) ta.value = lines.slice(0, 500).join('\n') + (lines.length > 500 ? `\n…(${lines.length} total)` : '');
      const header = document.querySelector(`.intruder-payload-list-block[data-list="${i}"] .intruder-payload-list-label`);
      if (header) header.textContent = `Position ${i + 1} — ${lines.length} item(s)`;
    });
  });

  // Clear list
  document.querySelectorAll('.intruder-clear-list-btn[data-list]').forEach(btn => {
    btn.addEventListener('click', () => {
      const i = Number(btn.dataset.list);
      _payloadLists[i] = [];
      const ta = document.querySelector(`.intruder-payload-textarea[data-list="${i}"]`);
      if (ta) ta.value = '';
      const header = document.querySelector(`.intruder-payload-list-block[data-list="${i}"] .intruder-payload-list-label`);
      if (header) header.textContent = `Position ${i + 1} — 0 item(s)`;
    });
  });

  // Add list (pitchfork/cluster-bomb)
  document.getElementById('intruder-add-list')?.addEventListener('click', () => {
    _payloadLists.push([]);
    _render();
  });

  // Start
  document.getElementById('intruder-start-btn')?.addEventListener('click', _start);

  // Stop
  document.getElementById('intruder-stop-btn')?.addEventListener('click', () => {
    window.electronAPI.intruder.stop();
    _running = false;
    _render();
  });

  // Clear results
  document.getElementById('intruder-clear-results-btn')?.addEventListener('click', () => {
    _results   = [];
    _total     = 0;
    _completed = 0;
    _render();
  });

  // Right-click on result row → Send to Repeater
  document.querySelectorAll('.intruder-result-row[data-index]').forEach(row => {
    row.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      // Dispatch event for the repeater to pick up
      document.dispatchEvent(new CustomEvent('repeater:sendTo', {
        detail: { label: `Intruder #${Number(row.dataset.index) + 1}` }
      }));
    });
  });
}

// ─── Start attack ─────────────────────────────────────────────────────────────

async function _start() {
  const tmplEl    = document.getElementById('intruder-template');
  const urlEl     = document.getElementById('intruder-target-url');
  const concEl    = document.getElementById('intruder-concurrency');
  const delayEl   = document.getElementById('intruder-delay');
  const timeoutEl = document.getElementById('intruder-timeout');
  const transformSel = document.getElementById('intruder-transform');

  const template  = tmplEl?.value?.trim() ?? '';
  const targetUrl = urlEl?.value?.trim() ?? '';

  if (!template) { _showError('Paste a request template first.'); return; }
  if (!targetUrl) { _showError('Enter a target URL.'); return; }
  if (_countPositions(template) === 0) { _showError('No §position markers§ found. Wrap text with § to mark injection points.'); return; }

  // Sync payload lists from textareas
  _syncPayloadTextareas();

  const transforms = transformSel
    ? Array.from(transformSel.selectedOptions).map(o => o.value)
    : [];

  const opts = {
    rawTemplate:  template,
    targetUrl,
    attackType:   _attackType,
    payloadLists: _payloadLists,
    transforms,
    concurrency:  Number(concEl?.value ?? 10),
    delayMs:      Number(delayEl?.value ?? 0),
    timeoutMs:    Number(timeoutEl?.value ?? 15000),
  };

  _results   = [];
  _total     = 0;
  _completed = 0;
  _running   = true;

  // Update only button/progress state — do NOT call _render() as it wipes the template textarea
  const startBtn = document.getElementById('intruder-start-btn');
  const stopBtn  = document.getElementById('intruder-stop-btn');
  const clearBtn = document.getElementById('intruder-clear-results-btn');
  if (startBtn) { startBtn.disabled = true; startBtn.textContent = 'Running…'; }
  if (stopBtn)  stopBtn.disabled = false;
  if (clearBtn) clearBtn.disabled = true;
  const tbody = document.getElementById('intruder-results-body');
  if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="intruder-empty-row">No results yet. Configure and start an attack.</td></tr>`;
  const fill  = document.getElementById('intruder-progress-fill');
  const label = document.getElementById('intruder-progress-label');
  if (fill)  fill.style.width = '0%';
  if (label) label.textContent = 'Starting…';

  const resp = await window.electronAPI.intruder.start(opts);
  if (!resp.success) {
    _running = false;
    _showError(resp.error);
    _render();
  }
}

function _syncPayloadTextareas() {
  document.querySelectorAll('.intruder-payload-textarea[data-list]').forEach(ta => {
    const i = Number(ta.dataset.list);
    _payloadLists[i] = ta.value.split('\n').map(l => l.trim()).filter(Boolean);
  });
}

function _showError(msg) {
  const label = document.getElementById('intruder-progress-label');
  if (label) label.textContent = `⚠ ${msg}`;
}

// ─── Live updates ─────────────────────────────────────────────────────────────

function _appendResult(result) {
  _results.push(result);
  // Append row directly without full re-render for performance
  const tbody = document.getElementById('intruder-results-body');
  if (!tbody) return;

  // Remove empty-row if present
  const emptyRow = tbody.querySelector('.intruder-empty-row');
  emptyRow?.parentElement?.remove();

  const r   = result;
  const tr  = document.createElement('tr');
  tr.className = 'intruder-result-row';
  tr.dataset.index = r.index;
  tr.innerHTML = `
    <td class="intruder-td-num">${r.index + 1}</td>
    <td class="intruder-td-payload" title="${_esc(r.payloads?.join(' | '))}">${_esc(r.payloads?.join(' | ')?.slice(0,60))}</td>
    <td>${_statusBadge(r.statusCode)}</td>
    <td class="intruder-td-num">${r.length?.toLocaleString() ?? '—'}</td>
    <td class="intruder-td-num">${r.durationMs ?? '—'}ms</td>
    <td class="intruder-td-error">${_esc(r.error ?? '')}</td>
  `;
  tr.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    document.dispatchEvent(new CustomEvent('repeater:sendTo', { detail: { label: `Intruder #${r.index + 1}` } }));
  });
  tbody.appendChild(tr);
}

function _updateProgress(prog) {
  _completed = prog.completed;
  _total     = prog.total;
  const fill  = document.getElementById('intruder-progress-fill');
  const label = document.getElementById('intruder-progress-label');
  if (fill)  fill.style.width  = `${prog.percent}%`;
  if (label) label.textContent = `${prog.completed} / ${prog.total} (${prog.percent}%)`;
}

// ─── Built-in wordlist loading ────────────────────────────────────────────────

const _builtinCache = {};

async function _loadBuiltinWordlist(name) {
  if (_builtinCache[name]) return _builtinCache[name];
  const filemap = {
    passwords: 'passwords.txt',
    usernames: 'usernames.txt',
    sqli:      'sqli-payloads.txt',
    xss:       'xss-payloads.txt',
  };
  const filename = filemap[name];
  if (!filename) return [];
  // Read via file dialog isn't suitable — use a direct read via browseFile result is not ideal.
  // We use a pre-built load mechanism through webContents path resolution instead.
  // Fallback: inline minimal built-in lists.
  const inlineDefaults = {
    passwords: ['password','123456','admin','letmein','qwerty','abc123','welcome','monkey','dragon','master'],
    usernames: ['admin','administrator','root','user','test','guest','demo','operator','system','support'],
    sqli:      ["'","''","' OR '1'='1","' OR 1=1--","' OR 'x'='x","'; DROP TABLE users--","1 AND 1=1","1 AND 1=2","1' AND '1'='1","1 UNION SELECT NULL--"],
    xss:       ['<script>alert(1)</script>','"><img src=x onerror=alert(1)>',"'><svg onload=alert(1)>",'javascript:alert(1)','<body onload=alert(1)>','<details open ontoggle=alert(1)>'],
  };
  _builtinCache[name] = inlineDefaults[name] ?? [];
  return _builtinCache[name];
}

async function _readWordlistFile(filePath) {
  const result = await window.electronAPI.intruder.readWordlist(filePath).catch(() => null);
  return result?.success ? result.lines : null;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Pre-fill the intruder with a raw HTTP request.
 * Called via custom event 'intruder:sendTo'.
 */
export function openWithRequest(raw, url = '') {
  const intruderItem = document.querySelector('#webapp-sidebar .sidebar-item[data-panel="intruder"]');
  intruderItem?.click();

  setTimeout(() => {
    const tmplEl = document.getElementById('intruder-template');
    const urlEl  = document.getElementById('intruder-target-url');
    if (tmplEl) tmplEl.value = raw;
    if (urlEl && url) urlEl.value = url;
    const n = _countPositions(raw);
    const hintEl = document.getElementById('intruder-pos-hint');
    if (hintEl) hintEl.innerHTML = `Detected <strong>${n}</strong> position(s).`;
  }, 50);
}

export function init() {
  _container = document.getElementById('webapp-panel-intruder');
  if (!_container) return;

  _render();

  // Listen for IPC events
  window.electronAPI.intruder.onResult(result => {
    _appendResult(result);
  });

  window.electronAPI.intruder.onProgress(prog => {
    _updateProgress(prog);
  });

  window.electronAPI.intruder.onComplete(summary => {
    _running   = false;
    _completed = summary.completed;
    _total     = summary.total;
    const fill  = document.getElementById('intruder-progress-fill');
    const label = document.getElementById('intruder-progress-label');
    const startBtn = document.getElementById('intruder-start-btn');
    const stopBtn  = document.getElementById('intruder-stop-btn');
    if (fill)     fill.style.width   = '100%';
    if (label)    label.textContent  = `Done — ${summary.completed} requests sent`;
    if (startBtn) { startBtn.disabled = false; startBtn.textContent = '▶ Start Attack'; }
    if (stopBtn)  stopBtn.disabled = true;
  });

  window.electronAPI.intruder.onError(err => {
    _running = false;
    _showError(err.message);
    const startBtn = document.getElementById('intruder-start-btn');
    if (startBtn) { startBtn.disabled = false; startBtn.textContent = '▶ Start Attack'; }
  });

  // Cross-module pivot
  document.addEventListener('intruder:sendTo', (e) => {
    const { raw, url } = e.detail ?? {};
    openWithRequest(raw ?? '', url ?? '');
  });

  window.__openIntruderPanel = openWithRequest;
}
