/**
 * repeater.js — Repeater Renderer Module (Feature 7D)
 *
 * Tabbed HTTP request editor + response viewer.
 * Supports multiple independent tabs, request/response history navigation,
 * raw and pretty-print modes, and cross-module "Send to Repeater" integration.
 */

// ─── Tab state ────────────────────────────────────────────────────────────────

let _tabs        = [];   // [{ id, label, history: [{req, res}], historyIdx }]
let _activeTabId = null;
let _tabCounter  = 0;
let _container   = null;

function _newTab(label = null, initialRequest = null, targetUrl = '') {
  const id = ++_tabCounter;
  const tab = {
    id,
    label:      label ?? `Tab ${id}`,
    history:    initialRequest ? [{ req: initialRequest, res: null }] : [{ req: '', res: null }],
    historyIdx: 0,
    targetUrl,
  };
  _tabs.push(tab);
  return tab;
}

function _activeTab() {
  return _tabs.find(t => t.id === _activeTabId) ?? null;
}

function _currentEntry(tab) {
  return tab.history[tab.historyIdx] ?? { req: '', res: null };
}

// ─── DOM helpers ──────────────────────────────────────────────────────────────

function _esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function _statusClass(code) {
  if (!code)           return 'status-null';
  if (code < 300)      return 'status-2xx';
  if (code < 400)      return 'status-3xx';
  if (code < 500)      return 'status-4xx';
  return 'status-5xx';
}

function _prettyBody(body, headers) {
  if (!body) return '';
  const ct = (headers?.['content-type'] ?? '').toLowerCase();
  if (ct.includes('json')) {
    try { return JSON.stringify(JSON.parse(body), null, 2); } catch {}
  }
  return body;
}

// ─── Render ───────────────────────────────────────────────────────────────────

function _render() {
  if (!_container) return;

  const tab   = _activeTab();
  const entry = tab ? _currentEntry(tab) : { req: '', res: null };

  _container.innerHTML = `
    <div class="repeater-layout">
      <!-- Tab bar -->
      <div class="repeater-tabbar" id="repeater-tabbar">
        ${_tabs.map(t => `
          <button class="repeater-tab${t.id === _activeTabId ? ' active' : ''}" data-tab="${t.id}">
            <span class="repeater-tab-label">${_esc(t.label)}</span>
            <span class="repeater-tab-close" data-close="${t.id}">×</span>
          </button>
        `).join('')}
        <button class="repeater-tab-add" id="repeater-add-tab" title="New tab">＋</button>
      </div>

      ${tab ? `
      <!-- Editor area -->
      <div class="repeater-editor-area">
        <!-- Request pane -->
        <div class="repeater-pane repeater-pane-req">
          <div class="repeater-pane-header">
            <span class="repeater-pane-title">Request</span>
            <div class="repeater-pane-actions">
              <select class="repeater-method-select" id="repeater-method" title="Override method">
                ${['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'].map(m => `
                  <option value="${m}"${_getMethod(entry.req) === m ? ' selected' : ''}>${m}</option>
                `).join('')}
              </select>
              <input class="repeater-url-input" id="repeater-url" placeholder="https://target.com/path" value="${_esc(tab.targetUrl || _getUrl(entry.req))}">
            </div>
          </div>
          <textarea
            class="repeater-raw-editor"
            id="repeater-req-editor"
            spellcheck="false"
            autocomplete="off"
            placeholder="GET /api/example HTTP/1.1&#10;Host: target.com&#10;User-Agent: NetSpecter/1.0&#10;&#10;"
          >${_esc(entry.req)}</textarea>
        </div>

        <!-- Divider -->
        <div class="repeater-divider"></div>

        <!-- Response pane -->
        <div class="repeater-pane repeater-pane-res">
          <div class="repeater-pane-header">
            <span class="repeater-pane-title">Response</span>
            ${entry.res ? `
              <span class="repeater-status-badge ${_statusClass(entry.res.statusCode)}">
                ${entry.res.statusCode ?? '—'}
              </span>
              <span class="repeater-duration">${entry.res.durationMs}ms</span>
              <span class="repeater-length">${(entry.res.body?.length ?? 0).toLocaleString()} bytes</span>
            ` : ''}
            <div class="repeater-view-toggle">
              <button class="repeater-view-btn active" data-view="raw">Raw</button>
              <button class="repeater-view-btn" data-view="pretty">Pretty</button>
              <button class="repeater-view-btn" data-view="render">Render</button>
            </div>
          </div>
          <div class="repeater-res-body" id="repeater-res-body">
            ${entry.res
              ? `<pre class="repeater-raw-display" id="repeater-res-display">${_esc(entry.res.rawResponse ?? '')}</pre>`
              : `<div class="repeater-empty-res"><span>Hit Send to see the response</span></div>`
            }
          </div>
        </div>
      </div>

      <!-- Toolbar -->
      <div class="repeater-toolbar">
        <button class="btn webapp" id="repeater-send-btn">Send</button>
        <button class="btn repeater-cancel-btn" id="repeater-cancel-btn" style="display:none">Cancel</button>
        <div class="repeater-history-nav">
          <button class="btn repeater-nav-btn" id="repeater-prev" title="Previous request" ${tab.historyIdx === 0 ? 'disabled' : ''}>←</button>
          <span class="repeater-hist-label">${tab.historyIdx + 1} / ${tab.history.length}</span>
          <button class="btn repeater-nav-btn" id="repeater-next" title="Next request" ${tab.historyIdx >= tab.history.length - 1 ? 'disabled' : ''}>→</button>
        </div>
        <span class="repeater-send-status" id="repeater-send-status"></span>
      </div>
      ` : `
      <div class="repeater-empty-state">
        <div class="repeater-empty-icon">↩</div>
        <div class="repeater-empty-title">No tabs open</div>
        <div class="repeater-empty-sub">Click ＋ to open a new Repeater tab, or right-click a history entry and "Send to Repeater".</div>
      </div>
      `}
    </div>
  `;

  _bindEvents();
}

// ─── Event binding ────────────────────────────────────────────────────────────

function _bindEvents() {
  // Tab switching
  document.querySelectorAll('.repeater-tab[data-tab]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      if (e.target.dataset.close) return; // handled below
      _activeTabId = Number(btn.dataset.tab);
      _render();
    });
  });

  // Tab close
  document.querySelectorAll('.repeater-tab-close[data-close]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = Number(btn.dataset.close);
      _tabs = _tabs.filter(t => t.id !== id);
      if (_activeTabId === id) {
        _activeTabId = _tabs[_tabs.length - 1]?.id ?? null;
      }
      _render();
    });
  });

  // New tab
  document.getElementById('repeater-add-tab')?.addEventListener('click', () => {
    const tab = _newTab();
    _activeTabId = tab.id;
    _render();
  });

  // Send
  document.getElementById('repeater-send-btn')?.addEventListener('click', _send);

  // Cancel
  document.getElementById('repeater-cancel-btn')?.addEventListener('click', () => {
    _cancelSend();
  });

  // History nav
  document.getElementById('repeater-prev')?.addEventListener('click', () => {
    const tab = _activeTab();
    if (tab && tab.historyIdx > 0) { tab.historyIdx--; _render(); }
  });
  document.getElementById('repeater-next')?.addEventListener('click', () => {
    const tab = _activeTab();
    if (tab && tab.historyIdx < tab.history.length - 1) { tab.historyIdx++; _render(); }
  });

  // View toggle (raw/pretty/render)
  document.querySelectorAll('.repeater-view-btn[data-view]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.repeater-view-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _switchView(btn.dataset.view);
    });
  });
}

// ─── Send ─────────────────────────────────────────────────────────────────────

let _sending = false;

async function _send() {
  if (_sending) return;
  const tab = _activeTab();
  if (!tab) return;

  const editor    = document.getElementById('repeater-req-editor');
  const urlInput  = document.getElementById('repeater-url');
  const statusEl  = document.getElementById('repeater-send-status');
  const sendBtn   = document.getElementById('repeater-send-btn');
  const cancelBtn = document.getElementById('repeater-cancel-btn');

  const raw = editor?.value?.trim() ?? '';
  const url = urlInput?.value?.trim() ?? '';

  if (!url) {
    if (statusEl) statusEl.textContent = '⚠ Enter a target URL';
    return;
  }

  _sending = true;
  if (sendBtn)   { sendBtn.disabled = true; sendBtn.textContent = 'Sending…'; }
  if (cancelBtn) cancelBtn.style.display = '';
  if (statusEl)  statusEl.textContent = '';

  try {
    const resp = await window.electronAPI.repeater.send({ url, rawRequest: raw });

    const entry = _currentEntry(tab);
    const newEntry = { req: raw, res: resp.success ? resp : null };

    // If we're not at the latest, truncate forward history
    tab.history = tab.history.slice(0, tab.historyIdx + 1);
    tab.history[tab.historyIdx] = { ...entry, req: raw };  // update req in current entry
    tab.history.push(newEntry);
    tab.historyIdx = tab.history.length - 1;

    if (!resp.success && statusEl) {
      statusEl.textContent = `⚠ ${resp.error}`;
    }
  } catch (err) {
    if (statusEl) statusEl.textContent = `⚠ ${err.message}`;
  } finally {
    _sending = false;
    if (sendBtn)   { sendBtn.disabled = false; sendBtn.textContent = 'Send'; }
    if (cancelBtn) cancelBtn.style.display = 'none';
    _render();
  }
}

function _cancelSend() {
  // No per-request abort exposed yet; just mark done
  _sending = false;
}

// ─── View switching ───────────────────────────────────────────────────────────

function _switchView(mode) {
  const tab   = _activeTab();
  const entry = tab ? _currentEntry(tab) : null;
  const body  = document.getElementById('repeater-res-body');
  const res   = entry?.res;

  if (!body || !res) return;

  if (mode === 'raw') {
    body.innerHTML = `<pre class="repeater-raw-display">${_esc(res.rawResponse ?? '')}</pre>`;
  } else if (mode === 'pretty') {
    const pretty = _prettyBody(res.body ?? '', res.headers ?? {});
    body.innerHTML = `<pre class="repeater-raw-display">${_esc(pretty)}</pre>`;
  } else if (mode === 'render') {
    // Use srcdoc — avoids ERR_BLOCKED_BY_CSP from data: URL navigation.
    // srcdoc sets iframe content directly as a DOM property (no URL load),
    // so frame-src CSP does not apply. Drop allow-same-origin so the sandboxed
    // null-origin frame cannot reach back into the parent document.
    body.innerHTML = '';
    const frame = document.createElement('iframe');
    frame.className  = 'repeater-render-frame';
    frame.sandbox    = 'allow-scripts allow-forms';
    frame.srcdoc     = res.body ?? '';
    body.appendChild(frame);
  }
}

// ─── Parse helpers ────────────────────────────────────────────────────────────

function _getMethod(raw) {
  const first = (raw ?? '').split(/[\r\n]/)[0]?.trim() ?? '';
  return first.split(/\s+/)[0] ?? 'GET';
}

/**
 * Best-effort: reconstruct a full URL from a raw HTTP request string.
 * Parses the request line for the path and the Host header for the hostname.
 * Defaults to https since most targets are TLS; caller may override via tab.targetUrl.
 */
function _getUrl(raw) {
  if (!raw) return '';
  const lines = raw.split(/\r?\n/);
  const requestLine = lines[0]?.trim() ?? '';
  const parts = requestLine.split(/\s+/);
  const path  = parts[1] ?? '/';

  // Find Host header (case-insensitive)
  const hostLine = lines.find(l => /^host\s*:/i.test(l));
  const host = hostLine ? hostLine.replace(/^host\s*:\s*/i, '').trim() : '';

  if (!host) return path; // no host — return bare path as fallback
  return `https://${host}${path === '*' ? '' : path}`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Open a new Repeater tab pre-filled with a raw HTTP request.
 * Called via CustomEvent 'repeater:sendTo' or window.__openRepeaterTab().
 */
export function openTab(rawRequest, label = null, targetUrl = '') {
  const tab = _newTab(label, rawRequest, targetUrl);
  _activeTabId = tab.id;

  // Switch webapp sidebar to the repeater panel
  const repeaterItem = document.querySelector('#webapp-sidebar .sidebar-item[data-panel="repeater"]');
  repeaterItem?.click();

  _render();
}

export function init() {
  _container = document.getElementById('webapp-panel-repeater');
  if (!_container) return;

  // Start with one empty tab
  const tab = _newTab('Tab 1');
  _activeTabId = tab.id;
  _render();

  // Listen for "Send to Repeater" events dispatched by other modules
  document.addEventListener('repeater:sendTo', (e) => {
    const { raw, url, label } = e.detail ?? {};
    openTab(raw ?? '', label ?? null, url ?? '');
  });

  window.__openRepeaterTab = openTab;
}
