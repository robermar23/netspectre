/**
 * proxy.js — Web App Workspace: HTTP Proxy UI Module
 * Handles HTTP History table, Request/Response Inspector,
 * Intercept panel, and WebSocket history.
 */

import { api } from '../../api.js';
import { state } from '../../state.js';

// ─── DOM refs ──────────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

// Controls
const btnStart         = $('btn-proxy-start');
const btnStop          = $('btn-proxy-stop');
const portInput        = $('proxy-port-input');
const interceptToggle  = $('proxy-intercept-toggle');
const interceptLabel   = $('proxy-intercept-toggle')?.closest('label');
const proxyDot         = $('proxy-dot');
const statusLabel      = $('proxy-status-label');
const btnClearHistory  = $('btn-proxy-clear-history');
const btnExportHar     = $('btn-proxy-export-har');
const btnCa            = $('btn-proxy-ca');

// Consent modal
const consentOverlay   = $('proxy-consent-overlay');
const consentInput     = $('proxy-consent-input');
const btnConsentAccept = $('btn-proxy-consent-accept');
const btnConsentReject = $('btn-proxy-consent-reject');
const btnCloseConsent  = $('btn-close-proxy-consent');

// CA modal
const caModal          = $('proxy-ca-modal');
const caPathText       = $('proxy-ca-path-text');
const caResultDiv      = $('proxy-ca-result');
const btnCaInstall     = $('btn-proxy-ca-install');
const btnCaCancel      = $('btn-proxy-ca-cancel');
const btnCloseCaModal  = $('btn-close-proxy-ca-modal');

// Sub-tabs
const subtabBtns       = document.querySelectorAll('.proxy-subtab');
const subtabHistory    = $('proxy-subtab-history');
const subtabIntercept  = $('proxy-subtab-intercept');
const subtabWebsocket  = $('proxy-subtab-websocket');

// Filter bar
const filterHost       = $('proxy-filter-host');
const filterMethod     = $('proxy-filter-method');
const filterStatus     = $('proxy-filter-status');
const filterSearch     = $('proxy-filter-search');
const btnFilterApply   = $('btn-proxy-filter-apply');
const btnFilterClear   = $('btn-proxy-filter-clear');

// History table (virtual scroll)
const historyWrapper   = $('proxy-history-wrapper');
const historyViewport  = $('proxy-history-viewport');
const historySpacer    = $('proxy-history-spacer');
const historyRows      = $('proxy-history-rows');
const historyEmpty     = $('proxy-history-empty');
const contextMenu      = $('proxy-context-menu');

// Inspector
const inspector        = $('proxy-inspector');
const inspectorTitle   = $('proxy-inspector-title');
const btnCloseInspector = $('btn-proxy-inspector-close');
const viewTabBtns      = document.querySelectorAll('.view-tab');
const reqRaw           = $('proxy-req-raw');
const reqHeaders       = $('proxy-req-headers');
const reqParams        = $('proxy-req-params');
const reqBody          = $('proxy-req-body');
const resRaw           = $('proxy-res-raw');
const resHeaders       = $('proxy-res-headers');
const resBody          = $('proxy-res-body');

// Intercept subtab
const interceptEmpty   = $('proxy-intercept-empty');
const interceptEditor  = $('proxy-intercept-editor');
const interceptLabel2  = $('intercept-request-label');
const interceptTextarea = $('proxy-intercept-textarea');
const btnForward       = $('btn-intercept-forward');
const btnForwardAll    = $('btn-intercept-forward-all');
const btnDrop          = $('btn-intercept-drop');
const interceptBadge   = $('intercept-queue-badge');
const globalInterceptBadge = $('proxy-intercept-badge');

// WebSocket subtab
const wsEmpty          = $('proxy-ws-empty');
const wsContainer      = $('proxy-ws-container');
const wsSessions       = $('proxy-ws-sessions');
const wsFrames         = $('proxy-ws-frames');

// ─── Constants ─────────────────────────────────────────────────────────────────

const ROW_HEIGHT = 32;    // px — fixed height for virtual scroll
const VISIBLE_BUFFER = 5; // extra rows above/below visible area

// ─── Local State ───────────────────────────────────────────────────────────────

let allRows          = [];   // full, unfiltered history
let filteredRows     = [];   // after applying filter
let scrollTop        = 0;
let viewportHeight   = 0;
let selectedRowId    = null;
let interceptQueue   = [];   // [{id, rawText, originalRaw}]
let currentIntercept = null; // currently displayed intercept item
let activeSubtab     = 'history';
let activeView       = 'raw';  // inspector view: raw | headers | params | body
let wsBySession      = new Map();  // sessionId -> {hostname, frames[]}
let selectedWsSession = null;

/** DNS resolution cache shared within this module: hostname → IPv4 (or null) */
const _dnsCache = new Map();

// ─── Public API ────────────────────────────────────────────────────────────────

export function init() {
  if (!btnStart) return; // DOM not present (workspace not loaded)

  // Move context menu to <body> so that backdrop-filter / transform on
  // ancestor panels doesn't break position:fixed viewport coordinates.
  if (contextMenu && contextMenu.parentElement !== document.body) {
    document.body.appendChild(contextMenu);
  }

  _wireConsentModal();
  _wireProxyControls();
  _wireSubtabs();
  _wireFilters();
  _wireHistoryTable();
  _wireInspector();
  _wireInterceptPanel();
  _wireWebSocketPanel();
  _wireCaModal();
  _wireIpcListeners();
  _restoreProxyStatus();
}

// ─── Consent Gate ──────────────────────────────────────────────────────────────

function _wireConsentModal() {
  consentInput?.addEventListener('input', () => {
    if (btnConsentAccept) {
      btnConsentAccept.disabled = consentInput.value.trim() !== 'I UNDERSTAND';
    }
  });

  btnConsentAccept?.addEventListener('click', () => {
    state.proxy.consentAccepted = true;
    consentOverlay?.classList.add('hidden');
    _doStartProxy();
  });

  btnConsentReject?.addEventListener('click', () => {
    consentOverlay?.classList.add('hidden');
    if (consentInput) consentInput.value = '';
    if (btnConsentAccept) btnConsentAccept.disabled = true;
  });

  btnCloseConsent?.addEventListener('click', () => {
    consentOverlay?.classList.add('hidden');
    if (consentInput) consentInput.value = '';
    if (btnConsentAccept) btnConsentAccept.disabled = true;
  });
}

// ─── Proxy Controls ────────────────────────────────────────────────────────────

function _wireProxyControls() {
  btnStart?.addEventListener('click', () => {
    if (!state.proxy.consentAccepted) {
      if (consentInput) consentInput.value = '';
      if (btnConsentAccept) btnConsentAccept.disabled = true;
      consentOverlay?.classList.remove('hidden');
    } else {
      _doStartProxy();
    }
  });

  btnStop?.addEventListener('click', async () => {
    await api.proxy.stop();
  });

  interceptToggle?.addEventListener('change', async () => {
    const enabled = interceptToggle.checked;
    state.proxy.interceptMode = enabled;
    await api.proxy.setIntercept(enabled);
    _updateInterceptUI();
  });

  btnClearHistory?.addEventListener('click', async () => {
    await api.proxy.clearHistory();
    allRows = [];
    filteredRows = [];
    _renderVirtualRows();
    _showEmptyState(true);
  });

  btnExportHar?.addEventListener('click', async () => {
    const result = await api.proxy.exportHar([]);
    if (result.success) {
      const blob = new Blob([JSON.stringify(result.har, null, 2)], { type: 'application/json' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `netspecter-proxy-${Date.now()}.har`;
      a.click();
      URL.revokeObjectURL(url);
    }
  });

  btnCa?.addEventListener('click', async () => {
    const paths = await api.proxy.getCaPath();
    if (caPathText) caPathText.textContent = paths.certPath ?? '(Start proxy first to generate CA)';
    if (caResultDiv) { caResultDiv.style.display = 'none'; caResultDiv.textContent = ''; }
    caModal?.classList.remove('hidden');
  });
}

async function _doStartProxy() {
  const port = parseInt(portInput?.value, 10) || 8888;
  if (port < 1024 || port > 65535) {
    _showStatusError('Port must be between 1024 and 65535.');
    return;
  }

  _setRunning(null); // transitioning
  const result = await api.proxy.start({ port, intercept: interceptToggle?.checked ?? false });
  if (result.success) {
    state.proxy.running = true;
    state.proxy.port    = port;
    _setRunning(true);
  } else {
    _showStatusError(result.error ?? 'Failed to start proxy.');
    _setRunning(false);
  }
}

function _setRunning(running) {
  if (running === true) {
    if (proxyDot) { proxyDot.className = 'proxy-status-dot running'; proxyDot.title = 'Proxy running'; }
    if (statusLabel) statusLabel.textContent = `Running on :${state.proxy.port}`;
    if (btnStart) btnStart.disabled = true;
    if (btnStop)  btnStop.disabled  = false;
    if (portInput) portInput.disabled = true;
  } else if (running === false) {
    if (proxyDot) { proxyDot.className = 'proxy-status-dot'; proxyDot.title = 'Proxy stopped'; }
    if (statusLabel) statusLabel.textContent = 'Stopped';
    if (btnStart) btnStart.disabled = false;
    if (btnStop)  btnStop.disabled  = true;
    if (portInput) portInput.disabled = false;
  } else {
    // transitioning
    if (proxyDot) { proxyDot.className = 'proxy-status-dot transitioning'; }
    if (statusLabel) statusLabel.textContent = 'Starting…';
    if (btnStart) btnStart.disabled = true;
    if (btnStop)  btnStop.disabled  = true;
  }
}

function _showStatusError(msg) {
  if (statusLabel) {
    statusLabel.textContent = `Error: ${msg}`;
    statusLabel.style.color = 'var(--danger)';
    setTimeout(() => { if (statusLabel) statusLabel.style.color = ''; }, 4000);
  }
}

async function _restoreProxyStatus() {
  try {
    const status = await api.proxy.getStatus();
    if (status.running) {
      state.proxy.running = true;
      state.proxy.port    = status.port;
      _setRunning(true);
      // Load persisted history
      await _refreshHistory();
    }
  } catch (e) {
    // Proxy not available yet — ignore
  }
}

// ─── Sub-tabs ──────────────────────────────────────────────────────────────────

function _wireSubtabs() {
  subtabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.subtab;
      subtabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeSubtab = tab;

      // Show/hide subtab content + filter bar
      if (subtabHistory)  subtabHistory.style.display  = tab === 'history'   ? 'flex' : 'none';
      if (subtabIntercept) subtabIntercept.style.display = tab === 'intercept' ? 'flex' : 'none';
      if (subtabWebsocket) subtabWebsocket.style.display = tab === 'websocket' ? 'flex' : 'none';

      const filterBar = $('proxy-filter-bar');
      if (filterBar) filterBar.style.display = tab === 'history' ? 'flex' : 'none';
    });
  });
}

// ─── Filter Bar ────────────────────────────────────────────────────────────────

function _wireFilters() {
  btnFilterApply?.addEventListener('click', _applyFilter);
  btnFilterClear?.addEventListener('click', () => {
    if (filterHost)   filterHost.value   = '';
    if (filterMethod) filterMethod.value = '';
    if (filterStatus) filterStatus.value = '';
    if (filterSearch) filterSearch.value = '';
    filteredRows = [...allRows];
    _renderVirtualRows();
  });
  filterSearch?.addEventListener('keydown', e => { if (e.key === 'Enter') _applyFilter(); });
}

function _applyFilter() {
  const host   = filterHost?.value.trim().toLowerCase()  || '';
  const method = filterMethod?.value.trim().toUpperCase() || '';
  const status = filterStatus?.value.trim()               || '';
  const search = filterSearch?.value.trim().toLowerCase() || '';

  filteredRows = allRows.filter(r => {
    if (host   && !r.host?.toLowerCase().includes(host))    return false;
    if (method && r.method !== method)                       return false;
    if (status && String(r.statusCode) !== status)           return false;
    if (search && !r.url?.toLowerCase().includes(search))   return false;
    return true;
  });
  _renderVirtualRows();
}

// ─── Network Workspace Pivot ───────────────────────────────────────────────────

/**
 * Resolve a proxy row's host to an IPv4 address, inject it into the network
 * workspace host list, and switch to the Network tab.
 */
async function _probeHostInNetwork(host) {
  if (!host) return;

  let ip = _dnsCache.get(host);
  if (ip === undefined) {
    try {
      const res = await api.resolveHostname(host);
      ip = res?.success ? res.ip : null;
    } catch { ip = null; }
    _dnsCache.set(host, ip);
  }

  const resolvedIp = ip || host; // fall back to treating host as an IP

  const existing = (state.hosts || []).find(h => h.ip === resolvedIp);
  if (!existing) {
    const newHost = {
      ip:       resolvedIp,
      hostname: resolvedIp !== host ? host : null,
      source:   'proxy',
      ports:    [],
    };
    if (!state.hosts) state.hosts = [];
    state.hosts.push(newHost);
    window.dispatchEvent(new CustomEvent('network:hostAdded', { detail: newHost }));
  }

  document.querySelector('.workspace-tab[data-workspace="network"]')?.click();
}

// ─── Virtual Scroll History Table ──────────────────────────────────────────────

function _wireHistoryTable() {
  historyViewport?.addEventListener('scroll', () => {
    scrollTop = historyViewport.scrollTop;
    _renderVirtualRows();
  });

  // Right-click context menu
  historyViewport?.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    const row = e.target.closest('[data-row-id]');
    if (!row) { contextMenu?.classList.add('hidden'); return; }
    selectedRowId = row.dataset.rowId;
    if (contextMenu) {
      contextMenu.style.left = `${e.clientX}px`;
      contextMenu.style.top  = `${e.clientY}px`;
      contextMenu.classList.remove('hidden');
    }
  });

  document.addEventListener('click', () => contextMenu?.classList.add('hidden'));

  // Inject "Probe in Network" item into context menu
  if (contextMenu) {
    const probeItem = document.createElement('div');
    probeItem.className = 'context-menu-item';
    probeItem.dataset.action = 'probe-network';
    probeItem.textContent = '🌐 Probe in Network';
    contextMenu.appendChild(probeItem);
  }

  contextMenu?.addEventListener('click', (e) => {
    const action = e.target.closest('[data-action]')?.dataset.action;
    if (!action || !selectedRowId) return;
    contextMenu.classList.add('hidden');
    if (action === 'delete') {
      api.proxy.deleteRequest(selectedRowId);
      allRows = allRows.filter(r => r.id !== selectedRowId);
      filteredRows = filteredRows.filter(r => r.id !== selectedRowId);
      _renderVirtualRows();
    } else if (action === 'probe-network') {
      const row = allRows.find(r => r.id === selectedRowId);
      if (row?.host) _probeHostInNetwork(row.host);
    } else if (action === 'repeater') {
      const row = allRows.find(r => r.id === selectedRowId);
      if (row) {
        const raw   = _buildRawText(row);
        const url   = `${row.protocol || 'http'}://${row.host}${row.path ?? '/'}${row.query ? '?' + row.query : ''}`;
        const label = `${row.method} ${row.path ?? '/'}`;
        document.dispatchEvent(new CustomEvent('repeater:sendTo', { detail: { raw, url, label } }));
      }
    } else if (action === 'intruder') {
      const row = allRows.find(r => r.id === selectedRowId);
      if (row) {
        const raw = _buildRawText(row);
        const url = `${row.protocol || 'http'}://${row.host}${row.path ?? '/'}${row.query ? '?' + row.query : ''}`;
        document.dispatchEvent(new CustomEvent('intruder:sendTo', { detail: { raw, url } }));
      }
    } else if (action === 'scanner') {
      const row = allRows.find(r => r.id === selectedRowId);
      if (row) {
        const url = `${row.protocol || 'http'}://${row.host}${row.path ?? '/'}${row.query ? '?' + row.query : ''}`;
        window.__openScannerPanel?.(url);
      }
    } else if (action === 'sitemap') {
      const row = allRows.find(r => r.id === selectedRowId);
      if (row) {
        const url = `${row.protocol || 'http'}://${row.host}${row.path ?? '/'}${row.query ? '?' + row.query : ''}`;
        window.__openSitemapTarget?.(url);
      }
    }
  });
}

function _appendToHistory(record) {
  allRows.unshift(record);
  filteredRows.unshift(record); // prepend — newest first
  _showEmptyState(false);
  _renderVirtualRows();
}

async function _refreshHistory() {
  try {
    const filter = {};
    const result = await api.proxy.getHistory(filter);
    if (result.success) {
      allRows = result.rows;
      filteredRows = [...allRows];
      _showEmptyState(allRows.length === 0);
      _renderVirtualRows();
    }
  } catch {}
}

function _showEmptyState(empty) {
  if (historyEmpty)   historyEmpty.style.display   = empty ? 'flex' : 'none';
  if (historyViewport) historyViewport.style.display = empty ? 'none' : 'block';
}

function _renderVirtualRows() {
  if (!historyViewport || !historySpacer || !historyRows) return;
  viewportHeight = historyViewport.clientHeight;

  const total     = filteredRows.length;
  const totalH    = total * ROW_HEIGHT;
  historySpacer.style.height = `${totalH}px`;

  const firstVisible = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - VISIBLE_BUFFER);
  const lastVisible  = Math.min(total - 1, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + VISIBLE_BUFFER);

  historyRows.innerHTML = '';

  for (let i = firstVisible; i <= lastVisible; i++) {
    const row = filteredRows[i];
    if (!row) continue;
    const el = _createRowEl(row, i + 1);
    el.style.top = `${i * ROW_HEIGHT}px`;
    historyRows.appendChild(el);
  }
}

function _createRowEl(row, num) {
  const el = document.createElement('div');
  el.className   = `proxy-table-row${row.id === selectedRowId ? ' selected' : ''}`;
  el.dataset.rowId = row.id;
  el.style.position = 'absolute';
  el.style.left = '0';
  el.style.right = '0';
  el.style.height = `${ROW_HEIGHT}px`;

  const method = row.method ?? '?';
  const status = row.statusCode;
  const methodClass = `method-${method.toLowerCase()}`;
  const statusClass = status >= 500 ? 'status-5xx' : status >= 400 ? 'status-4xx' :
                      status >= 300 ? 'status-3xx' : status >= 200 ? 'status-2xx' : 'status-other';

  el.innerHTML = `
    <div class="ph-col ph-num">${num}</div>
    <div class="ph-col ph-method"><span class="method-badge ${methodClass}">${_esc(method)}</span></div>
    <div class="ph-col ph-host"  title="${_esc(row.host ?? '')}">${_esc(row.host ?? '')}</div>
    <div class="ph-col ph-path"  title="${_esc(row.path ?? '')}">${_esc(row.path ?? '/')}</div>
    <div class="ph-col ph-status"><span class="status-badge ${statusClass}">${status ?? '—'}</span></div>
    <div class="ph-col ph-length">${_fmtBytes(row.responseLength)}</div>
    <div class="ph-col ph-mime"  title="${_esc(row.mimeType ?? '')}">${_esc(_shortMime(row.mimeType))}</div>
    <div class="ph-col ph-time">${row.durationMs != null ? `${row.durationMs}ms` : '—'}</div>
    <div class="ph-col ph-notes">${_esc(row.notes ?? '')}</div>
  `;

  el.addEventListener('click', () => _selectRow(row.id));
  return el;
}

async function _selectRow(id) {
  selectedRowId = id;
  _renderVirtualRows(); // Re-render to highlight selected
  inspector?.classList.remove('hidden');

  inspectorTitle && (inspectorTitle.textContent = 'Loading…');

  try {
    const result = await api.proxy.getRequest(id);
    if (!result.success) return;
    const row = result.row;
    state.selectedRequest = row;
    _populateInspector(row);
  } catch (e) {
    console.error('[Proxy] Failed to load request detail:', e);
  }
}

// ─── Inspector ─────────────────────────────────────────────────────────────────

function _wireInspector() {
  // Add "Probe in Network" button to the inspector toolbar, before the close button
  if (btnCloseInspector?.parentElement) {
    const probeBtn = document.createElement('button');
    probeBtn.className = 'btn-probe-network';
    probeBtn.title = 'Resolve this host to IP and add to Network workspace';
    probeBtn.innerHTML = '&#127760; Probe in Network';
    probeBtn.addEventListener('click', () => {
      const host = state.selectedRequest?.host;
      if (host) _probeHostInNetwork(host);
    });
    btnCloseInspector.parentElement.insertBefore(probeBtn, btnCloseInspector);
  }

  btnCloseInspector?.addEventListener('click', () => {
    inspector?.classList.add('hidden');
    selectedRowId = null;
    _renderVirtualRows();
  });

  viewTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      viewTabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeView = btn.dataset.view;
      if (state.selectedRequest) _populateInspector(state.selectedRequest);
    });
  });

  // Resizable inspector panes
  const handle = $('inspector-resize-handle');
  const panes  = inspector?.querySelectorAll('.proxy-inspector-pane');
  if (handle && panes && panes.length === 2) {
    let dragging = false;
    handle.addEventListener('mousedown', () => { dragging = true; document.body.style.cursor = 'col-resize'; });
    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      const container = handle.parentElement;
      const rect = container.getBoundingClientRect();
      const leftPct = ((e.clientX - rect.left) / rect.width * 100).toFixed(1);
      panes[0].style.flex = `0 0 ${leftPct}%`;
      panes[1].style.flex = `0 0 ${100 - leftPct}%`;
    });
    document.addEventListener('mouseup', () => { dragging = false; document.body.style.cursor = ''; });
  }
}

function _populateInspector(row) {
  if (!row) return;
  if (inspectorTitle) inspectorTitle.textContent = `${row.method} ${row.url}`;

  // Decode base64 bodies
  const reqBodyStr = row.requestBody  ? atob(row.requestBody)  : '';
  const resBodyStr = row.responseBody ? atob(row.responseBody) : '';

  const reqHeaderStr = _formatHeaderList(row.requestHeaders  || []);
  const resHeaderStr = _formatHeaderList(row.responseHeaders || []);

  if (activeView === 'raw') {
    if (reqRaw) reqRaw.textContent = reqHeaderStr + (reqBodyStr ? '\n\n' + reqBodyStr : '');
    if (resRaw) resRaw.textContent = resHeaderStr + (resBodyStr ? '\n\n' + resBodyStr : '');
    _showInspectorView('raw');
  } else if (activeView === 'headers') {
    if (reqHeaders) reqHeaders.innerHTML = _renderHeaderTable(row.requestHeaders  || []);
    if (resHeaders) resHeaders.innerHTML = _renderHeaderTable(row.responseHeaders || []);
    _showInspectorView('headers');
  } else if (activeView === 'params') {
    if (reqParams) reqParams.innerHTML = _renderParamsTable(row.query || '');
    _showInspectorView('params');
  } else if (activeView === 'body') {
    if (reqBody) reqBody.textContent = _prettyBody(reqBodyStr, _getHeader(row.requestHeaders, 'content-type'));
    if (resBody) resBody.textContent = _prettyBody(resBodyStr, row.mimeType ?? '');
    _showInspectorView('body');
  }
}

function _showInspectorView(view) {
  const paneEls = [
    { el: reqRaw,     v: 'raw' },
    { el: reqHeaders, v: 'headers' },
    { el: reqParams,  v: 'params' },
    { el: reqBody,    v: 'body' },
    { el: resRaw,     v: 'raw' },
    { el: resHeaders, v: 'headers' },
    { el: resBody,    v: 'body' },
  ];
  paneEls.forEach(({ el, v }) => {
    if (el) el.style.display = v === view ? 'block' : 'none';
  });
}

// ─── Intercept Panel ──────────────────────────────────────────────────────────

function _wireInterceptPanel() {
  btnForward?.addEventListener('click', async () => {
    if (!currentIntercept) return;
    const id  = currentIntercept.id;
    const raw = interceptTextarea?.value ?? null;
    await api.proxy.forward(id, raw !== currentIntercept.originalRaw ? raw : null);
    _dequeueIntercept(id);
  });

  btnForwardAll?.addEventListener('click', async () => {
    // Disable intercept, flush queue
    if (interceptToggle) interceptToggle.checked = false;
    state.proxy.interceptMode = false;
    await api.proxy.setIntercept(false);
    // Forward all remaining
    for (const item of [...interceptQueue]) {
      await api.proxy.forward(item.id, null);
    }
    interceptQueue = [];
    currentIntercept = null;
    _updateInterceptUI();
  });

  btnDrop?.addEventListener('click', async () => {
    if (!currentIntercept) return;
    await api.proxy.drop(currentIntercept.id);
    _dequeueIntercept(currentIntercept.id);
  });
}

function _enqueueIntercept(record) {
  // Build raw request text for display
  const rawText = _buildRawText(record);
  const item = { id: record.id, rawText, originalRaw: rawText, record };
  interceptQueue.push(item);
  _updateInterceptUI();
  if (!currentIntercept) _showNextIntercept();
}

function _dequeueIntercept(id) {
  interceptQueue = interceptQueue.filter(i => i.id !== id);
  currentIntercept = null;
  _showNextIntercept();
}

function _showNextIntercept() {
  if (interceptQueue.length === 0) {
    currentIntercept = null;
    if (interceptEmpty)  interceptEmpty.style.display  = 'flex';
    if (interceptEditor) interceptEditor.style.display = 'none';
    return;
  }
  currentIntercept = interceptQueue[0];
  if (interceptLabel2) interceptLabel2.textContent = `#${currentIntercept.id.slice(0, 8)} — ${currentIntercept.record.method} ${currentIntercept.record.url}`;
  if (interceptTextarea) {
    interceptTextarea.value = currentIntercept.rawText;
    interceptTextarea.dataset.originalRaw = currentIntercept.rawText;
  }
  if (interceptEmpty)  interceptEmpty.style.display  = 'none';
  if (interceptEditor) interceptEditor.style.display = 'flex';
}

function _updateInterceptUI() {
  const queueLen = interceptQueue.length;

  if (interceptBadge) {
    interceptBadge.textContent = queueLen > 0 ? String(queueLen) : '';
    interceptBadge.style.display = queueLen > 0 ? 'inline-flex' : 'none';
  }
  if (globalInterceptBadge) {
    globalInterceptBadge.textContent = queueLen > 0 ? String(queueLen) : '';
    globalInterceptBadge.style.display = queueLen > 0 ? 'inline-flex' : 'none';
    // Add pulse animation when intercept is active
    globalInterceptBadge.className = queueLen > 0 ? 'intercept-badge pulse' : 'intercept-badge';
  }

  const interceptOn = state.proxy.interceptMode;
  if (interceptEmpty) {
    interceptEmpty.style.display = (interceptOn && queueLen === 0) ? 'flex' : 'none';
    if (!interceptOn) interceptEmpty.textContent = 'Intercept mode is off.';
    else interceptEmpty.textContent = 'Waiting for a request…';
  }
}

// ─── WebSocket Panel ──────────────────────────────────────────────────────────

function _wireWebSocketPanel() {}

function _addWsFrame(frame) {
  const { sessionId, direction, hostname, timestamp, preview, isBinary } = frame;

  if (!wsBySession.has(sessionId)) {
    wsBySession.set(sessionId, { hostname, frames: [], el: null });
    _renderWsSessions();
  }

  const session = wsBySession.get(sessionId);
  session.frames.push(frame);

  if (wsEmpty) wsEmpty.style.display = 'none';
  if (wsContainer) wsContainer.style.display = 'flex';

  if (selectedWsSession === sessionId) {
    _appendWsFrameEl(frame);
  }
}

function _renderWsSessions() {
  if (!wsSessions) return;
  wsSessions.innerHTML = '';
  for (const [sid, sess] of wsBySession) {
    const el = document.createElement('div');
    el.className = `ws-session-item${sid === selectedWsSession ? ' selected' : ''}`;
    el.textContent = `${sess.hostname} (${sess.frames.length} frames)`;
    el.addEventListener('click', () => {
      selectedWsSession = sid;
      _renderWsSessions();
      _renderWsFrames(sid);
    });
    wsSessions.appendChild(el);
  }
}

function _renderWsFrames(sessionId) {
  if (!wsFrames) return;
  wsFrames.innerHTML = '';
  const session = wsBySession.get(sessionId);
  if (!session) return;
  session.frames.forEach(f => _appendWsFrameEl(f));
}

function _appendWsFrameEl(frame) {
  if (!wsFrames) return;
  const el = document.createElement('div');
  el.className = `ws-frame ${frame.direction === 'client->server' ? 'ws-out' : 'ws-in'}`;
  const time = new Date(frame.timestamp).toLocaleTimeString();
  el.innerHTML = `
    <span class="ws-frame-dir">${frame.direction === 'client->server' ? '→' : '←'}</span>
    <span class="ws-frame-time">${time}</span>
    <span class="ws-frame-preview">${_esc(frame.preview?.slice(0, 200) ?? '')}</span>
    <span class="ws-frame-len">${frame.length}B${frame.isBinary ? ' [binary]' : ''}</span>
  `;
  wsFrames.appendChild(el);
  wsFrames.scrollTop = wsFrames.scrollHeight;
}

// ─── CA Modal ─────────────────────────────────────────────────────────────────

function _wireCaModal() {
  btnCaInstall?.addEventListener('click', async () => {
    if (btnCaInstall) btnCaInstall.disabled = true;
    const result = await api.proxy.installCa();
    if (caResultDiv) {
      caResultDiv.style.display = 'block';
      caResultDiv.textContent   = result.message ?? result.error ?? 'Done.';
      caResultDiv.style.color   = result.success ? 'var(--success)' : 'var(--danger)';
    }
    if (btnCaInstall) btnCaInstall.disabled = false;
  });

  btnCaCancel?.addEventListener('click', () => caModal?.classList.add('hidden'));
  btnCloseCaModal?.addEventListener('click', () => caModal?.classList.add('hidden'));
}

// ─── IPC Listeners ─────────────────────────────────────────────────────────────

function _wireIpcListeners() {
  api.proxy.onStatus((status) => {
    state.proxy.running = status.running;
    state.proxy.port    = status.port ?? state.proxy.port;
    _setRunning(status.running);
  });

  api.proxy.onRequest((record) => {
    _appendToHistory(record);
  });

  api.proxy.onIntercepted((record) => {
    // Switch to intercept subtab automatically
    if (activeSubtab !== 'intercept') {
      const interceptBtn = document.querySelector('.proxy-subtab[data-subtab="intercept"]');
      interceptBtn?.click();
    }
    _enqueueIntercept(record);
  });

  api.proxy.onWsFrame((frame) => {
    _addWsFrame(frame);
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function _fmtBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1024 / 1024).toFixed(1)}M`;
}

function _shortMime(mime) {
  if (!mime) return '';
  const last = mime.split('/').pop();
  return last.split(';')[0].slice(0, 12);
}

function _formatHeaderList(headers) {
  if (!headers || !Array.isArray(headers)) return '';
  return headers.map(([k, v]) => `${k}: ${v}`).join('\n');
}

function _renderHeaderTable(headers) {
  if (!headers || !headers.length) return '<em style="color:var(--text-muted)">No headers</em>';
  const rows = headers.map(([k, v]) =>
    `<tr><td class="hdr-name">${_esc(k)}</td><td class="hdr-value">${_esc(v)}</td></tr>`
  ).join('');
  return `<table class="proxy-header-table"><tbody>${rows}</tbody></table>`;
}

function _renderParamsTable(query) {
  if (!query) return '<em style="color:var(--text-muted)">No query parameters</em>';
  try {
    const params = [...new URLSearchParams(query).entries()];
    if (!params.length) return '<em style="color:var(--text-muted)">No query parameters</em>';
    const rows = params.map(([k, v]) =>
      `<tr><td class="hdr-name">${_esc(k)}</td><td class="hdr-value">${_esc(v)}</td></tr>`
    ).join('');
    return `<table class="proxy-header-table"><tbody>${rows}</tbody></table>`;
  } catch {
    return `<em>${_esc(query)}</em>`;
  }
}

function _prettyBody(bodyStr, mimeType) {
  if (!bodyStr) return '(empty)';
  if ((mimeType || '').includes('json')) {
    try { return JSON.stringify(JSON.parse(bodyStr), null, 2); } catch {}
  }
  return bodyStr;
}

function _getHeader(headers, name) {
  if (!headers) return '';
  const h = headers.find(([k]) => k.toLowerCase() === name.toLowerCase());
  return h ? h[1] : '';
}

function _buildRawText(record) {
  const headers = (record.requestHeaders || []).map(([k, v]) => `${k}: ${v}`).join('\r\n');
  return `${record.method} ${record.path}${record.query ? '?' + record.query : ''} HTTP/1.1\r\n${headers}\r\n\r\n`;
}
