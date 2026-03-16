/**
 * oast.js — OAST Listener Renderer Module (Feature 7E)
 *
 * Controls the local OAST HTTP callback server and displays incoming callbacks
 * in a live table. Allows generation of unique probe tokens for injection into
 * scanner payloads, XXE entities, SSRF parameters, CMDi curl probes, etc.
 */

import { api } from '../../api.js';

// ─── State ────────────────────────────────────────────────────────────────────

let _running       = false;
let _callbackCount = 0;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function _timeStr(ts) {
  return new Date(ts).toLocaleTimeString();
}

// ─── Init ─────────────────────────────────────────────────────────────────────

export async function init() {
  await _populateInterfaces();
  _bindEvents();
  _subscribeIpc();
}

async function _populateInterfaces() {
  const select = document.getElementById('oast-iface');
  if (!select) return;
  try {
    const ifaces = await api.oast?.getInterfaces?.() ?? [];
    // Clear default and repopulate
    select.innerHTML = '';
    for (const { name, address } of ifaces) {
      const opt = document.createElement('option');
      opt.value = address;
      opt.textContent = name;
      // Pre-select first real interface (non-0.0.0.0) if available
      if (address !== '0.0.0.0' && !select.querySelector('option[data-real]')) {
        opt.dataset.real = '1';
        opt.selected = true;
      }
      select.appendChild(opt);
    }
    // If only the 0.0.0.0 entry exists, fall back to selecting it
    if (!select.querySelector('option[data-real]') && select.options.length > 0) {
      select.options[0].selected = true;
    }
  } catch { /* ignore — auto-detect remains */ }
}

function _bindEvents() {
  document.getElementById('oast-start-btn')?.addEventListener('click', async () => {
    const port = parseInt(document.getElementById('oast-port')?.value ?? '7331', 10);
    if (!port || port < 1025 || port > 65534) {
      alert('Port must be between 1025 and 65534.');
      return;
    }
    const callbackIp = document.getElementById('oast-iface')?.value || null;
    const result = await api.oast?.start?.({ port, callbackIp });
    if (!result?.success) {
      alert(`Failed to start OAST listener: ${result?.error ?? 'Unknown error'}`);
    }
  });

  document.getElementById('oast-stop-btn')?.addEventListener('click', async () => {
    await api.oast?.stop?.();
  });

  document.getElementById('oast-gen-btn')?.addEventListener('click', async () => {
    if (!_running) {
      alert('Start the OAST listener first.');
      return;
    }
    const meta = document.getElementById('oast-token-meta')?.value?.trim() || 'manual';
    const result = await api.oast?.getToken?.({ label: meta });
    if (result?.success && result.url) {
      const out = document.getElementById('oast-token-out');
      if (out) out.value = result.url;
    }
  });

  document.getElementById('oast-copy-btn')?.addEventListener('click', () => {
    const val = document.getElementById('oast-token-out')?.value;
    if (val) {
      navigator.clipboard.writeText(val).catch(() => {
        // Fallback for non-secure contexts
        const el = document.getElementById('oast-token-out');
        el?.select();
        document.execCommand('copy');
      });
    }
  });

  document.getElementById('oast-clear-btn')?.addEventListener('click', async () => {
    await api.oast?.clear?.();
    _callbackCount = 0;
    _clearTable();
  });
}

function _subscribeIpc() {
  api.oast?.onStatus?.(_onStatus);
  api.oast?.onCallback?.(_onCallback);
}

// ─── IPC callbacks ────────────────────────────────────────────────────────────

function _onStatus({ running, localUrl }) {
  _running = running;

  const startBtn   = document.getElementById('oast-start-btn');
  const stopBtn    = document.getElementById('oast-stop-btn');
  const badge      = document.getElementById('oast-status-badge');
  const urlDisplay = document.getElementById('oast-url-display');
  const ifaceEl    = document.getElementById('oast-iface');
  const portEl     = document.getElementById('oast-port');

  if (startBtn)  startBtn.disabled  = running;
  if (stopBtn)   stopBtn.disabled   = !running;
  if (ifaceEl)   ifaceEl.disabled   = running;
  if (portEl)    portEl.disabled    = running;
  if (badge)     badge.style.display = running ? '' : 'none';
  if (urlDisplay) {
    urlDisplay.style.display = running ? '' : 'none';
    if (running && localUrl) {
      urlDisplay.textContent = `Listening at ${localUrl}/oast/{token}`;
    }
  }
}

function _onCallback(hit) {
  _callbackCount++;

  const count = document.getElementById('oast-callback-count');
  if (count) count.textContent = `${_callbackCount} received`;

  _appendCallbackRow(hit);
}

// ─── Table helpers ────────────────────────────────────────────────────────────

function _appendCallbackRow(hit) {
  const tbody = document.getElementById('oast-callbacks-tbody');
  if (!tbody) return;

  const empty = document.getElementById('oast-empty-row');
  if (empty) empty.remove();

  const contextLabel = hit.meta?.label
    ? `<span style="color:var(--oast-accent,#34d399);">${_esc(hit.meta.label)}</span> — `
    : '';
  const tokenShort = hit.token ? `<span style="font-family:monospace;color:var(--text-muted);">${_esc(hit.token.substring(0, 12))}…</span>` : '';

  const tr = document.createElement('tr');
  tr.style.background = 'rgba(52,211,153,0.05)';
  tr.innerHTML = `
    <td>${_esc(_timeStr(hit.ts))}</td>
    <td style="font-family:monospace;">${_esc(hit.remoteIp)}</td>
    <td><span style="color:var(--method-get,#22c55e);">${_esc(hit.method ?? 'GET')}</span></td>
    <td>${contextLabel}${tokenShort}</td>`;

  // Prepend so newest is at top
  tbody.insertBefore(tr, tbody.firstChild);
}

function _clearTable() {
  const tbody = document.getElementById('oast-callbacks-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr id="oast-empty-row"><td colspan="4" style="text-align:center;color:var(--text-muted);padding:24px;">No callbacks yet.</td></tr>`;
}
