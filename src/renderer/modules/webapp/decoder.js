/**
 * decoder.js — Encoder/Decoder Workbench (Feature 7D)
 *
 * Pure renderer-side transforms (no IPC) for all synchronous operations.
 * Server-side IPC only for: gzip compress/decompress, MD5/SHA-1/SHA-256/SHA-512.
 *
 * Features:
 *   - Single-transform mode: pick one transform, see input → output
 *   - Chain mode: up to 10 chained transforms with pipeline visualization
 *   - Auto-runs on input change (debounced 300ms)
 *   - JWT decode (header + payload JSON, highlights alg:none)
 */

let _container  = null;
let _chainMode  = false;
let _chain      = [];           // [{ transform, label }]
let _debounceTimer = null;

// ─── Transform definitions ────────────────────────────────────────────────────

const TRANSFORMS = [
  // Client-side (sync)
  { id: 'base64-encode',    label: 'Base64 Encode',    side: 'client' },
  { id: 'base64-decode',    label: 'Base64 Decode',    side: 'client' },
  { id: 'url-encode',       label: 'URL Encode',       side: 'client' },
  { id: 'url-decode',       label: 'URL Decode',       side: 'client' },
  { id: 'html-encode',      label: 'HTML Encode',      side: 'client' },
  { id: 'html-decode',      label: 'HTML Decode',      side: 'client' },
  { id: 'hex-encode',       label: 'Hex Encode',       side: 'client' },
  { id: 'hex-decode',       label: 'Hex Decode',       side: 'client' },
  { id: 'unicode-encode',   label: 'Unicode Escape',   side: 'client' },
  { id: 'unicode-decode',   label: 'Unicode Unescape', side: 'client' },
  { id: 'jwt-decode',       label: 'JWT Decode',       side: 'client' },
  // Server-side (async via IPC)
  { id: 'gzip-compress',    label: 'Gzip Compress',    side: 'server' },
  { id: 'gzip-decompress',  label: 'Gzip Decompress',  side: 'server' },
  { id: 'md5',              label: 'MD5 Hash',         side: 'server' },
  { id: 'sha1',             label: 'SHA-1 Hash',       side: 'server' },
  { id: 'sha256',           label: 'SHA-256 Hash',     side: 'server' },
  { id: 'sha512',           label: 'SHA-512 Hash',     side: 'server' },
];

// ─── Client-side transforms ───────────────────────────────────────────────────

function _applyClientTransform(id, input) {
  switch (id) {
    case 'base64-encode':   return btoa(unescape(encodeURIComponent(input)));
    case 'base64-decode':   try { return decodeURIComponent(escape(atob(input))); } catch { return '[Base64 decode error]'; }
    case 'url-encode':      return encodeURIComponent(input);
    case 'url-decode':      try { return decodeURIComponent(input); } catch { return '[URL decode error]'; }
    case 'html-encode':     return input.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    case 'html-decode': {
      const el = document.createElement('textarea');
      el.innerHTML = input;
      return el.value;
    }
    case 'hex-encode':      return Array.from(new TextEncoder().encode(input)).map(b => b.toString(16).padStart(2,'0')).join('');
    case 'hex-decode': {
      const clean = input.replace(/\s/g,'');
      if (clean.length % 2 !== 0) return '[Hex decode error: odd length]';
      try {
        const bytes = new Uint8Array(clean.match(/.{2}/g).map(h => parseInt(h, 16)));
        return new TextDecoder().decode(bytes);
      } catch { return '[Hex decode error]'; }
    }
    case 'unicode-encode':  return Array.from(input).map(c => {
      const cp = c.codePointAt(0);
      return cp > 127 ? `\\u${cp.toString(16).padStart(4,'0')}` : c;
    }).join('');
    case 'unicode-decode':  try { return input.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h,16))); } catch { return input; }
    case 'jwt-decode':      return _jwtDecode(input);
    default:                return null; // signals "server-side needed"
  }
}

function _jwtDecode(token) {
  const parts = token.trim().split('.');
  if (parts.length < 2) return '[Not a valid JWT: expected at least 2 parts separated by "."]';
  try {
    const header  = JSON.parse(decodeURIComponent(escape(atob(parts[0].replace(/-/g,'+').replace(/_/g,'/')))));
    const payload = JSON.parse(decodeURIComponent(escape(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')))));

    const warnings = [];
    if (header.alg === 'none') warnings.push('⚠ CRITICAL: alg=none — signature not verified!');
    if (header.alg?.startsWith('HS')) warnings.push('ℹ alg=HS* (HMAC symmetric) — shared secret required for verification.');
    if (payload.exp) {
      const exp = new Date(payload.exp * 1000);
      if (exp < new Date()) warnings.push(`⚠ Token expired: ${exp.toISOString()}`);
      else if ((payload.exp - Date.now() / 1000) > 7 * 86400) warnings.push(`⚠ Long-lived token: expires ${exp.toISOString()}`);
    }

    const result = {
      header,
      payload,
      signature: parts[2] ?? null,
      warnings,
    };
    return JSON.stringify(result, null, 2);
  } catch {
    return '[JWT decode error — not valid base64url JSON]';
  }
}

// ─── Render ───────────────────────────────────────────────────────────────────

function _render() {
  if (!_container) return;

  const optionsHtml = TRANSFORMS.map(t =>
    `<option value="${t.id}">${t.label}${t.side === 'server' ? ' ⚡' : ''}</option>`
  ).join('');

  _container.innerHTML = `
    <div class="decoder-layout">
      <div class="decoder-toolbar">
        <label class="decoder-mode-label">
          <input type="checkbox" id="decoder-chain-toggle" ${_chainMode ? 'checked' : ''}>
          <span>Chain Mode</span>
        </label>
        <button class="btn decoder-copy-btn" id="decoder-copy-output" title="Copy output">Copy Output</button>
        <button class="btn decoder-swap-btn" id="decoder-swap" title="Swap input ↔ output">⇅ Swap</button>
        <button class="btn decoder-clear-btn" id="decoder-clear">Clear</button>
        <span class="decoder-hint">⚡ = server-side (async)</span>
      </div>

      <!-- Single mode -->
      <div id="decoder-single-mode" ${_chainMode ? 'style="display:none"' : ''}>
        <div class="decoder-panes">
          <div class="decoder-pane">
            <div class="decoder-pane-header">
              <span>Input</span>
              <select class="decoder-transform-select" id="decoder-transform-select">
                ${optionsHtml}
              </select>
              <button class="btn webapp decoder-go-btn" id="decoder-go">Apply →</button>
            </div>
            <textarea class="decoder-textarea" id="decoder-input" placeholder="Paste text to transform…" spellcheck="false"></textarea>
          </div>
          <div class="decoder-pane">
            <div class="decoder-pane-header"><span>Output</span></div>
            <textarea class="decoder-textarea" id="decoder-output" readonly placeholder="Result will appear here…" spellcheck="false"></textarea>
          </div>
        </div>
      </div>

      <!-- Chain mode -->
      <div id="decoder-chain-mode" ${!_chainMode ? 'style="display:none"' : ''}>
        <div class="decoder-chain-layout">
          <div class="decoder-chain-input-pane">
            <div class="decoder-pane-header"><span>Chain Input</span></div>
            <textarea class="decoder-textarea" id="decoder-chain-input" placeholder="Input to chain…" spellcheck="false"></textarea>
          </div>
          <div class="decoder-chain-steps">
            <div class="decoder-chain-steps-header">
              <span>Transform Chain</span>
              <button class="btn decoder-add-step-btn" id="decoder-add-step">+ Add Step</button>
            </div>
            <div id="decoder-chain-list">
              ${_chain.map((step, i) => `
                <div class="decoder-chain-step" data-step="${i}">
                  <span class="decoder-chain-step-num">${i + 1}</span>
                  <select class="decoder-transform-select decoder-chain-step-select" data-step="${i}">
                    ${TRANSFORMS.map(t => `<option value="${t.id}" ${step.transform === t.id ? 'selected' : ''}>${t.label}${t.side === 'server' ? ' ⚡' : ''}</option>`).join('')}
                  </select>
                  <button class="decoder-chain-remove" data-step="${i}" title="Remove">×</button>
                </div>
              `).join('')}
              ${_chain.length === 0
                ? `<div class="decoder-chain-empty">No steps — click "Add Step" to build a chain</div>`
                : ''}
            </div>
            <button class="btn webapp decoder-chain-run-btn" id="decoder-chain-run">▶ Run Chain</button>
          </div>
          <div class="decoder-chain-output-pane">
            <div class="decoder-pane-header"><span>Chain Output</span></div>
            <textarea class="decoder-textarea" id="decoder-chain-output" readonly placeholder="Chain result…" spellcheck="false"></textarea>
          </div>
        </div>
      </div>

    </div>
  `;

  _bindEvents();
}

// ─── Events ───────────────────────────────────────────────────────────────────

function _bindEvents() {
  // Chain mode toggle
  document.getElementById('decoder-chain-toggle')?.addEventListener('change', (e) => {
    _chainMode = e.target.checked;
    document.getElementById('decoder-single-mode').style.display = _chainMode ? 'none' : '';
    document.getElementById('decoder-chain-mode').style.display  = _chainMode ? '' : 'none';
  });

  // Single mode: auto-apply on input change (debounced)
  const inputEl  = document.getElementById('decoder-input');
  const outputEl = document.getElementById('decoder-output');
  inputEl?.addEventListener('input', () => {
    clearTimeout(_debounceTimer);
    _debounceTimer = setTimeout(() => _applySingle(inputEl, outputEl), 300);
  });

  // Manual apply button
  document.getElementById('decoder-go')?.addEventListener('click', () => {
    const inputEl  = document.getElementById('decoder-input');
    const outputEl = document.getElementById('decoder-output');
    if (inputEl && outputEl) _applySingle(inputEl, outputEl);
  });

  // Copy output
  document.getElementById('decoder-copy-output')?.addEventListener('click', () => {
    const outEl = document.getElementById(_chainMode ? 'decoder-chain-output' : 'decoder-output');
    if (outEl) navigator.clipboard.writeText(outEl.value).catch(() => {});
  });

  // Swap
  document.getElementById('decoder-swap')?.addEventListener('click', () => {
    const inEl  = document.getElementById('decoder-input');
    const outEl = document.getElementById('decoder-output');
    if (inEl && outEl) {
      const tmp  = inEl.value;
      inEl.value = outEl.value;
      outEl.value = tmp;
    }
  });

  // Clear
  document.getElementById('decoder-clear')?.addEventListener('click', () => {
    ['decoder-input','decoder-output','decoder-chain-input','decoder-chain-output'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
  });

  // Chain: add step
  document.getElementById('decoder-add-step')?.addEventListener('click', () => {
    if (_chain.length >= 10) return;
    _chain.push({ transform: 'base64-encode', label: 'Base64 Encode' });
    _render();
    // Restore focus
    document.getElementById('decoder-chain-toggle').checked = true;
    document.getElementById('decoder-single-mode').style.display = 'none';
    document.getElementById('decoder-chain-mode').style.display  = '';
  });

  // Chain: remove step
  document.querySelectorAll('.decoder-chain-remove[data-step]').forEach(btn => {
    btn.addEventListener('click', () => {
      _chain.splice(Number(btn.dataset.step), 1);
      _render();
      document.getElementById('decoder-chain-toggle').checked = true;
      document.getElementById('decoder-single-mode').style.display = 'none';
      document.getElementById('decoder-chain-mode').style.display  = '';
    });
  });

  // Chain: change step transform
  document.querySelectorAll('.decoder-chain-step-select[data-step]').forEach(sel => {
    sel.addEventListener('change', () => {
      _chain[Number(sel.dataset.step)].transform = sel.value;
    });
  });

  // Chain: run
  document.getElementById('decoder-chain-run')?.addEventListener('click', _runChain);
}

// ─── Apply single transform ───────────────────────────────────────────────────

async function _applySingle(inputEl, outputEl) {
  const transformId = document.getElementById('decoder-transform-select')?.value;
  if (!transformId || !inputEl || !outputEl) return;

  const input = inputEl.value;
  const result = _applyClientTransform(transformId, input);

  if (result !== null) {
    outputEl.value = result;
    return;
  }

  // Server-side
  outputEl.value = '⏳ Processing…';
  try {
    const resp = await window.electronAPI.decoder.transform(transformId, input);
    outputEl.value = resp.success ? resp.output : `⚠ ${resp.error}`;
  } catch (err) {
    outputEl.value = `⚠ ${err.message}`;
  }
}

// ─── Run chain ────────────────────────────────────────────────────────────────

async function _runChain() {
  const inputEl  = document.getElementById('decoder-chain-input');
  const outputEl = document.getElementById('decoder-chain-output');
  if (!inputEl || !outputEl) return;

  if (_chain.length === 0) {
    outputEl.value = '(no steps in chain)';
    return;
  }

  let current = inputEl.value;
  outputEl.value = '⏳ Running chain…';

  for (const step of _chain) {
    const result = _applyClientTransform(step.transform, current);
    if (result !== null) {
      current = result;
    } else {
      // Server-side step
      try {
        const resp = await window.electronAPI.decoder.transform(step.transform, current);
        if (!resp.success) { outputEl.value = `⚠ Step "${step.transform}" failed: ${resp.error}`; return; }
        current = resp.output;
      } catch (err) {
        outputEl.value = `⚠ ${err.message}`;
        return;
      }
    }
  }

  outputEl.value = current;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function init() {
  _container = document.getElementById('webapp-panel-decoder');
  if (!_container) return;
  _render();
}
