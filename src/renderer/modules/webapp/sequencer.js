/**
 * sequencer.js — Sequencer Renderer Module (Feature 7D)
 *
 * Analyzes randomness quality of tokens (session cookies, CSRF tokens, reset links).
 * Supports:
 *   - Live capture: replay a request N times, collect tokens from Set-Cookie / header / body-regex
 *   - Manual paste: paste a list of tokens directly
 *   - Analysis: Shannon entropy, FIPS 140-2 tests, chi-squared, verdict
 *   - Visual: entropy gauge, byte-frequency histogram, FIPS test cards
 */

let _container = null;
let _tokens    = [];
let _collecting = false;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function _verdictColor(v) {
  if (v === 'STRONG')   return 'var(--success, #22c55e)';
  if (v === 'MODERATE') return 'var(--severity-medium, #eab308)';
  return 'var(--severity-critical, #ef4444)';
}

// ─── Render ───────────────────────────────────────────────────────────────────

function _render() {
  if (!_container) return;

  _container.innerHTML = `
    <div class="sequencer-layout">

      <!-- Config panel -->
      <div class="sequencer-config-panel">

        <!-- Capture mode tabs -->
        <div class="sequencer-mode-tabs">
          <button class="sequencer-mode-tab active" data-mode="capture" id="seq-tab-capture">Live Capture</button>
          <button class="sequencer-mode-tab" data-mode="manual"  id="seq-tab-manual">Manual Paste</button>
        </div>

        <!-- Live capture form -->
        <div class="sequencer-mode-pane active" id="seq-pane-capture">
          <div class="sequencer-field-row">
            <label class="sequencer-label">Target URL</label>
            <input class="sequencer-input" id="seq-url" placeholder="https://target.com/login" />
          </div>
          <div class="sequencer-field-row">
            <label class="sequencer-label">Method</label>
            <select class="sequencer-select" id="seq-method">
              <option>GET</option><option>POST</option><option>PUT</option>
            </select>
          </div>
          <div class="sequencer-field-row">
            <label class="sequencer-label">Request Body</label>
            <input class="sequencer-input" id="seq-body" placeholder="username=test&password=test" />
          </div>
          <div class="sequencer-field-row">
            <label class="sequencer-label">Token Source</label>
            <select class="sequencer-select" id="seq-source">
              <option value="cookie">Set-Cookie header</option>
              <option value="header">Response header</option>
              <option value="body-regex">Body (regex)</option>
            </select>
          </div>
          <div class="sequencer-field-row" id="seq-cookie-row">
            <label class="sequencer-label">Cookie Name</label>
            <input class="sequencer-input" id="seq-cookie-name" placeholder="JSESSIONID (leave blank for first)" />
          </div>
          <div class="sequencer-field-row" id="seq-header-row" style="display:none">
            <label class="sequencer-label">Header Name</label>
            <input class="sequencer-input" id="seq-header-name" placeholder="X-CSRF-Token" />
          </div>
          <div class="sequencer-field-row" id="seq-regex-row" style="display:none">
            <label class="sequencer-label">Body Regex</label>
            <input class="sequencer-input" id="seq-body-regex" placeholder='value="([^"]+)"' />
          </div>
          <div class="sequencer-field-row">
            <label class="sequencer-label">Sample Count</label>
            <input type="number" class="sequencer-input" id="seq-count" value="100" min="10" max="1000" style="width:80px">
            <label class="sequencer-label" style="margin-left:12px">Delay (ms)</label>
            <input type="number" class="sequencer-input" id="seq-delay" value="100" min="0" max="5000" style="width:70px">
          </div>
          <div class="sequencer-capture-actions">
            <button class="btn webapp" id="seq-start-btn">${_collecting ? 'Collecting…' : '▶ Start Capture'}</button>
            <button class="btn" id="seq-stop-btn" ${!_collecting ? 'disabled' : ''}>⏹ Stop</button>
            <span class="sequencer-capture-status" id="seq-capture-status">
              ${_tokens.length > 0 ? `${_tokens.length} tokens collected` : ''}
            </span>
          </div>
        </div>

        <!-- Manual paste pane -->
        <div class="sequencer-mode-pane" id="seq-pane-manual" style="display:none">
          <div class="sequencer-field-row">
            <label class="sequencer-label">Paste Tokens</label>
          </div>
          <textarea
            class="sequencer-token-paste"
            id="seq-token-paste"
            placeholder="Paste one token per line…&#10;eyJhbGciOiJIUzI1NiJ9.xxx&#10;eyJhbGciOiJIUzI1NiJ9.yyy&#10;…"
            spellcheck="false"
          >${_esc(_tokens.join('\n'))}</textarea>
          <div class="sequencer-capture-actions">
            <button class="btn webapp" id="seq-load-paste-btn">Load Tokens</button>
            <span id="seq-paste-count">${_tokens.length} tokens loaded</span>
          </div>
        </div>

        <!-- Analyze button -->
        <div class="sequencer-analyze-bar">
          <button class="btn webapp" id="seq-analyze-btn" ${_tokens.length < 2 ? 'disabled' : ''}>
            🔬 Analyze ${_tokens.length} Tokens
          </button>
          <button class="btn" id="seq-clear-btn">Clear</button>
        </div>
      </div>

      <!-- Results panel -->
      <div class="sequencer-results-panel" id="seq-results-panel">
        <div class="sequencer-empty-state" id="seq-empty-state">
          <div class="sequencer-empty-icon">🎲</div>
          <div class="sequencer-empty-title">No analysis yet</div>
          <div class="sequencer-empty-sub">Collect or paste tokens, then click Analyze.</div>
        </div>
        <div class="sequencer-analysis" id="seq-analysis" style="display:none"></div>
      </div>

    </div>
  `;

  _bindEvents();
}

// ─── Events ───────────────────────────────────────────────────────────────────

function _bindEvents() {
  // Mode tabs
  document.querySelectorAll('.sequencer-mode-tab[data-mode]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sequencer-mode-tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.sequencer-mode-pane').forEach(p => p.style.display = 'none');
      btn.classList.add('active');
      const pane = document.getElementById(`seq-pane-${btn.dataset.mode}`);
      if (pane) pane.style.display = '';
    });
  });

  // Token source change
  document.getElementById('seq-source')?.addEventListener('change', (e) => {
    document.getElementById('seq-cookie-row').style.display  = e.target.value === 'cookie'     ? '' : 'none';
    document.getElementById('seq-header-row').style.display  = e.target.value === 'header'     ? '' : 'none';
    document.getElementById('seq-regex-row').style.display   = e.target.value === 'body-regex' ? '' : 'none';
  });

  // Start capture
  document.getElementById('seq-start-btn')?.addEventListener('click', _startCapture);

  // Stop
  document.getElementById('seq-stop-btn')?.addEventListener('click', () => {
    window.electronAPI.sequencer.collect({ url: 'stop' }).catch(() => {});
    _collecting = false;
    _render();
  });

  // Load pasted tokens
  document.getElementById('seq-load-paste-btn')?.addEventListener('click', () => {
    const ta = document.getElementById('seq-token-paste');
    _tokens = (ta?.value ?? '').split('\n').map(l => l.trim()).filter(Boolean);
    const countEl = document.getElementById('seq-paste-count');
    if (countEl) countEl.textContent = `${_tokens.length} tokens loaded`;
    const analyzeBtn = document.getElementById('seq-analyze-btn');
    if (analyzeBtn) {
      analyzeBtn.disabled = _tokens.length < 2;
      analyzeBtn.textContent = `🔬 Analyze ${_tokens.length} Tokens`;
    }
  });

  // Analyze
  document.getElementById('seq-analyze-btn')?.addEventListener('click', _analyze);

  // Clear
  document.getElementById('seq-clear-btn')?.addEventListener('click', () => {
    _tokens = [];
    _render();
  });
}

// ─── Capture ─────────────────────────────────────────────────────────────────

async function _startCapture() {
  const url       = document.getElementById('seq-url')?.value?.trim();
  const method    = document.getElementById('seq-method')?.value ?? 'GET';
  const body      = document.getElementById('seq-body')?.value?.trim() || null;
  const source    = document.getElementById('seq-source')?.value ?? 'cookie';
  const cookieName = document.getElementById('seq-cookie-name')?.value?.trim() || undefined;
  const headerName = document.getElementById('seq-header-name')?.value?.trim() || undefined;
  const bodyRegex  = document.getElementById('seq-body-regex')?.value?.trim() || undefined;
  const count     = Number(document.getElementById('seq-count')?.value ?? 100);
  const delayMs   = Number(document.getElementById('seq-delay')?.value ?? 100);

  if (!url) { _setStatus('⚠ Enter a target URL'); return; }

  _tokens    = [];
  _collecting = true;
  _setStatus(`Collecting tokens… 0 / ${count}`);

  const startBtn = document.getElementById('seq-start-btn');
  const stopBtn  = document.getElementById('seq-stop-btn');
  if (startBtn) { startBtn.disabled = true; startBtn.textContent = 'Collecting…'; }
  if (stopBtn)  stopBtn.disabled = false;

  const resp = await window.electronAPI.sequencer.collect({
    url, method, body, count, tokenSource: source,
    cookieName, headerName, bodyRegex, delayMs,
  });

  if (!resp.success) {
    _collecting = false;
    _setStatus(`⚠ ${resp.error}`);
    if (startBtn) { startBtn.disabled = false; startBtn.textContent = '▶ Start Capture'; }
    if (stopBtn)  stopBtn.disabled = true;
  }
}

function _setStatus(msg) {
  const el = document.getElementById('seq-capture-status');
  if (el) el.textContent = msg;
}

// ─── Analysis rendering ───────────────────────────────────────────────────────

async function _analyze() {
  if (_tokens.length < 2) return;

  const analyzeBtn = document.getElementById('seq-analyze-btn');
  if (analyzeBtn) { analyzeBtn.disabled = true; analyzeBtn.textContent = 'Analyzing…'; }

  const resp = await window.electronAPI.sequencer.analyze(_tokens);

  if (analyzeBtn) { analyzeBtn.disabled = false; analyzeBtn.textContent = `🔬 Analyze ${_tokens.length} Tokens`; }

  if (!resp.success) { _setStatus(`⚠ ${resp.error}`); return; }

  _renderAnalysis(resp.result);
}

function _renderAnalysis(r) {
  const emptyEl    = document.getElementById('seq-empty-state');
  const analysisEl = document.getElementById('seq-analysis');
  if (emptyEl)    emptyEl.style.display    = 'none';
  if (!analysisEl) return;
  analysisEl.style.display = '';

  const color   = _verdictColor(r.verdict);
  const fips    = r.fipsTests ?? {};

  const histSvg = _histogramSvg(r.histogram ?? []);

  analysisEl.innerHTML = `
    <div class="seq-verdict-card" style="border-color:${color}">
      <div class="seq-verdict-label" style="color:${color}">${r.verdict}</div>
      <div class="seq-verdict-meta">
        ${r.sampleCount} tokens · ${r.tokenLengthRange?.[0]}–${r.tokenLengthRange?.[1]} chars ·
        ${r.effectiveBitCount} effective bits
      </div>
    </div>

    <div class="seq-metrics-grid">
      <div class="seq-metric-card">
        <div class="seq-metric-label">Shannon Entropy</div>
        <div class="seq-metric-value" style="color:${_entropyColor(r.entropyPerByte)}">${r.entropyPerByte} bits/byte</div>
        <div class="seq-metric-bar">
          <div class="seq-metric-bar-fill" style="width:${(r.entropyPerByte / 8 * 100).toFixed(1)}%;background:${_entropyColor(r.entropyPerByte)}"></div>
        </div>
        <div class="seq-metric-hint">Max: 8.0 (ideal random)</div>
      </div>

      <div class="seq-fips-grid">
        ${_fipsCard('Monobit', fips.monobit)}
        ${_fipsCard('Block Freq', fips.blockFrequency)}
        ${_fipsCard('Runs', fips.runs)}
        ${_fipsCard('Longest Run', fips.longestRun)}
      </div>
    </div>

    <div class="seq-chi-row">
      <span class="seq-chi-label">Chi-Squared (byte dist):</span>
      <span class="seq-fips-badge ${r.chiSquared?.pass ? 'pass' : r.chiSquared?.pass === null ? 'skip' : 'fail'}">
        ${r.chiSquared?.pass ? 'PASS' : r.chiSquared?.pass === null ? 'SKIP' : 'FAIL'}
      </span>
      <span class="seq-chi-detail"> χ²=${r.chiSquared?.chi2 ?? '—'} p=${r.chiSquared?.pValue ?? '—'}</span>
    </div>

    <div class="seq-histogram-section">
      <div class="seq-histogram-title">Byte Frequency Distribution</div>
      ${histSvg}
    </div>

    <div class="seq-remediation">
      <strong>Assessment:</strong> ${_esc(r.remediation)}
    </div>
  `;
}

function _fipsCard(name, test) {
  const pass  = test?.pass;
  const badge = pass === true ? 'pass' : pass === null ? 'skip' : 'fail';
  const label = pass === true ? 'PASS' : pass === null ? 'N/A' : 'FAIL';
  return `
    <div class="seq-fips-card">
      <span class="seq-fips-name">${_esc(name)}</span>
      <span class="seq-fips-badge ${badge}">${label}</span>
      <span class="seq-fips-note">${_esc(test?.note ?? '')}</span>
    </div>
  `;
}

function _entropyColor(e) {
  if (e >= 6.5) return 'var(--success, #22c55e)';
  if (e >= 4.0) return 'var(--severity-medium, #eab308)';
  return 'var(--severity-critical, #ef4444)';
}

function _histogramSvg(hist) {
  if (!hist?.length) return '<div class="seq-hist-empty">No data</div>';
  const max    = Math.max(...hist) || 1;
  const w      = 512;
  const h      = 64;
  const barW   = w / 256;
  const bars   = hist.map((v, i) => {
    const barH = (v / max) * h;
    return `<rect x="${i * barW}" y="${h - barH}" width="${barW - 0.5}" height="${barH}" fill="var(--webapp-btn)" opacity="0.7"/>`;
  }).join('');
  return `<svg class="seq-histogram-svg" viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg">
    <rect width="${w}" height="${h}" fill="rgba(0,0,0,0.2)" rx="2"/>
    ${bars}
  </svg>`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function init() {
  _container = document.getElementById('webapp-panel-sequencer');
  if (!_container) return;

  _render();

  // IPC listeners
  window.electronAPI.sequencer.onToken(({ token, index, total }) => {
    _tokens.push(token);
    _setStatus(`Collecting… ${index + 1} / ${total}`);
    const analyzeBtn = document.getElementById('seq-analyze-btn');
    if (analyzeBtn) {
      analyzeBtn.disabled = _tokens.length < 2;
      analyzeBtn.textContent = `🔬 Analyze ${_tokens.length} Tokens`;
    }
  });

  window.electronAPI.sequencer.onResult(({ type, count }) => {
    if (type === 'collect') {
      _collecting = false;
      _setStatus(`✓ ${count} tokens collected`);
      const startBtn = document.getElementById('seq-start-btn');
      const stopBtn  = document.getElementById('seq-stop-btn');
      if (startBtn) { startBtn.disabled = false; startBtn.textContent = '▶ Start Capture'; }
      if (stopBtn)  stopBtn.disabled = true;
      const analyzeBtn = document.getElementById('seq-analyze-btn');
      if (analyzeBtn) {
        analyzeBtn.disabled = _tokens.length < 2;
        analyzeBtn.textContent = `🔬 Analyze ${_tokens.length} Tokens`;
      }
    }
  });

  window.electronAPI.sequencer.onError(({ message }) => {
    _collecting = false;
    _setStatus(`⚠ ${message}`);
  });
}
