/**
 * comparer.js — Side-by-Side Diff View (Feature 7D)
 *
 * Uses Myers diff algorithm (O(ND) diff) implemented in pure JS.
 * Supports word-diff, line-diff, and byte-diff modes.
 * Can accept drag-from-proxy-history or manual paste into either side.
 */

let _container = null;
let _sideA     = '';
let _sideB     = '';
let _diffMode  = 'line';  // 'line' | 'word' | 'byte'

// ─── Myers diff ───────────────────────────────────────────────────────────────

/**
 * Myers O(ND) diff algorithm.
 * Returns an array of operations: { type: 'equal'|'insert'|'delete', value }
 *
 * @param {string[]} a  — sequence A tokens
 * @param {string[]} b  — sequence B tokens
 * @returns {{ type: string, value: string }[]}
 */
export function myersDiff(a, b) {
  const n = a.length;
  const m = b.length;
  const max = n + m;

  if (max === 0) return [];

  // V[k] = furthest reaching x position on diagonal k
  const v = new Array(2 * max + 1).fill(0);
  const trace = [];

  for (let d = 0; d <= max; d++) {
    trace.push([...v]);
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && v[k - 1 + max] < v[k + 1 + max])) {
        x = v[k + 1 + max]; // move down (insert)
      } else {
        x = v[k - 1 + max] + 1; // move right (delete)
      }
      let y = x - k;
      // Follow diagonal (equal)
      while (x < n && y < m && a[x] === b[y]) { x++; y++; }
      v[k + max] = x;
      if (x >= n && y >= m) {
        // Found the end — backtrack
        return _backtrack(trace, a, b, n, m, max, d);
      }
    }
  }
  // Fallback: everything different
  return [
    ...a.map(v => ({ type: 'delete', value: v })),
    ...b.map(v => ({ type: 'insert', value: v })),
  ];
}

function _backtrack(trace, a, b, n, m, max, d) {
  const ops = [];
  let x = n, y = m;

  for (let depth = d; depth > 0; depth--) {
    const v   = trace[depth];
    const k   = x - y;
    let prevK;
    if (k === -depth || (k !== depth && (v[k - 1 + max] ?? -1) < (v[k + 1 + max] ?? -1))) {
      prevK = k + 1; // came from insert (move down in edit graph)
    } else {
      prevK = k - 1; // came from delete (move right in edit graph)
    }
    const prevX = v[prevK + max] ?? 0;
    const prevY = prevX - prevK;

    // Consume snake (equal elements along the diagonal)
    while (x > prevX && y > prevY) {
      ops.unshift({ type: 'equal', value: a[x - 1] });
      x--; y--;
    }
    // Single non-diagonal edit
    if (prevK === k - 1) {
      // Came from k-1 by moving right → delete from A
      ops.unshift({ type: 'delete', value: a[x - 1] });
      x--;
    } else {
      // Came from k+1 by moving down → insert from B
      ops.unshift({ type: 'insert', value: b[y - 1] });
      y--;
    }
  }
  // Remaining snake at start of edit graph
  while (x > 0 && y > 0) {
    ops.unshift({ type: 'equal', value: a[x - 1] });
    x--; y--;
  }
  return ops;
}

// ─── Tokenizers ──────────────────────────────────────────────────────────────

function _tokenize(text, mode) {
  if (mode === 'line') return text.split('\n');
  if (mode === 'word') return text.match(/\S+|\s+/g) ?? [];
  if (mode === 'byte') return Array.from(text).map(c => c.codePointAt(0).toString(16).padStart(4,'0'));
  return text.split('\n');
}

// ─── Stats ───────────────────────────────────────────────────────────────────

function _computeStats(ops) {
  let added = 0, deleted = 0, equal = 0;
  for (const op of ops) {
    const len = op.value?.length ?? 0;
    if (op.type === 'insert') added   += len;
    if (op.type === 'delete') deleted += len;
    if (op.type === 'equal')  equal   += len;
  }
  const total   = added + deleted + equal;
  const similar = total > 0 ? ((equal / total) * 100).toFixed(1) : '100.0';
  return { added, deleted, equal, similar };
}

// ─── Render ───────────────────────────────────────────────────────────────────

function _render() {
  if (!_container) return;

  _container.innerHTML = `
    <div class="comparer-layout">
      <div class="comparer-toolbar">
        <div class="comparer-mode-group">
          ${['line','word','byte'].map(m => `
            <button class="comparer-mode-btn${_diffMode===m?' active':''}" data-mode="${m}">${m.charAt(0).toUpperCase()+m.slice(1)} Diff</button>
          `).join('')}
        </div>
        <button class="btn webapp" id="comparer-run-btn">Compare</button>
        <button class="btn" id="comparer-clear-btn">Clear</button>
        <span class="comparer-stats" id="comparer-stats"></span>
      </div>

      <div class="comparer-input-row">
        <div class="comparer-side">
          <div class="comparer-side-header">
            Side A
            <span class="comparer-side-hint">Drag a history row here, or paste below</span>
          </div>
          <textarea
            class="comparer-textarea"
            id="comparer-a"
            placeholder="Paste text A here, or drag from HTTP History…"
            spellcheck="false"
          >${_esc(_sideA)}</textarea>
        </div>
        <div class="comparer-side">
          <div class="comparer-side-header">
            Side B
            <span class="comparer-side-hint">Drag a history row here, or paste below</span>
          </div>
          <textarea
            class="comparer-textarea"
            id="comparer-b"
            placeholder="Paste text B here, or drag from HTTP History…"
            spellcheck="false"
          >${_esc(_sideB)}</textarea>
        </div>
      </div>

      <div class="comparer-result" id="comparer-result"></div>
    </div>
  `;

  _bindEvents();
}

function _esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ─── Events ───────────────────────────────────────────────────────────────────

function _bindEvents() {
  document.querySelectorAll('.comparer-mode-btn[data-mode]').forEach(btn => {
    btn.addEventListener('click', () => {
      _diffMode = btn.dataset.mode;
      document.querySelectorAll('.comparer-mode-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });

  document.getElementById('comparer-run-btn')?.addEventListener('click', _runDiff);
  document.getElementById('comparer-clear-btn')?.addEventListener('click', () => {
    _sideA = ''; _sideB = '';
    const resultEl = document.getElementById('comparer-result');
    if (resultEl) resultEl.innerHTML = '';
    const statsEl = document.getElementById('comparer-stats');
    if (statsEl) statsEl.textContent = '';
    const a = document.getElementById('comparer-a');
    const b = document.getElementById('comparer-b');
    if (a) a.value = '';
    if (b) b.value = '';
  });
}

// ─── Diff execution ───────────────────────────────────────────────────────────

function _runDiff() {
  const aEl    = document.getElementById('comparer-a');
  const bEl    = document.getElementById('comparer-b');
  const result = document.getElementById('comparer-result');
  const stats  = document.getElementById('comparer-stats');

  _sideA = aEl?.value ?? '';
  _sideB = bEl?.value ?? '';

  if (!_sideA && !_sideB) return;

  const tokA = _tokenize(_sideA, _diffMode);
  const tokB = _tokenize(_sideB, _diffMode);

  // Cap at 10,000 tokens to avoid hang
  if (tokA.length + tokB.length > 20_000) {
    if (result) result.innerHTML = `<div class="comparer-warn">⚠ Input too large for inline diff. Limit: 10,000 tokens per side.</div>`;
    return;
  }

  const ops    = myersDiff(tokA, tokB);
  const st     = _computeStats(ops);

  if (stats) {
    stats.textContent = `+${st.added} added  −${st.deleted} removed  ${st.similar}% similar`;
  }

  if (_diffMode === 'line') {
    _renderLineDiff(ops, result);
  } else {
    _renderInlineDiff(ops, result);
  }
}

function _renderLineDiff(ops, container) {
  const linesA = [], linesB = [];
  for (const op of ops) {
    if (op.type === 'equal')  { linesA.push({ type: 'equal',  value: op.value }); linesB.push({ type: 'equal',  value: op.value }); }
    if (op.type === 'delete') { linesA.push({ type: 'delete', value: op.value }); linesB.push({ type: 'empty' }); }
    if (op.type === 'insert') { linesA.push({ type: 'empty' }); linesB.push({ type: 'insert', value: op.value }); }
  }

  const rowsA = linesA.map(l => _diffLine(l)).join('');
  const rowsB = linesB.map(l => _diffLine(l)).join('');

  if (container) {
    container.innerHTML = `
      <div class="comparer-diff-panes">
        <div class="comparer-diff-pane"><pre class="comparer-diff-pre">${rowsA}</pre></div>
        <div class="comparer-diff-pane"><pre class="comparer-diff-pre">${rowsB}</pre></div>
      </div>
    `;
  }
}

function _diffLine(l) {
  if (l.type === 'empty')  return `<span class="diff-empty"> </span>\n`;
  if (l.type === 'delete') return `<span class="diff-del">${_esc(l.value)}</span>\n`;
  if (l.type === 'insert') return `<span class="diff-ins">${_esc(l.value)}</span>\n`;
  return `<span class="diff-eq">${_esc(l.value)}</span>\n`;
}

function _renderInlineDiff(ops, container) {
  const parts = ops.map(op => {
    if (op.type === 'equal')  return `<span class="diff-eq">${_esc(op.value)}</span>`;
    if (op.type === 'delete') return `<span class="diff-del">${_esc(op.value)}</span>`;
    if (op.type === 'insert') return `<span class="diff-ins">${_esc(op.value)}</span>`;
    return '';
  }).join('');

  if (container) {
    container.innerHTML = `<div class="comparer-inline-diff"><pre class="comparer-diff-pre">${parts}</pre></div>`;
  }
}

// ─── Cross-module: accept history drag ───────────────────────────────────────

export function setSide(side, text) {
  if (side === 'a') _sideA = text;
  if (side === 'b') _sideB = text;
  const el = document.getElementById(`comparer-${side}`);
  if (el) el.value = text;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function init() {
  _container = document.getElementById('webapp-panel-comparer');
  if (!_container) return;
  _render();

  // Listen for history drag/send events
  document.addEventListener('comparer:sendTo', (e) => {
    const { side = 'a', text = '' } = e.detail ?? {};
    setside(side, text);
  });
}
