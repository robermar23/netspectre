/**
 * intruderEngine.js — Automated HTTP Fuzzer Engine (Feature 7D)
 *
 * Attack types (matching Burp Intruder):
 *   Sniper        — iterates each position independently (list × positions requests)
 *   BatteringRam  — same payload applied to all positions simultaneously
 *   Pitchfork     — parallel lists, row-aligned (N payload lists, 1 payload from each per request)
 *   ClusterBomb   — cartesian product of all payload lists across all positions
 *
 * Position markers: §value§  (e.g. "username=§admin§&password=§pass§")
 *
 * Exports:
 *   startIntruder(opts, onResult, onProgress, onComplete, onError)
 *   stopIntruder()
 *   isIntruderRunning()
 *   cleanupIntruder()
 */

import { sendProbe } from './scanner/index.js';

// ─── State ────────────────────────────────────────────────────────────────────

let _controller  = null;
let _running     = false;

// ─── Semaphore ────────────────────────────────────────────────────────────────

function createSemaphore(max) {
  let running = 0;
  const queue = [];
  return {
    acquire() {
      return new Promise(resolve => {
        const tryRun = () => {
          if (running < max) {
            running++;
            resolve(() => { running--; if (queue.length) queue.shift()(); });
          } else {
            queue.push(tryRun);
          }
        };
        tryRun();
      });
    },
  };
}

// ─── Position parsing ─────────────────────────────────────────────────────────

/**
 * Extract position placeholders from a raw request template.
 * Returns array of { start, end, value } (indices into the template string).
 * §text§ markers are found from left to right.
 */
export function parsePositions(template) {
  const positions = [];
  let i = 0;
  while (i < template.length) {
    const open = template.indexOf('§', i);
    if (open === -1) break;
    const close = template.indexOf('§', open + 1);
    if (close === -1) break;
    positions.push({
      start: open,
      end:   close,
      value: template.slice(open + 1, close),
    });
    i = close + 1;
  }
  return positions;
}

/**
 * Replace all §markers§ in a template with the given payload values.
 * payloads: string[]  — one per position (must match positions.length)
 */
export function applyPayloads(template, positions, payloads) {
  let result = '';
  let cursor = 0;
  for (let i = 0; i < positions.length; i++) {
    const pos = positions[i];
    result += template.slice(cursor, pos.start);
    result += payloads[i] ?? '';
    cursor  = pos.end + 1;
  }
  result += template.slice(cursor);
  return result;
}

// ─── Payload transforms ───────────────────────────────────────────────────────

export function applyTransforms(payload, transforms = []) {
  let result = payload;
  for (const t of transforms) {
    switch (t) {
      case 'url-encode':   result = encodeURIComponent(result); break;
      case 'url-decode':   try { result = decodeURIComponent(result); } catch {} break;
      case 'base64-encode': result = Buffer.from(result).toString('base64'); break;
      case 'base64-decode': try { result = Buffer.from(result, 'base64').toString('utf8'); } catch {} break;
      case 'uppercase':    result = result.toUpperCase(); break;
      case 'lowercase':    result = result.toLowerCase(); break;
      case 'reverse':      result = result.split('').reverse().join(''); break;
      case 'html-encode':  result = result.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); break;
      default:
        if (t?.type === 'prefix')  result = t.value + result;
        if (t?.type === 'suffix')  result = result + t.value;
    }
  }
  return result;
}

// ─── Request generator per attack type ───────────────────────────────────────

/**
 * Returns an iterable of { payloads: string[], index: number } tuples.
 * positions: array of position descriptors
 * payloadLists: string[][] — one list per position (or single list for Sniper/BatteringRam)
 */
export function* generateRequests(attackType, positions, payloadLists) {
  const posCount = positions.length;
  if (posCount === 0) return;

  switch (attackType) {
    case 'sniper': {
      // One payload list; iterate each position independently
      const list = payloadLists[0] ?? [];
      let index = 0;
      for (let p = 0; p < posCount; p++) {
        for (const payload of list) {
          const payloads = positions.map((_, i) => i === p ? payload : positions[i].value);
          yield { payloads, index: index++ };
        }
      }
      break;
    }
    case 'battering-ram': {
      // Single list, same payload into all positions simultaneously
      const list = payloadLists[0] ?? [];
      let index = 0;
      for (const payload of list) {
        yield { payloads: Array(posCount).fill(payload), index: index++ };
      }
      break;
    }
    case 'pitchfork': {
      // N lists, aligned row-by-row (shortest list caps total)
      const length = Math.min(...payloadLists.map(l => l.length));
      for (let i = 0; i < length; i++) {
        const payloads = payloadLists.map((l, p) => l[i] ?? positions[p]?.value ?? '');
        yield { payloads, index: i };
      }
      break;
    }
    case 'cluster-bomb': {
      // Cartesian product — can be huge; cap at 1,000,000 total
      const lists   = payloadLists.slice(0, posCount);
      const counts  = lists.map(l => l.length);
      const total   = counts.reduce((a, b) => a * b, 1);
      const cap     = Math.min(total, 1_000_000);
      let index = 0;
      function* _product(arr) {
        if (arr.length === 0) { yield []; return; }
        const [first, ...rest] = arr;
        for (const v of first) {
          for (const tail of _product(rest)) {
            yield [v, ...tail];
          }
        }
      }
      for (const combo of _product(lists)) {
        if (index >= cap) break;
        yield { payloads: combo, index: index++ };
      }
      break;
    }
    default:
      throw new Error(`Unknown attack type: ${attackType}`);
  }
}

// ─── Main engine ──────────────────────────────────────────────────────────────

/**
 * @param {{
 *   rawTemplate:  string,           // raw HTTP request with §markers§
 *   targetUrl:    string,           // base URL (method/host extracted from template if not overridden)
 *   attackType:   'sniper'|'battering-ram'|'pitchfork'|'cluster-bomb',
 *   payloadLists: string[][],       // one list per position (sniper/bram: [0] only)
 *   transforms:   string[],         // applied to each payload before insertion
 *   concurrency:  number,           // max concurrent requests (1–50)
 *   delayMs:      number,           // delay between each request (ms)
 *   timeoutMs:    number,
 * }} opts
 */
export function startIntruder(opts, onResult, onProgress, onComplete, onError) {
  if (_running) {
    onError?.(new Error('Intruder already running'));
    return;
  }

  const {
    rawTemplate,
    targetUrl,
    attackType    = 'sniper',
    payloadLists  = [[]],
    transforms    = [],
    concurrency   = 10,
    delayMs       = 0,
    timeoutMs     = 15_000,
  } = opts;

  // Validate
  if (!rawTemplate || !targetUrl) {
    onError?.(new Error('rawTemplate and targetUrl are required'));
    return;
  }
  try { new URL(targetUrl); } catch {
    onError?.(new Error(`Invalid targetUrl: ${targetUrl}`));
    return;
  }

  const maxConcurrency = Math.min(Math.max(1, concurrency), 50);
  const positions = parsePositions(rawTemplate);
  if (positions.length === 0) {
    onError?.(new Error('No §position markers§ found in the request template. Wrap text with § to mark injection points.'));
    return;
  }

  // Apply transforms to all payloads
  const transformedLists = payloadLists.map(list =>
    list.map(p => applyTransforms(p, transforms))
  );

  _controller = new AbortController();
  _running    = true;
  const signal = _controller.signal;
  const sem    = createSemaphore(maxConcurrency);

  // Collect all request descriptors first (synchronously) to know total count
  const requests = [...generateRequests(attackType, positions, transformedLists)];
  const total    = requests.length;
  let completed  = 0;

  if (total === 0) {
    _running = false;
    onComplete?.({ total: 0, completed: 0 });
    return;
  }

  const promises = requests.map(({ payloads, index }) => async () => {
    if (signal.aborted) return;
    const release = await sem.acquire();
    try {
      if (signal.aborted) return;

      const filledTemplate = applyPayloads(rawTemplate, positions, payloads);

      // Parse the filled template to extract method, path, headers, body
      const { method, headers, body } = _parseTemplate(filledTemplate);

      // Reconstruct URL using the base targetUrl + path from template
      let reqUrl = targetUrl;
      try {
        const base  = new URL(targetUrl);
        const tPath = _extractPath(filledTemplate);
        if (tPath) {
          base.pathname = tPath.split('?')[0];
          base.search   = tPath.includes('?') ? '?' + tPath.split('?')[1] : '';
          reqUrl = base.href;
        }
      } catch {}

      const t0 = Date.now();
      let result;
      try {
        const resp = await sendProbe({ method, url: reqUrl, headers, body, timeoutMs }, signal);
        result = {
          index,
          payloads,
          statusCode:  resp.statusCode,
          length:      resp.body?.length ?? 0,
          durationMs:  resp.durationMs,
          error:       null,
        };
      } catch (err) {
        if (err.name === 'AbortError') return;
        result = {
          index,
          payloads,
          statusCode:  null,
          length:      0,
          durationMs:  Date.now() - t0,
          error:       err.message,
        };
      }

      onResult?.(result);
      completed++;
      onProgress?.({ completed, total, percent: Math.round((completed / total) * 100) });

      if (delayMs > 0) await _sleep(delayMs);
    } finally {
      release();
    }
  });

  Promise.all(promises.map(fn => fn())).then(() => {
    _running = false;
    onComplete?.({ total, completed });
  }).catch(err => {
    _running = false;
    if (err.name !== 'AbortError') onError?.(err);
  });
}

export function stopIntruder() {
  _controller?.abort();
  _running = false;
}

export function isIntruderRunning() {
  return _running;
}

export function cleanupIntruder() {
  stopIntruder();
  _controller = null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _parseTemplate(template) {
  const normalized = template.replace(/\r\n/g, '\n');
  const blankLine  = normalized.indexOf('\n\n');
  const headerPart = blankLine === -1 ? normalized : normalized.slice(0, blankLine);
  const bodyPart   = blankLine === -1 ? '' : normalized.slice(blankLine + 2);

  const lines = headerPart.split('\n');
  const [method = 'GET'] = (lines[0] ?? '').trim().split(/\s+/);
  const headers = {};
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  return { method: method.toUpperCase(), headers, body: bodyPart || null };
}

function _extractPath(template) {
  const firstLine = template.replace(/\r\n/g, '\n').split('\n')[0] ?? '';
  const parts = firstLine.trim().split(/\s+/);
  return parts[1] ?? null;
}

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
