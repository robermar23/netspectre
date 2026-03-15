/**
 * Feature 7C — Active Vulnerability Scanner Orchestrator
 *
 * Manages a queue of scan jobs. Each job is { target: RequestRecord, modules: string[] }.
 * Replays requests with modified payloads using pure Node.js http/https — no external deps.
 *
 * Exports:
 *   startScan(opts, onFinding, onProgress, onComplete, onError)
 *   stopScan()
 *   isScanRunning()
 *   cleanupScan()
 *   getFindings()
 *   clearFindings()
 */

import http  from 'http';
import https from 'https';
import { SCANNER_DEFAULT_CONCURRENCY, SCANNER_DEFAULT_TIMEOUT_MS } from '#shared/webConstants.js';

import { runSqli }          from './sqli.js';
import { runXss }           from './xss.js';
import { runSsrf }          from './ssrf.js';
import { runXxe }           from './xxe.js';
import { runCmdInjection }  from './cmdInjection.js';
import { runPathTraversal } from './pathTraversal.js';
import { runCors }          from './cors.js';
import { runHeaders }       from './headers.js';
import { runBrokenAuth }    from './brokenAuth.js';
import { runDeserialize }   from './deserialize.js';

// ─── Active session state ─────────────────────────────────────────────────────

let _controller  = null;
let _running     = false;
let _findings    = [];

// ─── Module registry ──────────────────────────────────────────────────────────

const MODULE_RUNNERS = {
  sqli:          runSqli,
  xss:           runXss,
  ssrf:          runSsrf,
  xxe:           runXxe,
  cmdInjection:  runCmdInjection,
  pathTraversal: runPathTraversal,
  cors:          runCors,
  headers:       runHeaders,
  brokenAuth:    runBrokenAuth,
  deserialize:   runDeserialize,
};

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

// ─── sendProbe ────────────────────────────────────────────────────────────────

/**
 * Shared HTTP probe used by all scanner modules.
 * Returns { statusCode, headers, body, durationMs } — never throws on HTTP errors.
 *
 * @param {{ method: string, url: string, headers?: object, body?: string, timeoutMs?: number, followRedirect?: boolean }} opts
 * @param {AbortSignal} signal
 */
export function sendProbe(opts, signal) {
  const {
    method      = 'GET',
    url,
    headers     = {},
    body        = null,
    timeoutMs   = SCANNER_DEFAULT_TIMEOUT_MS,
    followRedirect = true,
  } = opts;

  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));

    let parsed;
    try { parsed = new URL(url); } catch { return reject(new Error(`Invalid URL: ${url}`)); }

    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;

    const reqHeaders = { ...headers };
    if (body && !reqHeaders['content-length'] && !reqHeaders['Content-Length']) {
      reqHeaders['content-length'] = Buffer.byteLength(body).toString();
    }

    const reqOpts = {
      hostname:            parsed.hostname,
      port:                parsed.port || (isHttps ? 443 : 80),
      path:                parsed.pathname + parsed.search,
      method:              method.toUpperCase(),
      headers:             reqHeaders,
      timeout:             timeoutMs,
      rejectUnauthorized:  false,
      checkServerIdentity: () => undefined,
    };

    const t0 = Date.now();

    const req = lib.request(reqOpts, (res) => {
      // Single redirect follow
      if (followRedirect && (res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 307 || res.statusCode === 308) && res.headers.location) {
        req.destroy();
        const redirectUrl = res.headers.location.startsWith('http')
          ? res.headers.location
          : new URL(res.headers.location, url).href;
        sendProbe({ ...opts, url: redirectUrl, followRedirect: false }, signal)
          .then(resolve).catch(reject);
        return;
      }

      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       Buffer.concat(chunks).toString('utf8').slice(0, 500_000),
          durationMs: Date.now() - t0,
        });
      });
      res.on('error', reject);
    });

    req.on('timeout', () => req.destroy(new Error('Timeout')));
    req.on('error', (err) => {
      if (signal?.aborted) {
        reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
      } else {
        reject(err);
      }
    });

    if (signal) {
      signal.addEventListener('abort', () => req.destroy(), { once: true });
    }

    if (body) req.write(body);
    req.end();
  });
}

// ─── Parameter extraction ─────────────────────────────────────────────────────

/**
 * Extract injectable parameters from a request record.
 * Returns an array of { location, name, value, inject(newVal) → { ...target, [injected] } }
 */
export function extractParams(target) {
  const params = [];
  const { url, method, requestHeaders = {}, body } = target;

  // Query string params
  try {
    const parsed = new URL(url);
    for (const [name, value] of parsed.searchParams) {
      params.push({
        location: 'query',
        name,
        value,
        inject(payload) {
          const u = new URL(url);
          u.searchParams.set(name, payload);
          return { ...target, url: u.href };
        },
      });
    }
  } catch {}

  // POST body params
  const ct = (requestHeaders['content-type'] || requestHeaders['Content-Type'] || '').toLowerCase();
  if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    if (ct.includes('application/x-www-form-urlencoded')) {
      try {
        const params2 = new URLSearchParams(body);
        for (const [name, value] of params2) {
          const n = name, v = value;
          params.push({
            location: 'body',
            name:  n,
            value: v,
            inject(payload) {
              const p = new URLSearchParams(body);
              p.set(n, payload);
              return { ...target, body: p.toString() };
            },
          });
        }
      } catch {}
    } else if (ct.includes('application/json')) {
      try {
        const obj = JSON.parse(body);
        for (const [key, val] of Object.entries(obj)) {
          if (typeof val === 'string' || typeof val === 'number') {
            const k = key;
            params.push({
              location: 'json',
              name:  k,
              value: String(val),
              inject(payload) {
                const clone = JSON.parse(body);
                clone[k] = payload;
                return { ...target, body: JSON.stringify(clone) };
              },
            });
          }
        }
      } catch {}
    }
  }

  // Cookie params
  const cookie = requestHeaders['cookie'] || requestHeaders['Cookie'] || '';
  if (cookie) {
    for (const pair of cookie.split(';')) {
      const eq = pair.indexOf('=');
      if (eq === -1) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      params.push({
        location: 'cookie',
        name,
        value,
        inject(payload) {
          const parts = cookie.split(';').map(p => {
            const e = p.indexOf('=');
            return e !== -1 && p.slice(0, e).trim() === name
              ? ` ${name}=${payload}`
              : p;
          });
          return {
            ...target,
            requestHeaders: { ...requestHeaders, cookie: parts.join(';').trim() },
          };
        },
      });
    }
  }

  return params;
}

// ─── Finding builder ──────────────────────────────────────────────────────────

export function makeFinding(fields) {
  return {
    id:          crypto.randomUUID(),
    severity:    'info',
    type:        'unknown',
    title:       '',
    description: '',
    url:         '',
    parameter:   null,
    payload:     null,
    evidence:    {},
    remediation: '',
    references:  [],
    timestamp:   Date.now(),
    ...fields,
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * @param {object} opts
 * @param {Array<{requestId, url, method, requestHeaders, body}>} opts.targets
 * @param {string[]} opts.modules
 * @param {number} [opts.concurrency]
 * @param {number} [opts.timeoutMs]
 * @param {string|null} [opts.oastCallbackUrl]
 * @param {function(finding)} onFinding
 * @param {function({tested, total, findings})} onProgress
 * @param {function({findings, total})} onComplete
 * @param {function(Error)} onError
 */
export async function startScan(opts, onFinding, onProgress, onComplete, onError) {
  if (_running) {
    onError(new Error('Scan already running'));
    return;
  }

  const {
    targets       = [],
    modules       = Object.keys(MODULE_RUNNERS),
    concurrency   = SCANNER_DEFAULT_CONCURRENCY,
    timeoutMs     = SCANNER_DEFAULT_TIMEOUT_MS,
    oastCallbackUrl = null,
  } = opts;

  if (!targets.length) {
    onError(new Error('No targets provided'));
    return;
  }

  _controller = new AbortController();
  _running    = true;
  _findings   = [];

  const signal    = _controller.signal;
  const sem       = createSemaphore(Math.min(concurrency, 20));
  let   tested    = 0;
  const total     = targets.length;

  const scanOpts  = { timeoutMs, oastCallbackUrl, signal };

  // Resolve runners for selected modules
  const runners = modules
    .filter(m => MODULE_RUNNERS[m])
    .map(m => MODULE_RUNNERS[m]);

  if (!runners.length) {
    onError(new Error('No valid scan modules selected'));
    _running = false;
    return;
  }

  const jobs = targets.map(target => async () => {
    const release = await sem.acquire();
    try {
      if (signal.aborted) return;

      // Run each module sequentially against this target
      for (const runner of runners) {
        if (signal.aborted) break;
        try {
          const found = await runner(target, scanOpts);
          for (const f of found) {
            _findings.push(f);
            onFinding(f);
          }
        } catch (err) {
          if (err.name === 'AbortError') break;
          // Module errors are non-fatal; continue with next module
        }
      }

      tested++;
      onProgress({ tested, total, findings: _findings.length });
    } finally {
      release();
    }
  });

  try {
    await Promise.all(jobs.map(j => j()));
  } catch (err) {
    if (err.name !== 'AbortError') onError(err);
  } finally {
    _running = false;
    if (!signal.aborted) {
      onComplete({ findings: _findings, total: tested });
    }
  }
}

export function stopScan() {
  _controller?.abort();
  _running = false;
}

export function isScanRunning() { return _running; }

export function cleanupScan() {
  stopScan();
  _findings = [];
}

export function getFindings() { return [..._findings]; }

export function clearFindings() { _findings = []; }
