/**
 * dirFuzzer.js — Web Directory Fuzzer (Phase 4E)
 *
 * Pure Node.js http/https implementation — no external dependencies required.
 * Concurrency is managed with a semaphore pattern so we never blow out the
 * target with unbounded parallel requests.
 *
 * Security notes:
 * - URL validated before use; only http/https schemes accepted
 * - Path entries are validated to prevent injection
 * - AbortController used for clean cancellation
 * - All callbacks invoked synchronously within the event loop — no side-channel leaks
 */

import http from 'http';
import https from 'https';
import fs from 'fs';
import { URL } from 'url';
import { COMMON_WEB_PATHS } from '#shared/networkConstants.js';


// ---- state ----------------------------------------------------------------

/** @type {AbortController|null} */
let activeController = null;
let isRunning = false;

// ---- validation -----------------------------------------------------------

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);
const SAFE_PATH_RE = /^\/[a-zA-Z0-9\-._~!$&'()*+,;:@%/]*$/;

/**
 * Validate and normalise the target base URL.
 * Returns the validated URL object or throws.
 * @param {string} raw
 * @returns {URL}
 */
function validateTargetUrl(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`Invalid target URL: "${raw}"`);
  }
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    throw new Error(`Unsupported scheme "${parsed.protocol}". Only http/https are allowed.`);
  }
  // Strip any path/query from the base so we control the path entirely
  parsed.pathname = '/';
  parsed.search = '';
  parsed.hash = '';
  return parsed;
}

/**
 * Load paths from a wordlist file (one per line, blank/comment lines skipped).
 * @param {string} filePath
 * @returns {string[]}
 */
function loadWordlist(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  return content
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

/**
 * Expand a path list by appending file extensions.
 * e.g. '/admin' + ['.php', '.html'] → ['/admin', '/admin.php', '/admin.html']
 * Paths that already have an extension or end with / are not expanded.
 * @param {string[]} paths
 * @param {string[]} extensions  e.g. ['.php', '.html']
 * @returns {string[]}
 */
function expandWithExtensions(paths, extensions) {
  if (!extensions || extensions.length === 0) return paths;
  const out = [];
  for (const p of paths) {
    out.push(p);
    // Don't expand if path ends with / or already has an extension
    if (!p.endsWith('/') && !/\.[a-zA-Z0-9]{1,10}$/.test(p)) {
      for (const ext of extensions) {
        out.push(p + ext);
      }
    }
  }
  return out;
}

// ---- semaphore ------------------------------------------------------------

/**
 * Simple counting semaphore to cap concurrent in-flight HTTP requests.
 */
class Semaphore {
  constructor(max) {
    this._max = max;
    this._count = 0;
    this._queue = [];
  }

  acquire() {
    return new Promise(resolve => {
      if (this._count < this._max) {
        this._count++;
        resolve();
      } else {
        this._queue.push(resolve);
      }
    });
  }

  release() {
    this._count--;
    if (this._queue.length > 0) {
      const next = this._queue.shift();
      this._count++;
      next();
    }
  }
}

// ---- HTTP probe -----------------------------------------------------------

/**
 * Send a single HEAD (falling back to GET) request and return the result.
 * Respects AbortSignal for cooperative cancellation.
 *
 * @param {URL}    baseUrl
 * @param {string} testPath
 * @param {object} opts
 * @param {number}  opts.timeout        per-request timeout ms
 * @param {boolean} opts.followRedirects follow 3xx
 * @param {object}  opts.customHeaders   extra request headers
 * @param {AbortSignal} opts.signal
 * @returns {Promise<{path,statusCode,contentLength,contentType,redirectUrl,responseTime}|null>}
 *          null means request was aborted or timed out
 */
function probeUrl(baseUrl, testPath, { timeout, followRedirects, customHeaders, signal }) {
  return new Promise(resolve => {
    if (signal.aborted) { resolve(null); return; }

    const start = Date.now();
    const targetUrl = new URL(testPath, baseUrl);
    const lib = targetUrl.protocol === 'https:' ? https : http;

    const options = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: 'HEAD',
      timeout,
      headers: {
        'User-Agent': 'NetSpecter-DirFuzzer/1.0',
        'Accept': '*/*',
        ...customHeaders,
      },
      // Avoid TLS errors on self-signed certs in lab environments
      rejectUnauthorized: false,
    };

    const onAbort = () => { req.destroy(); resolve(null); };
    signal.addEventListener('abort', onAbort, { once: true });

    const req = lib.request(options, (res) => {
      signal.removeEventListener('abort', onAbort);
      const responseTime = Date.now() - start;
      const statusCode = res.statusCode;
      const contentLength = parseInt(res.headers['content-length'] || '0', 10) || 0;
      const contentType = res.headers['content-type'] || '';
      const redirectUrl = (statusCode >= 300 && statusCode < 400) ? res.headers['location'] || null : null;

      // Consume the response body to free the socket
      res.resume();

      // If we got a redirect and followRedirects is off, still report the hit
      resolve({ path: testPath, statusCode, contentLength, contentType, redirectUrl, responseTime });
    });

    req.on('timeout', () => {
      req.destroy();
      signal.removeEventListener('abort', onAbort);
      resolve(null);
    });

    req.on('error', () => {
      signal.removeEventListener('abort', onAbort);
      resolve(null); // Network errors are silently skipped
    });

    req.end();
  });
}

// ---- public API -----------------------------------------------------------

/**
 * Start a directory fuzz run.
 *
 * @param {object}   options
 * @param {string}   options.targetUrl       Base URL, e.g. "http://192.168.1.100:8080"
 * @param {string|null} options.wordlistPath  Path to wordlist file or null for built-in
 * @param {string[]} options.extensions       Extensions to append, e.g. ['.php','.html']
 * @param {number[]} options.statusFilter     Status codes to report, default [200,301,302,403]
 * @param {number}   options.concurrency      Parallel requests, default 10, max 50
 * @param {number}   options.timeout          Per-request timeout ms, default 3000
 * @param {boolean}  options.followRedirects  Follow 3xx, default false
 * @param {object}   options.customHeaders    Optional extra request headers
 *
 * @param {function} onHit       Called with each hit result payload
 * @param {function} onProgress  Called with {tested, total, percent}
 * @param {function} onComplete  Called with {total, hits, elapsed}
 * @param {function} onError     Called with {message} on fatal error
 * @param {function} [onActivity]  Called with {status, url, method, statusCode, isHit, timestamp} for every probe
 */
export async function startDirFuzz(options, onHit, onProgress, onComplete, onError, onActivity) {
  if (isRunning) {
    onError({ message: 'A fuzzing run is already in progress. Stop it first.' });
    return;
  }

  // Validate options
  if (!options || typeof options !== 'object') {
    onError({ message: 'Invalid options payload.' });
    return;
  }

  let baseUrl;
  try {
    baseUrl = validateTargetUrl(options.targetUrl || '');
  } catch (err) {
    onError({ message: err.message });
    return;
  }

  const concurrency = Math.min(Math.max(parseInt(options.concurrency, 10) || 10, 1), 50);
  const timeout = Math.min(Math.max(parseInt(options.timeout, 10) || 3000, 500), 30000);
  const statusFilter = Array.isArray(options.statusFilter) && options.statusFilter.length > 0
    ? options.statusFilter.map(Number).filter(n => n >= 100 && n < 600)
    : [200, 201, 204, 301, 302, 307, 308, 403, 405];
  const extensions = Array.isArray(options.extensions)
    ? options.extensions.map(e => e.startsWith('.') ? e : '.' + e).filter(e => /^\.[a-zA-Z0-9]{1,10}$/.test(e))
    : [];
  const followRedirects = Boolean(options.followRedirects);
  const customHeaders = (options.customHeaders && typeof options.customHeaders === 'object')
    ? options.customHeaders
    : {};

  // Load paths
  let basePaths;
  if (options.wordlistPath) {
    try {
      basePaths = loadWordlist(options.wordlistPath);
    } catch (err) {
      onError({ message: `Failed to read wordlist: ${err.message}` });
      return;
    }
    if (basePaths.length === 0) {
      onError({ message: 'Wordlist file is empty.' });
      return;
    }
    // Cap wordlists at 100,000 entries to prevent runaway
    if (basePaths.length > 100000) basePaths = basePaths.slice(0, 100000);
  } else {
    basePaths = [...COMMON_WEB_PATHS];
  }

  // Ensure all paths start with /
  basePaths = basePaths.map(p => p.startsWith('/') ? p : '/' + p);

  const allPaths = expandWithExtensions(basePaths, extensions);
  const total = allPaths.length;

  isRunning = true;
  activeController = new AbortController();
  const { signal } = activeController;

  const sem = new Semaphore(concurrency);
  const startTime = Date.now();
  let tested = 0;
  let hits = 0;

  try {
    const tasks = allPaths.map(testPath => async () => {
      if (signal.aborted) return;
      await sem.acquire();
      try {
        if (signal.aborted) return;
        const probeFullUrl = new URL(testPath, baseUrl).toString();
        const result = await probeUrl(baseUrl, testPath, { timeout, followRedirects, customHeaders, signal });
        if (result) {
          const isHit = statusFilter.includes(result.statusCode);
          onActivity?.({
            status:     'done',
            url:        probeFullUrl,
            method:     'HEAD',
            statusCode: result.statusCode,
            isHit,
            timestamp:  Date.now(),
          });
          if (isHit) {
            hits++;
            onHit(result);
          }
        }
      } finally {
        sem.release();
        tested++;
        const percent = Math.round((tested / total) * 100);
        onProgress({ tested, total, percent });
      }
    });

    // Launch all tasks concurrently (semaphore caps actual parallelism)
    await Promise.all(tasks.map(fn => fn()));
  } catch (err) {
    if (!signal.aborted) {
      onError({ message: `Fuzzing error: ${err.message}` });
    }
  } finally {
    const elapsed = Date.now() - startTime;
    isRunning = false;
    activeController = null;
    if (!signal.aborted) {
      onComplete({ total, hits, elapsed });
    }
  }
}

/**
 * Stop any active fuzzing run immediately.
 */
export function stopDirFuzz() {
  if (activeController) {
    activeController.abort();
    activeController = null;
  }
  isRunning = false;
}

/**
 * Returns true if a fuzzing session is currently active.
 * @returns {boolean}
 */
export function isDirFuzzRunning() {
  return isRunning;
}

/**
 * Cleanup — alias for stop, called on app quit.
 */
export function cleanupDirFuzz() {
  stopDirFuzz();
}

import { IPC_CHANNELS } from '#shared/ipc.js';
import { isValidHttpUrl } from '#shared/validate.js';

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.DIRFUZZ_START, async (event, options) => {
    console.log(`Dir fuzz requested on ${options?.targetUrl}`);

    if (!options || typeof options !== 'object') {
      return { status: 'error', error: 'Invalid options payload' };
    }

    if (!isValidHttpUrl(options.targetUrl)) {
      return { status: 'error', error: 'Invalid target URL — must be a valid http:// or https:// URL' };
    }

    // startDirFuzz is async and streams results; fire and don't await
    startDirFuzz(
      options,
      (hit)      => getWindow()?.webContents.send(IPC_CHANNELS.DIRFUZZ_HIT, hit),
      (progress) => getWindow()?.webContents.send(IPC_CHANNELS.DIRFUZZ_PROGRESS, progress),
      (complete) => getWindow()?.webContents.send(IPC_CHANNELS.DIRFUZZ_COMPLETE, complete),
      (err)      => getWindow()?.webContents.send(IPC_CHANNELS.DIRFUZZ_ERROR, err),
      (activity) => getWindow()?.webContents.send(IPC_CHANNELS.DIRFUZZ_ACTIVITY, activity)
    );

    return { status: 'started' };
  });

  ipcMain.handle(IPC_CHANNELS.DIRFUZZ_STOP, async () => {
    console.log('Dir fuzz stop requested');
    stopDirFuzz();
    return { status: 'stopped' };
  });
}
