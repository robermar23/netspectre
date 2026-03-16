/**
 * Feature 7E — OAST Manager (Out-of-Band Application Security Testing)
 *
 * Operates two modes in parallel:
 *   1. Local HTTP listener — starts an HTTP server on the user's local IP so
 *      targets reachable on the same LAN can trigger callbacks.
 *   2. External OAST server — poll-based integration with an interactsh-compatible
 *      server that the user self-hosts (URL configured in Settings).
 *
 * Public API:
 *   startOast(port, externalUrl)  → { success, localUrl }
 *   stopOast()
 *   isOastRunning()
 *   allocateToken(meta)           → token string
 *   correlate(token)              → meta | null  (marks as hit)
 *   getPendingTokens()            → Map snapshot
 *   getCallbacks()                → recent callback list
 *   clearCallbacks()
 *   registerIpcHandlers(ipcMain, getWindow)
 */

import http    from 'http';
import os      from 'os';
import crypto  from 'crypto';
import { OAST_DEFAULT_PORT, OAST_TOKEN_TTL_MS, OAST_MAX_PENDING } from '#shared/webConstants.js';
import { IPC_CHANNELS } from '#shared/ipc.js';

// ─── State ─────────────────────────────────────────────────────────────────────

let _server        = null;          // http.Server
let _running       = false;
let _localUrl      = null;          // e.g. http://192.168.1.5:7331
let _localPort     = OAST_DEFAULT_PORT;
let _pendingTokens = new Map();     // token → { meta, ts, hit: bool }
let _callbacks     = [];            // recent hit records for UI display
let _onCallback    = null;          // injected by IPC handler
let _ttlTimer      = null;          // setInterval for TTL cleanup

// ─── Local network IP detection ────────────────────────────────────────────────

function _getLocalIp() {
  try {
    const ifaces = os.networkInterfaces();
    for (const list of Object.values(ifaces)) {
      for (const iface of list) {
        if (iface.family === 'IPv4' && !iface.internal) return iface.address;
      }
    }
  } catch { /* ignore */ }
  return '127.0.0.1';
}

/**
 * Returns all non-internal IPv4 interfaces available on this machine,
 * plus a sentinel entry for "all interfaces" (0.0.0.0).
 * Each entry: { name: string, address: string }
 */
export function getLocalInterfaces() {
  const results = [{ name: 'All interfaces (0.0.0.0)', address: '0.0.0.0' }];
  try {
    const ifaces = os.networkInterfaces();
    for (const [name, list] of Object.entries(ifaces)) {
      for (const iface of list) {
        if (iface.family === 'IPv4' && !iface.internal) {
          results.push({ name: `${name} (${iface.address})`, address: iface.address });
        }
      }
    }
  } catch { /* ignore */ }
  return results;
}

// ─── Token management ──────────────────────────────────────────────────────────

/**
 * Allocate a unique OAST probe token tied to metadata (module, target URL, param).
 * Returns the token string to embed in payloads.
 */
export function allocateToken(meta = {}) {
  if (_pendingTokens.size >= OAST_MAX_PENDING) {
    // Evict oldest unhit token to cap memory usage
    for (const [k, v] of _pendingTokens) {
      if (!v.hit) { _pendingTokens.delete(k); break; }
    }
  }
  const token = crypto.randomBytes(12).toString('hex');
  _pendingTokens.set(token, { meta, ts: Date.now(), hit: false });
  return token;
}

/**
 * Returns the OAST payload URL for a given token (or allocates one).
 * Callers embed this in injection payloads.
 */
export function getOastUrl(token) {
  if (!_running || !_localUrl) return null;
  return `${_localUrl}/oast/${token}`;
}

/**
 * Attempt to correlate an incoming token with a pending probe.
 * Marks the probe as hit and returns its metadata. Returns null if unknown.
 */
export function correlate(token) {
  const probe = _pendingTokens.get(token);
  if (!probe) return null;
  probe.hit = true;
  return probe.meta;
}

export function getPendingTokens() {
  return new Map(_pendingTokens);
}

export function getCallbacks() {
  return [..._callbacks];
}

export function clearCallbacks() {
  _callbacks = [];
  _pendingTokens.clear();
}

// ─── TTL cleanup ───────────────────────────────────────────────────────────────

function _startTtlCleanup() {
  _ttlTimer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of _pendingTokens) {
      if (!v.hit && now - v.ts > OAST_TOKEN_TTL_MS) _pendingTokens.delete(k);
    }
  }, 30_000);
  _ttlTimer.unref?.();
}

function _stopTtlCleanup() {
  if (_ttlTimer) { clearInterval(_ttlTimer); _ttlTimer = null; }
}

// ─── HTTP listener ─────────────────────────────────────────────────────────────

export function startOast(port = OAST_DEFAULT_PORT, callbackIpOrFn = null, onCallbackFn = null) {
  if (_running) return { success: false, error: 'OAST already running.' };

  // Back-compat: startOast(port, fn) is equivalent to startOast(port, null, fn)
  const callbackIp = (typeof callbackIpOrFn === 'string') ? callbackIpOrFn : null;
  const callback   = (typeof callbackIpOrFn === 'function') ? callbackIpOrFn : onCallbackFn;

  _onCallback = callback;
  _localPort  = port;

  return new Promise((resolve) => {
    // Use caller-specified IP for callback URLs; fall back to auto-detect.
    // If '0.0.0.0' is selected, auto-detect the best non-internal IP for display.
    const resolvedIp = (callbackIp && callbackIp !== '0.0.0.0') ? callbackIp : _getLocalIp();

    _server = http.createServer((req, res) => {
      // Accept any path matching /oast/<token>
      const match = req.url?.match(/^\/oast\/([a-f0-9]{24})/);
      if (match) {
        const token   = match[1];
        const meta    = correlate(token);
        const hitRecord = {
          token,
          ts:       Date.now(),
          remoteIp: req.socket?.remoteAddress ?? 'unknown',
          path:     req.url,
          method:   req.method,
          headers:  req.headers,
          meta,
        };
        _callbacks.unshift(hitRecord);
        if (_callbacks.length > 200) _callbacks.length = 200;

        if (_onCallback) _onCallback(hitRecord);

        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
        return;
      }

      // Health probe
      if (req.url === '/health') {
        res.writeHead(200);
        res.end('oast-ok');
        return;
      }

      res.writeHead(404);
      res.end();
    });

    _server.once('error', (err) => {
      _running  = false;
      _localUrl = null;
      resolve({ success: false, error: err.message });
    });

    // Bind on all interfaces so LAN targets can reach it from any network path
    _server.listen(port, '0.0.0.0', () => {
      _running  = true;
      _localUrl = `http://${resolvedIp}:${port}`;
      _startTtlCleanup();
      resolve({ success: true, localUrl: _localUrl, localIp: resolvedIp, port });
    });
  });
}

export function stopOast() {
  _stopTtlCleanup();
  _onCallback = null;
  if (_server) {
    _server.close();
    _server = null;
  }
  _running  = false;
  _localUrl = null;
}

export function isOastRunning() { return _running; }
export function getOastLocalUrl() { return _localUrl; }
export function getOastPort() { return _localPort; }

// ─── IPC Registration ──────────────────────────────────────────────────────────

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.OAST_GET_INTERFACES, () => getLocalInterfaces());

  ipcMain.handle(IPC_CHANNELS.OAST_START, async (_event, { port, callbackIp } = {}) => {
    const p  = (typeof port === 'number' && port > 1024 && port < 65535) ? port : OAST_DEFAULT_PORT;
    const ip = (typeof callbackIp === 'string' && callbackIp) ? callbackIp : null;

    const result = await startOast(p, ip, (hit) => {
      getWindow()?.webContents.send(IPC_CHANNELS.OAST_CALLBACK, hit);
    });

    if (result.success) {
      getWindow()?.webContents.send(IPC_CHANNELS.OAST_STATUS, {
        running:  true,
        localUrl: result.localUrl,
        port:     result.port,
        localIp:  result.localIp,
      });
    }
    return result;
  });

  ipcMain.handle(IPC_CHANNELS.OAST_STOP, async () => {
    stopOast();
    getWindow()?.webContents.send(IPC_CHANNELS.OAST_STATUS, { running: false });
    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.OAST_GET_TOKEN, async (_event, meta = {}) => {
    if (!_running) return { success: false, error: 'OAST not running' };
    const token = allocateToken(meta);
    return { success: true, token, url: getOastUrl(token) };
  });

  ipcMain.handle(IPC_CHANNELS.OAST_CLEAR, async () => {
    clearCallbacks();
    return { success: true };
  });
}
