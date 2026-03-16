/**
 * Feature 7E — WebSocket Fuzzer
 *
 * Establishes real WebSocket connections using Node.js net/tls module
 * (RFC 6455 handshake + frame encode/decode — zero external 'ws' package dependency).
 *
 * Attack types:
 *   • Payload injection — send a configurable payload list to the WS endpoint
 *   • Error/anomaly detection — flags responses containing known error patterns
 *   • Timing-based detection — frames that take unusually long to respond
 *
 * Public API:
 *   startWsFuzz(opts, onResult, onProgress, onComplete, onError)
 *   stopWsFuzz()
 *   isWsFuzzRunning()
 *   cleanupWsFuzz()
 *   registerIpcHandlers(ipcMain, getWindow)
 *
 * opts: {
 *   url:           string         // ws:// or wss://
 *   payloads:      string[]       // list of messages to send
 *   concurrency:   number         // simultaneous connections (default 3)
 *   timeoutMs:     number         // per-frame timeout (default 8000)
 *   extraHeaders:  object         // additional Upgrade headers
 * }
 */

import net    from 'net';
import tls    from 'tls';
import crypto from 'crypto';
import { WS_FUZZ_DEFAULT_CONCURRENCY, WS_FUZZ_DEFAULT_TIMEOUT_MS } from '#shared/webConstants.js';
import { IPC_CHANNELS } from '#shared/ipc.js';

// ─── State ─────────────────────────────────────────────────────────────────────

let _running    = false;
let _aborted    = false;

// ─── RFC 6455 WebSocket helpers ────────────────────────────────────────────────

/** Build the HTTP Upgrade handshake for a WebSocket connection */
function _buildUpgradeRequest(host, path, extraHeaders = {}) {
  const key = crypto.randomBytes(16).toString('base64');
  const lines = [
    `GET ${path || '/'} HTTP/1.1`,
    `Host: ${host}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`,
    'Sec-WebSocket-Version: 13',
    ...Object.entries(extraHeaders).map(([k, v]) => `${k}: ${v}`),
    '',
    '',
  ];
  return { raw: lines.join('\r\n'), key };
}

/** Verify server's Sec-WebSocket-Accept value */
function _verifyAccept(serverAccept, clientKey) {
  const expected = crypto
    .createHash('sha1')
    .update(clientKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  return expected === serverAccept;
}

/** Encode a single client-to-server WebSocket frame (masked, text opcode) */
function _encodeFrame(payload) {
  const data   = Buffer.from(payload, 'utf8');
  const maskKey = crypto.randomBytes(4);
  const masked  = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) masked[i] = data[i] ^ maskKey[i % 4];

  let header;
  if (data.length < 126) {
    header = Buffer.alloc(6);
    header[0] = 0x81;                // FIN=1, opcode=1 (text)
    header[1] = 0x80 | data.length; // MASK=1, 7-bit length
    maskKey.copy(header, 2);
  } else if (data.length < 65536) {
    header = Buffer.alloc(8);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(data.length, 2);
    maskKey.copy(header, 4);
  } else {
    header = Buffer.alloc(14);
    header[0] = 0x81;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(data.length), 2);
    maskKey.copy(header, 10);
  }

  return Buffer.concat([header, masked]);
}

/** Decode one or more server-sent frames from a Buffer chunk */
function _decodeFrames(buf) {
  const messages = [];
  let offset = 0;

  while (offset + 2 <= buf.length) {
    const b0     = buf[offset];
    const b1     = buf[offset + 1];
    const opcode = b0 & 0x0f;
    const masked  = !!(b1 & 0x80);
    let payloadLen = b1 & 0x7f;
    let headerEnd = offset + 2;

    if (payloadLen === 126) {
      if (buf.length < headerEnd + 2) break;
      payloadLen = buf.readUInt16BE(headerEnd);
      headerEnd += 2;
    } else if (payloadLen === 127) {
      if (buf.length < headerEnd + 8) break;
      payloadLen = Number(buf.readBigUInt64BE(headerEnd));
      headerEnd += 8;
    }
    if (masked) headerEnd += 4;

    if (buf.length < headerEnd + payloadLen) break;

    const payload = buf.slice(headerEnd, headerEnd + payloadLen);
    offset = headerEnd + payloadLen;

    if (opcode === 0x08) { messages.push({ type: 'close', body: '' }); break; }
    if (opcode === 0x01) messages.push({ type: 'text',  body: payload.toString('utf8') });
    if (opcode === 0x02) messages.push({ type: 'binary', body: `[binary ${payload.length}b]` });
  }

  return messages;
}

// Error pattern detection in server responses
const ERROR_PATTERNS = [
  { re: /exception|stacktrace|at .*\(.*\.java/i,  type: 'Java exception' },
  { re: /syntaxerror|typeerror|referenceerror/i,   type: 'JS error' },
  { re: /you have an error in your sql/i,          type: 'SQL error' },
  { re: /traceback \(most recent call last\)/i,    type: 'Python traceback' },
  { re: /warning.*mysql|mysqli/i,                  type: 'PHP MySQL warning' },
  { re: /internal server error/i,                  type: 'Internal server error' },
  { re: /access denied for user/i,                 type: 'DB access denied' },
  { re: /undefined.*index|undefined variable/i,    type: 'PHP undefined variable' },
];

// ─── Single WS probe ───────────────────────────────────────────────────────────

function _sendWsProbe(opts) {
  return new Promise((resolve, reject) => {
    const { host, port, path, isSecure, payload, extraHeaders, timeoutMs } = opts;

    const connectFn = isSecure ? tls.connect : net.createConnection;
    const connArgs  = isSecure
      ? [{ host, port, rejectUnauthorized: false }, onConnect]
      : [{ host, port }, onConnect];

    const { raw: upgradeReq, key: wsKey } = _buildUpgradeRequest(`${host}:${port}`, path, extraHeaders);

    let socket  = null;
    let buf     = Buffer.alloc(0);
    let upgraded = false;
    let timer   = null;

    function cleanup() {
      if (timer) { clearTimeout(timer); timer = null; }
      socket?.destroy();
    }

    function onConnect() {
      timer = setTimeout(() => {
        cleanup();
        reject(Object.assign(new Error('WS probe timeout'), { code: 'ETIMEDOUT' }));
      }, timeoutMs);

      socket.write(upgradeReq);
    }

    try {
      socket = connectFn(...connArgs);
    } catch (e) {
      return reject(e);
    }

    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);

      if (!upgraded) {
        const hdrEnd = buf.indexOf('\r\n\r\n');
        if (hdrEnd === -1) return;

        const hdrStr = buf.slice(0, hdrEnd).toString();
        const statusLine = hdrStr.split('\r\n')[0];

        if (!statusLine.includes('101')) {
          cleanup();
          return resolve({
            statusLine,
            upgraded: false,
            payload,
            response: '',
            durationMs: 0,
            error: `Server rejected upgrade: ${statusLine}`,
          });
        }

        // Verify accept key
        const acceptMatch = hdrStr.match(/Sec-WebSocket-Accept:\s*(.+)/i);
        const serverAccept = acceptMatch?.[1]?.trim() ?? '';
        if (!_verifyAccept(serverAccept, wsKey)) {
          cleanup();
          return resolve({ upgraded: false, payload, error: 'Invalid Sec-WebSocket-Accept', response: '' });
        }

        upgraded = true;
        buf = buf.slice(hdrEnd + 4); // remaining bytes after HTTP headers

        // Send the fuzz payload
        const t0 = Date.now();
        socket.write(_encodeFrame(payload));

        // Reset timer for response wait
        clearTimeout(timer);
        timer = setTimeout(() => {
          cleanup();
          resolve({ upgraded: true, payload, response: '', durationMs: timeoutMs, timedOut: true });
        }, timeoutMs);

        if (buf.length > 0) processFrames(t0);
        return;
      }

      processFrames(Date.now());
    });

    function processFrames(t0) {
      if (!buf.length) return;
      const frames = _decodeFrames(buf);
      if (!frames.length) return;

      clearTimeout(timer);
      const response = frames.map(f => f.body).join('\n');
      const durationMs = Date.now() - t0;

      // Detect error patterns
      const errorHit = ERROR_PATTERNS.find(ep => ep.re.test(response));

      cleanup();
      resolve({
        upgraded:   true,
        payload,
        response,
        durationMs,
        errorType:  errorHit?.type ?? null,
        frameTypes: frames.map(f => f.type),
      });
    }

    socket.on('error', (err) => { cleanup(); reject(err); });
    socket.on('close', () => { cleanup(); resolve({ upgraded, payload, response: buf.toString('utf8'), durationMs: 0 }); });
  });
}

// ─── Semaphore ─────────────────────────────────────────────────────────────────

class Semaphore {
  constructor(n) {
    this._n = n;
    this._queue = [];
  }
  acquire() {
    if (this._n > 0) { this._n--; return Promise.resolve(); }
    return new Promise(r => this._queue.push(r));
  }
  release() {
    if (this._queue.length > 0) this._queue.shift()();
    else this._n++;
  }
}

// ─── Main fuzzer ───────────────────────────────────────────────────────────────

export async function startWsFuzz(opts, onResult, onProgress, onComplete, onError) {
  if (_running) { onError?.(new Error('WS Fuzzer already running')); return; }

  _running = true;
  _aborted = false;

  const {
    url,
    payloads     = [],
    concurrency  = WS_FUZZ_DEFAULT_CONCURRENCY,
    timeoutMs    = WS_FUZZ_DEFAULT_TIMEOUT_MS,
    extraHeaders = {},
  } = opts;

  let parsed;
  try { parsed = new URL(url); } catch (e) {
    _running = false;
    onError?.(new Error(`Invalid WebSocket URL: ${url}`));
    return;
  }

  if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
    _running = false;
    onError?.(new Error(`Invalid WebSocket URL: must use ws:// or wss:// (got ${parsed.protocol})`));
    return;
  }

  if (!payloads.length) {
    _running = false;
    onError?.(new Error('payloads array must not be empty'));
    return;
  }

  const isSecure = parsed.protocol === 'wss:';
  const host     = parsed.hostname;
  const port     = parsed.port ? parseInt(parsed.port, 10) : (isSecure ? 443 : 80);
  const path     = parsed.pathname + parsed.search;

  const sem  = new Semaphore(Math.max(1, Math.min(concurrency, 20)));
  const total = payloads.length;
  let done    = 0;
  let hits    = 0;

  const jobs = payloads.map((payload, index) => async () => {
    if (_aborted) return;
    await sem.acquire();
    if (_aborted) { sem.release(); return; }

    const idx = index;
    try {
      const result = await _sendWsProbe({ host, port, path, isSecure, payload, extraHeaders, timeoutMs });
      done++;

      const hasAnomaly = result.errorType !== null ||
                        result.timedOut   === true  ||
                        !result.upgraded;

      if (hasAnomaly) hits++;

      onResult?.({
        index: idx,
        payload,
        response:    result.response,
        durationMs:  result.durationMs ?? 0,
        upgraded:    result.upgraded,
        errorType:   result.errorType ?? null,
        timedOut:    result.timedOut  ?? false,
        frameTypes:  result.frameTypes ?? [],
        anomaly:     hasAnomaly,
        error:       result.error ?? null,
      });

      onProgress?.({ done, total, hits, pct: Math.round((done / total) * 100) });
    } catch (err) {
      done++;
      onResult?.({
        index: idx, payload,
        response: '', durationMs: 0,
        upgraded: false, errorType: null,
        timedOut: false, frameTypes: [],
        anomaly: true,
        error: err.message,
      });
      onProgress?.({ done, total, hits, pct: Math.round((done / total) * 100) });
    } finally {
      sem.release();
    }
  });

  try {
    await Promise.all(jobs.map(j => j()));
    _running = false;
    onComplete?.({ total, done, hits });
  } catch (err) {
    _running = false;
    if (!_aborted) onError?.(err);
  }
}

export function stopWsFuzz() {
  _aborted = true;
  _running = false;
}

export function isWsFuzzRunning() { return _running; }

export function cleanupWsFuzz() {
  _aborted = true;
  _running = false;
}

// ─── IPC Registration ──────────────────────────────────────────────────────────

export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.WS_FUZZ_START, async (_event, opts = {}) => {
    if (isWsFuzzRunning()) return { success: false, error: 'Fuzzer already running' };

    if (!opts.url || !opts.url.startsWith('ws')) {
      return { success: false, error: 'url must start with ws:// or wss://' };
    }
    if (!Array.isArray(opts.payloads) || !opts.payloads.length) {
      return { success: false, error: 'payloads array is required' };
    }

    const win = getWindow();

    startWsFuzz(
      opts,
      (result)   => win?.webContents.send(IPC_CHANNELS.WS_FUZZ_RESULT,   result),
      (progress) => win?.webContents.send(IPC_CHANNELS.WS_FUZZ_PROGRESS,  progress),
      (complete) => win?.webContents.send(IPC_CHANNELS.WS_FUZZ_COMPLETE,  complete),
      (err)      => win?.webContents.send(IPC_CHANNELS.WS_FUZZ_ERROR,
                      { message: err instanceof Error ? err.message : String(err) }),
    );

    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.WS_FUZZ_STOP, async () => {
    stopWsFuzz();
    return { success: true };
  });
}
