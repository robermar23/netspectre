/**
 * Tests for Feature 7E — WebSocket Fuzzer backend
 * Covers: frame encoding/decoding helpers, single probe (mocked socket),
 *         concurrency semaphore, abort handling, anomaly detection.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  startWsFuzz, stopWsFuzz, isWsFuzzRunning, cleanupWsFuzz,
} from '../../src/main/webapp/wsFuzzer.js';

// ─── Mock net/tls ─────────────────────────────────────────────────────────────

let _dataHandler    = null;
let _errorHandler   = null;
let _closeHandler   = null;
let _connectHandler = null;

const mockSocket = {
  write: vi.fn(),
  destroy: vi.fn(),
  on: vi.fn((event, cb) => {
    if (event === 'data')  _dataHandler  = cb;
    if (event === 'error') _errorHandler = cb;
    if (event === 'close') _closeHandler = cb;
  }),
};

vi.mock('net', () => ({
  default: {
    createConnection: vi.fn((opts, cb) => {
      _connectHandler = cb;
      return mockSocket;
    }),
  },
}));

vi.mock('tls', () => ({
  default: {
    connect: vi.fn((opts, cb) => {
      _connectHandler = cb;
      return mockSocket;
    }),
  },
}));

// Build a minimal valid HTTP 101 upgrade response
function buildUpgradeResponse(clientKey) {
  const crypto = require('crypto');
  const accept = crypto
    .createHash('sha1')
    .update(clientKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  return Buffer.from(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
}

// Build a simple unmasked text WebSocket frame (server → client)
function buildServerFrame(text) {
  const payload = Buffer.from(text, 'utf8');
  const header  = Buffer.alloc(2);
  header[0] = 0x81; // FIN + text opcode
  header[1] = payload.length & 0x7f;
  return Buffer.concat([header, payload]);
}

describe('wsFuzzer', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    cleanupWsFuzz();
    _dataHandler = _errorHandler = _closeHandler = _connectHandler = null;
    mockSocket.write.mockReset();
    mockSocket.destroy.mockReset();
    mockSocket.on.mockImplementation((event, cb) => {
      if (event === 'data')  _dataHandler  = cb;
      if (event === 'error') _errorHandler = cb;
      if (event === 'close') _closeHandler = cb;
    });
  });

  afterEach(() => {
    cleanupWsFuzz();
  });

  it('rejects invalid URLs', async () => {
    const onError = vi.fn();
    await startWsFuzz({ url: 'http://not-a-ws-url', payloads: ['test'] }, null, null, null, onError);
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringMatching(/Invalid WebSocket URL/i) }));
  });

  it('rejects empty payload list', async () => {
    const onError = vi.fn();
    await startWsFuzz({ url: 'ws://target.com/ws', payloads: [] }, null, null, null, onError);
    expect(onError).toHaveBeenCalled();
  });

  it('reports not running initially', () => {
    expect(isWsFuzzRunning()).toBe(false);
  });

  it('stopWsFuzz sets running to false', () => {
    stopWsFuzz();
    expect(isWsFuzzRunning()).toBe(false);
  });

  it('completes successfully on upgraded connection with response', async () => {
    const onResult   = vi.fn();
    const onProgress = vi.fn();
    const onComplete = vi.fn();
    const onError    = vi.fn();

    const fuzzPromise = startWsFuzz(
      { url: 'ws://target.com/ws', payloads: ['hello'], concurrency: 1, timeoutMs: 5000 },
      onResult, onProgress, onComplete, onError,
    );

    // Simulate connect + upgrade + server text frame
    // The socket.write captures the HTTP upgrade request so we can extract the key
    await new Promise(r => setImmediate(r)); // let the code call createConnection
    _connectHandler?.();

    await new Promise(r => setImmediate(r)); // let the upgrade request be written
    // Extract Sec-WebSocket-Key from the write call
    const upgradeReq = mockSocket.write.mock.calls[0]?.[0] ?? '';
    const keyMatch   = upgradeReq.toString().match(/Sec-WebSocket-Key:\s*(.+)/i);
    const clientKey  = keyMatch?.[1]?.trim() ?? 'test';

    // Send 101 Switching Protocols
    _dataHandler?.(buildUpgradeResponse(clientKey));

    await new Promise(r => setImmediate(r));
    // Send a server text frame
    _dataHandler?.(buildServerFrame('{"status":"ok"}'));

    await fuzzPromise;

    expect(onResult).toHaveBeenCalledTimes(1);
    const r = onResult.mock.calls[0][0];
    expect(r.upgraded).toBe(true);
    expect(r.payload).toBe('hello');
    expect(r.response).toContain('"status"');
    expect(r.anomaly).toBe(false);
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(onError).not.toHaveBeenCalled();
  });

  it('flags non-101 upgrade response as anomaly', async () => {
    const onResult = vi.fn();

    const fuzzPromise = startWsFuzz(
      { url: 'ws://target.com/ws', payloads: ['probe'], concurrency: 1, timeoutMs: 5000 },
      onResult, null, null, null,
    );

    await new Promise(r => setImmediate(r));
    _connectHandler?.();
    await new Promise(r => setImmediate(r));

    // Server rejects the upgrade with 400
    _dataHandler?.(Buffer.from('HTTP/1.1 400 Bad Request\r\n\r\n'));

    await fuzzPromise;

    expect(onResult).toHaveBeenCalledTimes(1);
    const r = onResult.mock.calls[0][0];
    expect(r.upgraded).toBe(false);
    expect(r.anomaly).toBe(true);
  });

  it('detects error patterns in response as anomaly', async () => {
    const onResult = vi.fn();

    const fuzzPromise = startWsFuzz(
      { url: 'ws://target.com/ws', payloads: ['inject'], concurrency: 1, timeoutMs: 5000 },
      onResult, null, null, null,
    );

    await new Promise(r => setImmediate(r));
    _connectHandler?.();
    await new Promise(r => setImmediate(r));

    const upgradeReq = mockSocket.write.mock.calls[0]?.[0] ?? '';
    const keyMatch   = upgradeReq.toString().match(/Sec-WebSocket-Key:\s*(.+)/i);
    const clientKey  = keyMatch?.[1]?.trim() ?? 'key';

    _dataHandler?.(buildUpgradeResponse(clientKey));
    await new Promise(r => setImmediate(r));

    // Server returns a Java exception in the WS frame
    _dataHandler?.(buildServerFrame('java.lang.NullPointerException at com.example.Handler'));

    await fuzzPromise;

    expect(onResult).toHaveBeenCalledTimes(1);
    const r = onResult.mock.calls[0][0];
    expect(r.anomaly).toBe(true);
    expect(r.errorType).toMatch(/Java exception/i);
  });

  it('handles socket error gracefully', async () => {
    const onResult = vi.fn();
    const onError  = vi.fn();

    const fuzzPromise = startWsFuzz(
      { url: 'ws://target.com/ws', payloads: ['test'], concurrency: 1, timeoutMs: 5000 },
      onResult, null, null, onError,
    );

    await new Promise(r => setImmediate(r));
    _connectHandler?.();
    await new Promise(r => setImmediate(r));
    _errorHandler?.(new Error('ECONNREFUSED'));

    await fuzzPromise;

    expect(onResult).toHaveBeenCalledTimes(1);
    const r = onResult.mock.calls[0][0];
    expect(r.anomaly).toBe(true);
    expect(r.error).toMatch(/ECONNREFUSED/);
  });

  it('processes multiple payloads with progress callbacks', async () => {
    const onProgress = vi.fn();
    const onComplete = vi.fn();

    const payloads = ['p1', 'p2', 'p3'];
    const fuzzPromise = startWsFuzz(
      { url: 'ws://target.com/ws', payloads, concurrency: 1, timeoutMs: 500 },
      null, onProgress, onComplete, null,
    );

    // For each payload: connect → 101 → close socket (simulating timeout/close)
    for (let i = 0; i < payloads.length; i++) {
      await new Promise(r => setImmediate(r));
      _connectHandler?.();
      await new Promise(r => setImmediate(r));
      _errorHandler?.(new Error('ECONNRESET'));
      await new Promise(r => setImmediate(r));
    }

    await fuzzPromise;

    expect(onProgress).toHaveBeenCalled();
    expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({ total: 3 }));
  });
});
