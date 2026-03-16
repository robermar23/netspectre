/**
 * Tests for Feature 7E — OAST Manager
 * Covers: server lifecycle, token allocation/correlation, TTL cleanup, HTTP callback routing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  startOast, stopOast, isOastRunning,
  allocateToken, correlate, getPendingTokens,
  getCallbacks, clearCallbacks, getOastLocalUrl, getOastPort,
} from '../../src/main/webapp/oastManager.js';

// ── Mock http ─────────────────────────────────────────────────────────────────

let _requestHandler = null;
let _listenCallback = null;
let _mockPort       = null;

const mockServer = {
  once: vi.fn((event, cb) => { if (event === 'error') mockServer._errCb = cb; }),
  listen: vi.fn((port, host, cb) => {
    _mockPort = port;
    _listenCallback = cb;
  }),
  close: vi.fn(),
  _errCb: null,
};

vi.mock('http', () => ({
  default: {
    createServer: vi.fn((handler) => {
      _requestHandler = handler;
      return mockServer;
    }),
  },
}));

vi.mock('os', () => ({
  default: {
    networkInterfaces: vi.fn(() => ({
      eth0: [{ family: 'IPv4', internal: false, address: '192.168.1.100' }],
    })),
  },
}));

// Helper to simulate server listening successfully
function triggerListen() {
  _listenCallback?.();
}

// Helper to simulate an incoming HTTP request
function simulateRequest(url, remoteAddress = '10.0.0.5') {
  const res = { writeHead: vi.fn(), end: vi.fn() };
  const req = {
    url,
    method: 'GET',
    headers: {},
    socket: { remoteAddress },
  };
  _requestHandler?.(req, res);
  return { req, res };
}

describe('oastManager', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    clearCallbacks();
    stopOast();
    // Reset server mock state
    mockServer.once.mockImplementation((event, cb) => { if (event === 'error') mockServer._errCb = cb; });
    mockServer.listen.mockImplementation((port, host, cb) => { _mockPort = port; _listenCallback = cb; });
    mockServer.close.mockReset();
  });

  afterEach(() => {
    stopOast();
    clearCallbacks();
  });

  // ─── Token management ────────────────────────────────────────────────────────

  it('allocates a 24-char hex token', () => {
    const token = allocateToken({ label: 'test' });
    expect(token).toMatch(/^[a-f0-9]{24}$/);
  });

  it('allocates unique tokens on each call', () => {
    const t1 = allocateToken();
    const t2 = allocateToken();
    expect(t1).not.toBe(t2);
  });

  it('correlate returns meta for a known token and marks it hit', () => {
    const token = allocateToken({ module: 'sqli', url: 'http://x.com' });
    const meta  = correlate(token);
    expect(meta).toEqual({ module: 'sqli', url: 'http://x.com' });
    // Second correlate should still return the meta (hit flag set)
    expect(correlate(token)).not.toBeNull();
  });

  it('correlate returns null for unknown token', () => {
    expect(correlate('deadbeef000000000000dead')).toBeNull();
  });

  it('getPendingTokens returns a copy of the Map', () => {
    const t = allocateToken({ x: 1 });
    const map = getPendingTokens();
    expect(map.has(t)).toBe(true);
    // Mutating the copy should not affect internal state
    map.delete(t);
    expect(getPendingTokens().has(t)).toBe(true);
  });

  it('clearCallbacks empties callbacks and pending tokens', () => {
    allocateToken({ x: 1 });
    clearCallbacks();
    expect(getPendingTokens().size).toBe(0);
    expect(getCallbacks()).toHaveLength(0);
  });

  // ─── Server lifecycle ────────────────────────────────────────────────────────

  it('startOast resolves with success and localUrl', async () => {
    const promise = startOast(7331);
    triggerListen();
    const result = await promise;
    expect(result.success).toBe(true);
    expect(result.localUrl).toContain('192.168.1.100');
    expect(result.port).toBe(7331);
    expect(isOastRunning()).toBe(true);
  });

  it('startOast rejects if already running', async () => {
    const p1 = startOast(7331);
    triggerListen();
    await p1;
    const p2 = await startOast(7332);
    expect(p2.success).toBe(false);
    expect(p2.error).toMatch(/already running/i);
  });

  it('stopOast sets isOastRunning to false', async () => {
    const p = startOast(7331);
    triggerListen();
    await p;
    stopOast();
    expect(isOastRunning()).toBe(false);
    expect(getOastLocalUrl()).toBeNull();
  });

  it('startOast handles server error', async () => {
    const promise = startOast(7331);
    mockServer._errCb?.(new Error('EADDRINUSE'));
    const result = await promise;
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/EADDRINUSE/);
  });

  // ─── HTTP callback routing ────────────────────────────────────────────────────

  it('valid OAST callback is recorded and correlates token', async () => {
    const callbackFn = vi.fn();
    const p = startOast(7331, callbackFn);
    triggerListen();
    await p;

    const token = allocateToken({ module: 'xxe', target: 'http://t.com' });
    const { res } = simulateRequest(`/oast/${token}`, '203.0.113.42');

    expect(res.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
    expect(callbackFn).toHaveBeenCalledTimes(1);
    const hit = callbackFn.mock.calls[0][0];
    expect(hit.token).toBe(token);
    expect(hit.remoteIp).toBe('203.0.113.42');
    expect(hit.meta).toEqual({ module: 'xxe', target: 'http://t.com' });
    expect(getCallbacks()).toHaveLength(1);
  });

  it('unknown token callback is still recorded but meta is null', async () => {
    const callbackFn = vi.fn();
    const p = startOast(7331, callbackFn);
    triggerListen();
    await p;

    simulateRequest('/oast/aaaaaaaabbbbbbbbcccccccc');
    const hit = callbackFn.mock.calls[0][0];
    expect(hit.meta).toBeNull();
  });

  it('health probe returns 200', async () => {
    const p = startOast(7331);
    triggerListen();
    await p;

    const { res } = simulateRequest('/health');
    expect(res.writeHead).toHaveBeenCalledWith(200);
    expect(res.end).toHaveBeenCalledWith('oast-ok');
  });

  it('unknown paths return 404', async () => {
    const p = startOast(7331);
    triggerListen();
    await p;

    const { res } = simulateRequest('/unknown/path');
    expect(res.writeHead).toHaveBeenCalledWith(404);
  });

  it('callbacks capped at 200 entries', async () => {
    const p = startOast(7331);
    triggerListen();
    await p;

    for (let i = 0; i < 250; i++) {
      const t = allocateToken();
      simulateRequest(`/oast/${t}`);
    }
    expect(getCallbacks().length).toBeLessThanOrEqual(200);
  });
});
