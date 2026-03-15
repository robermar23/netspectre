/**
 * test/webapp/proxyServer.test.js
 * Tests for the MITM proxy server.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import http from 'http';
import net from 'net';
import fs from 'fs';

// ── Mock node-forge ────────────────────────────────────────────────────────────

vi.mock('node-forge', () => {
  const cert = {
    publicKey: null,
    serialNumber: '',
    validity: { notBefore: new Date(), notAfter: new Date() },
    setSubject:     () => {},
    setIssuer:      () => {},
    setExtensions:  () => {},
    sign:           () => {},
    subject:        { attributes: [] },
  };
  const keyPair = { publicKey: {}, privateKey: {} };
  return {
    default: {
      pki: {
        rsa: { generateKeyPair: () => keyPair },
        createCertificate: () => ({ ...cert }),
        certificateToPem:  () => '---CERT---',
        privateKeyToPem:   () => '---KEY---',
        certificateFromPem: () => ({ ...cert }),
        privateKeyFromPem:  () => keyPair.privateKey,
      },
      md: { sha256: { create: () => ({}) } },
    },
  };
});

// ── Mock electron ──────────────────────────────────────────────────────────────

vi.mock('electron', () => ({
  app: { getPath: vi.fn(() => '/tmp/test-proxy-ca') },
  shell: { showItemInFolder: vi.fn() },
}));

// ── Mock fs ───────────────────────────────────────────────────────────────────

vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal();
  const mockFs = {
    ...actual,
    existsSync:    vi.fn(() => false),
    mkdirSync:     vi.fn(),
    writeFileSync: vi.fn(),
    readFileSync:  vi.fn(() => '---CERT---'),
  };
  return { ...mockFs, default: mockFs };
});

// ── Mock #shared/webConstants.js ───────────────────────────────────────────────

vi.mock('#shared/webConstants.js', () => ({
  PROXY_CA_DIR:         'proxy-ca',
  PROXY_CERT_CACHE_SIZE: 200,
}));

// ── Import module under test ───────────────────────────────────────────────────

import {
  startProxy, stopProxy, setInterceptMode,
  forwardInterceptedRequest, dropInterceptedRequest,
  isProxyRunning, getProxyPort,
} from '../../src/main/webapp/proxyServer.js';

// ─── Tests ─────────────────────────────────────────────────────────────────────

describe('proxyServer', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // Default: CA does not exist yet (first launch)
    fs.existsSync.mockReturnValue(false);
  });

  afterEach(async () => {
    stopProxy();
    await new Promise(r => setTimeout(r, 50));
  });

  // ── isProxyRunning initial state ──────────────────────────────────────────────

  describe('initial state', () => {
    it('reports not running before start', () => {
      expect(isProxyRunning()).toBe(false);
    });
  });

  // ── startProxy ────────────────────────────────────────────────────────────────

  describe('startProxy', () => {
    it('starts and reports running on available port', async () => {
      // Find a free port first
      const port = await _getFreePort();
      const result = await startProxy({ port, intercept: false });
      expect(result.success).toBe(true);
      expect(isProxyRunning()).toBe(true);
      expect(getProxyPort()).toBe(port);
    });

    it('returns error if port is already in use', async () => {
      const port = await _getFreePort();
      // Occupy the port with another server
      const blocker = http.createServer();
      await new Promise(r => blocker.listen(port, '127.0.0.1', r));

      try {
        const result = await startProxy({ port, intercept: false });
        expect(result.success).toBe(false);
        expect(result.error).toBeDefined();
      } finally {
        await new Promise(r => blocker.close(r));
      }
    });

    it('returns error if called when already running', async () => {
      const port = await _getFreePort();
      await startProxy({ port, intercept: false });
      const second = await startProxy({ port: port + 1, intercept: false });
      expect(second.success).toBe(false);
      expect(second.error).toContain('already running');
    });

    it('generates CA cert files on first launch', async () => {
      fs.existsSync.mockReturnValue(false);
      const port = await _getFreePort();
      await startProxy({ port, intercept: false });
      expect(fs.writeFileSync).toHaveBeenCalledTimes(2); // cert + key
    });

    it('loads existing CA cert without regenerating on second launch', async () => {
      fs.existsSync.mockReturnValue(true);  // CA already exists
      const port = await _getFreePort();
      await startProxy({ port, intercept: false });
      // writeFileSync should NOT be called (cert already exists)
      expect(fs.writeFileSync).not.toHaveBeenCalled();
    });
  });

  // ── stopProxy ─────────────────────────────────────────────────────────────────

  describe('stopProxy', () => {
    it('stops a running proxy', async () => {
      const port = await _getFreePort();
      await startProxy({ port, intercept: false });
      expect(isProxyRunning()).toBe(true);
      stopProxy();
      await new Promise(r => setTimeout(r, 50));
      expect(isProxyRunning()).toBe(false);
    });

    it('is safe to call when not running', () => {
      expect(() => stopProxy()).not.toThrow();
    });
  });

  // ── setInterceptMode ──────────────────────────────────────────────────────────

  describe('setInterceptMode', () => {
    it('can be toggled without error', async () => {
      const port = await _getFreePort();
      await startProxy({ port, intercept: false });
      expect(() => setInterceptMode(true)).not.toThrow();
      expect(() => setInterceptMode(false)).not.toThrow();
    });
  });

  // ── forwardInterceptedRequest ─────────────────────────────────────────────────

  describe('forwardInterceptedRequest', () => {
    it('is safe to call with unknown id', () => {
      expect(() => forwardInterceptedRequest('nonexistent-id', null)).not.toThrow();
    });
  });

  // ── dropInterceptedRequest ────────────────────────────────────────────────────

  describe('dropInterceptedRequest', () => {
    it('is safe to call with unknown id', () => {
      expect(() => dropInterceptedRequest('nonexistent-id')).not.toThrow();
    });
  });

  // ── URL scheme validation (via HTTP proxy request) ────────────────────────────

  describe('HTTP request handling', () => {
    it('rejects file:// scheme requests', async () => {
      const port = await _getFreePort();
      await startProxy({ port, intercept: false, onRequest: vi.fn() });

      const response = await new Promise((resolve, reject) => {
        const req = http.request(
          { host: '127.0.0.1', port, path: 'file:///etc/passwd', method: 'GET' },
          (res) => resolve(res)
        );
        req.on('error', reject);
        req.end();
      });

      expect(response.statusCode).toBe(400);
    });

    it('accepts a plain HTTP GET request and calls onRequest callback', async () => {
      const onRequest = vi.fn();
      const port = await _getFreePort();
      await startProxy({ port, intercept: false, onRequest });

      // Use a local test server as the upstream
      const upstreamPort = await _getFreePort();
      const upstream = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('hello proxy');
      });
      await new Promise(r => upstream.listen(upstreamPort, '127.0.0.1', r));

      try {
        await new Promise((resolve, reject) => {
          const proxyReq = http.request({
            host:    '127.0.0.1',
            port,
            path:    `http://127.0.0.1:${upstreamPort}/test`,
            method:  'GET',
            headers: { Host: `127.0.0.1:${upstreamPort}` },
          }, (res) => {
            res.resume();
            res.on('end', resolve);
          });
          proxyReq.on('error', reject);
          proxyReq.end();
        });

        expect(onRequest).toHaveBeenCalledOnce();
        const record = onRequest.mock.calls[0][0];
        expect(record.method).toBe('GET');
        expect(record.host).toBe('127.0.0.1');
        expect(record.statusCode).toBe(200);
      } finally {
        await new Promise(r => upstream.close(r));
      }
    });
  });

  // ── CONNECT tunnel security ────────────────────────────────────────────────────

  describe('CONNECT tunnel', () => {
    it('responds 200 Connection Established to CONNECT', async () => {
      const port = await _getFreePort();
      await startProxy({ port, intercept: false, onRequest: vi.fn() });

      const response = await new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1', () => {
          socket.write('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n');
        });
        let buf = '';
        socket.on('data', (chunk) => {
          buf += chunk.toString();
          if (buf.includes('\r\n\r\n')) {
            socket.destroy();
            resolve(buf);
          }
        });
        socket.on('error', reject);
        setTimeout(() => { socket.destroy(); resolve(buf); }, 1000);
      });

      expect(response).toContain('200 Connection Established');
    });
  });
});

// ─── Helper ─────────────────────────────────────────────────────────────────────

function _getFreePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}
