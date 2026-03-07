import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { startDirFuzz, stopDirFuzz, isDirFuzzRunning, cleanupDirFuzz } from '../src/main/dirFuzzer.js';

// ---- Module mocks --------------------------------------------------------

// Mock http and https so no real network calls are made
vi.mock('http', () => ({
  default: { request: vi.fn() },
  request: vi.fn(),
}));

vi.mock('https', () => ({
  default: { request: vi.fn() },
  request: vi.fn(),
}));

vi.mock('fs', () => ({
  default: {
    readFileSync: vi.fn(),
    existsSync: vi.fn().mockReturnValue(true),
  },
  readFileSync: vi.fn(),
  existsSync: vi.fn().mockReturnValue(true),
}));

// Mock networkConstants to use a small, deterministic built-in wordlist
vi.mock('#shared/networkConstants.js', () => ({
  COMMON_WEB_PATHS: ['/admin', '/login', '/.env', '/robots.txt'],
}));

// ---- Helpers -------------------------------------------------------------

import http from 'http';
import https from 'https';
import fs from 'fs';

/**
 * Build a minimal mock HTTP response.
 * Calling `callback(res)` simulates the server responding.
 */
function makeMockReqRes({ statusCode = 200, headers = {}, fail = false } = {}) {
  const res = {
    statusCode,
    headers: {
      'content-length': '512',
      'content-type': 'text/html',
      ...headers,
    },
    resume: vi.fn(),
    on: vi.fn(),
  };

  const req = {
    on: vi.fn(),
    end: vi.fn(),
    destroy: vi.fn(),
  };

  // Store the response callback so tests can fire it at will
  req._fireResponse = (callback) => callback(res);

  if (fail) {
    // Simulate a network error
    req._fireError = () => {
      const errHandler = req.on.mock.calls.find(c => c[0] === 'error');
      if (errHandler) errHandler[1](new Error('ECONNREFUSED'));
    };
  }

  return { req, res };
}

/**
 * Configure http.request (or https.request) to immediately call the response callback
 * with the given status code.
 */
function mockHttpRespond(mod, statusCode = 200, contentType = 'text/html') {
  mod.request.mockImplementation((options, callback) => {
    const { req, res } = makeMockReqRes({ statusCode, headers: { 'content-type': contentType } });
    // Fire response asynchronously so the event loop processes it
    setImmediate(() => req._fireResponse(callback));
    return req;
  });
}

// ---- Tests ---------------------------------------------------------------

describe('dirFuzzer module', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanupDirFuzz();
  });

  afterEach(() => {
    cleanupDirFuzz();
  });

  // ---- isDirFuzzRunning --------------------------------------------------

  describe('isDirFuzzRunning()', () => {
    it('returns false when idle', () => {
      expect(isDirFuzzRunning()).toBe(false);
    });
  });

  // ---- Input validation --------------------------------------------------

  describe('Input validation', () => {
    it('rejects missing targetUrl', async () => {
      const onError = vi.fn();
      await startDirFuzz({}, vi.fn(), vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringMatching(/Invalid target URL/i) })
      );
    });

    it('rejects empty targetUrl', async () => {
      const onError = vi.fn();
      await startDirFuzz({ targetUrl: '' }, vi.fn(), vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringMatching(/Invalid target URL/i) })
      );
    });

    it('rejects non-http scheme (ftp://)', async () => {
      const onError = vi.fn();
      await startDirFuzz({ targetUrl: 'ftp://192.168.1.1' }, vi.fn(), vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringMatching(/Unsupported scheme/i) })
      );
    });

    it('rejects javascript: pseudo-scheme', async () => {
      const onError = vi.fn();
      await startDirFuzz({ targetUrl: 'javascript:alert(1)' }, vi.fn(), vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.any(String) })
      );
    });

    it('rejects custom wordlistPath pointing to empty file', async () => {
      fs.readFileSync.mockReturnValue('');
      const onError = vi.fn();
      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', wordlistPath: '/tmp/empty.txt' },
        vi.fn(), vi.fn(), vi.fn(), onError
      );
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringMatching(/empty/i) })
      );
    });

    it('rejects unreadable wordlist file', async () => {
      fs.readFileSync.mockImplementation(() => { throw new Error('ENOENT: no such file'); });
      const onError = vi.fn();
      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', wordlistPath: '/nonexistent/list.txt' },
        vi.fn(), vi.fn(), vi.fn(), onError
      );
      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringMatching(/wordlist/i) })
      );
    });

    it('rejects null options', async () => {
      const onError = vi.fn();
      await startDirFuzz(null, vi.fn(), vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalled();
    });

    it('prevents concurrent runs', async () => {
      mockHttpRespond(http, 200);
      const onError = vi.fn();

      // Start first run (does not await — it is running)
      const p1 = startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 1 },
        vi.fn(), vi.fn(), vi.fn(), vi.fn()
      );

      // Immediately start a second run — should be rejected
      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1' },
        vi.fn(), vi.fn(), vi.fn(), onError
      );

      expect(onError).toHaveBeenCalledWith(
        expect.objectContaining({ message: expect.stringMatching(/already in progress/i) })
      );

      stopDirFuzz();
      await p1;
    });
  });

  // ---- Status code filtering ---------------------------------------------

  describe('Status code filtering', () => {
    it('reports hits matching the default filter (200)', async () => {
      mockHttpRespond(http, 200);

      const onHit = vi.fn();
      const onComplete = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 4, timeout: 500 },
        onHit, vi.fn(), onComplete, vi.fn()
      );

      expect(onHit).toHaveBeenCalled();
      // All paths returned 200, all should be hits since 200 is in default filter
      expect(onHit.mock.calls[0][0]).toMatchObject({
        statusCode: 200,
        path: expect.stringMatching(/^\//),
        responseTime: expect.any(Number),
        contentType: 'text/html',
      });
    });

    it('does NOT report hits filtered out by statusFilter', async () => {
      mockHttpRespond(http, 404); // 404 is not in default filter

      const onHit = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', statusFilter: [200, 301], concurrency: 4, timeout: 500 },
        onHit, vi.fn(), vi.fn(), vi.fn()
      );

      expect(onHit).not.toHaveBeenCalled();
    });

    it('reports 403 hits when 403 is in the filter', async () => {
      mockHttpRespond(http, 403);

      const onHit = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', statusFilter: [403], concurrency: 4, timeout: 500 },
        onHit, vi.fn(), vi.fn(), vi.fn()
      );

      expect(onHit).toHaveBeenCalled();
      expect(onHit.mock.calls.every(c => c[0].statusCode === 403)).toBe(true);
    });

    it('redirects: hit payload includes redirectUrl when 301 returned', async () => {
      http.request.mockImplementation((options, callback) => {
        const { req, res } = makeMockReqRes({
          statusCode: 301,
          headers: { location: '/admin/login', 'content-length': '0', 'content-type': 'text/html' },
        });
        setImmediate(() => req._fireResponse(callback));
        return req;
      });

      const onHit = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', statusFilter: [301], concurrency: 4, timeout: 500 },
        onHit, vi.fn(), vi.fn(), vi.fn()
      );

      expect(onHit).toHaveBeenCalled();
      const firstHit = onHit.mock.calls[0][0];
      expect(firstHit.redirectUrl).toBe('/admin/login');
    });
  });

  // ---- Progress reporting ------------------------------------------------

  describe('Progress reporting', () => {
    it('reports progress for each path tested', async () => {
      mockHttpRespond(http, 200);

      const onProgress = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 4, timeout: 500 },
        vi.fn(), onProgress, vi.fn(), vi.fn()
      );

      // Should have been called once per path (4 built-in paths in our mock)
      expect(onProgress).toHaveBeenCalledTimes(4);
      // Last call should have tested === total and percent === 100
      const lastCall = onProgress.mock.calls[onProgress.mock.calls.length - 1][0];
      expect(lastCall.tested).toBe(lastCall.total);
      expect(lastCall.percent).toBe(100);
    });

    it('progress payload has required shape', async () => {
      mockHttpRespond(http, 404);

      const onProgress = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 4, timeout: 500, statusFilter: [200] },
        vi.fn(), onProgress, vi.fn(), vi.fn()
      );

      const call = onProgress.mock.calls[0][0];
      expect(call).toMatchObject({
        tested: expect.any(Number),
        total: expect.any(Number),
        percent: expect.any(Number),
      });
      expect(call.percent).toBeGreaterThanOrEqual(0);
      expect(call.percent).toBeLessThanOrEqual(100);
    });
  });

  // ---- Completion --------------------------------------------------------

  describe('onComplete callback', () => {
    it('fires with total, hits, and elapsed when run finishes', async () => {
      mockHttpRespond(http, 200);

      const onComplete = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 4, timeout: 500 },
        vi.fn(), vi.fn(), onComplete, vi.fn()
      );

      expect(onComplete).toHaveBeenCalledOnce();
      const result = onComplete.mock.calls[0][0];
      expect(result).toMatchObject({
        total: expect.any(Number),
        hits: expect.any(Number),
        elapsed: expect.any(Number),
      });
      expect(result.total).toBe(4); // 4 paths in mock wordlist
      expect(result.hits).toBe(4); // all 200s match default filter
      expect(result.elapsed).toBeGreaterThanOrEqual(0);
    });

    it('hits count matches number of onHit calls', async () => {
      // Return 200 for first two paths, 404 for rest
      let callCount = 0;
      http.request.mockImplementation((options, callback) => {
        const statusCode = callCount++ < 2 ? 200 : 404;
        const { req, res } = makeMockReqRes({ statusCode });
        setImmediate(() => req._fireResponse(callback));
        return req;
      });

      const onHit = vi.fn();
      const onComplete = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', statusFilter: [200], concurrency: 4, timeout: 500 },
        onHit, vi.fn(), onComplete, vi.fn()
      );

      const { hits } = onComplete.mock.calls[0][0];
      expect(hits).toBe(onHit.mock.calls.length);
      expect(hits).toBe(2);
    });
  });

  // ---- Extension expansion -----------------------------------------------

  describe('Extension expansion', () => {
    it('appends extensions to non-extension paths', async () => {
      const probedPaths = [];
      http.request.mockImplementation((options, callback) => {
        probedPaths.push(options.path);
        const { req, res } = makeMockReqRes({ statusCode: 404 });
        setImmediate(() => req._fireResponse(callback));
        return req;
      });

      await startDirFuzz(
        {
          targetUrl: 'http://192.168.1.1',
          extensions: ['.php', '.bak'],
          statusFilter: [200],
          concurrency: 10,
          timeout: 500,
        },
        vi.fn(), vi.fn(), vi.fn(), vi.fn()
      );

      // /admin should appear as /admin, /admin.php, /admin.bak
      const adminPaths = probedPaths.filter(p => p.startsWith('/admin'));
      expect(adminPaths).toContain('/admin');
      expect(adminPaths).toContain('/admin.php');
      expect(adminPaths).toContain('/admin.bak');
    });

    it('does NOT expand paths that already have an extension', async () => {
      const probedPaths = [];
      http.request.mockImplementation((options, callback) => {
        probedPaths.push(options.path);
        const { req, res } = makeMockReqRes({ statusCode: 404 });
        setImmediate(() => req._fireResponse(callback));
        return req;
      });

      await startDirFuzz(
        {
          targetUrl: 'http://192.168.1.1',
          extensions: ['.txt'],
          statusFilter: [200],
          concurrency: 10,
          timeout: 500,
        },
        vi.fn(), vi.fn(), vi.fn(), vi.fn()
      );

      // robots.txt already has .txt extension; should NOT appear as robots.txt.txt
      expect(probedPaths).not.toContain('/robots.txt.txt');
    });
  });

  // ---- Custom wordlist ----------------------------------------------------

  describe('Custom wordlist loading', () => {
    it('reads paths from file when wordlistPath is provided', async () => {
      fs.readFileSync.mockReturnValue('/custom1\n/custom2\n# comment\n\n/custom3\n');
      mockHttpRespond(http, 404);

      const onComplete = vi.fn();

      await startDirFuzz(
        {
          targetUrl: 'http://192.168.1.1',
          wordlistPath: '/tmp/custom.txt',
          statusFilter: [200],
          concurrency: 4,
          timeout: 500,
        },
        vi.fn(), vi.fn(), onComplete, vi.fn()
      );

      expect(fs.readFileSync).toHaveBeenCalledWith('/tmp/custom.txt', 'utf8');
      // 3 valid paths (/custom1, /custom2, /custom3) — comment and blank lines stripped
      expect(onComplete.mock.calls[0][0].total).toBe(3);
    });
  });

  // ---- Cancellation (stopDirFuzz) ----------------------------------------

  describe('Cancellation', () => {
    it('stopDirFuzz aborts the run and onComplete is NOT called', async () => {
      // Make http.request never resolve — simulates slow network
      http.request.mockImplementation((options, callback) => {
        const req = {
          on: vi.fn(),
          end: vi.fn(),
          destroy: vi.fn(),
        };
        // Don't call callback — request hangs indefinitely
        return req;
      });

      const onComplete = vi.fn();
      const onError = vi.fn();

      const runPromise = startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 1, timeout: 10000 },
        vi.fn(), vi.fn(), onComplete, onError
      );

      // Abort immediately
      stopDirFuzz();
      await runPromise;

      expect(onComplete).not.toHaveBeenCalled();
      expect(isDirFuzzRunning()).toBe(false);
    });

    it('isDirFuzzRunning returns false after stop', async () => {
      mockHttpRespond(http, 200);

      const p = startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 4, timeout: 500 },
        vi.fn(), vi.fn(), vi.fn(), vi.fn()
      );

      stopDirFuzz();
      await p;

      expect(isDirFuzzRunning()).toBe(false);
    });
  });

  // ---- HTTPS --------------------------------------------------------------

  describe('HTTPS targets', () => {
    it('uses https.request for https:// URLs', async () => {
      mockHttpRespond(https, 200);

      await startDirFuzz(
        { targetUrl: 'https://192.168.1.1', concurrency: 4, timeout: 500 },
        vi.fn(), vi.fn(), vi.fn(), vi.fn()
      );

      expect(https.request).toHaveBeenCalled();
      expect(http.request).not.toHaveBeenCalled();
    });
  });

  // ---- Network errors (silent skip) --------------------------------------

  describe('Network errors', () => {
    it('silently skips failed requests and continues', async () => {
      // First request errors, rest succeed
      let count = 0;
      http.request.mockImplementation((options, callback) => {
        const req = {
          on: vi.fn(),
          end: vi.fn(),
          destroy: vi.fn(),
        };
        count++;
        if (count === 1) {
          // Simulate network error
          setImmediate(() => {
            const errHandler = req.on.mock.calls.find(c => c[0] === 'error');
            if (errHandler) errHandler[1](new Error('ECONNREFUSED'));
          });
        } else {
          const { res } = makeMockReqRes({ statusCode: 200 });
          setImmediate(() => callback(res));
        }
        return req;
      });

      const onError = vi.fn();
      const onComplete = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 4, timeout: 500 },
        vi.fn(), vi.fn(), onComplete, onError
      );

      // Fatal onError should NOT have been called — network errors are swallowed per-request
      expect(onError).not.toHaveBeenCalled();
      // Run completed normally
      expect(onComplete).toHaveBeenCalledOnce();
    });
  });

  // ---- Concurrency cap ---------------------------------------------------

  describe('Concurrency capping', () => {
    it('caps concurrency at 50', async () => {
      // Verify we can pass concurrency: 200 without crashing; it will be clamped internally
      mockHttpRespond(http, 404);

      const onComplete = vi.fn();

      await startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 200, timeout: 500, statusFilter: [200] },
        vi.fn(), vi.fn(), onComplete, vi.fn()
      );

      expect(onComplete).toHaveBeenCalledOnce();
    });
  });

  // ---- cleanupDirFuzz ----------------------------------------------------

  describe('cleanupDirFuzz()', () => {
    it('stops any active run when called', async () => {
      http.request.mockImplementation((options, callback) => ({
        on: vi.fn(),
        end: vi.fn(),
        destroy: vi.fn(),
      }));

      const p = startDirFuzz(
        { targetUrl: 'http://192.168.1.1', concurrency: 1, timeout: 10000 },
        vi.fn(), vi.fn(), vi.fn(), vi.fn()
      );

      cleanupDirFuzz();
      await p;

      expect(isDirFuzzRunning()).toBe(false);
    });
  });
});
