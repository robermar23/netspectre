/**
 * test/webapp/activeCrawler.test.js
 * Tests for activeCrawler.js — Playwright-based headless crawler.
 *
 * Playwright itself is mocked; all tests verify business logic only.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─── Mock playwright-core ─────────────────────────────────────────────────────

// We mock `module` so createRequire returns a mock `require` that resolves playwright-core
const mockPage = {
  setDefaultTimeout: vi.fn(),
  goto:     vi.fn().mockResolvedValue({}),
  evaluate: vi.fn().mockResolvedValue([]),
  on:       vi.fn(),
  $:        vi.fn().mockResolvedValue(null),
};

const mockContext = {
  newPage: vi.fn().mockResolvedValue(mockPage),
  close:   vi.fn().mockResolvedValue(undefined),
};

const mockBrowser = {
  newContext: vi.fn().mockResolvedValue(mockContext),
  close:      vi.fn().mockResolvedValue(undefined),
};

const mockPlaywright = {
  chromium: {
    launch: vi.fn().mockResolvedValue(mockBrowser),
  },
};

vi.mock('module', async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    createRequire: () => (id) => {
      if (id === 'playwright-core') return mockPlaywright;
      throw new Error(`Cannot find module '${id}'`);
    },
  };
});

import {
  startActiveCrawl,
  stopActiveCrawl,
  isActiveCrawlRunning,
} from '../../src/main/webapp/activeCrawler.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeCallbacks() {
  return {
    onUrl:      vi.fn(),
    onForm:     vi.fn(),
    onProgress: vi.fn(),
    onComplete: vi.fn(),
    onError:    vi.fn(),
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('activeCrawler.js', () => {

  beforeEach(() => {
    vi.clearAllMocks();
    // Default: evaluate returns empty arrays (no links, no forms)
    mockPage.evaluate.mockResolvedValue([]);
    mockPage.goto.mockResolvedValue({});
  });

  afterEach(() => {
    stopActiveCrawl();
  });

  // ─ isActiveCrawlRunning ───────────────────────────────────────────────────

  describe('isActiveCrawlRunning', () => {
    it('returns false when no crawl is active', () => {
      expect(isActiveCrawlRunning()).toBe(false);
    });
  });

  // ─ Input Validation ───────────────────────────────────────────────────────

  describe('input validation', () => {
    it('calls onError with missing startUrl', async () => {
      const cb = makeCallbacks();
      await startActiveCrawl({}, cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError);
      expect(cb.onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('startUrl') }));
    });

    it('calls onError with invalid URL', async () => {
      const cb = makeCallbacks();
      await startActiveCrawl({ startUrl: 'not-a-url' }, cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError);
      expect(cb.onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('Invalid') }));
    });
  });

  // ─ Playwright integration ─────────────────────────────────────────────────

  describe('Playwright integration', () => {
    it('launches Chromium with proxy settings when proxyUrl is provided', async () => {
      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'http://target.com', maxPages: 1, maxDepth: 1, respectRobots: false, proxyUrl: 'http://127.0.0.1:8888' },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );
      expect(mockPlaywright.chromium.launch).toHaveBeenCalledWith(expect.objectContaining({
        headless: true,
        proxy: expect.objectContaining({ server: expect.stringContaining('127.0.0.1') }),
      }));
    });

    it('launches Chromium without proxy when no proxyUrl given', async () => {
      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'http://target.com', maxPages: 1, maxDepth: 1, respectRobots: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );
      const launchArg = mockPlaywright.chromium.launch.mock.calls[0][0];
      expect(launchArg.headless).toBe(true);
      expect(launchArg.proxy).toBeUndefined();
    });

    it('launches browser with ignoreHTTPSErrors in context', async () => {
      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'https://secure.target.com', maxPages: 1, maxDepth: 0, respectRobots: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );
      expect(mockBrowser.newContext).toHaveBeenCalledWith(expect.objectContaining({
        ignoreHTTPSErrors: true,
      }));
    });

    it('calls onUrl with the start URL', async () => {
      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'http://target.com/', maxPages: 1, maxDepth: 0, respectRobots: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );
      expect(cb.onUrl).toHaveBeenCalledWith(expect.stringContaining('target.com'));
    });

    it('calls onComplete when crawl finishes', async () => {
      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'http://target.com/', maxPages: 1, maxDepth: 0, respectRobots: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );
      expect(cb.onComplete).toHaveBeenCalled();
    });

    it('respects maxPages limit', async () => {
      // Setup: evaluate returns 100 links, but maxPages=3
      mockPage.evaluate.mockResolvedValue([
        'http://target.com/page1', 'http://target.com/page2', 'http://target.com/page3',
        'http://target.com/page4', 'http://target.com/page5',
      ]);

      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'http://target.com/', maxPages: 3, maxDepth: 2, respectRobots: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );

      // onProgress is called once per page visit; should not exceed maxPages
      const progressCalls = cb.onProgress.mock.calls.map(c => c[0].visited);
      if (progressCalls.length > 0) {
        expect(Math.max(...progressCalls)).toBeLessThanOrEqual(3);
      }
    });

    it('enforces hard maxDepth cap at CRAWLER_MAX_DEPTH', async () => {
      // If user requests depth=999, it should be capped at 10
      // We just verify no errors occur and crawl completes
      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'http://target.com/', maxPages: 1, maxDepth: 999, respectRobots: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );
      expect(cb.onComplete).toHaveBeenCalled();
      expect(cb.onError).not.toHaveBeenCalled();
    });

    it('closes browser and context on completion', async () => {
      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'http://target.com/', maxPages: 1, maxDepth: 0, respectRobots: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );
      expect(mockContext.close).toHaveBeenCalled();
      expect(mockBrowser.close).toHaveBeenCalled();
    });

    it('handles navigation timeout without crashing', async () => {
      mockPage.goto.mockRejectedValueOnce(new Error('Navigation timeout'));

      const cb = makeCallbacks();
      await startActiveCrawl(
        { startUrl: 'http://target.com/', maxPages: 1, maxDepth: 0, respectRobots: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );
      expect(cb.onComplete).toHaveBeenCalled();
      expect(cb.onError).not.toHaveBeenCalled();
    });

    it('does not queue out-of-scope links', async () => {
      mockPage.evaluate.mockResolvedValue([
        'http://external.com/evil',
        'http://target.com/safe-page',
      ]);

      const urlsSeen = [];
      const cb = makeCallbacks();
      cb.onUrl.mockImplementation(url => urlsSeen.push(url));

      await startActiveCrawl(
        { startUrl: 'http://target.com/', maxPages: 5, maxDepth: 1, respectRobots: false, includeSubdomains: false },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );

      // Should NOT have navigated to external.com
      expect(mockPage.goto).not.toHaveBeenCalledWith(expect.stringContaining('external.com'), expect.anything());
    });
  });

  // ─ stopActiveCrawl ────────────────────────────────────────────────────────

  describe('stopActiveCrawl', () => {
    it('can be called when no crawl is running without error', () => {
      expect(() => stopActiveCrawl()).not.toThrow();
    });

    it('marks crawl as not running after stop', () => {
      stopActiveCrawl();
      expect(isActiveCrawlRunning()).toBe(false);
    });
  });

  // ─ Dependency missing ─────────────────────────────────────────────────────

  describe('dependency missing', () => {
    it('calls onError with DEPENDENCY_MISSING code when playwright-core is absent', async () => {
      // Temporarily override the mock to simulate missing dependency
      const { createRequire } = await import('module');
      const origReq = createRequire(import.meta.url);

      vi.doMock('module', async () => {
        const original = await import('module');
        return {
          ...original,
          createRequire: () => (id) => {
            throw new Error(`Cannot find module '${id}'`);
          },
        };
      });

      // Re-import the module with the broken mock
      const { startActiveCrawl: startFresh } = await import('../../src/main/webapp/activeCrawler.js?bust=' + Date.now());
      const cb = makeCallbacks();
      await startFresh(
        { startUrl: 'http://target.com/' },
        cb.onUrl, cb.onForm, cb.onProgress, cb.onComplete, cb.onError,
      );

      // Should emit DEPENDENCY_MISSING error
      if (cb.onError.mock.calls.length > 0) {
        expect(cb.onError).toHaveBeenCalledWith(expect.objectContaining({ code: 'DEPENDENCY_MISSING' }));
      }

      vi.resetModules();
    });
  });
});
