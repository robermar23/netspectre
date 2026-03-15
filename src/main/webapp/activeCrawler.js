/**
 * activeCrawler.js — Active Headless Crawler (Feature 7B)
 *
 * Launches a Playwright browser (soft dependency — graceful fallback if not
 * installed), routes all traffic through the MITM proxy, and performs a
 * breadth-first crawl of the target URL.
 *
 * Because all traffic is routed through the proxy, the passive spider
 * (crawler.js) receives every discovered URL for free.
 *
 * Playwright is a SOFT dependency:
 *   - If playwright-core is not installed, emits CRAWLER_DEPENDENCY_MISSING.
 *   - The caller should prompt the user to install it.
 *
 * Key design constraints (matching CLAUDE.md / Feature 7 spec):
 *   - No shell strings — Playwright is invoked via its JS API.
 *   - Max depth hard-capped at CRAWLER_MAX_DEPTH.
 *   - Max pages hard-capped at CRAWLER_MAX_PAGES.
 *   - Respects robots.txt (parsed once per origin; skipped on parse error).
 *   - Cancelled via AbortController signal.
 */

import http  from 'http';
import https from 'https';
import { existsSync } from 'fs';
import { join } from 'path';
import { URL } from 'url';
import {
  CRAWLER_MAX_DEPTH,
  CRAWLER_MAX_PAGES,
  CRAWLER_DEFAULT_DEPTH,
  CRAWLER_DEFAULT_PAGES,
  CRAWLER_DEFAULT_TIMEOUT_MS,
  ROBOTS_MAX_BYTES,
} from '#shared/webConstants.js';

// ─── Module State ─────────────────────────────────────────────────────────────

/** @type {import('playwright-core').Browser | null} */
let _browser = null;

/** @type {AbortController | null} */
let _abortCtrl = null;

let _running = false;

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Check if playwright-core is available without importing it (avoids crash).
 *
 * @param {string[]} [extraSearchPaths=[]] - Additional directories to search
 *   (e.g. app.getPath('userData') in packaged builds where the user installs
 *   playwright-core outside the ASAR archive).
 * @returns {Promise<boolean>}
 */
export async function isPlaywrightAvailable(extraSearchPaths = []) {
  // Standard module resolution — works in dev and when installed in app root.
  try {
    const { createRequire } = await import('module');
    const req = createRequire(import.meta.url);
    req.resolve('playwright-core');
    return true;
  } catch {}

  // Fallback: check explicit directories (packaged app with userData install).
  for (const searchPath of extraSearchPaths) {
    if (existsSync(join(searchPath, 'node_modules', 'playwright-core', 'package.json'))) {
      return true;
    }
  }

  return false;
}

/**
 * Start an active headless crawl.
 *
 * @param {Object}   opts
 * @param {string}   opts.startUrl
 * @param {number}   [opts.maxDepth=3]
 * @param {number}   [opts.maxPages=200]
 * @param {string}   [opts.proxyUrl='http://127.0.0.1:8888']
 * @param {boolean}  [opts.includeSubdomains=false]
 * @param {boolean}  [opts.submitForms=true]
 * @param {boolean}  [opts.clickButtons=true]
 * @param {boolean}  [opts.waitForNetworkIdle=true]
 * @param {number}   [opts.timeoutMs=30000]
 * @param {boolean}  [opts.respectRobots=true]
 * @param {Function} onUrl      - Called with (url: string) for each new URL found
 * @param {Function} onForm     - Called with (form: Object) for each form found
 * @param {Function} onProgress - Called with ({ visited, queued, total }) progress updates
 * @param {Function} onComplete - Called when crawl finishes
 * @param {Function} onError    - Called with (Error) on fatal errors
 * @returns {Promise<void>}
 */
export async function startActiveCrawl(opts, onUrl, onForm, onProgress, onComplete, onError) {
  if (_running) {
    onError(new Error('A crawl is already running.'));
    return;
  }

  // Validate inputs before doing anything expensive
  if (!opts.startUrl) {
    onError(new Error('startUrl is required.'));
    return;
  }

  let startUrl;
  try {
    startUrl = new URL(opts.startUrl);
  } catch {
    onError(new Error(`Invalid startUrl: "${opts.startUrl}" is not a valid URL.`));
    return;
  }

  // Resolve playwright-core dynamically (soft dep).
  // Try standard resolution first; then check any extra paths supplied by the
  // caller (used in packaged builds where the user installs into userData).
  let playwright;
  const extraModulePaths = Array.isArray(opts.extraModulePaths) ? opts.extraModulePaths : [];
  try {
    const { createRequire } = await import('module');
    const req = createRequire(import.meta.url);
    playwright = req('playwright-core');
  } catch {
    let found = false;
    for (const searchPath of extraModulePaths) {
      const pwPath = join(searchPath, 'node_modules', 'playwright-core');
      if (existsSync(join(pwPath, 'package.json'))) {
        try {
          const { createRequire } = await import('module');
          playwright = createRequire(import.meta.url)(pwPath);
          found = true;
          break;
        } catch {}
      }
    }
    if (!found) {
      onError(Object.assign(new Error('playwright-core not installed'), { code: 'DEPENDENCY_MISSING' }));
      return;
    }
  }

  _abortCtrl = new AbortController();
  const signal = _abortCtrl.signal;
  _running    = true;

  const maxDepth  = Math.min(opts.maxDepth  ?? CRAWLER_DEFAULT_DEPTH,    CRAWLER_MAX_DEPTH);
  const maxPages  = Math.min(opts.maxPages  ?? CRAWLER_DEFAULT_PAGES,    CRAWLER_MAX_PAGES);
  // null means no proxy — browser connects directly. A falsy opts.proxyUrl
  // (including null explicitly passed by the IPC handler when proxy isn't
  // running) must not fall back to a dead address.
  const proxyUrl  = opts.proxyUrl || null;
  const timeoutMs = opts.timeoutMs ?? CRAWLER_DEFAULT_TIMEOUT_MS;

  // robots.txt cache: origin → Set<disallowed path prefixes>
  const robotsCache = new Map();

  try {
    _browser = await playwright.chromium.launch({
      headless: true,
      ...(proxyUrl ? { proxy: { server: proxyUrl } } : {}),
    });

    const context = await _browser.newContext({
      ignoreHTTPSErrors: true, // proxy handles TLS; don't let Chromium refuse our MITM cert
      userAgent: 'NetSpecter-Crawler/1.0 (Security Scanner; authorized testing only)',
    });

    const page = await context.newPage();
    page.setDefaultTimeout(timeoutMs);

    // BFS queue: { url: string, depth: number }
    const queue   = [{ url: startUrl.href, depth: 0 }];
    const visited = new Set();
    let   visitedCount = 0;

    // Helper: check robots.txt
    async function isAllowed(urlStr) {
      if (!opts.respectRobots) return true;
      try {
        const u      = new URL(urlStr);
        const origin = u.origin;
        if (!robotsCache.has(origin)) {
          const disallowed = await _fetchRobots(origin, proxyUrl);
          robotsCache.set(origin, disallowed);
        }
        const disallowed = robotsCache.get(origin);
        const path = u.pathname;
        return ![...disallowed].some(prefix => path.startsWith(prefix));
      } catch {
        return true; // on error, allow
      }
    }

    // Intercept all requests to collect URLs (proxy already captures them;
    // this is a belt-and-suspenders approach for dynamically-fetched URLs)
    page.on('request', (req) => {
      const url = req.url();
      if (_isInScope(url, startUrl, opts.includeSubdomains) && !visited.has(url)) {
        onUrl(url);
      }
    });

    while (queue.length > 0 && visitedCount < maxPages && !signal.aborted) {
      const { url, depth } = queue.shift();

      if (visited.has(url)) continue;
      visited.add(url);

      if (!_isInScope(url, startUrl, opts.includeSubdomains)) continue;
      if (!(await isAllowed(url))) continue;

      visitedCount++;
      onProgress({ visited: visitedCount, queued: queue.length, total: maxPages });
      onUrl(url);

      try {
        await page.goto(url, {
          waitUntil: opts.waitForNetworkIdle ? 'networkidle' : 'domcontentloaded',
          timeout:   timeoutMs,
        });
      } catch (navErr) {
        // Non-fatal: navigation timeout, net error, etc. Continue with next URL.
        continue;
      }

      if (signal.aborted) break;

      if (depth < maxDepth) {
        // Extract all links from the current page DOM
        const links = await page.evaluate(() => {
          const urls = new Set();
          document.querySelectorAll('a[href], area[href]').forEach(el => {
            try { urls.add(new URL(el.href, location.href).href); } catch {}
          });
          document.querySelectorAll('[src]').forEach(el => {
            try { urls.add(new URL(el.src, location.href).href); } catch {}
          });
          return [...urls];
        }).catch(() => []);

        for (const link of links) {
          const normalized = _normalizeUrl(link);
          if (normalized && !visited.has(normalized) && _isInScope(normalized, startUrl, opts.includeSubdomains)) {
            queue.push({ url: normalized, depth: depth + 1 });
          }
        }

        // Discover forms
        const forms = await page.evaluate(() => {
          return [...document.querySelectorAll('form')].map(form => ({
            action: form.action || location.href,
            method: (form.method || 'GET').toUpperCase(),
            inputs: [...form.querySelectorAll('input, textarea, select')].map(el => ({
              name:  el.name,
              type:  el.type || el.tagName.toLowerCase(),
              value: el.value || '',
            })).filter(i => i.name),
          }));
        }).catch(() => []);

        for (const form of forms) {
          onForm(form);
          onUrl(form.action);

          // Optionally submit forms
          if (opts.submitForms && form.inputs.length > 0) {
            try {
              await _submitForm(page, form, timeoutMs);
            } catch { /* non-fatal */ }
          }
        }
      }
    }

    await context.close();
    await _browser.close();
    _browser = null;

  } catch (err) {
    if (!signal.aborted) onError(err);
  } finally {
    _running    = false;
    _abortCtrl  = null;
    onComplete();
  }
}

/** Stop the active crawl. Idempotent. */
export function stopActiveCrawl() {
  _abortCtrl?.abort();
  _browser?.close().catch(() => {});
  _browser  = null;
  _running  = false;
}

/** Whether a crawl is currently running. */
export function isActiveCrawlRunning() {
  return _running;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Return true if `url` is within the crawl scope relative to `origin`.
 */
function _isInScope(url, originUrl, includeSubdomains) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    if (includeSubdomains) {
      return u.hostname === originUrl.hostname || u.hostname.endsWith(`.${originUrl.hostname}`);
    }
    return u.hostname === originUrl.hostname;
  } catch {
    return false;
  }
}

/** Normalize a URL for deduplication (sort query params, strip fragment). */
function _normalizeUrl(raw) {
  try {
    const u = new URL(raw);
    u.hash = '';
    const params = [...u.searchParams.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    u.search = '';
    params.forEach(([k, v]) => u.searchParams.append(k, v));
    return u.href;
  } catch {
    return null;
  }
}

/**
 * Fetch and parse robots.txt for `origin`.
 * Returns a Set of disallowed path prefixes for all user-agents.
 */
async function _fetchRobots(origin, proxyUrl) {
  const disallowed = new Set();
  try {
    const robotsUrl = `${origin}/robots.txt`;
    const body = await _httpGet(robotsUrl, ROBOTS_MAX_BYTES);
    let applicable = false;
    for (const line of body.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (/^user-agent:\s*\*/i.test(trimmed)) { applicable = true; continue; }
      if (/^user-agent:/i.test(trimmed)) { applicable = false; continue; }
      if (applicable && /^disallow:\s*/i.test(trimmed)) {
        const path = trimmed.replace(/^disallow:\s*/i, '').trim();
        if (path) disallowed.add(path);
      }
    }
  } catch { /* robots.txt unavailable — allow everything */ }
  return disallowed;
}

/**
 * Simple HTTP GET that reads up to `maxBytes` of the response body.
 * Uses Node built-ins only — no external deps.
 */
function _httpGet(url, maxBytes) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod    = parsed.protocol === 'https:' ? https : http;
    const req    = mod.get(url, { timeout: 5000 }, (res) => {
      const chunks = [];
      let total    = 0;
      res.on('data', (chunk) => {
        total += chunk.length;
        if (total > maxBytes) { req.destroy(); return; }
        chunks.push(chunk);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

/**
 * Attempt to submit a form by filling visible text inputs with "test"
 * and clicking the submit button.
 */
async function _submitForm(page, form, timeoutMs) {
  await page.evaluate((formData) => {
    const formEl = [...document.querySelectorAll('form')].find(f =>
      (f.action || location.href) === formData.action && (f.method || 'GET').toUpperCase() === formData.method
    );
    if (!formEl) return;
    formEl.querySelectorAll('input[type="text"], input[type="search"], input:not([type])').forEach(el => {
      if (!el.value) el.value = 'test';
    });
    formEl.querySelectorAll('select').forEach(el => {
      if (el.options.length > 0) el.selectedIndex = 0;
    });
  }, form);

  try {
    const submitBtn = await page.$(`form[action="${form.action}"] [type="submit"], form [type="submit"]`);
    if (submitBtn) {
      await Promise.race([
        submitBtn.click(),
        page.waitForNavigation({ timeout: timeoutMs }).catch(() => {}),
      ]);
    }
  } catch { /* ignore submit errors */ }
}
