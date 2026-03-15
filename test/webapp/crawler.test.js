/**
 * test/webapp/crawler.test.js
 * Tests for the passive spider (crawler.js).
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  observeRequest, getSitemap, clearSitemap,
  exportSitemapJson, getSitemapStats, getAttackSurface,
} from '../../src/main/webapp/crawler.js';

// ─── Helper ───────────────────────────────────────────────────────────────────

function makeRecord(overrides = {}) {
  return {
    id:              'test-id',
    timestamp:       Date.now(),
    method:          'GET',
    url:             'http://example.com/',
    host:            'example.com',
    path:            '/',
    query:           '',
    statusCode:      200,
    mimeType:        'text/html',
    requestHeaders:  {},
    responseHeaders: { 'content-type': 'text/html; charset=utf-8' },
    requestBody:     null,
    responseBody:    null,
    durationMs:      120,
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('crawler.js — passive spider', () => {

  beforeEach(() => { clearSitemap(); });

  // ─ observeRequest ───────────────────────────────────────────────────────────

  describe('observeRequest', () => {

    it('adds the requested URL to the sitemap', () => {
      observeRequest(makeRecord({ url: 'http://example.com/login', method: 'GET' }));
      const map = getSitemap();
      expect(map['example.com']).toBeDefined();
      expect(map['example.com'].children['login']).toBeDefined();
    });

    it('records the HTTP method', () => {
      observeRequest(makeRecord({ url: 'http://example.com/api/users', method: 'POST' }));
      const map = getSitemap();
      const node = map['example.com'].children['api'].children['users'];
      expect(node.methods).toContain('POST');
    });

    it('returns newUrls for newly discovered URLs', () => {
      const { newUrls } = observeRequest(makeRecord({ url: 'http://example.com/dashboard' }));
      expect(newUrls).toContain('http://example.com/dashboard');
    });

    it('does not report duplicate URLs in newUrls', () => {
      observeRequest(makeRecord({ url: 'http://example.com/page' }));
      const { newUrls } = observeRequest(makeRecord({ url: 'http://example.com/page' }));
      expect(newUrls).toHaveLength(0);
    });

    it('extracts href links from HTML response body', () => {
      const html = Buffer.from('<a href="/about">About</a><a href="/contact">Contact</a>');
      const { newUrls } = observeRequest(makeRecord({
        url:          'http://example.com/',
        responseBody: html,
        responseHeaders: { 'content-type': 'text/html' },
      }));
      expect(newUrls).toContain('http://example.com/about');
      expect(newUrls).toContain('http://example.com/contact');
    });

    it('extracts src attributes from HTML', () => {
      const html = Buffer.from('<img src="/images/logo.png"><script src="/js/app.js"></script>');
      const { newUrls } = observeRequest(makeRecord({
        url:          'http://example.com/',
        responseBody: html,
        responseHeaders: { 'content-type': 'text/html' },
      }));
      expect(newUrls).toContain('http://example.com/images/logo.png');
      expect(newUrls).toContain('http://example.com/js/app.js');
    });

    it('extracts action attributes from form tags', () => {
      const html = Buffer.from('<form action="/login" method="POST"><input name="user" type="text"></form>');
      const { newUrls, newForms } = observeRequest(makeRecord({
        url:          'http://example.com/',
        responseBody: html,
        responseHeaders: { 'content-type': 'text/html' },
      }));
      expect(newUrls).toContain('http://example.com/login');
      expect(newForms.length).toBeGreaterThan(0);
      expect(newForms[0].method).toBe('POST');
    });

    it('captures form inputs', () => {
      const html = Buffer.from(`
        <form action="/submit" method="POST">
          <input name="username" type="text">
          <input name="password" type="password">
          <input type="submit" value="Login">
        </form>`);
      const { newForms } = observeRequest(makeRecord({
        url:          'http://example.com/',
        responseBody: html,
        responseHeaders: { 'content-type': 'text/html' },
      }));
      expect(newForms[0].inputs.map(i => i.name)).toContain('username');
      expect(newForms[0].inputs.map(i => i.name)).toContain('password');
      expect(newForms[0].inputs.find(i => i.name === 'password').type).toBe('password');
    });

    it('extracts API path patterns from JSON response', () => {
      const json = Buffer.from('{"links": ["/api/v1/users", "/api/v1/orders"]}');
      const { newUrls } = observeRequest(makeRecord({
        url:          'http://example.com/api',
        responseBody: json,
        responseHeaders: { 'content-type': 'application/json' },
      }));
      expect(newUrls.some(u => u.includes('/api/v1/users'))).toBe(true);
    });

    it('extracts URLs from Link: response headers', () => {
      const { newUrls } = observeRequest(makeRecord({
        url:             'http://example.com/',
        responseHeaders: {
          'content-type': 'text/html',
          'link':         '</api/docs>; rel="help", </next>; rel="next"',
        },
        responseBody: Buffer.from('<html></html>'),
      }));
      expect(newUrls.some(u => u.includes('/api/docs'))).toBe(true);
    });

    it('does not add cross-origin links with different host', () => {
      const html = Buffer.from('<a href="https://external.com/page">External</a>');
      observeRequest(makeRecord({
        url:          'http://example.com/',
        responseBody: html,
        responseHeaders: { 'content-type': 'text/html' },
      }));
      const map = getSitemap();
      // external.com might be added but example.com should not have it as child
      expect(map['example.com']?.children['external.com']).toBeUndefined();
    });

    it('ignores javascript: and data: hrefs', () => {
      const html = Buffer.from(`
        <a href="javascript:void(0)">JS Link</a>
        <a href="data:text/html,hello">Data Link</a>
        <a href="#anchor">Anchor</a>`);
      const { newUrls } = observeRequest(makeRecord({
        url:          'http://example.com/',
        responseBody: html,
        responseHeaders: { 'content-type': 'text/html' },
      }));
      // None of these should produce new URLs (root is already seen)
      expect(newUrls.filter(u => u.includes('javascript') || u.includes('data:'))).toHaveLength(0);
    });

    it('handles missing response body gracefully', () => {
      expect(() => {
        observeRequest(makeRecord({ responseBody: null }));
      }).not.toThrow();
    });

    it('handles malformed URLs gracefully', () => {
      expect(() => {
        observeRequest(makeRecord({ url: 'not-a-valid-url' }));
      }).not.toThrow();
    });

    it('handles extremely large response body by skipping parse', () => {
      const bigBody = Buffer.alloc(3_000_000, 'a'); // > CRAWLER_MAX_PARSE_BYTES
      expect(() => {
        observeRequest(makeRecord({
          responseBody:    bigBody,
          responseHeaders: { 'content-type': 'text/html' },
        }));
      }).not.toThrow();
    });

    it('builds nested path tree correctly', () => {
      observeRequest(makeRecord({ url: 'http://example.com/api/v1/users' }));
      const map = getSitemap();
      expect(map['example.com'].children['api'].children['v1'].children['users']).toBeDefined();
    });

    it('merges methods for the same URL on repeat visits', () => {
      observeRequest(makeRecord({ url: 'http://example.com/resource', method: 'GET' }));
      observeRequest(makeRecord({ url: 'http://example.com/resource', method: 'POST' }));
      const map = getSitemap();
      const node = map['example.com'].children['resource'];
      expect(node.methods).toContain('GET');
      expect(node.methods).toContain('POST');
    });

    it('parses query string parameters into node params', () => {
      observeRequest(makeRecord({ url: 'http://example.com/search?q=hello&page=1' }));
      const map = getSitemap();
      const node = map['example.com'].children['search'];
      expect(node.params.map(p => p.name)).toContain('q');
      expect(node.params.map(p => p.name)).toContain('page');
    });
  });

  // ─ getSitemap ───────────────────────────────────────────────────────────────

  describe('getSitemap', () => {
    it('returns empty object when no requests observed', () => {
      expect(getSitemap()).toEqual({});
    });

    it('returns deep copy safe for IPC serialization', () => {
      observeRequest(makeRecord({ url: 'http://example.com/' }));
      const a = getSitemap();
      const b = getSitemap();
      // Modifying one should not affect the other
      a['example.com'].children['injected'] = {};
      expect(b['example.com'].children['injected']).toBeUndefined();
    });
  });

  // ─ clearSitemap ─────────────────────────────────────────────────────────────

  describe('clearSitemap', () => {
    it('wipes all data', () => {
      observeRequest(makeRecord({ url: 'http://example.com/page' }));
      clearSitemap();
      expect(getSitemap()).toEqual({});
    });

    it('allows subsequent observation to rebuild tree', () => {
      observeRequest(makeRecord({ url: 'http://example.com/page' }));
      clearSitemap();
      observeRequest(makeRecord({ url: 'http://other.com/new' }));
      const map = getSitemap();
      expect(map['other.com']).toBeDefined();
      expect(map['example.com']).toBeUndefined();
    });
  });

  // ─ exportSitemapJson ────────────────────────────────────────────────────────

  describe('exportSitemapJson', () => {
    it('returns valid JSON string', () => {
      observeRequest(makeRecord({ url: 'http://example.com/login' }));
      const json = exportSitemapJson();
      expect(() => JSON.parse(json)).not.toThrow();
      const parsed = JSON.parse(json);
      expect(parsed['example.com']).toBeDefined();
    });

    it('returns "{}" when sitemap is empty', () => {
      expect(exportSitemapJson()).toBe('{}');
    });
  });

  // ─ getSitemapStats ──────────────────────────────────────────────────────────

  describe('getSitemapStats', () => {
    it('returns zero stats for empty sitemap', () => {
      const stats = getSitemapStats();
      expect(stats.hosts).toBe(0);
      expect(stats.urls).toBe(0);
    });

    it('counts hosts correctly', () => {
      observeRequest(makeRecord({ url: 'http://alpha.com/' }));
      observeRequest(makeRecord({ url: 'http://beta.com/' }));
      const stats = getSitemapStats();
      expect(stats.hosts).toBe(2);
    });

    it('counts URLs across all hosts', () => {
      observeRequest(makeRecord({ url: 'http://example.com/' }));
      observeRequest(makeRecord({ url: 'http://example.com/page1' }));
      observeRequest(makeRecord({ url: 'http://example.com/page2' }));
      const stats = getSitemapStats();
      expect(stats.urls).toBeGreaterThanOrEqual(3);
    });
  });

  // ─ getAttackSurface ─────────────────────────────────────────────────────────

  describe('getAttackSurface', () => {
    it('returns empty array when no attack surface identified', () => {
      observeRequest(makeRecord({ url: 'http://example.com/' }));
      expect(getAttackSurface()).toEqual([]);
    });

    it('includes nodes with forms in attack surface', () => {
      const html = Buffer.from('<form action="/login" method="POST"><input name="user"></form>');
      observeRequest(makeRecord({
        url:          'http://example.com/',
        responseBody: html,
        responseHeaders: { 'content-type': 'text/html' },
      }));
      const surface = getAttackSurface();
      expect(surface.some(s => s.url.includes('/login'))).toBe(true);
    });

    it('includes nodes with query params in attack surface', () => {
      observeRequest(makeRecord({ url: 'http://example.com/search?q=test' }));
      const surface = getAttackSurface();
      expect(surface.some(s => s.url.includes('/search'))).toBe(true);
    });
  });
});
