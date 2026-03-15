/**
 * crawler.js — Passive Spider (Feature 7B)
 *
 * Observes every request/response captured by the proxy and builds an
 * in-memory URL tree (sitemap).  Makes NO new HTTP requests itself —
 * all data comes from traffic already flowing through the MITM proxy.
 *
 * Tree shape:
 *   _sitemap[hostname] = {
 *     methods:  string[],
 *     forms:    FormEntry[],
 *     params:   ParamEntry[],
 *     children: { [segment]: <same shape> }
 *   }
 */

import { URL } from 'url';
import { CRAWLER_MAX_PARSE_BYTES } from '#shared/webConstants.js';

// ─── In-memory State ──────────────────────────────────────────────────────────

/** @type {Object.<string, SitemapNode>} hostname → root node */
let _sitemap = {};

/** Set of full URLs already processed to avoid redundant parsing */
let _seen = new Set();

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Process one proxy request record captured by proxyServer.
 * Extracts links, forms, and parameters from the response and adds them
 * to the in-memory sitemap.
 *
 * @param {Object} record - Full request record from proxyServer.js
 * @returns {{ newUrls: string[], newForms: Object[] }} Incremental additions
 */
export function observeRequest(record) {
  const newUrls  = [];
  const newForms = [];

  // Always register the requested URL itself
  const added = _addUrl(record.url, record.method, record.query, record.statusCode);
  if (added) newUrls.push(record.url);

  const contentType = _getHeader(record.responseHeaders, 'content-type') ?? '';
  const bodyBuf     = record.responseBody;

  if (!bodyBuf || bodyBuf.length === 0) return { newUrls, newForms };

  // Bail out if the body is enormous to protect main-thread performance
  if (bodyBuf.length > CRAWLER_MAX_PARSE_BYTES) return { newUrls, newForms };

  if (_isHtml(contentType)) {
    const html = bodyBuf.toString('utf-8');

    // Extract href / src / action links
    for (const href of _extractHtmlLinks(html, record.url)) {
      if (_addUrl(href, 'GET', null, null)) newUrls.push(href);
    }

    // Extract forms
    for (const form of _extractForms(html, record.url)) {
      _addForm(form.action || record.url, form);
      newForms.push(form);
    }
  }

  if (_isJson(contentType)) {
    const text = bodyBuf.toString('utf-8');
    for (const apiPath of _extractJsonApiPaths(text, record.url)) {
      if (_addUrl(apiPath, 'GET', null, null)) newUrls.push(apiPath);
    }
  }

  // Extract from Link: response header (RFC 5988)
  const linkHeader = _getHeader(record.responseHeaders, 'link');
  if (linkHeader) {
    for (const href of _extractLinkHeader(linkHeader, record.url)) {
      if (_addUrl(href, 'GET', null, null)) newUrls.push(href);
    }
  }

  return { newUrls, newForms };
}

/** Return the full sitemap tree (deep copy for safe IPC serialization). */
export function getSitemap() {
  return JSON.parse(JSON.stringify(_sitemap));
}

/**
 * Return a flat array of all nodes that have forms or query params
 * (i.e. potential attack surface entries).
 * @returns {{ url: string, methods: string[], paramCount: number, formCount: number }[]}
 */
export function getAttackSurface() {
  const results = [];
  for (const [host, root] of Object.entries(_sitemap)) {
    _walkForAttackSurface(root, `https://${host}`, results);
  }
  return results;
}

/** Wipe the entire sitemap. */
export function clearSitemap() {
  _sitemap = {};
  _seen.clear();
}

/** Return sitemap as a JSON string suitable for file export. */
export function exportSitemapJson() {
  return JSON.stringify(_sitemap, null, 2);
}

/** Summary counts for the status bar. */
export function getSitemapStats() {
  let hosts  = Object.keys(_sitemap).length;
  let urls   = 0;
  let forms  = 0;
  let params = 0;
  for (const root of Object.values(_sitemap)) {
    const s = _countStats(root);
    urls   += s.urls;
    forms  += s.forms;
    params += s.params;
  }
  return { hosts, urls, forms, params };
}

// ─── Tree Helpers ─────────────────────────────────────────────────────────────

/**
 * Add a URL to the sitemap tree.
 * @returns {boolean} true if this was a new URL
 */
function _addUrl(rawUrl, method, query, statusCode) {
  const parsed = _safeParseUrl(rawUrl);
  if (!parsed) return false;

  const key = parsed.origin + parsed.pathname;
  if (_seen.has(key)) {
    // Still update method list even for known URLs
    const node = _getNode(parsed.hostname, parsed.pathname);
    if (node && method && !node.methods.includes(method.toUpperCase())) {
      node.methods.push(method.toUpperCase());
    }
    return false;
  }
  _seen.add(key);

  const node = _getOrCreateNode(parsed.hostname, parsed.pathname);
  if (method && !node.methods.includes(method.toUpperCase())) {
    node.methods.push(method.toUpperCase());
  }
  if (statusCode) node.statusCode = statusCode;

  // Parse query string params
  if (query || parsed.search) {
    const qs = query || parsed.search.slice(1);
    for (const [name] of new URLSearchParams(qs)) {
      if (!node.params.find(p => p.name === name && p.source === 'query')) {
        node.params.push({ name, source: 'query' });
      }
    }
  }

  return true;
}

/** Add a form to the node for the given action URL. */
function _addForm(actionUrl, form) {
  const parsed = _safeParseUrl(actionUrl);
  if (!parsed) return;
  const node = _getOrCreateNode(parsed.hostname, parsed.pathname);
  // Avoid exact duplicate forms
  const sig = JSON.stringify({ method: form.method, inputs: form.inputs?.map(i => i.name).sort() });
  if (!node.forms.find(f => JSON.stringify({ method: f.method, inputs: f.inputs?.map(i => i.name).sort() }) === sig)) {
    node.forms.push(form);
  }
}

/** Return existing node or undefined (no creation). */
function _getNode(hostname, pathname) {
  const root = _sitemap[hostname];
  if (!root) return undefined;
  const segments = _pathSegments(pathname);
  let node = root;
  for (const seg of segments) {
    node = node.children[seg];
    if (!node) return undefined;
  }
  return node;
}

/** Get or create the tree node for a hostname + pathname. */
function _getOrCreateNode(hostname, pathname) {
  if (!_sitemap[hostname]) {
    _sitemap[hostname] = _newNode();
  }
  const segments = _pathSegments(pathname);
  let node = _sitemap[hostname];
  for (const seg of segments) {
    if (!node.children[seg]) {
      node.children[seg] = _newNode();
    }
    node = node.children[seg];
  }
  return node;
}

function _newNode() {
  return { methods: [], forms: [], params: [], children: {}, statusCode: null };
}

function _pathSegments(pathname) {
  return pathname.replace(/^\//, '').split('/').filter(Boolean);
}

// ─── HTML Extraction Helpers ──────────────────────────────────────────────────

/**
 * Extract all navigable URLs from an HTML string.
 * Uses regex; avoids jsdom/node-html-parser dependency.
 */
function _extractHtmlLinks(html, baseUrlStr) {
  const base = _safeParseUrl(baseUrlStr);
  if (!base) return [];

  const urls  = new Set();
  // Match href, src, action, data-src
  const re = /(?:href|src|action|data-src|data-href)\s*=\s*["']([^"'\s>]{1,2000})["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const resolved = _resolveUrl(m[1].trim(), base);
    if (resolved) urls.add(resolved);
  }
  return [...urls];
}

/**
 * Extract form definitions from HTML:
 * { action, method, inputs: [{ name, type, value }] }
 */
function _extractForms(html, baseUrlStr) {
  const base = _safeParseUrl(baseUrlStr);
  if (!base) return [];

  const forms = [];
  // Match <form ... > ... </form> blocks (greedy-safe with size limit)
  const formRe = /<form([^>]{0,500})>([\s\S]{0,20000}?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html)) !== null) {
    const attrs   = fm[1];
    const body    = fm[2];
    const action  = _attrVal(attrs, 'action') ?? baseUrlStr;
    const method  = (_attrVal(attrs, 'method') ?? 'GET').toUpperCase();
    const resolved = _resolveUrl(action, base);
    if (!resolved) continue;

    const inputs = [];
    const inputRe = /<input([^>]{0,300})>/gi;
    let im;
    while ((im = inputRe.exec(body)) !== null) {
      const name = _attrVal(im[1], 'name');
      if (!name) continue;
      inputs.push({
        name,
        type:  _attrVal(im[1], 'type') ?? 'text',
        value: _attrVal(im[1], 'value') ?? '',
      });
    }
    // Also capture <textarea name="..."> and <select name="...">
    const textAreaRe = /<textarea([^>]{0,200})>/gi;
    let tm;
    while ((tm = textAreaRe.exec(body)) !== null) {
      const name = _attrVal(tm[1], 'name');
      if (name) inputs.push({ name, type: 'textarea', value: '' });
    }

    forms.push({ action: resolved, method, inputs });
  }
  return forms;
}

/**
 * Scan a JSON response body for URL-like patterns
 * e.g. "/api/v1/users", "https://example.com/path".
 */
function _extractJsonApiPaths(text, baseUrlStr) {
  const base = _safeParseUrl(baseUrlStr);
  if (!base) return [];

  const paths = new Set();
  // Match quoted strings that look like paths
  const pathRe = /"(\/[a-z0-9\-_/]{1,200})"/gi;
  let m;
  while ((m = pathRe.exec(text)) !== null) {
    try {
      const resolved = new URL(m[1], base.origin).href;
      paths.add(resolved);
    } catch { /* skip */ }
  }
  return [...paths];
}

/**
 * Parse RFC-5988 Link: header value to extract hrefs.
 * Example: Link: </api/users>; rel="next", </api/docs>; rel="help"
 */
function _extractLinkHeader(header, baseUrlStr) {
  const base = _safeParseUrl(baseUrlStr);
  if (!base) return [];

  const urls = [];
  const re   = /<([^>]{1,500})>/g;
  let m;
  while ((m = re.exec(header)) !== null) {
    const resolved = _resolveUrl(m[1].trim(), base);
    if (resolved) urls.push(resolved);
  }
  return urls;
}

// ─── Stats / Walk Helpers ─────────────────────────────────────────────────────

function _countStats(node) {
  let urls   = 1;
  let forms  = node.forms.length;
  let params = node.params.length;
  for (const child of Object.values(node.children)) {
    const s = _countStats(child);
    urls   += s.urls;
    forms  += s.forms;
    params += s.params;
  }
  return { urls, forms, params };
}

function _walkForAttackSurface(node, prefix, results) {
  if (node.forms.length > 0 || node.params.length > 0) {
    results.push({
      url:        prefix,
      methods:    node.methods,
      paramCount: node.params.length,
      formCount:  node.forms.length,
    });
  }
  for (const [seg, child] of Object.entries(node.children)) {
    _walkForAttackSurface(child, `${prefix}/${seg}`, results);
  }
}

// ─── URL Utility Helpers ──────────────────────────────────────────────────────

function _safeParseUrl(raw) {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u;
  } catch {
    return null;
  }
}

function _resolveUrl(href, base) {
  if (!href) return null;
  if (href.startsWith('data:') || href.startsWith('javascript:') || href.startsWith('#')) return null;
  try {
    const u = new URL(href, base.href);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.href;
  } catch {
    return null;
  }
}

/** Extract a single attribute value from an attribute string. */
function _attrVal(attrStr, name) {
  const re = new RegExp(`${name}\\s*=\\s*["']([^"']{0,500})["']`, 'i');
  const m  = re.exec(attrStr);
  return m ? m[1] : null;
}

function _getHeader(headers, name) {
  if (!headers) return null;
  // headers may be an object or a parsed array
  if (Array.isArray(headers)) {
    const entry = headers.find(h => h[0]?.toLowerCase() === name);
    return entry ? entry[1] : null;
  }
  if (typeof headers === 'object') {
    return headers[name] ?? headers[name.toLowerCase()] ?? null;
  }
  return null;
}

function _isHtml(contentType) {
  return contentType.includes('text/html') || contentType.includes('application/xhtml');
}

function _isJson(contentType) {
  return contentType.includes('application/json') || contentType.includes('text/json');
}
