/**
 * repeaterEngine.js — HTTP Request Relay for the Repeater Tool (Feature 7D)
 *
 * Receives a raw HTTP request string (as typed in the Repeater editor), parses it,
 * fires the request via Node's http/https (bypassing browser CORS), and returns
 * the full response including headers, body, timing, and a reconstructed raw dump.
 *
 * Exports:
 *   sendRepeaterRequest(opts, signal) → Promise<{ statusCode, headers, body, durationMs, rawRequest, rawResponse }>
 */

import http  from 'http';
import https from 'https';

const ALLOWED_SCHEMES = ['http:', 'https:'];
const MAX_RESPONSE_BYTES = 5_000_000; // 5 MB cap

/**
 * Parse a raw HTTP request string into structured parts.
 * Raw format:
 *   METHOD PATH HTTP/1.1\r\n
 *   Header-Name: Value\r\n
 *   \r\n
 *   body
 *
 * @param {string} raw
 * @param {string} [fallbackHost]  Used when raw lacks a Host header
 * @returns {{ method: string, path: string, headers: object, body: string }}
 */
export function parseRawRequest(raw) {
  // Normalize CRLF / LF
  const normalized = raw.replace(/\r\n/g, '\n');
  const blankLine  = normalized.indexOf('\n\n');
  const headerPart = blankLine === -1 ? normalized : normalized.slice(0, blankLine);
  const bodyPart   = blankLine === -1 ? '' : normalized.slice(blankLine + 2);

  const lines = headerPart.split('\n');
  const [method = 'GET', rawPath = '/', _version = 'HTTP/1.1'] = (lines[0] ?? '').trim().split(/\s+/);

  const headers = {};
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const name  = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (name) headers[name.toLowerCase()] = value;
  }

  return { method: method.toUpperCase(), path: rawPath, headers, body: bodyPart };
}

/**
 * Reconstruct a raw HTTP request string from structured parts.
 */
function _buildRawRequest(method, url, headers, body) {
  const parsed   = new URL(url);
  const path     = parsed.pathname + parsed.search;
  let raw = `${method} ${path} HTTP/1.1\r\n`;
  for (const [k, v] of Object.entries(headers)) {
    raw += `${k}: ${v}\r\n`;
  }
  raw += '\r\n';
  if (body) raw += body;
  return raw;
}

/**
 * Reconstruct a raw HTTP response string.
 */
function _buildRawResponse(statusCode, statusMessage, headers, body) {
  let raw = `HTTP/1.1 ${statusCode} ${statusMessage}\r\n`;
  for (const [k, v] of Object.entries(headers)) {
    const vals = Array.isArray(v) ? v : [v];
    for (const val of vals) {
      raw += `${k}: ${val}\r\n`;
    }
  }
  raw += '\r\n';
  if (body) raw += body;
  return raw;
}

/**
 * Send an HTTP/HTTPS request and return the full response.
 *
 * @param {{
 *   url:       string,
 *   rawRequest?: string,  // if provided, parsed to extract method/headers/body
 *   method?:   string,
 *   headers?:  object,
 *   body?:     string,
 *   timeoutMs?: number,
 *   followRedirects?: number,  // max redirect count (default 3)
 * }} opts
 * @param {AbortSignal} [signal]
 */
export function sendRepeaterRequest(opts, signal) {
  const {
    url,
    rawRequest,
    timeoutMs        = 30_000,
    followRedirects  = 3,
  } = opts;

  // Parse raw request if supplied, otherwise use explicit fields
  let method, headers, body;
  if (rawRequest) {
    const parsed = parseRawRequest(rawRequest);
    method  = parsed.method;
    headers = { ...parsed.headers };
    body    = parsed.body || null;
  } else {
    method  = (opts.method ?? 'GET').toUpperCase();
    headers = { ...(opts.headers ?? {}) };
    body    = opts.body ?? null;
  }

  // Validate URL
  let parsedUrl;
  try { parsedUrl = new URL(url); } catch {
    return Promise.reject(new Error(`Invalid URL: ${url}`));
  }
  if (!ALLOWED_SCHEMES.includes(parsedUrl.protocol)) {
    return Promise.reject(new Error(`URL scheme '${parsedUrl.protocol}' is not allowed.`));
  }

  return _doRequest({ url, method, headers, body, timeoutMs, followRedirects }, signal, 0);
}

function _doRequest({ url, method, headers, body, timeoutMs, followRedirects }, signal, depth) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));

    const parsedUrl = new URL(url);
    const isHttps   = parsedUrl.protocol === 'https:';
    const lib       = isHttps ? https : http;

    // Ensure Host header is set
    const reqHeaders = { ...headers };
    if (!reqHeaders['host'] && !reqHeaders['Host']) {
      reqHeaders['host'] = parsedUrl.host;
    }

    const bodyBuf = body ? Buffer.from(body, 'utf8') : null;
    if (bodyBuf && !reqHeaders['content-length'] && !reqHeaders['Content-Length']) {
      reqHeaders['content-length'] = bodyBuf.length.toString();
    }

    const reqOpts = {
      hostname:            parsedUrl.hostname,
      port:                parsedUrl.port || (isHttps ? 443 : 80),
      path:                parsedUrl.pathname + parsedUrl.search,
      method,
      headers:             reqHeaders,
      timeout:             timeoutMs,
      rejectUnauthorized:  false,
      checkServerIdentity: () => undefined,
    };

    const rawRequest  = _buildRawRequest(method, url, reqHeaders, body ?? '');
    const t0          = Date.now();

    const req = lib.request(reqOpts, (res) => {
      const { statusCode, statusMessage = '' } = res;

      // Redirect handling
      if (depth < followRedirects &&
          [301, 302, 303, 307, 308].includes(statusCode) &&
          res.headers.location) {
        req.destroy();
        const redirectUrl = res.headers.location.startsWith('http')
          ? res.headers.location
          : new URL(res.headers.location, url).href;
        const newMethod = (statusCode === 303 || (method !== 'GET' && statusCode !== 307 && statusCode !== 308)) ? 'GET' : method;
        const newBody   = newMethod === 'GET' ? null : body;
        _doRequest(
          { url: redirectUrl, method: newMethod, headers: reqHeaders, body: newBody, timeoutMs, followRedirects },
          signal, depth + 1
        ).then(resolve).catch(reject);
        return;
      }

      const chunks = [];
      let totalBytes = 0;
      res.on('data', chunk => {
        totalBytes += chunk.length;
        if (totalBytes <= MAX_RESPONSE_BYTES) chunks.push(chunk);
      });
      res.on('end', () => {
        const bodyBuf     = Buffer.concat(chunks);
        const bodyStr     = bodyBuf.toString('utf8');
        const durationMs  = Date.now() - t0;
        const rawResponse = _buildRawResponse(statusCode, statusMessage, res.headers, bodyStr);

        resolve({
          statusCode,
          statusMessage,
          headers:     res.headers,
          body:        bodyStr,
          durationMs,
          rawRequest,
          rawResponse,
          truncated:   totalBytes > MAX_RESPONSE_BYTES,
        });
      });
      res.on('error', reject);
    });

    if (signal) {
      const onAbort = () => {
        req.destroy();
        reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
      };
      signal.addEventListener('abort', onAbort, { once: true });
      req.on('close', () => signal.removeEventListener('abort', onAbort));
    }

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timed out after ${timeoutMs}ms`));
    });

    req.on('error', reject);

    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}
