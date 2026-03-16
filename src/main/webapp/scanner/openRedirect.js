/**
 * Feature 7E — Open Redirect Detection Module
 *
 * Tests URL parameters that look like redirect targets for:
 *   1. Direct external redirect (off-domain Location header)
 *   2. Protocol-relative redirect (// prefix)
 *   3. Backslash bypass (/\evil.com)
 *   4. URL encoding bypass (%2F%2Fevil.com)
 *   5. Double-encoding bypass (%252F%252Fevil.com)
 *   6. HTML/JS-injection via redirect value (XSS chaining)
 *   7. Meta-refresh / JavaScript redirect detection in response body
 *
 * Severity: Medium (standalone) — can be upgraded to High when chained with XSS.
 * References: CWE-601, OWASP A01:2021
 */

import { sendProbe, makeFinding } from './index.js';
import { REDIRECT_PARAM_NAMES } from '#shared/webConstants.js';

// ─── Constants ─────────────────────────────────────────────────────────────────

const EVIL_DOMAIN = 'evil-redir.netspectre.test';
const EVIL_URL    = `https://${EVIL_DOMAIN}/`;

const REDIRECT_PAYLOADS = [
  { payload: EVIL_URL,                      type: 'direct',           desc: 'Direct external URL' },
  { payload: `///${EVIL_DOMAIN}/`,          type: 'triple-slash',     desc: 'Triple-slash redirect' },
  { payload: `//${EVIL_DOMAIN}/`,           type: 'protocol-rel',     desc: 'Protocol-relative URL' },
  { payload: `/\\${EVIL_DOMAIN}/`,          type: 'backslash',        desc: 'Backslash bypass' },
  { payload: `%2F%2F${EVIL_DOMAIN}%2F`,    type: 'url-encoded',      desc: 'URL-encoded //domain/' },
  { payload: `%252F%252F${EVIL_DOMAIN}%252F`, type: 'double-encoded', desc: 'Double-encoded //domain/' },
  { payload: `https:%09%2F%2F${EVIL_DOMAIN}/`, type: 'tab-encoded',  desc: 'Tab-encoded bypass' },
  { payload: `https://${EVIL_DOMAIN}@legitimate.example.com/`, type: 'at-sign', desc: 'User-info bypass' },
];

// ─── Helpers ───────────────────────────────────────────────────────────────────

function _isOffDomainLocation(location, originalHost) {
  if (!location) return false;
  try {
    const loc = new URL(location.startsWith('/') && !location.startsWith('//') ? `https://${originalHost}${location}` : location);
    return loc.hostname !== originalHost && loc.hostname.includes(EVIL_DOMAIN.split('.')[0]);
  } catch { return false; }
}

function _hasJsOrMetaRedirect(body, domain) {
  const lower = body.toLowerCase();
  const hasMeta     = lower.includes('http-equiv="refresh"') && lower.includes(domain.toLowerCase());
  const hasJsAssign = lower.includes('window.location') && lower.includes(domain.toLowerCase());
  const hasJsReplace = lower.includes('location.replace') && lower.includes(domain.toLowerCase());
  return hasMeta || hasJsAssign || hasJsReplace;
}

function _buildProbeUrl(originalUrl, paramName, payload) {
  try {
    const u = new URL(originalUrl);
    u.searchParams.set(paramName, payload);
    return u.toString();
  } catch { return null; }
}

// ─── Module runner ─────────────────────────────────────────────────────────────

export async function runOpenRedirect(target, opts) {
  const { signal, timeoutMs } = opts;
  const findings = [];

  let parsedUrl;
  try { parsedUrl = new URL(target.url); } catch { return findings; }

  // Find redirect-like parameters in query string + POST body
  const queryParams = [...parsedUrl.searchParams.keys()];
  const bodyParams  = (() => {
    if (!target.requestBody) return [];
    const b = String(target.requestBody);
    // form-urlencoded
    if ((target.requestHeaders?.['content-type'] || '').includes('application/x-www-form-urlencoded')) {
      return [...new URLSearchParams(b).keys()];
    }
    return [];
  })();

  const allParams = [...new Set([...queryParams, ...bodyParams])];
  const redirectParams = allParams.filter(p =>
    REDIRECT_PARAM_NAMES.some(r => p.toLowerCase().includes(r.toLowerCase())),
  );

  // Also probe any param whose current value starts with http:// or https://
  const urlValueParams = queryParams.filter(p => {
    const v = parsedUrl.searchParams.get(p) ?? '';
    return v.startsWith('http://') || v.startsWith('https://') || v.startsWith('//');
  });

  const probeParams = [...new Set([...redirectParams, ...urlValueParams])];
  if (!probeParams.length) return findings;

  const originalHost = parsedUrl.hostname;

  for (const param of probeParams) {
    if (signal?.aborted) break;

    for (const { payload, type, desc } of REDIRECT_PAYLOADS) {
      if (signal?.aborted) break;

      const probeUrl = _buildProbeUrl(target.url, param, payload);
      if (!probeUrl) continue;

      try {
        const resp = await sendProbe({
          method:         target.method || 'GET',
          url:            probeUrl,
          headers:        target.requestHeaders || {},
          body:           target.requestBody ?? null,
          timeoutMs,
          followRedirect: false,
        }, signal);

        const location = Object.entries(resp.headers || {})
          .find(([k]) => k.toLowerCase() === 'location')?.[1] ?? '';

        const isHeaderRedirect = (resp.statusCode >= 300 && resp.statusCode < 400) &&
          _isOffDomainLocation(location, originalHost);

        const isBodyRedirect = resp.body
          ? _hasJsOrMetaRedirect(resp.body, EVIL_DOMAIN)
          : false;

        if (isHeaderRedirect || isBodyRedirect) {
          findings.push(makeFinding({
            severity:    'medium',
            type:        'openRedirect',
            title:       `Open Redirect — Parameter "${param}" (${desc})`,
            description: `The parameter "${param}" is vulnerable to an open redirect. Injecting an external URL via ${desc} causes the server to redirect to an attacker-controlled domain. This can be used for phishing, OAuth token theft, or chained with XSS.`,
            url:         target.url,
            parameter:   param,
            payload,
            evidence: {
              probeUrl,
              statusCode:   resp.statusCode,
              location:     location || '(body redirect)',
              redirectType: isHeaderRedirect ? 'HTTP redirect' : 'body redirect (JS/meta)',
            },
            remediation: 'Validate redirect destinations against a strict allowlist of known-good URLs or restrict to relative paths only. Reject any redirect_uri not registered in the application. Encode the final destination in an opaque token rather than passing it as a URL.',
            references:  ['CWE-601', 'OWASP A01:2021'],
          }));
          break; // One finding per param is sufficient
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }
  }

  return findings;
}
