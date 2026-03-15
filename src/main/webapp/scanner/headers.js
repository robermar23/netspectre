/**
 * Feature 7C — HTTP Security Headers Audit Module
 *
 * Passively audits response headers from the proxy history.
 * No additional HTTP requests are made.
 *
 * Checks:
 *   - Missing security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, etc.)
 *   - Version disclosure (Server:, X-Powered-By:)
 *   - Cookie flag audit (HttpOnly, Secure, SameSite)
 *   - Dangerous CORS combination (ACAO: * + ACAC: true)
 */

import { makeFinding } from './index.js';
import { SECURITY_HEADERS } from '#shared/webConstants.js';

// ─── Version disclosure patterns ──────────────────────────────────────────────

const VERSION_PATTERNS = [
  { header: 'server',        pattern: /[0-9]\.[0-9]/, label: 'Server version disclosure' },
  { header: 'x-powered-by', pattern: /.+/,           label: 'Technology disclosure (X-Powered-By)' },
  { header: 'x-aspnet-version', pattern: /.+/,       label: 'ASP.NET version disclosure' },
  { header: 'x-generator',  pattern: /.+/,           label: 'Generator disclosure' },
];

// ─── Module runner ────────────────────────────────────────────────────────────

export async function runHeaders(target, _opts) {
  const findings  = [];
  const respHdrs  = target.responseHeaders || {};
  const reqUrl    = target.url;
  const isHttps   = reqUrl.startsWith('https://');

  // Normalise all header names to lowercase
  const hdrs = {};
  for (const [k, v] of Object.entries(respHdrs)) {
    hdrs[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }

  // ── 1. Missing security headers ───────────────────────────────────────────
  for (const { name, severity, label, recommended } of SECURITY_HEADERS) {
    if (!hdrs[name]) {
      // HSTS only matters over HTTPS
      if (name === 'strict-transport-security' && !isHttps) continue;

      findings.push(makeFinding({
        severity,
        type:        'headers',
        title:       `Missing Security Header: ${label}`,
        description: `The response from ${reqUrl} does not include the ${label} header. This header helps protect against common web attacks.`,
        url:         reqUrl,
        evidence:    {
          missingHeader: label,
          recommended,
        },
        remediation: `Add the header: ${label}: ${recommended}`,
        references:  ['OWASP Secure Headers Project', 'https://securityheaders.com'],
      }));
    }
  }

  // ── 2. Version / technology disclosure ───────────────────────────────────
  for (const { header, pattern, label } of VERSION_PATTERNS) {
    const val = hdrs[header];
    if (val && pattern.test(val)) {
      findings.push(makeFinding({
        severity:    'info',
        type:        'headers',
        title:       `${label}: "${val}"`,
        description: `The ${header} header reveals server technology and version information: "${val}". This aids attackers in targeting known vulnerabilities.`,
        url:         reqUrl,
        evidence:    { header, value: val },
        remediation: `Remove or obfuscate the ${header} header. Configure your web server to suppress version information.`,
        references:  ['CWE-200', 'OWASP A05:2021'],
      }));
    }
  }

  // ── 3. Cookie audit ───────────────────────────────────────────────────────
  const setCookies = _getSetCookieValues(respHdrs);
  for (const cookieStr of setCookies) {
    const name  = cookieStr.split('=')[0].trim();
    const lower = cookieStr.toLowerCase();

    if (!lower.includes('httponly')) {
      findings.push(makeFinding({
        severity:    'medium',
        type:        'headers',
        title:       `Cookie "${name}" Missing HttpOnly Flag`,
        description: `The cookie "${name}" does not have the HttpOnly flag set. This allows JavaScript to read the cookie, enabling theft via XSS.`,
        url:         reqUrl,
        evidence:    { cookie: cookieStr.slice(0, 200) },
        remediation: `Set the HttpOnly attribute on the ${name} cookie: Set-Cookie: ${name}=value; HttpOnly`,
        references:  ['CWE-1004', 'OWASP A02:2021'],
      }));
    }

    if (isHttps && !lower.includes('; secure')) {
      findings.push(makeFinding({
        severity:    'medium',
        type:        'headers',
        title:       `Cookie "${name}" Missing Secure Flag (HTTPS endpoint)`,
        description: `The cookie "${name}" is set over HTTPS without the Secure flag. The cookie could be transmitted over HTTP if the user accesses the site via HTTP.`,
        url:         reqUrl,
        evidence:    { cookie: cookieStr.slice(0, 200) },
        remediation: `Add the Secure attribute: Set-Cookie: ${name}=value; Secure`,
        references:  ['CWE-614', 'OWASP A02:2021'],
      }));
    }

    if (!lower.includes('samesite')) {
      findings.push(makeFinding({
        severity:    'low',
        type:        'headers',
        title:       `Cookie "${name}" Missing SameSite Attribute`,
        description: `The cookie "${name}" does not specify a SameSite attribute. Without this attribute, the cookie may be sent with cross-site requests, enabling CSRF attacks.`,
        url:         reqUrl,
        evidence:    { cookie: cookieStr.slice(0, 200) },
        remediation: `Add SameSite=Lax or SameSite=Strict: Set-Cookie: ${name}=value; SameSite=Lax`,
        references:  ['CWE-1275', 'OWASP A01:2021'],
      }));
    }
  }

  // ── 4. Dangerous CORS: ACAO * + ACAC true ────────────────────────────────
  const acao = hdrs['access-control-allow-origin'] || '';
  const acac = hdrs['access-control-allow-credentials'] || '';
  if (acao === '*' && acac.toLowerCase() === 'true') {
    findings.push(makeFinding({
      severity:    'critical',
      type:        'headers',
      title:       'Dangerous CORS: Wildcard Origin with Allow-Credentials',
      description: `${reqUrl} returns Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. Although browsers reject this combination per spec, it signals a serious misconfiguration.`,
      url:         reqUrl,
      evidence:    { 'Access-Control-Allow-Origin': acao, 'Access-Control-Allow-Credentials': acac },
      remediation: 'Replace the wildcard ACAO with an explicit origin allowlist. Never combine * with Allow-Credentials.',
      references:  ['CWE-942', 'OWASP A05:2021'],
    }));
  }

  return findings;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function _getSetCookieValues(rawHeaders) {
  const results = [];
  for (const [k, v] of Object.entries(rawHeaders)) {
    if (k.toLowerCase() === 'set-cookie') {
      if (Array.isArray(v)) results.push(...v);
      else results.push(String(v));
    }
  }
  return results;
}
