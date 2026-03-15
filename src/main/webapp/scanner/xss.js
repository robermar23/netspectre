/**
 * Feature 7C — Cross-Site Scripting (XSS) Scanner Module
 *
 * Techniques:
 *   1. Reflected XSS — inject canary + payload, check for unencoded reflection
 *   2. DOM sink hints — flag .innerHTML / document.write in response
 *   3. Context-aware encoding bypass variants (URL-encoded, double-encoded, unicode)
 *
 * All payloads are static string constants.
 */

import { sendProbe, extractParams, makeFinding } from './index.js';

// ─── Payload constants ─────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "'><svg onload=alert(1)>",
  '<body onload=alert(1)>',
  '<details open ontoggle=alert(1)>',
  '"><iframe src=javascript:alert(1)>',
];

const XSS_ENCODED_PAYLOADS = [
  '%3Cscript%3Ealert(1)%3C/script%3E',    // URL-encoded
  '%253Cscript%253Ealert(1)%253C/script%253E', // Double URL-encoded
  '\u003Cscript\u003Ealert(1)\u003C/script\u003E', // Unicode
];

// DOM sink patterns (heuristic, triggers INFO finding)
const DOM_SINK_PATTERNS = [
  /\.innerHTML\s*=/,
  /document\.write\s*\(/,
  /document\.writeln\s*\(/,
  /\.outerHTML\s*=/,
  /location\.href\s*=/,
  /eval\s*\(/,
  /setTimeout\s*\(\s*['"]/,
  /setInterval\s*\(\s*['"]/,
];

// ─── Module runner ─────────────────────────────────────────────────────────────

/**
 * @param {object} target
 * @param {{ timeoutMs, signal }} opts
 * @returns {Promise<Finding[]>}
 */
export async function runXss(target, opts) {
  const { signal, timeoutMs } = opts;
  const findings = [];
  const params   = extractParams(target);

  // DOM sink passive check — no extra request needed
  if (target.responseBody) {
    for (const pattern of DOM_SINK_PATTERNS) {
      if (pattern.test(target.responseBody)) {
        findings.push(makeFinding({
          severity:    'info',
          type:        'xss',
          title:       'Potential DOM XSS Sink Detected',
          description: `The page at ${target.url} contains JavaScript code that writes to a DOM sink (${pattern.toString().slice(1,40)}...). If the data originates from an attacker-controlled source (e.g., location.hash, document.referrer) this may be exploitable as DOM-based XSS. Manual review required.`,
          url:         target.url,
          evidence:    { response: `Matched pattern: ${pattern}` },
          remediation: 'Avoid passing untrusted data to DOM sinks. Use textContent instead of innerHTML. Apply DOMPurify for rich HTML.',
          references:  ['CWE-79', 'OWASP A03:2021'],
        }));
        break; // One DOM sink finding per URL is enough
      }
    }
  }

  if (!params.length) return findings;

  for (const param of params) {
    if (signal?.aborted) break;
    let found = false;

    // ── 1. Standard XSS payloads ─────────────────────────────────────────────
    for (const payload of XSS_PAYLOADS) {
      if (signal?.aborted) break;
      if (found) break;

      // Use a unique canary tied to this payload
      const canary   = `NSXSS${crypto.randomUUID().replace(/-/g,'').slice(0,8)}`;
      const testPayload = payload.replace('alert(1)', `alert('${canary}')`);

      const injected = param.inject(testPayload);
      try {
        const resp = await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
          signal,
        );

        // Check if payload appears unencoded (literal < in HTML context)
        if (resp.body.includes('<script') || resp.body.includes('onerror=') || resp.body.includes('onload=') || resp.body.includes('ontoggle=')) {
          findings.push(makeFinding({
            severity:    'high',
            type:        'xss',
            title:       `Reflected XSS in parameter "${param.name}"`,
            description: `The "${param.name}" parameter reflects user input without proper encoding, allowing injection of arbitrary HTML/JavaScript. Payload "${testPayload}" was reflected unescaped in the response.`,
            url:         target.url,
            parameter:   param.name,
            payload:     testPayload,
            evidence:    {
              request:  `${target.method} ${target.url}`,
              response: _extractSnippet(resp.body, canary, testPayload),
            },
            remediation: 'HTML-encode all user-supplied output. Apply a strict Content-Security-Policy. Use context-aware encoding.',
            references:  ['CWE-79', 'OWASP A03:2021'],
          }));
          found = true;
        } else if (resp.body.includes(canary)) {
          // Partial reflection — canary present but tags stripped (may still be bypassable)
          findings.push(makeFinding({
            severity:    'low',
            type:        'xss',
            title:       `Partial XSS Reflection in parameter "${param.name}" (filter may be bypassable)`,
            description: `The "${param.name}" parameter reflects the canary string but strips HTML tags. This may indicate a bypassable filter. Manual testing with alternative payloads is recommended.`,
            url:         target.url,
            parameter:   param.name,
            payload:     testPayload,
            evidence:    {
              request:  `${target.method} ${target.url}`,
              response: _extractSnippet(resp.body, canary, canary),
            },
            remediation: 'Use a robust output encoding library. Avoid blocklist-based XSS filters.',
            references:  ['CWE-79', 'OWASP A03:2021'],
          }));
          found = true;
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }

    // ── 2. Encoded bypass variants ───────────────────────────────────────────
    if (!found) {
      for (const payload of XSS_ENCODED_PAYLOADS) {
        if (signal?.aborted) break;
        const injected = param.inject(payload);
        try {
          const resp = await sendProbe(
            { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
            signal,
          );
          if (resp.body.includes('<script') || resp.body.includes('onerror=')) {
            findings.push(makeFinding({
              severity:    'high',
              type:        'xss',
              title:       `Reflected XSS (Encoded Bypass) in parameter "${param.name}"`,
              description: `The "${param.name}" parameter is vulnerable to XSS via an encoded payload variant, suggesting the filter does not normalise encoded input before checking.`,
              url:         target.url,
              parameter:   param.name,
              payload,
              evidence:    { request: `${target.method} ${target.url}`, response: resp.body.slice(0, 300) },
              remediation: 'Decode and normalise input before filtering. Use context-aware output encoding.',
              references:  ['CWE-79', 'OWASP A03:2021'],
            }));
            break;
          }
        } catch (err) {
          if (err.name === 'AbortError') return findings;
        }
      }
    }
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function _extractSnippet(body, ...searchTerms) {
  for (const term of searchTerms) {
    const idx = body.indexOf(term);
    if (idx !== -1) {
      return body.slice(Math.max(0, idx - 100), idx + term.length + 100);
    }
  }
  return body.slice(0, 300);
}
