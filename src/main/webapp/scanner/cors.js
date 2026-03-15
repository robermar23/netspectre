/**
 * Feature 7C — CORS Misconfiguration Scanner Module
 *
 * Per-host checks:
 *   1. Reflected arbitrary Origin
 *   2. ACAO: * with Credentials (impossible per spec — some frameworks still do it)
 *   3. null Origin reflection
 *   4. Subdomain prefix / suffix bypass (target.com.evil.test)
 */

import { sendProbe, makeFinding } from './index.js';

// ─── Module runner ────────────────────────────────────────────────────────────

export async function runCors(target, opts) {
  const { signal, timeoutMs } = opts;
  const findings = [];

  let parsed;
  try { parsed = new URL(target.url); } catch { return findings; }

  const targetOrigin = `${parsed.protocol}//${parsed.host}`;

  const probes = [
    {
      origin:   'https://evil.netspecter.test',
      label:    'arbitrary origin reflection',
      severity: 'high',
      check:    (acao, acac) => acao === 'https://evil.netspecter.test',
      desc:     (acao) => `The Access-Control-Allow-Origin header reflects the arbitrary test origin "${acao}", allowing any website to make credentialed cross-origin requests.`,
    },
    {
      origin:   'null',
      label:    'null origin reflection',
      severity: 'high',
      check:    (acao) => acao === 'null',
      desc:     () => 'The server returns Access-Control-Allow-Origin: null, which can be exploited from sandboxed iframes or local file contexts.',
    },
    {
      origin:   `https://${parsed.hostname}.evil.test`,
      label:    'subdomain bypass',
      severity: 'critical',
      check:    (acao) => acao === `https://${parsed.hostname}.evil.test`,
      desc:     (acao) => `The server reflects the origin "${acao}" — which is a subdomain of the attacker's domain, not the target domain. This allows full cross-origin data access.`,
    },
    {
      origin:   `https://evil${parsed.hostname}`,
      label:    'prefix bypass',
      severity: 'high',
      check:    (acao) => acao === `https://evil${parsed.hostname}`,
      desc:     (acao) => `The server reflects "${acao}", which uses the target hostname as a suffix. This indicates a regex-based origin check that is bypassable.`,
    },
  ];

  for (const probe of probes) {
    if (signal?.aborted) break;
    try {
      const resp = await sendProbe(
        {
          method:  'GET',
          url:     target.url,
          headers: { ...(target.requestHeaders || {}), Origin: probe.origin },
          timeoutMs,
        },
        signal,
      );

      const acao = resp.headers['access-control-allow-origin'] || '';
      const acac = resp.headers['access-control-allow-credentials'] || '';

      if (probe.check(acao, acac)) {
        const isCredentialed = acac.toLowerCase() === 'true';
        findings.push(makeFinding({
          severity:    probe.severity,
          type:        'cors',
          title:       `CORS Misconfiguration — ${probe.label} at ${target.url}`,
          description: probe.desc(acao) + (isCredentialed ? ' Credentials are also allowed, enabling cookie theft.' : ''),
          url:         target.url,
          payload:     `Origin: ${probe.origin}`,
          evidence:    {
            request:      `GET ${target.url} (Origin: ${probe.origin})`,
            response:     `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac || 'not set'}`,
            credentialed: isCredentialed,
          },
          remediation: 'Maintain a strict allowlist of trusted origins. Never reflect the Origin header verbatim. Do not combine ACAO: * with ACAC: true.',
          references:  ['CWE-942', 'OWASP A05:2021'],
        }));
      }

      // Special check: ACAO: * with credentials (spec violation but some frameworks allow)
      if (acao === '*' && acac.toLowerCase() === 'true') {
        findings.push(makeFinding({
          severity:    'critical',
          type:        'cors',
          title:       `CORS — Wildcard Origin with Credentials at ${target.url}`,
          description: 'The server sets Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true simultaneously. Although the browser rejects this per spec, it may indicate a misconfigured framework that treats them independently, or it could still be exploitable in some contexts.',
          url:         target.url,
          payload:     probe.origin,
          evidence:    {
            response: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true`,
          },
          remediation: 'Never combine a wildcard ACAO with ACAC: true. Use explicit origin allowlisting.',
          references:  ['CWE-942', 'OWASP A05:2021'],
        }));
      }
    } catch (err) {
      if (err.name === 'AbortError') return findings;
    }
  }

  return findings;
}
