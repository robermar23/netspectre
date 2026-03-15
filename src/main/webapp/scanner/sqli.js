/**
 * Feature 7C — SQL Injection Scanner Module
 *
 * Techniques:
 *   1. Time-Based Blind (MySQL SLEEP, MSSQL WAITFOR, PostgreSQL pg_sleep)
 *   2. Error-Based (parse DB error strings)
 *   3. Boolean-Based (AND 1=1 vs AND 1=2 length delta)
 *   4. UNION-Based (NULL column enumeration)
 *
 * All payloads are static string constants — never assembled from user input.
 */

import { sendProbe, extractParams, makeFinding } from './index.js';
import { DB_ERROR_PATTERNS, SCANNER_TIMING_THRESHOLD_MS } from '#shared/webConstants.js';

// ─── Payload sets ──────────────────────────────────────────────────────────────

const TIME_PAYLOADS = [
  { db: 'MySQL',      payload: "'; SELECT SLEEP(5)-- -" },
  { db: 'MySQL',      payload: "1; SELECT SLEEP(5)-- -" },
  { db: 'MSSQL',      payload: "'; WAITFOR DELAY '0:0:5'-- -" },
  { db: 'MSSQL',      payload: "1; WAITFOR DELAY '0:0:5'-- -" },
  { db: 'PostgreSQL', payload: "'; SELECT pg_sleep(5)-- -" },
  { db: 'PostgreSQL', payload: "1; SELECT pg_sleep(5)-- -" },
];

const ERROR_PAYLOADS = ["'", "''", "\\", "1/0", "1 AND 1=2", "1'", "1\""];

const BOOLEAN_TRUE  = ["1 AND 1=1-- -", "' AND '1'='1'-- -"];
const BOOLEAN_FALSE = ["1 AND 1=2-- -", "' AND '1'='2'-- -"];

const UNION_TEMPLATES = (n) =>
  `' UNION SELECT ${Array(n).fill('NULL').join(',')}-- -`;

// ─── Module runner ─────────────────────────────────────────────────────────────

/**
 * @param {object} target - { url, method, requestHeaders, body }
 * @param {{ timeoutMs, signal }} opts
 * @returns {Promise<Finding[]>}
 */
export async function runSqli(target, opts) {
  const { signal, timeoutMs } = opts;
  const findings = [];
  const params   = extractParams(target);

  if (!params.length) return findings;

  for (const param of params) {
    if (signal?.aborted) break;

    // ── 1. Time-based blind ──────────────────────────────────────────────────
    // First establish baseline timing
    let baselineMs = 0;
    try {
      const base = await sendProbe(
        { method: target.method, url: target.url, headers: target.requestHeaders, body: target.body, timeoutMs },
        signal,
      );
      baselineMs = base.durationMs;
    } catch { /* skip if baseline fails */ }

    for (const { db, payload } of TIME_PAYLOADS) {
      if (signal?.aborted) break;
      const injected = param.inject(payload);
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
            type:        'sqli',
            title:       `SQL Injection (Time-Based Blind) in parameter "${param.name}"`,
            description: `The "${param.name}" parameter is vulnerable to time-based blind SQL injection. Injecting a ${db} sleep payload caused a ${elapsed}ms response delay (baseline: ${baselineMs}ms).`,
            url:         target.url,
            parameter:   param.name,
            payload,
            evidence:    {
              request:  `${injected.method || target.method} ${injected.url || target.url}`,
              response: `HTTP ${resp.statusCode} — ${elapsed}ms (baseline: ${baselineMs}ms)`,
              timingMs: elapsed,
            },
            remediation: 'Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.',
            references:  ['CWE-89', 'OWASP A03:2021', 'https://owasp.org/www-community/attacks/SQL_Injection'],
          }));
          break; // One time-based finding per param is enough
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }

    // ── 2. Error-based ───────────────────────────────────────────────────────
    for (const payload of ERROR_PAYLOADS) {
      if (signal?.aborted) break;
      if (findings.some(f => f.parameter === param.name && f.type === 'sqli' && f.severity === 'critical')) break;
      const injected = param.inject(payload);
      try {
        const resp = await sendProbe(
          { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
          signal,
        );
        for (const { pattern, db } of DB_ERROR_PATTERNS) {
          if (pattern.test(resp.body)) {
            findings.push(makeFinding({
              severity:    'critical',
              type:        'sqli',
              title:       `SQL Injection (Error-Based, ${db}) in parameter "${param.name}"`,
              description: `The "${param.name}" parameter reflects a ${db} database error when injected with: ${payload}`,
              url:         target.url,
              parameter:   param.name,
              payload,
              evidence:    {
                request:  `${target.method} ${target.url}`,
                response: resp.body.slice(0, 500),
                dbType:   db,
              },
              remediation: 'Use parameterized queries / prepared statements. Suppress database error messages in production.',
              references:  ['CWE-89', 'OWASP A03:2021'],
            }));
            break;
          }
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }

    // ── 3. Boolean-based ─────────────────────────────────────────────────────
    if (!findings.some(f => f.parameter === param.name && f.type === 'sqli')) {
      try {
        const trueResponses = [];
        const falseResponses = [];

        for (const payload of BOOLEAN_TRUE) {
          if (signal?.aborted) break;
          const injected = param.inject(payload);
          const resp = await sendProbe(
            { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
            signal,
          );
          trueResponses.push(resp.body.length);
        }
        for (const payload of BOOLEAN_FALSE) {
          if (signal?.aborted) break;
          const injected = param.inject(payload);
          const resp = await sendProbe(
            { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
            signal,
          );
          falseResponses.push(resp.body.length);
        }

        const trueAvg  = trueResponses.reduce((a, b) => a + b, 0) / (trueResponses.length || 1);
        const falseAvg = falseResponses.reduce((a, b) => a + b, 0) / (falseResponses.length || 1);
        const delta    = Math.abs(trueAvg - falseAvg);

        if (delta > 10) {
          findings.push(makeFinding({
            severity:    'medium',
            type:        'sqli',
            title:       `SQL Injection (Boolean-Based Blind) in parameter "${param.name}"`,
            description: `The "${param.name}" parameter produces different response lengths (delta: ${Math.round(delta)} bytes) for true vs false boolean conditions, indicating boolean-based blind SQL injection.`,
            url:         target.url,
            parameter:   param.name,
            payload:     BOOLEAN_TRUE[0],
            evidence:    {
              request:   `${target.method} ${target.url}`,
              response:  `Avg true length: ${Math.round(trueAvg)}, Avg false length: ${Math.round(falseAvg)}`,
              deltaBytes: Math.round(delta),
            },
            remediation: 'Use parameterized queries / prepared statements.',
            references:  ['CWE-89', 'OWASP A03:2021'],
          }));
        }
      } catch (err) {
        if (err.name === 'AbortError') return findings;
      }
    }

    // ── 4. UNION-based ───────────────────────────────────────────────────────
    if (!findings.some(f => f.parameter === param.name && f.type === 'sqli' && ['critical','high'].includes(f.severity))) {
      for (let cols = 1; cols <= 10; cols++) {
        if (signal?.aborted) break;
        const payload  = UNION_TEMPLATES(cols);
        const injected = param.inject(payload);
        try {
          const resp = await sendProbe(
            { method: injected.method || target.method, url: injected.url, headers: injected.requestHeaders || target.requestHeaders, body: injected.body, timeoutMs },
            signal,
          );
          if (resp.statusCode === 200 && /NULL/i.test(resp.body)) {
            findings.push(makeFinding({
              severity:    'high',
              type:        'sqli',
              title:       `SQL Injection (UNION-Based, ${cols} column${cols > 1 ? 's' : ''}) in parameter "${param.name}"`,
              description: `The "${param.name}" parameter is vulnerable to UNION-based SQL injection with ${cols} column(s). The UNION SELECT NULL payload was reflected in the response.`,
              url:         target.url,
              parameter:   param.name,
              payload,
              evidence:    {
                request:  `${target.method} ${target.url}`,
                response: resp.body.slice(0, 300),
              },
              remediation: 'Use parameterized queries / prepared statements.',
              references:  ['CWE-89', 'OWASP A03:2021'],
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
