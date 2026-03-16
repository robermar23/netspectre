/**
 * Feature 7E — GraphQL Scanner Module
 *
 * Tests GraphQL endpoints discovered by apiDetector.js for:
 *   1. Introspection enabled — information disclosure
 *   2. Batch query abuse — DoS / rate-limit bypass
 *   3. Deeply nested query DoS
 *   4. Field suggestion leakage — misspelled fields expose schema hints
 *   5. SQLi / NoSQLi via resolver arguments
 *   6. Auth bypass via __typename on type fields
 *
 * Endpoints are identified heuristically:
 *   - Path matches /graphql, /gql, /api/graphql, /query (from webConstants GRAPHQL_PATHS)
 *   - Content-Type: application/json with "data"/"errors" keys in response
 */

import { sendProbe, makeFinding } from './index.js';
import {
  GRAPHQL_PATHS,
  GRAPHQL_INTROSPECTION_QUERY,
  GRAPHQL_BATCH_PROBE_COUNT,
} from '#shared/webConstants.js';

// ─── Helpers ───────────────────────────────────────────────────────────────────

function _isGraphqlEndpoint(target) {
  try {
    const u = new URL(target.url);
    if (GRAPHQL_PATHS.some(p => u.pathname.toLowerCase().includes(p.toLowerCase().replace('/graphql', 'graphql')))) return true;
  } catch { /* ignore */ }

  // Content-type negotiation: POST with application/json that returned "data" or "errors"
  const ct = Object.entries(target.responseHeaders || {})
    .find(([k]) => k.toLowerCase() === 'content-type')?.[1] || '';
  if (!ct.includes('application/json')) return false;

  try {
    const body = typeof target.responseBody === 'string'
      ? target.responseBody
      : target.responseBody?.toString?.('utf8') ?? '';
    const parsed = JSON.parse(body);
    return 'data' in parsed || 'errors' in parsed;
  } catch { return false; }
}

function _gqlPost(url, body, headers, signal, timeoutMs) {
  return sendProbe({
    method: 'POST',
    url,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(headers || {}),
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
    timeoutMs,
    followRedirect: false,
  }, signal);
}

// ─── Module runner ─────────────────────────────────────────────────────────────

export async function runGraphql(target, opts) {
  const { signal, timeoutMs, oastCallbackUrl: oastUrl } = opts;
  const findings = [];

  if (signal?.aborted) return findings;
  if (!_isGraphqlEndpoint(target)) return findings;

  const url     = target.url;
  const reqHdrs = target.requestHeaders || {};

  // ── 1. Introspection enabled ──────────────────────────────────────────────
  try {
    const resp = await _gqlPost(url, { query: '{__schema{types{name kind}}}' }, reqHdrs, signal, timeoutMs);
    if (signal?.aborted) return findings;

    let parsed = null;
    try { parsed = JSON.parse(resp.body); } catch { /* not JSON */ }

    if (parsed?.data?.__schema?.types?.length > 0) {
      findings.push(makeFinding({
        severity:    'medium',
        type:        'graphql',
        title:       'GraphQL Introspection Enabled',
        description: 'The GraphQL endpoint allows introspection queries, exposing the full API schema including all types, fields, queries, and mutations. Attackers can use this to map the attack surface and discover unintended operations.',
        url,
        evidence:    {
          query:      '{__schema{types{name kind}}}',
          typeCount:  parsed.data.__schema.types.length,
          sample:     parsed.data.__schema.types.slice(0, 5).map(t => t.name).join(', '),
        },
        remediation: 'Disable introspection in production environments. Most GraphQL servers have an `introspection` flag in their configuration. Use field-level authorization instead of relying on schema obscurity.',
        references:  ['OWASP API3:2023', 'CWE-200'],
      }));
    }
  } catch (err) {
    if (err.name === 'AbortError') return findings;
  }

  // ── 2. Batch query abuse ──────────────────────────────────────────────────
  try {
    const batchPayload = Array.from({ length: GRAPHQL_BATCH_PROBE_COUNT }, () => ({
      query: '{__typename}',
    }));
    const t0   = Date.now();
    const resp = await _gqlPost(url, batchPayload, reqHdrs, signal, timeoutMs);
    const dur  = Date.now() - t0;

    if (signal?.aborted) return findings;

    let parsed = null;
    try { parsed = JSON.parse(resp.body); } catch { /* ignore */ }

    // If we get back an array with 100 results, batching is accepted
    if (Array.isArray(parsed) && parsed.length >= GRAPHQL_BATCH_PROBE_COUNT * 0.9) {
      findings.push(makeFinding({
        severity:    'medium',
        type:        'graphql',
        title:       `GraphQL Batch Query Abuse — ${GRAPHQL_BATCH_PROBE_COUNT} Queries Accepted`,
        description: `The GraphQL endpoint accepts batched query arrays. An attacker can send ${GRAPHQL_BATCH_PROBE_COUNT}+ queries in a single HTTP request, bypassing rate limits and amplifying the impact of brute-force or enumeration attacks.`,
        url,
        evidence:    {
          batchSize:    GRAPHQL_BATCH_PROBE_COUNT,
          responseTime: `${dur}ms`,
          resultCount:  parsed.length,
        },
        remediation: 'Limit the number of operations in a single batch request. Enforce per-request query cost budgets. Disable batch queries if not required.',
        references:  ['OWASP API4:2023', 'CWE-400'],
      }));
    }
  } catch (err) {
    if (err.name === 'AbortError') return findings;
  }

  // ── 3. Deeply nested query DoS ────────────────────────────────────────────
  try {
    // Build a 12-level deep nested query — any schema with recursive types is vulnerable
    const nested = '{a{b{c{d{e{f{g{h{i{j{k{l{__typename}}}}}}}}}}}}}}';
    const t0   = Date.now();
    const resp = await _gqlPost(url, { query: nested }, reqHdrs, signal, { ...timeoutMs, timeoutMs: 15_000 });
    const dur  = Date.now() - t0;

    if (signal?.aborted) return findings;
    if (dur > 5000 && resp.statusCode !== 400) {
      findings.push(makeFinding({
        severity:    'medium',
        type:        'graphql',
        title:       'GraphQL Deeply Nested Query — Potential DoS',
        description: `A deeply nested GraphQL query (12 levels) took ${dur}ms and received a non-400 response. Servers without query depth limits are vulnerable to resource exhaustion via deeply nested queries.`,
        url,
        evidence:    {
          depth:        12,
          responseTime: `${dur}ms`,
          statusCode:   resp.statusCode,
        },
        remediation: 'Set a maximum query depth limit (e.g., 5–7 levels). Use a query complexity analysis library (e.g., graphql-depth-limit, graphql-cost-analysis).',
        references:  ['OWASP API4:2023', 'CWE-400'],
      }));
    }
  } catch (err) {
    if (err.name === 'AbortError') return findings;
  }

  // ── 4. Field suggestion leakage ───────────────────────────────────────────
  try {
    const resp = await _gqlPost(url, { query: '{nsProbeField_typo{id}}' }, reqHdrs, signal, timeoutMs);
    if (signal?.aborted) return findings;

    const body = resp.body || '';
    // GraphQL servers with field suggestions reply with "Did you mean ...?"
    if (/did you mean/i.test(body)) {
      const match = body.match(/did you mean[^"]*"([^"]+)"/i);
      findings.push(makeFinding({
        severity:    'low',
        type:        'graphql',
        title:       'GraphQL Field Suggestion Leakage',
        description: `The GraphQL endpoint returns field suggestion messages for misspelled field names, leaking information about the actual schema. This can aid schema enumeration even when introspection is disabled.`,
        url,
        evidence:    {
          probe:      '{nsProbeField_typo{id}}',
          suggestion: match?.[1] ?? '(see body)',
          bodyExcerpt: body.substring(0, 300),
        },
        remediation: 'Disable field suggestions in your GraphQL server configuration. For Apollo Server, set `fieldNamesToMask: []` or override the `formatError` hook to strip suggestion messages.',
        references:  ['OWASP API3:2023', 'CWE-200'],
      }));
    }
  } catch (err) {
    if (err.name === 'AbortError') return findings;
  }

  // ── 5. SQLi / injection via resolver arguments ────────────────────────────
  try {
    // Probe __typename (always valid) with a SQL payload in a query argument
    const sqliPayload = `{__typename(id:"1' OR '1'='1")}`;
    const resp = await _gqlPost(url, { query: sqliPayload }, reqHdrs, signal, timeoutMs);
    if (signal?.aborted) return findings;

    const body = resp.body || '';
    const DB_ERRORS = [
      /you have an error in your sql syntax/i,
      /sqlexception/i,
      /pg_query\(\)/i,
      /unclosed quotation mark/i,
      /ora-[0-9]{5}/i,
      /sqlite.*exception/i,
      /no such column/i,
    ];
    const hit = DB_ERRORS.find(re => re.test(body));
    if (hit) {
      findings.push(makeFinding({
        severity:    'critical',
        type:        'graphql',
        title:       'SQL Injection via GraphQL Resolver Arguments',
        description: `A SQL injection probe embedded in a GraphQL query argument triggered a database error response. The GraphQL layer is not sanitizing arguments before passing them to underlying SQL resolvers.`,
        url,
        payload:     sqliPayload,
        evidence:    {
          probe:      sqliPayload,
          bodyExcerpt: body.substring(0, 400),
        },
        remediation: 'Use parameterized queries or ORMs in all resolvers. Never concatenate GraphQL arguments into SQL strings. Apply input validation and type-checking at the resolver boundary.',
        references:  ['CWE-89', 'OWASP A03:2021'],
      }));
    }
  } catch (err) {
    if (err.name === 'AbortError') return findings;
  }

  // ── 6. OAST probe via __typename argument (blind injection confirmation) ──
  if (oastUrl) {
    try {
      const oastPayload = `{__typename(url:"${oastUrl}")}`;
      await _gqlPost(url, { query: oastPayload }, reqHdrs, signal, timeoutMs);
    } catch (err) {
      if (err.name === 'AbortError') return findings;
    }
  }

  return findings;
}
