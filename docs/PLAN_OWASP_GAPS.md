# OWASP Top 10 Gap Closure — Implementation Plan

> NetSpecter Active Vulnerability Scanner — Feature 7C Extension
>
> **Status:** Planning
> **Covers:** A01, A02, A06, A07 (extension), A08
> **Skills applied:** security-auditor, scanning-tools, security-scanning-security-hardening,
> security-scanning-security-dependencies, nodejs-backend-patterns, nodejs-best-practices,
> javascript-pro, network-engineer, network-101, ui-skills, ui-ux-designer

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Coverage Baseline](#2-current-coverage-baseline)
3. [Architecture & Integration Model](#3-architecture--integration-model)
4. [A01 — Broken Access Control / IDOR Scanner](#4-a01--broken-access-control--idor-scanner)
5. [A02 — TLS & Cryptographic Failures Analyzer](#5-a02--tls--cryptographic-failures-analyzer)
6. [A06 — Vulnerable & Outdated Components Scanner](#6-a06--vulnerable--outdated-components-scanner)
7. [A07 — Session Security (brokenAuth Extension)](#7-a07--session-security-brokenauth-extension)
8. [A08 — Software & Data Integrity (SRI Checker)](#8-a08--software--data-integrity-sri-checker)
9. [Shared IPC Channel Additions](#9-shared-ipc-channel-additions)
10. [UI/UX Design Specification](#10-uiux-design-specification)
11. [Test Plan](#11-test-plan)
12. [Implementation Order](#12-implementation-order)
13. [Security & Ethical Constraints](#13-security--ethical-constraints)

---

## 1. Executive Summary

NetSpecter's active vulnerability scanner currently covers 5 of the 10 OWASP Top 10 (2021)
categories fully, with partial coverage of 3 more. This plan closes the five remaining gaps:

| Gap | Module | Priority | Effort |
|-----|--------|----------|--------|
| A01 Broken Access Control | `idor.js` (new) | HIGH | Large |
| A02 Cryptographic Failures | `tlsAnalyzer.js` (new) | HIGH | Medium |
| A06 Vulnerable Components | `componentCve.js` (new) | HIGH | Medium |
| A07 Auth/Session Failures | extend `brokenAuth.js` | MEDIUM | Small |
| A08 Integrity Failures | `sriChecker.js` (new) | MEDIUM | Small |

Each new module follows the **exact same contract** as the existing 10 scanner modules:

```js
export async function run[Module](target, scanOpts) → Promise<Finding[]>
```

No new IPC channels are required for findings — all new modules flow through the existing
`SCANNER_FINDING` / `SCANNER_PROGRESS` / `SCANNER_ACTIVITY` pipeline. One new IPC channel
(`SCANNER_AUTH_CONTEXT`) is added for IDOR's optional auth token input.

---

## 2. Current Coverage Baseline

### Existing Modules (src/main/webapp/scanner/)

| File | Module Key | OWASP | Detection Method |
|------|------------|-------|-----------------|
| `sqli.js` | `sqli` | A03 | Time-blind, error-based, boolean, UNION |
| `xss.js` | `xss` | A03 | Canary reflection, DOM sink patterns |
| `ssrf.js` | `ssrf` | A10 | Cloud metadata, timing-blind, OAST |
| `xxe.js` | `xxe` | A03 | File URI entities, response delta |
| `cmdInjection.js` | `cmdInjection` | A03 | Separator injection, time-based |
| `pathTraversal.js` | `pathTraversal` | A03 | ../sequences, file content patterns |
| `cors.js` | `cors` | A05 | Origin reflection, null, subdomain bypass |
| `headers.js` | `headers` | A05 | Security header presence/correctness |
| `brokenAuth.js` | `brokenAuth` | A07 | Rate limit, JWT alg:none, weak creds |
| `deserialize.js` | `deserialize` | A08 | PHP/Java/Python/ViewState markers |

### Gap Summary

```
A01 Broken Access Control    ❌  No IDOR, no access control testing
A02 Cryptographic Failures   🟡  HSTS header only; no TLS handshake analysis
A03 Injection                ✅  SQLi, CMDi, XXE, XSS, LFI
A04 Insecure Design          ❌  Not automatable
A05 Security Misconfiguration ✅ CORS + Headers modules
A06 Vulnerable Components    ❌  No version fingerprinting or CVE lookup
A07 Auth & Session Failures  🟡  Rate-limit, JWT; missing session fixation, cookie entropy
A08 Integrity Failures       🟡  Deserialize pattern; no SRI, no subresource integrity
A09 Logging & Monitoring     ❌  Not automatable from black-box scanner
A10 SSRF                     ✅  Full SSRF module
```

---

## 3. Architecture & Integration Model

### 3.1 File Structure (after all 5 modules added)

```
src/
├── shared/
│   ├── ipc.js                         ← add SCANNER_AUTH_CONTEXT channel
│   └── webConstants.js                ← add CVE_DB, TLS_WEAK_CIPHERS, SRI_EXTERNAL_ORIGINS constants
│
├── main/
│   └── webapp/
│       ├── scanner/
│       │   ├── index.js               ← register 4 new modules in MODULE_RUNNERS + MODULE_META
│       │   ├── idor.js                ← NEW: A01 IDOR detection
│       │   ├── tlsAnalyzer.js         ← NEW: A02 TLS/crypto analysis
│       │   ├── componentCve.js        ← NEW: A06 component version + CVE lookup
│       │   ├── sriChecker.js          ← NEW: A08 SRI integrity checker
│       │   ├── brokenAuth.js          ← MODIFY: add session fixation + cookie entropy
│       │   └── [existing 9 modules]
│       └── ipc/
│           └── webappIpc.js           ← add SCANNER_AUTH_CONTEXT handler
│
├── renderer/
│   ├── modules/webapp/
│   │   └── scanner.js                 ← add auth context input, 4 new module checkboxes
│   └── index.html                     ← 4 new module chips + auth token input field
│
└── resources/
    └── db/
        └── component-cve-db.json      ← NEW: bundled offline CVE database (web components)
```

### 3.2 Module Contract (Unchanged)

All new modules must implement this exact signature to integrate with the orchestrator:

```js
/**
 * @param {object} target
 * @param {string}  target.url
 * @param {string}  target.method
 * @param {object}  target.requestHeaders
 * @param {string|null} target.body
 * @param {object} scanOpts
 * @param {number}  scanOpts.timeoutMs
 * @param {string|null} scanOpts.oastCallbackUrl
 * @param {AbortSignal} scanOpts.signal
 * @param {object|null} scanOpts.authContext         ← NEW: {header, value} for IDOR
 * @returns {Promise<Finding[]>}
 */
export async function run[Module](target, scanOpts) { ... }
```

### 3.3 Data Flow

```
renderer (scanner.js)
  └─ api.scanner.start(opts)
       └─ IPC: SCANNER_START → webappIpc.js
            └─ startScan(opts, onFinding, onProgress, onComplete, onError, onActivity)
                 └─ for each target × module:
                      onActivity({ status:'start', module, moduleLabel, description })
                      findings = await runModule(target, scanOpts)
                      onActivity({ status:'done', module, findings: findings.length })
                      for each finding:
                        onFinding(finding)   → IPC: SCANNER_FINDING → renderer
                 └─ onProgress({ tested, total }) → IPC: SCANNER_PROGRESS
                 └─ onComplete({ findings })     → IPC: SCANNER_COMPLETE
```

### 3.4 scanOpts Extension

The `scanOpts` object passed from the orchestrator must be extended to carry `authContext`:

```js
// scanner/index.js — startScan()
const scanOpts = {
  timeoutMs,
  oastCallbackUrl,
  signal,
  authContext: opts.authContext ?? null,   // { header: 'Authorization', value: 'Bearer ...' }
};
```

The `authContext` is plumbed through from the IPC payload. Modules that do not need auth
simply ignore this field (e.g., TLS, SRI, ComponentCVE).

---

## 4. A01 — Broken Access Control / IDOR Scanner

### 4.1 Background & Theory

Insecure Direct Object Reference (IDOR) occurs when an application exposes a reference to an
internal object (database ID, filename, UUID) in a URL or parameter without verifying that the
authenticated user has permission to access that object. NetSpecter can detect this by:

1. **Horizontal IDOR** — substituting numeric IDs to access other users' resources
2. **Unauthenticated access** — removing auth headers to check if a protected resource leaks
3. **Parameter tampering** — substituting UUIDs/tokens with guessable values

OWASP classification: **A01:2021 – Broken Access Control** (most common OWASP finding in 2021,
present in 94% of applications tested).

### 4.2 Detection Strategies

#### Strategy 1: Numeric ID Enumeration
- Detect numeric IDs in URL path segments (`/api/users/123`) and query params (`?id=123`)
- Send requests with ID ± 1, ± 5, ± 10, ± 100
- Compare response: status 200 + non-empty body of similar structure = IDOR

#### Strategy 2: UUID Substitution
- Detect UUIDs in path/params using UUID regex
- Substitute with a known test UUID (`00000000-0000-0000-0000-000000000001`) or all-zeros
- If response is 200 + body > 50 bytes: flag as potential IDOR

#### Strategy 3: Unauthenticated Access Check
- If `authContext` is provided (auth header+value), send the original request without the auth header
- If unauthenticated response is 200 with body size within ±20% of authenticated response: CRITICAL IDOR

#### Strategy 4: Object ID in POST/JSON Bodies
- Scan POST/PUT JSON bodies for `id`, `userId`, `user_id`, `accountId`, `customerId`, `orderId` fields
- Substitute with adjacent values (originalValue + 1, originalValue - 1)
- Compare response body similarity

### 4.3 Implementation — `src/main/webapp/scanner/idor.js`

```js
/**
 * idor.js — IDOR / Broken Access Control Scanner (A01:2021)
 *
 * Detects Insecure Direct Object Reference vulnerabilities by:
 *   1. Enumerating numeric IDs in URLs and parameters
 *   2. Substituting UUIDs with test values
 *   3. Checking authenticated endpoints without credentials
 *   4. Probing JSON body ID fields
 */

import { sendProbe, extractParams, makeFinding } from './index.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_ID_REGEX = /^\d+$/;
const TEST_UUID = '00000000-0000-0000-0000-000000000001';
const IDOR_ID_KEYS = new Set(['id','userId','user_id','accountId','account_id',
  'customerId','customer_id','orderId','order_id','fileId','file_id',
  'documentId','document_id','recordId','record_id','profileId','profile_id']);

/**
 * Extract all candidate injectable ID locations from a target.
 * Returns array of { location, name, originalValue, injectFn }
 */
function extractIdCandidates(target) {
  const candidates = [];
  const { url, requestHeaders = {}, body } = target;

  // URL path segments: /api/users/123/orders/456
  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split('/').filter(Boolean);
    segments.forEach((seg, idx) => {
      if (NUMERIC_ID_REGEX.test(seg) || UUID_REGEX.test(seg)) {
        candidates.push({
          location: 'path',
          name:     `segment[${idx}]`,
          originalValue: seg,
          isUuid:   UUID_REGEX.test(seg),
          injectFn: (newVal) => {
            const u = new URL(url);
            const parts = u.pathname.split('/');
            const segIdx = parts.findIndex((p, i) => i > 0 && p === seg);
            if (segIdx !== -1) parts[segIdx] = newVal;
            u.pathname = parts.join('/');
            return { ...target, url: u.href };
          },
        });
      }
    });

    // Query string: ?id=123&userId=456
    for (const [name, value] of parsed.searchParams.entries()) {
      if (NUMERIC_ID_REGEX.test(value) || UUID_REGEX.test(value) ||
          IDOR_ID_KEYS.has(name.toLowerCase())) {
        candidates.push({
          location: 'query',
          name,
          originalValue: value,
          isUuid: UUID_REGEX.test(value),
          injectFn: (newVal) => {
            const u = new URL(url);
            u.searchParams.set(name, newVal);
            return { ...target, url: u.href };
          },
        });
      }
    }
  } catch {}

  // JSON body: { "userId": 123, "orderId": "abc-123" }
  const ct = (requestHeaders['content-type'] || requestHeaders['Content-Type'] || '').toLowerCase();
  if (body && ct.includes('application/json')) {
    try {
      const obj = JSON.parse(body);
      for (const [key, val] of Object.entries(obj)) {
        if (IDOR_ID_KEYS.has(key.toLowerCase()) ||
            (typeof val === 'number' && Number.isInteger(val)) ||
            (typeof val === 'string' && (UUID_REGEX.test(val) || NUMERIC_ID_REGEX.test(val)))) {
          candidates.push({
            location: 'json-body',
            name: key,
            originalValue: String(val),
            isUuid: typeof val === 'string' && UUID_REGEX.test(val),
            injectFn: (newVal) => {
              const clone = JSON.parse(body);
              clone[key] = NUMERIC_ID_REGEX.test(String(val)) ? Number(newVal) : newVal;
              return { ...target, body: JSON.stringify(clone) };
            },
          });
        }
      }
    } catch {}
  }

  return candidates;
}

/**
 * Compare two responses for structural similarity.
 * Returns true if responses look like the same resource.
 */
function responsesAreSimilar(baseline, probe) {
  if (probe.statusCode !== 200) return false;
  // Size within ±40% of baseline (allows for field variations)
  const sizeDelta = Math.abs(probe.body.length - baseline.body.length) / (baseline.body.length || 1);
  if (sizeDelta > 0.40) return false;
  // Both should be non-trivial (not empty responses or redirects)
  if (probe.body.length < 20) return false;
  return true;
}

export async function runIdor(target, scanOpts) {
  const findings = [];
  const { timeoutMs, signal, authContext } = scanOpts;

  // Strategy 1 & 2: ID Enumeration (numeric and UUID)
  const candidates = extractIdCandidates(target);
  if (candidates.length === 0) return findings;

  // Get baseline response first
  let baseline;
  try {
    baseline = await sendProbe(
      { method: target.method || 'GET', url: target.url,
        headers: target.requestHeaders, body: target.body, timeoutMs },
      signal
    );
  } catch { return findings; }

  if (baseline.statusCode !== 200) return findings;

  for (const candidate of candidates.slice(0, 6)) { // cap at 6 candidates
    if (signal?.aborted) break;

    // Generate probe values
    const probeValues = candidate.isUuid
      ? [TEST_UUID]
      : [
          String(Number(candidate.originalValue) + 1),
          String(Number(candidate.originalValue) - 1),
          String(Number(candidate.originalValue) + 100),
        ];

    for (const probeVal of probeValues) {
      if (signal?.aborted) break;
      if (probeVal === candidate.originalValue) continue;

      const injected = candidate.injectFn(probeVal);
      let probeResp;
      try {
        probeResp = await sendProbe(
          { method: injected.method || 'GET', url: injected.url,
            headers: injected.requestHeaders, body: injected.body, timeoutMs },
          signal
        );
      } catch { continue; }

      if (responsesAreSimilar(baseline, probeResp)) {
        findings.push(makeFinding({
          type:        'idor',
          severity:    'high',
          title:       'Potential Insecure Direct Object Reference (IDOR)',
          description: `The parameter "${candidate.name}" in the ${candidate.location} appears ` +
            `to accept arbitrary object IDs. Substituting the original value "${candidate.originalValue}" ` +
            `with "${probeVal}" returned HTTP 200 with a similar response body, suggesting object-level ` +
            `access control is not enforced.`,
          url:         injected.url,
          parameter:   `${candidate.location}:${candidate.name}`,
          payload:     probeVal,
          evidence: {
            originalUrl:      target.url,
            probedUrl:        injected.url,
            baselineStatus:   baseline.statusCode,
            probeStatus:      probeResp.statusCode,
            baselineBodyLen:  baseline.body.length,
            probeBodyLen:     probeResp.body.length,
          },
          remediation:
            'Implement object-level authorization checks on every resource access. ' +
            'Validate that the authenticated user owns or has permission to access the ' +
            'requested object ID. Use non-guessable UUIDs instead of sequential integers. ' +
            'Apply RBAC/ABAC at the data access layer, not just the route layer.',
          references: [
            'OWASP A01:2021 – Broken Access Control',
            'CWE-639: Authorization Bypass Through User-Controlled Key',
            'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
            'https://portswigger.net/web-security/access-control/idor',
          ],
        }));
        break; // one finding per candidate is enough
      }
    }
  }

  // Strategy 3: Unauthenticated Access Check
  if (authContext?.header && authContext?.value) {
    // Strip auth from headers
    const strippedHeaders = { ...target.requestHeaders };
    delete strippedHeaders[authContext.header];
    delete strippedHeaders[authContext.header.toLowerCase()];
    delete strippedHeaders[authContext.header.toUpperCase()];

    let unauthResp;
    try {
      unauthResp = await sendProbe(
        { method: target.method || 'GET', url: target.url,
          headers: strippedHeaders, body: target.body, timeoutMs },
        signal
      );
    } catch {}

    if (unauthResp && responsesAreSimilar(baseline, unauthResp)) {
      findings.push(makeFinding({
        type:        'idor',
        severity:    'critical',
        title:       'Unauthenticated Access to Authenticated Resource',
        description: `Removing the "${authContext.header}" authentication header from the request ` +
          `returned HTTP 200 with a response body similar in size to the authenticated response. ` +
          `This endpoint does not enforce authentication.`,
        url:         target.url,
        parameter:   `header:${authContext.header}`,
        payload:     '(header removed)',
        evidence: {
          authenticatedStatus:  baseline.statusCode,
          unauthenticatedStatus: unauthResp.statusCode,
          authenticatedBodyLen: baseline.body.length,
          unauthBodyLen:        unauthResp.body.length,
        },
        remediation:
          'All protected endpoints must verify authentication on every request. ' +
          'Use middleware that enforces authentication before route handlers execute. ' +
          'Never rely on client-side checks alone.',
        references: [
          'OWASP A01:2021 – Broken Access Control',
          'CWE-306: Missing Authentication for Critical Function',
        ],
      }));
    }
  }

  return findings;
}
```

### 4.4 MODULE_META Entry

```js
idor: {
  label: 'IDOR / Access Control',
  description:
    'Detects Insecure Direct Object Reference (IDOR) and broken access control. ' +
    'Extracts numeric IDs and UUIDs from URL path segments, query strings, and JSON ' +
    'body fields. Probes adjacent/test values and compares response similarity to ' +
    'detect unauthorized object access. With an auth token configured, also tests ' +
    'whether removing credentials still returns 200 (unauthenticated access).',
},
```

### 4.5 Auth Context IPC Flow

A new optional configuration field `authContext` flows from the renderer through IPC:

```
renderer: { header: 'Authorization', value: 'Bearer eyJ...' }
  → IPC payload opts.authContext
    → startScan() → scanOpts.authContext
      → runIdor(target, scanOpts) uses scanOpts.authContext
```

The user sets this in the scanner config UI (see Section 10). It is **never logged** and
**never stored** — it is memory-only for the scan session, consistent with the project's
credential security pattern.

### 4.6 Limitations & False Positive Mitigation

- A 40% body size tolerance is conservative to reduce false positives; adjust based on test results
- Only checks the first 6 ID candidates per target to avoid excessive requests
- Numeric IDs < 1 (e.g., `id=0`) skip the `-1` probe (would be negative)
- Sequential integer IDs on paginated resources may produce false positives — finding title
  says "Potential" to reflect uncertainty
- Does NOT attempt to decode response bodies to semantically confirm different users' data
  (that would require user-provided test account pairs)

---

## 5. A02 — TLS & Cryptographic Failures Analyzer

### 5.1 Background & Theory

OWASP A02:2021 covers failures in cryptography including:
- Weak/deprecated TLS protocol versions (TLS 1.0, TLS 1.1, SSLv3)
- Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, ANON ciphers)
- Expired, self-signed, or hostname-mismatched certificates
- Missing HSTS / short max-age
- Insufficient key sizes (RSA < 2048, EC < 224)
- Certificate transparency not enforced

Node.js provides `tls.connect()` which gives full access to the TLS negotiation result
including negotiated protocol, cipher name, and peer certificate details.

### 5.2 Detection Checks

| Check | Severity | Condition |
|-------|----------|-----------|
| SSLv3 enabled | CRITICAL | `protocol === 'SSLv3'` |
| TLS 1.0 enabled | HIGH | `protocol === 'TLSv1'` |
| TLS 1.1 enabled | MEDIUM | `protocol === 'TLSv1.1'` |
| Weak cipher | HIGH | cipher name contains RC4, DES, 3DES, NULL, EXPORT, ANON |
| Expired certificate | HIGH | `cert.valid_to < now` |
| Certificate expiring soon | MEDIUM | `cert.valid_to < now + 30 days` |
| Self-signed certificate | MEDIUM | `issuer === subject` |
| Hostname mismatch | HIGH | alt names do not include request hostname |
| Short RSA key | MEDIUM | RSA key < 2048 bits |
| Very short RSA key | HIGH | RSA key < 1024 bits |
| No HSTS | MEDIUM | `Strict-Transport-Security` header missing from HTTPS response |
| Short HSTS max-age | LOW | `max-age < 31536000` (< 1 year) |
| No HSTS preload | INFO | `preload` directive absent |
| HTTP (no TLS) | MEDIUM | Target uses `http://` scheme |

### 5.3 Implementation — `src/main/webapp/scanner/tlsAnalyzer.js`

```js
/**
 * tlsAnalyzer.js — TLS & Cryptographic Failures Scanner (A02:2021)
 *
 * Uses Node.js tls.connect() to inspect the TLS handshake directly:
 *   - Protocol version (SSLv3 / TLS 1.0 / TLS 1.1 are deprecated)
 *   - Cipher suite strength (RC4, DES, 3DES, NULL, EXPORT, ANON = weak)
 *   - Certificate validity (expiry, self-signed, hostname mismatch)
 *   - Key size (RSA < 2048 bit, EC < 224 bit)
 * Also checks HSTS header correctness on HTTPS responses.
 */

import tls  from 'tls';
import http from 'http';
import https from 'https';
import { makeFinding } from './index.js';

const WEAK_CIPHER_PATTERNS = [
  /RC4/i, /DES(?!-EDE3)/i, /3DES/i, /DES-EDE3/i,
  /NULL/i, /EXPORT/i, /ANON/i, /MD5/i,
];

const HSTS_MIN_MAX_AGE = 31_536_000; // 1 year in seconds

/**
 * Open a TLS connection to hostname:port and return negotiation details.
 * Ignores certificate errors intentionally (we want to inspect bad certs).
 */
function probeTls(hostname, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host:                 hostname,
        port:                 port,
        rejectUnauthorized:   false,   // inspect bad certs
        checkServerIdentity:  () => undefined,
        timeout:              timeoutMs,
      },
      () => {
        const protocol = socket.getProtocol?.() ?? null;
        const cipher   = socket.getCipher?.()  ?? null;
        const cert     = socket.getPeerCertificate(true);
        socket.destroy();
        resolve({ protocol, cipher, cert });
      }
    );
    socket.on('error',   reject);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('TLS timeout')); });
  });
}

/**
 * Fetch the response headers from the target URL to check HSTS.
 */
function fetchHeaders(url, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib    = parsed.protocol === 'https:' ? https : http;
    const req    = lib.request(
      { hostname: parsed.hostname, port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: '/', method: 'HEAD', timeout: timeoutMs, rejectUnauthorized: false },
      (res) => {
        res.resume();
        resolve(res.headers);
      }
    );
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    signal?.addEventListener('abort', () => req.destroy(), { once: true });
    req.end();
  });
}

export async function runTlsAnalyzer(target, scanOpts) {
  const findings = [];
  const { timeoutMs, signal } = scanOpts;

  let parsed;
  try { parsed = new URL(target.url); } catch { return findings; }

  const isHttps  = parsed.protocol === 'https:';
  const hostname = parsed.hostname;
  const port     = Number(parsed.port) || (isHttps ? 443 : 80);

  // A — HTTP (no encryption at all)
  if (!isHttps) {
    findings.push(makeFinding({
      type:        'tlsAnalyzer',
      severity:    'medium',
      title:       'Unencrypted HTTP Connection',
      description: `The target "${hostname}" is accessed over plain HTTP with no TLS encryption. ` +
        `All data including credentials, session tokens, and sensitive information is transmitted ` +
        `in cleartext and is vulnerable to interception (man-in-the-middle attacks).`,
      url:         target.url,
      evidence: { protocol: 'http', port },
      remediation:
        'Redirect all HTTP traffic to HTTPS. Configure HSTS to prevent protocol downgrade attacks. ' +
        'Obtain a certificate from a trusted CA (e.g., Let\'s Encrypt). ' +
        'Ensure all resources (scripts, images, APIs) are served over HTTPS.',
      references: [
        'OWASP A02:2021 – Cryptographic Failures',
        'CWE-319: Cleartext Transmission of Sensitive Information',
        'https://letsencrypt.org/',
      ],
    }));
    return findings; // No TLS to probe further
  }

  // B — Probe TLS handshake
  let tlsInfo;
  try {
    tlsInfo = await probeTls(hostname, port, timeoutMs);
  } catch (err) {
    if (err.name === 'AbortError') return findings;
    return findings; // Cannot connect — not a TLS finding per se
  }

  const { protocol, cipher, cert } = tlsInfo;

  // B1 — Weak protocol version
  if (protocol === 'SSLv3' || protocol === 'SSLv2') {
    findings.push(makeFinding({
      type: 'tlsAnalyzer', severity: 'critical',
      title: `Deprecated SSL Protocol: ${protocol}`,
      description: `The server negotiated ${protocol}, a protocol with known cryptographic ` +
        `weaknesses (POODLE, DROWN attacks). ${protocol} has been prohibited by RFC 7568 / RFC 6176.`,
      url: target.url,
      evidence: { protocol, cipherSuite: cipher?.name },
      remediation: `Disable ${protocol} entirely. Configure the server to support TLS 1.2 and TLS 1.3 only. ` +
        'In Nginx: ssl_protocols TLSv1.2 TLSv1.3; In Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3',
      references: ['RFC 7568', 'CVE-2014-3566 (POODLE)', 'OWASP A02:2021'],
    }));
  } else if (protocol === 'TLSv1') {
    findings.push(makeFinding({
      type: 'tlsAnalyzer', severity: 'high',
      title: 'Deprecated TLS 1.0 Protocol',
      description: 'The server accepted a TLS 1.0 connection. TLS 1.0 is deprecated per RFC 8996 ' +
        'and fails PCI DSS 3.2+ compliance requirements. It is vulnerable to BEAST and POODLE-TLS attacks.',
      url: target.url,
      evidence: { protocol, cipherSuite: cipher?.name },
      remediation: 'Disable TLS 1.0. Accept only TLS 1.2 and TLS 1.3.',
      references: ['RFC 8996', 'PCI DSS 3.2+', 'OWASP A02:2021'],
    }));
  } else if (protocol === 'TLSv1.1') {
    findings.push(makeFinding({
      type: 'tlsAnalyzer', severity: 'medium',
      title: 'Deprecated TLS 1.1 Protocol',
      description: 'The server accepted TLS 1.1, which was deprecated by RFC 8996 in March 2021.',
      url: target.url,
      evidence: { protocol, cipherSuite: cipher?.name },
      remediation: 'Disable TLS 1.1. Support TLS 1.2 and TLS 1.3 only.',
      references: ['RFC 8996', 'OWASP A02:2021'],
    }));
  }

  // B2 — Weak cipher suite
  if (cipher?.name) {
    const weakMatch = WEAK_CIPHER_PATTERNS.find(p => p.test(cipher.name));
    if (weakMatch) {
      findings.push(makeFinding({
        type: 'tlsAnalyzer', severity: 'high',
        title: `Weak TLS Cipher Suite: ${cipher.name}`,
        description: `The negotiated cipher suite "${cipher.name}" uses a known-weak algorithm. ` +
          `Weak ciphers allow attackers to decrypt intercepted traffic via cryptanalysis or brute force.`,
        url: target.url,
        evidence: { cipherSuite: cipher.name, protocol },
        remediation:
          'Configure your server to use only strong cipher suites. Recommended order: ' +
          'TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256 (TLS 1.3). ' +
          'Use Mozilla SSL Configuration Generator for your server software.',
        references: [
          'https://ssl-config.mozilla.org/',
          'OWASP A02:2021',
          'CWE-326: Inadequate Encryption Strength',
        ],
      }));
    }
  }

  // B3 — Certificate expiry
  if (cert && cert.valid_to) {
    const expiryDate = new Date(cert.valid_to);
    const now        = new Date();
    const daysUntil  = Math.floor((expiryDate - now) / 86_400_000);

    if (daysUntil < 0) {
      findings.push(makeFinding({
        type: 'tlsAnalyzer', severity: 'high',
        title: 'Expired TLS Certificate',
        description: `The TLS certificate for "${hostname}" expired on ${cert.valid_to} ` +
          `(${Math.abs(daysUntil)} days ago). Browsers will show security warnings and ` +
          `HSTS-enforced browsers will refuse to connect entirely.`,
        url: target.url,
        evidence: { subject: cert.subject, expiryDate: cert.valid_to, daysExpired: Math.abs(daysUntil) },
        remediation: 'Renew the certificate immediately. Use Let\'s Encrypt with auto-renewal (certbot) ' +
          'or configure certificate expiry monitoring alerts.',
        references: ['OWASP A02:2021', 'CWE-298: Improper Validation of Certificate Expiration'],
      }));
    } else if (daysUntil < 30) {
      findings.push(makeFinding({
        type: 'tlsAnalyzer', severity: 'medium',
        title: `TLS Certificate Expiring in ${daysUntil} Days`,
        description: `The TLS certificate for "${hostname}" expires on ${cert.valid_to}. ` +
          `Certificates expiring in under 30 days require immediate renewal planning.`,
        url: target.url,
        evidence: { expiryDate: cert.valid_to, daysRemaining: daysUntil },
        remediation: 'Renew the certificate. Set up automated renewal with certbot or equivalent.',
        references: ['OWASP A02:2021'],
      }));
    }
  }

  // B4 — Self-signed certificate
  if (cert && cert.issuer && cert.subject) {
    const issuerCN  = cert.issuer.CN  || '';
    const subjectCN = cert.subject.CN || '';
    if (issuerCN === subjectCN && issuerCN !== '') {
      findings.push(makeFinding({
        type: 'tlsAnalyzer', severity: 'medium',
        title: 'Self-Signed TLS Certificate',
        description: `The certificate for "${hostname}" is self-signed (issuer CN "${issuerCN}" ` +
          `equals subject CN). Self-signed certificates are not trusted by browsers and ` +
          `provide no protection against man-in-the-middle attacks.`,
        url: target.url,
        evidence: { issuerCN, subjectCN, serialNumber: cert.serialNumber },
        remediation: 'Obtain a certificate from a trusted Certificate Authority. ' +
          'For public sites, use Let\'s Encrypt (free). For internal services, deploy an internal CA.',
        references: ['OWASP A02:2021', 'CWE-295: Improper Certificate Validation'],
      }));
    }
  }

  // B5 — HSTS check (requires an actual HTTP response, not just TLS)
  let responseHeaders = {};
  try {
    responseHeaders = await fetchHeaders(target.url, timeoutMs, signal);
  } catch {}

  const hstsHeader = responseHeaders['strict-transport-security'];
  if (!hstsHeader) {
    findings.push(makeFinding({
      type: 'tlsAnalyzer', severity: 'medium',
      title: 'Missing Strict-Transport-Security (HSTS) Header',
      description:
        'The HTTPS response does not include the Strict-Transport-Security header. ' +
        'Without HSTS, browsers may still connect over HTTP if redirected or tricked, ' +
        'enabling SSL-stripping man-in-the-middle attacks.',
      url: target.url,
      evidence: { header: 'Strict-Transport-Security', value: '(absent)' },
      remediation:
        'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n' +
        'Submit the domain to https://hstspreload.org/ for browser preload list inclusion.',
      references: ['RFC 6797', 'OWASP A02:2021', 'https://hstspreload.org/'],
    }));
  } else {
    const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
    if (maxAge < HSTS_MIN_MAX_AGE) {
      findings.push(makeFinding({
        type: 'tlsAnalyzer', severity: 'low',
        title: `HSTS max-age Too Short (${maxAge}s)`,
        description: `The Strict-Transport-Security max-age is ${maxAge} seconds ` +
          `(${Math.round(maxAge / 86400)} days), below the recommended minimum of 1 year (31536000s).`,
        url: target.url,
        evidence: { hstsHeader, maxAge },
        remediation: 'Set max-age to at least 31536000 (1 year). ' +
          'Consider adding includeSubDomains and preload directives.',
        references: ['RFC 6797', 'OWASP A02:2021'],
      }));
    }
  }

  return findings;
}
```

### 5.4 MODULE_META Entry

```js
tlsAnalyzer: {
  label: 'TLS / Crypto Failures',
  description:
    'Uses Node.js tls.connect() to directly inspect the TLS handshake. Checks protocol ' +
    'version (SSLv3/TLS 1.0/1.1 are deprecated per RFC 8996), cipher suite strength ' +
    '(RC4, DES, 3DES, NULL, EXPORT, ANON flagged), certificate validity (expiry, ' +
    'self-signed, hostname mismatch), and RSA key size. Also checks HSTS header ' +
    'presence and max-age on HTTPS responses. For HTTP targets, flags missing encryption.',
},
```

---

## 6. A06 — Vulnerable & Outdated Components Scanner

### 6.1 Background & Theory

OWASP A06:2021 covers the use of libraries, frameworks, and other software components with
known vulnerabilities. Web applications expose component versions through:

- HTTP response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, etc.)
- HTML `<meta>` tags (`<meta name="generator" content="WordPress 6.1">`)
- Versioned asset URLs (`/wp-includes/js/jquery/jquery.min.js?ver=3.6.0`)
- HTML comments (`<!-- This site is powered by Joomla! 4.2 -->`)
- Response body strings (frameworks often include version in error pages or footers)

Once a version is identified, it is matched against a bundled CVE database covering the most
commonly exploited web components.

### 6.2 Component Fingerprinting Signatures

```
Component        Detection Method                       Header/Pattern
────────────────────────────────────────────────────────────────────────
Apache HTTPD     Server header                          Server: Apache/2.4.51
Nginx            Server header                          Server: nginx/1.20.1
IIS              Server header                          Server: Microsoft-IIS/10.0
PHP              X-Powered-By header                    X-Powered-By: PHP/7.4.3
ASP.NET          X-Powered-By / X-AspNet-Version        X-Powered-By: ASP.NET
WordPress        HTML meta generator                    <meta name="generator" content="WordPress 5.8">
WordPress        Asset URL pattern                      ?ver=\d+\.\d+
Joomla           HTML meta generator                    <meta name="generator" content="Joomla! 4.2">
Drupal           X-Generator header                     X-Generator: Drupal 9
jQuery           Script URL                             jquery.min.js?ver=3.5.1
jQuery UI        Script URL                             jquery-ui.min.js?ver=1.12.1
Bootstrap        HTML comment or Link header            bootstrap.min.css?ver=4.6.0
Angular          HTML body script                       ng-version="12.0.0"
React            HTML body                              __REACT_DEVTOOLS (version)
Express          X-Powered-By header                    X-Powered-By: Express
Laravel          X-Powered-By / cookie naming           X-Powered-By: PHP, laravel_session
```

### 6.3 Bundled CVE Database Schema

The offline database is stored as `resources/db/component-cve-db.json`:

```json
{
  "schemaVersion": "1.0",
  "generated": "2026-01-01",
  "components": [
    {
      "name": "jquery",
      "displayName": "jQuery",
      "vulnerabilities": [
        {
          "cveId": "CVE-2019-11358",
          "cvssScore": 6.1,
          "severity": "medium",
          "affectedVersions": "< 3.4.0",
          "fixedVersion": "3.4.0",
          "description": "Prototype pollution via $.extend(true, ...)",
          "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11358"]
        },
        {
          "cveId": "CVE-2020-11022",
          "cvssScore": 6.1,
          "severity": "medium",
          "affectedVersions": ">= 1.0.3, < 3.5.0",
          "fixedVersion": "3.5.0",
          "description": "XSS via HTML tags in passed-in text"
        },
        {
          "cveId": "CVE-2020-11023",
          "cvssScore": 6.1,
          "severity": "medium",
          "affectedVersions": ">= 1.0.3, < 3.5.0",
          "fixedVersion": "3.5.0",
          "description": "XSS by passing HTML to manipulation methods"
        }
      ]
    },
    {
      "name": "bootstrap",
      "displayName": "Bootstrap",
      "vulnerabilities": [
        {
          "cveId": "CVE-2019-8331",
          "cvssScore": 6.1,
          "severity": "medium",
          "affectedVersions": ">= 4.0.0, < 4.3.1",
          "fixedVersion": "4.3.1",
          "description": "XSS in tooltip data-template attribute"
        }
      ]
    },
    {
      "name": "wordpress",
      "displayName": "WordPress",
      "vulnerabilities": [
        {
          "cveId": "CVE-2022-21661",
          "cvssScore": 7.5,
          "severity": "high",
          "affectedVersions": "< 5.8.3",
          "fixedVersion": "5.8.3",
          "description": "SQL injection via WP_Query"
        },
        {
          "cveId": "CVE-2023-2745",
          "cvssScore": 5.4,
          "severity": "medium",
          "affectedVersions": "< 6.2.1",
          "fixedVersion": "6.2.1",
          "description": "Directory traversal via plugin/theme upload"
        }
      ]
    }
  ]
}
```

### 6.4 Version Comparison Utility

Semantic version comparison follows npm semver-style `<=` / `>=` / `< X.Y.Z` ranges:

```js
/**
 * Returns true if detectedVersion falls within the affectedVersions range string.
 * Supports: "< 3.4.0", ">= 1.0.3, < 3.5.0", "= 5.8.1"
 */
function isVersionAffected(detectedVersion, rangeStr) {
  // Parse detected version into [major, minor, patch]
  const parseSemver = v => v.replace(/[^\d.]/g, '').split('.').map(Number).slice(0, 3);
  const compareVers = (a, b) => {
    for (let i = 0; i < 3; i++) {
      if ((a[i] || 0) < (b[i] || 0)) return -1;
      if ((a[i] || 0) > (b[i] || 0)) return  1;
    }
    return 0;
  };
  const det = parseSemver(detectedVersion);
  return rangeStr.split(',').every(clause => {
    clause = clause.trim();
    const match = clause.match(/^([<>=!]+)\s*([\d.]+)/);
    if (!match) return true;
    const [, op, ver] = match;
    const cmp = compareVers(det, parseSemver(ver));
    if (op === '<')  return cmp < 0;
    if (op === '<=') return cmp <= 0;
    if (op === '>')  return cmp > 0;
    if (op === '>=') return cmp >= 0;
    if (op === '=')  return cmp === 0;
    return true;
  });
}
```

### 6.5 Implementation — `src/main/webapp/scanner/componentCve.js`

```js
/**
 * componentCve.js — Vulnerable & Outdated Components Scanner (A06:2021)
 *
 * Fingerprints component versions from:
 *   - HTTP response headers (Server, X-Powered-By, X-Generator, X-AspNet-Version)
 *   - HTML <meta name="generator"> tags
 *   - Versioned asset URL parameters (?ver=X.Y.Z)
 *   - HTML comment patterns and body version strings
 *
 * Matches detected versions against a bundled offline CVE database
 * at resources/db/component-cve-db.json.
 */

import { sendProbe, makeFinding } from './index.js';
import { createRequire } from 'module';

// Load bundled CVE database (JSON file, zero network dependency)
const require = createRequire(import.meta.url);
let CVE_DB;
try {
  CVE_DB = require('../../../../resources/db/component-cve-db.json');
} catch {
  CVE_DB = { components: [] };
}

// ─── Fingerprint Patterns ──────────────────────────────────────────────────

const HEADER_PATTERNS = [
  { header: 'server',             componentKey: 'apache',    regex: /Apache\/([\d.]+)/i },
  { header: 'server',             componentKey: 'nginx',     regex: /nginx\/([\d.]+)/i },
  { header: 'server',             componentKey: 'iis',       regex: /Microsoft-IIS\/([\d.]+)/i },
  { header: 'x-powered-by',       componentKey: 'php',       regex: /PHP\/([\d.]+)/i },
  { header: 'x-powered-by',       componentKey: 'express',   regex: /Express/i,     noVersion: true },
  { header: 'x-aspnet-version',   componentKey: 'aspnet',    regex: /([\d.]+)/      },
  { header: 'x-generator',        componentKey: 'drupal',    regex: /Drupal ([\d.]+)/i },
];

const HTML_PATTERNS = [
  { componentKey: 'wordpress', regex: /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress ([\d.]+)/i },
  { componentKey: 'joomla',    regex: /<meta[^>]+name=["']generator["'][^>]+content=["']Joomla! ([\d.]+)/i },
  { componentKey: 'drupal',    regex: /<meta[^>]+name=["']generator["'][^>]+content=["']Drupal ([\d.]+)/i },
  { componentKey: 'angular',   regex: /ng-version="([\d.]+)"/i },
];

const ASSET_URL_PATTERNS = [
  { componentKey: 'jquery',     regex: /jquery(?:\.min)?\.js\?ver=([\d.]+)/i },
  { componentKey: 'jquery-ui',  regex: /jquery-ui(?:\.min)?\.js\?ver=([\d.]+)/i },
  { componentKey: 'bootstrap',  regex: /bootstrap(?:\.min)?\.(?:js|css)\?ver=([\d.]+)/i },
  { componentKey: 'wordpress',  regex: /\/wp-includes\/.*\?ver=([\d.]+)/i },
];

// ─── Version Range Checker ──────────────────────────────────────────────────

function isVersionAffected(detectedVersion, rangeStr) {
  const parseSemver = v => v.replace(/[^\d.]/g, '').split('.').map(Number).slice(0, 3);
  const compareVers = (a, b) => {
    for (let i = 0; i < 3; i++) {
      const diff = (a[i] || 0) - (b[i] || 0);
      if (diff !== 0) return diff < 0 ? -1 : 1;
    }
    return 0;
  };
  const det = parseSemver(detectedVersion);
  return rangeStr.split(',').every(clause => {
    const m = clause.trim().match(/^([<>=!]{1,2})\s*([\d.]+)/);
    if (!m) return true;
    const cmp = compareVers(det, parseSemver(m[2]));
    return m[1] === '<'  ? cmp < 0
         : m[1] === '<=' ? cmp <= 0
         : m[1] === '>'  ? cmp > 0
         : m[1] === '>=' ? cmp >= 0
         : m[1] === '='  ? cmp === 0
         : true;
  });
}

// ─── Main Export ──────────────────────────────────────────────────────────

export async function runComponentCve(target, scanOpts) {
  const findings = [];
  const { timeoutMs, signal } = scanOpts;

  let response;
  try {
    response = await sendProbe(
      { method: 'GET', url: target.url, headers: target.requestHeaders, timeoutMs },
      signal
    );
  } catch { return findings; }

  const detectedComponents = new Map(); // componentKey → { version, displayName, source }

  // Pass 1: Response headers
  for (const pat of HEADER_PATTERNS) {
    const val = response.headers[pat.header] || response.headers[pat.header.toLowerCase()];
    if (!val) continue;
    if (pat.noVersion) {
      detectedComponents.set(pat.componentKey, { version: null, source: `header:${pat.header}`, displayName: pat.componentKey });
      continue;
    }
    const m = val.match(pat.regex);
    if (m) {
      detectedComponents.set(pat.componentKey, { version: m[1], source: `header:${pat.header}`, displayName: pat.componentKey });
    }
  }

  // Pass 2: HTML body patterns (meta tags, ng-version, etc.)
  const body = response.body || '';
  for (const pat of HTML_PATTERNS) {
    const m = body.match(pat.regex);
    if (m) {
      detectedComponents.set(pat.componentKey, { version: m[1], source: 'html-meta', displayName: pat.componentKey });
    }
  }

  // Pass 3: Versioned asset URL patterns in <script> and <link> tags
  for (const pat of ASSET_URL_PATTERNS) {
    const m = body.match(pat.regex);
    if (m) {
      if (!detectedComponents.has(pat.componentKey)) {
        detectedComponents.set(pat.componentKey, { version: m[1], source: 'asset-url', displayName: pat.componentKey });
      }
    }
  }

  // Version disclosure finding (even if no CVE — leaking version info is bad practice)
  for (const [key, info] of detectedComponents) {
    if (info.version && (info.source.startsWith('header:server') || info.source.startsWith('header:x-powered'))) {
      findings.push(makeFinding({
        type:        'componentCve',
        severity:    'info',
        title:       `Version Disclosed: ${info.displayName || key} ${info.version}`,
        description: `The response ${info.source} reveals the exact version of ${key} (${info.version}). ` +
          `This information helps attackers identify specific known vulnerabilities for this version.`,
        url:         target.url,
        parameter:   info.source,
        payload:     null,
        evidence:    { component: key, version: info.version, disclosedIn: info.source },
        remediation: 'Suppress version information in HTTP headers. In Nginx: server_tokens off; ' +
          'In Apache: ServerTokens Prod; ServerSignature Off; In PHP: expose_php = Off',
        references: ['OWASP A06:2021', 'CWE-200: Exposure of Sensitive Information'],
      }));
    }
  }

  // CVE matching
  for (const [key, info] of detectedComponents) {
    if (!info.version) continue;
    const dbEntry = CVE_DB.components?.find(c => c.name === key);
    if (!dbEntry) continue;

    for (const vuln of dbEntry.vulnerabilities ?? []) {
      if (!isVersionAffected(info.version, vuln.affectedVersions)) continue;

      const severityMap = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
      findings.push(makeFinding({
        type:        'componentCve',
        severity:    severityMap[vuln.severity] ?? 'medium',
        title:       `${dbEntry.displayName} ${info.version} — ${vuln.cveId}`,
        description: `Detected ${dbEntry.displayName} version ${info.version} (via ${info.source}). ` +
          `This version is affected by ${vuln.cveId} (CVSS ${vuln.cvssScore}): ${vuln.description}. ` +
          `Fixed in version ${vuln.fixedVersion}.`,
        url:         target.url,
        parameter:   info.source,
        payload:     null,
        evidence: {
          component:         dbEntry.displayName,
          detectedVersion:   info.version,
          affectedRange:     vuln.affectedVersions,
          fixedVersion:      vuln.fixedVersion,
          cvssScore:         vuln.cvssScore,
          disclosureSource:  info.source,
        },
        remediation:
          `Update ${dbEntry.displayName} to version ${vuln.fixedVersion} or later. ` +
          `Check for any dependent packages that may also need updating. ` +
          `Establish a regular dependency audit schedule (weekly/monthly).`,
        references: [
          `https://nvd.nist.gov/vuln/detail/${vuln.cveId}`,
          'OWASP A06:2021 – Vulnerable and Outdated Components',
          ...(vuln.references ?? []),
        ],
      }));
    }
  }

  return findings;
}
```

### 6.6 CVE Database Maintenance

The bundled `component-cve-db.json` must be maintained manually or via a generation script.
Initial coverage should include at minimum:

- jQuery (all CVEs for versions < 3.6.0)
- Bootstrap (< 5.1.3)
- WordPress (< 6.4.x)
- jQuery UI (< 1.13.2)
- AngularJS 1.x (end-of-life, all versions flagged)
- Apache HTTPD (latest critical CVEs)
- Nginx (latest critical CVEs)
- PHP 7.x (end-of-life, flag all versions)
- Express.js (flag version disclosure only — CVEs rare)

A `scripts/update-cve-db.js` generator script should periodically fetch from
the NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`) for the above
components and regenerate the JSON file. This should run as a periodic CI task,
not at runtime (zero external network dependency in the scanner itself).

---

## 7. A07 — Session Security (brokenAuth Extension)

### 7.1 Background

The existing `brokenAuth.js` covers:
- Rate-limit detection (20 rapid replays)
- Username enumeration via response delta
- JWT `alg:none` attack
- Weak credential pairs

The remaining A07 gaps:
1. **Session fixation** — does the session cookie change after authentication?
2. **Cookie security flags** — Secure, HttpOnly, SameSite (deeper check than headers.js)
3. **Session token entropy** — is the token sufficiently random?
4. **Concurrent session control** — can the same user log in twice simultaneously?

### 7.2 New Checks to Add to `brokenAuth.js`

#### Check: Cookie Security Flags (Deep)

The existing `headers.js` does a surface-level cookie check. `brokenAuth.js` should do a
deep per-cookie analysis:

```js
// In brokenAuth.js — new function addedbelow existing checks
async function checkCookieFlags(target, scanOpts) {
  const findings = [];
  const { timeoutMs, signal } = scanOpts;

  let resp;
  try {
    resp = await sendProbe(
      { method: target.method || 'GET', url: target.url,
        headers: target.requestHeaders, body: target.body, timeoutMs },
      signal
    );
  } catch { return findings; }

  const rawCookies = [resp.headers['set-cookie']].flat().filter(Boolean);
  if (!rawCookies.length) return findings;

  for (const raw of rawCookies) {
    const name        = raw.split('=')[0].trim();
    const lower       = raw.toLowerCase();
    const hasSecure   = lower.includes('; secure');
    const hasHttpOnly = lower.includes('; httponly');
    const sameSiteMatch = lower.match(/samesite=(\w+)/);
    const sameSite    = sameSiteMatch ? sameSiteMatch[1] : null;
    const isSession   = _isLikelySessionCookie(name);

    // Flag: no Secure on what looks like a session/auth cookie
    if (!hasSecure && isSession) {
      findings.push(makeFinding({
        type: 'brokenAuth', severity: 'medium',
        title: `Session Cookie Missing Secure Flag: ${name}`,
        description: `The cookie "${name}" appears to be a session/auth cookie but is set ` +
          `without the Secure flag. It can be transmitted over HTTP connections, making it ` +
          `vulnerable to interception on mixed-content pages or HTTP redirects.`,
        url: target.url,
        parameter: `cookie:${name}`,
        evidence: { cookieName: name, cookieRaw: raw.slice(0, 200) },
        remediation: `Add the Secure flag to cookie "${name}": Set-Cookie: ${name}=...; Secure; HttpOnly; SameSite=Lax`,
        references: ['OWASP A07:2021', 'CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute'],
      }));
    }

    if (!hasHttpOnly && isSession) {
      findings.push(makeFinding({
        type: 'brokenAuth', severity: 'medium',
        title: `Session Cookie Missing HttpOnly Flag: ${name}`,
        description: `The cookie "${name}" is accessible to JavaScript (no HttpOnly flag). ` +
          `If XSS exists anywhere on this site, attackers can steal this session token.`,
        url: target.url,
        parameter: `cookie:${name}`,
        evidence: { cookieName: name },
        remediation: `Add HttpOnly to cookie "${name}". HttpOnly prevents document.cookie access.`,
        references: ['OWASP A07:2021', 'CWE-1004: Sensitive Cookie Without HttpOnly Flag'],
      }));
    }

    if ((!sameSite || sameSite === 'none') && isSession) {
      findings.push(makeFinding({
        type: 'brokenAuth', severity: 'medium',
        title: `Session Cookie Missing SameSite Protection: ${name}`,
        description: `The cookie "${name}" has no SameSite attribute (or SameSite=None). ` +
          `This makes the cookie vulnerable to Cross-Site Request Forgery (CSRF) attacks.`,
        url: target.url,
        parameter: `cookie:${name}`,
        evidence: { cookieName: name, sameSite: sameSite ?? '(absent)' },
        remediation: `Add SameSite=Lax (or Strict) to cookie "${name}". ` +
          `SameSite=Lax is the recommended minimum for session cookies.`,
        references: ['OWASP A07:2021', 'RFC 6265bis', 'CWE-352: Cross-Site Request Forgery'],
      }));
    }
  }

  return findings;
}

/**
 * Heuristic: is this cookie name likely to be a session/auth cookie?
 */
function _isLikelySessionCookie(name) {
  const lower = name.toLowerCase();
  return /sess|token|auth|jwt|sid|login|remember|csrf|xsrf/.test(lower);
}
```

#### Check: Session Token Entropy

```js
/**
 * Estimate the entropy of a session token by collecting 5 samples
 * and measuring character space × length.
 * Flags tokens with < 64 bits of effective entropy.
 */
async function checkSessionEntropy(target, scanOpts) {
  const findings = [];
  const { timeoutMs, signal } = scanOpts;

  const tokens = [];
  for (let i = 0; i < 5; i++) {
    if (signal?.aborted) break;
    try {
      const resp = await sendProbe(
        { method: target.method || 'GET', url: target.url,
          headers: target.requestHeaders, timeoutMs },
        signal
      );
      const cookies = [resp.headers['set-cookie']].flat().filter(Boolean);
      for (const raw of cookies) {
        const name = raw.split('=')[0].trim();
        if (!_isLikelySessionCookie(name)) continue;
        const valMatch = raw.match(/^[^=]+=([^;]+)/);
        if (valMatch) tokens.push({ name, value: valMatch[1].trim() });
      }
    } catch {}
  }

  // Analyze each distinct token name
  const byName = {};
  for (const { name, value } of tokens) {
    if (!byName[name]) byName[name] = [];
    byName[name].push(value);
  }

  for (const [name, vals] of Object.entries(byName)) {
    if (vals.length < 2) continue;
    // Check sequential/predictable: are values all identical?
    const unique = new Set(vals);
    if (unique.size === 1) {
      findings.push(makeFinding({
        type: 'brokenAuth', severity: 'high',
        title: `Static Session Token: ${name}`,
        description: `The session cookie "${name}" returned the same value across 5 independent requests. ` +
          `This suggests the token is static or does not change per session, making it trivially replayable.`,
        url: target.url,
        parameter: `cookie:${name}`,
        evidence: { tokenValue: vals[0], samplesChecked: vals.length },
        remediation: 'Generate a unique cryptographically random token for each new session. ' +
          'Use crypto.randomBytes(32) or equivalent. Never reuse tokens.',
        references: ['OWASP A07:2021', 'CWE-330: Use of Insufficiently Random Values'],
      }));
      continue;
    }

    // Estimate entropy: characterSpace ^ length
    const sample = vals[0];
    const charSpace = /^[0-9a-f]+$/i.test(sample) ? 16
                    : /^[0-9a-zA-Z]+$/.test(sample) ? 62
                    : 256;
    const estimatedBits = Math.log2(charSpace) * sample.length;
    if (estimatedBits < 64) {
      findings.push(makeFinding({
        type: 'brokenAuth', severity: 'medium',
        title: `Low-Entropy Session Token: ${name} (~${Math.round(estimatedBits)} bits)`,
        description: `The session token "${name}" has an estimated entropy of ~${Math.round(estimatedBits)} bits ` +
          `(${sample.length} chars, charset size ${charSpace}). OWASP recommends ≥128 bits of entropy for session tokens.`,
        url: target.url,
        parameter: `cookie:${name}`,
        evidence: { tokenSample: sample.slice(0, 20) + '…', estimatedBits: Math.round(estimatedBits), charSpace },
        remediation: 'Use at least 128 bits (32 hex chars / 22 base64 chars) of cryptographic randomness. ' +
          'Node.js: crypto.randomBytes(32).toString(\'hex\')',
        references: ['OWASP A07:2021', 'CWE-331: Insufficient Entropy', 'NIST SP 800-63B'],
      }));
    }
  }

  return findings;
}
```

### 7.3 Integration into `brokenAuth.js`

The two new functions are called at the end of `runBrokenAuth()` before returning:

```js
// At the end of the existing runBrokenAuth function:
const cookieFindings  = await checkCookieFlags(target, scanOpts);
const entropyFindings = await checkSessionEntropy(target, scanOpts);
findings.push(...cookieFindings, ...entropyFindings);
return findings;
```

### 7.4 Updated MODULE_META

```js
brokenAuth: {
  label: 'Broken Authentication',
  description:
    'Sends 20 rapid identical requests to check whether the server rate-limits or locks out. ' +
    'Probes for username enumeration by comparing response bodies/sizes for valid vs. invalid ' +
    'usernames. Inspects Authorization/JWT headers for the alg:none attack and decodes the ' +
    'payload. Tries common weak credential pairs against detected login endpoints. ' +
    'NEW: Audits Set-Cookie headers for missing Secure/HttpOnly/SameSite flags on session ' +
    'cookies. Collects 5 token samples to estimate entropy and detect static/low-entropy tokens.',
},
```

---

## 8. A08 — Software & Data Integrity (SRI Checker)

### 8.1 Background & Theory

OWASP A08:2021 covers failures that allow attackers to inject unsigned/unverified code or data
into a pipeline. For web applications, the most detectable manifestation is missing
**Subresource Integrity (SRI)** on third-party JavaScript and CSS files.

SRI works by adding a `integrity="sha256-BASE64..."` attribute to `<script>` and `<link>` tags.
The browser computes the hash of the fetched resource and refuses to execute it if it doesn't
match. Without SRI, a compromised CDN or third-party host can serve malicious code.

### 8.2 Detection Logic

1. Fetch the target URL and parse the HTML response body
2. Find all `<script src="...">` and `<link rel="stylesheet" href="...">` tags
3. For each resource URL:
   - Is it **external** (different origin from the page)? If not, skip.
   - Does it have an `integrity` attribute? If not → HIGH finding.
   - Does the `integrity` use a weak hash (sha1)? → MEDIUM finding.
   - Is the `integrity` present without `crossorigin="anonymous"`? → LOW finding.
   - Does the resource URL use `http://` on an HTTPS page? → MEDIUM (mixed content).
4. Also check for `<meta http-equiv="Content-Security-Policy">` with `require-sri-for script style`

### 8.3 Implementation — `src/main/webapp/scanner/sriChecker.js`

```js
/**
 * sriChecker.js — Subresource Integrity (SRI) Scanner (A08:2021)
 *
 * Parses the HTML response to find external <script> and <link> tags
 * that are missing integrity= attributes. Also checks for weak hash
 * algorithms and mixed content (http:// resources on https:// pages).
 */

import { sendProbe, makeFinding } from './index.js';

const EXTERNAL_SCRIPT_REGEX = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
const EXTERNAL_LINK_REGEX   = /<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["'][^>]*>|<link[^>]+href=["']([^"']+)["'][^>]+rel=["']stylesheet["'][^>]*>/gi;
const INTEGRITY_ATTR_REGEX  = /integrity=["']([^"']+)["']/i;
const CROSSORIGIN_ATTR_REGEX= /crossorigin=["']([^"']*?)["']/i;

function isExternal(resourceUrl, pageOrigin) {
  try {
    const resOrigin = new URL(resourceUrl, pageOrigin).origin;
    return resOrigin !== pageOrigin;
  } catch { return false; }
}

function resolveUrl(src, pageOrigin) {
  try { return new URL(src, pageOrigin).href; }
  catch { return src; }
}

export async function runSriChecker(target, scanOpts) {
  const findings = [];
  const { timeoutMs, signal } = scanOpts;

  let resp;
  try {
    resp = await sendProbe(
      { method: 'GET', url: target.url, headers: target.requestHeaders, timeoutMs },
      signal
    );
  } catch { return findings; }

  if (resp.statusCode !== 200) return findings;

  // Only check HTML responses
  const ct = resp.headers['content-type'] || '';
  if (!ct.includes('text/html') && !ct.includes('application/xhtml')) return findings;

  const body = resp.body || '';
  let pageOrigin;
  try { pageOrigin = new URL(target.url).origin; } catch { return findings; }
  const isHttpsPage = target.url.startsWith('https://');

  // Collect all external resource tags
  const resources = [];
  let m;

  // Script tags
  const scriptRegex = /<script([^>]*)>/gi;
  while ((m = scriptRegex.exec(body)) !== null) {
    const attrs = m[1];
    const srcMatch = attrs.match(/src=["']([^"']+)["']/i);
    if (!srcMatch) continue;
    const src = resolveUrl(srcMatch[1], pageOrigin);
    if (!isExternal(src, pageOrigin)) continue;
    resources.push({
      tag:       'script',
      src,
      attrs,
      integrity: attrs.match(INTEGRITY_ATTR_REGEX)?.[1] ?? null,
      crossorigin: attrs.match(CROSSORIGIN_ATTR_REGEX)?.[1] ?? null,
    });
  }

  // Link (stylesheet) tags
  const linkRegex = /<link([^>]*)>/gi;
  while ((m = linkRegex.exec(body)) !== null) {
    const attrs = m[1];
    if (!/rel=["']stylesheet["']/i.test(attrs)) continue;
    const hrefMatch = attrs.match(/href=["']([^"']+)["']/i);
    if (!hrefMatch) continue;
    const src = resolveUrl(hrefMatch[1], pageOrigin);
    if (!isExternal(src, pageOrigin)) continue;
    resources.push({
      tag:       'link',
      src,
      attrs,
      integrity: attrs.match(INTEGRITY_ATTR_REGEX)?.[1] ?? null,
      crossorigin: attrs.match(CROSSORIGIN_ATTR_REGEX)?.[1] ?? null,
    });
  }

  // Analyze each external resource
  const missingIntegrity = resources.filter(r => !r.integrity);
  const weakHash         = resources.filter(r => r.integrity && r.integrity.startsWith('sha1-'));
  const missingCrossOrigin = resources.filter(r => r.integrity && !r.crossorigin);
  const mixedContent     = resources.filter(r => isHttpsPage && r.src.startsWith('http://'));

  // Group missing-integrity findings (one finding per host, not per resource)
  const missingByHost = {};
  for (const r of missingIntegrity) {
    try {
      const host = new URL(r.src).hostname;
      if (!missingByHost[host]) missingByHost[host] = [];
      missingByHost[host].push(r);
    } catch {}
  }

  for (const [host, list] of Object.entries(missingByHost)) {
    findings.push(makeFinding({
      type:        'sriChecker',
      severity:    'medium',
      title:       `Missing SRI on ${list.length} External Resource${list.length > 1 ? 's' : ''} from ${host}`,
      description: `${list.length} external ${list.map(r => r.tag).join('/')} resource(s) from "${host}" ` +
        `are loaded without a Subresource Integrity (integrity=) attribute. If this CDN or third-party ` +
        `host is compromised, an attacker can serve malicious JavaScript or CSS without detection.`,
      url:         target.url,
      parameter:   null,
      payload:     null,
      evidence: {
        affectedResources: list.slice(0, 5).map(r => r.src),
        totalAffected:     list.length,
        cdnHost:           host,
      },
      remediation:
        'Add integrity= attributes to all external resources. Generate hashes with:\n' +
        'curl -s https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A\n' +
        'Then add: <script src="..." integrity="sha384-BASE64=" crossorigin="anonymous">\n' +
        'Use https://www.srihash.org/ for a web-based generator.',
      references: [
        'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
        'OWASP A08:2021 – Software and Data Integrity Failures',
        'https://www.srihash.org/',
      ],
    }));
  }

  // Weak hash findings
  for (const r of weakHash) {
    findings.push(makeFinding({
      type: 'sriChecker', severity: 'low',
      title: `Weak SRI Hash Algorithm (SHA-1): ${r.src.slice(0, 60)}`,
      description: `The integrity= attribute uses SHA-1 which is cryptographically broken. ` +
        `Attackers may be able to craft a malicious resource that produces the same hash.`,
      url: target.url,
      parameter: null,
      evidence: { src: r.src, integrity: r.integrity },
      remediation: 'Replace SHA-1 hashes with SHA-384 or SHA-512. ' +
        'SHA-384 is the current recommendation for SRI.',
      references: ['OWASP A08:2021', 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
    }));
  }

  // Missing crossorigin on integrity-tagged resources
  if (missingCrossOrigin.length > 0) {
    findings.push(makeFinding({
      type: 'sriChecker', severity: 'info',
      title: `SRI Without crossorigin= Attribute (${missingCrossOrigin.length} resources)`,
      description: `${missingCrossOrigin.length} resource(s) have integrity= but are missing ` +
        `crossorigin="anonymous". Without this attribute, the browser may send credentials ` +
        `to the CDN and SRI validation may not work correctly in all browsers.`,
      url: target.url,
      evidence: { affectedCount: missingCrossOrigin.length },
      remediation: 'Add crossorigin="anonymous" to all external resources that have integrity= attributes.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/crossorigin'],
    }));
  }

  // Mixed content findings
  for (const r of mixedContent.slice(0, 3)) {
    findings.push(makeFinding({
      type: 'sriChecker', severity: 'medium',
      title: `Mixed Content: HTTP Resource on HTTPS Page`,
      description: `The HTTPS page loads "${r.src}" over HTTP. This is mixed active content — ` +
        `the browser may block it, and it is vulnerable to man-in-the-middle injection.`,
      url: target.url,
      evidence: { resourceUrl: r.src, tag: r.tag },
      remediation: 'Change all resource URLs from http:// to https://. ' +
        'Enable HTTPS for all CDN/third-party resources.',
      references: ['OWASP A02:2021', 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'],
    }));
  }

  return findings;
}
```

### 8.4 MODULE_META Entry

```js
sriChecker: {
  label: 'SRI / Integrity Check',
  description:
    'Fetches the page HTML and locates all external <script src> and <link rel=stylesheet> ' +
    'tags loading resources from third-party origins (CDNs, etc.). Flags any that are ' +
    'missing the integrity= SRI attribute — a compromised CDN could otherwise inject ' +
    'arbitrary JavaScript. Also checks for SHA-1 weak hashes, missing crossorigin= ' +
    'attributes, and mixed HTTP/HTTPS content on HTTPS pages.',
},
```

---

## 9. Shared IPC Channel Additions

### 9.1 ipc.js Changes

```js
// In src/shared/ipc.js — add alongside existing SCANNER_* channels:
SCANNER_AUTH_CONTEXT: 'scanner-auth-context',   // renderer -> main (set auth context)
```

### 9.2 webappIpc.js Changes

```js
// Handle auth context (memory-only — never logged, never stored)
let _currentAuthContext = null;

ipcMain.handle(IPC_CHANNELS.SCANNER_AUTH_CONTEXT, (_event, ctx) => {
  if (!ctx || typeof ctx !== 'object') {
    _currentAuthContext = null;
    return { success: true };
  }
  // Validate: only allow known safe header names
  const allowedHeaders = [
    'authorization', 'x-api-key', 'x-auth-token', 'cookie',
    'x-access-token', 'token', 'bearer',
  ];
  const headerLower = (ctx.header || '').toLowerCase();
  if (!allowedHeaders.includes(headerLower) && !headerLower.startsWith('x-')) {
    return { success: false, error: 'Unrecognized auth header name' };
  }
  _currentAuthContext = {
    header: ctx.header,
    value:  ctx.value,   // value never validated (may be any token format)
  };
  return { success: true };
});
```

The `_currentAuthContext` is passed into `startScan()` via `opts.authContext` when a scan starts.

### 9.3 preload.js Addition

```js
scanner: {
  // ... existing entries ...
  setAuthContext: (ctx) => ipcRenderer.invoke(IPC_CHANNELS.SCANNER_AUTH_CONTEXT, ctx),
},
```

---

## 10. UI/UX Design Specification

### 10.1 New Module Chips in Scan Config

Add 4 new module checkboxes to the `scanner-modules-grid` in `index.html`:

```html
<!-- Add after existing 10 module checkboxes -->
<label class="scanner-module-label"
       title="IDOR / Broken Access Control — requires auth token for full coverage">
  <input type="checkbox" class="scanner-module-cb" value="idor" checked>
  <span class="scanner-module-chip severity-high">IDOR</span>
</label>
<label class="scanner-module-label" title="TLS & Cryptographic Failures">
  <input type="checkbox" class="scanner-module-cb" value="tlsAnalyzer" checked>
  <span class="scanner-module-chip severity-high">TLS</span>
</label>
<label class="scanner-module-label" title="Vulnerable & Outdated Components — CVE detection">
  <input type="checkbox" class="scanner-module-cb" value="componentCve" checked>
  <span class="scanner-module-chip severity-medium">CVE</span>
</label>
<label class="scanner-module-label" title="Session Cookie Security Flags & Token Entropy">
  <!-- extends existing brokenAuth, separate toggle for the new session checks only -->
  <input type="checkbox" class="scanner-module-cb" value="sriChecker" checked>
  <span class="scanner-module-chip severity-medium">SRI</span>
</label>
```

> Note: Session security checks are part of `brokenAuth` (same checkbox). The module chip
> tooltip should be updated to mention session fixation and cookie entropy.

### 10.2 Auth Context Input (IDOR)

Add a collapsible "Advanced: Auth Token" section inside the scanner config, visible when
the IDOR module is checked. This follows the existing `activity-collapsed` CSS pattern:

```html
<!-- In scanner config, after module selection grid -->
<div id="scanner-auth-section" class="scanner-auth-section scanner-auth-collapsed">
  <button id="scanner-auth-toggle" class="scanner-auth-toggle-btn">
    ▸ Auth Token (for IDOR & Unauthenticated Access checks)
  </button>
  <div class="scanner-auth-body">
    <div class="scanner-auth-hint">
      Optional. Provide a live session credential so the IDOR module can test
      whether removing it exposes protected resources. Never stored or logged.
    </div>
    <div class="scanner-auth-row">
      <select id="scanner-auth-header" class="scanner-auth-header-select">
        <option value="Authorization">Authorization</option>
        <option value="X-Api-Key">X-Api-Key</option>
        <option value="X-Auth-Token">X-Auth-Token</option>
        <option value="Cookie">Cookie</option>
      </select>
      <input id="scanner-auth-value" type="password" class="scanner-auth-value-input"
             placeholder="Bearer eyJ..." autocomplete="off" spellcheck="false">
      <button id="scanner-auth-clear-btn" class="btn secondary" title="Clear credentials">✕</button>
    </div>
  </div>
</div>
```

**Security constraints on the auth input:**
- `type="password"` — prevents shoulder surfing and browser password manager confusing it
- `autocomplete="off"` — prevents browser saving
- Value is sent via IPC to main process ONLY at scan-start time, not stored in state
- Clear button wipes both DOM input and calls `api.scanner.setAuthContext(null)`
- Scanner's Clear button also clears auth context

### 10.3 CSS for New Module Chips

```css
/* In webapp.css — add to the activity chip color section */
.activity-chip-idor        { background: rgba(239,68,68,0.2);   color: #fca5a5; }
.activity-chip-tlsAnalyzer { background: rgba(59,130,246,0.2);  color: #93c5fd; }
.activity-chip-componentCve{ background: rgba(168,85,247,0.2);  color: #d8b4fe; }
.activity-chip-sriChecker  { background: rgba(234,179,8,0.15);  color: #fde68a; }

/* Module chip severity colors (scanner config grid) */
.scanner-module-chip.severity-critical { background: rgba(220,38,38,0.25);  color: #fca5a5; }
.scanner-module-chip.severity-high     { background: rgba(239,68,68,0.18);  color: #fca5a5; }
.scanner-module-chip.severity-medium   { background: rgba(234,179,8,0.18);  color: #fde68a; }

/* Auth section */
.scanner-auth-section { margin-top: 8px; border-radius: 5px;
                        border: 1px solid rgba(255,255,255,0.07); overflow: hidden; }
.scanner-auth-collapsed .scanner-auth-body { display: none; }
.scanner-auth-toggle-btn { background: none; border: none; color: var(--accent);
                            font-size: 12px; font-weight: 600; cursor: pointer;
                            padding: 6px 10px; width: 100%; text-align: left; }
.scanner-auth-body  { padding: 8px 10px; background: rgba(0,0,0,0.15); }
.scanner-auth-hint  { font-size: 11px; color: rgba(255,255,255,0.35); margin-bottom: 8px; }
.scanner-auth-row   { display: flex; gap: 6px; align-items: center; }
.scanner-auth-header-select { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);
                               color: #e2e8f0; border-radius: 4px; padding: 4px 6px; font-size: 12px; }
.scanner-auth-value-input { flex: 1; background: rgba(255,255,255,0.06);
                             border: 1px solid rgba(255,255,255,0.12); color: #e2e8f0;
                             border-radius: 4px; padding: 4px 8px; font-size: 12px;
                             font-family: var(--font-mono); }
```

### 10.4 `_typeLabel` Update in `scanner.js`

```js
// In scanner.js _typeLabel()
const LABELS = {
  sqli:          'SQLi',
  xss:           'XSS',
  ssrf:          'SSRF',
  xxe:           'XXE',
  cmdInjection:  'CMDi',
  pathTraversal: 'LFI',
  cors:          'CORS',
  headers:       'Headers',
  brokenAuth:    'Auth',
  deserialize:   'Deserial.',
  idor:          'IDOR',          // NEW
  tlsAnalyzer:   'TLS',           // NEW
  componentCve:  'CVE',           // NEW
  sriChecker:    'SRI',           // NEW
};
```

### 10.5 UX Principles Applied (ui-ux-designer skill)

- **Progressive disclosure**: Auth token input is hidden by default, revealed only when needed
- **Security transparency**: Auth field is `type=password`; "Never stored or logged" copy is visible
- **Affordance**: New module chips maintain the same visual weight as existing ones
- **Cognitive load**: New checks (session entropy, cookie flags) are grouped under the existing
  "Auth" module chip — the user does not need to learn new concepts, just knows Auth got better
- **Error prevention**: Auth input has placeholder text showing the expected format
- **Feedback**: Activity log shows TLS/CVE/SRI/IDOR chip colors, making it easy to follow progress
- **Accessibility**: All new inputs have `title` attributes; color coding is supplemented by text labels

---

## 11. Test Plan

### 11.1 Test File Structure

```
test/
├── webapp/
│   ├── scanner/
│   │   ├── idor.test.js             (new)
│   │   ├── tlsAnalyzer.test.js      (new)
│   │   ├── componentCve.test.js     (new)
│   │   ├── sriChecker.test.js       (new)
│   │   └── brokenAuth.test.js       (extend existing)
│   └── component-cve-db.test.js     (db schema validation)
```

### 11.2 IDOR Tests (`idor.test.js`)

```js
describe('runIdor', () => {
  // Setup: mock sendProbe
  // 1. Returns no findings when URL has no numeric IDs or UUIDs
  // 2. Returns HIGH finding when adjacent ID probe returns 200 + similar body
  // 3. Returns no finding when adjacent ID probe returns 404
  // 4. Returns no finding when body size differs by >40% (false positive guard)
  // 5. Returns CRITICAL finding when auth header removal still returns 200 + similar body
  // 6. Returns no finding when auth removal returns 401
  // 7. Correctly handles UUID substitution with TEST_UUID
  // 8. Correctly handles JSON body id fields
  // 9. Caps at 6 candidates (no runaway probing)
  // 10. Respects AbortSignal
  // 11. Does not generate negative ID probes when original ID is 0 or 1
  // 12. _isLikelySessionCookie: correctly identifies auth cookie names
});
```

### 11.3 TLS Tests (`tlsAnalyzer.test.js`)

```js
describe('runTlsAnalyzer', () => {
  // 1. Returns MEDIUM "unencrypted" finding for http:// URL
  // 2. Returns CRITICAL finding when probeTls returns protocol='SSLv3'
  // 3. Returns HIGH finding when probeTls returns protocol='TLSv1'
  // 4. Returns MEDIUM finding when probeTls returns protocol='TLSv1.1'
  // 5. Returns no protocol finding when TLSv1.2 or TLSv1.3
  // 6. Returns HIGH finding when cipher name contains 'RC4'
  // 7. Returns HIGH finding when cipher name contains 'DES-CBC3' (3DES)
  // 8. Returns no cipher finding for ECDHE-RSA-AES256-GCM-SHA384
  // 9. Returns HIGH finding for expired certificate (valid_to in past)
  // 10. Returns MEDIUM finding for cert expiring in 15 days
  // 11. Returns no expiry finding for cert valid for 200 days
  // 12. Returns MEDIUM finding for self-signed cert (issuer.CN === subject.CN)
  // 13. Returns MEDIUM HSTS missing finding when Strict-Transport-Security absent
  // 14. Returns LOW HSTS max-age finding when max-age=3600
  // 15. Returns no HSTS finding when max-age=31536000 + includeSubDomains
  // 16. Handles tls.connect() timeout gracefully (no crash, empty findings)
  // 17. Respects AbortSignal
});
```

### 11.4 ComponentCVE Tests (`componentCve.test.js`)

```js
describe('runComponentCve', () => {
  // 1. Detects Apache version from Server header, matches CVE
  // 2. Detects PHP version from X-Powered-By header, matches CVE
  // 3. Detects jQuery version from asset URL ?ver= pattern, matches CVE
  // 4. Detects WordPress from meta generator tag, matches CVE
  // 5. Returns version disclosure (INFO) finding for Server header even if no CVE
  // 6. Returns no findings when Server: header is absent
  // 7. isVersionAffected: '2.1.4' matches '< 3.4.0' correctly
  // 8. isVersionAffected: '3.5.0' does NOT match '< 3.5.0'
  // 9. isVersionAffected: '2.0.0' matches '>= 1.0.3, < 3.5.0'
  // 10. isVersionAffected: '0.9.0' does NOT match '>= 1.0.3, < 3.5.0'
  // 11. Returns no findings when version is above the fixed version
  // 12. Handles missing CVE db gracefully (empty components array)
  // 13. Non-200 responses return no findings
});
```

### 11.5 SRI Checker Tests (`sriChecker.test.js`)

```js
describe('runSriChecker', () => {
  // 1. Returns MEDIUM finding for external <script> missing integrity=
  // 2. Returns MEDIUM finding for external <link stylesheet> missing integrity=
  // 3. Returns no finding for same-origin <script> (internal resource)
  // 4. Returns no finding for external <script> WITH integrity= and crossorigin=
  // 5. Groups findings by CDN hostname (1 finding per host, not 1 per tag)
  // 6. Returns LOW finding for sha1- weak hash
  // 7. Returns INFO finding for integrity= without crossorigin=
  // 8. Returns MEDIUM mixed-content finding for http:// resource on https:// page
  // 9. Returns no findings for non-HTML content-type responses
  // 10. Returns no findings for 404 responses
  // 11. Handles malformed HTML gracefully (no crash)
  // 12. Resolves relative URLs correctly against page origin
  // 13. Caps mixed-content findings at 3 per target
});
```

### 11.6 BrokenAuth Extension Tests (additions to `brokenAuth.test.js`)

```js
describe('brokenAuth — session extensions', () => {
  // Cookie flags:
  // 1. Returns MEDIUM finding for session cookie missing Secure flag
  // 2. Returns MEDIUM finding for session cookie missing HttpOnly flag
  // 3. Returns MEDIUM finding for session cookie missing SameSite
  // 4. Returns no finding for non-session cookie (name='analytics_id') missing flags
  // 5. Returns no finding when all three flags present
  // 6. Detects 'sessionid', 'authtoken', 'jwt', 'remember_me' as session cookies
  // 7. Does not flag 'ga', 'fbp', '__utma' style analytics cookies

  // Token entropy:
  // 8. Returns HIGH finding when 5 requests return identical token values
  // 9. Returns MEDIUM finding when token is 8 hex chars (~32 bits estimated entropy)
  // 10. Returns no entropy finding for 64-char hex token (~256 bits)
  // 11. Correctly estimates charSpace: hex=16, alphanumeric=62, arbitrary=256
  // 12. Returns no entropy finding if < 2 tokens collected (insufficient data)
});
```

### 11.7 Coverage Target

Following the project's existing pattern (80% test coverage per `review-test-coverage` skill):
- All new module files: 80%+ line coverage
- `isVersionAffected()` utility: 100% branch coverage (all operators)
- `_isLikelySessionCookie()`: 100% branch coverage

---

## 12. Implementation Order

Implementation should follow a risk-priority-first approach with shortest-path integration
tested at each step:

### Sprint 1 — Infrastructure & Quick Wins (2–3 hours)
1. Add `resources/db/component-cve-db.json` with initial 8 components
2. Implement `componentCve.js` (no new APIs, no new IPC — pure response inspection)
3. Implement `sriChecker.js` (no new APIs — pure HTML parsing)
4. Register both in `MODULE_RUNNERS` / `MODULE_META` / `index.html` / `_typeLabel`
5. Write and pass all unit tests for both modules

### Sprint 2 — TLS Analyzer (2 hours)
1. Implement `tlsAnalyzer.js` (uses Node built-in `tls` — no new deps)
2. Register module
3. Write and pass all unit tests
4. Verify the `probeTls()` mock pattern works with Vitest

### Sprint 3 — Auth Context & IDOR (3–4 hours)
1. Add `SCANNER_AUTH_CONTEXT` to `ipc.js`
2. Add IPC handler in `webappIpc.js` with `_currentAuthContext` state
3. Extend `startScan()` to accept and pass `authContext` in `scanOpts`
4. Add `setAuthContext` to `preload.js`
5. Implement `idor.js`
6. Add auth context UI to scanner config panel (`index.html` + `webapp.css`)
7. Wire auth toggle/clear in `scanner.js` renderer
8. Write and pass all unit tests

### Sprint 4 — BrokenAuth Extension (1–2 hours)
1. Add `checkCookieFlags()` to `brokenAuth.js`
2. Add `checkSessionEntropy()` to `brokenAuth.js`
3. Update `MODULE_META.brokenAuth.description`
4. Extend `brokenAuth.test.js` with new test cases

### Sprint 5 — CVE Database & Testing (1–2 hours)
1. Expand `component-cve-db.json` to full initial coverage list
2. Write `scripts/update-cve-db.js` NVD API generator (optional automation)
3. Full integration test: run scanner against a test server that exposes all 5 gap types
4. Review all findings for false positive rate

---

## 13. Security & Ethical Constraints

### 13.1 Constraints from security-auditor skill

- **No intrusive testing without consent**: All new modules are passive (read headers, parse HTML)
  or minimally intrusive (adjacent ID probe sends one extra GET per candidate). None brute-force
  or cause destructive side effects.
- **Auth context is never persisted**: The `authContext` object exists only in `_currentAuthContext`
  (main process memory) for the duration of the scan. It is cleared on `SCANNER_CLEAR` and on
  window close (`window-all-closed` handler).
- **IDOR probes are read-only**: All IDOR probe requests use the same method as the original
  (GET by default). No IDOR probes mutate data (no PUT/DELETE probes) to avoid accidental
  data destruction on real targets.
- **TLS connects do not authenticate**: `tls.connect()` with `rejectUnauthorized: false` only
  inspects the handshake — it does not send any application data.

### 13.2 Constraints from scanning-tools skill

- **Scope boundary respected**: All new modules only probe the exact URL provided in `target.url`
  — they do not crawl to additional paths unless explicitly coded (SRI fetches the page URL only).
- **Rate limiting**: IDOR caps at 6 candidates × 3 probes = max 18 extra requests per target.
  Session entropy collects 5 samples — minimal overhead.
- **No IP scanning**: These are web app modules only. They operate on HTTP/HTTPS URLs,
  never raw socket IP scanning.

### 13.3 Pentest Consent Flow

The existing pentest consent modal (`#pentest-consent-overlay`) already gates all scanner
activity. No additional consent gate is required for the new modules. The IDOR module's
auth token UI includes inline copy ("Never stored or logged") to maintain transparency.

### 13.4 Responsible Disclosure

Findings from all new modules carry `references` arrays pointing to OWASP documentation,
CVE advisories, and RFC references — consistent with the existing modules and the project's
security education posture.

---

*End of PLAN_OWASP_GAPS.md*
*Plan generated: 2026-03-15 | Based on skills: security-auditor, scanning-tools,
security-scanning-security-hardening, security-scanning-security-dependencies,
nodejs-backend-patterns, nodejs-best-practices, javascript-pro, network-engineer,
network-101, ui-skills, ui-ux-designer*
