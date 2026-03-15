# Feature 7 — Web Application Security Testing Workspace

> **Status:** Phases 7A–7D COMPLETE. Phase 7E (Out-of-Band / Advanced) in planning.
> **Branch:** `scanner-enhance` (current), merged features from `webapp-scanner`
> **Scope:** Full L7 web application security testing capability integrated into the existing NetSpecter Electron application under the "Web App" workspace tab.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Implementation Status](#3-implementation-status)
4. [Phase 7A — Intercepting HTTPS Proxy](#4-phase-7a--intercepting-https-proxy)
5. [Phase 7B — Web Crawling & Attack Surface Mapping](#5-phase-7b--web-crawling--attack-surface-mapping)
6. [Phase 7C — Active Vulnerability Scanner](#6-phase-7c--active-vulnerability-scanner)
7. [Phase 7D — Manual Testing Utilities](#7-phase-7d--manual-testing-utilities)
8. [Phase 7E — Out-of-Band & Advanced Detection (Planned)](#8-phase-7e--out-of-band--advanced-detection-planned)
9. [IPC Channel Definitions](#9-ipc-channel-definitions)
10. [File & Module Layout](#10-file--module-layout)
11. [Security Constraints](#11-security-constraints)
12. [Test Strategy](#12-test-strategy)
13. [CSS & Theming](#13-css--theming)
14. [Consent & Ethics Gate](#14-consent--ethics-gate)
15. [Dependency Analysis](#15-dependency-analysis)
16. [OWASP Gap Analysis & Roadmap](#16-owasp-gap-analysis--roadmap)

---

## 1. Executive Summary

Feature 7 transforms NetSpecter from a network-layer scanner into a full-stack security testing platform. The Web Application Testing Workspace is an integrated Burp Suite-style toolkit accessible via the **Web App tab** in the main UI. It operates alongside the Network workspace, allowing seamless pivot between network-level host discovery and application-level vulnerability assessment.

### Goals

- **Zero-friction setup**: No external proxy tools or browser extensions required. The MITM proxy runs inside the Electron main process.
- **Network-to-Web pivot**: Any HTTP port discovered in the Network workspace can be sent directly to the Scanner, Repeater, or Intruder with one click.
- **OWASP Top 10 coverage**: All ten OWASP 2021 categories are addressed across the scanner modules.
- **No cloud dependencies**: All analysis is local. No telemetry, no OAST callbacks to external services by default.
- **Consistent UX**: The glassmorphic dark theme, panel/modal patterns, and IPC streaming model are extended — not replaced.

### Non-Goals

- Full browser DevTools replacement
- Traffic replay at scale (use dedicated load-testing tools)
- Authenticated crawling with complex SSO flows (OAuth/SAML — out of scope for initial release)

---

## 2. Architecture Overview

The Web App workspace follows the same IPC + streaming architecture as all other NetSpecter features.

```text
Browser (external) ──HTTPS──► proxyServer.js (MITM)
                                    │
                              requestStore.js (SQLite)
                                    │
                              webappIpc.js ◄──── Renderer (proxy.js, sitemap.js)
                                    │
                         ┌──────────┴──────────────┐
                         │                         │
                   crawler.js              scanner/index.js
                   activeCrawler.js            sqli.js
                   apiDetector.js              xss.js
                         │                    ssrf.js  xxe.js
                   sitemap events          cmdInjection.js
                                           pathTraversal.js
                         │                    cors.js
                   repeaterEngine.js          headers.js
                   intruderEngine.js          brokenAuth.js
                   sequencerEngine.js         deserialize.js
```

### Process Boundary

All proxy, crawling, scanning, and engine logic runs in the **main process**. The renderer receives results via `mainWindow.webContents.send()` and renders them. No network operations occur in the renderer.

### Data Flow

1. Browser → proxy → `proxyServer.js` intercepts CONNECT, issues leaf cert, decrypts TLS
2. Request/response stored in SQLite via `requestStore.js`
3. `PROXY_REQUEST` IPC event streamed to renderer → `proxy.js` table row added
4. Crawler passively builds sitemap from stored requests
5. Active crawler (Playwright) spiders additional endpoints
6. Scanner pulls targets from URL / history / sitemap, runs modules, streams `SCANNER_FINDING` events
7. Repeater sends single raw requests via `repeaterEngine.js`, streams response back
8. Intruder expands payload matrix, runs concurrent probes via `intruderEngine.js`, streams `INTRUDER_RESULT` events

---

## 3. Implementation Status

| Phase | Feature | Status | Key Files |
| --- | --- | --- | --- |
| 7A | Intercepting HTTPS Proxy | ✅ COMPLETE | `proxyServer.js`, `requestStore.js` |
| 7A | HAR 1.2 Export | ✅ COMPLETE | `webappIpc.js` |
| 7A | Request Intercept & Edit | ✅ COMPLETE | `proxyServer.js` |
| 7B | Passive Crawler (sitemap from proxy) | ✅ COMPLETE | `crawler.js` |
| 7B | Active Crawler (Playwright headless) | ✅ COMPLETE | `activeCrawler.js` |
| 7B | API Endpoint Detection | ✅ COMPLETE | `apiDetector.js` |
| 7B | Sitemap Tree UI | ✅ COMPLETE | `sitemap.js` |
| 7B | External URL Recording | ✅ COMPLETE | `crawler.js` |
| 7C | SQLi Scanner | ✅ COMPLETE | `scanner/sqli.js` |
| 7C | XSS Scanner | ✅ COMPLETE | `scanner/xss.js` |
| 7C | SSRF Scanner | ✅ COMPLETE | `scanner/ssrf.js` |
| 7C | XXE Scanner | ✅ COMPLETE | `scanner/xxe.js` |
| 7C | Command Injection Scanner | ✅ COMPLETE | `scanner/cmdInjection.js` |
| 7C | Path Traversal Scanner | ✅ COMPLETE | `scanner/pathTraversal.js` |
| 7C | CORS Misconfiguration | ✅ COMPLETE | `scanner/cors.js` |
| 7C | HTTP Security Headers | ✅ COMPLETE | `scanner/headers.js` |
| 7C | Broken Authentication | ✅ COMPLETE | `scanner/brokenAuth.js` |
| 7C | Deserialization Detection | ✅ COMPLETE | `scanner/deserialize.js` |
| 7C | Findings Export (JSON/CSV/HTML) | ✅ COMPLETE | `webappIpc.js` |
| 7C | Network Badge Injection | ✅ COMPLETE | `scanner.js` renderer |
| 7D | Request Repeater | ✅ COMPLETE | `repeaterEngine.js`, `repeater.js` |
| 7D | Intruder (4 attack types) | ✅ COMPLETE | `intruderEngine.js`, `intruder.js` |
| 7D | Token Sequencer | ✅ COMPLETE | `sequencerEngine.js`, `sequencer.js` |
| 7D | Encoder/Decoder | ✅ COMPLETE | `decoder.js` |
| 7D | Response Comparer | ✅ COMPLETE | `comparer.js` |
| 7E | OAST Callbacks | 🔲 PLANNED | — |
| 7E | GraphQL Scanner Module | 🔲 PLANNED | — |
| 7E | WebSocket Fuzzer | 🔲 PLANNED | — |
| 7E | JWT Attack Suite | 🔲 PLANNED | — |
| 7E | OAuth/OIDC Misconfiguration | 🔲 PLANNED | — |
| 7E | Open Redirect Detection | 🔲 PLANNED | — |
| 7E | Business Logic Fuzzing | 🔲 PLANNED | — |

---

## 4. Phase 7A — Intercepting HTTPS Proxy

### Design

The proxy runs as an HTTP/1.1 server bound to `127.0.0.1` on a configurable port (default 8080). For HTTPS, it handles `CONNECT` tunnel requests by issuing a `200 Connection Established` response, then impersonates the target server using a dynamically generated TLS certificate signed by a locally-generated CA.

### Certificate Authority

- CA key pair + self-signed cert generated once with `node-forge` and stored via `electron-store`
- Leaf certificates for each intercepted hostname are generated on demand and cached in memory
- The CA cert is exportable from the Settings pane for installation in the browser's trust store

### Request Storage (SQLite)

All proxied requests and responses are stored in a `better-sqlite3` database at the user data path:

```text
%APPDATA%/netspectre/proxy-history.db   (Windows)
~/Library/Application Support/netspectre/proxy-history.db  (macOS)
~/.config/netspectre/proxy-history.db  (Linux)
```

**Schema:**

```sql
CREATE TABLE requests (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,          -- Unix ms timestamp
  method    TEXT NOT NULL,
  url       TEXT NOT NULL,
  host      TEXT NOT NULL,
  path      TEXT NOT NULL,
  query     TEXT,
  reqHeaders TEXT,                     -- JSON
  reqBody   BLOB,
  status    INTEGER,
  resHeaders TEXT,                     -- JSON
  resBody   BLOB,
  duration  INTEGER,                   -- ms
  tls       INTEGER DEFAULT 0          -- 1 = was HTTPS
);
```

### IPC Channels (7A)

| Channel | Direction | Description |
| --- | --- | --- |
| `PROXY_START` | Renderer → Main | Start the proxy on the given port |
| `PROXY_STOP` | Renderer → Main | Stop the proxy |
| `PROXY_STATUS` | Main → Renderer | Port, running state |
| `PROXY_REQUEST` | Main → Renderer | Streamed request entry (id, method, url, status) |
| `PROXY_GET_HISTORY` | Renderer → Main | Fetch paginated history with filters |
| `PROXY_GET_REQUEST` | Renderer → Main | Fetch full request+response by ID |
| `PROXY_CLEAR_HISTORY` | Renderer → Main | Delete all rows from requests table |
| `PROXY_EXPORT_HAR` | Renderer → Main | Export history as HAR 1.2 JSON file |
| `PROXY_INTERCEPT_TOGGLE` | Renderer → Main | Enable/disable request interception |
| `PROXY_FORWARD` | Renderer → Main | Forward a held request (optionally modified) |
| `PROXY_DROP` | Renderer → Main | Drop a held request |
| `PROXY_GET_CA_CERT` | Renderer → Main | Return PEM of the CA certificate |

### Security Constraints

- Proxy binds only to `127.0.0.1` — never `0.0.0.0`
- CA private key stays in main process memory and `electron-store` — never sent to renderer
- `isValidHttpUrl()` validates all forwarded URLs before connection
- Max request body size: 10 MB to prevent memory exhaustion

---

## 5. Phase 7B — Web Crawling & Attack Surface Mapping

### Passive Crawler (`crawler.js`)

Builds a sitemap automatically from proxied traffic without issuing any additional requests. For every stored request, it:

1. Parses the URL into `{ host, path, query, params[] }`
2. Extracts links and form actions from HTML response bodies
3. Classifies the endpoint via `apiDetector.js`
4. Emits `CRAWLER_URL_FOUND` and `CRAWLER_EXTERNAL_URL` events

### Active Crawler (`activeCrawler.js`)

Uses `playwright-core` to launch a headless Chromium instance that:

1. Navigates to the seed URL
2. Clicks links, submits forms with benign test values
3. Intercepts all network requests made by the page
4. Records discovered URLs back via IPC
5. Respects a configurable depth limit (default 3) and page count limit (default 100)

**Playwright is not bundled** — the user must have a Chromium executable available. `activeCrawler.js` calls `playwright.chromium.launch({ executablePath })` using the path from `electron-store`.

### API Detector (`apiDetector.js`)

Classifies each endpoint using heuristics:

| Signal | Classification |
| --- | --- |
| `Content-Type: application/json` response | REST API |
| Path matches `/graphql`, `/gql` | GraphQL |
| `Upgrade: websocket` request header | WebSocket |
| `Content-Type: text/html` response | HTML Page |
| Path ends with `.js`, `.css`, `.png`, etc. | Static Asset |

### Sitemap UI (`sitemap.js`)

Renders a collapsible tree grouped by hostname → path segments. Each leaf node shows:

- HTTP method badge
- Endpoint classification icon (API, WS, HTML, Asset)
- Parameter count
- Context menu: Send to Repeater, Scanner, Intruder

### IPC Channels (7B)

| Channel | Direction | Description |
| --- | --- | --- |
| `CRAWLER_START_ACTIVE` | Renderer → Main | Start active crawl from seed URL |
| `CRAWLER_STOP` | Renderer → Main | Abort active crawl |
| `CRAWLER_URL_FOUND` | Main → Renderer | New endpoint discovered |
| `CRAWLER_EXTERNAL_URL` | Main → Renderer | External URL reference recorded |
| `CRAWLER_PROGRESS` | Main → Renderer | Pages visited / depth |
| `CRAWLER_COMPLETE` | Main → Renderer | Active crawl finished |
| `CRAWLER_GET_SITEMAP` | Renderer → Main | Return full sitemap from DB |
| `CRAWLER_CLEAR` | Renderer → Main | Clear sitemap |

---

## 6. Phase 7C — Active Vulnerability Scanner

### Orchestrator (`scanner/index.js`)

The scanner orchestrator:

- Accepts a target list (URLs from direct input, proxy history query, or sitemap)
- Runs enabled modules concurrently using a semaphore (configurable, default 10)
- Each module receives a `sendProbe(url, opts)` function and an `AbortSignal`
- Modules call `makeFinding(severity, title, description, evidence, remediation, references)` to emit results
- Results are streamed via `SCANNER_FINDING` IPC event in real-time

### Scanner Modules

#### SQLi (`sqli.js`)

Tests each URL parameter and POST body field with four techniques:

| Technique | Method | Detection |
| --- | --- | --- |
| Time-based blind | `'; SLEEP(5)--` / `'; WAITFOR DELAY '0:0:5'--` | Response time delta > 4s |
| Error-based | `'`, `''`, `\` | DB error strings in response (MySQL, MSSQL, Oracle, PostgreSQL, SQLite) |
| Boolean-based | `AND 1=1` vs `AND 1=2` | Response body length delta > 20 bytes |
| UNION-based | `UNION SELECT NULL--` variations | `NULL` or column count error patterns |

DB fingerprinting: error string patterns identify MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and MongoDB. The detected DB type is included in the finding's evidence.

#### XSS (`xss.js`)

| Technique | Description |
| --- | --- |
| Reflected (canary) | Injects `<netspecter-xss-RAND>` canary; checks if it appears unescaped in response |
| DOM sink hints | Response body scanned for `innerHTML`, `document.write`, `eval(` patterns near reflected input |
| Encoded bypass | HTML entity encoding, Unicode escaping, double-encoding variants |
| Event handler | `" onmouseover=alert(1)` variants for attribute injection contexts |

#### SSRF (`ssrf.js`)

| Probe | Target |
| --- | --- |
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` |
| GCP Metadata | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` |
| Localhost redirect | `http://localhost/`, `http://127.0.0.1/` |
| Timing-based blind | Compare response time with fast vs slow target |

Detection: response body matches cloud metadata patterns; status 200 with metadata content; significant timing difference for blind detection.

#### XXE (`xxe.js`)

Injects XML payloads into request bodies where `Content-Type: application/xml` or XML structure is detected:

| Probe | Description |
| --- | --- |
| File read (Unix) | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — checks response for `root:` |
| File read (Win) | `<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">` — checks for `[fonts]` |
| Parser delta | Malformed vs well-formed response size/status delta |
| OAST | `<!ENTITY xxe SYSTEM "http://OAST_HOST/">` (when OAST configured) |

#### Command Injection (`cmdInjection.js`)

| Technique | Payloads | Detection |
| --- | --- | --- |
| Output reflection | `; echo NETSPECTRE_CMD_$(id)` | Checks response for `NETSPECTRE_CMD_` followed by uid |
| Time-based | `; sleep 5 #`, `& timeout 5 >nul` | Response time delta > 4s |
| OAST curl | `; curl http://OAST_HOST/` | (when OAST configured) |

#### Path Traversal (`pathTraversal.js`)

Tests file path parameters and URL path segments with:

- Unix traversal: `../../etc/passwd`, `....//....//etc/passwd`, URL-encoded variants
- Windows traversal: `..\..\..\windows\win.ini`, mixed slash variants
- Null byte injection: `../etc/passwd%00.jpg`

Detection: response body contains `/etc/passwd` content (`root:x:0:0`) or Windows ini markers.

#### CORS (`cors.js`)

Sends multiple requests with crafted `Origin` headers:

| Test | Origin Header | Success Condition |
| --- | --- | --- |
| Arbitrary origin | `https://evil.com` | `ACAO: https://evil.com` + `ACAC: true` |
| Null origin | `null` | `ACAO: null` |
| Subdomain bypass | `https://evil.target.com` | `ACAO: https://evil.target.com` |
| Prefix bypass | `https://targetcom.evil.com` | `ACAO: https://targetcom.evil.com` |
| Wildcard + credentials | `*` | `ACAO: *` + `ACAC: true` (invalid but misconfigured) |

#### HTTP Security Headers (`headers.js`)

Audits every response for:

| Header | Finding |
| --- | --- |
| Missing `Strict-Transport-Security` | Medium severity |
| Missing `Content-Security-Policy` | Medium severity |
| Missing `X-Frame-Options` | Medium severity |
| Missing `X-Content-Type-Options` | Low severity |
| Missing `Referrer-Policy` | Info |
| `Server` header revealing version | Low severity |
| `X-Powered-By` header present | Low severity |
| `Set-Cookie` missing `Secure` flag | Medium severity |
| `Set-Cookie` missing `HttpOnly` flag | Low severity |
| `Set-Cookie` missing `SameSite` | Low severity |

#### Broken Authentication (`brokenAuth.js`)

| Test | Description |
| --- | --- |
| Rate limit bypass | Sends 20 identical login requests, checks if all succeed (no lockout) |
| Username enumeration | Compares response length/time for valid vs invalid usernames |
| Weak credentials | Tests common pairs (admin/admin, root/root, admin/password) |
| JWT inspection | Decodes JWT from cookies/headers; checks `alg: none`, weak secret hints, expiry |
| Session fixation | Checks if session ID changes post-authentication |

#### Deserialization (`deserialize.js`)

Detects serialized object patterns in request/response bodies:

| Language | Pattern |
| --- | --- |
| PHP | `O:N:"ClassName":` or `a:N:{` |
| Java | `rO0AB` (Base64 `aced0005`) or `%ac%ed%00%05` |
| Python pickle | `\x80\x02` or `\x80\x04` opcodes |
| .NET ViewState | `__VIEWSTATE` parameter (checked for MAC validation) |
| Node.js | `{"rce":"_$$ND_FUNC$$_function()` |

### Finding Severity Levels

| Severity | Color | Examples |
| --- | --- | --- |
| Critical | Red `#ff4444` | SQLi, RCE via CMDi, XXE file read |
| High | Orange `#ff8c00` | Reflected XSS, SSRF, arbitrary CORS |
| Medium | Yellow `#ffd700` | CSRF, missing HSTS, session fixation |
| Low | Blue `#4fc3f7` | Missing headers, version disclosure |
| Info | Gray `#9e9e9e` | API endpoint found, referrer policy |

### Export Formats

- **JSON**: Full findings array with all fields
- **CSV**: Severity, title, URL, parameter, evidence (one row per finding)
- **HTML Report**: Styled standalone HTML with severity-grouped sections, evidence blocks, and remediation guidance

### IPC Channels (7C)

| Channel | Direction | Description |
| --- | --- | --- |
| `SCANNER_START` | Renderer → Main | Start scan with config (target, modules, concurrency) |
| `SCANNER_STOP` | Renderer → Main | Abort running scan |
| `SCANNER_FINDING` | Main → Renderer | Individual finding streamed |
| `SCANNER_PROGRESS` | Main → Renderer | Requests sent / total |
| `SCANNER_COMPLETE` | Main → Renderer | Scan finished |
| `SCANNER_ERROR` | Main → Renderer | Error during scan |
| `SCANNER_GET_FINDINGS` | Renderer → Main | Return all findings for session |
| `SCANNER_EXPORT` | Renderer → Main | Export findings (format, filepath) |
| `SCANNER_CLEAR` | Renderer → Main | Clear findings |

---

## 7. Phase 7D — Manual Testing Utilities

### Request Repeater (`repeaterEngine.js`)

Provides raw HTTP request relay independent of the browser/proxy:

**`parseRawRequest(rawString)`** — Parses a raw HTTP request string:

```text
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":"test"}
```

Into `{ method, path, headers, body }`.

**`sendRepeaterRequest(opts, signal)`** — Executes the request via Node.js `http`/`https`, respecting:

- TLS certificate validation (configurable bypass for self-signed certs)
- Redirect following (configurable, default off)
- 5 MB response size cap
- `AbortSignal` for cancellation
- Returns `{ statusCode, headers, body, durationMs, rawRequest, rawResponse }`

### Intruder Engine (`intruderEngine.js`)

**`parsePositions(template)`** — Finds `§marker§` positions in a raw request template.

**`buildPayloadMatrix(attackType, positions, payloadLists)`** — Generates the full request set:

| Attack Type | Requests Generated |
| --- | --- |
| Sniper | `positions.length × payloadList.length` |
| Battering Ram | `payloadList.length` |
| Pitchfork | `min(payloadList lengths)` |
| Cluster Bomb | `product(all payloadList lengths)` |

**`startIntruder(opts, onResult, onProgress, onComplete, onError)`** — Runs the attack with configurable concurrency (semaphore-based, default 10).

Each result includes: `{ requestIndex, payload, statusCode, responseLength, durationMs, responseBody }`.

### Token Sequencer (`sequencerEngine.js`)

Collects token samples and applies:

- **Bit-level entropy analysis**: Shannon entropy per bit position across all samples
- **FIPS 140-2 statistical tests**:
  - Monobit: count of 1-bits must be 9,725–10,275 per 20,000 bits
  - Poker: chi-squared test on 4-bit groups
  - Runs: count of consecutive identical bits
  - Long runs: no run of 26+ identical bits
- **Visualization data**: Returns per-bit entropy values for charting in the renderer

### Encoder/Decoder (`decoder.js` — renderer-side)

Pure renderer-side module (no IPC needed). Supported transforms:

| Operation | Implementation |
| --- | --- |
| URL encode/decode | `encodeURIComponent` / `decodeURIComponent` |
| HTML encode/decode | DOM `textContent` assign trick |
| Base64 encode/decode | `btoa` / `atob` |
| Hex encode/decode | `charCodeAt` / `String.fromCharCode` |
| MD5 hash | Pure JS implementation |
| SHA-1/256/512 | Web Crypto API (`crypto.subtle.digest`) |
| GZIP | `DecompressionStream('gzip')` |
| Smart decode | Heuristic chain detection |

### Response Comparer (`comparer.js` — renderer-side)

Pure renderer-side diff using Myers diff algorithm:

- **Word-level mode**: Tokenizes by whitespace, diffs word tokens
- **Byte-level mode**: Diffs character-by-character
- Highlights added content (green), removed content (red), unchanged (gray)

---

## 8. Phase 7E — Out-of-Band & Advanced Detection (Planned)

### 8.1 OAST Integration

Out-of-band application security testing requires a callback server to receive DNS/HTTP interactions triggered by injected payloads. Options for implementation:

#### Option A: Self-hosted OAST server (recommended for privacy)

- NetSpecter spins up a DNS server (port 53) and HTTP server in the main process
- Generates unique subdomain tokens per probe: `<token>.oast.netspectre.local`
- Correlation: when a DNS query or HTTP request arrives matching a token, the finding is upgraded with "confirmed OOB interaction"
- Requires elevated privileges on Linux/macOS for port 53

#### Option B: Interactsh (Projectdiscovery)

- Use the `interactsh-client` library against a self-hosted `interactsh-server` instance
- User provides their own Interactsh server URL in Settings
- No dependency on external infrastructure

Priority: Option B is faster to implement. Option A is the long-term goal.

### 8.2 GraphQL Scanner Module

GraphQL endpoints identified by `apiDetector.js` require specialized testing:

| Test | Description |
| --- | --- |
| Introspection enabled | `{__schema{types{name}}}` — info disclosure |
| Batch query abuse | Send array of queries in single request |
| Nested query DoS | Deeply nested queries (e.g., 10 levels) |
| Field suggestion leakage | Misspelled field names trigger suggestion messages |
| SQLi via arguments | Inject SQL payloads into resolver arguments |
| Auth bypass via `__typename` | Query type fields without authentication |

### 8.3 WebSocket Fuzzer

For WebSocket endpoints discovered by `apiDetector.js`:

- Establish WS connection via `ws` npm package in main process
- Send configurable payload list to each message slot
- Record responses for manual analysis
- Detect error patterns indicating injection vulnerabilities

### 8.4 JWT Attack Suite

Extend `brokenAuth.js` with a dedicated JWT attack module:

| Attack | Description |
| --- | --- |
| `alg: none` | Strip signature, set algorithm to `none` |
| Weak HMAC secret | Wordlist-based secret brute-force (HMAC-SHA256) |
| RS256 → HS256 confusion | Use public key as HMAC secret |
| `kid` injection | Inject path traversal or SQLi into the `kid` header |
| `jku`/`x5u` spoofing | Point to attacker-controlled JWK Set |
| Expired token acceptance | Modify `exp` claim, check if server validates |

### 8.5 OAuth/OIDC Misconfiguration

| Check | Description |
| --- | --- |
| Open redirect in `redirect_uri` | Test wildcard/unvalidated redirect URIs |
| State parameter missing | Detect CSRF vulnerability in authorization flow |
| Authorization code leakage | Check `Referer` header after code exchange |
| Token in URL fragment | Check for insecure token delivery |
| PKCE bypass | Test flows where PKCE is optional but shouldn't be |

### 8.6 Open Redirect Detection

Add to scanner orchestrator as a lightweight standalone module:

- Test URL parameters containing `http://`, `//`, `/\`, encoded variants
- Follow redirects and check if final destination is off-domain
- Severity: Medium (can be chained with XSS for phishing amplification)

---

## 9. IPC Channel Definitions

All channel names are defined in `src/shared/ipc.js`. The web app channels use a `PROXY_`, `CRAWLER_`, `SCANNER_`, `REPEATER_`, `INTRUDER_`, `SEQUENCER_` prefix convention.

Key channels per subsystem:

```javascript
// Proxy (7A)
PROXY_START, PROXY_STOP, PROXY_STATUS, PROXY_REQUEST,
PROXY_GET_HISTORY, PROXY_GET_REQUEST, PROXY_CLEAR_HISTORY,
PROXY_EXPORT_HAR, PROXY_INTERCEPT_TOGGLE, PROXY_FORWARD,
PROXY_DROP, PROXY_GET_CA_CERT

// Crawler (7B)
CRAWLER_START_ACTIVE, CRAWLER_STOP, CRAWLER_URL_FOUND,
CRAWLER_EXTERNAL_URL, CRAWLER_PROGRESS, CRAWLER_COMPLETE,
CRAWLER_GET_SITEMAP, CRAWLER_CLEAR

// Scanner (7C)
SCANNER_START, SCANNER_STOP, SCANNER_FINDING, SCANNER_PROGRESS,
SCANNER_COMPLETE, SCANNER_ERROR, SCANNER_GET_FINDINGS,
SCANNER_EXPORT, SCANNER_CLEAR

// Repeater (7D)
REPEATER_SEND, REPEATER_RESPONSE, REPEATER_ERROR

// Intruder (7D)
INTRUDER_START, INTRUDER_STOP, INTRUDER_RESULT,
INTRUDER_PROGRESS, INTRUDER_COMPLETE, INTRUDER_ERROR

// Sequencer (7D)
SEQUENCER_ANALYZE, SEQUENCER_RESULT
```

---

## 10. File & Module Layout

### Main Process

```text
src/main/webapp/
├── proxyServer.js       MITM proxy, cert generation, request storage coordination
├── requestStore.js      SQLite schema, CRUD, HAR export
├── crawler.js           Passive sitemap builder, external URL recorder
├── activeCrawler.js     Playwright-based headless browser crawler
├── apiDetector.js       REST/GraphQL/WS/HTML classification heuristics
├── repeaterEngine.js    Raw HTTP request relay (parseRawRequest, sendRepeaterRequest)
├── intruderEngine.js    Payload matrix generation, attack runner (4 types)
├── sequencerEngine.js   Token entropy analysis, FIPS tests
├── ipc/
│   └── webappIpc.js     All web app IPC handler registrations + export helpers
└── scanner/
    ├── index.js         Orchestrator: semaphore, AbortController, sendProbe, makeFinding
    ├── sqli.js          SQL injection (4 techniques, DB fingerprint)
    ├── xss.js           Cross-site scripting (reflected, DOM, encoded)
    ├── ssrf.js          Server-side request forgery (cloud metadata, timing)
    ├── xxe.js           XML external entity (file read, OAST)
    ├── cmdInjection.js  Command injection (output, time-based, OAST)
    ├── pathTraversal.js Local file inclusion (Unix/Windows, null byte)
    ├── cors.js          CORS misconfiguration (5 origin tests)
    ├── headers.js       HTTP security header audit (10+ checks)
    ├── brokenAuth.js    Auth weaknesses (rate limit, enum, weak creds, JWT)
    └── deserialize.js   Deserialization pattern detection (5 languages)
```

### Renderer

```text
src/renderer/modules/webapp/
├── index.js        Tab manager, workspace router, init
├── proxy.js        Proxy history table, filter controls, intercept UI
├── sitemap.js      Crawl tree, endpoint type icons, context menus
├── repeater.js     Raw request/response editor, tab management
├── intruder.js     Position marker UI, payload config, results table
├── sequencer.js    Token capture, entropy charts, FIPS test results
├── decoder.js      Encoder/decoder toolbox (pure renderer)
├── comparer.js     Side-by-side diff (pure renderer)
└── scanner.js      Module selection, progress, findings table, export
```

---

## 11. Security Constraints

All security rules from the project CLAUDE.md apply. Additional constraints for the web app subsystem:

1. **Proxy binds `127.0.0.1` only** — the MITM proxy must never be accessible from other hosts on the network.
2. **URL validation before any outbound request** — `isValidHttpUrl()` from `src/shared/validate.js` must gate all `sendProbe()`, `sendRepeaterRequest()`, and active crawler navigation calls.
3. **No credentials in SQLite** — if a proxied request contains an `Authorization: Basic` header, the decoded credentials are not stored in the requests table. Only the raw header value is stored (as proxied), and findings from `brokenAuth.js` are never written to disk.
4. **Consent gate** — the web app workspace requires the same pentest consent as offensive tools. `#pentest-consent-overlay` is shown before any active scanning, intruder, or active crawl operation.
5. **Max body size** — `proxyServer.js` enforces a 10 MB cap on request/response bodies. `repeaterEngine.js` enforces 5 MB.
6. **TLS verification bypass** — when the user configures "ignore TLS errors" for repeater/scanner, this is scoped to those specific requests only, using `rejectUnauthorized: false` on the `https.request` options. The main process TLS configuration is never globally mutated.
7. **No eval, no VM** — scanner payloads are plain strings. No `eval()` or `vm.runInContext()` used anywhere in the web app subsystem.
8. **Passive-by-default** — the proxy and passive crawler are always-on once started; active crawling and scanning require explicit user action.

---

## 12. Test Strategy

### Unit Tests

All backend modules have corresponding unit tests in `test/webapp/`:

| Test File | Module Under Test | Key Coverage |
| --- | --- | --- |
| `requestStore.test.js` | `requestStore.js` | Schema init, insert, query, HAR export, pagination |
| `proxyServer.test.js` | `proxyServer.js` | CONNECT handling, cert generation mock, request/response piping |
| `crawler.test.js` | `crawler.js` | URL parsing, sitemap building, external URL recording |
| `activeCrawler.test.js` | `activeCrawler.js` | Playwright mock, depth limit, page count limit |
| `apiDetector.test.js` | `apiDetector.js` | REST/GraphQL/WS/HTML/asset classification |
| `intruderEngine.test.js` | `intruderEngine.js` | Position parsing, payload matrix (all 4 types), concurrency |
| `sequencerEngine.test.js` | `sequencerEngine.js` | Entropy calculation, FIPS test pass/fail scenarios |

### Scanner Module Tests

Each scanner module should have its own test file in `test/webapp/scanner/`:

| Test File | Coverage |
| --- | --- |
| `sqli.test.js` | Time-based mock (delayed response), error pattern match, boolean delta |
| `xss.test.js` | Canary reflection detection, DOM pattern detection |
| `ssrf.test.js` | Cloud metadata response matching, timing detection |
| `xxe.test.js` | File content pattern detection, malformed XML delta |
| `cmdInjection.test.js` | Output reflection detection, time-based mock |
| `pathTraversal.test.js` | `/etc/passwd` content detection, encoding variants |
| `cors.test.js` | All 5 origin test scenarios, ACAO/ACAC header validation |
| `headers.test.js` | Each missing header produces correct severity finding |
| `brokenAuth.test.js` | Rate limit detection (20 req), JWT decode, weak cred match |
| `deserialize.test.js` | All 5 language patterns detected |

### Mocking Conventions

```javascript
// Mock http/https for scanner tests
vi.mock('http', () => ({ request: vi.fn() }));
vi.mock('https', () => ({ request: vi.fn() }));

// Mock better-sqlite3 (function constructor pattern)
vi.mock('better-sqlite3', () => {
  function MockDatabase() {
    this.prepare = vi.fn().mockReturnValue({
      run: vi.fn(),
      get: vi.fn(),
      all: vi.fn().mockReturnValue([]),
    });
    this.exec = vi.fn();
    this.close = vi.fn();
  }
  return { default: MockDatabase };
});

// Always call closeRequestStore() in afterEach for SQLite tests
afterEach(() => { closeRequestStore(); });
```

### Coverage Target

The web app subsystem targets **80% line coverage**. Run with:

```bash
npx vitest run --coverage --reporter=verbose
```

---

## 13. CSS & Theming

All web app workspace styles live in `src/renderer/webapp.css`. The theme follows the glassmorphic dark pattern from `style.css`.

### Key CSS Variables (webapp context)

```css
--proxy-accent:    #38bdf8;   /* sky blue — proxy/crawler */
--scanner-accent:  #f97316;   /* orange — scanner findings */
--critical:        #ff4444;
--high:            #ff8c00;
--medium:          #ffd700;
--low:             #4fc3f7;
--info:            #9e9e9e;
--repeater-accent: #a78bfa;   /* purple — repeater/intruder */
```

### Component Classes

| Class | Usage |
| --- | --- |
| `.webapp-tab-bar` | Top tab row (Proxy, Sitemap, Scanner, Repeater, Intruder, ...) |
| `.webapp-panel` | Each tool's content panel |
| `.proxy-history-row` | Single history table row, `[data-method]` for coloring |
| `.finding-row` | Scanner findings table row |
| `.finding-severity-badge` | Colored pill badge (critical/high/medium/low/info) |
| `.finding-detail` | Expandable detail row (description, evidence, remediation) |
| `.web-vuln-badge` | Badge injected onto Network host cards |
| `.repeater-pane` | Left (request) / right (response) split panes |
| `.intruder-position` | `§…§` highlighted spans in raw request editor |
| `.sequencer-chart` | Token entropy visualization container |

---

## 14. Consent & Ethics Gate

The web app workspace displays `#pentest-consent-overlay` before allowing:

- Active scanning (`SCANNER_START`)
- Active crawling (`CRAWLER_START_ACTIVE`)
- Intruder attacks (`INTRUDER_START`)

The consent modal explains that:

- These tools send requests to the target host
- Users must have explicit written authorization to test any system they do not own
- NetSpecter's authors accept no liability for unauthorized use

Acceptance is persisted to `electron-store` so the modal is shown only once per session (not per action).

---

## 15. Dependency Analysis

### Runtime Dependencies Added by Feature 7

| Package | Version | Purpose | Bundle Impact |
| --- | --- | --- | --- |
| `better-sqlite3` | ^12.8.0 | SQLite request history | Native module — requires rebuild |
| `node-forge` | ^1.3.3 | TLS cert generation for MITM | ~400 KB |
| `playwright-core` | ^1.58.2 | Active crawler headless browser | Large — Chromium not bundled |

### `better-sqlite3` Native Module

Requires a C++ compiler at `npm install` time (via `node-gyp`). The `postinstall` script runs `electron-rebuild` to compile against the Electron version. This means:

- Windows requires Visual Studio Build Tools
- macOS requires Xcode Command Line Tools
- Linux requires `build-essential`

The compiled `.node` binary is excluded from ASAR:

```json
{
  "build": {
    "asarUnpack": ["**/better_sqlite3.node"]
  }
}
```

> **Note**: This key is not yet in `package.json`. It should be added before the next `dist` build to prevent ASAR extraction errors on packaged app startup.

### `playwright-core` vs `playwright`

`playwright-core` is used (not `playwright`) to avoid bundling browser executables. Active crawling requires the user to have Chromium installed separately. The executable path is configurable in Settings.

---

## 16. OWASP Gap Analysis & Roadmap

NetSpecter's scanner covers the OWASP Top 10 2021 as follows:

| OWASP 2021 Category | NetSpecter Module | Coverage Level | Gap |
| --- | --- | --- | --- |
| A01 Broken Access Control | `cors.js`, `brokenAuth.js` | Partial | No horizontal/vertical privilege escalation testing |
| A02 Cryptographic Failures | `headers.js` (HSTS, cookie flags) | Partial | No TLS cipher audit, no certificate chain validation |
| A03 Injection | `sqli.js`, `cmdInjection.js`, `xxe.js`, `pathTraversal.js` | Good | NoSQLi, LDAP injection, template injection not covered |
| A04 Insecure Design | Manual only | None | By design — requires business logic knowledge |
| A05 Security Misconfiguration | `headers.js`, `cors.js`, `cloudEnum.js` | Good | No cloud IAM misconfiguration |
| A06 Vulnerable Components | `nmapScanner.js` (CVE via Nmap) | Partial | No JS dependency audit (npm audit equivalent) |
| A07 Auth & Identity Failures | `brokenAuth.js` | Good | JWT suite incomplete (7E planned) |
| A08 Software Integrity Failures | `deserialize.js` | Partial | No SRI check, no CI/CD pipeline inspection |
| A09 Logging & Monitoring Failures | Manual only | None | Requires access to application logs |
| A10 SSRF | `ssrf.js` | Good | No DNS rebinding detection; OAST confirmations pending (7E) |

### Priority Roadmap (Post 7E)

1. **NoSQL Injection** — MongoDB `$where`, Elasticsearch injection
2. **SSTI (Server-Side Template Injection)** — `{{7*7}}` canary for Jinja2, Twig, Freemarker
3. **Open Redirect** — URL parameter redirect detection (standalone module)
4. **GraphQL Scanner** — Introspection, batch abuse, nested DoS
5. **WebSocket Fuzzer** — Payload injection into WS message frames
6. **JWT Attack Suite** — Full implementation of 7E.4
7. **TLS/Certificate Audit** — Cipher suite weakness, expired certs, chain validation
8. **Dependency Audit Integration** — Parse `package.json` / `requirements.txt` from responses and cross-reference against vulnerability databases
